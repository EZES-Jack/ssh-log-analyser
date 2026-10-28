"""SSH auth.log analyser: parse failed logins and flag brute-force activity."""
import argparse
import ipaddress
import re
import sys
from collections import Counter, defaultdict

# Matches both formats:
#   Failed password for root from 1.2.3.4 port 22 ssh2
#   Failed password for invalid user test from 1.2.3.4 port 22 ssh2
FAILED_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"  # e.g. Oct 28 09:12:01
    r"\S+\ssshd\[\d+\]:\s"                                   # host and sshd[pid]:
    r"Failed password for (?:invalid user )?(?P<user>\S+) "  # optional "invalid user"
    r"from (?P<ip>\S+) port \d+"
)


def parse_line(line):
    """Return {'timestamp', 'user', 'ip'} for a failed-login line, else None."""
    match = FAILED_RE.match(line)
    if not match:
        return None
    # Logs are untrusted input: confirm the captured text is a real IP address.
    try:
        ipaddress.ip_address(match.group("ip"))
    except ValueError:
        return None
    return match.groupdict()


def parse_file(path):
    """Yield one dict per failed login in the file."""
    # errors="replace" stops a stray bad byte from crashing the whole run.
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:  # reads one line at a time, so large logs are fine
            entry = parse_line(line)
            if entry:
                yield entry


def count_failures(entries):
    """Return (failures_per_ip, users_per_ip) for an iterable of parsed entries."""
    failures = Counter()
    # defaultdict(set) creates an empty set on first use; a set keeps each
    # username once, so len() gives the number of distinct accounts targeted.
    users = defaultdict(set)

    for entry in entries:
        failures[entry["ip"]] += 1
        users[entry["ip"]].add(entry["user"])

    return failures, users


def find_suspects(failures, threshold):
    """Return [(ip, count), ...] for IPs at or above threshold, worst first."""
    flagged = [(ip, n) for ip, n in failures.items() if n >= threshold]
    # Sort on the count (index 1), highest first.
    return sorted(flagged, key=lambda item: item[1], reverse=True)


def build_report(path, failures, users, threshold):
    """Return the summary report as a single string."""
    lines = [
        "SSH failed-login report",
        f"File: {path}",
        f"Threshold: {threshold} failures",
        f"Total failed logins: {sum(failures.values())}",
        f"Unique source IPs: {len(failures)}",
        "",
        f"{'IP':<18}{'Failures':<10}Usernames tried",
    ]
    # most_common() lists IPs from most to fewest failures.
    for ip, count in failures.most_common():
        lines.append(f"{ip:<18}{count:<10}{len(users[ip])}")

    lines.append("")
    suspects = find_suspects(failures, threshold)
    if suspects:
        lines.append(f"POSSIBLE BRUTE FORCE (>= {threshold} failures):")
        for ip, count in suspects:
            # sorted() makes the username list stable between runs.
            names = ", ".join(sorted(users[ip]))
            lines.append(f"  {ip}: {count} failures, usernames: {names}")
    else:
        lines.append("No IPs reached the threshold.")
    return "\n".join(lines)


def positive_int(value):
    """argparse type: accept only whole numbers of 1 or more."""
    number = int(value)  # raises ValueError for text, which argparse reports
    if number < 1:
        raise argparse.ArgumentTypeError("threshold must be 1 or more")
    return number


def main():
    parser = argparse.ArgumentParser(
        description="Analyse an SSH auth.log for failed logins and brute-force activity."
    )
    parser.add_argument("logfile", help="path to the auth.log file to analyse")
    parser.add_argument(
        "-t", "--threshold", type=positive_int, default=5,
        help="failures from one IP that trigger a flag (default: 5)",
    )
    args = parser.parse_args()

    try:
        failures, users = count_failures(parse_file(args.logfile))
    except OSError as err:
        # Covers missing file, no permission, a folder instead of a file.
        print(f"Error: cannot read {args.logfile}: {err.strerror}", file=sys.stderr)
        return 1

    print(build_report(args.logfile, failures, users, args.threshold))
    return 0


if __name__ == "__main__":
    sys.exit(main())