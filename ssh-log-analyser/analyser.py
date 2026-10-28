"""SSH auth.log analyser: parse failed logins and flag brute-force activity."""
import ipaddress
import re
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