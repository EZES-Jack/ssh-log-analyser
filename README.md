# SSH Log Analyser

A small command-line tool that reads a Linux `auth.log` file, extracts failed SSH
login attempts, counts failures per source IP, and flags possible brute-force
activity above a configurable threshold.

> **Authorised use only.** Use this tool only on systems and logs you own or have
> explicit permission to analyse. The sample data in this repo is fake and uses
> documentation-range IPs (203.0.113.0/24, RFC 5737).

## What it does

- Parses `Failed password` lines, including the `invalid user` variant
- Extracts timestamp, username and source IP for each failure
- Validates each IP with the `ipaddress` module (log content is untrusted input)
- Counts failures and distinct usernames tried per IP
- Flags IPs at or above a threshold and prints a summary report

Standard library only. Requires Python 3.8+.

## How to run

```
python analyser.py sample_auth.log
python analyser.py sample_auth.log --threshold 2
python analyser.py --help
```

| Argument | Description |
|---|---|
| `logfile` | Path to the auth.log file (required) |
| `-t`, `--threshold` | Failures from one IP that trigger a flag (default 5) |

Exit codes: `0` success, `1` file could not be read.

## Example output

```
SSH failed-login report
File: sample_auth.log
Threshold: 5 failures
Total failed logins: 9
Unique source IPs: 3

IP                Failures  Usernames tried
203.0.113.10      6         4
203.0.113.25      2         1
203.0.113.77      1         1

POSSIBLE BRUTE FORCE (>= 5 failures):
  203.0.113.10: 6 failures, usernames: admin, oracle, root, test
```

## Tests

```
python -m unittest -v
```

## Limitations

- Syslog timestamps have no year, so timestamps are kept as text
- Only `Failed password` lines are matched (not `Failed publickey` etc.)
- Failures are counted over the whole file, not within a time window
  (tools like fail2ban use windows, e.g. 5 failures in 10 minutes)

## What I learned

- **Logs are untrusted input.** The regex only proves a line has the right shape, so I validate each IP with the `ipaddress` module before using it.
- **Generators keep memory low.** `parse_file` yields one entry at a time, so it can handle very large logs without loading them into memory.
- **Distinct usernames add context.** One IP trying root, admin, test and oracle looks like guessing, not a typo, which makes the report more useful than a raw count.
- **Debugging is checking one assumption at a time.** I hit a missing import, a relative-path error caused by the working directory, and an indentation bug that silently skipped code.
- **Next steps:** count failures within a time window (like fail2ban), match more log patterns such as `Failed publickey`, and add JSON output.
