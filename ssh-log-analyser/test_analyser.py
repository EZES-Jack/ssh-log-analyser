"""Unit tests for analyser.py (standard library unittest, no extra installs)."""
import argparse
import os
import tempfile
import unittest
from collections import Counter
from pathlib import Path

import analyser

# Build the sample log path from this file's location, so the tests
# pass no matter which folder they are run from.
SAMPLE_LOG = Path(__file__).resolve().parent / "sample_auth.log"


class TestParseLine(unittest.TestCase):
    def test_normal_failed_login(self):
        line = "Oct 28 09:12:01 server sshd[1201]: Failed password for root from 203.0.113.10 port 51234 ssh2"
        self.assertEqual(
            analyser.parse_line(line),
            {"timestamp": "Oct 28 09:12:01", "user": "root", "ip": "203.0.113.10"},
        )

    def test_invalid_user_format(self):
        line = "Oct 28 10:01:44 server sshd[1502]: Failed password for invalid user guest from 203.0.113.77 port 33001 ssh2"
        result = analyser.parse_line(line)
        # The words "invalid user" must not end up in the username.
        self.assertEqual(result["user"], "guest")

    def test_ignores_non_failure_lines(self):
        accepted = "Oct 28 09:45:02 server sshd[1410]: Accepted password for alice from 203.0.113.25 port 40100 ssh2"
        sudo = "Oct 28 10:06:00 server sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls"
        self.assertIsNone(analyser.parse_line(accepted))
        self.assertIsNone(analyser.parse_line(sudo))

    def test_rejects_invalid_ip(self):
        # Matches the regex shape but is not a real IP, so it must be dropped.
        line = "Oct 28 09:12:01 server sshd[1201]: Failed password for root from 999.999.1.1 port 22 ssh2"
        self.assertIsNone(analyser.parse_line(line))


class TestCounting(unittest.TestCase):
    def test_count_failures_and_users(self):
        entries = [
            {"ip": "203.0.113.10", "user": "root"},
            {"ip": "203.0.113.10", "user": "admin"},
            {"ip": "203.0.113.10", "user": "root"},
            {"ip": "203.0.113.25", "user": "alice"},
        ]
        failures, users = analyser.count_failures(entries)
        self.assertEqual(failures["203.0.113.10"], 3)
        # "root" appears twice but is stored once, so there are 2 distinct names.
        self.assertEqual(users["203.0.113.10"], {"root", "admin"})

    def test_threshold_boundary(self):
        failures = Counter({"203.0.113.10": 5, "203.0.113.25": 4})
        # Exactly at the threshold is flagged; one below is not.
        self.assertEqual(analyser.find_suspects(failures, 5), [("203.0.113.10", 5)])

    def test_suspects_sorted_worst_first(self):
        failures = Counter({"203.0.113.25": 6, "203.0.113.10": 9})
        result = analyser.find_suspects(failures, 5)
        self.assertEqual(result[0][0], "203.0.113.10")


class TestFileAndCli(unittest.TestCase):
    def test_sample_log_end_to_end(self):
        failures, users = analyser.count_failures(analyser.parse_file(SAMPLE_LOG))
        self.assertEqual(sum(failures.values()), 9)
        self.assertEqual(failures["203.0.113.10"], 6)
        self.assertEqual(analyser.find_suspects(failures, 5), [("203.0.113.10", 6)])

    def test_bad_bytes_do_not_crash(self):
        # delete=False plus manual cleanup keeps this working on Windows,
        # where an open temp file cannot be reopened by name.
        with tempfile.NamedTemporaryFile("wb", suffix=".log", delete=False) as tmp:
            tmp.write(b"\xff\xfe not valid utf-8\n")
            name = tmp.name
        try:
            self.assertEqual(list(analyser.parse_file(name)), [])
        finally:
            os.remove(name)

    def test_positive_int_validation(self):
        self.assertEqual(analyser.positive_int("3"), 3)
        with self.assertRaises(argparse.ArgumentTypeError):
            analyser.positive_int("0")

    def test_report_flags_suspect(self):
        failures = Counter({"203.0.113.10": 6})
        users = {"203.0.113.10": {"root"}}
        report = analyser.build_report("x.log", failures, users, 5)
        self.assertIn("POSSIBLE BRUTE FORCE", report)
        self.assertIn("203.0.113.10", report)


if __name__ == "__main__":
    unittest.main()