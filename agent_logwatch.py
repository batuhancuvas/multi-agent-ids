import re
import os
from collections import defaultdict

AUTH_LOG = "/var/log/auth.log"

class LogWatchAgent:
    def __init__(self):
        self.failed_counts = defaultdict(int)
        self.last_position = 0
        self.pattern = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
        try:
            self.last_position = os.path.getsize(AUTH_LOG)
        except OSError:
            self.last_position = 0

    def check(self):
        """Read newly added lines in auth.log and count failed logins.
        Returns: {ip: failed_attempt_count} (only the increase this round)."""
        new_failures = defaultdict(int)
        try:
            with open(AUTH_LOG, "r") as f:
                f.seek(self.last_position)
                for line in f:
                    m = self.pattern.search(line)
                    if m:
                        ip = m.group(1)
                        self.failed_counts[ip] += 1
                        new_failures[ip] += 1
                self.last_position = f.tell()
        except OSError:
            pass
        return new_failures

    def get_total_failures(self, ip):
        """Return the total failed-login count for an IP."""
        return self.failed_counts.get(ip, 0)