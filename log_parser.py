#!/usr/bin/env python3
import re
import argparse
import csv
from collections import defaultdict

# One-line regex: matches "Failed password for <user> from <ip>"
FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def parse_file(path, threshold=3, csv_path=None):
    fail_counts = defaultdict(int)
    matches = []   # (user, ip, line)

    # Read the file line by line (works for any text log)
    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = FAILED_PATTERN.search(line)
            if m:
                user = m.group("user")
                ip = m.group("ip")
                fail_counts[ip] += 1
                matches.append((user, ip, line.strip()))

    # Output: line-by-line findings
    if matches:
        for user, ip, _ in matches:
            print(f"Failed login: user={user} ip={ip}")
    else:
        print("No failed logins found matching the SSH pattern.")
        return

    # Summary by IP
    print("\n=== Failed login counts by IP ===")
    for ip, count in fail_counts.items():
        print(f"{ip} -> {count} failures")

    # Alerts (brute force threshold)
    alerts = []
    print("\n=== Suspicious Activity (threshold >= {0}) ===".format(threshold))
    for ip, count in fail_counts.items():
        if count >= threshold:
            msg = f"ALERT 🚨 {ip} has {count} failed login attempts (possible brute force)"
            print(msg)
            alerts.append({"ip": ip, "count": count, "type": "BRUTE_FORCE"})

    # Optional: write alerts to CSV
    if csv_path and alerts:
        with open(csv_path, "w", newline="") as fp:
            writer = csv.DictWriter(fp, fieldnames=["ip", "count", "type"])
            writer.writeheader()
            writer.writerows(alerts)
        print(f"\nSaved alerts to: {csv_path}")

def main():
    ap = argparse.ArgumentParser(description="Mini SIEM log parser for SSH failed logins.")
    ap.add_argument("--log", required=True, help="Path to any log file (e.g., auth.log)")
    ap.add_argument("--threshold", type=int, default=3, help="Failures from same IP to trigger an alert (default 3)")
    ap.add_argument("--csv", help="Optional path to write alerts CSV (e.g., reports/alerts.csv)")
    args = ap.parse_args()

    parse_file(args.log, threshold=args.threshold, csv_path=args.csv)

if __name__ == "__main__":
    main()

