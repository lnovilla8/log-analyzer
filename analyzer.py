import re
from collections import defaultdict
from datetime import datetime

# --- Configuration ---
LOG_FILE = "auth.log"
THRESHOLD = 5  # number of failures to trigger alert
WINDOW_SECONDS = 60  # time window to check for brute force

# --- Data structures ---
failed_attempts = defaultdict(list)  # ip -> list of timestamps
flagged_ips = set()

# --- Regex to parse log lines ---
pattern = re.compile(
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from ([\d\.]+|::1) port"
)

# --- Parse the log file ---
print("=" * 60)
print("  SSH BRUTE FORCE DETECTION REPORT")
print("=" * 60)
print(f"\nLog file : {LOG_FILE}")
print(f"Threshold: {THRESHOLD} failures within {WINDOW_SECONDS} seconds\n")

with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        match = pattern.search(line)
        if match:
            timestamp_str, username, ip = match.groups()

            # Parse timestamp (add dummy year so datetime works)
            timestamp = datetime.strptime("2026 " + timestamp_str, "%Y %b %d %H:%M:%S")

            # Store the attempt
            failed_attempts[ip].append((timestamp, username))

# --- Detect brute force ---
print("-" * 60)
print("FLAGGED IPs (Brute Force Detected)")
print("-" * 60)

brute_force_found = False

for ip, attempts in failed_attempts.items():
    attempts.sort()  # sort by time
    for i in range(len(attempts)):
        window = [
            a for a in attempts
            if (a[0] - attempts[i][0]).total_seconds() <= WINDOW_SECONDS
            and (a[0] - attempts[i][0]).total_seconds() >= 0
        ]
        if len(window) >= THRESHOLD:
            if ip not in flagged_ips:
                flagged_ips.add(ip)
                usernames = set(a[1] for a in attempts)
                print(f"\n  [!] ALERT: {ip}")
                print(f"      Total failed attempts : {len(attempts)}")
                print(f"      Usernames tried        : {', '.join(usernames)}")
                print(f"      First attempt          : {attempts[0][0]}")
                print(f"      Last attempt           : {attempts[-1][0]}")
                brute_force_found = True
            break

if not brute_force_found:
    print("\n  No brute force activity detected.")

# --- Summary ---
print("\n" + "-" * 60)
print("SUMMARY")
print("-" * 60)
print(f"  Total IPs with failed attempts : {len(failed_attempts)}")
print(f"  IPs flagged as brute force     : {len(flagged_ips)}")
print(f"  IPs below threshold            : {len(failed_attempts) - len(flagged_ips)}")

print("\n" + "-" * 60)
print("ALL FAILED ATTEMPT COUNTS BY IP")
print("-" * 60)
for ip, attempts in sorted(failed_attempts.items(), key=lambda x: len(x[1]), reverse=True):
    flag = " [FLAGGED]" if ip in flagged_ips else ""
    print(f"  {ip:<20} {len(attempts)} attempts{flag}")

print("\n" + "=" * 60)
print("  Scan complete.")
print("=" * 60)