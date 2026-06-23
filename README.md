# SSH Brute Force Log Analyzer

## What it does
This brute-force log analyzer analyzes event logs and detects whether a brute-force attack has occurred. It outputs a report text file with information on which IP addresses the attacks came from, the number of attempts, the times they tried to log in to the account, and a summary of IP addresses flagged as brute-force attacks.

## Why it matters
A brute-force attack occurs when an adversary repeatedly attempts to log in to an account they are not permitted to access. A brute force analyzer is important because it automatically alerts SOC analysts when someone is trying to break into an account. This tool simulates the kind of log triage a SOC analyst performs daily using a SIEM like Splunk or Microsoft Sentinel.

## How to run it
Run the script with python3 analyzer.py . It will then prompt you to input the name of the event log file that you want to examine.

## Example output
Enter log file: auth.log
============================================================
  SSH BRUTE FORCE DETECTION REPORT
============================================================

Log file : auth.log
Threshold: 5 failures within 60 seconds

------------------------------------------------------------
FLAGGED IPs (Brute Force Detected)
------------------------------------------------------------

  [!] ALERT: 203.0.113.42
      Total failed attempts : 8
      Usernames tried        : oracle, admin
      First attempt          : 2026-06-22 18:05:12
      Last attempt           : 2026-06-22 18:25:03

  [!] ALERT: 198.51.100.7
      Total failed attempts : 6
      Usernames tried        : root
      First attempt          : 2026-06-22 18:10:01
      Last attempt           : 2026-06-22 18:10:10

  [!] ALERT: 10.0.0.99
      Total failed attempts : 5
      Usernames tried        : user
      First attempt          : 2026-06-22 18:30:00
      Last attempt           : 2026-06-22 18:30:04

------------------------------------------------------------
SUMMARY
------------------------------------------------------------
  Total IPs with failed attempts : 4
  IPs flagged as brute force     : 3
  IPs below threshold            : 1

------------------------------------------------------------
ALL FAILED ATTEMPT COUNTS BY IP
------------------------------------------------------------
  203.0.113.42         8 attempts [FLAGGED]
  198.51.100.7         6 attempts [FLAGGED]
  10.0.0.99            5 attempts [FLAGGED]
  172.16.0.55          1 attempts

============================================================
  Scan complete.
============================================================

## Skills demonstrated
Python, regular expressions (re module), log parsing, 
brute force detection logic, file I/O, datetime manipulation
