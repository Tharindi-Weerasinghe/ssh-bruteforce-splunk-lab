# Project Notes

This lab simulates failed SSH login attempts from a Kali Linux machine against an Ubuntu machine. Ubuntu authentication logs were collected using Splunk Enterprise and searched using SPL.

The main detection identifies repeated failed SSH login attempts from the same source IP within a 5-minute time window.

Lab machines:
- Kali Linux: attacker simulation
- Ubuntu: SSH target and log source
- Splunk Enterprise: SIEM and detection platform

Important log source:
- /var/log/auth.log

Detection threshold:
- 3 or more failed SSH login attempts from the same source IP within 5 minutes

Alert:
- SSH Brute Force Detection
- Scheduled every 5 minutes
- Trigger condition: number of results greater than 0
