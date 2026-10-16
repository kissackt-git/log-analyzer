# ITIL Incident Record

| Field | Value |
| --- | --- |
| Incident ID | INC-20261015-165704 |
| Recorded | 2026-10-15 16:57:04 |
| Status | New |
| Category | Security – Unauthorized Access |
| Impact / Urgency | High / High |
| Priority | P1 |
| Severity | High |
| Affected accounts | admin, alice, carol, dave, oracle, root, test, ubuntu |
| Affected CIs / IPs | 10.0.0.15, 172.16.8.40, 192.168.1.10, 203.0.113.88 |

## Summary

Automated analysis of auth.log detected a brute-force SSH authentication attack; a successful login immediately after failed attempts (possible account compromise); successful logins during an unsocial maintenance window (00:00–05:00). Highest assigned severity is High (P1). The incident is recorded against the SSH authentication service on the monitored host.

## Description (alerts observed)

  - [High] brute_force @ Oct 14 18:42:11 user=admin,oracle,root,test,ubuntu ip=203.0.113.88: 48 failed logins within 10 minutes (Oct 14 18:42:11 – Oct 14 18:44:32)
  - [High] possible_compromise @ Oct 14 18:44:42 user=admin ip=203.0.113.88: Successful login for admin after 48 failed attempts from this IP in 10 minutes
  - [Low] off_hours_login @ Oct 13 03:07:21 user=alice ip=192.168.1.10: Successful login for alice between midnight and 5am
  - [Low] off_hours_login @ Oct 14 03:18:44 user=carol ip=10.0.0.15: Successful login for carol between midnight and 5am
  - [Low] off_hours_login @ Oct 15 03:41:09 user=dave ip=172.16.8.40: Successful login for dave between midnight and 5am

## Recommended actions

1. Containment: block or rate-limit the source IP(s) at the firewall or fail2ban.
2. Investigation: review sshd logs for additional hosts targeted by the same source.
3. Containment: disable or lock the affected account(s) pending verification.
4. Eradication: reset credentials and revoke active SSH sessions/keys for those accounts.
5. Recovery: confirm the account holder’s activity before re-enabling access.
6. Investigation: confirm whether the midnight–05:00 logins were approved change or on-call work.
7. Communication: notify the service owner and information security if High/P1.
8. Closure: update this incident with evidence, root cause, and any problem record (ITIL Problem Management).
