# SSH Log Analyzer

Python tooling that generates a sample Linux `auth.log`, parses SSH login events, flags suspicious activity, and writes an ITIL-style incident report.

## Purpose

Give a self-contained way to practice log analysis: produce realistic SSH noise plus planted incidents, extract structured events, apply simple detections, and turn alerts into a report a service desk or SOC could file.

## Features

- **Log generation** (`generate_logs.py`) — 500 `sshd` lines, mostly normal, plus a brute-force burst from one IP, a successful login after those failures, and a few 3am logins.
- **Parsing** (`analyzer.py`) — timestamp, username, IP, and success/failure for each line.
- **Detections** with **Low / Medium / High** severity:
  - brute force: 5+ failed logins from one IP in 10 minutes
  - possible compromise: a success right after failures from the same IP
  - off-hours: successful logins between midnight and 5am
- **Incident report** — ITIL-style Markdown with summary, affected accounts, severity, and recommended actions (containment, eradication, recovery, communication, closure).
- **AI optional** — if `OPENAI_API_KEY` or `AI_API_KEY` is set, alerts are sent to the OpenAI API; otherwise a local template is used.
- **CLI** — choose the log path and report path (`report.md` by default).

## How to run

Requires Python 3.10 or newer. No third-party packages.

```powershell
python generate_logs.py
python analyzer.py
```

Defaults: read `auth.log`, write `report.md`.

```powershell
python analyzer.py --log auth.log --output report.md
python analyzer.py -l path\to\auth.log -o path\to\report.md
```

Optional AI report (falls back to the template if the call fails):

```powershell
$env:OPENAI_API_KEY = "sk-..."
# optional: $env:OPENAI_MODEL = "gpt-4o-mini"
python analyzer.py
```

## Sample output

Console:

```text
Parsed 500 events from auth.log
Success: 284
Failure: 216

Alerts: 5
[High] brute_force: Oct 14 18:42:11 user=admin,oracle,root,test,ubuntu ip=203.0.113.88 — 48 failed logins within 10 minutes (...)
[High] possible_compromise: Oct 14 18:44:42 user=admin ip=203.0.113.88 — Successful login for admin after 48 failed attempts ...
[Low] off_hours_login: Oct 13 03:07:21 user=alice ip=192.168.1.10 — Successful login for alice between midnight and 5am
[Low] off_hours_login: Oct 14 03:18:44 user=carol ip=10.0.0.15 — Successful login for carol between midnight and 5am
[Low] off_hours_login: Oct 15 03:41:09 user=dave ip=172.16.8.40 — Successful login for dave between midnight and 5am

Wrote incident report to report.md
```

`report.md` (template path, excerpt):

```markdown
# ITIL Incident Record

| Field | Value |
| --- | --- |
| Incident ID | INC-20261015-165628 |
| Status | New |
| Category | Security – Unauthorized Access |
| Priority | P1 |
| Severity | High |
| Affected accounts | admin, alice, carol, dave, oracle, root, test, ubuntu |

## Summary

Automated analysis of auth.log detected a brute-force SSH authentication attack;
a successful login immediately after failed attempts (possible account compromise);
successful logins during an unsocial maintenance window (00:00–05:00).
```

Exact counts and timestamps can shift if you change `generate_logs.py`; with the default seed they stay stable.

## Skills demonstrated

- Regular-expression parsing of syslog / `sshd` lines
- Structured Python (dataclasses, type hints, `pathlib`, `argparse`)
- Time-window detection (sliding window, correlation of failures then success)
- Severity mapping and ITIL incident writing (priority, impact, recommended actions)
- Environment-based configuration and a fallback when an external API is unavailable
- HTTP JSON client usage (`urllib`) without extra dependencies
- Reproducible synthetic data for testing detections
