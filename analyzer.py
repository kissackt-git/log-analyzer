#!/usr/bin/env python3
"""Parse SSH events from auth.log, detect suspicious activity, and summarize."""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path

DEFAULT_LOG_PATH = Path("auth.log")
DEFAULT_REPORT_PATH = Path("report.md")
LOG_YEAR = 2026
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
COMPROMISE_WINDOW = timedelta(minutes=10)
COMPROMISE_MIN_FAILURES = 2
OFF_HOURS_START = 0  # midnight
OFF_HOURS_END = 5  # 05:00 exclusive

LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)

ACCEPTED_RE = re.compile(
    r"^Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)"
)
FAILED_RE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
INVALID_RE = re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)")
PAM_FAIL_RE = re.compile(
    r"authentication failure;.*rhost=(?P<ip>\S+)\s+user=(?P<user>\S+)"
)
SESSION_RE = re.compile(r"session opened for user (?P<user>\S+)")

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}
ITIL_PRIORITY = {"High": "P1", "Medium": "P2", "Low": "P3"}
API_KEY_ENV_VARS = ("OPENAI_API_KEY", "AI_API_KEY")
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")


@dataclass(frozen=True)
class Event:
    timestamp: str
    when: datetime
    username: str
    ip: str
    outcome: str  # "success" or "failure"
    kind: str


@dataclass(frozen=True)
class Alert:
    severity: str
    rule: str
    timestamp: str
    username: str
    ip: str
    detail: str


def parse_timestamp(ts: str) -> datetime:
    return datetime.strptime(f"{LOG_YEAR} {ts}", "%Y %b %d %H:%M:%S")


def parse_line(line: str) -> Event | None:
    match = LINE_RE.match(line.rstrip("\n"))
    if not match:
        return None

    ts = match.group("ts")
    when = parse_timestamp(ts)
    msg = match.group("msg")

    if (accepted := ACCEPTED_RE.search(msg)):
        return Event(ts, when, accepted.group("user"), accepted.group("ip"), "success", "accepted")
    if (failed := FAILED_RE.search(msg)):
        return Event(ts, when, failed.group("user"), failed.group("ip"), "failure", "failed_password")
    if (invalid := INVALID_RE.search(msg)):
        return Event(ts, when, invalid.group("user"), invalid.group("ip"), "failure", "invalid_user")
    if (pam_fail := PAM_FAIL_RE.search(msg)):
        return Event(ts, when, pam_fail.group("user"), pam_fail.group("ip"), "failure", "pam_fail")
    if (session := SESSION_RE.search(msg)):
        return Event(ts, when, session.group("user"), "-", "success", "session")
    return None


def analyze(path: Path) -> list[Event]:
    events: list[Event] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            event = parse_line(line)
            if event is not None:
                events.append(event)
    events.sort(key=lambda event: event.when)
    return events


def failed_attempts(events: list[Event]) -> list[Event]:
    """One failure per login try (skip PAM duplicates of Failed password)."""
    return [event for event in events if event.kind == "failed_password"]


def successful_logins(events: list[Event]) -> list[Event]:
    """One success per login (skip session-opened follow-ups)."""
    return [event for event in events if event.kind == "accepted"]


def detect_brute_force(events: list[Event]) -> list[Alert]:
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in failed_attempts(events):
        by_ip[event.ip].append(event)

    alerts: list[Alert] = []
    for ip, failures in by_ip.items():
        left = 0
        max_count = 0
        window_start: Event | None = None
        window_end: Event | None = None
        for right, event in enumerate(failures):
            while failures[right].when - failures[left].when > BRUTE_FORCE_WINDOW:
                left += 1
            count = right - left + 1
            if count > max_count:
                max_count = count
                window_start = failures[left]
                window_end = failures[right]
        if max_count >= BRUTE_FORCE_THRESHOLD and window_start and window_end:
            severity = "High" if max_count >= 10 else "Medium"
            users = sorted({item.username for item in failures})
            alerts.append(
                Alert(
                    severity=severity,
                    rule="brute_force",
                    timestamp=window_start.timestamp,
                    username=",".join(users),
                    ip=ip,
                    detail=(
                        f"{max_count} failed logins within 10 minutes "
                        f"({window_start.timestamp} – {window_end.timestamp})"
                    ),
                )
            )
    return alerts


def detect_compromise(events: list[Event]) -> list[Alert]:
    failures_by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in failed_attempts(events):
        failures_by_ip[event.ip].append(event)

    alerts: list[Alert] = []
    for success in successful_logins(events):
        prior = [
            failure
            for failure in failures_by_ip[success.ip]
            if failure.when <= success.when
            and success.when - failure.when <= COMPROMISE_WINDOW
        ]
        if len(prior) < COMPROMISE_MIN_FAILURES:
            continue
        severity = "High" if len(prior) >= BRUTE_FORCE_THRESHOLD else "Medium"
        alerts.append(
            Alert(
                severity=severity,
                rule="possible_compromise",
                timestamp=success.timestamp,
                username=success.username,
                ip=success.ip,
                detail=(
                    f"Successful login for {success.username} after "
                    f"{len(prior)} failed attempts from this IP in 10 minutes"
                ),
            )
        )
    return alerts


def detect_off_hours(events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in successful_logins(events):
        if OFF_HOURS_START <= event.when.hour < OFF_HOURS_END:
            alerts.append(
                Alert(
                    severity="Low",
                    rule="off_hours_login",
                    timestamp=event.timestamp,
                    username=event.username,
                    ip=event.ip,
                    detail=(
                        f"Successful login for {event.username} between "
                        "midnight and 5am"
                    ),
                )
            )
    return alerts


def detect(events: list[Event]) -> list[Alert]:
    alerts = detect_brute_force(events) + detect_compromise(events) + detect_off_hours(events)
    alerts.sort(key=lambda alert: (SEVERITY_ORDER[alert.severity], alert.timestamp, alert.rule))
    return alerts


def overall_severity(alerts: list[Alert]) -> str:
    if not alerts:
        return "Low"
    return min((alert.severity for alert in alerts), key=lambda item: SEVERITY_ORDER[item])


def affected_accounts(alerts: list[Alert]) -> list[str]:
    names: set[str] = set()
    for alert in alerts:
        for name in alert.username.split(","):
            name = name.strip()
            if name:
                names.add(name)
    return sorted(names)


def alert_payload(alerts: list[Alert]) -> list[dict[str, str]]:
    return [asdict(alert) for alert in alerts]


def report_from_template(alerts: list[Alert]) -> str:
    """ITIL-style incident report used when no AI API key is configured."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    incident_ref = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    severity = overall_severity(alerts)
    priority = ITIL_PRIORITY[severity]
    accounts = affected_accounts(alerts) or ["None identified"]
    ips = sorted({alert.ip for alert in alerts if alert.ip and alert.ip != "-"}) or ["None identified"]
    rules = sorted({alert.rule for alert in alerts})

    if not alerts:
        summary = (
            "No security alerts were raised from SSH authentication logs. "
            "This record is logged for completeness; no service impact is indicated."
        )
        impact = "No user or service impact identified."
        category = "Security – Informational"
        status = "Closed"
        actions = [
            "No immediate action required.",
            "Continue routine log review on the next monitoring cycle.",
        ]
    else:
        summary_bits = []
        if "brute_force" in rules:
            summary_bits.append("a brute-force SSH authentication attack")
        if "possible_compromise" in rules:
            summary_bits.append("a successful login immediately after failed attempts (possible account compromise)")
        if "off_hours_login" in rules:
            summary_bits.append("successful logins during an unsocial maintenance window (00:00–05:00)")
        joined = "; ".join(summary_bits) if summary_bits else "suspicious SSH authentication activity"
        summary = (
            f"Automated analysis of auth.log detected {joined}. "
            f"Highest assigned severity is {severity} ({priority}). "
            "The incident is recorded against the SSH authentication service on the monitored host."
        )
        if "possible_compromise" in rules or "brute_force" in rules:
            impact = (
                "Confidentiality of one or more user accounts may be affected. "
                "Availability of SSH is not reported as degraded, but unauthorized access risk is elevated."
            )
            status = "New"
            category = "Security – Unauthorized Access"
        else:
            impact = (
                "Limited security monitoring impact. Off-hours access should be verified "
                "against change and access records; no confirmed service outage."
            )
            status = "New"
            category = "Security – Policy Deviation"

        actions = []
        if "brute_force" in rules:
            actions.extend(
                [
                    "Containment: block or rate-limit the source IP(s) at the firewall or fail2ban.",
                    "Investigation: review sshd logs for additional hosts targeted by the same source.",
                ]
            )
        if "possible_compromise" in rules:
            actions.extend(
                [
                    "Containment: disable or lock the affected account(s) pending verification.",
                    "Eradication: reset credentials and revoke active SSH sessions/keys for those accounts.",
                    "Recovery: confirm the account holder’s activity before re-enabling access.",
                ]
            )
        if "off_hours_login" in rules:
            actions.append(
                "Investigation: confirm whether the midnight–05:00 logins were approved change or on-call work."
            )
        actions.extend(
            [
                "Communication: notify the service owner and information security if High/P1.",
                "Closure: update this incident with evidence, root cause, and any problem record (ITIL Problem Management).",
            ]
        )

    observation_lines = [
        f"  - [{alert.severity}] {alert.rule} @ {alert.timestamp} user={alert.username} ip={alert.ip}: {alert.detail}"
        for alert in alerts
    ] or ["  - None"]

    action_lines = "\n".join(f"{idx}. {step}" for idx, step in enumerate(actions, start=1))
    return "\n".join(
        [
            "# ITIL Incident Record",
            "",
            f"| Field | Value |",
            f"| --- | --- |",
            f"| Incident ID | {incident_ref} |",
            f"| Recorded | {now} |",
            f"| Status | {status} |",
            f"| Category | {category} |",
            f"| Impact / Urgency | {severity} / {severity} |",
            f"| Priority | {priority} |",
            f"| Severity | {severity} |",
            f"| Affected accounts | {', '.join(accounts)} |",
            f"| Affected CIs / IPs | {', '.join(ips)} |",
            "",
            "## Summary",
            "",
            summary,
            "",
            "## Description (alerts observed)",
            "",
            *observation_lines,
            "",
            "## Recommended actions",
            "",
            action_lines,
        ]
    )


def send_alerts_to_ai(alerts: list[Alert], api_key: str) -> str:
    """Send alerts to the OpenAI API and return an ITIL incident report."""
    prompt = {
        "model": OPENAI_MODEL,
        "temperature": 0.2,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an IT operations analyst. Write a concise ITIL incident record in "
                    "Markdown from SSH log alerts. Always include: Incident ID, Status, Category, "
                    "Priority, Severity, Summary, Affected accounts, Affected CIs/IPs, Description, "
                    "and Recommended actions. Use ITIL language (incident, impact, urgency, "
                    "priority, containment, eradication, recovery, communication, closure). "
                    "Do not invent hosts, users, or IPs that are not in the alerts."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Produce an ITIL incident report for these authentication alerts:\n"
                    + json.dumps(alert_payload(alerts), indent=2)
                ),
            },
        ],
    }
    request = urllib.request.Request(
        OPENAI_URL,
        data=json.dumps(prompt).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.loads(response.read().decode("utf-8"))
    return body["choices"][0]["message"]["content"].strip()


def generate_incident_report(alerts: list[Alert]) -> str:
    """Build an incident report via AI when an API key is set, otherwise a template."""
    api_key = ""
    for name in API_KEY_ENV_VARS:
        api_key = os.environ.get(name, "").strip()
        if api_key:
            break
    if not api_key:
        return report_from_template(alerts)
    try:
        return send_alerts_to_ai(alerts, api_key)
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError, TimeoutError, json.JSONDecodeError) as exc:
        fallback = report_from_template(alerts)
        return (
            f"(AI API request failed: {exc}; generated from template instead)\n\n{fallback}"
        )


def print_summary(events: list[Event], alerts: list[Alert], log_path: Path) -> None:
    successes = sum(1 for event in events if event.outcome == "success")
    failures = sum(1 for event in events if event.outcome == "failure")
    print(f"Parsed {len(events)} events from {log_path}")
    print(f"Success: {successes}")
    print(f"Failure: {failures}")
    print()
    print(f"Alerts: {len(alerts)}")
    if not alerts:
        print("No detections.")
        return
    for alert in alerts:
        print(
            f"[{alert.severity}] {alert.rule}: {alert.timestamp} "
            f"user={alert.username} ip={alert.ip} — {alert.detail}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze SSH auth logs, detect suspicious activity, and write an ITIL incident report."
    )
    parser.add_argument(
        "-l",
        "--log",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help="Path to the auth log (default: auth.log)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="Path to write the incident report (default: report.md)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    log_path: Path = args.log
    output_path: Path = args.output

    if not log_path.exists():
        raise SystemExit(f"Log file not found: {log_path}")

    events = analyze(log_path)
    alerts = detect(events)
    print_summary(events, alerts, log_path)

    report = generate_incident_report(alerts)
    output_path.write_text(report.rstrip() + "\n", encoding="utf-8")
    print()
    print(f"Wrote incident report to {output_path}")


if __name__ == "__main__":
    main()
