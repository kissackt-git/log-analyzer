#!/usr/bin/env python3
"""Generate a fake Linux auth.log with SSH login events.

Writes 500 sshd lines: mostly normal traffic, plus a brute-force burst from
one IP, a successful login after those failures, and a few 3am logins.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

OUTPUT_PATH = Path("auth.log")
LINE_COUNT = 500
HOSTNAME = "webserver"
ATTACKER_IP = "203.0.113.88"
COMPROMISED_USER = "admin"

NORMAL_USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]
INVALID_USERS = ["root", "test", "ubuntu", "oracle", "guest", "pi"]
NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.24",
    "10.0.0.15",
    "10.0.4.8",
    "172.16.8.40",
    "198.51.100.22",
]
NIGHT_USERS = ["alice", "carol"]
NIGHT_IPS = ["192.168.1.10", "10.0.0.15"]

# Mix of daytime hours for ordinary traffic (avoid 03:00).
DAY_HOURS = list(range(7, 23))


def syslog_ts(dt: datetime) -> str:
    """Format a timestamp like syslog auth.log (no leading zero on day)."""
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"


def sshd(dt: datetime, pid: int, message: str) -> str:
    return f"{syslog_ts(dt)} {HOSTNAME} sshd[{pid}]: {message}"


def random_port() -> int:
    return random.randint(32768, 60999)


def accepted_password(dt: datetime, pid: int, user: str, ip: str, port: int) -> list[str]:
    return [
        sshd(dt, pid, f"Accepted password for {user} from {ip} port {port} ssh2"),
        sshd(
            dt + timedelta(seconds=1),
            pid,
            f"pam_unix(sshd:session): session opened for user {user} by (uid=0)",
        ),
    ]


def accepted_publickey(dt: datetime, pid: int, user: str, ip: str, port: int) -> list[str]:
    return [
        sshd(dt, pid, f"Accepted publickey for {user} from {ip} port {port} ssh2"),
        sshd(
            dt + timedelta(seconds=1),
            pid,
            f"pam_unix(sshd:session): session opened for user {user} by (uid=0)",
        ),
    ]


def failed_password(dt: datetime, pid: int, user: str, ip: str, port: int) -> list[str]:
    return [
        sshd(
            dt,
            pid,
            f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
            f"tty=ssh ruser= rhost={ip}  user={user}",
        ),
        sshd(dt + timedelta(seconds=1), pid, f"Failed password for {user} from {ip} port {port} ssh2"),
    ]


def invalid_user(dt: datetime, pid: int, user: str, ip: str, port: int) -> list[str]:
    return [
        sshd(dt, pid, f"Invalid user {user} from {ip} port {port}"),
        sshd(
            dt + timedelta(seconds=1),
            pid,
            f"Failed password for invalid user {user} from {ip} port {port} ssh2",
        ),
    ]


def random_daytime(rng: random.Random, start: datetime, span_days: int) -> datetime:
    day = start + timedelta(days=rng.randint(0, span_days - 1))
    hour = rng.choice(DAY_HOURS)
    minute = rng.randint(0, 59)
    second = rng.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=second, microsecond=0)


def main() -> None:
    rng = random.Random(42)
    start = datetime(2026, 10, 12, 8, 0, 0)
    pid = 14000
    events: list[tuple[datetime, str]] = []

    def next_pid() -> int:
        nonlocal pid
        pid += rng.randint(1, 7)
        return pid

    def add_lines(base: datetime, lines: list[str]) -> None:
        for i, line in enumerate(lines):
            events.append((base + timedelta(seconds=i), line))

    # Brute-force: many failed logins from one IP, then a successful login.
    attack_start = datetime(2026, 10, 14, 18, 42, 10)
    attack_users = ["admin", "root", "ubuntu", "test", "oracle"]
    for i in range(48):
        t = attack_start + timedelta(seconds=i * 3)
        user = attack_users[i % len(attack_users)]
        port = 40000 + i
        current_pid = next_pid()
        if user == COMPROMISED_USER:
            add_lines(t, failed_password(t, current_pid, user, ATTACKER_IP, port))
        else:
            add_lines(t, invalid_user(t, current_pid, user, ATTACKER_IP, port))

    success_time = attack_start + timedelta(seconds=48 * 3 + 8)
    add_lines(
        success_time,
        accepted_password(
            success_time, next_pid(), COMPROMISED_USER, ATTACKER_IP, 40048
        ),
    )

    # A few successful logins at 3am (unusual hours).
    night_times = [
        datetime(2026, 10, 13, 3, 7, 21),
        datetime(2026, 10, 14, 3, 18, 44),
        datetime(2026, 10, 15, 3, 41, 9),
    ]
    for t, user, ip in zip(night_times, NIGHT_USERS + ["dave"], NIGHT_IPS + ["172.16.8.40"]):
        add_lines(t, accepted_publickey(t, next_pid(), user, ip, random_port()))

    # Fill the rest with mostly normal daytime traffic.
    while len(events) < LINE_COUNT:
        t = random_daytime(rng, start, span_days=4)
        user = rng.choice(NORMAL_USERS)
        ip = rng.choice(NORMAL_IPS)
        port = random_port()
        current_pid = next_pid()
        roll = rng.random()
        if roll < 0.72:
            kind = accepted_publickey if rng.random() < 0.65 else accepted_password
            lines = kind(t, current_pid, user, ip, port)
        elif roll < 0.88:
            lines = failed_password(t, current_pid, user, ip, port)
        else:
            lines = invalid_user(t, current_pid, rng.choice(INVALID_USERS), ip, port)
        remaining = LINE_COUNT - len(events)
        add_lines(t, lines[:remaining])

    events.sort(key=lambda item: item[0])
    lines = [line for _, line in events[:LINE_COUNT]]

    OUTPUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(lines)} lines to {OUTPUT_PATH.resolve()}")


if __name__ == "__main__":
    main()
