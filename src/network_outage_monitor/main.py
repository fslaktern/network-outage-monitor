import argparse
import os
import time
from datetime import datetime, timedelta
from glob import glob
from typing import Generator, NamedTuple, Optional

import requests
from scapy.layers.inet import ICMP, IP
from scapy.packet import Packet
from scapy.plist import PacketList, SndRcvList
from scapy.sendrecv import sr


class Entry(NamedTuple):
    timestamp: int
    status: bool


class DiscordWebhook:
    def __init__(self, url: str, ip: str) -> None:
        self.url: str = url
        self.ip: str = ip
        self.session: requests.Session = requests.Session()

    def notify(self, state: bool, delta: timedelta) -> bool:
        formatted_delta = format_timedelta(delta)
        if state:
            title = f"{self.ip} is REACHABLE"
            content = f"Was unreachable for {formatted_delta}"
            color = 0x2ECC71  # green
        else:
            title = f"{self.ip} is UNREACHABLE"
            content = f"Was reachable for {formatted_delta}"
            color = 0xE74C3C  # red

        return self.send(title, content, color)

    def send(self, title: str, content: str, color: int) -> bool:
        data = {
            "username": "Network outage monitor",
            "embeds": [
                {
                    "title": title,
                    "description": content,
                    "color": color,
                }
            ],
        }

        try:
            response = self.session.post(self.url, json=data)
            response.raise_for_status()
            return response.ok
        except requests.RequestException as e:
            print(f"Error sending webhook notification: {e}")
            return False


def format_timedelta(td: timedelta) -> str:
    total_seconds = int(td.total_seconds())

    days, remainder = divmod(total_seconds, 60 * 60 * 24)
    hours, remainder = divmod(remainder, 60 * 60)
    minutes, seconds = divmod(remainder, 60)

    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")

    return " ".join(parts)


def get_last_entry(log_dir: str) -> Optional[Entry]:
    log_files = sorted(glob(os.path.join(log_dir, "uptime_*.log")))
    if not log_files:
        return None

    last_entry: Optional[Entry] = None
    for filepath in log_files:
        for entry in read_entries(filepath):
            last_entry = entry
    return last_entry


def is_up(ip: str) -> bool:
    pkt: Packet = IP(dst=ip) / ICMP()

    ans: SndRcvList
    _unans: PacketList
    ans, _unans = sr(pkt, timeout=2, verbose=0)
    return bool(ans)


def write_entry(filepath: str, entry: Entry) -> None:
    """
    Write a 4-byte packed record:
    - 31 bits: timestamp
    - 1 bit: status (1 = up, 0 = down)
    """
    if entry.timestamp >= (1 << 31):
        raise ValueError("Timestamp too large for 31-bit storage")

    value = (entry.timestamp << 1) | int(entry.status)
    packed = value.to_bytes(4, byteorder="big")
    with open(filepath, "ab") as f:
        f.write(packed)


def read_entries(filepath: str) -> Generator[Entry, None, None]:
    """
    Yield (timestamp, status) from the 4-byte packed binary file.
    """
    with open(filepath, "rb") as f:
        while True:
            chunk: bytes = f.read(4)
            if len(chunk) < 4:
                break
            value = int.from_bytes(chunk, byteorder="big")
            timestamp = value >> 1
            status = bool(value & 1)
            yield Entry(timestamp, status)


def daemon_mode(
    ip: str, interval: int, save_dir: str, webhook: Optional[DiscordWebhook]
) -> None:
    os.makedirs(save_dir, exist_ok=True)
    print(f"Starting uptime monitor every {interval}s. Saving to directory: {save_dir}")

    previous_update = int(time.time())
    previous_state: Optional[bool] = None

    last_entry = get_last_entry(save_dir)
    if last_entry:
        previous_update = last_entry.timestamp
        previous_state = last_entry.status
        print(
            f"Resuming from last entry at {datetime.fromtimestamp(previous_update)} "
            f"({'UP' if previous_state else 'DOWN'})"
        )

    while True:
        try:
            time.sleep(interval)
            now = int(time.time())
            state = is_up(ip)

            if state != previous_state:
                month_str = datetime.fromtimestamp(now).strftime("%Y-%m")
                filename = os.path.join(save_dir, f"uptime_{month_str}.log")
                current_entry = Entry(now, state)
                write_entry(filename, current_entry)

                if webhook is not None:
                    delta = datetime.fromtimestamp(
                        current_entry.timestamp
                    ) - datetime.fromtimestamp(previous_update)
                    webhook.notify(state, delta)

                previous_update = current_entry.timestamp
                previous_state = current_entry.status

        except KeyboardInterrupt:
            break


def log_mode(load_dir: str) -> None:
    from glob import glob

    log_files = sorted(glob(os.path.join(load_dir, "uptime_*.log")))
    if not log_files:
        print("No log files found")
        return

    print(f"| {'Time':<19} | Status |")
    print(f"|{'-' * 21}|--------|")

    for filepath in log_files:
        for timestamp, status in read_entries(filepath):
            timestr = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            statstr = "UP" if status else "DOWN"
            print(f"| {timestr} | {statstr:<6} |")


def main() -> None:
    parser = argparse.ArgumentParser(description="Uptime Monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # daemon subcommand
    daemon_parser = subparsers.add_parser("daemon", help="Run monitor daemon")
    daemon_parser.add_argument(
        "--interval", type=int, default=20, help="Check interval in seconds"
    )
    daemon_parser.add_argument(
        "--save", type=str, required=True, help="Directory to save logs"
    )
    daemon_parser.add_argument("--ip", type=str, required=True, help="IP to monitor")
    daemon_parser.add_argument(
        "--discord-webhook",
        type=str,
        help="Send up and downtime notifications to a Discord webhook",
    )

    # log subcommand
    log_parser = subparsers.add_parser("log", help="Read and print logs")
    log_parser.add_argument(
        "--load", type=str, required=True, help="Directory to load logs from"
    )

    args = parser.parse_args()

    if args.command == "daemon":
        if args.discord_webhook is None:
            daemon_mode(args.ip, args.interval, args.save, None)
        else:
            webhook = DiscordWebhook(args.discord_webhook, args.ip)
            daemon_mode(args.ip, args.interval, args.save, webhook)
    elif args.command == "log":
        log_mode(args.load)


if __name__ == "__main__":
    main()
