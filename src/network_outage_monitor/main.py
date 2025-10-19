import argparse
import os
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import IntEnum
from glob import glob
from pathlib import Path
from typing import Generator, Optional

import requests
from loguru import logger
from scapy.layers.inet import ICMP, IP
from scapy.packet import Packet
from scapy.plist import PacketList, SndRcvList
from scapy.sendrecv import sr


class Status(IntEnum):
    UP = 0
    DOWN = 1
    # Indicate continuation, not up or downtime
    STARTED = 2
    # Indicate end of current monitoring, not up or downtime
    STOPPED = 3

    def __str__(self) -> str:
        return ["UP", "DOWN", "STARTED", "STOPPED"][self.value]


@dataclass
class LogEntry:
    timestamp: int
    status: Status


@dataclass
class UptimeSummary:
    uptime: timedelta
    downtime: timedelta


@dataclass
class DiscordEmbed:
    title: str
    description: str | None
    color: int


@dataclass
class DiscordMessage:
    username: str
    embeds: list[DiscordEmbed]


class DiscordWebhook:
    def __init__(self, url: str, ip: str) -> None:
        self.url: str = url
        self.ip: str = ip
        self.session: requests.Session = requests.Session()

    def notify(self, state: Status, delta: timedelta, previous_status: Status) -> bool:
        formatted_delta = format_timedelta(delta)
        match state:
            case Status.UP:
                if previous_status in {Status.STARTED, Status.STOPPED}:
                    description = f"Was unreachable for {formatted_delta}"
                else:
                    description = None

                embed = DiscordEmbed(
                    title=f"{self.ip} is REACHABLE",
                    description=description,
                    color=0x2ECC71,  # green
                )
            case Status.DOWN:
                if previous_status in {Status.STARTED, Status.STOPPED}:
                    description = f"Was reachable for {formatted_delta}"
                else:
                    description = None

                embed = DiscordEmbed(
                    title=f"{self.ip} is UNREACHABLE",
                    description=description,
                    color=0xE74C3C,  # red
                )
            case Status.STARTED:
                embed = DiscordEmbed(
                    title=f"Started monitoring {self.ip}",
                    description=None,
                    color=0x0389FA,  # blue
                )
            case Status.STOPPED:
                embed = DiscordEmbed(
                    title=f"Stopped monitoring {self.ip}",
                    description=None,
                    color=0x0389FA,  # blue
                )

        return self.send(embed)

    def send(self, embed: DiscordEmbed) -> bool:
        data = DiscordMessage(
            username="Network Outage Monitor",
            embeds=[embed],
        )

        try:
            response = self.session.post(
                self.url,
                json=asdict(data),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            return response.ok
        except requests.RequestException as e:
            logger.warning(f"Got error when sending webhook notification: {e}")
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


def get_last_entries(log_dir: Path, n: int = 1) -> deque[LogEntry]:
    log_files = sorted(glob(str(log_dir / "uptime_*.log")))
    queue: deque[LogEntry] = deque(maxlen=n)

    if not log_files:
        return queue

    for filepath in log_files:
        queue.extend(read_entries(filepath))

    return queue


def try_continue_monitoring(
    save_dir: Path, webhook: Optional[DiscordWebhook]
) -> LogEntry:
    default = LogEntry(int(time.time()), Status.STARTED)
    entries = get_last_entries(save_dir, n=2)

    # Notify start
    handle_status_change(
        save_dir,
        state=Status.STARTED,
        # Previous entry is not used for Status.STARTED, so this is just a placeholder
        previous=LogEntry(0, Status.STOPPED),
        webhook=webhook,
    )

    # need at least 1 entry if we want to continue
    if not entries:
        return default

    # Last entry SHOULD be Status.STOPPED
    if entries[-1].status != Status.STOPPED:
        return default

    # The second last SHOULD be one of Status.UP or Status.DOWN
    if entries[-2].status not in {Status.STARTED, Status.STOPPED}:
        return default

    # Print that we continue from the last time we stopped, but set timestamp such
    # that the total uptime and total downtime calculation doesn't include the time
    # in between STOPPED and STARTED
    last_entry = entries[-2]
    time_of_stop = entries[-1].timestamp
    time_to_ignore = default.timestamp - time_of_stop

    logger.info(
        f"Resuming from last entry at {datetime.fromtimestamp(last_entry.timestamp)} "
        f"({last_entry.status!s})"
    )

    return LogEntry(last_entry.timestamp + time_to_ignore, last_entry.status)


def is_up(ip: str) -> Status:
    pkt: Packet = IP(dst=ip) / ICMP()

    ans: SndRcvList
    _unans: PacketList
    ans, _unans = sr(pkt, timeout=2, verbose=0)

    return Status.UP if ans else Status.DOWN


def write_entry(filepath: Path, entry: LogEntry) -> None:
    """
    Write a 5-byte packed record:
    - 38 bits: timestamp
    - 2 bits: status
    """
    if entry.timestamp >= (1 << 38):
        raise ValueError("Timestamp too large for 38-bit storage")

    value = (entry.timestamp << 2) | entry.status
    packed = value.to_bytes(5, byteorder="big")
    with open(filepath, "ab") as f:
        f.write(packed)


def read_entries(filepath: str) -> Generator[LogEntry, None, None]:
    """
    Yield (timestamp, status) from the 5-byte packed binary file.
    """
    with open(filepath, "rb") as f:
        while True:
            chunk: bytes = f.read(5)
            if len(chunk) < 5:
                break

            n = int.from_bytes(chunk, byteorder="big")
            timestamp = n >> 2
            status = Status(n & 0b11)
            yield LogEntry(timestamp, status)


def handle_status_change(
    save_dir: Path, state: Status, previous: LogEntry, webhook: Optional[DiscordWebhook]
) -> LogEntry:
    now = int(time.time())
    month_str = datetime.fromtimestamp(now).strftime("%Y-%m")

    filename = save_dir / f"uptime_{month_str}.log"

    current_entry = LogEntry(now, state)
    write_entry(filename, current_entry)

    if webhook is not None:
        current_time = datetime.fromtimestamp(current_entry.timestamp)
        previous_time = datetime.fromtimestamp(previous.timestamp)
        delta = current_time - previous_time
        webhook.notify(state, delta, previous.status)

    return current_entry


def print_log_entries(entries: list[LogEntry]) -> None:
    print(f"| {'Time':<19} | {'Status':<7} |")
    print(f"|{'-' * 21}|{'-' * 9}|")

    for entry in entries:
        timestr = datetime.fromtimestamp(entry.timestamp).strftime(r"%Y-%m-%d %H:%M:%S")
        print(f"| {timestr:<19} | {entry.status!s:<7} |")


def sum_up_and_downtime(entries: list[LogEntry]) -> UptimeSummary:
    total_uptime = timedelta()
    total_downtime = timedelta()

    # Calculate accumulated of uptime and downtime
    for i in range(1, len(entries)):
        previous = entries[i - 1]
        current = entries[i]
        delta = timedelta(seconds=current.timestamp - previous.timestamp)

        # If delta is negative, the log is invalid
        assert delta >= timedelta(seconds=0)

        logger.trace(f"{previous.status!s:<8} -> {current.status!s:<8}: {delta}")
        match previous.status:
            case Status.UP:
                total_uptime += delta
            case Status.DOWN:
                total_downtime += delta
            case _:
                # Status.STARTED:
                # Ignore time between STARTED and current entry as the next entry after
                # STARTED will have happened immediately and contain uptime status
                #
                # Status.STOPPED:
                # Ignore time between STOPPED and current entry as the monitor didn't
                # run at this time
                pass

    return UptimeSummary(total_uptime, total_downtime)


def daemon_mode(
    ip: str, interval: int, save_dir: Path, webhook: Optional[DiscordWebhook]
) -> None:
    os.makedirs(save_dir, exist_ok=True)
    logger.info(
        f"Pinging {ip} every {interval}s. Saving status and timestamp to directory: "
        f"{save_dir}"
    )

    previous_entry = try_continue_monitoring(save_dir, webhook)

    while True:
        try:
            time.sleep(interval)
            state = is_up(ip)

            if state != previous_entry.status:
                previous_entry = handle_status_change(
                    save_dir, state, previous_entry, webhook
                )

        except KeyboardInterrupt:
            logger.info("Logging status STOPPED")
            handle_status_change(save_dir, Status.STOPPED, previous_entry, webhook)
            break


def log_mode(load_dir: Path) -> int:
    log_files: list[str] = sorted(glob(str(load_dir / "uptime_*.log")))
    if not log_files:
        logger.error(f"No log files found in {load_dir}")
        return 1

    entries: list[LogEntry] = []

    for filepath in log_files:
        entries.extend(read_entries(filepath))

    if not entries:
        logger.warning("Found one or more log files, but they were all empty")
        return 0

    entries.sort(key=lambda e: e.timestamp)

    summary = sum_up_and_downtime(entries)
    print(f"Total uptime: {format_timedelta(summary.uptime)}")
    print(f"Total downtime: {format_timedelta(summary.downtime)}")
    
    print()
    print_log_entries(entries)

    return 0


def get_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Uptime Monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # daemon subcommand
    daemon_parser = subparsers.add_parser("daemon", help="Run monitor daemon")
    daemon_parser.add_argument(
        "--interval", type=int, default=20, help="Check interval in seconds"
    )
    daemon_parser.add_argument(
        "--save", type=Path, required=True, help="Directory to save logs"
    )
    daemon_parser.add_argument("--ip", type=str, required=True, help="IP to monitor")
    daemon_parser.add_argument(
        "--discord-webhook",
        type=str,
        help="Send up and downtime notifications to a Discord webhook",
    )
    daemon_parser.add_argument(
        "--discord-webhook-file",
        type=Path,
        help="Send up and downtime notifications to a Discord webhook. Reads webhook "
        "URL from the specified URL",
    )

    # log subcommand
    log_parser = subparsers.add_parser("log", help="Read and print logs")
    log_parser.add_argument(
        "--load", type=Path, required=True, help="Directory to load logs from"
    )

    args = parser.parse_args()
    return args


def instantiate_logger() -> None:
    logger.remove()
    logger_format = (
        "<green>[{time:HH:mm:ss.SSS}]</green> "
        "<cyan>[{function}</cyan>:<cyan>{line}]</cyan> "
        "<level>[{level}]</level> "
        "<level>{message}</level>"
    )
    logger.add(sys.stdout, format=logger_format)


def main() -> int:
    instantiate_logger()
    args = get_cli_args()

    if args.command == "daemon":
        if args.discord_webhook is None and args.discord_webhook_file is None:
            daemon_mode(args.ip, args.interval, args.save, None)
        else:
            webhook_url: str = args.discord_webhook
            if args.discord_webhook is None:
                try:
                    with open(args.discord_webhook_file, "r") as fd:
                        webhook_url = fd.read().strip()
                except FileNotFoundError:
                    logger.error(
                        "Couldn't find file containing webhook URL at "
                        f"{args.discord_webhook_file}"
                    )
                    return 1
                except PermissionError:
                    logger.error(
                        "No permission to read file containing webhook URL at "
                        f"{args.discord_webhoopk_file}"
                    )
                    return 1
                except Exception as e:
                    logger.exception(e)
                    return 1

            webhook = DiscordWebhook(webhook_url, args.ip)
            daemon_mode(args.ip, args.interval, args.save, webhook)
            return 0
    elif args.command == "log":
        return log_mode(args.load)

    return 1


if __name__ == "__main__":
    sys.exit(main())
