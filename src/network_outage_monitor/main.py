import argparse
import os
import time
from datetime import datetime
from typing import Generator

import requests


def is_site_up(url: str) -> bool:
    try:
        response = requests.head(url, timeout=5)
        return response.ok
    except requests.RequestException:
        return False


def write_entry(filepath: str, timestamp: int, status: bool) -> None:
    """
    Write a 4-byte packed record:
    - 31 bits: timestamp
    - 1 bit: status (1 = up, 0 = down)
    """
    if timestamp >= (1 << 31):
        raise ValueError("Timestamp too large for 31-bit storage")

    value = (timestamp << 1) | int(status)
    packed = value.to_bytes(4, byteorder="big")
    with open(filepath, "ab") as f:
        f.write(packed)


def read_entries(filepath: str) -> Generator[tuple[int, bool]]:
    """
    Yield (timestamp, status) from the 4-byte packed binary file.
    """
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(4)
            if len(chunk) < 4:
                break
            value = int.from_bytes(chunk, byteorder="big")
            timestamp = value >> 1
            status = value & 1
            yield timestamp, bool(status)


def daemon_mode(url: str, interval: int, save_dir: str) -> None:
    os.makedirs(save_dir, exist_ok=True)
    print(f"Starting uptime monitor every {interval}s. Saving to: {save_dir}")

    while True:
        now = int(time.time())
        status = is_site_up(url)
        month_str = datetime.fromtimestamp(now).strftime("%Y-%m")
        filename = os.path.join(save_dir, f"uptime_{month_str}.log")
        write_entry(filename, now, status)
        time.sleep(interval)


def log_mode(load_dir: str) -> None:
    from glob import glob

    log_files = sorted(glob(os.path.join(load_dir, "uptime_*.log")))
    if not log_files:
        print("No log files found.")
        return

    print(f"| {'Time':<20} | Status |")
    print(f"|{'-'*21}|--------|")

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
    daemon_parser.add_argument("--url", type=str, required=True, help="URL to monitor")

    # log subcommand
    log_parser = subparsers.add_parser("log", help="Read and print logs")
    log_parser.add_argument(
        "--load", type=str, required=True, help="Directory to load logs from"
    )

    args = parser.parse_args()

    if args.command == "daemon":
        daemon_mode(args.url, args.interval, args.save)
    elif args.command == "log":
        log_mode(args.load)


if __name__ == "__main__":
    main()
