#!/usr/bin/env python3
"""Run the STUN-enabled Suricata Docker image on a pcap and summarize alerts.

This helper assumes you have already built the Docker image described in the
README (defaults to the tag ``suricata-stun``). It mounts the pcap directory,
rule directory, and a log output directory into the container, executes
Suricata, and then parses ``fast.log`` to report alert counts by SID.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Dict

DEFAULT_IMAGE = "suricata-stun"
DEFAULT_PCAP = Path("qa/pcaps/stun_3rules_60pkts.pcap")
DEFAULT_RULES = Path("rules/stun.rules")
DEFAULT_LOG_DIR = Path("log-docker")


class DockerReplayError(RuntimeError):
    """Raised when replaying the capture inside Docker fails."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image",
        default=DEFAULT_IMAGE,
        help="Docker image tag or ID to run (default: %(default)s)",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        default=DEFAULT_PCAP,
        help="Path to the pcap to replay (default: %(default)s)",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES,
        help="Path to the rules file (default: %(default)s)",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=DEFAULT_LOG_DIR,
        help="Directory for Suricata logs on the host (default: %(default)s)",
    )
    parser.add_argument(
        "--preserve-logs",
        action="store_true",
        help="Do not delete existing fast.log before replaying",
    )
    return parser.parse_args()


def ensure_paths(pcap: Path, rules: Path, log_dir: Path) -> None:
    if not pcap.is_file():
        raise DockerReplayError(f"pcap not found: {pcap}")
    if not rules.is_file():
        raise DockerReplayError(f"rules file not found: {rules}")
    log_dir.mkdir(parents=True, exist_ok=True)


def clear_existing_logs(log_dir: Path, preserve: bool) -> None:
    fast_log = log_dir / "fast.log"
    if preserve:
        return
    if fast_log.exists():
        fast_log.unlink()


def build_docker_command(image: str, pcap: Path, rules: Path, log_dir: Path) -> list[str]:
    pcap_mount = pcap.resolve().parent
    rules_mount = rules.resolve().parent
    pcap_inside = Path("/pcaps") / pcap.name
    rules_inside = Path("/rules") / rules.name
    return [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{pcap_mount}:/pcaps",
        "-v",
        f"{rules_mount}:/rules",
        "-v",
        f"{log_dir.resolve()}:/var/log/suricata",
        image,
        "-r",
        str(pcap_inside),
        "-S",
        str(rules_inside),
        "-c",
        "/etc/suricata/suricata.yaml",
        "--set",
        "default-log-dir=/var/log/suricata",
        "-l",
        "/var/log/suricata",
    ]


def run_docker_replay(command: list[str]) -> None:
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError as exc:
        raise DockerReplayError("docker is not installed or not in PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise DockerReplayError(f"docker run failed with exit code {exc.returncode}") from exc


def parse_fast_log(log_dir: Path) -> Dict[str, int]:
    fast_log = log_dir / "fast.log"
    if not fast_log.is_file():
        raise DockerReplayError(f"fast.log not found in {log_dir}")

    sid_pattern = re.compile(r"sid:(\d+)")
    counts: Counter[str] = Counter()

    with fast_log.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            match = sid_pattern.search(line)
            if match:
                counts[match.group(1)] += 1

    return dict(counts)


def print_summary(counts: Dict[str, int]) -> None:
    total = sum(counts.values())
    print(f"Total alerts: {total}")
    if not counts:
        print("No SIDs observed in fast.log")
        return
    print("Alerts by SID:")
    for sid, cnt in sorted(counts.items(), key=lambda item: item[0]):
        print(f"  SID {sid}: {cnt}")


def main() -> None:
    args = parse_args()
    ensure_paths(args.pcap, args.rules, args.log_dir)
    clear_existing_logs(args.log_dir, args.preserve_logs)
    command = build_docker_command(args.image, args.pcap, args.rules, args.log_dir)
    print("Running:", " ".join(command))
    run_docker_replay(command)
    counts = parse_fast_log(args.log_dir)
    print_summary(counts)


if __name__ == "__main__":
    try:
        main()
    except DockerReplayError as error:
        raise SystemExit(f"Error: {error}")
