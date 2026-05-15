#!/usr/bin/env python3

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

BASELINE_FILE = Path("process_baseline.json")
ALERT_LOG_FILE = Path("ids_alerts.log")

FAILED_LOGIN_PATTERNS = [
    r"Failed password",
    r"authentication failure",
    r"invalid user",
    r"Login incorrect",
]

SUSPICIOUS_PROCESS_KEYWORDS = [
    "nc",
    "netcat",
    "nmap",
    "hydra",
    "john",
    "sqlmap",
    "aircrack",
]


def get_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def write_alert(message: str) -> None:
    timestamped_message = f"[{get_timestamp()}] {message}"
    ALERT_LOG_FILE.write_text(
        ALERT_LOG_FILE.read_text(encoding="utf-8") + timestamped_message + "\n"
        if ALERT_LOG_FILE.exists()
        else timestamped_message + "\n",
        encoding="utf-8",
    )
    print(timestamped_message)


def print_banner() -> None:
    print("=" * 72)
    print("              SIMPLE INTRUSION DETECTION SYSTEM")
    print("=" * 72)
    print("Welcome!")
    print("This program monitors unusual system activity.")
    print()
    print("Security Features:")
    print("  - Failed login detection")
    print("  - Process change monitoring")
    print("  - Suspicious process keyword detection")
    print("  - Process baseline creation")
    print("  - Security alert logging")
    print()
    print("Note:")
    print("  Failed login detection works best with Linux authentication logs.")
    print("  You can also test it using a sample_auth.log file.")
    print("=" * 72)
    print()


def read_file_lines(file_path: Path) -> list[str]:
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    return file_path.read_text(encoding="utf-8", errors="ignore").splitlines()


def detect_failed_logins(auth_log_path: str) -> int:
    path = Path(auth_log_path)

    print()
    print("Failed Login Detection")
    print("-" * 72)

    try:
        lines = read_file_lines(path)
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return 1

    failed_login_count = 0

    for line in lines:
        for pattern in FAILED_LOGIN_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                failed_login_count += 1
                write_alert(f"FAILED LOGIN DETECTED: {line}")
                break

    if failed_login_count == 0:
        print("No failed login attempts detected.")
    else:
        print("-" * 72)
        print(f"Total failed login attempts detected: {failed_login_count}")

    print()
    return 0


def get_running_processes() -> dict[str, str]:
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,comm"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception as exc:
        raise RuntimeError(f"Could not read running processes: {exc}")

    processes = {}

    lines = result.stdout.strip().splitlines()

    for line in lines[1:]:
        parts = line.strip().split(maxsplit=1)

        if len(parts) == 2:
            pid, command = parts
            processes[pid] = command

    return processes


def save_process_baseline() -> int:
    print()
    print("Creating Process Baseline")
    print("-" * 72)

    try:
        processes = get_running_processes()
    except RuntimeError as exc:
        print(f"Error: {exc}")
        return 1

    data = {
        "created_at": get_timestamp(),
        "processes": processes,
    }

    BASELINE_FILE.write_text(json.dumps(data, indent=4), encoding="utf-8")

    print(f"Process baseline created successfully.")
    print(f"Total processes saved: {len(processes)}")
    print(f"Baseline file: {BASELINE_FILE.resolve()}")
    print()

    return 0


def load_process_baseline() -> dict[str, str]:
    if not BASELINE_FILE.exists():
        raise FileNotFoundError(
            "Process baseline not found. Create a baseline first."
        )

    data = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    return data.get("processes", {})


def detect_suspicious_processes(processes: dict[str, str]) -> int:
    suspicious_count = 0

    for pid, command in processes.items():
        command_lower = command.lower()

        for keyword in SUSPICIOUS_PROCESS_KEYWORDS:
            if keyword in command_lower:
                suspicious_count += 1
                write_alert(
                    f"SUSPICIOUS PROCESS DETECTED: PID={pid}, COMMAND={command}"
                )
                break

    return suspicious_count


def check_process_changes() -> int:
    print()
    print("Process Change Monitoring")
    print("-" * 72)

    try:
        baseline_processes = load_process_baseline()
        current_processes = get_running_processes()
    except Exception as exc:
        print(f"Error: {exc}")
        return 1

    baseline_pids = set(baseline_processes.keys())
    current_pids = set(current_processes.keys())

    new_pids = current_pids - baseline_pids
    stopped_pids = baseline_pids - current_pids

    changed_processes = 0

    for pid in new_pids:
        changed_processes += 1
        write_alert(
            f"NEW PROCESS DETECTED: PID={pid}, COMMAND={current_processes[pid]}"
        )

    for pid in stopped_pids:
        changed_processes += 1
        write_alert(
            f"PROCESS STOPPED: PID={pid}, COMMAND={baseline_processes[pid]}"
        )

    suspicious_count = detect_suspicious_processes(current_processes)

    if changed_processes == 0 and suspicious_count == 0:
        print("No unusual process changes detected.")
    else:
        print("-" * 72)
        print(f"Process changes detected: {changed_processes}")
        print(f"Suspicious processes detected: {suspicious_count}")

    print()
    return 0


def show_log_file() -> int:
    print()
    print("IDS Alert Log")
    print("-" * 72)

    if not ALERT_LOG_FILE.exists():
        print("No alert log found yet.")
        print()
        return 0

    content = ALERT_LOG_FILE.read_text(encoding="utf-8")

    if not content.strip():
        print("Alert log is empty.")
    else:
        print(content)

    print()
    return 0


def create_sample_auth_log() -> int:
    sample_content = """May 15 10:22:01 ubuntu sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 53422 ssh2
May 15 10:23:18 ubuntu sshd[1235]: Failed password for root from 192.168.1.11 port 53423 ssh2
May 15 10:24:02 ubuntu login[1236]: authentication failure; user=student
May 15 10:25:44 ubuntu sshd[1237]: Accepted password for user from 192.168.1.12 port 53424 ssh2
"""

    Path("sample_auth.log").write_text(sample_content, encoding="utf-8")

    print()
    print("Sample authentication log created successfully.")
    print("File: sample_auth.log")
    print()
    return 0


def print_menu() -> None:
    print("Main Menu")
    print("-" * 72)
    print("1. Create process baseline")
    print("2. Check process changes")
    print("3. Detect failed logins")
    print("4. Create sample authentication log")
    print("5. Show IDS alert log")
    print("6. Exit")
    print("-" * 72)


def ask_menu_choice() -> str:
    while True:
        choice = input("Enter your choice (1/2/3/4/5/6): ").strip()

        if choice in {"1", "2", "3", "4", "5", "6"}:
            return choice

        print("Invalid choice. Please enter a number from 1 to 6.")


def menu_mode() -> int:
    print_banner()

    while True:
        print_menu()
        choice = ask_menu_choice()

        if choice == "1":
            save_process_baseline()

        elif choice == "2":
            check_process_changes()

        elif choice == "3":
            auth_log_path = input(
                "Enter authentication log path "
                "(default: sample_auth.log): "
            ).strip()

            if not auth_log_path:
                auth_log_path = "sample_auth.log"

            detect_failed_logins(auth_log_path)

        elif choice == "4":
            create_sample_auth_log()

        elif choice == "5":
            show_log_file()

        elif choice == "6":
            print()
            print("Thank you for using the Simple Intrusion Detection System.")
            return 0


def show_cli_examples() -> None:
    print()
    print("Command-Line Usage Examples")
    print("-" * 72)
    print("Run interactive menu:")
    print("  python3 main.py")
    print()
    print("Create process baseline:")
    print("  python3 main.py --init-baseline")
    print()
    print("Check process changes:")
    print("  python3 main.py --check-processes")
    print()
    print("Create sample authentication log:")
    print("  python3 main.py --create-sample-log")
    print()
    print("Detect failed logins from sample log:")
    print("  python3 main.py --auth-log sample_auth.log")
    print()
    print("Detect failed logins from Linux auth log:")
    print("  sudo python3 main.py --auth-log /var/log/auth.log")
    print()
    print("Run all checks:")
    print("  python3 main.py --all --auth-log sample_auth.log")
    print("-" * 72)
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simple Intrusion Detection System"
    )

    parser.add_argument(
        "--init-baseline",
        action="store_true",
        help="Create a baseline of currently running processes",
    )

    parser.add_argument(
        "--check-processes",
        action="store_true",
        help="Check for new, stopped, or suspicious processes",
    )

    parser.add_argument(
        "--auth-log",
        type=str,
        help="Path to authentication log file for failed login detection",
    )

    parser.add_argument(
        "--create-sample-log",
        action="store_true",
        help="Create a sample authentication log for testing",
    )

    parser.add_argument(
        "--show-log",
        action="store_true",
        help="Show IDS alert log",
    )

    parser.add_argument(
        "--examples",
        action="store_true",
        help="Show command-line usage examples",
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Run failed login detection and process monitoring",
    )

    return parser.parse_args()


def run_cli_mode(args: argparse.Namespace) -> int:
    exit_code = 0

    if args.examples:
        show_cli_examples()

    if args.create_sample_log:
        exit_code |= create_sample_auth_log()

    if args.init_baseline:
        exit_code |= save_process_baseline()

    if args.check_processes:
        exit_code |= check_process_changes()

    if args.auth_log:
        exit_code |= detect_failed_logins(args.auth_log)

    if args.show_log:
        exit_code |= show_log_file()

    if args.all:
        auth_log = args.auth_log or "sample_auth.log"

        if not BASELINE_FILE.exists():
            print("Process baseline does not exist. Creating one first...")
            save_process_baseline()

        exit_code |= detect_failed_logins(auth_log)
        exit_code |= check_process_changes()

    return exit_code


def main() -> int:
    args = parse_args()

    cli_options_used = any([
        args.init_baseline,
        args.check_processes,
        args.auth_log is not None,
        args.create_sample_log,
        args.show_log,
        args.examples,
        args.all,
    ])

    if not cli_options_used:
        return menu_mode()

    return run_cli_mode(args)


if __name__ == "__main__":
    sys.exit(main())
