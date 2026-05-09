#!/usr/bin/env python3

import hashlib
import json
import os
import sys
from pathlib import Path
from datetime import datetime

HASH_DATABASE = "hashes.json"
LOG_FILE = "integrity_logs.txt"
MONITORED_FOLDER = "monitored_files"


def calculate_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def load_hash_database() -> dict:
    if not os.path.exists(HASH_DATABASE):
        return {}

    try:
        with open(HASH_DATABASE, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return {}


def save_hash_database(data: dict) -> None:
    with open(HASH_DATABASE, "w") as file:
        json.dump(data, file, indent=4)


def write_log(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{timestamp}] {message}\n")


def create_monitored_folder() -> None:
    Path(MONITORED_FOLDER).mkdir(exist_ok=True)


def scan_files() -> list[Path]:
    folder = Path(MONITORED_FOLDER)

    return [file for file in folder.iterdir() if file.is_file()]


def create_baseline() -> None:
    print("\nCreating integrity baseline...")
    print("-" * 60)

    files = scan_files()

    if not files:
        print("No files found inside monitored_files folder.")
        return

    database = {}

    for file in files:
        file_hash = calculate_sha256(file)

        database[str(file)] = {
            "hash": file_hash,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        print(f"Baseline saved: {file.name}")

    save_hash_database(database)

    write_log("Baseline hashes created.")

    print("\nBaseline creation completed successfully.")


def verify_integrity() -> None:
    print("\nRunning integrity scan...")
    print("-" * 60)

    current_files = scan_files()

    if not current_files:
        print("No monitored files found.")
        return

    database = load_hash_database()

    if not database:
        print("No baseline database found.")
        return

    current_paths = set(str(file) for file in current_files)
    stored_paths = set(database.keys())

    modified_files = []
    new_files = []
    deleted_files = []

    for file in current_files:
        current_hash = calculate_sha256(file)

        if str(file) not in database:
            new_files.append(file.name)
            continue

        stored_hash = database[str(file)]["hash"]

        if current_hash != stored_hash:
            modified_files.append(file.name)

    for stored_file in stored_paths:
        if stored_file not in current_paths:
            deleted_files.append(Path(stored_file).name)

    print("\nIntegrity Scan Results")
    print("=" * 60)

    if not modified_files and not new_files and not deleted_files:
        print("All monitored files are safe.")
        write_log("Integrity scan passed successfully.")
        return

    if modified_files:
        print("\nMODIFIED FILES DETECTED:")
        for file in modified_files:
            print(f"  [!] {file}")
            write_log(f"WARNING: Modified file detected -> {file}")

    if new_files:
        print("\nNEW FILES DETECTED:")
        for file in new_files:
            print(f"  [+] {file}")
            write_log(f"INFO: New file detected -> {file}")

    if deleted_files:
        print("\nDELETED FILES DETECTED:")
        for file in deleted_files:
            print(f"  [-] {file}")
            write_log(f"WARNING: Deleted file detected -> {file}")

    print("\nSecurity scan completed.")


def show_database() -> None:
    database = load_hash_database()

    print("\nStored Integrity Database")
    print("=" * 60)

    if not database:
        print("No hashes stored.")
        return

    for file_path, info in database.items():
        print(f"\nFile: {file_path}")
        print(f"SHA-256: {info['hash']}")
        print(f"Created: {info['created_at']}")


def show_logs() -> None:
    print("\nSecurity Logs")
    print("=" * 60)

    if not os.path.exists(LOG_FILE):
        print("No logs found.")
        return

    with open(LOG_FILE, "r") as file:
        logs = file.read()

    print(logs)


def print_banner() -> None:
    print("=" * 72)
    print("             FILE INTEGRITY MONITORING SYSTEM")
    print("=" * 72)
    print("This cybersecurity tool monitors files using SHA-256 hashing.")
    print("It helps detect unauthorized modifications and tampering.")
    print()
    print("Security Features:")
    print("  - SHA-256 integrity verification")
    print("  - Multiple file monitoring")
    print("  - Tampering detection")
    print("  - Deleted file detection")
    print("  - New file detection")
    print("  - Security logging")
    print("  - JSON hash database")
    print("=" * 72)
    print()


def print_menu() -> None:
    print("Main Menu")
    print("-" * 60)
    print("1. Create integrity baseline")
    print("2. Verify file integrity")
    print("3. Show stored hash database")
    print("4. Show security logs")
    print("5. Exit")
    print("-" * 60)


def get_choice() -> str:
    while True:
        choice = input("Enter your choice (1-5): ").strip()

        if choice in {"1", "2", "3", "4", "5"}:
            return choice

        print("Invalid option.")


def main() -> int:
    create_monitored_folder()

    print_banner()

    while True:
        print_menu()

        choice = get_choice()

        if choice == "1":
            create_baseline()

        elif choice == "2":
            verify_integrity()

        elif choice == "3":
            show_database()

        elif choice == "4":
            show_logs()

        elif choice == "5":
            print("\nExiting File Integrity Monitoring System.")
            return 0


if __name__ == "__main__":
    sys.exit(main())