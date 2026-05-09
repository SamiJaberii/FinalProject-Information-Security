#!/usr/bin/env python3

import argparse
import secrets
import string
import sys
from pathlib import Path

AMBIGUOUS_CHARS = "Il1O0"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

MIN_PASSWORD_LENGTH = 4
MAX_PASSWORD_LENGTH = 64
MAX_PASSWORD_COUNT = 20

COMPLEXITY_PRESETS = {
    "low": {
        "lowercase": True,
        "uppercase": False,
        "digits": True,
        "symbols": False,
        "description": "Lowercase letters + digits",
    },
    "medium": {
        "lowercase": True,
        "uppercase": True,
        "digits": True,
        "symbols": False,
        "description": "Lowercase + uppercase + digits",
    },
    "high": {
        "lowercase": True,
        "uppercase": True,
        "digits": True,
        "symbols": True,
        "description": "Lowercase + uppercase + digits + symbols",
    },
}


def remove_ambiguous(text: str) -> str:
    return "".join(ch for ch in text if ch not in AMBIGUOUS_CHARS)


def get_character_sets(
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_ambiguous: bool,
) -> list[str]:
    char_sets = []

    if use_lowercase:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = remove_ambiguous(chars)
        if chars:
            char_sets.append(chars)

    if use_uppercase:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = remove_ambiguous(chars)
        if chars:
            char_sets.append(chars)

    if use_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = remove_ambiguous(chars)
        if chars:
            char_sets.append(chars)

    if use_symbols:
        char_sets.append(SYMBOLS)

    return char_sets


def build_pool(char_sets: list[str]) -> str:
    return "".join(char_sets)


def validate_options(length: int, char_sets: list[str]) -> None:
    if length < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password length must be at least {MIN_PASSWORD_LENGTH}."
        )

    if length > MAX_PASSWORD_LENGTH:
        raise ValueError(
            f"Password length cannot be more than {MAX_PASSWORD_LENGTH}."
        )

    if not char_sets:
        raise ValueError("No character groups selected.")

    if length < len(char_sets):
        raise ValueError(
            "Password length is too short for the selected character groups."
        )


def apply_complexity_preset(complexity: str) -> tuple[bool, bool, bool, bool]:
    preset = COMPLEXITY_PRESETS[complexity]
    return (
        preset["lowercase"],
        preset["uppercase"],
        preset["digits"],
        preset["symbols"],
    )


def generate_password(
    length: int,
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_ambiguous: bool,
) -> str:
    char_sets = get_character_sets(
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
        exclude_ambiguous=exclude_ambiguous,
    )

    validate_options(length, char_sets)

    pool = build_pool(char_sets)

    password_chars = [secrets.choice(group) for group in char_sets]

    while len(password_chars) < length:
        password_chars.append(secrets.choice(pool))

    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


def evaluate_strength(password: str) -> str:
    length = len(password)

    has_lower = any(ch.islower() for ch in password)
    has_upper = any(ch.isupper() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(ch in SYMBOLS for ch in password)

    score = 0

    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1

    if has_lower:
        score += 1
    if has_upper:
        score += 1
    if has_digit:
        score += 1
    if has_symbol:
        score += 1

    if score <= 3:
        return "Weak"
    elif score <= 5:
        return "Moderate"
    elif score <= 6:
        return "Strong"
    else:
        return "Very Strong"


def save_passwords(passwords: list[str], output_file: str) -> Path:
    path = Path(output_file)

    if path.suffix == "":
        path = path.with_suffix(".txt")

    path.write_text("\n".join(passwords) + "\n", encoding="utf-8")

    return path.resolve()


def print_banner() -> None:
    print("=" * 72)
    print("                 SECURE PASSWORD GENERATOR PROGRAM")
    print("=" * 72)
    print("Welcome!")
    print("This program generates strong random passwords securely.")
    print("It helps users create safer passwords with customizable options.")
    print()
    print("Security Features:")
    print("  - Secure cryptographic randomness")
    print("  - Password strength evaluation")
    print("  - Configurable complexity presets")
    print("  - Symbol inclusion/exclusion")
    print("  - Ambiguous character removal")
    print("  - Multiple password generation")
    print("  - Save passwords securely to file")
    print()
    print("WARNING:")
    print("  Do not reuse passwords across multiple accounts.")
    print("=" * 72)
    print()


def print_menu() -> None:
    print("Main Menu")
    print("-" * 72)
    print("1. Generate password interactively")
    print("2. Show command-line usage examples")
    print("3. Exit")
    print("-" * 72)


def show_cli_help_examples() -> None:
    print()
    print("Command-Line Usage Examples")
    print("-" * 72)
    print("Default interactive mode:")
    print("  python3 main.py")
    print()
    print("Generate one high-complexity password:")
    print("  python3 main.py --length 16 --complexity high")
    print()
    print("Generate medium complexity password with symbols:")
    print("  python3 main.py --length 20 --complexity medium --symbols")
    print()
    print("Generate 3 passwords and save them:")
    print(
        "  python3 main.py --length 18 --complexity high --count 3 -o passwords.txt"
    )
    print()
    print("Exclude ambiguous characters:")
    print("  python3 main.py --length 16 --complexity high --exclude-ambiguous")
    print("-" * 72)
    print()


def ask_menu_choice() -> str:
    while True:
        choice = input("Enter your choice (1/2/3): ").strip()

        if choice in {"1", "2", "3"}:
            return choice

        print("Invalid choice. Please enter 1, 2, or 3.")


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "

    while True:
        answer = input(prompt + suffix).strip().lower()

        if answer == "":
            return default

        if answer in {"y", "yes"}:
            return True

        if answer in {"n", "no"}:
            return False

        print("Please enter yes or no.")


def print_complexity_options() -> None:
    print()
    print("Available complexity levels:")

    for key, value in COMPLEXITY_PRESETS.items():
        print(f"  - {key:<6} : {value['description']}")

    print()


def ask_complexity() -> str:
    print_complexity_options()

    while True:
        value = input(
            "Choose complexity (low / medium / high): "
        ).strip().lower()

        if value in COMPLEXITY_PRESETS:
            return value

        print("Invalid choice. Please enter low, medium, or high.")


def ask_length() -> int:
    while True:
        value = input(
            f"Enter password length ({MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH}): "
        ).strip()

        if not value.isdigit():
            print("Please enter a valid number.")
            continue

        length = int(value)

        if length < MIN_PASSWORD_LENGTH:
            print(
                f"Password length must be at least {MIN_PASSWORD_LENGTH}."
            )
            continue

        if length > MAX_PASSWORD_LENGTH:
            print(
                f"Password length cannot be more than {MAX_PASSWORD_LENGTH}."
            )
            continue

        return length


def ask_count() -> int:
    while True:
        value = input(
            f"How many passwords do you want to generate? (1-{MAX_PASSWORD_COUNT}): "
        ).strip()

        if not value.isdigit():
            print("Please enter a valid number.")
            continue

        count = int(value)

        if count < 1:
            print("Please enter a number greater than 0.")
            continue

        if count > MAX_PASSWORD_COUNT:
            print(
                f"You can generate maximum {MAX_PASSWORD_COUNT} passwords at once."
            )
            continue

        return count


def ask_output_file() -> str | None:
    save_to_file = ask_yes_no(
        "Do you want to save the generated password(s) to a file?",
        default=False,
    )

    if not save_to_file:
        return None

    file_name = input(
        "Enter output file name (default: passwords.txt): "
    ).strip()

    return file_name if file_name else "passwords.txt"


def interactive_generate() -> int:
    print()
    print("Interactive Password Generation")
    print("-" * 72)

    complexity = ask_complexity()
    length = ask_length()

    preset_lower, preset_upper, preset_digits, preset_symbols = (
        apply_complexity_preset(complexity)
    )

    print()
    print("Selected preset includes:")
    print(f"  Lowercase letters : {'Yes' if preset_lower else 'No'}")
    print(f"  Uppercase letters : {'Yes' if preset_upper else 'No'}")
    print(f"  Digits            : {'Yes' if preset_digits else 'No'}")
    print(f"  Symbols           : {'Yes' if preset_symbols else 'No'}")
    print()

    use_symbols = preset_symbols

    if complexity != "high":
        if ask_yes_no(
            "Do you want to include symbols too?",
            default=False
        ):
            use_symbols = True
    else:
        if ask_yes_no(
            "Do you want to disable symbols?",
            default=False
        ):
            use_symbols = False

    exclude_ambiguous = ask_yes_no(
        "Do you want to exclude ambiguous characters (I, l, 1, O, 0)?",
        default=True,
    )

    count = ask_count()

    output_file = ask_output_file()

    use_lowercase, use_uppercase, use_digits, _ = (
        apply_complexity_preset(complexity)
    )

    print()
    print("Generating password(s)...")
    print("-" * 72)

    try:
        passwords = []

        for index in range(count):
            password = generate_password(
                length=length,
                use_lowercase=use_lowercase,
                use_uppercase=use_uppercase,
                use_digits=use_digits,
                use_symbols=use_symbols,
                exclude_ambiguous=exclude_ambiguous,
            )

            passwords.append(password)

            print(f"Password {index + 1}: {password}")
            print(f"Strength   : {evaluate_strength(password)}")
            print("-" * 40)

        if output_file:
            saved_path = save_passwords(passwords, output_file)
            print(f"Saved password(s) to: {saved_path}")

        print("Password generation completed successfully.")
        print()

        return 0

    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1


def menu_mode() -> int:
    print_banner()

    while True:
        print_menu()

        choice = ask_menu_choice()

        if choice == "1":
            interactive_generate()

        elif choice == "2":
            show_cli_help_examples()

        elif choice == "3":
            print()
            print("Thank you for using the Secure Password Generator.")
            return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Secure Password Generator - Generate strong random passwords."
    )

    parser.add_argument(
        "-l",
        "--length",
        type=int,
        help="Length of each password"
    )

    parser.add_argument(
        "-c",
        "--complexity",
        choices=["low", "medium", "high"],
        help="Password complexity preset",
    )

    parser.add_argument(
        "--symbols",
        action="store_true",
        help="Force symbols on"
    )

    parser.add_argument(
        "--no-symbols",
        action="store_true",
        help="Force symbols off"
    )

    parser.add_argument(
        "--no-lowercase",
        action="store_true",
        help="Disable lowercase letters"
    )

    parser.add_argument(
        "--no-uppercase",
        action="store_true",
        help="Disable uppercase letters"
    )

    parser.add_argument(
        "--no-digits",
        action="store_true",
        help="Disable digits"
    )

    parser.add_argument(
        "--exclude-ambiguous",
        action="store_true",
        help="Exclude ambiguous characters",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of passwords to generate",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Save generated password(s) to a file"
    )

    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run menu and interactive mode",
    )

    return parser.parse_args()


def resolve_character_options(
    args: argparse.Namespace
) -> tuple[bool, bool, bool, bool]:

    complexity = args.complexity or "high"

    use_lowercase, use_uppercase, use_digits, use_symbols = (
        apply_complexity_preset(complexity)
    )

    if args.symbols:
        use_symbols = True

    if args.no_symbols:
        use_symbols = False

    if args.no_lowercase:
        use_lowercase = False

    if args.no_uppercase:
        use_uppercase = False

    if args.no_digits:
        use_digits = False

    return use_lowercase, use_uppercase, use_digits, use_symbols


def print_cli_summary(
    length: int,
    complexity: str,
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_ambiguous: bool,
    count: int,
) -> None:

    print("Generation Settings")
    print("-" * 72)
    print(f"Length             : {length}")
    print(f"Complexity Preset  : {complexity}")
    print(f"Lowercase          : {'Yes' if use_lowercase else 'No'}")
    print(f"Uppercase          : {'Yes' if use_uppercase else 'No'}")
    print(f"Digits             : {'Yes' if use_digits else 'No'}")
    print(f"Symbols            : {'Yes' if use_symbols else 'No'}")
    print(f"Exclude Ambiguous  : {'Yes' if exclude_ambiguous else 'No'}")
    print(f"Password Count     : {count}")
    print("-" * 72)
    print()


def run_cli_mode(args: argparse.Namespace) -> int:
    try:
        length = args.length if args.length is not None else 16
        complexity = args.complexity or "high"

        if args.count < 1:
            raise ValueError("--count must be at least 1.")

        if args.count > MAX_PASSWORD_COUNT:
            raise ValueError(
                f"--count cannot be more than {MAX_PASSWORD_COUNT}."
            )

        use_lowercase, use_uppercase, use_digits, use_symbols = (
            resolve_character_options(args)
        )

        print_cli_summary(
            length=length,
            complexity=complexity,
            use_lowercase=use_lowercase,
            use_uppercase=use_uppercase,
            use_digits=use_digits,
            use_symbols=use_symbols,
            exclude_ambiguous=args.exclude_ambiguous,
            count=args.count,
        )

        passwords = []

        for index in range(args.count):
            password = generate_password(
                length=length,
                use_lowercase=use_lowercase,
                use_uppercase=use_uppercase,
                use_digits=use_digits,
                use_symbols=use_symbols,
                exclude_ambiguous=args.exclude_ambiguous,
            )

            passwords.append(password)

            print(f"Password {index + 1}: {password}")
            print(f"Strength   : {evaluate_strength(password)}")
            print("-" * 40)

        if args.output:
            saved_path = save_passwords(passwords, args.output)
            print(f"Saved password(s) to: {saved_path}")

        return 0

    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1


def main() -> int:
    args = parse_args()

    cli_options_used = any([
        args.length is not None,
        args.complexity is not None,
        args.symbols,
        args.no_symbols,
        args.no_lowercase,
        args.no_uppercase,
        args.no_digits,
        args.exclude_ambiguous,
        args.count != 1,
        args.output is not None,
    ])

    if args.interactive or not cli_options_used:
        return menu_mode()

    return run_cli_mode(args)


if __name__ == "__main__":
    sys.exit(main())