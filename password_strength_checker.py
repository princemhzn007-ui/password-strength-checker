"""
DecodeLabs Industrial Training Kit — Cyber Security
Project 1: Password Strength Checker

Goal:
    Evaluate a password and classify it as Weak, Medium, or Strong
    based on length and character variety (uppercase, digits, symbols).

Key skills demonstrated:
    - String handling
    - Conditional logic
    - Basic security awareness (common password / entropy checks)
"""

import string

# A small sample list of commonly leaked/breached passwords.
# In a real system this would be backed by a much larger dataset
# (e.g. "Have I Been Pwned" password list).
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "password1", "111111", "12345678", "letmein", "iloveyou",
    "admin", "welcome", "monkey", "dragon", "football",
}

MIN_LENGTH = 8
SYMBOLS = set(string.punctuation)


def check_length(password: str) -> bool:
    """Return True if password meets the minimum length requirement."""
    return len(password) >= MIN_LENGTH


def has_uppercase(password: str) -> bool:
    return any(char.isupper() for char in password)


def has_lowercase(password: str) -> bool:
    return any(char.islower() for char in password)


def has_digit(password: str) -> bool:
    return any(char.isdigit() for char in password)


def has_symbol(password: str) -> bool:
    return any(char in SYMBOLS for char in password)


def is_common_password(password: str) -> bool:
    """Check against a known list of weak/leaked passwords (case-insensitive)."""
    return password.lower() in COMMON_PASSWORDS


def evaluate_password(password: str) -> dict:
    """
    Evaluate a password's strength.

    Returns a dict with:
        - strength: "Weak" | "Medium" | "Strong"
        - score: number of criteria met (0-5)
        - details: dict of individual check results
        - suggestions: list of improvement tips
    """
    details = {
        "length_ok": check_length(password),
        "has_uppercase": has_uppercase(password),
        "has_lowercase": has_lowercase(password),
        "has_digit": has_digit(password),
        "has_symbol": has_symbol(password),
        "is_common": is_common_password(password),
    }

    # A known-common password is an automatic fail, regardless of other criteria.
    if details["is_common"]:
        return {
            "strength": "Weak",
            "score": 0,
            "details": details,
            "suggestions": [
                "This password appears in known leaked password lists.",
                "Choose something unique — avoid dictionary words and common patterns.",
            ],
        }

    # Length is a hard gate: too short = automatic Weak.
    if not details["length_ok"]:
        return {
            "strength": "Weak",
            "score": 0,
            "details": details,
            "suggestions": [f"Use at least {MIN_LENGTH} characters."],
        }

    # Score the remaining variety checks.
    score = sum([
        details["has_uppercase"],
        details["has_lowercase"],
        details["has_digit"],
        details["has_symbol"],
    ])

    suggestions = []
    if not details["has_uppercase"]:
        suggestions.append("Add at least one uppercase letter.")
    if not details["has_lowercase"]:
        suggestions.append("Add at least one lowercase letter.")
    if not details["has_digit"]:
        suggestions.append("Add at least one number.")
    if not details["has_symbol"]:
        suggestions.append("Add at least one symbol (e.g. !, @, #, $).")

    if score <= 2:
        strength = "Weak"
    elif score in (3, 4):
        # Long AND fully varied passwords get bumped to Strong.
        strength = "Strong" if (score == 4 and len(password) >= 12) else "Medium"
    else:
        strength = "Strong"

    return {
        "strength": strength,
        "score": score,
        "details": details,
        "suggestions": suggestions,
    }


def print_report(password: str) -> None:
    result = evaluate_password(password)
    bar = {"Weak": "🔴", "Medium": "🟠", "Strong": "🟢"}[result["strength"]]

    print(f"\nPassword: {'*' * len(password)}")
    print(f"Strength: {bar} {result['strength']}  (score: {result['score']}/4)")
    if result["suggestions"]:
        print("Suggestions:")
        for tip in result["suggestions"]:
            print(f"  - {tip}")
    print("-" * 40)


if __name__ == "__main__":
    print("=== DecodeLabs Password Strength Checker ===")
    print("Type a password to check it, or 'quit' to exit.\n")

    while True:
        pwd = input("Enter password: ")
        if pwd.lower() == "quit":
            print("Goodbye!")
            break
        print_report(pwd)
