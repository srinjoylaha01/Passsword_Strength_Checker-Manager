#!/usr/bin/env python3
"""
Password Audit Toolkit (CLI)
=============================
A command-line password strength checker and encrypted local password
manager. Mirrors the browser version: entropy/pattern-based strength
analysis, a secure password generator, and an AES-256-GCM encrypted vault
keyed by a master password (PBKDF2-SHA256, 150,000 iterations).

Dependencies:
    pip install cryptography

Optional (better strength scoring if installed):
    pip install zxcvbn

Run:
    python3 password_audit.py
"""

import base64
import getpass
import json
import math
import os
import re
import secrets
import string
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

try:
    import zxcvbn  # type: ignore
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False


VAULT_DIR = Path.home() / ".password_audit"
VAULT_FILE = VAULT_DIR / "vault.json"
PBKDF2_ITERATIONS = 150_000
SALT_LEN = 16
IV_LEN = 12
KEY_LEN = 32  # 256-bit AES key
VERIFIER_PLAINTEXT = b"PWAUDIT_VAULT_OK"


# --------------------------------------------------------------------------
# Strength analysis
# --------------------------------------------------------------------------

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein",
    "welcome", "monkey", "dragon", "iloveyou", "football", "1234567",
    "sunshine", "master", "login", "princess", "qwertyuiop", "solo",
    "passw0rd", "starwars", "freedom", "whatever", "trustno1",
    "superman", "batman", "hello", "charlie", "donald", "shadow",
    "michael", "jennifer", "hunter", "summer", "access", "flower",
    "secret", "hockey",
}

SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

SCORE_LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"]


def has_sequential(pw: str) -> bool:
    lower = pw.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - 2):
            fwd = seq[i:i + 3]
            rev = fwd[::-1]
            if fwd in lower or rev in lower:
                return True
    return False


def has_repeated(pw: str) -> bool:
    return re.search(r"(.)\1\1", pw) is not None


def pool_size(pw: str) -> int:
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"[0-9]", pw):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        pool += 32
    return pool or 1


def estimate_entropy_bits(pw: str) -> int:
    if not pw:
        return 0
    return round(len(pw) * math.log2(pool_size(pw)))


def fallback_score(entropy_bits: int) -> int:
    if entropy_bits < 28:
        return 0
    if entropy_bits < 40:
        return 1
    if entropy_bits < 60:
        return 2
    if entropy_bits < 80:
        return 3
    return 4


@dataclass
class AnalysisResult:
    score: int
    label: str
    entropy_bits: int
    checks: list = field(default_factory=list)  # list of (label, passed)
    warning: Optional[str] = None
    crack_times: Optional[dict] = None  # only populated if zxcvbn is available


def analyze_password(pw: str) -> AnalysisResult:
    entropy_bits = estimate_entropy_bits(pw)
    crack_times = None

    if ZXCVBN_AVAILABLE:
        result = zxcvbn.zxcvbn(pw)
        score = result["score"]
        ct = result["crack_times_display"]
        crack_times = {
            "offline_fast": ct["offline_fast_hashing_1e10_per_second"],
            "offline_slow": ct["offline_slow_hashing_1e4_per_second"],
            "online_throttled": ct["online_throttling_100_per_hour"],
        }
    else:
        score = fallback_score(entropy_bits)

    checks = [
        ("At least 12 characters", len(pw) >= 12),
        ("Mixes upper and lower case", bool(re.search(r"[a-z]", pw)) and bool(re.search(r"[A-Z]", pw))),
        ("Contains a digit", bool(re.search(r"[0-9]", pw))),
        ("Contains a symbol", bool(re.search(r"[^a-zA-Z0-9]", pw))),
        ("Not a known common password", pw.lower() not in COMMON_PASSWORDS),
        ("No sequential runs (abc, 123, qwe)", not has_sequential(pw)),
        ("No repeated-character runs (aaa, 111)", not has_repeated(pw)),
    ]

    warning = None
    if pw.lower() in COMMON_PASSWORDS:
        warning = "This exact password appears on well-known leaked-password lists. Treat it as already compromised."
    elif any(not passed for _, passed in checks):
        warning = "Address the failed checks above to raise resistance to offline guessing attacks."

    return AnalysisResult(
        score=score,
        label=SCORE_LABELS[score],
        entropy_bits=entropy_bits,
        checks=checks,
        warning=warning,
        crack_times=crack_times,
    )


def print_analysis(pw: str) -> None:
    if not pw:
        print("  (empty password)")
        return
    result = analyze_password(pw)
    bar_width = 30
    filled = round((result.score + 1) / 5 * bar_width)
    bar = "#" * filled + "-" * (bar_width - filled)

    print(f"\n  [{bar}]  {result.label}  (score {result.score}/4)")
    print(f"  Estimated entropy: {result.entropy_bits} bits")

    if result.crack_times:
        print(f"  Crack time (offline, fast hash):  {result.crack_times['offline_fast']}")
        print(f"  Crack time (offline, slow hash):  {result.crack_times['offline_slow']}")
        print(f"  Crack time (online, throttled):   {result.crack_times['online_throttled']}")
    else:
        print("  (install 'zxcvbn' for pattern-based crack-time estimates: pip install zxcvbn)")

    print("\n  Checklist:")
    for label, passed in result.checks:
        mark = "[x]" if passed else "[ ]"
        print(f"    {mark} {label}")

    if result.warning:
        print(f"\n  ! {result.warning}")
    print()


# --------------------------------------------------------------------------
# Password generation
# --------------------------------------------------------------------------

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?"
AMBIGUOUS = set("0O1lI")


def generate_password(length: int = 18, use_lower=True, use_upper=True,
                       use_digits=True, use_symbols=True,
                       exclude_ambiguous=False) -> str:
    pool = ""
    if use_lower:
        pool += LOWER
    if use_upper:
        pool += UPPER
    if use_digits:
        pool += DIGITS
    if use_symbols:
        pool += SYMBOLS
    if exclude_ambiguous:
        pool = "".join(c for c in pool if c not in AMBIGUOUS)
    if not pool:
        raise ValueError("At least one character set must be selected.")
    # secrets.choice uses a CSPRNG (os.urandom under the hood) — the Python
    # equivalent of the browser's crypto.getRandomValues, not random.choice.
    return "".join(secrets.choice(pool) for _ in range(length))


# --------------------------------------------------------------------------
# Encrypted vault (PBKDF2 + AES-256-GCM), stored at ~/.password_audit/vault.json
# --------------------------------------------------------------------------

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_bytes(key: bytes, plaintext: bytes) -> str:
    aesgcm = AESGCM(key)
    iv = os.urandom(IV_LEN)
    ct = aesgcm.encrypt(iv, plaintext, None)
    return base64.b64encode(iv).decode() + "." + base64.b64encode(ct).decode()


def decrypt_bytes(key: bytes, packed: str) -> bytes:
    iv_b64, ct_b64 = packed.split(".")
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ct, None)


def vault_exists() -> bool:
    return VAULT_FILE.exists()


def load_vault_file() -> dict:
    with open(VAULT_FILE, "r") as f:
        return json.load(f)


def save_vault_file(data: dict) -> None:
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(VAULT_FILE, 0o600)


def setup_vault() -> Optional[bytes]:
    print("\nNo vault found. Let's create one.")
    while True:
        p1 = getpass.getpass("Set a master password (min 8 chars): ")
        if len(p1) < 8:
            print("  Too short, try again.")
            continue
        p2 = getpass.getpass("Confirm master password: ")
        if p1 != p2:
            print("  Passwords don't match, try again.")
            continue
        break

    salt = os.urandom(SALT_LEN)
    key = derive_key(p1, salt)
    verifier = encrypt_bytes(key, VERIFIER_PLAINTEXT)
    vault_blob = encrypt_bytes(key, json.dumps([]).encode())

    save_vault_file({
        "salt": base64.b64encode(salt).decode(),
        "verifier": verifier,
        "vault": vault_blob,
    })
    print("Vault created.\n")
    return key


def unlock_vault() -> Optional[bytes]:
    data = load_vault_file()
    salt = base64.b64decode(data["salt"])
    for attempt in range(3):
        pw = getpass.getpass("Master password: ")
        key = derive_key(pw, salt)
        try:
            plain = decrypt_bytes(key, data["verifier"])
            if plain == VERIFIER_PLAINTEXT:
                return key
        except Exception:
            pass
        print(f"  Incorrect master password. ({2 - attempt} attempt(s) left)")
    return None


def load_entries(key: bytes) -> list:
    data = load_vault_file()
    plain = decrypt_bytes(key, data["vault"])
    return json.loads(plain)


def save_entries(key: bytes, entries: list) -> None:
    data = load_vault_file()
    data["vault"] = encrypt_bytes(key, json.dumps(entries).encode())
    save_vault_file(data)


def vault_menu() -> None:
    if vault_exists():
        key = unlock_vault()
        if key is None:
            print("Too many failed attempts. Returning to main menu.\n")
            return
    else:
        key = setup_vault()

    entries = load_entries(key)
    idle_start = time.time()
    AUTO_LOCK_SECONDS = 5 * 60

    while True:
        if time.time() - idle_start > AUTO_LOCK_SECONDS:
            print("\nVault auto-locked after 5 minutes of inactivity.\n")
            return

        print("--- Vault ---")
        for i, e in enumerate(entries):
            print(f"  {i + 1}. {e['site']}  ({e.get('username', '')})")
        if not entries:
            print("  (no entries yet)")
        print("\n  [a] add   [s] show password   [e] edit   [d] delete   [l] lock & return")
        choice = input("> ").strip().lower()
        idle_start = time.time()

        if choice == "a":
            site = input("  Site/app: ").strip()
            user = input("  Username/email: ").strip()
            pw = getpass.getpass("  Password (hidden): ")
            if not site or not pw:
                print("  Site and password are required.\n")
                continue
            entries.append({"site": site, "username": user, "password": pw})
            save_entries(key, entries)
            print("  Added.\n")

        elif choice == "s":
            idx = _pick_index(entries)
            if idx is not None:
                print(f"  Password for {entries[idx]['site']}: {entries[idx]['password']}\n")

        elif choice == "e":
            idx = _pick_index(entries)
            if idx is not None:
                site = input(f"  Site [{entries[idx]['site']}]: ").strip() or entries[idx]["site"]
                user = input(f"  Username [{entries[idx].get('username', '')}]: ").strip() or entries[idx].get("username", "")
                pw = getpass.getpass("  New password (leave blank to keep current): ")
                if not pw:
                    pw = entries[idx]["password"]
                entries[idx] = {"site": site, "username": user, "password": pw}
                save_entries(key, entries)
                print("  Updated.\n")

        elif choice == "d":
            idx = _pick_index(entries)
            if idx is not None:
                confirm = input(f"  Delete '{entries[idx]['site']}'? (y/N): ").strip().lower()
                if confirm == "y":
                    entries.pop(idx)
                    save_entries(key, entries)
                    print("  Deleted.\n")

        elif choice == "l":
            print("Vault locked.\n")
            return

        else:
            print("  Unrecognized option.\n")


def _pick_index(entries: list) -> Optional[int]:
    if not entries:
        print("  No entries yet.\n")
        return None
    raw = input("  Entry number: ").strip()
    if not raw.isdigit() or not (1 <= int(raw) <= len(entries)):
        print("  Invalid entry number.\n")
        return None
    return int(raw) - 1


def reset_vault() -> None:
    confirm = input("This permanently deletes the local vault file. Type 'yes' to confirm: ").strip()
    if confirm == "yes" and VAULT_FILE.exists():
        VAULT_FILE.unlink()
        print("Vault deleted.\n")
    else:
        print("Cancelled.\n")


# --------------------------------------------------------------------------
# Main menu
# --------------------------------------------------------------------------

def main() -> None:
    print("=" * 52)
    print("  PASSWORD AUDIT TOOLKIT")
    print("  Strength checker · secure generator · local vault")
    print("=" * 52)
    if not ZXCVBN_AVAILABLE:
        print("  (tip: pip install zxcvbn for richer strength scoring)")

    while True:
        print("\nMain menu:")
        print("  1. Analyze a password")
        print("  2. Generate a password")
        print("  3. Open vault")
        print("  4. Reset/delete local vault")
        print("  5. Quit")
        choice = input("> ").strip()

        if choice == "1":
            pw = getpass.getpass("Password to test (hidden): ")
            print_analysis(pw)

        elif choice == "2":
            try:
                length = int(input("  Length [18]: ").strip() or "18")
            except ValueError:
                length = 18
            excl = input("  Exclude ambiguous characters (0,O,1,l,I)? (y/N): ").strip().lower() == "y"
            pw = generate_password(length=length, exclude_ambiguous=excl)
            print(f"\n  Generated: {pw}")
            print_analysis(pw)

        elif choice == "3":
            vault_menu()

        elif choice == "4":
            reset_vault()

        elif choice == "5":
            print("Goodbye.")
            sys.exit(0)

        else:
            print("Unrecognized option.")


if __name__ == "__main__":
    main()
