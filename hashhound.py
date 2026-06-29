#!/usr/bin/env python3
"""
HashHound - Password Hash Analyzer & Cracker
Author: Aqsa
GitHub: https://github.com/Aqsa819/HashHound
"""

import hashlib
import argparse
import os
import sys
import re
import time
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = BLUE = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# ─── Banner ──────────────────────────────────────────────────────────────────

def banner():
    print(f"""{Fore.CYAN}{Style.BRIGHT}
  ██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
  ██║  ██║██╔══██╗██╔════╝██║  ██║██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
  ███████║███████║███████╗███████║███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
  ██╔══██║██╔══██║╚════██║██╔══██║██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
  ██║  ██║██║  ██║███████║██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝
{Style.RESET_ALL}
{Fore.YELLOW}  [*] Password Hash Analyzer, Identifier & Cracker
  [*] Supports: MD5, SHA1, SHA224, SHA256, SHA384, SHA512, NTLM
{Style.RESET_ALL}""")

# ─── Hash Identifier ─────────────────────────────────────────────────────────

HASH_SIGNATURES = {
    32:  [("MD5",    r"^[a-f0-9]{32}$"),
          ("NTLM",   r"^[a-f0-9]{32}$")],
    40:  [("SHA1",   r"^[a-f0-9]{40}$")],
    56:  [("SHA224", r"^[a-f0-9]{56}$")],
    64:  [("SHA256", r"^[a-f0-9]{64}$")],
    96:  [("SHA384", r"^[a-f0-9]{96}$")],
    128: [("SHA512", r"^[a-f0-9]{128}$")],
}

HASH_STRENGTH = {
    "MD5":    ("WEAK",    Fore.RED,    "Broken — collision attacks exist, never use for passwords"),
    "NTLM":   ("WEAK",    Fore.RED,    "Broken — used in Windows auth, easily cracked"),
    "SHA1":   ("WEAK",    Fore.RED,    "Deprecated — collision found by Google SHAttered attack"),
    "SHA224": ("MODERATE",Fore.YELLOW, "Acceptable but SHA256+ preferred"),
    "SHA256": ("STRONG",  Fore.GREEN,  "Strong — widely used, no known practical attacks"),
    "SHA384": ("STRONG",  Fore.GREEN,  "Strong — truncated SHA512 variant"),
    "SHA512": ("STRONG",  Fore.GREEN,  "Very strong — recommended for integrity checks"),
}

def identify_hash(hash_str):
    """Identify possible hash types from length and pattern."""
    hash_str = hash_str.strip().lower()
    length = len(hash_str)
    candidates = []

    if length in HASH_SIGNATURES:
        for name, pattern in HASH_SIGNATURES[length]:
            if re.match(pattern, hash_str):
                candidates.append(name)

    return candidates, hash_str

# ─── Hash Generator ──────────────────────────────────────────────────────────

def generate_hashes(plaintext):
    """Generate all supported hashes for a plaintext string."""
    encoded = plaintext.encode("utf-8")
    return {
        "MD5":    hashlib.md5(encoded).hexdigest(),
        "NTLM":   "N/A (MD4 unsupported on this system)",
        "SHA1":   hashlib.sha1(encoded).hexdigest(),
        "SHA224": hashlib.sha224(encoded).hexdigest(),
        "SHA256": hashlib.sha256(encoded).hexdigest(),
        "SHA384": hashlib.sha384(encoded).hexdigest(),
        "SHA512": hashlib.sha512(encoded).hexdigest(),
    }

# ─── Hash Cracker ────────────────────────────────────────────────────────────

def crack_hash(hash_str, hash_type, wordlist_path, verbose=False):
    """Dictionary attack using wordlist."""
    hash_str = hash_str.strip().lower()

    if not os.path.exists(wordlist_path):
        print(f"{Fore.RED}[!] Wordlist not found: {wordlist_path}")
        return None

    algo_map = {
        "MD5":    lambda w: hashlib.md5(w).hexdigest(),
        "NTLM":   lambda w: hashlib.new("md4", w.decode().encode("utf-16-le")).hexdigest(),
        "SHA1":   lambda w: hashlib.sha1(w).hexdigest(),
        "SHA224": lambda w: hashlib.sha224(w).hexdigest(),
        "SHA256": lambda w: hashlib.sha256(w).hexdigest(),
        "SHA384": lambda w: hashlib.sha384(w).hexdigest(),
        "SHA512": lambda w: hashlib.sha512(w).hexdigest(),
    }

    if hash_type not in algo_map:
        print(f"{Fore.RED}[!] Unsupported hash type: {hash_type}")
        return None

    hasher = algo_map[hash_type]
    start = time.time()
    attempts = 0

    print(f"{Fore.CYAN}[*] Starting dictionary attack on {hash_type} hash...")
    print(f"{Fore.CYAN}[*] Wordlist: {wordlist_path}\n")

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                attempts += 1
                try:
                    computed = hasher(word.encode("utf-8"))
                    if computed == hash_str:
                        elapsed = time.time() - start
                        print(f"{Fore.GREEN}[+] CRACKED! Password: {Style.BRIGHT}{word}")
                        print(f"{Fore.GREEN}[+] Attempts: {attempts} | Time: {elapsed:.2f}s")
                        return word
                    if verbose and attempts % 10000 == 0:
                        print(f"{Fore.YELLOW}[*] Tried {attempts} passwords... last: {word}")
                except Exception:
                    continue
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Cracking stopped by user after {attempts} attempts.")
        return None

    elapsed = time.time() - start
    print(f"{Fore.RED}[-] Hash not cracked. Tried {attempts} passwords in {elapsed:.2f}s")
    return None

# ─── Password Strength Analyzer ──────────────────────────────────────────────

def analyze_password_strength(password):
    """Analyze password strength and give recommendations."""
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short — use at least 8 characters")

    if len(password) >= 12:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters (A-Z)")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters (a-z)")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers (0-9)")

    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        score += 1
    else:
        feedback.append("Add special characters (!@#$%^&*)")

    common_passwords = ["password", "123456", "admin", "qwerty", "letmein",
                        "welcome", "monkey", "dragon", "master", "abc123"]
    if password.lower() in common_passwords:
        score = 0
        feedback.append("This is a commonly used password — change it immediately!")

    levels = {
        (0, 2): ("VERY WEAK",  Fore.RED),
        (2, 3): ("WEAK",       Fore.RED),
        (3, 4): ("MODERATE",   Fore.YELLOW),
        (4, 5): ("STRONG",     Fore.GREEN),
        (5, 7): ("VERY STRONG",Fore.GREEN),
    }

    strength, color = "UNKNOWN", Fore.WHITE
    for (low, high), (label, col) in levels.items():
        if low <= score < high:
            strength, color = label, col
            break

    return score, strength, color, feedback

# ─── Display Functions ────────────────────────────────────────────────────────

def display_identify(hash_str, candidates):
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  HASH IDENTIFICATION")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Hash   : {Fore.YELLOW}{hash_str[:32]}{'...' if len(hash_str)>32 else ''}")
    print(f"  {Fore.WHITE}Length : {len(hash_str)} characters\n")

    if not candidates:
        print(f"  {Fore.RED}[!] Unknown hash format")
    else:
        print(f"  {Fore.CYAN}Possible Types:")
        for algo in candidates:
            strength, color, desc = HASH_STRENGTH.get(algo, ("UNKNOWN", Fore.WHITE, ""))
            print(f"  {Fore.WHITE}  → {Fore.YELLOW}{algo:<10} {color}[{strength}]  {Fore.WHITE}{desc}")

    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

def display_generate(plaintext, hashes):
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  HASH GENERATION")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Plaintext : {Fore.YELLOW}{plaintext}\n")

    for algo, h in hashes.items():
        strength, color, _ = HASH_STRENGTH.get(algo, ("UNKNOWN", Fore.WHITE, ""))
        print(f"  {color}{algo:<10}{Style.RESET_ALL} {Fore.WHITE}{h}  {color}[{strength}]")

    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

def display_strength(password, score, strength, color, feedback):
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  PASSWORD STRENGTH ANALYSIS")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Password : {Fore.YELLOW}{'*' * len(password)} ({len(password)} chars)")

    bar_filled = int((score / 6) * 20)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    print(f"  {color}Score    : {score}/6  [{bar}]")
    print(f"  {color}Strength : {strength}{Style.RESET_ALL}")

    if feedback:
        print(f"\n  {Fore.YELLOW}Recommendations:")
        for tip in feedback:
            print(f"  {Fore.YELLOW}  • {tip}")
    else:
        print(f"\n  {Fore.GREEN}  ✓ Password looks strong!")

    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

# ─── Demo Mode ───────────────────────────────────────────────────────────────

def run_demo():
    print(f"\n{Fore.YELLOW}[*] Running DEMO mode...\n")

    # Demo 1: Identify
    demo_hashes = [
        "5f4dcc3b5aa765d61d8327deb882cf99",   # MD5 of "password"
        "aaf4c61ddcc5e8a2dabede0f3b482cd9dd8ad9",  # SHA1 (truncated for demo)
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # SHA256 of "password"
    ]

    print(f"{Fore.CYAN}[*] Demo 1 — Hash Identification{Style.RESET_ALL}")
    for h in demo_hashes:
        candidates, clean = identify_hash(h)
        display_identify(clean, candidates)

    # Demo 2: Generate
    print(f"{Fore.CYAN}[*] Demo 2 — Hash Generation{Style.RESET_ALL}")
    hashes = generate_hashes("P@ssw0rd123!")
    display_generate("P@ssw0rd123!", hashes)

    # Demo 3: Password strength
    print(f"{Fore.CYAN}[*] Demo 3 — Password Strength Analysis{Style.RESET_ALL}")
    test_passwords = ["password", "Admin@123", "Tr0ub4dor&3#Xk9!"]
    for pwd in test_passwords:
        score, strength, color, feedback = analyze_password_strength(pwd)
        display_strength(pwd, score, strength, color, feedback)

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    banner()

    parser = argparse.ArgumentParser(description="HashHound — Hash Analyzer & Cracker")
    parser.add_argument("--identify", metavar="HASH", help="Identify hash type")
    parser.add_argument("--generate", metavar="TEXT", help="Generate all hashes for plaintext")
    parser.add_argument("--crack", metavar="HASH", help="Crack hash using dictionary attack")
    parser.add_argument("--type", metavar="TYPE", help="Hash type for cracking (MD5, SHA1, SHA256...)")
    parser.add_argument("--wordlist", metavar="FILE", default="wordlist.txt", help="Wordlist file path")
    parser.add_argument("--strength", metavar="PASSWORD", help="Analyze password strength")
    parser.add_argument("--demo", action="store_true", help="Run demo mode")
    parser.add_argument("--verbose", action="store_true", help="Verbose cracking output")
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    if args.identify:
        candidates, clean = identify_hash(args.identify)
        display_identify(clean, candidates)
        return

    if args.generate:
        hashes = generate_hashes(args.generate)
        display_generate(args.generate, hashes)
        return

    if args.crack:
        if not args.type:
            print(f"{Fore.RED}[!] Specify hash type with --type (e.g. --type MD5)")
            sys.exit(1)
        candidates, clean = identify_hash(args.crack)
        display_identify(clean, candidates)
        crack_hash(clean, args.type.upper(), args.wordlist, args.verbose)
        return

    if args.strength:
        score, strength, color, feedback = analyze_password_strength(args.strength)
        display_strength(args.strength, score, strength, color, feedback)
        return

    # Interactive mode
    print(f"{Fore.CYAN}[*] Interactive Mode — choose an option:\n")
    print(f"  {Fore.YELLOW}1{Fore.WHITE} — Identify hash type")
    print(f"  {Fore.YELLOW}2{Fore.WHITE} — Generate hashes from plaintext")
    print(f"  {Fore.YELLOW}3{Fore.WHITE} — Crack hash (dictionary attack)")
    print(f"  {Fore.YELLOW}4{Fore.WHITE} — Analyze password strength")
    print(f"  {Fore.YELLOW}5{Fore.WHITE} — Run demo\n")

    choice = input(f"{Fore.CYAN}  Choice: {Style.RESET_ALL}").strip()

    if choice == "1":
        h = input(f"{Fore.WHITE}  Enter hash: {Style.RESET_ALL}").strip()
        candidates, clean = identify_hash(h)
        display_identify(clean, candidates)

    elif choice == "2":
        text = input(f"{Fore.WHITE}  Enter plaintext: {Style.RESET_ALL}").strip()
        hashes = generate_hashes(text)
        display_generate(text, hashes)

    elif choice == "3":
        h = input(f"{Fore.WHITE}  Enter hash: {Style.RESET_ALL}").strip()
        t = input(f"{Fore.WHITE}  Hash type (MD5/SHA1/SHA256...): {Style.RESET_ALL}").strip().upper()
        w = input(f"{Fore.WHITE}  Wordlist path [wordlist.txt]: {Style.RESET_ALL}").strip() or "wordlist.txt"
        candidates, clean = identify_hash(h)
        display_identify(clean, candidates)
        crack_hash(clean, t, w)

    elif choice == "4":
        pwd = input(f"{Fore.WHITE}  Enter password to analyze: {Style.RESET_ALL}").strip()
        score, strength, color, feedback = analyze_password_strength(pwd)
        display_strength(pwd, score, strength, color, feedback)

    elif choice == "5":
        run_demo()

    else:
        print(f"{Fore.RED}[!] Invalid choice.")

if __name__ == "__main__":
    main()
