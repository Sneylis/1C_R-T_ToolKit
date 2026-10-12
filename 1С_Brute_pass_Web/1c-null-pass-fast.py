#!/usr/bin/env python3
"""
1C Null Password Checker — Fast Playwright Edition.
Использует URL-параметры ?N=user&P=password для автоматической аутентификации.
Перехватывает финальный HTTP-ответ /e1cib/login.

    pip install playwright && playwright install chromium

    # Проверка только пустых паролей:
    python3 1c-null-pass-fast.py http://10.101.81.111/toir users.txt -v

    # Проверка по словарю слабых паролей:
    python3 1c-null-pass-fast.py http://10.101.81.111/toir users.txt -w passwords.txt -v
"""

import sys
import argparse
import time
import threading
from urllib.parse import quote

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout
except ImportError:
    print("[!] pip install playwright && playwright install chromium")
    sys.exit(1)

C = {"G": "\033[92m", "R": "\033[91m", "Y": "\033[93m",
     "B": "\033[94m", "BOLD": "\033[1m", "0": "\033[0m"}

parser = argparse.ArgumentParser(description="1C Null/Weak Password Checker (Fast)")
parser.add_argument("target", help="1C web app URL")
parser.add_argument("users", help="File with usernames")
parser.add_argument("-w", "--wordlist", help="Password wordlist file (.txt, one per line)")
parser.add_argument("-o", "--output", help="Save results to file")
parser.add_argument("--headed", action="store_true", help="Show browser")
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("--delay", type=float, default=0.5,
                    help="Delay between attempts (default: 0.5s)")
parser.add_argument("--timeout", type=int, default=15,
                    help="Login timeout in seconds (default: 15)")
parser.add_argument("--skip-empty", action="store_true",
                    help="Skip empty password check (only test wordlist)")
args = parser.parse_args()

target = args.target.rstrip("/")

with open(args.users, "r", encoding="utf-8", errors="ignore") as f:
    users = [u.strip() for u in f if u.strip()]

# Build password list
passwords = []
if not args.skip_empty:
    passwords.append("")  # Empty password always first

if args.wordlist:
    with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            p = line.rstrip("\n\r")
            if p and p not in passwords:
                passwords.append(p)

if not passwords:
    print(f"{C['R']}[!] No passwords to test. Use -w or remove --skip-empty.{C['0']}")
    sys.exit(1)

mode_label = "empty password only"
if args.wordlist:
    wl_count = len(passwords) - (0 if args.skip_empty else 1)
    if args.skip_empty:
        mode_label = f"wordlist ({wl_count} passwords)"
    else:
        mode_label = f"empty + wordlist ({wl_count} passwords)"

total_checks = len(users) * len(passwords)

print(f"""
{C['BOLD']}{C['Y']}╔══════════════════════════════════════════════╗
║  1C Null/Weak Password Checker  (Fast)       ║
╚══════════════════════════════════════════════╝{C['0']}

{C['B']}Target:{C['0']}    {target}
{C['B']}Users:{C['0']}     {len(users)}
{C['B']}Mode:{C['0']}      {mode_label}
{C['B']}Total:{C['0']}     {total_checks} checks
{C['B']}Method:{C['0']}    URL params ?N=user&P=pass (auto-auth via bootstrap.js)
""")

# Results: list of (username, password) tuples
found = []
license_error = False


def try_login(page, user, password, timeout_sec):
    """
    Attempt login with given user:password via URL params.
    Returns: "success" | "fail" | "license" | "timeout" | "error"
    """
    result = {"last_status": None, "count": 0, "done": threading.Event()}

    def on_response(response):
        url = response.url
        if "/e1cib/login" in url and response.request.method == "POST":
            result["last_status"] = response.status
            result["count"] += 1
            if response.status == 400:
                result["done"].set()

    page.on("response", on_response)

    try:
        encoded_user = quote(user, safe="")
        encoded_pass = quote(password, safe="")
        auth_url = f"{target}/en_US/?N={encoded_user}&P={encoded_pass}"

        page.goto(auth_url, timeout=timeout_sec * 1000)

        try:
            page.wait_for_load_state("networkidle", timeout=timeout_sec * 1000)
        except PwTimeout:
            pass

        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            if result["done"].is_set():
                break
            prev_count = result["count"]
            time.sleep(1.5)
            if result["count"] == prev_count and result["count"] > 0:
                break

        status = result["last_status"]
        count = result["count"]

        if status == 400:
            return "license"
        elif status == 200 and count >= 2:
            return "success"
        elif status == 200 and count == 1:
            try:
                content = page.content()
                if any(x in content for x in
                       ["workspacePanel", "TabBar", "CommandBar"]):
                    return "success"
            except:
                pass
            return "fail"
        elif status == 402:
            return "fail"
        else:
            return "timeout"

    except PwTimeout:
        return "timeout"
    except Exception:
        return "error"
    finally:
        try:
            page.remove_listener("response", on_response)
        except:
            pass


with sync_playwright() as pw:
    browser = pw.chromium.launch(
        headless=not args.headed,
        args=["--ignore-certificate-errors", "--no-sandbox"]
    )

    check_num = 0

    for i, user in enumerate(users, 1):
        if license_error:
            break

        user_cracked = False

        for password in passwords:
            if license_error:
                break

            check_num += 1
            pwd_display = "<empty>" if password == "" else password
            label = f"[{check_num}/{total_checks}]"

            sys.stdout.write(
                f"\r{C['B']}{label} {user} : {pwd_display:<30}{C['0']}"
            )
            sys.stdout.flush()

            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            try:
                outcome = try_login(page, user, password, args.timeout)

                if outcome == "license":
                    print(
                        f"\r{C['R']}{C['BOLD']}"
                        f"[!] License exhausted — stopping.{C['0']}"
                    )
                    license_error = True

                elif outcome == "success":
                    found.append((user, password))
                    if password == "":
                        print(
                            f"\r{C['BOLD']}{C['G']}"
                            f"[NULL-PASS] {user:<50}{C['0']}"
                        )
                    else:
                        print(
                            f"\r{C['BOLD']}{C['G']}"
                            f"[WEAK-PASS] {user} : {password:<40}{C['0']}"
                        )
                    # Logout to free license
                    try:
                        page.goto(
                            f"{target}/en_US/e1cib/logout", timeout=5000
                        )
                    except:
                        pass
                    user_cracked = True

                elif outcome == "fail":
                    if args.verbose:
                        print(
                            f"\r{label} {user} : {pwd_display:<30}"
                            f" — rejected"
                        )
                elif outcome == "timeout":
                    if args.verbose:
                        print(
                            f"\r{C['Y']}{label} {user} : {pwd_display:<30}"
                            f" — timeout{C['0']}"
                        )
                else:
                    if args.verbose:
                        print(
                            f"\r{C['R']}{label} {user} : {pwd_display:<30}"
                            f" — error{C['0']}"
                        )

            finally:
                try:
                    context.close()
                except:
                    pass
                time.sleep(args.delay)

            # If password found for this user, skip remaining passwords
            if user_cracked:
                # Fast-forward the counter for remaining passwords
                remaining = len(passwords) - passwords.index(password) - 1
                check_num += remaining
                break

    browser.close()

# ── Summary ──
sys.stdout.write("\r" + " " * 100 + "\r")
print(f"\n{C['B']}{'─' * 50}{C['0']}")

if found:
    null_pass = [(u, p) for u, p in found if p == ""]
    weak_pass = [(u, p) for u, p in found if p != ""]

    if null_pass:
        print(
            f"{C['BOLD']}{C['G']}"
            f"[+] Accounts with EMPTY password ({len(null_pass)}):{C['0']}"
        )
        for u, _ in null_pass:
            print(f"    {C['G']}{u}{C['0']}")

    if weak_pass:
        print(
            f"{C['BOLD']}{C['G']}"
            f"[+] Accounts with WEAK password ({len(weak_pass)}):{C['0']}"
        )
        for u, p in weak_pass:
            print(f"    {C['G']}{u} : {p}{C['0']}")
else:
    if args.wordlist:
        print(f"{C['Y']}[-] No weak or empty passwords found.{C['0']}")
    else:
        print(f"{C['Y']}[-] No accounts with empty password found.{C['0']}")

if license_error:
    print(f"\n{C['R']}[!] Scan incomplete — license limit.{C['0']}")

if args.output and found:
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"# 1C Password Audit — {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Target: {target}\n\n")
        for u, p in found:
            if p == "":
                f.write(f"{u}\t<EMPTY>\n")
            else:
                f.write(f"{u}\t{p}\n")
    print(f"{C['B']}Saved: {args.output}{C['0']}")

print(f"{C['B']}Done at {time.strftime('%H:%M:%S')}{C['0']}")
