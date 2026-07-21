#!/usr/bin/env python3
"""
Nessus Interactive Scan Onboarder  v3.0
-----------------------------------------
Interactive CLI to bulk-create authenticated or unauthenticated scans.

Authenticated scans use pre-configured Nessus policies (with SSH key baked in).
The script reads the 'username' column from the CSV and maps it to the matching
policy fetched live from Nessus.

Requirements:
    pip install requests pandas openpyxl urllib3
"""

import json
import re
import sys
import time
import urllib3
import requests
import pandas as pd
import getpass
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── ANSI Colors ──────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

def c(text, color): return f"{color}{text}{RESET}"
def ok(text):   print(f"  {c('✓', GREEN)} {text}")
def err(text):  print(f"  {c('✗', RED)} {text}")
def info(text): print(f"  {c('→', CYAN)} {text}")
def warn(text): print(f"  {c('!', YELLOW)} {text}")

def banner():
    print()
    print(c("╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("║        Nessus Bulk Scan Onboarder  v3.0              ║", CYAN))
    print(c("╚══════════════════════════════════════════════════════╝", CYAN))
    print()

def ask(prompt, default=None):
    if default:
        val = input(f"  {c('?', CYAN)} {prompt} [{c(default, DIM)}]: ").strip()
        return val if val else default
    val = input(f"  {c('?', CYAN)} {prompt}: ").strip()
    return val

def ask_choice(prompt, choices):
    print(f"\n  {c('?', CYAN)} {prompt}")
    for i, ch in enumerate(choices, 1):
        print(f"     {c(str(i), BOLD)}. {ch}")
    while True:
        try:
            sel = int(input(f"\n  Enter choice [1-{len(choices)}]: ").strip())
            if 1 <= sel <= len(choices):
                return sel - 1
        except (ValueError, KeyboardInterrupt):
            pass
        warn(f"Please enter a number between 1 and {len(choices)}.")

def progress_bar(current, total, label="", width=35):
    filled = int(width * current / max(total, 1))
    bar    = "█" * filled + "░" * (width - filled)
    pct    = int(100 * current / max(total, 1))
    print(f"\r  {c('Progress', CYAN)} [{c(bar, GREEN)}] {c(str(pct)+'%', BOLD)} ({current}/{total})  {c(label, DIM):<50}", end="", flush=True)


# ─── Nessus Client ────────────────────────────────────────────────────────────

class NessusClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        self.session  = requests.Session()
        self.session.verify = False
        self.session.headers.update({"Content-Type": "application/json"})
        self._login(username, password)

    def _get_api_token(self):
        try:
            r = self.session.get(f"{self.base_url}/nessus6.js", timeout=10)
            m = re.search(r'"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"', r.text)
            if m:
                return m.group(1)
        except Exception:
            pass
        return ""

    def _login(self, username, password):
        r = self.session.post(
            f"{self.base_url}/session",
            data=json.dumps({"username": username, "password": password}),
            timeout=15,
        )
        if r.status_code == 401:
            raise ValueError("Invalid username or password.")
        r.raise_for_status()
        token = r.json().get("token")
        if not token:
            raise ValueError("No session token returned by Nessus.")
        self.session.headers.update({"X-Cookie": f"token={token}"})
        api_token = self._get_api_token()
        if api_token:
            self.session.headers.update({"X-API-Token": api_token})

    def logout(self):
        try:
            self.session.delete(f"{self.base_url}/session", timeout=10)
        except Exception:
            pass

    def get(self, path):
        r = self.session.get(f"{self.base_url}{path}", timeout=15)
        r.raise_for_status()
        return r.json()

    def post(self, path, data):
        r = self.session.post(f"{self.base_url}{path}", data=json.dumps(data), timeout=15)
        r.raise_for_status()
        return r.json()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def get_template_uuid(client, name="basic"):
    templates = client.get("/editor/scan/templates").get("templates", [])
    for t in templates:
        if t["name"] == name:
            return t["uuid"]
    return templates[0]["uuid"]


def load_csv(filepath):
    if filepath.lower().endswith(".csv"):
        df = pd.read_csv(
            filepath,
            encoding="utf-8-sig",
            keep_default_na=False,
            on_bad_lines="skip",
        )
    else:
        df = pd.read_excel(filepath, keep_default_na=False)
    df.columns = [col.strip().lstrip("\ufeff").lower() for col in df.columns]
    for col in df.columns:
        if df[col].dtype == object or str(df[col].dtype) == "string":
            df[col] = df[col].astype(str).str.strip()
    if "ip" not in df.columns:
        raise ValueError(f"No 'ip' column found. Columns detected: {list(df.columns)}")
    df = df[df["ip"].str.strip().str.len() > 0].reset_index(drop=True)
    return df


def create_scan_with_policy(client, folder_id, policy_id, advanced_uuid, name, ip):
    """Create a scan using a user-defined policy (credentials baked into the policy)."""
    payload = {
        "uuid": advanced_uuid,
        "settings": {
            "name": name,
            "folder_id": folder_id,
            "text_targets": ip,
            "policy_id": policy_id,
            "enabled": True,
        },
    }
    result = client.post("/scans", payload)
    return result["scan"]["id"]


def create_scan_no_creds(client, folder_id, template_uuid, name, ip):
    """Create a scan with no credentials (unauthenticated)."""
    payload = {
        "uuid": template_uuid,
        "settings": {
            "name": name,
            "folder_id": folder_id,
            "text_targets": ip,
            "enabled": True,
        },
    }
    result = client.post("/scans", payload)
    return result["scan"]["id"]


def print_summary(created, failed):
    print()
    print(c("  ┌─────────────────────────────────────────────────────────┐", CYAN))
    print(c( "  │  Summary                                                 │", CYAN))
    print(c( "  └─────────────────────────────────────────────────────────┘", CYAN))
    print()
    if created:
        ok(f"{c(str(len(created)), GREEN+BOLD)} scans created successfully:")
        for s in created:
            policy_label = f"policy={s.get('policy','unauth')}"
            print(f"      {c('·', DIM)} {s['hostname']:<38} {s['ip']:<18} id={s['scan_id']}  {c(policy_label, DIM)}")
    if failed:
        print()
        err(f"{c(str(len(failed)), RED+BOLD)} scans failed:")
        for s in failed:
            print(f"      {c('·', DIM)} {s['hostname']:<38} {s['ip']:<18} {c(s['error'], RED)}")
    if created:
        out = "nessus_scan_results.csv"
        pd.DataFrame(created).to_csv(out, index=False)
        print()
        info(f"Scan IDs saved to: {c(out, BOLD)}")
    print()


# ─── Onboarding flows ─────────────────────────────────────────────────────────

def onboard_unauthenticated(client, df, folder_id, folder_name):
    template_uuid = get_template_uuid(client, "basic")
    print()
    info(f"Onboarding {len(df)} hosts — UNAUTHENTICATED — folder: '{folder_name}'")
    print()

    created, failed = [], []
    total = len(df)

    for i, (_, row) in enumerate(df.iterrows(), 1):
        hostname = str(row.get("hostname", row["ip"])).strip()
        ip       = str(row["ip"]).strip()
        progress_bar(i - 1, total, hostname)
        try:
            scan_id = create_scan_no_creds(client, folder_id, template_uuid, hostname, ip)
            created.append({"hostname": hostname, "ip": ip, "scan_id": scan_id, "policy": "unauthenticated"})
        except Exception as e:
            failed.append({"hostname": hostname, "ip": ip, "error": str(e)})
        time.sleep(0.3)

    progress_bar(total, total, "Done")
    print("\n")
    return created, failed


def onboard_authenticated(client, df, folder_id, folder_name, policy_map, advanced_uuid):
    """
    policy_map: dict of {username_lowercase: (policy_id, policy_name)}
    Hosts whose username doesn't match any policy are skipped with an error.
    """
    print()
    info(f"Onboarding {len(df)} hosts — AUTHENTICATED (policy-based) — folder: '{folder_name}'")
    print()
    info("Username → Policy mapping:")
    for uname, (pid, pname) in policy_map.items():
        print(f"      {c(uname, BOLD):<20} → {c(pname, GREEN)} (id={pid})")
    print()

    created, failed = [], []
    total = len(df)

    for i, (_, row) in enumerate(df.iterrows(), 1):
        hostname = str(row.get("hostname", row["ip"])).strip()
        ip       = str(row["ip"]).strip()
        username = str(row.get("username", "")).strip().lower()

        progress_bar(i - 1, total, hostname)

        if username not in policy_map:
            failed.append({
                "hostname": hostname,
                "ip": ip,
                "error": f"No policy mapped for username '{username}' — add a policy for this user in Nessus UI"
            })
            time.sleep(0.1)
            continue

        policy_id, policy_name = policy_map[username]

        try:
            scan_id = create_scan_with_policy(client, folder_id, policy_id, advanced_uuid, hostname, ip)
            created.append({"hostname": hostname, "ip": ip, "scan_id": scan_id, "policy": policy_name})
        except Exception as e:
            failed.append({"hostname": hostname, "ip": ip, "error": str(e)})
        time.sleep(0.3)

    progress_bar(total, total, "Done")
    print("\n")
    return created, failed


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    banner()

    while True:
        choice = ask_choice("Main Menu", [
            "Run Scan Onboarder",
            "Exit",
        ])

        if choice == 1:
            print()
            sys.exit(0)

        # ── Step 1: Nessus connection ──
        print()
        print(c("  ── Nessus Connection ──────────────────────────────", DIM))
        nessus_url  = ask("Nessus URL", "https://10.110.100.233:8834")
        nessus_user = ask("Nessus username", "mssoc")
        nessus_pass = getpass.getpass(f"  {c('?', CYAN)} Nessus password: ")

        print()
        info("Connecting to Nessus...")
        try:
            client = NessusClient(nessus_url, nessus_user, nessus_pass)
            ok(f"Logged in to {c(nessus_url, BOLD)}")
        except Exception as e:
            err(f"Login failed: {e}")
            continue

        # ── Step 2: CSV path ──
        print()
        print(c("  ── Hosts File ─────────────────────────────────────", DIM))
        while True:
            csv_path = ask("Path to hosts CSV/Excel file", "/home/ubuntu/hosts.csv")
            if os.path.exists(csv_path):
                try:
                    df = load_csv(csv_path)
                    ok(f"Loaded {c(str(len(df)), BOLD)} hosts from {c(csv_path, BOLD)}")
                    print()
                    print(f"  {'HOSTNAME':<38} {'IP':<18} {'USERNAME':<12}")
                    print(f"  {'─'*38} {'─'*18} {'─'*12}")
                    for _, row in df.head(5).iterrows():
                        hn = str(row.get('hostname', '')).strip()
                        ip = str(row.get('ip', '')).strip()
                        un = str(row.get('username', '')).strip()
                        print(f"  {hn:<38} {ip:<18} {un:<12}")
                    if len(df) > 5:
                        print(f"  {c(f'... and {len(df)-5} more', DIM)}")
                    print()
                    break
                except Exception as e:
                    err(f"Could not read file: {e}")
            else:
                err(f"File not found: {csv_path}")

        # ── Step 3: Scan type ──
        scan_type = ask_choice("Scan type", [
            "Authenticated scan  (SSH key via Nessus policy)",
            "Unauthenticated scan  (no credentials)",
        ])

        # ── Step 4: Folder picker ──
        print()
        print(c("  ── Nessus Folder ──────────────────────────────────", DIM))
        info("Fetching folders from Nessus...")
        try:
            all_folders = client.get("/folders").get("folders", [])
            custom_folders = [f for f in all_folders if f.get("type") == "custom"]
            if not custom_folders:
                custom_folders = all_folders
        except Exception as e:
            err(f"Could not fetch folders: {e}")
            client.logout()
            continue

        folder_names = [f["name"] for f in custom_folders]
        folder_ids   = [f["id"]   for f in custom_folders]
        folder_idx   = ask_choice("Select destination folder", folder_names)
        folder_id    = folder_ids[folder_idx]
        folder_name  = folder_names[folder_idx]
        ok(f"Selected: {c(folder_name, BOLD)} (id={folder_id})")

        # ── Step 5: Run ──
        print()
        print(c("  ── Onboarding ─────────────────────────────────────", DIM))

        if scan_type == 1:
            # Unauthenticated
            created, failed = onboard_unauthenticated(client, df, folder_id, folder_name)

        else:
            # Authenticated — fetch policies from Nessus and let user map them
            print()
            info("Fetching policies from Nessus...")
            try:
                raw_policies = client.get("/policies").get("policies") or []
            except Exception as e:
                err(f"Could not fetch policies: {e}")
                client.logout()
                continue

            if not raw_policies:
                err("No user-defined policies found in Nessus.")
                warn("Go to Nessus UI → Policies → New Policy → Credentialed Patch Audit")
                warn("Create one policy per SSH username (e.g. SSH-admin, SSH-versa) with your key uploaded.")
                client.logout()
                continue

            ok(f"Found {len(raw_policies)} policies:")
            for p in raw_policies:
                print(f"      {c('·', DIM)} id={p['id']}  {c(p['name'], BOLD)}")

            # Get unique usernames from CSV
            usernames = sorted(df["username"].str.lower().unique()) if "username" in df.columns else []
            if not usernames:
                err("No 'username' column in CSV — cannot map policies.")
                client.logout()
                continue

            print()
            info(f"Usernames found in CSV: {c(', '.join(usernames), BOLD)}")
            info("Map each username to a Nessus policy:")
            print()

            policy_choices = [f"{p['name']} (id={p['id']})" for p in raw_policies]
            policy_choices.append("SKIP — no policy for this username")

            policy_map = {}
            for uname in usernames:
                idx = ask_choice(f"Policy for username '{c(uname, BOLD)}'", policy_choices)
                if idx < len(raw_policies):
                    p = raw_policies[idx]
                    policy_map[uname] = (p["id"], p["name"])
                    ok(f"'{uname}' → {p['name']} (id={p['id']})")
                else:
                    warn(f"'{uname}' will be SKIPPED (no policy assigned)")

            if not policy_map:
                err("No policies mapped — nothing to onboard.")
                client.logout()
                continue

            # Get advanced template UUID (wrapper for user policies)
            info("Resolving Advanced Scan template UUID...")
            try:
                advanced_uuid = get_template_uuid(client, "advanced")
                ok(f"Advanced template UUID resolved.")
            except Exception as e:
                err(f"Could not resolve template: {e}")
                client.logout()
                continue

            print()
            created, failed = onboard_authenticated(
                client, df, folder_id, folder_name, policy_map, advanced_uuid
            )

        print_summary(created, failed)
        client.logout()
        ok("Session logged out.")
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {c('Interrupted. Goodbye!', YELLOW)}\n")
        sys.exit(0)
