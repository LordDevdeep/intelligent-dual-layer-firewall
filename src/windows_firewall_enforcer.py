import json
import argparse
import subprocess
import ipaddress

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

DECISION_LOG = ROOT / "experiments" / "phase5" / "live_test" / "decision_log.jsonl"

WINDOWS_IP = "192.168.56.1"
KALI_IP = "192.168.56.101"

RULE_PREFIX = "RESOLUTE AutoBlock"


def run_ps(script):

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", script
        ],
        capture_output=True,
        text=True,
        timeout=30
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)

    return result.stdout.strip()


def is_admin():

    result = run_ps(
        "$p = New-Object Security.Principal.WindowsPrincipal("
        "[Security.Principal.WindowsIdentity]::GetCurrent()); "
        "$p.IsInRole("
        "[Security.Principal.WindowsBuiltInRole]::Administrator)"
    )

    return result.lower() == "true"


def get_candidates():

    candidates = set()

    if not DECISION_LOG.exists():
        print("Decision log not found.")
        return []

    with DECISION_LOG.open(encoding="utf-8") as file:

        for line in file:

            if not line.strip():
                continue

            try:
                record = json.loads(line)

                if record.get("decision") != "BLOCK_CANDIDATE":
                    continue

                ip = record.get("source_ip")

                address = ipaddress.ip_address(ip)

                if (
                    address.version == 4
                    and str(address) == KALI_IP
                ):
                    candidates.add(str(address))

                else:
                    print("Rejected IP:", ip)

            except (ValueError, TypeError, json.JSONDecodeError):
                print("Skipped invalid record.")

    return sorted(candidates)


def block_ip(ip, apply):

    name = f"{RULE_PREFIX} {ip}"

    # Check whether rule already exists.
    check = run_ps(
        f"$r = Get-NetFirewallRule "
        f"-DisplayName '{name}' "
        f"-ErrorAction SilentlyContinue; "
        f"if ($r) {{ 'EXISTS' }} else {{ 'MISSING' }}"
    )

    if check.strip() == "EXISTS":
        print("Rule already exists:", name)
        return

    command = (
        f"New-NetFirewallRule "
        f"-DisplayName '{name}' "
        f"-Direction Inbound "
        f"-Action Block "
        f"-RemoteAddress '{ip}' "
        f"-LocalAddress '{WINDOWS_IP}' "
        f"-Profile Any "
        f"-Enabled True | Out-Null; "
        f"Write-Output 'CREATED'"
    )

    if not apply:
        print("[DRY RUN] Would block:", ip)
        return

    run_ps(command)

    print("FIREWALL BLOCK CREATED:", ip)


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--apply",
        action="store_true"
    )

    parser.add_argument(
        "--remove-test-rule",
        action="store_true"
    )

    args = parser.parse_args()

    print("=" * 55)
    print("RESOLUTE WINDOWS FIREWALL ENFORCER")
    print("=" * 55)

    if args.remove_test_rule:

        if not is_admin():
            print("Run PowerShell as Administrator.")
            return

        name = f"{RULE_PREFIX} {KALI_IP}"

        run_ps(
            f"Remove-NetFirewallRule "
            f"-DisplayName '{name}' "
            f"-ErrorAction SilentlyContinue"
        )

        print("Test block rule removed.")
        return

    if args.apply and not is_admin():
        print("ERROR: Administrator privileges required.")
        return

    candidates = get_candidates()

    print("Block candidates:", candidates)

    if not candidates:
        print("No eligible block candidates.")
        return

    for ip in candidates:
        block_ip(ip, args.apply)

    print("\nMode:", "APPLY" if args.apply else "DRY RUN")
    print("Enforcer completed.")


if __name__ == "__main__":
    main()