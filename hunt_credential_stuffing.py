import pandas as pd
import numpy as np
from colorama import init, Fore, Style
from tabulate import tabulate
import datetime

init(autoreset=True)

"""
THREAT HUNT: Credential Stuffing Detection
==========================================
HYPOTHESIS: An attacker is conducting a distributed credential
stuffing attack against our authentication infrastructure.
Rather than brute forcing from one IP — which would trigger
standard lockout policies — they are using many different
source IPs, each attempting only 1-2 logins to stay below
per-source detection thresholds.

TECHNIQUE: While each individual source IP looks clean,
the attack reveals itself through:
1. Unusual volume of failed logins from NEW/external IPs
2. Many different source IPs targeting the SAME accounts
3. Tight time clustering of failures across sources
4. Abnormal ratio of network logons vs interactive logons

MITRE ATT&CK: T1110.004 - Credential Stuffing
"""

def load_logs(filepath):
    df = pd.read_csv(filepath)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def is_internal_ip(ip):
    """Checks if an IP is in a private/internal range"""
    if pd.isna(ip):
        return False
    return (ip.startswith("192.168.") or
            ip.startswith("10.") or
            ip.startswith("172.16."))

def hunt_credential_stuffing(filepath="data/auth_logs.csv"):
    """
    Main credential stuffing hunt function.

    Steps:
    1. Load authentication logs
    2. Separate internal vs external source IPs
    3. Analyze external IP failure patterns
    4. Detect distributed low-and-slow attack signature
    5. Identify compromised accounts
    """
    print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*60}")
    print("  THREAT HUNT: CREDENTIAL STUFFING DETECTION")
    print("  Hypothesis: Distributed low-and-slow auth attack")
    print("  Data source: Windows Authentication Event Logs")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    print(f"{Fore.CYAN}[*] Loading authentication logs: {filepath}"
          f"{Style.RESET_ALL}")
    df = load_logs(filepath)
    print(f"{Fore.CYAN}[*] Loaded {len(df)} authentication events"
          f"{Style.RESET_ALL}\n")

    # ── Analysis 1: External IP Failure Patterns ─────────────
    print(f"{Fore.WHITE}{Style.BRIGHT}ANALYSIS 1 — External Source IP Failures"
          f"{Style.RESET_ALL}")
    print("─" * 60)

    # Tag internal vs external IPs
    df["is_internal"] = df["src_ip"].apply(is_internal_ip)
    external_df = df[~df["is_internal"]].copy()
    failed_external = external_df[
        external_df["status"] == "Failed"
    ].copy()

    total_external_failures = len(failed_external)
    unique_external_ips = failed_external["src_ip"].nunique()
    unique_targeted_accounts = failed_external["username"].nunique()

    print(f"  External failed logins    : {total_external_failures}")
    print(f"  Unique source IPs         : {unique_external_ips}")
    print(f"  Unique targeted accounts  : {unique_targeted_accounts}")

    if total_external_failures > 20:
        print(f"\n  {Fore.RED}[!] HIGH volume of external authentication "
              f"failures detected{Style.RESET_ALL}")

    # ── Analysis 2: Per-Source IP Behavior ───────────────────
    print(f"\n{Fore.WHITE}{Style.BRIGHT}ANALYSIS 2 — Per-Source IP Attempt Volume"
          f"{Style.RESET_ALL}")
    print("─" * 60)

    ip_stats = failed_external.groupby("src_ip").agg(
        attempt_count=("username", "count"),
        unique_accounts=("username", "nunique"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max")
    ).reset_index()

    # Classic stuffing signature — many IPs with very few attempts each
    low_volume_ips = ip_stats[ip_stats["attempt_count"] <= 3]
    high_volume_ips = ip_stats[ip_stats["attempt_count"] > 10]

    print(f"  IPs with 1-3 attempts     : {len(low_volume_ips)} "
          f"{'← stuffing signature' if len(low_volume_ips) > 10 else ''}")
    print(f"  IPs with 10+ attempts     : {len(high_volume_ips)} "
          f"(traditional brute force)")

    if len(low_volume_ips) > 10:
        print(f"\n  {Fore.RED}[!] Distributed low-volume attack pattern "
              f"detected — {len(low_volume_ips)} IPs each attempting "
              f"≤3 logins{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}    This pattern evades per-source lockout "
              f"policies{Style.RESET_ALL}")

    # ── Analysis 3: Time Clustering ──────────────────────────
    print(f"\n{Fore.WHITE}{Style.BRIGHT}ANALYSIS 3 — Attack Time Clustering"
          f"{Style.RESET_ALL}")
    print("─" * 60)

    if len(failed_external) > 0:
        attack_start = failed_external["timestamp"].min()
        attack_end = failed_external["timestamp"].max()
        attack_duration = (attack_end - attack_start).total_seconds()

        print(f"  Attack window start : {attack_start}")
        print(f"  Attack window end   : {attack_end}")
        print(f"  Total duration      : {attack_duration:.0f} seconds "
              f"({attack_duration/60:.1f} minutes)")
        print(f"  Attack rate         : "
              f"{total_external_failures/(attack_duration/60):.1f} "
              f"attempts per minute")

        if attack_duration < 1800:
            print(f"\n  {Fore.RED}[!] All failures clustered within "
                  f"{attack_duration/60:.1f} minutes — "
                  f"automated attack confirmed{Style.RESET_ALL}")

    # ── Analysis 4: Targeted Account Analysis ────────────────
    print(f"\n{Fore.WHITE}{Style.BRIGHT}ANALYSIS 4 — Targeted Account Analysis"
          f"{Style.RESET_ALL}")
    print("─" * 60)

    account_targeting = failed_external.groupby("username").agg(
        failed_attempts=("status", "count"),
        unique_source_ips=("src_ip", "nunique")
    ).reset_index().sort_values("unique_source_ips", ascending=False)

    print(tabulate(
        account_targeting.head(10).values.tolist(),
        headers=["Username", "Failed Attempts", "Unique Source IPs"],
        tablefmt="grid"
    ))

    high_target_accounts = account_targeting[
        account_targeting["unique_source_ips"] > 5
    ]

    if len(high_target_accounts) > 0:
        print(f"\n  {Fore.RED}[!] Accounts targeted from 5+ unique IPs — "
              f"high-priority investigation targets:{Style.RESET_ALL}")
        for _, row in high_target_accounts.iterrows():
            print(f"  → {row['username']} — targeted from "
                  f"{row['unique_source_ips']} unique IPs")

    # ── Analysis 5: Successful Logins After Failures ─────────
    print(f"\n{Fore.WHITE}{Style.BRIGHT}"
          f"ANALYSIS 5 — Successful Logins After Attack Window"
          f"{Style.RESET_ALL}")
    print("─" * 60)

    if len(failed_external) > 0:
        attack_end = failed_external["timestamp"].max()

        # Check for successful external logins after the attack
        successful_after = external_df[
            (external_df["status"] == "Success") &
            (external_df["timestamp"] >= attack_start)
        ]

        if len(successful_after) > 0:
            print(f"\n  {Fore.RED}[!!!] CRITICAL — Successful external "
                  f"authentication detected after attack window:"
                  f"{Style.RESET_ALL}")
            for _, row in successful_after.iterrows():
                print(f"\n  Account   : {row['username']}")
                print(f"  Source IP : {row['src_ip']}")
                print(f"  Time      : {row['timestamp']}")
                print(f"  {Fore.RED}  → LIKELY COMPROMISED — "
                      f"credential stuffing succeeded{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[✓] No successful external logins "
                  f"detected after attack window{Style.RESET_ALL}")

    # ── Hunt Conclusion ──────────────────────────────────────
    stuffing_confirmed = (
        len(low_volume_ips) > 10 and
        total_external_failures > 20
    )

    print(f"\n{'='*60}")
    print(f"{Fore.WHITE}{Style.BRIGHT}HUNT CONCLUSION{Style.RESET_ALL}")
    print(f"  Hypothesis "
          f"{'CONFIRMED' if stuffing_confirmed else 'NOT CONFIRMED'}")

    if stuffing_confirmed:
        print(f"  {Fore.RED}[!] Credential stuffing attack identified"
              f"{Style.RESET_ALL}")
        print(f"  Attack signature: {len(low_volume_ips)} unique IPs, "
              f"each attempting ≤3 logins")
        print(f"  Accounts at risk: {unique_targeted_accounts}")
        print(f"\n  Recommended actions:")
        print(f"  → Force password reset for all targeted accounts")
        print(f"  → Block all identified attacker IP ranges")
        print(f"  → Enable MFA for all externally accessible services")
        print(f"  → Review and investigate any successful "
              f"post-attack logins")
        print(f"\n  MITRE ATT&CK: T1110.004 - Credential Stuffing")
    print()

    return stuffing_confirmed

if __name__ == "__main__":
    hunt_credential_stuffing()