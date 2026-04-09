import pandas as pd
import numpy as np
from colorama import init, Fore, Style
from tabulate import tabulate
import datetime

init(autoreset=True)

"""
THREAT HUNT: Lateral Movement Detection
========================================
HYPOTHESIS: An attacker who has gained initial access to one
endpoint is moving laterally through the network using
legitimate Windows administration tools — PsExec, WMI, or
PowerShell remoting — to access additional systems.

TECHNIQUE: Lateral movement using legitimate tools leaves
specific signatures in Windows event logs:
1. Unusual source/destination pairs for admin tool usage
2. Network logons (type 3) from workstations to servers
3. Service installation events (7045) from unexpected sources
4. Same account authenticating to multiple systems rapidly
5. Admin tool usage outside business hours

MITRE ATT&CK: T1021.002 - SMB/Windows Admin Shares (PsExec)
              T1047     - Windows Management Instrumentation
              T1570     - Lateral Tool Transfer
"""

def load_logs(filepath):
    df = pd.read_csv(filepath)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def is_admin_tool(process_name):
    """Identifies known lateral movement tools"""
    if pd.isna(process_name):
        return False
    admin_tools = [
        "psexec.exe", "psexesvc.exe", "wmic.exe",
        "winrm.cmd", "powershell.exe", "mstsc.exe",
        "wmiexec.py", "smbexec.py"
    ]
    return process_name.lower() in admin_tools

def is_server(hostname):
    """Identifies server hostnames"""
    if pd.isna(hostname):
        return False
    return hostname.upper().startswith("SRV-")

def is_workstation(hostname):
    """Identifies workstation hostnames"""
    if pd.isna(hostname):
        return False
    return hostname.upper().startswith("WKSTN-")

def hunt_lateral_movement(filepath="data/windows_events.csv"):
    """
    Main lateral movement hunt function.

    Steps:
    1. Load Windows event logs
    2. Hunt for admin tool usage patterns
    3. Detect workstation-to-server lateral movement
    4. Identify rapid multi-system authentication
    5. Flag service installation from unusual sources
    """
    print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*60}")
    print("  THREAT HUNT: LATERAL MOVEMENT DETECTION")
    print("  Hypothesis: Attacker moving via admin tools")
    print("  Data source: Windows Security Event Logs")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    print(f"{Fore.CYAN}[*] Loading Windows event logs: {filepath}"
          f"{Style.RESET_ALL}")
    df = load_logs(filepath)
    print(f"{Fore.CYAN}[*] Loaded {len(df)} Windows events"
          f"{Style.RESET_ALL}\n")

    findings = []

    # ── Hunt 1: Admin Tool Usage ─────────────────────────────
    print(f"{Fore.WHITE}{Style.BRIGHT}ANALYSIS 1 — Admin Tool Usage Detection"
          f"{Style.RESET_ALL}")
    print("─" * 60)

    df["is_admin_tool"] = df["process_name"].apply(is_admin_tool)
    admin_events = df[df["is_admin_tool"]].copy()

    print(f"  Total admin tool events   : {len(admin_events)}")

    if len(admin_events) > 0:
        tool_counts = admin_events["process_name"].value_counts()
        for tool, count in tool_counts.items():
            print(f"  {tool:<25}: {count} events")

        # Flag admin tools used outside business hours
        admin_events["hour"] = admin_events["timestamp"].dt.hour
        after_hours = admin_events[
            (admin_events["hour"] < 7) |
            (admin_events["hour"] > 19)
        ]

        if len(after_hours) > 0:
            print(f"\n  {Fore.RED}[!] Admin tool usage detected outside "
                  f"business hours:{Style.RESET_ALL}")
            for _, row in after_hours.iterrows():
                print(f"  → {row['process_name']} used by {row['username']} "
                      f"on {row['src_host']} → {row['dest_host']} "
                      f"at {row['timestamp']}")
                findings.append({
                    "type": "After-hours admin tool",
                    "detail": f"{row['process_name']} — "
                              f"{row['src_host']} → {row['dest_host']}",
                    "user": row["username"],
                    "time": str(row["timestamp"]),
                    "severity": "HIGH"
                })

    # ── Hunt 2: Workstation to Server Lateral Movement ───────
    print(f"\n{Fore.WHITE}{Style.BRIGHT}"
          f"ANALYSIS 2 — Workstation → Server Movement"
          f"{Style.RESET_ALL}")
    print("─" * 60)

    # Network logons (type 3) from workstations to servers
    network_logons = df[
        (df["event_id"] == 4624) &
        (df["logon_type"] == 3)
    ].copy()

    wkstn_to_srv = network_logons[
        network_logons["src_host"].apply(is_workstation) &
        network_logons["dest_host"].apply(is_server)
    ]

    print(f"  Network logons (type 3)   : {len(network_logons)}")
    print(f"  Workstation → Server      : {len(wkstn_to_srv)}")

    if len(wkstn_to_srv) > 0:
        # Group by source/dest/user
        movement_summary = wkstn_to_srv.groupby(
            ["src_host", "dest_host", "username"]
        ).agg(
            count=("timestamp", "count"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max")
        ).reset_index()

        # Flag using admin tools
        suspicious_moves = wkstn_to_srv[
            wkstn_to_srv["process_name"].apply(is_admin_tool)
        ]

        if len(suspicious_moves) > 0:
            print(f"\n  {Fore.RED}[!] Workstation → Server movement "
                  f"via admin tools detected:{Style.RESET_ALL}")
            for _, row in suspicious_moves.iterrows():
                print(f"  → {row['src_host']} → {row['dest_host']} "
                      f"via {row['process_name']} "
                      f"({row['username']}) at {row['timestamp']}")
                findings.append({
                    "type": "Lateral movement via admin tool",
                    "detail": f"{row['src_host']} → {row['dest_host']} "
                              f"via {row['process_name']}",
                    "user": row["username"],
                    "time": str(row["timestamp"]),
                    "severity": "CRITICAL"
                })

    # ── Hunt 3: Rapid Multi-System Authentication ────────────
    print(f"\n{Fore.WHITE}{Style.BRIGHT}"
          f"ANALYSIS 3 — Rapid Multi-System Authentication"
          f"{Style.RESET_ALL}")
    print("─" * 60)

    # Find accounts that authenticated to many systems quickly
    logon_events = df[df["event_id"] == 4624].copy()

    user_system_activity = logon_events.groupby("username").agg(
        unique_systems=("dest_host", "nunique"),
        total_logons=("timestamp", "count"),
        time_span_minutes=(
            "timestamp",
            lambda x: (x.max() - x.min()).total_seconds() / 60
        )
    ).reset_index()

    # Flag accounts hitting many systems in short time
    rapid_movers = user_system_activity[
        (user_system_activity["unique_systems"] >= 3) &
        (user_system_activity["time_span_minutes"] <= 30)
    ].sort_values("unique_systems", ascending=False)

    print(tabulate(
        user_system_activity.sort_values(
            "unique_systems", ascending=False
        ).head(8)[
            ["username", "unique_systems",
             "total_logons", "time_span_minutes"]
        ].round(1).values.tolist(),
        headers=["Username", "Unique Systems",
                 "Total Logons", "Time Span (min)"],
        tablefmt="grid"
    ))

    if len(rapid_movers) > 0:
        print(f"\n  {Fore.RED}[!] Accounts with rapid "
              f"multi-system authentication:{Style.RESET_ALL}")
        for _, row in rapid_movers.iterrows():
            print(f"  → {row['username']} authenticated to "
                  f"{row['unique_systems']} systems in "
                  f"{row['time_span_minutes']:.1f} minutes")
            findings.append({
                "type": "Rapid multi-system authentication",
                "detail": f"{row['unique_systems']} systems in "
                          f"{row['time_span_minutes']:.1f} minutes",
                "user": row["username"],
                "time": "Multiple",
                "severity": "HIGH"
            })

    # ── Hunt 4: Service Installation Chain ───────────────────
    print(f"\n{Fore.WHITE}{Style.BRIGHT}"
          f"ANALYSIS 4 — Service Installation Events"
          f"{Style.RESET_ALL}")
    print("─" * 60)

    service_installs = df[df["event_id"] == 7045].copy()
    print(f"  Total service installs    : {len(service_installs)}")

    # Service installs from admin tools are classic PsExec signature
    suspicious_installs = service_installs[
        service_installs["process_name"].apply(is_admin_tool)
    ]

    if len(suspicious_installs) > 0:
        print(f"\n  {Fore.RED}[!] Service installations via admin "
              f"tools — classic PsExec signature:{Style.RESET_ALL}")

        install_chain = suspicious_installs[[
            "timestamp", "src_host",
            "dest_host", "username", "process_name"
        ]].sort_values("timestamp")

        print(tabulate(
            install_chain.values.tolist(),
            headers=["Timestamp", "Source",
                     "Destination", "User", "Tool"],
            tablefmt="grid"
        ))

        # Detect movement chain
        unique_sources = suspicious_installs["src_host"].unique()
        unique_dests = suspicious_installs["dest_host"].unique()
        print(f"\n  Movement chain detected:")
        print(f"  Sources : {', '.join(unique_sources)}")
        print(f"  Targets : {', '.join(unique_dests)}")

        for _, row in suspicious_installs.iterrows():
            findings.append({
                "type": "PsExec service installation",
                "detail": f"{row['src_host']} → {row['dest_host']}",
                "user": row["username"],
                "time": str(row["timestamp"]),
                "severity": "CRITICAL"
            })

    # ── Hunt Conclusion ──────────────────────────────────────
    critical_findings = [
        f for f in findings if f["severity"] == "CRITICAL"
    ]
    lateral_confirmed = len(critical_findings) > 0

    print(f"\n{'='*60}")
    print(f"{Fore.WHITE}{Style.BRIGHT}HUNT CONCLUSION{Style.RESET_ALL}")
    print(f"  Hypothesis "
          f"{'CONFIRMED' if lateral_confirmed else 'NOT CONFIRMED'}")
    print(f"  Total findings : {len(findings)}")
    print(f"  Critical       : {len(critical_findings)}")

    if lateral_confirmed:
        print(f"\n  {Fore.RED}[!] Active lateral movement confirmed"
              f"{Style.RESET_ALL}")

        # Show unique compromised accounts
        compromised_users = list(set(
            f["user"] for f in critical_findings
        ))
        compromised_systems = list(set(
            f["detail"].split(" → ")[1].split(" via")[0]
            for f in critical_findings
            if " → " in f["detail"]
        ))

        print(f"  Compromised accounts  : "
              f"{', '.join(compromised_users)}")
        print(f"  Compromised systems   : "
              f"{', '.join(compromised_systems)}")
        print(f"\n  Recommended actions:")
        print(f"  → Isolate all identified compromised systems")
        print(f"  → Disable compromised accounts immediately")
        print(f"  → Capture memory dumps before remediation")
        print(f"  → Hunt for persistence mechanisms on all "
              f"affected systems")
        print(f"  → Review data access on compromised servers")
        print(f"\n  MITRE ATT&CK:")
        print(f"  → T1021.002 - SMB/Windows Admin Shares (PsExec)")
        print(f"  → T1047     - Windows Management Instrumentation")
    print()

    return findings

if __name__ == "__main__":
    hunt_lateral_movement()