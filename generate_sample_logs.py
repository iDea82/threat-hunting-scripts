import pandas as pd
import numpy as np
import random
import datetime
import os

"""
SAMPLE LOG GENERATOR
====================
Generates three realistic log datasets for threat hunting:

1. network_logs.csv    — Web proxy/firewall logs for beaconing detection
2. auth_logs.csv       — Authentication logs for credential stuffing detection
3. windows_events.csv  — Windows event logs for lateral movement detection

Each dataset contains a mix of legitimate and malicious activity.
The malicious activity is deliberately subtle — designed to represent
the kind of low-and-slow attacker behavior that evades standard
detection rules but shows up clearly under statistical analysis.
"""

random.seed(42)
np.random.seed(42)

BASE_TIME = datetime.datetime(2026, 4, 7, 0, 0, 0)

# ── Internal hosts ───────────────────────────────────────────
INTERNAL_HOSTS = [
    "WKSTN-ATIJANI-01", "WKSTN-SMITH-02", "WKSTN-JONES-03",
    "WKSTN-PATEL-04", "WKSTN-CHEN-05", "SRV-DC-01",
    "SRV-FILE-01", "SRV-APP-01", "SRV-SQL-01"
]

INTERNAL_IPS = {
    "WKSTN-ATIJANI-01": "192.168.1.87",
    "WKSTN-SMITH-02":   "192.168.1.102",
    "WKSTN-JONES-03":   "192.168.1.115",
    "WKSTN-PATEL-04":   "192.168.1.128",
    "WKSTN-CHEN-05":    "192.168.1.143",
    "SRV-DC-01":        "192.168.10.10",
    "SRV-FILE-01":      "192.168.10.20",
    "SRV-APP-01":       "192.168.10.30",
    "SRV-SQL-01":       "192.168.10.40"
}

USERS = [
    "atijani", "jsmith", "bjones",
    "rpatel", "lchen", "svc_backup",
    "svc_monitoring", "administrator"
]

# ── Legitimate external destinations ─────────────────────────
LEGIT_DESTINATIONS = [
    ("142.250.80.46",  "google.com",       443),
    ("13.107.42.14",   "microsoft.com",    443),
    ("151.101.1.140",  "stackoverflow.com", 443),
    ("185.199.108.153","github.com",       443),
    ("52.84.0.50",     "amazonaws.com",    443),
    ("104.18.12.153",  "cloudflare.com",   443),
    ("17.253.144.10",  "apple.com",        443),
    ("216.58.209.142", "youtube.com",      443),
]

# ── Malicious C2 server ──────────────────────────────────────
C2_IP = "185.220.101.45"
C2_DOMAIN = "update-service.net"
C2_PORT = 443

def generate_network_logs():
    """
    Generates web proxy/firewall logs containing:
    - Normal browsing traffic from multiple hosts
    - ONE host beaconing to a C2 server every ~5 minutes
      with slight jitter to evade exact-interval detection
    """
    print("  Generating network logs...")
    records = []

    # Normal traffic — 24 hours, multiple hosts
    for hour in range(24):
        for host in INTERNAL_HOSTS:
            # Varying activity levels by time of day
            if 8 <= hour <= 18:
                num_requests = random.randint(15, 45)
            elif 18 < hour <= 22:
                num_requests = random.randint(5, 15)
            else:
                num_requests = random.randint(0, 3)

            for _ in range(num_requests):
                dest = random.choice(LEGIT_DESTINATIONS)
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                timestamp = BASE_TIME + datetime.timedelta(
                    hours=hour, minutes=minute, seconds=second
                )
                records.append({
                    "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "src_host": host,
                    "src_ip": INTERNAL_IPS[host],
                    "dest_ip": dest[0],
                    "dest_domain": dest[1],
                    "dest_port": dest[2],
                    "bytes_sent": random.randint(500, 50000),
                    "bytes_received": random.randint(1000, 500000),
                    "action": "allow",
                    "protocol": "HTTPS"
                })

    # Malicious beaconing — WKSTN-ATIJANI-01 beacons every ~5 min
    # Jitter of +/- 30 seconds to evade exact-interval detection
    beacon_host = "WKSTN-ATIJANI-01"
    beacon_interval = 300  # 5 minutes in seconds
    beacon_jitter = 30     # +/- 30 seconds

    current_time = BASE_TIME + datetime.timedelta(hours=2, minutes=17)
    end_time = BASE_TIME + datetime.timedelta(hours=24)

    while current_time < end_time:
        jitter = random.randint(-beacon_jitter, beacon_jitter)
        records.append({
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_host": beacon_host,
            "src_ip": INTERNAL_IPS[beacon_host],
            "dest_ip": C2_IP,
            "dest_domain": C2_DOMAIN,
            "dest_port": C2_PORT,
            "bytes_sent": random.randint(200, 800),
            "bytes_received": random.randint(100, 400),
            "action": "allow",
            "protocol": "HTTPS"
        })
        current_time += datetime.timedelta(seconds=beacon_interval + jitter)

    df = pd.DataFrame(records)
    df = df.sort_values("timestamp").reset_index(drop=True)
    df.to_csv("data/network_logs.csv", index=False)
    print(f"  ✓ network_logs.csv — {len(df)} records "
          f"({len([r for r in records if r['dest_ip'] == C2_IP])} beacon events)")
    return df

def generate_auth_logs():
    """
    Generates authentication logs containing:
    - Normal login patterns for all users
    - Credential stuffing attack — many source IPs
      each trying just 1-2 passwords against many accounts
      staying under per-source thresholds
    """
    print("  Generating authentication logs...")
    records = []

    # Normal authentication — business hours
    for hour in range(7, 20):
        for user in USERS:
            if random.random() < 0.7:
                minute = random.randint(0, 59)
                timestamp = BASE_TIME + datetime.timedelta(
                    hours=hour, minutes=minute
                )
                records.append({
                    "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "username": user,
                    "src_ip": random.choice(list(INTERNAL_IPS.values())),
                    "dest_host": "SRV-DC-01",
                    "event_id": 4624,
                    "status": "Success",
                    "logon_type": "Interactive",
                    "auth_package": "NTLM"
                })

            # Occasional failed logins
            if random.random() < 0.15:
                minute = random.randint(0, 59)
                timestamp = BASE_TIME + datetime.timedelta(
                    hours=hour, minutes=minute
                )
                records.append({
                    "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "username": user,
                    "src_ip": random.choice(list(INTERNAL_IPS.values())),
                    "dest_host": "SRV-DC-01",
                    "event_id": 4625,
                    "status": "Failed",
                    "logon_type": "Interactive",
                    "auth_package": "NTLM"
                })

    # Credential stuffing attack — distributed, low and slow
    # Each attacker IP tries only 1-2 accounts — below threshold
    attacker_ips = [
        f"203.{random.randint(1,254)}.{random.randint(1,254)}."
        f"{random.randint(1,254)}"
        for _ in range(50)
    ]

    stuffing_start = BASE_TIME + datetime.timedelta(hours=3, minutes=22)
    for i, attacker_ip in enumerate(attacker_ips):
        # Each IP tries 1-3 usernames
        targets = random.sample(USERS, random.randint(1, 3))
        for j, target_user in enumerate(targets):
            timestamp = stuffing_start + datetime.timedelta(
                seconds=i * 12 + j * 4
            )
            records.append({
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "username": target_user,
                "src_ip": attacker_ip,
                "dest_host": "SRV-DC-01",
                "event_id": 4625,
                "status": "Failed",
                "logon_type": "Network",
                "auth_package": "NTLM"
            })

    # One successful compromise after stuffing
    success_time = stuffing_start + datetime.timedelta(minutes=12)
    records.append({
        "timestamp": success_time.strftime("%Y-%m-%d %H:%M:%S"),
        "username": "bjones",
        "src_ip": attacker_ips[23],
        "dest_host": "SRV-DC-01",
        "event_id": 4624,
        "status": "Success",
        "logon_type": "Network",
        "auth_package": "NTLM"
    })

    df = pd.DataFrame(records)
    df = df.sort_values("timestamp").reset_index(drop=True)
    df.to_csv("data/auth_logs.csv", index=False)
    print(f"  ✓ auth_logs.csv — {len(df)} records "
          f"({len(attacker_ips)} attacker IPs, "
          f"{sum(1 for r in records if r.get('src_ip','').startswith('203.'))} "
          f"stuffing attempts)")
    return df

def generate_windows_events():
    """
    Generates Windows event logs containing:
    - Normal admin activity
    - Lateral movement — attacker using PsExec and WMI
      to move from compromised workstation to servers
    """
    print("  Generating Windows event logs...")
    records = []

    # Normal admin events
    admin_events = [
        (4624, "Successful logon"),
        (4625, "Failed logon"),
        (4648, "Logon with explicit credentials"),
        (4672, "Special privileges assigned"),
        (4688, "Process created"),
        (7045, "Service installed"),
    ]

    for hour in range(8, 18):
        num_events = random.randint(20, 60)
        for _ in range(num_events):
            event = random.choice(admin_events)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            timestamp = BASE_TIME + datetime.timedelta(
                hours=hour, minutes=minute, seconds=second
            )
            src_host = random.choice(INTERNAL_HOSTS)
            dest_host = random.choice(INTERNAL_HOSTS)
            user = random.choice(USERS[:6])

            records.append({
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "event_id": event[0],
                "description": event[1],
                "src_host": src_host,
                "src_ip": INTERNAL_IPS[src_host],
                "dest_host": dest_host,
                "dest_ip": INTERNAL_IPS[dest_host],
                "username": user,
                "process_name": random.choice([
                    "explorer.exe", "chrome.exe",
                    "outlook.exe", "svchost.exe"
                ]),
                "logon_type": random.choice([2, 3, 10]),
                "is_admin": random.random() < 0.2
            })

    # Lateral movement — attacker moves from WKSTN-ATIJANI-01
    # to servers using PsExec and WMI after credential compromise
    lateral_start = BASE_TIME + datetime.timedelta(
        hours=3, minutes=34
    )

    lateral_moves = [
        # (src, dest, tool, username, minutes_offset)
        ("WKSTN-ATIJANI-01", "SRV-FILE-01",  "psexec.exe", "bjones", 0),
        ("WKSTN-ATIJANI-01", "SRV-APP-01",   "wmic.exe",   "bjones", 3),
        ("SRV-FILE-01",      "SRV-DC-01",    "psexec.exe", "bjones", 7),
        ("SRV-APP-01",       "SRV-SQL-01",   "wmic.exe",   "bjones", 11),
        ("SRV-DC-01",        "SRV-SQL-01",   "psexec.exe", "bjones", 15),
    ]

    for src, dest, tool, user, offset in lateral_moves:
        timestamp = lateral_start + datetime.timedelta(minutes=offset)

        # Service installation event (PsExec creates a service)
        records.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "event_id": 7045,
            "description": "New service installed",
            "src_host": src,
            "src_ip": INTERNAL_IPS[src],
            "dest_host": dest,
            "dest_ip": INTERNAL_IPS[dest],
            "username": user,
            "process_name": tool,
            "logon_type": 3,
            "is_admin": True
        })

        # Network logon event
        records.append({
            "timestamp": (
                timestamp + datetime.timedelta(seconds=2)
            ).strftime("%Y-%m-%d %H:%M:%S"),
            "event_id": 4624,
            "description": "Successful logon",
            "src_host": src,
            "src_ip": INTERNAL_IPS[src],
            "dest_host": dest,
            "dest_ip": INTERNAL_IPS[dest],
            "username": user,
            "process_name": tool,
            "logon_type": 3,
            "is_admin": True
        })

    df = pd.DataFrame(records)
    df = df.sort_values("timestamp").reset_index(drop=True)
    df.to_csv("data/windows_events.csv", index=False)
    print(f"  ✓ windows_events.csv — {len(df)} records "
          f"({len(lateral_moves) * 2} lateral movement events)")
    return df

if __name__ == "__main__":
    print("\n  Generating sample log datasets...\n")
    os.makedirs("data", exist_ok=True)
    generate_network_logs()
    generate_auth_logs()
    generate_windows_events()
    print("\n  ✓ All log files generated in data/\n")