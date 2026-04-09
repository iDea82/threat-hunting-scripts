import pandas as pd
import numpy as np
from colorama import init, Fore, Style
from tabulate import tabulate
import datetime

init(autoreset=True)

"""
THREAT HUNT: Beaconing Detection
=================================
HYPOTHESIS: A compromised host inside our network is running
malware that periodically calls home to a C2 server at regular
intervals. This beaconing behavior blends into normal HTTPS
traffic but reveals itself through statistical analysis of
connection timing.

TECHNIQUE: Malware beacons at a fixed interval with small
random jitter to avoid exact-interval detection. While no
two consecutive connections happen at exactly the same time,
the STANDARD DEVIATION of intervals between connections to
the same destination will be abnormally low compared to
legitimate browsing traffic.

MITRE ATT&CK: T1071.001 - Application Layer Protocol: Web
              T1571 - Non-Standard Port
"""

def load_logs(filepath):
    df = pd.read_csv(filepath)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def calculate_beacon_score(intervals):
    """
    Calculates a beacon score based on the statistical
    properties of connection intervals.

    Low standard deviation = regular timing = beaconing
    High standard deviation = irregular timing = normal browsing

    Returns a score from 0-100 where higher = more suspicious
    """
    if len(intervals) < 5:
        return 0

    mean_interval = np.mean(intervals)
    std_interval = np.std(intervals)

    if mean_interval == 0:
        return 0

    # Coefficient of variation — lower = more regular = more suspicious
    cv = std_interval / mean_interval

    # Convert to a 0-100 score — lower CV = higher score
    if cv < 0.1:
        score = 95
    elif cv < 0.2:
        score = 85
    elif cv < 0.3:
        score = 70
    elif cv < 0.5:
        score = 50
    elif cv < 0.8:
        score = 25
    else:
        score = 5

    return score

def hunt_beaconing(filepath="data/network_logs.csv"):
    """
    Main beaconing hunt function.

    Steps:
    1. Load network logs
    2. Group by source host + destination IP
    3. Calculate inter-connection intervals for each pair
    4. Score each pair statistically
    5. Flag pairs with suspiciously regular timing
    """
    print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*60}")
    print("  THREAT HUNT: BEACONING DETECTION")
    print("  Hypothesis: Malware C2 beaconing via regular HTTPS")
    print("  Data source: Network proxy/firewall logs")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    # Load logs
    print(f"{Fore.CYAN}[*] Loading network logs: {filepath}{Style.RESET_ALL}")
    df = load_logs(filepath)
    print(f"{Fore.CYAN}[*] Loaded {len(df)} records spanning "
          f"{df['timestamp'].min()} to {df['timestamp'].max()}"
          f"{Style.RESET_ALL}\n")

    # Filter to outbound HTTPS only — C2 typically uses 443
    https_df = df[df["dest_port"] == 443].copy()
    print(f"{Fore.CYAN}[*] Filtered to {len(https_df)} HTTPS connections"
          f"{Style.RESET_ALL}")

    # Group by source host + destination IP
    groups = https_df.groupby(["src_host", "dest_ip"])

    results = []

    for (src_host, dest_ip), group in groups:
        # Need at least 5 connections to calculate meaningful statistics
        if len(group) < 5:
            continue

        # Sort by timestamp and calculate intervals in seconds
        sorted_group = group.sort_values("timestamp")
        timestamps = sorted_group["timestamp"].tolist()
        intervals = []

        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i-1]).total_seconds()
            if delta > 0:
                intervals.append(delta)

        if len(intervals) < 4:
            continue

        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        beacon_score = calculate_beacon_score(intervals)

        # Only report suspicious pairs
        if beacon_score >= 50:
            dest_domain = sorted_group["dest_domain"].iloc[0]
            total_bytes = sorted_group["bytes_sent"].sum()

            results.append({
                "src_host": src_host,
                "dest_ip": dest_ip,
                "dest_domain": dest_domain,
                "connections": len(group),
                "mean_interval_sec": round(mean_interval, 1),
                "std_deviation_sec": round(std_interval, 1),
                "beacon_score": beacon_score,
                "total_bytes_sent": total_bytes,
                "first_seen": sorted_group["timestamp"].min(),
                "last_seen": sorted_group["timestamp"].max()
            })

    # Sort by beacon score descending
    results.sort(key=lambda x: x["beacon_score"], reverse=True)

    if not results:
        print(f"\n{Fore.GREEN}[✓] No beaconing behavior detected"
              f"{Style.RESET_ALL}\n")
        return []

    # Print results
    print(f"\n{Fore.RED}[!] BEACONING CANDIDATES IDENTIFIED: "
          f"{len(results)}{Style.RESET_ALL}\n")

    for r in results:
        color = Fore.RED if r["beacon_score"] >= 80 else Fore.YELLOW

        print(f"{color}{'─'*60}{Style.RESET_ALL}")
        print(f"{color}  BEACON SCORE: {r['beacon_score']}/100{Style.RESET_ALL}")
        print(f"  Source Host   : {r['src_host']}")
        print(f"  Destination   : {r['dest_ip']} ({r['dest_domain']})")
        print(f"  Connections   : {r['connections']}")
        print(f"  Mean Interval : {r['mean_interval_sec']}s "
              f"({r['mean_interval_sec']/60:.1f} minutes)")
        print(f"  Std Deviation : {r['std_deviation_sec']}s")
        print(f"  Total Sent    : {r['total_bytes_sent']:,} bytes")
        print(f"  Active Period : {r['first_seen']} → {r['last_seen']}")

        # Interpret the findings
        print(f"\n  {Fore.YELLOW}ANALYST NOTES:{Style.RESET_ALL}")
        if r["beacon_score"] >= 80:
            print(f"  → Highly regular connection pattern detected")
            print(f"  → Mean interval of {r['mean_interval_sec']/60:.1f} minutes "
                  f"is consistent with malware C2 beaconing")
            print(f"  → Low standard deviation ({r['std_deviation_sec']}s) "
                  f"indicates automated rather than human behavior")
            print(f"  → Recommend: Isolate host, capture traffic, "
                  f"check process making connections")
        print()

    # Summary table
    print(f"\n{Fore.WHITE}{Style.BRIGHT}SUMMARY TABLE{Style.RESET_ALL}")
    table_data = [[
        r["src_host"],
        r["dest_ip"],
        r["connections"],
        f"{r['mean_interval_sec']/60:.1f}m",
        f"{r['std_deviation_sec']}s",
        r["beacon_score"]
    ] for r in results]

    print(tabulate(
        table_data,
        headers=["Source Host", "Dest IP", "Conns",
                 "Mean Interval", "Std Dev", "Score"],
        tablefmt="grid"
    ))

    print(f"\n{Fore.WHITE}{Style.BRIGHT}HUNT CONCLUSION{Style.RESET_ALL}")
    print(f"  Hypothesis {'CONFIRMED' if results else 'NOT CONFIRMED'} — "
          f"{len(results)} beaconing candidate(s) identified")
    print(f"  MITRE ATT&CK: T1071.001 - C2 over Web Protocols")
    print(f"  Next Step: Correlate with endpoint data — "
          f"identify process making connections\n")

    return results

if __name__ == "__main__":
    hunt_beaconing()