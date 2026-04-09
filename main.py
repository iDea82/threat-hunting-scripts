import sys
from colorama import init, Fore, Style
from hunt_beaconing import hunt_beaconing
from hunt_credential_stuffing import hunt_credential_stuffing
from hunt_lateral_movement import hunt_lateral_movement

init(autoreset=True)

def print_banner():
    print(f"\n{Fore.CYAN}{Style.BRIGHT}")
    print("=" * 60)
    print("  THREAT HUNTING PLATFORM")
    print("  Proactive Adversary Detection")
    print("  Built by Adesina Tijani — Security Operations")
    print("=" * 60)
    print(Style.RESET_ALL)

def print_menu():
    print(f"{Fore.WHITE}{Style.BRIGHT}Available Hunts:{Style.RESET_ALL}\n")
    print(f"  {Fore.CYAN}[1]{Style.RESET_ALL} Beaconing Detection")
    print(f"      Hypothesis: Malware C2 beaconing via regular HTTPS")
    print(f"      MITRE: T1071.001\n")
    print(f"  {Fore.CYAN}[2]{Style.RESET_ALL} Credential Stuffing Detection")
    print(f"      Hypothesis: Distributed low-and-slow auth attack")
    print(f"      MITRE: T1110.004\n")
    print(f"  {Fore.CYAN}[3]{Style.RESET_ALL} Lateral Movement Detection")
    print(f"      Hypothesis: Attacker moving via admin tools")
    print(f"      MITRE: T1021.002 / T1047\n")
    print(f"  {Fore.CYAN}[4]{Style.RESET_ALL} Run All Hunts\n")

if __name__ == "__main__":
    print_banner()
    print_menu()

    choice = input("Select hunt [1-4]: ").strip()

    if choice == "1":
        hunt_beaconing()
    elif choice == "2":
        hunt_credential_stuffing()
    elif choice == "3":
        hunt_lateral_movement()
    elif choice == "4":
        print(f"\n{Fore.CYAN}[*] Running all hunts...{Style.RESET_ALL}\n")
        b = hunt_beaconing()
        c = hunt_credential_stuffing()
        l = hunt_lateral_movement()

        # Final summary
        print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*60}")
        print("  FULL HUNT SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        print(f"  Beaconing         : "
              f"{'CONFIRMED' if b else 'NOT CONFIRMED'}")
        print(f"  Credential Stuffing: "
              f"{'CONFIRMED' if c else 'NOT CONFIRMED'}")
        print(f"  Lateral Movement  : "
              f"{'CONFIRMED' if l else 'NOT CONFIRMED'}\n")
    else:
        print(f"{Fore.RED}Invalid selection{Style.RESET_ALL}")
        sys.exit(1)