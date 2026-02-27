"""
Security Log Analysis Toolkit – Stage 1 Core Prototype

Stage 1 uses a hardcoded dataset (sample_logs) to validate core analysis logic:
- Count total FAIL and SUCCESS logins
- Count FAILs per IP
- Flag suspicious IPs based on a fixed threshold
- Print a structured security report

Next stages will replace the hardcoded dataset with file input, regex parsing,
and an interactive menu system.
"""

from typing import Dict, List, Tuple


# =========================
# CONFIGURATION
# =========================
FAILURE_THRESHOLD = 8  # Fixed threshold for Stage 1 (example: 5 or 8)


# =========================
# DATASET (Stage 1: Hardcoded)
# =========================
sample_logs = [
    # --- Malicious IP Block (192.168.1.10) ---
    {"status": "FAIL", "user": "admin", "ip": "192.168.1.10"},
    {"status": "FAIL", "user": "root", "ip": "192.168.1.10"},
    {"status": "FAIL", "user": "guest", "ip": "192.168.1.10"},
    {"status": "FAIL", "user": "backup", "ip": "192.168.1.10"},
    {"status": "FAIL", "user": "test", "ip": "192.168.1.10"},
    {"status": "FAIL", "user": "admin", "ip": "192.168.1.10"},
    {"status": "FAIL", "user": "root", "ip": "192.168.1.10"},
    {"status": "FAIL", "user": "guest", "ip": "192.168.1.10"},
    {"status": "FAIL", "user": "admin", "ip": "192.168.1.10"},
    {"status": "FAIL", "user": "backup", "ip": "192.168.1.10"},

    # --- Normal Mixed Traffic ---
    {"status": "SUCCESS", "user": "kristin", "ip": "192.168.1.15"},
    {"status": "FAIL", "user": "kristin", "ip": "192.168.1.15"},
    {"status": "SUCCESS", "user": "john", "ip": "192.168.1.20"},
    {"status": "FAIL", "user": "john", "ip": "192.168.1.20"},
    {"status": "SUCCESS", "user": "alice", "ip": "192.168.1.21"},
    {"status": "FAIL", "user": "alice", "ip": "192.168.1.21"},
    {"status": "SUCCESS", "user": "bob", "ip": "192.168.1.22"},
    {"status": "FAIL", "user": "admin", "ip": "192.168.1.22"},
    {"status": "SUCCESS", "user": "carol", "ip": "192.168.1.23"},
    {"status": "FAIL", "user": "guest", "ip": "192.168.1.23"},

    {"status": "SUCCESS", "user": "dave", "ip": "192.168.1.24"},
    {"status": "FAIL", "user": "root", "ip": "192.168.1.24"},
    {"status": "SUCCESS", "user": "eve", "ip": "192.168.1.25"},
    {"status": "FAIL", "user": "admin", "ip": "192.168.1.25"},
    {"status": "SUCCESS", "user": "mike", "ip": "192.168.1.26"},
    {"status": "FAIL", "user": "guest", "ip": "192.168.1.26"},
    {"status": "SUCCESS", "user": "nancy", "ip": "192.168.1.27"},
    {"status": "FAIL", "user": "admin", "ip": "192.168.1.27"},
    {"status": "SUCCESS", "user": "sam", "ip": "192.168.1.28"},
    {"status": "FAIL", "user": "root", "ip": "192.168.1.28"},

    {"status": "SUCCESS", "user": "linda", "ip": "192.168.1.29"},
    {"status": "FAIL", "user": "admin", "ip": "192.168.1.29"},
    {"status": "SUCCESS", "user": "paul", "ip": "192.168.1.30"},
    {"status": "FAIL", "user": "guest", "ip": "192.168.1.30"},
    {"status": "SUCCESS", "user": "kevin", "ip": "192.168.1.31"},
    {"status": "FAIL", "user": "root", "ip": "192.168.1.31"},
    {"status": "SUCCESS", "user": "sara", "ip": "192.168.1.32"},
    {"status": "FAIL", "user": "admin", "ip": "192.168.1.32"},
    {"status": "SUCCESS", "user": "maria", "ip": "192.168.1.33"},
    {"status": "FAIL", "user": "guest", "ip": "192.168.1.33"},

    {"status": "SUCCESS", "user": "daniel", "ip": "192.168.1.34"},
    {"status": "FAIL", "user": "admin", "ip": "192.168.1.34"},
    {"status": "SUCCESS", "user": "olivia", "ip": "192.168.1.35"},
    {"status": "FAIL", "user": "root", "ip": "192.168.1.35"},
    {"status": "SUCCESS", "user": "chris", "ip": "192.168.1.36"},
    {"status": "FAIL", "user": "guest", "ip": "192.168.1.36"},
    {"status": "SUCCESS", "user": "emily", "ip": "192.168.1.37"},
    {"status": "FAIL", "user": "admin", "ip": "192.168.1.37"},
    {"status": "SUCCESS", "user": "ryan", "ip": "192.168.1.38"},
    {"status": "FAIL", "user": "root", "ip": "192.168.1.38"},
]


# =========================
# ANALYSIS FUNCTIONS
# =========================
def count_events(logs: List[Dict[str, str]]) -> Tuple[int, int]:
    """Return (fail_count, success_count)."""
    fail_count = 0
    success_count = 0

    for entry in logs:
        status = entry.get("status", "").upper()
        if status == "FAIL":
            fail_count += 1
        elif status == "SUCCESS":
            success_count += 1

    return fail_count, success_count


def count_fails_by_ip(logs: List[Dict[str, str]]) -> Dict[str, int]:
    """Return dict mapping IP -> number of FAIL events."""
    fails_by_ip: Dict[str, int] = {}

    for entry in logs:
        status = entry.get("status", "").upper()
        ip = entry.get("ip", "UNKNOWN")

        if status == "FAIL":
            fails_by_ip[ip] = fails_by_ip.get(ip, 0) + 1

    return fails_by_ip


def find_suspicious_ips(fails_by_ip: Dict[str, int], threshold: int) -> List[Tuple[str, int]]:
    """Return list of (ip, fail_count) where fail_count >= threshold, sorted descending."""
    flagged = [(ip, count) for ip, count in fails_by_ip.items() if count >= threshold]
    flagged.sort(key=lambda x: x[1], reverse=True)
    return flagged


# =========================
# REPORTING
# =========================
def print_report(
    logs: List[Dict[str, str]],
    fail_count: int,
    success_count: int,
    fails_by_ip: Dict[str, int],
    suspicious: List[Tuple[str, int]],
    threshold: int,
) -> None:
    """Print a structured, readable security report."""
    print("\n" + "=" * 46)
    print("      SECURITY LOG SUMMARY REPORT (STAGE 1)")
    print("=" * 46)

    print(f"Total log entries:        {len(logs)}")
    print(f"Total FAILED logins:      {fail_count}")
    print(f"Total SUCCESS logins:     {success_count}")

    # Sort IPs by fail count (descending)
    sorted_fails = sorted(fails_by_ip.items(), key=lambda x: x[1], reverse=True)

    print("\nFAILED LOGINS BY IP (Most Frequent First):")
    if sorted_fails:
        for ip, count in sorted_fails:
            print(f"  {ip:<15}  {count}")
    else:
        print("  No failed login attempts recorded.")

    print(f"\nSUSPICIOUS IPs (FAIL >= {threshold}):")
    if suspicious:
        for ip, count in suspicious:
            print(f"  ALERT: {ip:<15}  {count} failed attempts")
    else:
        print("  None flagged.")

    print("=" * 46 + "\n")


# =========================
# MAIN
# =========================
def main() -> None:
    fail_count, success_count = count_events(sample_logs)
    fails_by_ip = count_fails_by_ip(sample_logs)
    suspicious = find_suspicious_ips(fails_by_ip, FAILURE_THRESHOLD)

    print_report(
        logs=sample_logs,
        fail_count=fail_count,
        success_count=success_count,
        fails_by_ip=fails_by_ip,
        suspicious=suspicious,
        threshold=FAILURE_THRESHOLD,
    )
    
    input("Press Enter to exit...")


if __name__ == "__main__":
    main()