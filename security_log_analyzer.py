"""
Security Log Analysis Toolkit – Stage 1 Core Prototype

Implements threshold-based detection of suspicious IP activity
using authentication event data.

Stage 1 uses a hardcoded dataset (sample_logs) to validate core analysis logic:
- Count total FAIL and SUCCESS logins
- Count FAILS per IP
- Flag suspicious IPs based on a fixed threshold
- Print a structured security report

Next stages will replace the hardcoded dataset with file input, regex parsing,
and an interactive menu system.
"""

from typing import Dict, List, Tuple

# =========================
# CONFIGURATION
# =========================
FAILURE_THRESHOLD = 8  # fixed threshold for Stage 1 (example: 5 or 8)

# =========================
# DATASET SETUP (Stage 1: Hardcoded Strings)
# Format: "STATUS USER IP"
# =========================
sample_logs: List[str] = [

    # --- Malicious IP block (192.168.1.10) ---
    "FAIL admin 192.168.1.10",
    "FAIL root 192.168.1.10",
    "FAIL guest 192.168.1.10",
    "FAIL backup 192.168.1.10",
    "FAIL test 192.168.1.10",
    "FAIL admin 192.168.1.10",
    "FAIL root 192.168.1.10",
    "FAIL guest 192.168.1.10",
    "FAIL admin 192.168.1.10",
    "FAIL backup 192.168.1.10",

    # --- Normal mixed traffic ---
    "SUCCESS kristin 192.168.1.15",
    "FAIL kristin 192.168.1.15",
    "SUCCESS john 192.168.1.20",
    "FAIL john 192.168.1.20",
    "SUCCESS alice 192.168.1.21",
    "FAIL alice 192.168.1.21",
    "SUCCESS bob 192.168.1.22",
    "FAIL admin 192.168.1.22",
    "SUCCESS carol 192.168.1.23",
    "FAIL guest 192.168.1.23",

    "SUCCESS dave 192.168.1.24",
    "FAIL root 192.168.1.24",
    "SUCCESS eve 192.168.1.25",
    "FAIL admin 192.168.1.25",
    "SUCCESS mike 192.168.1.26",
    "FAIL guest 192.168.1.26",
    "SUCCESS nancy 192.168.1.27",
    "FAIL admin 192.168.1.27",
    "SUCCESS sam 192.168.1.28",
    "FAIL root 192.168.1.28",

    "SUCCESS linda 192.168.1.29",
    "FAIL admin 192.168.1.29",
    "SUCCESS paul 192.168.1.30",
    "FAIL guest 192.168.1.30",
    "SUCCESS kevin 192.168.1.31",
    "FAIL root 192.168.1.31",
    "SUCCESS sara 192.168.1.32",
    "FAIL admin 192.168.1.32",
    "SUCCESS maria 192.168.1.33",
    "FAIL guest 192.168.1.33",

    "SUCCESS daniel 192.168.1.34",
    "FAIL admin 192.168.1.34",
    "SUCCESS olivia 192.168.1.35",
    "FAIL root 192.168.1.35",
    "SUCCESS chris 192.168.1.36",
    "FAIL guest 192.168.1.36",
    "SUCCESS emily 192.168.1.37",
    "FAIL admin 192.168.1.37",
    "SUCCESS ryan 192.168.1.38",
    "FAIL root 192.168.1.38",
]


# =========================
# STEP 3: LOG PARSING (split)
# =========================
def parse_log_entry(log_line: str) -> Tuple[str, str, str]:
    """
    Parse a log entry using split().
    Expected format: "STATUS USER IP"
    Returns: (status, user, ip)
    """
    parts = log_line.split()
    status = parts[0]
    user = parts[1]
    ip = parts[2]
    return status, user, ip


# =========================
# STEP 4-6: COUNTING + THRESHOLD CHECK
# =========================
def analyze_logs(logs: List[str], threshold: int) -> Tuple[int, int, Dict[str, int], List[Tuple[str, int]]]:
    total_fail = 0
    total_success = 0
    fails_by_ip: Dict[str, int] = {}

    for line in logs:
        status, user, ip = parse_log_entry(line)

        if status == "FAIL":
            total_fail += 1
            fails_by_ip[ip] = fails_by_ip.get(ip, 0) + 1
        elif status == "SUCCESS":
            total_success += 1

    # suspicious list: IPs meeting/exceeding threshold
    suspicious = [(ip, count) for ip, count in fails_by_ip.items() if count >= threshold]
    suspicious.sort(key=lambda x: x[1], reverse=True)

    return total_fail, total_success, fails_by_ip, suspicious


# =========================
# STEP 7: REPORT OUTPUT
# =========================
def print_report(
    logs: List[str],
    total_fail: int,
    total_success: int,
    fails_by_ip: Dict[str, int],
    suspicious: List[Tuple[str, int]],
    threshold: int
) -> None:
    print("\n==============================================")
    print("     SECURITY LOG SUMMARY REPORT (STAGE 1)")
    print("==============================================")
    print(f"Total log entries:      {len(logs)}")
    print(f"Total FAIL logins:      {total_fail}")
    print(f"Total SUCCESS logins:   {total_success}")

    print("\nFAILED LOGINS BY IP (Most Frequent First):")
    sorted_fails = sorted(fails_by_ip.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_fails:
        print(f"{ip:<15} {count}")

    print(f"\nSUSPICIOUS IPs (FAIL >= {threshold}):")
    if suspicious:
        for ip, count in suspicious:
            print(f"ALERT: {ip:<15} {count} failed attempts")
    else:
        print("None flagged.")

    print("==============================================\n")


def main() -> None:
    total_fail, total_success, fails_by_ip, suspicious = analyze_logs(sample_logs, FAILURE_THRESHOLD)
    print_report(sample_logs, total_fail, total_success, fails_by_ip, suspicious, FAILURE_THRESHOLD)
    input("Press Enter to exit...")


if __name__ == "__main__":
    main()
