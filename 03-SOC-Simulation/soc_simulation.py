from collections import defaultdict
from datetime import datetime


LOG_FILE = "sample_logs.txt"

FAILED_LOGIN_THRESHOLD = 3


def parse_log_line(line):
    """
    Parse a security log entry into structured fields.
    """

    parts = [part.strip() for part in line.split("|")]

    if len(parts) != 5:
        return None

    timestamp = parts[0]
    level = parts[1]
    ip_address = parts[2]
    event = parts[3]
    details = parts[4]

    return {
        "timestamp": timestamp,
        "level": level,
        "ip": ip_address,
        "event": event,
        "details": details
    }


def load_logs():
    """
    Read and parse the sample security log file.
    """

    logs = []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                log = parse_log_line(line)

                if log:
                    logs.append(log)

    except FileNotFoundError:

        print(f"\n[ERROR] Log file '{LOG_FILE}' was not found.")
        return []

    return logs


def analyze_logs(logs):
    """
    Analyze logs and generate security alerts.
    """

    failed_attempts = defaultdict(list)
    alerts = []

    for log in logs:

        ip = log["ip"]

        # Detect failed login attempts
        if log["event"] == "LOGIN_FAILED":

            failed_attempts[ip].append(log)

        # Detect unauthorized access
        elif log["event"] == "UNAUTHORIZED_ACCESS":

            alerts.append({
                "severity": "HIGH",
                "type": "Unauthorized Access Attempt",
                "ip": ip,
                "timestamp": log["timestamp"],
                "details": log["details"]
            })

    # Analyze repeated failed logins
    for ip, attempts in failed_attempts.items():

        if len(attempts) >= FAILED_LOGIN_THRESHOLD:

            alerts.append({
                "severity": "HIGH",
                "type": "Possible Brute-Force Attack",
                "ip": ip,
                "timestamp": attempts[0]["timestamp"],
                "details": (
                    f"{len(attempts)} failed login attempts detected"
                )
            })

    # Detect successful login after multiple failures
    for ip, attempts in failed_attempts.items():

        if len(attempts) >= FAILED_LOGIN_THRESHOLD:

            first_failure_time = datetime.strptime(
                attempts[0]["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            for log in logs:

                if (
                    log["ip"] == ip
                    and log["event"] == "LOGIN_SUCCESS"
                ):

                    success_time = datetime.strptime(
                        log["timestamp"],
                        "%Y-%m-%d %H:%M:%S"
                    )

                    if success_time > first_failure_time:

                        alerts.append({
                            "severity": "CRITICAL",
                            "type": "Successful Login After Failed Attempts",
                            "ip": ip,
                            "timestamp": log["timestamp"],
                            "details": (
                                "Successful authentication occurred "
                                "after repeated failed login attempts"
                            )
                        })

                        break

    return alerts

def save_alert_report(alerts):
    """
    Save detected security alerts to a text report.
    """

    report_file = "alerts_report.txt"

    with open(report_file, "w", encoding="utf-8") as file:

        file.write("=" * 70 + "\n")
        file.write("              SOC INCIDENT REPORT\n")
        file.write("=" * 70 + "\n\n")

        if not alerts:

            file.write("No suspicious activity detected.\n")

        else:

            file.write(f"Total Alerts: {len(alerts)}\n\n")

            for number, alert in enumerate(alerts, start=1):

                file.write(f"ALERT #{number}\n")
                file.write("-" * 70 + "\n")
                file.write(f"Severity   : {alert['severity']}\n")
                file.write(f"Type       : {alert['type']}\n")
                file.write(f"Source IP  : {alert['ip']}\n")
                file.write(f"Timestamp  : {alert['timestamp']}\n")
                file.write(f"Details    : {alert['details']}\n\n")

        file.write("=" * 70 + "\n")
        file.write("SOC ANALYSIS REPORT GENERATED\n")
        file.write("=" * 70 + "\n")

    print(f"\n[REPORT] Incident report saved to: {report_file}")
def display_summary(logs, alerts):
    """
    Display SOC analysis results.
    """

    print("\n" + "=" * 70)
    print("              SOC SIMULATION - SECURITY MONITOR")
    print("=" * 70)

    print("\n[1] LOG COLLECTION")
    print("-" * 70)

    print(f"Total log entries analyzed: {len(logs)}")

    print("\n[2] THREAT ANALYSIS")
    print("-" * 70)

    print("Analyzing authentication and access events...")

    print("\n[3] SECURITY ALERTS")
    print("-" * 70)

    if not alerts:

        print("No suspicious activity detected.")

    else:

        for number, alert in enumerate(alerts, start=1):

            print(f"\nALERT #{number}")
            print(f"Severity   : {alert['severity']}")
            print(f"Type       : {alert['type']}")
            print(f"Source IP  : {alert['ip']}")
            print(f"Timestamp  : {alert['timestamp']}")
            print(f"Details    : {alert['details']}")

    print("\n[4] SOC SUMMARY")
    print("-" * 70)

    critical = sum(
        1 for alert in alerts
        if alert["severity"] == "CRITICAL"
    )

    high = sum(
        1 for alert in alerts
        if alert["severity"] == "HIGH"
    )

    print(f"Critical alerts : {critical}")
    print(f"High alerts     : {high}")
    print(f"Total alerts    : {len(alerts)}")

    print("\n" + "=" * 70)
    print("                 SOC ANALYSIS COMPLETE")
    print("=" * 70)


def main():

    logs = load_logs()

    if not logs:
        return

    alerts = analyze_logs(logs)

    display_summary(logs, alerts)

    save_alert_report(alerts)

if __name__ == "__main__":
    main()