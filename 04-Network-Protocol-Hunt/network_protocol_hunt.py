from collections import Counter


TRAFFIC_FILE = "network_traffic.txt"


# Protocol security classification
PROTOCOL_RISK = {
    "DNS": ("LOW", "Domain name resolution"),
    "HTTPS": ("LOW", "Encrypted web communication"),
    "SSH": ("LOW", "Encrypted remote administration"),
    "HTTP": ("MEDIUM", "Unencrypted web communication"),
    "SMTP": ("MEDIUM", "Email protocol; encryption depends on configuration"),
    "FTP": ("HIGH", "File transfer protocol may transmit credentials/data in plaintext"),
    "TELNET": ("CRITICAL", "Unencrypted remote access protocol")
}


def parse_traffic_line(line):
    """
    Convert one network traffic line into structured data.
    """

    parts = [part.strip() for part in line.split("|")]

    if len(parts) != 9:
        return None

    return {
        "timestamp": parts[0],
        "source_ip": parts[1],
        "destination_ip": parts[2],
        "source_port": parts[3],
        "destination_port": parts[4],
        "transport": parts[5],
        "protocol": parts[6],
        "action": parts[7],
        "details": parts[8]
    }


def load_traffic():
    """
    Load and parse network traffic.
    """

    traffic = []

    try:

        with open(TRAFFIC_FILE, "r", encoding="utf-8") as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                entry = parse_traffic_line(line)

                if entry:
                    traffic.append(entry)

    except FileNotFoundError:

        print(f"\n[ERROR] {TRAFFIC_FILE} was not found.")
        return []

    return traffic


def analyze_protocols(traffic):
    """
    Analyze protocols and identify risky communication.
    """

    protocol_counts = Counter()
    findings = []

    for entry in traffic:

        protocol = entry["protocol"]

        protocol_counts[protocol] += 1

        risk, description = PROTOCOL_RISK.get(
            protocol,
            ("UNKNOWN", "Unknown protocol")
        )

        if risk in ("HIGH", "CRITICAL"):

            findings.append({
                "severity": risk,
                "protocol": protocol,
                "source": entry["source_ip"],
                "destination": entry["destination_ip"],
                "port": entry["destination_port"],
                "action": entry["action"],
                "details": entry["details"],
                "description": description
            })

    return protocol_counts, findings


def display_results(traffic, protocol_counts, findings):
    """
    Display network protocol investigation results.
    """

    print("\n" + "=" * 72)
    print("             NETWORK PROTOCOL HUNT - ANALYZER")
    print("=" * 72)

    print("\n[1] TRAFFIC COLLECTION")
    print("-" * 72)

    print(f"Total traffic records analyzed: {len(traffic)}")

    print("\n[2] PROTOCOL DISCOVERY")
    print("-" * 72)

    for protocol, count in sorted(protocol_counts.items()):

        risk, description = PROTOCOL_RISK.get(
            protocol,
            ("UNKNOWN", "Unknown protocol")
        )

        print(
            f"{protocol:<8} | "
            f"Port: {get_port(protocol):<4} | "
            f"Risk: {risk:<8} | "
            f"Records: {count}"
        )

    print("\n[3] SECURITY FINDINGS")
    print("-" * 72)

    if not findings:

        print("No high-risk protocols detected.")

    else:

        for number, finding in enumerate(findings, start=1):

            print(f"\nFINDING #{number}")
            print(f"Severity     : {finding['severity']}")
            print(f"Protocol     : {finding['protocol']}")
            print(f"Source IP    : {finding['source']}")
            print(f"Destination  : {finding['destination']}")
            print(f"Port         : {finding['port']}")
            print(f"Action       : {finding['action']}")
            print(f"Details      : {finding['details']}")
            print(f"Risk         : {finding['description']}")

    print("\n[4] HUNT SUMMARY")
    print("-" * 72)

    high = sum(
        1 for finding in findings
        if finding["severity"] == "HIGH"
    )

    critical = sum(
        1 for finding in findings
        if finding["severity"] == "CRITICAL"
    )

    print(f"High-risk findings     : {high}")
    print(f"Critical findings      : {critical}")
    print(f"Total security findings: {len(findings)}")

    print("\n" + "=" * 72)
    print("             NETWORK PROTOCOL HUNT COMPLETE")
    print("=" * 72)


def get_port(protocol):
    """
    Return the standard destination port for a protocol.
    """

    ports = {
        "DNS": 53,
        "HTTPS": 443,
        "SSH": 22,
        "HTTP": 80,
        "SMTP": 25,
        "FTP": 21,
        "TELNET": 23
    }

    return ports.get(protocol, "?")


def save_report(traffic, protocol_counts, findings):
    """
    Generate a network investigation report.
    """

    report_file = "protocol_hunt_report.txt"

    with open(report_file, "w", encoding="utf-8") as file:

        file.write("=" * 72 + "\n")
        file.write("             NETWORK PROTOCOL HUNT REPORT\n")
        file.write("=" * 72 + "\n\n")

        file.write(
            f"Total traffic records analyzed: {len(traffic)}\n\n"
        )

        file.write("PROTOCOL SUMMARY\n")
        file.write("-" * 72 + "\n")

        for protocol, count in sorted(protocol_counts.items()):

            risk, description = PROTOCOL_RISK.get(
                protocol,
                ("UNKNOWN", "Unknown protocol")
            )

            file.write(
                f"{protocol:<8} | "
                f"Port: {get_port(protocol):<4} | "
                f"Risk: {risk:<8} | "
                f"Records: {count}\n"
            )

        file.write("\nSECURITY FINDINGS\n")
        file.write("-" * 72 + "\n")

        for number, finding in enumerate(findings, start=1):

            file.write(f"\nFINDING #{number}\n")
            file.write(f"Severity     : {finding['severity']}\n")
            file.write(f"Protocol     : {finding['protocol']}\n")
            file.write(f"Source IP    : {finding['source']}\n")
            file.write(f"Destination  : {finding['destination']}\n")
            file.write(f"Port         : {finding['port']}\n")
            file.write(f"Action       : {finding['action']}\n")
            file.write(f"Details      : {finding['details']}\n")
            file.write(f"Risk         : {finding['description']}\n")

        file.write("\n" + "=" * 72 + "\n")
        file.write("NETWORK PROTOCOL HUNT REPORT GENERATED\n")
        file.write("=" * 72 + "\n")

    print(
        f"\n[REPORT] Investigation report saved to: {report_file}"
    )


def main():

    traffic = load_traffic()

    if not traffic:
        return

    protocol_counts, findings = analyze_protocols(traffic)

    display_results(
        traffic,
        protocol_counts,
        findings
    )

    save_report(
        traffic,
        protocol_counts,
        findings
    )


if __name__ == "__main__":
    main()