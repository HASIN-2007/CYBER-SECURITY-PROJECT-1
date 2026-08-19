import re
from pathlib import Path


COMMON_PASSWORD_FILE = "common_passwords.txt"
REPORT_FILE = "password_security_report.txt"


def load_common_passwords():
    """Load commonly used passwords from the local dictionary."""

    common_passwords = set()

    try:
        with open(COMMON_PASSWORD_FILE, "r", encoding="utf-8") as file:
            for line in file:
                password = line.strip().lower()

                if password:
                    common_passwords.add(password)

    except FileNotFoundError:
        print(f"[WARNING] {COMMON_PASSWORD_FILE} was not found.")

    return common_passwords


def analyze_password(password, common_passwords):
    """Analyze password security characteristics."""

    checks = {
        "Minimum length (8+)": len(password) >= 8,
        "Uppercase letter": bool(re.search(r"[A-Z]", password)),
        "Lowercase letter": bool(re.search(r"[a-z]", password)),
        "Number": bool(re.search(r"\d", password)),
        "Special character": bool(re.search(r"[^A-Za-z0-9]", password)),
    }

    common_password = password.lower() in common_passwords

    score = sum(checks.values())

    if len(password) >= 12:
        score += 1

    if common_password:
        score = max(0, score - 2)

    if common_password:
        strength = "VERY WEAK"
    elif score <= 2:
        strength = "WEAK"
    elif score == 3:
        strength = "MODERATE"
    elif score == 4:
        strength = "STRONG"
    else:
        strength = "VERY STRONG"

    recommendations = []

    if len(password) < 8:
        recommendations.append(
            "Use at least 8 characters."
        )

    if len(password) < 12:
        recommendations.append(
            "Consider using 12 or more characters."
        )

    if not checks["Uppercase letter"]:
        recommendations.append(
            "Add at least one uppercase letter."
        )

    if not checks["Lowercase letter"]:
        recommendations.append(
            "Add at least one lowercase letter."
        )

    if not checks["Number"]:
        recommendations.append(
            "Add at least one number."
        )

    if not checks["Special character"]:
        recommendations.append(
            "Add at least one special character."
        )

    if common_password:
        recommendations.append(
            "Avoid commonly used passwords."
        )

    if not recommendations:
        recommendations.append(
            "Password meets all implemented security checks."
        )

    return {
        "length": len(password),
        "checks": checks,
        "common_password": common_password,
        "score": score,
        "strength": strength,
        "recommendations": recommendations
    }


def display_results(result):
    """Display password analysis results."""

    print("\n" + "=" * 72)
    print("             PASSWORD STRENGTH CHECKER")
    print("=" * 72)

    print("\n[1] PASSWORD ANALYSIS")
    print("-" * 72)

    print(f"Password length : {result['length']} characters")
    print(f"Security score  : {result['score']}/6")
    print(f"Strength level  : {result['strength']}")

    print("\n[2] SECURITY CHECKS")
    print("-" * 72)

    for check_name, passed in result["checks"].items():

        status = "PASS" if passed else "FAIL"

        print(f"{status:<6} | {check_name}")

    print("\n[3] COMMON PASSWORD CHECK")
    print("-" * 72)

    if result["common_password"]:
        print("WARNING: Password appears in the common-password dictionary.")

    else:
        print("PASS: Password was not found in the local common-password dictionary.")

    print("\n[4] SECURITY RECOMMENDATIONS")
    print("-" * 72)

    for number, recommendation in enumerate(
        result["recommendations"],
        start=1
    ):
        print(f"{number}. {recommendation}")

    print("\n" + "=" * 72)
    print("             PASSWORD ANALYSIS COMPLETE")
    print("=" * 72)


def save_report(result):
    """Save password analysis results to a report."""

    with open(REPORT_FILE, "w", encoding="utf-8") as file:

        file.write("=" * 72 + "\n")
        file.write("             PASSWORD SECURITY REPORT\n")
        file.write("=" * 72 + "\n\n")

        file.write(
            f"Password length : {result['length']} characters\n"
        )

        file.write(
            f"Security score  : {result['score']}/6\n"
        )

        file.write(
            f"Strength level  : {result['strength']}\n\n"
        )

        file.write("SECURITY CHECKS\n")
        file.write("-" * 72 + "\n")

        for check_name, passed in result["checks"].items():

            status = "PASS" if passed else "FAIL"

            file.write(
                f"{status:<6} | {check_name}\n"
            )

        file.write("\nCOMMON PASSWORD CHECK\n")
        file.write("-" * 72 + "\n")

        if result["common_password"]:
            file.write(
                "WARNING: Password appears in the common-password dictionary.\n"
            )
        else:
            file.write(
                "PASS: Password was not found in the local dictionary.\n"
            )

        file.write("\nSECURITY RECOMMENDATIONS\n")
        file.write("-" * 72 + "\n")

        for number, recommendation in enumerate(
            result["recommendations"],
            start=1
        ):
            file.write(
                f"{number}. {recommendation}\n"
            )

        file.write("\n" + "=" * 72 + "\n")
        file.write("PASSWORD SECURITY REPORT GENERATED\n")
        file.write("=" * 72 + "\n")

    print(
        f"\n[REPORT] Security report saved to: {REPORT_FILE}"
    )


def main():

    print("\n" + "=" * 72)
    print("             PASSWORD STRENGTH CHECKER")
    print("=" * 72)

    common_passwords = load_common_passwords()

    password = input(
        "\nEnter a password to analyze: "
    )

    if not password:
        print("\n[ERROR] Password cannot be empty.")
        return

    result = analyze_password(
        password,
        common_passwords
    )

    display_results(result)

    save_report(result)


if __name__ == "__main__":
    main()