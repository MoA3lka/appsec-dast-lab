"""Turn an OWASP ZAP JSON report into a prioritised Markdown findings table."""

import argparse
import json
import re
import sys

RISK_NAMES = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}

# A few well-known CWE to OWASP Top 10 (2021) mappings; anything else is mapped by hand
OWASP_BY_CWE = {
    "79": "A03 Injection",
    "89": "A03 Injection",
    "352": "A01 Broken Access Control",
    "200": "A01 Broken Access Control",
    "264": "A01 Broken Access Control",
    "829": "A08 Software and Data Integrity Failures",
    "497": "A01 Broken Access Control",
    "524": "A04 Insecure Design",
    "319": "A02 Cryptographic Failures",
    "16": "A05 Security Misconfiguration",
}


def strip_html(text):
    """ZAP descriptions contain HTML tags; keep the plain text only."""
    return re.sub(r"<[^>]+>", "", text or "").strip()


def load_findings(path):
    """Read a ZAP report and return one dict per alert, highest risk first."""
    with open(path, encoding="utf-8") as f:
        report = json.load(f)

    findings = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            risk_code = str(alert.get("riskcode", "0"))
            cwe = str(alert.get("cweid", ""))
            findings.append({
                "name": alert.get("name") or alert.get("alert", "Unknown"),
                "risk": RISK_NAMES.get(risk_code, "Unknown"),
                "risk_code": int(risk_code) if risk_code.isdigit() else 0,
                "cwe": cwe,
                "owasp": OWASP_BY_CWE.get(cwe, "Map manually"),
                "count": len(alert.get("instances", [])),
                "solution": strip_html(alert.get("solution")),
            })

    return sorted(findings, key=lambda f: (-f["risk_code"], f["name"]))


def to_markdown(findings):
    """Build a findings table an engineer can act on."""
    lines = [
        "| Risk | Finding | CWE | OWASP Top 10 | Instances | Fix |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        fix = f["solution"].replace("|", "/").replace("\n", " ")
        lines.append(f"| {f['risk']} | {f['name']} | {f['cwe']} | {f['owasp']} | {f['count']} | {fix} |")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Summarise an OWASP ZAP JSON report.")
    parser.add_argument("--input", required=True, help="path to the ZAP JSON report")
    parser.add_argument("--fail-on-high", action="store_true", help="exit with code 1 if any High risk finding exists")
    args = parser.parse_args()

    findings = load_findings(args.input)
    print(to_markdown(findings))

    if args.fail_on_high and any(f["risk"] == "High" for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()