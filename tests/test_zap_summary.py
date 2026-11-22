from zap_summary import load_findings, strip_html, to_markdown

SAMPLE = "samples/sample_zap_report.json"


def test_findings_are_sorted_highest_risk_first():
    findings = load_findings(SAMPLE)
    assert [f["risk"] for f in findings] == ["Medium", "Medium", "Low"]


def test_known_cwe_maps_to_owasp_category():
    findings = {f["name"]: f for f in load_findings(SAMPLE)}
    assert findings["Cross-Domain Misconfiguration"]["owasp"] == "A01 Broken Access Control"
    assert findings["Content Security Policy (CSP) Header Not Set"]["owasp"] == "Map manually"


def test_instances_are_counted():
    findings = {f["name"]: f for f in load_findings(SAMPLE)}
    assert findings["Content Security Policy (CSP) Header Not Set"]["count"] == 2


def test_html_is_removed_from_solutions():
    assert strip_html("<p>Set the header.</p>") == "Set the header."


def test_markdown_table_has_one_row_per_finding():
    table = to_markdown(load_findings(SAMPLE))
    assert len(table.splitlines()) == 2 + 3