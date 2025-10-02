import pytest
from freezegun import freeze_time

import CriminalIP  # the module under test

BASE_URL = "https://example.com"


def make_client():
    return CriminalIP.Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        headers={"x-api-key": "DUMMY"},
    )


# ---------------------- get_ip_report ----------------------


def test_get_ip_report_ok(requests_mock):
    client = make_client()
    ip = "8.8.8.8"

    url = f"{BASE_URL}/v1/asset/ip/report"
    requests_mock.get(url, json={"status": 200, "ip": ip, "score": {"inbound": "low"}}, status_code=200)

    res = CriminalIP.get_ip_report(client, {"ip": ip})
    assert hasattr(res, "raw_response")
    assert res.raw_response["ip"] == ip
    assert res.outputs_prefix == "CriminalIP.IP"


def test_get_ip_report_404(requests_mock):
    client = make_client()
    ip = "0.0.0.0"

    url = f"{BASE_URL}/v1/asset/ip/report"
    requests_mock.get(url, json={"detail": "not found"}, status_code=404)

    with pytest.raises(Exception):
        CriminalIP.get_ip_report(client, {"ip": ip})


# ---------------------- check_malicious_ip ----------------------


def test_check_malicious_ip_true_by_score_and_protected(requests_mock):
    client = make_client()
    ip = "1.2.3.4"

    url = f"{BASE_URL}/v1/asset/ip/report"
    mock = {
        "status": 200,
        "ip": ip,
        "score": {"inbound": "Dangerous", "outbound": "Critical"},
        "protected_ip": {"count": 1, "data": [{"ip_address": "9.9.9.9"}]},
        "issues": {"is_proxy": False, "is_vpn": False},
    }
    requests_mock.get(url, json=mock, status_code=200)

    res = CriminalIP.check_malicious_ip(client, {"ip": ip})
    assert "Malicious: True" in res.readable_output
    assert res.outputs["malicious"] is True
    assert res.outputs["real_ip_list"][0]["ip_address"] == "9.9.9.9"


def test_check_malicious_ip_false_all_clear(requests_mock):
    client = make_client()
    ip = "8.8.8.8"

    url = f"{BASE_URL}/v1/asset/ip/report"
    mock = {
        "status": 200,
        "ip": ip,
        "score": {"inbound": "low", "outbound": "low"},
        "protected_ip": {"count": 0, "data": []},
        "issues": {"is_proxy": False, "is_vpn": False, "is_tor": False},
    }
    requests_mock.get(url, json=mock, status_code=200)

    res = CriminalIP.check_malicious_ip(client, {"ip": ip})
    assert "Malicious: False" in res.readable_output
    assert res.outputs["malicious"] is False


def test_check_malicious_ip_true_by_issue_flag(requests_mock):
    client = make_client()
    ip = "5.6.7.8"

    url = f"{BASE_URL}/v1/asset/ip/report"
    mock = {
        "status": 200,
        "ip": ip,
        "score": {"inbound": "low", "outbound": "low"},
        "protected_ip": {"count": 0, "data": []},
        "issues": {"is_tor": True},
    }
    requests_mock.get(url, json=mock, status_code=200)

    res = CriminalIP.check_malicious_ip(client, {"ip": ip})
    assert res.outputs["malicious"] is True


# ---------------------- check_last_scan_date ----------------------


@freeze_time("2025-08-22 12:00:00")
def test_check_last_scan_date_found_within_7_days(requests_mock):
    client = make_client()
    domain = "example.com"

    url = f"{BASE_URL}/v1/domain/reports"
    mock = {"data": {"reports": [{"scan_id": "SCAN-NEW", "reg_dtime": "2025-08-18T10:00:00Z"}]}}
    requests_mock.get(url, json=mock, status_code=200)

    res = CriminalIP.check_last_scan_date(client, {"domain": domain})
    assert res.outputs["scanned"] is True
    assert res.outputs["scan_id"] == "SCAN-NEW"


@freeze_time("2025-08-22 12:00:00")
def test_check_last_scan_date_not_found_or_old(requests_mock):
    client = make_client()
    domain = "example.com"

    url = f"{BASE_URL}/v1/domain/reports"
    mock = {"data": {"reports": [{"scan_id": "SCAN-OLD", "reg_dtime": "2025-07-01T00:00:00Z"}]}}
    requests_mock.get(url, json=mock, status_code=200)

    res = CriminalIP.check_last_scan_date(client, {"domain": domain})
    assert res.outputs["scanned"] is False
    assert res.outputs["scan_id"] in ["", "SCAN-OLD"]


def test_check_last_scan_date_no_reports(requests_mock):
    client = make_client()
    domain = "no-report.com"

    url = f"{BASE_URL}/v1/domain/reports"
    requests_mock.get(url, json={"data": {"reports": []}}, status_code=200)

    res = CriminalIP.check_last_scan_date(client, {"domain": domain})
    assert res.readable_output.startswith("### CriminalIP - Last Scan Date Check")
    assert res.outputs.get("last_scan_date") is None


# ---------------------- domain quick/lite/full scan ----------------------


def test_domain_quick_scan(requests_mock):
    client = make_client()
    domain = "example.com"

    url = f"{BASE_URL}/v1/domain/quick/hash/view"
    requests_mock.get(url, json={"status": 200, "domain": domain}, status_code=200)

    raw = client.domain_quick_scan(domain)
    assert raw["domain"] == domain


def test_domain_lite_scan_start(requests_mock):
    client = make_client()
    domain = "example.com"

    url = f"{BASE_URL}/v1/domain/lite/scan"
    requests_mock.get(url, json={"status": 200, "scan_id": "LITE-1"}, status_code=200)

    raw = client.domain_lite_scan(domain)
    assert raw["scan_id"] == "LITE-1"


def test_domain_lite_scan_status(requests_mock):
    client = make_client()
    scan_id = "LITE-1"

    url = f"{BASE_URL}/v1/domain/lite/progress"
    requests_mock.get(url, json={"status": 200, "scan_id": scan_id, "progress": 55}, status_code=200)

    raw = client.domain_lite_scan_status(scan_id)
    assert raw["progress"] == 55


def test_domain_lite_scan_result(requests_mock):
    client = make_client()
    scan_id = "LITE-1"

    url = f"{BASE_URL}/v1/domain/lite/report/{scan_id}"
    requests_mock.get(url, json={"status": 200, "scan_id": scan_id, "findings": {}}, status_code=200)

    raw = client.domain_lite_scan_result(scan_id)
    assert raw["scan_id"] == scan_id


def test_domain_full_scan_start(requests_mock):
    client = make_client()
    domain = "example.com"

    url = f"{BASE_URL}/v1/domain/scan"
    requests_mock.post(url, json={"status": 200, "scan_id": "FULL-1"}, status_code=200)

    raw = client.domain_full_scan(domain)
    assert raw["scan_id"] == "FULL-1"


def test_domain_full_scan_status(requests_mock):
    client = make_client()
    scan_id = "FULL-1"

    url = f"{BASE_URL}/v1/domain/status/{scan_id}"
    requests_mock.get(url, json={"status": 200, "scan_id": scan_id, "state": "running"}, status_code=200)

    raw = client.domain_full_scan_status(scan_id)
    assert raw["state"] == "running"


def test_domain_full_scan_result(requests_mock):
    client = make_client()
    scan_id = "FULL-1"

    url = f"{BASE_URL}/v2/domain/report/{scan_id}"
    requests_mock.get(url, json={"status": 200, "data": {"summary": {"risks": 2}}}, status_code=200)

    raw = client.domain_full_scan_result(scan_id)
    assert raw["data"]["summary"]["risks"] == 2


# ---------------------- make_email_body ----------------------


@freeze_time("2025-08-22 12:00:00")
def test_make_email_body_with_findings(requests_mock):
    client = make_client()
    domain = "example.com"
    scan_id = "FULL-1"

    url = f"{BASE_URL}/v2/domain/report/{scan_id}"
    mock = {"data": {"summary": {"punycode": True, "dga_score": 9, "newborn_domain": "2025-08-10T00:00:00Z"}}}
    requests_mock.get(url, json=mock, status_code=200)

    res = CriminalIP.make_email_body(client, {"domain": domain, "scan_id": scan_id})
    assert "### CriminalIP - Full Scan Report" in res.readable_output
    assert "DGA Score" in res.readable_output or "Punycode" in res.readable_output


@freeze_time("2025-08-22 12:00:00")
def test_make_email_body_no_findings(requests_mock):
    client = make_client()
    domain = "example.com"
    scan_id = "FULL-1"

    url = f"{BASE_URL}/v2/domain/report/{scan_id}"
    mock = {"data": {"summary": {"punycode": False, "dga_score": 3}}}
    requests_mock.get(url, json=mock, status_code=200)

    res = CriminalIP.make_email_body(client, {"domain": domain, "scan_id": scan_id})
    assert res.readable_output.startswith("### CriminalIP - Full Scan Report")
    assert "DGA Score" in res.readable_output


# ---------------------- micro_asm ----------------------


@freeze_time("2025-08-22 12:00:00")
def test_micro_asm_with_findings(requests_mock):
    client = make_client()
    domain = "example.com"
    scan_id = "FULL-2"

    url = f"{BASE_URL}/v2/domain/report/{scan_id}"
    mock = {
        "data": {
            "certificates": [{"valid_to": "2025-09-05T00:00:00Z"}],
            "network_logs": {
                "abuse_record": {"critical": 1, "dangerous": 0},
                "data": [{"url": "http://localhost/payload.exe"}],
            },
        }
    }
    requests_mock.get(url, json=mock, status_code=200)

    res = CriminalIP.micro_asm(client, {"domain": domain, "scan_id": scan_id})
    assert "### CriminalIP - Micro ASM Report" in res.readable_output
    assert "example.com" in res.readable_output
    assert "Certificate Valid To" in res.readable_output
    assert "Abuse Critical" in res.readable_output


@freeze_time("2025-08-22 12:00:00")
def test_micro_asm_no_findings(requests_mock):
    client = make_client()
    domain = "example.com"
    scan_id = "FULL-3"

    url = f"{BASE_URL}/v2/domain/report/{scan_id}"
    mock = {
        "data": {
            "certificates": [{"valid_to": "2026-01-01T00:00:00Z"}],
            "network_logs": {"abuse_record": {"critical": 0, "dangerous": 0}, "data": []},
        }
    }
    requests_mock.get(url, json=mock, status_code=200)

    res = CriminalIP.micro_asm(client, {"domain": domain, "scan_id": scan_id})
    assert res.readable_output.startswith("### CriminalIP - Micro ASM Report")
    assert "Abuse Critical" in res.readable_output


# ---------------------- smoke: client.domain_reports ----------------------


def test_domain_reports(requests_mock):
    client = make_client()
    domain = "example.com"

    url = f"{BASE_URL}/v1/domain/reports"
    requests_mock.get(url, json={"data": {"reports": [{"scan_id": "S1"}]}}, status_code=200)

    raw = client.domain_reports(domain)
    assert "reports" in raw.get("data", {})
