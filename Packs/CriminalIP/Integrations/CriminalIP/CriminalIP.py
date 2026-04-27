import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401  # pylint: disable=import-error
from CommonServerUserPython import *  # noqa: F401  # pylint: disable=import-error
from datetime import datetime, UTC
import dateparser
from typing import Any, cast


class Client(BaseClient):
    """
    Criminal IP API Client using XSOAR BaseClient.
    """

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        headers: dict[str, str],
        timeout: float | None = None,
    ):
        super().__init__(
            base_url=base_url.rstrip("/") if base_url else "",
            verify=verify,
            proxy=proxy,
            headers=headers,
        )
        self.timeout: float = float(timeout) if timeout is not None else 0.0

    def ip_lookup(self, ip: str) -> dict:
        return self._http_request(
            "GET",
            "/v1/asset/ip/report",
            params={"ip": ip},
            timeout=self.timeout,
        )

    def domain_quick_scan(self, domain: str) -> dict:
        return self._http_request(
            "GET",
            "/v1/domain/quick/hash/view",
            params={"domain": domain},
            timeout=self.timeout,
        )

    def domain_lite_scan(self, domain: str) -> dict:
        return self._http_request(
            "GET",
            "/v1/domain/lite/scan",
            params={"query": domain},
            timeout=self.timeout,
        )

    def domain_lite_scan_status(self, scan_id: str) -> dict:
        return self._http_request(
            "GET",
            "/v1/domain/lite/progress",
            params={"scan_id": scan_id},
            timeout=self.timeout,
        )

    def domain_lite_scan_result(self, scan_id: str) -> dict:
        return self._http_request(
            "GET",
            f"/v1/domain/lite/report/{scan_id}",
            timeout=self.timeout,
        )

    def domain_full_scan(self, domain: str) -> dict:
        return self._http_request(
            "POST",
            "/v1/domain/scan",
            files={"query": (None, domain)},
            timeout=self.timeout,
        )

    def domain_full_scan_status(self, scan_id: str) -> dict:
        return self._http_request(
            "GET",
            f"/v1/domain/status/{scan_id}",
            timeout=self.timeout,
        )

    def domain_full_scan_result(self, scan_id: str) -> dict:
        return self._http_request(
            "GET",
            f"/v2/domain/report/{scan_id}",
            timeout=self.timeout,
        )

    def domain_reports(self, domain: str) -> dict:
        return self._http_request(
            "GET",
            "/v1/domain/reports",
            params={"query": domain, "offset": 0},
            timeout=self.timeout,
        )


def validate_response(raw: dict, prefix: str, scan_id: str | None = None, domain: str | None = None):
    status = raw.get("status")

    if status and status != 200:
        msg = raw.get("message") or raw.get("error") or "Unknown error"
        if scan_id:
            return_error(f"CriminalIP Error: {msg} (scan_id={scan_id}). Details: {raw}")
        elif domain:
            return_error(f"CriminalIP Error: {msg} (domain={domain}). Details: {raw}")
        else:
            return_error(f"CriminalIP Error: {msg}. Details: {raw}")

    if status == 200 and not raw.get("data"):
        return CommandResults(
            readable_output=tableToMarkdown(f"{prefix} - No data available", [{}]),
            outputs_prefix=prefix,
            outputs={},
            raw_response=raw,
        )

    return None


def _wrap_simple_output(prefix: str, raw: dict, key_field: str = "") -> CommandResults:
    if not raw:
        return_error(f"CriminalIP Error: Empty response for {prefix}.")

    if isinstance(raw, dict):
        if "error" in raw or "errors" in raw:
            err_msg = raw.get("error") or raw.get("errors")
            return_error(f"CriminalIP Error: {err_msg}. Details: {raw}")
        if "message" in raw and str(raw.get("message")).lower() not in ("ok", "success", "api success"):
            err_msg = raw.get("message")
            return_error(f"CriminalIP Error: {err_msg}. Details: {raw}")

    status_val = None
    for status_key in ("status", "code", "status_code", "http_status"):
        if status_key in raw:
            status_val = raw.get(status_key)
            break
    if status_val is not None:
        try:
            s_int = int(status_val)
            if s_int != 200:
                return_error(f"CriminalIP Error: HTTP status {s_int} returned for {prefix}. Details: {raw}")
        except Exception:
            if str(status_val).lower() not in ("200", "ok", "success"):
                return_error(f"CriminalIP Error: Status '{status_val}' returned for {prefix}. Details: {raw}")

    data_container = raw.get("data") if isinstance(raw.get("data"), dict) else raw
    flat: dict[str, Any] = {}

    def extract_scan_id() -> Any:
        if isinstance(data_container, dict):
            if "scan_id" in data_container:
                return data_container.get("scan_id")
            if "data" in data_container and isinstance(data_container["data"], dict):
                return data_container["data"].get("scan_id")
        return raw.get("scan_id")

    def extract_progress() -> Any:
        for key in ("scan_percentage", "progress", "percentage"):
            if isinstance(data_container, dict) and key in data_container:
                return data_container.get(key)
            if key in raw:
                return raw.get(key)
        state = (raw.get("state") or (data_container or {}).get("state") or "").lower()
        if state in {"done", "completed", "complete", "finished", "success"}:
            return 100
        if state in {"running", "in_progress", "scanning", "queued"}:
            return 0
        return None

    if prefix in {"CriminalIP.Full_Scan", "CriminalIP.Domain_Lite"}:
        scan_id = extract_scan_id()
        if not scan_id:
            return_error("CriminalIP Error: No scan_id returned")
        flat["scan_id"] = scan_id
        flat["data"] = {"scan_id": scan_id}

    elif prefix in {"CriminalIP.Full_Scan_Status", "CriminalIP.Domain_Lite_Status"}:
        pct = extract_progress()
        if pct is None:
            return_error("CriminalIP Error: Could not extract scan progress")
        flat["scan_percentage"] = pct
        flat["data"] = {"scan_percentage": pct}
        if "status" in raw:
            flat["status"] = raw["status"]
        if "state" in raw:
            flat["state"] = raw["state"]

    elif prefix == "CriminalIP.Domain_Quick":
        data_section = raw.get("data") or {}
        flat = {
            "domain": data_section.get("domain"),
            "reg_dtime": data_section.get("reg_dtime"),
            "result": data_section.get("result"),
            "type": data_section.get("type"),
        }
        readable = tableToMarkdown(
            "CriminalIP - Domain Quick Scan (Risk Result)",
            [
                {
                    "Domain": flat.get("domain", "N/A"),
                    "Reg Date": flat.get("reg_dtime", "N/A"),
                    "Risk Result": flat.get("result", "N/A"),
                    "Type": flat.get("type", "N/A"),
                }
            ],
        )
        return CommandResults(
            readable_output=readable,
            outputs_prefix=prefix,
            outputs_key_field="domain",
            outputs=flat,
            raw_response=raw,
        )

    elif prefix == "CriminalIP.Domain_Lite_Result":
        domain_info = (data_container or {}).get("main_domain_info") or {}
        dns_record = (data_container or {}).get("dns_record") or {}
        summary = (data_container or {}).get("summary") or {}
        mapped_ips = (data_container or {}).get("mapped_ip") or []
        if isinstance(mapped_ips, dict):
            mapped_ips = [mapped_ips]

        def _join_safe(lst):
            if not lst:
                return "N/A"
            return ", ".join(lst)

        a_records_list: list[str] = []
        try:
            a_records_list = (dns_record.get("dns_record_type_a") or {}).get("ipv4", []) or []
        except Exception:
            a_records_list = []

        ns_records_list = dns_record.get("dns_record_type_ns", []) or []

        flat = {
            "domain": domain_info.get("main_domain") or "N/A",
            "created": domain_info.get("domain_created") or "N/A",
            "registrar": domain_info.get("domain_registrar") or "N/A",
            "score": data_container.get("domain_score") if isinstance(data_container, dict) else "N/A",
            "report_time": raw.get("report_time")
            or (data_container.get("report_time") if isinstance(data_container, dict) else "N/A"),
            "phishing_prob": summary.get("url_phishing_prob") if summary.get("url_phishing_prob") is not None else "N/A",
            "dga_score": summary.get("dga_score") if summary.get("dga_score") is not None else "N/A",
            "abuse_critical": (summary.get("abuse_record") or {}).get("critical", 0),
            "abuse_dangerous": (summary.get("abuse_record") or {}).get("dangerous", 0),
            "a_records": _join_safe(a_records_list[:5]),
            "ns_records": _join_safe(ns_records_list[:3]),
            "mapped_ips": _join_safe([f"{i.get('ip')}({i.get('score')})" for i in mapped_ips[:5]]),
        }

        readable = tableToMarkdown("CriminalIP - Domain Lite Scan Result (Summary)", [flat])
        return CommandResults(
            readable_output=readable,
            outputs_prefix=prefix,
            outputs_key_field="domain",
            outputs=flat,
            raw_response=raw,
        )

    elif prefix == "CriminalIP.Full_Scan_Result":
        data_section = (data_container or {}) or {}
        domain_info = data_section.get("main_domain_info") or {}
        summary = data_section.get("summary") or {}
        certs = data_section.get("certificates") or []
        connected_ips = data_section.get("connected_ip_info") or []
        ssl_detail = data_section.get("ssl_detail") or {}

        def _join_connected(ips):
            if not ips:
                return "N/A"
            return ", ".join([f"{i.get('ip')}({i.get('score')},{i.get('country')})" for i in ips[:5]])

        flat = {
            "domain": domain_info.get("main_domain") or "N/A",
            "created": domain_info.get("domain_created") or "N/A",
            "registrar": domain_info.get("domain_registrar") or "N/A",
            "score": (domain_info.get("domain_score") or {}).get("score") or "N/A",
            "report_time": raw.get("report_time")
            or (data_section.get("report_time") if isinstance(data_section, dict) else "N/A"),
            "phishing_prob": summary.get("url_phishing_prob") if summary.get("url_phishing_prob") is not None else "N/A",
            "dga_score": summary.get("dga_score") if summary.get("dga_score") is not None else "N/A",
            "punycode": summary.get("punycode") if summary.get("punycode") is not None else "N/A",
            "fake_https": summary.get("fake_https_url") if summary.get("fake_https_url") is not None else "N/A",
            "abuse_critical": (summary.get("abuse_record") or {}).get("critical", 0),
            "abuse_dangerous": (summary.get("abuse_record") or {}).get("dangerous", 0),
            "cert_valid_to": certs[0].get("valid_to") if certs else "N/A",
            "connected_ips": _join_connected(connected_ips),
            "score_percentage": (domain_info.get("domain_score") or {}).get("score_percentage") or "N/A",
            "ssl_vulns": ", ".join([k for k, v in (ssl_detail.get("vulnerable") or {}).items() if v]) or "None",
        }

        readable = tableToMarkdown("CriminalIP - Full Scan Result (Summary)", [flat])
        return CommandResults(
            readable_output=readable,
            outputs_prefix=prefix,
            outputs_key_field="domain",
            outputs=flat,
            raw_response=raw,
        )

    else:
        if isinstance(data_container, dict) and data_container:
            flat = data_container
        else:
            flat = raw or {"info": "No data available"}

    return CommandResults(
        readable_output=tableToMarkdown(prefix, [flat]),
        outputs_prefix=prefix,
        outputs_key_field=key_field or "",
        outputs=flat,
        raw_response=raw,
    )


def get_ip_report(client: Client, args: dict[str, Any]) -> CommandResults:
    ip = args.get("ip")
    if not ip:
        return_error("ip argument is required")
    ip = cast(str, ip)

    raw = client.ip_lookup(ip)
    if not raw or "error" in raw:
        return_error(f"CriminalIP Error: No IP report found for {ip}")

    first_whois = (raw.get("whois", {}).get("data") or [{}])[0]
    first_hostname = (raw.get("hostname", {}).get("data") or [{}])[0]
    first_port = (raw.get("port", {}).get("data") or [{}])[0]
    first_vuln = (raw.get("vulnerability", {}).get("data") or [{}])[0]

    summary = {
        "IP": raw.get("ip"),
        "InboundScore": raw.get("score", {}).get("inbound"),
        "OutboundScore": raw.get("score", {}).get("outbound"),
        "Issues": ", ".join([k for k, v in (raw.get("issues") or {}).items() if v]) or "None",
        "ProtectedIPs": raw.get("protected_ip", {}).get("count", 0),
        "RelatedDomains": raw.get("domain", {}).get("count", 0),
        "ASN": first_whois.get("as_no"),
        "ASName": first_whois.get("as_name"),
        "Org": first_whois.get("org_name"),
        "Country": first_whois.get("org_country_code"),
        "Hostname": first_hostname.get("domain_name_full"),
        "OpenPorts": len(raw.get("port", {}).get("data", [])),
        "ObservedPort": first_port.get("open_port_no"),
        "ObservedService": first_port.get("app_name"),
        "Vulnerabilities": len(raw.get("vulnerability", {}).get("data", [])),
        "ObservedCVE": first_vuln.get("cve_id"),
        "ObservedCVSS": first_vuln.get("cvssv3_score"),
    }

    return CommandResults(
        readable_output=tableToMarkdown("CriminalIP - IP Report (Extended Summary)", [summary]),
        outputs_prefix="CriminalIP.IP",
        outputs_key_field="ip",
        outputs=summary,
        raw_response=raw,
    )


def check_malicious_ip(client: Client, args: dict[str, Any]) -> CommandResults:
    ip = args.get("ip")
    if not ip:
        return_error("ip argument is required")
    ip = cast(str, ip)

    data = client.ip_lookup(ip)
    if not data or "error" in data:
        return_error(f"CriminalIP Error: No data returned for IP {ip}")

    malicious = False
    real_ip_list: list[dict] = []

    score = data.get("score", {})
    if score.get("inbound") in ("Dangerous", "Critical") or score.get("outbound") in ("Dangerous", "Critical"):
        malicious = True

    protected = data.get("protected_ip", {})
    if protected.get("count", 0) > 0:
        malicious = True
        real_ip_list = protected.get("data", [])

    if any((data.get("issues") or {}).values()):
        malicious = True

    outputs = {
        "ip": ip,
        "malicious": malicious,
        "real_ip_list": real_ip_list,
        "raw": data,
    }

    real_ips_str = ", ".join([item.get("ip_address", "") for item in real_ip_list]) if real_ip_list else "None"

    readable_output = f"Malicious: {malicious}\n" + tableToMarkdown(
        "CriminalIP - Malicious IP Check",
        [
            {
                "IP": ip,
                "Malicious": malicious,
                "RealIPs": real_ips_str,
            }
        ],
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CriminalIP.Mal_IP",
        outputs_key_field="ip",
        outputs=outputs,
        raw_response=data,
    )


def _to_aware_utc(dt: datetime | None) -> datetime | None:
    if not dt:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def check_last_scan_date(client: Client, args: dict[str, Any]) -> CommandResults:
    domain = args.get("domain")
    if not domain:
        return_error("domain argument is required")
    domain = cast(str, domain)

    raw = client.domain_reports(domain)
    if not raw or "error" in raw:
        return_error(f"CriminalIP Error: No scan reports found for {domain}")

    reports = (raw.get("data") or {}).get("reports", [])
    if not reports:
        return CommandResults(
            readable_output=tableToMarkdown(
                "CriminalIP - Last Scan Date Check",
                [{"Domain": domain, "Scan ID": "N/A", "Scan Date": "N/A", "Scanned (within 7d)": False}],
            ),
            outputs_prefix="CriminalIP.Scan_Date",
            outputs_key_field="scan_id",
            outputs={"last_scan_date": None},
            raw_response=raw,
        )
    report = reports[0]
    reg_dt = _to_aware_utc(dateparser.parse(report.get("reg_dtime", "")))
    now = datetime.now(UTC)
    scanned_bool = bool(reg_dt and (now - reg_dt).days <= 7)

    outputs = {
        "domain": domain,
        "scan_id": report.get("scan_id"),
        "scan_date": str(reg_dt) if reg_dt else "",
        "scanned": scanned_bool,
        "raw": raw,
    }

    readable = tableToMarkdown(
        "CriminalIP - Last Scan Date Check",
        [
            {
                "Domain": domain,
                "Scan ID": report.get("scan_id"),
                "Scan Date": str(reg_dt) if reg_dt else "N/A",
                "Scanned (within 7d)": scanned_bool,
            }
        ],
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="CriminalIP.Scan_Date",
        outputs_key_field="scan_id",
        outputs=outputs,
        raw_response=raw,
    )


def domain_quick_scan(client: Client, args: dict[str, Any]) -> CommandResults:
    domain = args.get("domain")
    if not domain:
        return_error("domain argument is required")
    domain = cast(str, domain)

    raw = client.domain_quick_scan(domain)
    return _wrap_simple_output("CriminalIP.Domain_Quick", raw, key_field="domain")


def domain_lite_scan(client: Client, args: dict[str, Any]) -> CommandResults:
    domain = args.get("domain")
    if not domain:
        return_error("domain argument is required")
    domain = cast(str, domain)

    raw = client.domain_lite_scan(domain)

    scan_id = (raw.get("data") or {}).get("scan_id")
    if not scan_id:
        return_error(f"CriminalIP Error: No scan_id returned. Details: {raw}")

    outputs = {"domain": domain, "scan_id": scan_id}

    readable = tableToMarkdown(
        "CriminalIP - Domain Lite Scan Started",
        [{"Domain": domain, "Scan ID": scan_id}],
        headers=["Domain", "Scan ID"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="CriminalIP.Domain_Lite",
        outputs_key_field="scan_id",
        outputs=outputs,
        raw_response=raw,
    )


def domain_lite_scan_status(client: Client, args: dict[str, Any]) -> CommandResults:
    scan_id = args.get("scan_id")
    if not scan_id:
        return_error("scan_id argument is required")
    scan_id = cast(str, scan_id)

    raw = client.domain_lite_scan_status(scan_id)
    if not raw or not raw.get("data"):
        return_error(f"CriminalIP Error: No status found for scan_id={scan_id}")
    return _wrap_simple_output("CriminalIP.Domain_Lite_Status", raw)


def domain_lite_scan_result(client: Client, args: dict[str, Any]) -> CommandResults:
    scan_id = args.get("scan_id")
    if not scan_id:
        return_error("scan_id argument is required")
    scan_id = cast(str, scan_id)

    raw = client.domain_lite_scan_result(scan_id)
    if not raw or not raw.get("data"):
        return_error(f"CriminalIP Error: No result found for scan_id={scan_id}")
    return _wrap_simple_output("CriminalIP.Domain_Lite_Result", raw, key_field="domain")


def domain_full_scan(client: Client, args: dict[str, Any]) -> CommandResults:
    domain = args.get("domain")
    if not domain:
        return_error("domain argument is required")
    domain = cast(str, domain)

    raw = client.domain_full_scan(domain)

    scan_id = (raw.get("data") or {}).get("scan_id")
    if not scan_id:
        return_error(f"CriminalIP Error: No scan_id returned. Details: {raw}")

    outputs = {"scan_id": scan_id}

    readable = tableToMarkdown(
        "CriminalIP - Full Scan Started",
        [{"Domain": domain}, {"Scan ID": scan_id}],
        headers=[],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="CriminalIP.Full_Scan",
        outputs_key_field="scan_id",
        outputs=outputs,
        raw_response=raw,
    )


def domain_full_scan_status(client: Client, args: dict[str, Any]) -> CommandResults:
    scan_id = args.get("scan_id")
    if not scan_id:
        return_error("scan_id argument is required")
    scan_id = cast(str, scan_id)

    raw = client.domain_full_scan_status(scan_id)
    if not raw or not raw.get("data"):
        return_error(f"CriminalIP Error: No status found for scan_id={scan_id}")
    return _wrap_simple_output("CriminalIP.Full_Scan_Status", raw)


def domain_full_scan_result(client: Client, args: dict[str, Any]) -> CommandResults:
    scan_id = args.get("scan_id")
    if not scan_id:
        return_error("scan_id argument is required")
    scan_id = cast(str, scan_id)

    raw = client.domain_full_scan_result(scan_id)
    if not raw or not raw.get("data"):
        return_error(f"CriminalIP Error: No result found for scan_id={scan_id}")
    return _wrap_simple_output("CriminalIP.Full_Scan_Result", raw, key_field="domain")


def make_email_body(client: Client, args: dict[str, Any]) -> CommandResults:
    domain, scan_id = args.get("domain"), args.get("scan_id")
    if not scan_id or not domain:
        return_error("Both scan_id and domain are required")

    scan_id = cast(str, scan_id)
    domain = cast(str, domain)

    raw = client.domain_full_scan_result(scan_id)
    if not raw or "error" in raw:
        return_error(f"CriminalIP Error: No scan result found for scan_id={scan_id}")

    data = raw.get("data", {}) or {}
    domain_info = data.get("main_domain_info", {}) or {}
    summary = data.get("summary", {}) or {}
    certs = data.get("certificates", []) or []
    ssl_detail = data.get("ssl_detail", {}) or {}
    connected_ips = data.get("connected_ip_info", []) or []

    abuse_record = summary.get("abuse_record", {}) or {}
    abuse_critical = abuse_record.get("critical", 0)
    abuse_dangerous = abuse_record.get("dangerous", 0)
    cert_valid_to = certs[0].get("valid_to") if certs else "N/A"

    connected_ips_str = (
        ", ".join([f"{ip.get('ip')}({ip.get('score')},{ip.get('country')})" for ip in connected_ips]) if connected_ips else "N/A"
    )
    ssl_vulns = ", ".join([k for k, v in (ssl_detail.get("vulnerable") or {}).items() if v]) or "None"
    domain_score = domain_info.get("domain_score") or {}

    flat = {
        "Domain": domain_info.get("main_domain") or domain,
        "Scan ID": scan_id,
        "Domain Score": domain_score.get("score", "N/A"),
        "Score %": domain_score.get("score_percentage", "N/A"),
        "Certificate Valid To": cert_valid_to,
        "Connected IPs": connected_ips_str,
        "Phishing Probability": summary.get("url_phishing_prob", "N/A"),
        "DGA Score": summary.get("dga_score", "N/A"),
        "Registrar": domain_info.get("domain_registrar", "N/A"),
        "Created": domain_info.get("domain_created", "N/A"),
        "Report Time": data.get("report_time", "N/A"),
        "Abuse Critical": abuse_critical,
        "Abuse Dangerous": abuse_dangerous,
        "Fake HTTPS": summary.get("fake_https_url", False),
        "Punycode": summary.get("punycode", False),
        "SSL Vulns": ssl_vulns,
    }

    readable = tableToMarkdown("CriminalIP - Full Scan Report", [flat])

    return CommandResults(
        readable_output=readable,
        outputs_prefix="CriminalIP.Email_Body",
        outputs_key_field="scan_id",
        outputs={
            "domain": domain,
            "scan_id": scan_id,
            "domain_score": domain_score.get("score"),
            "phishing_prob": summary.get("url_phishing_prob"),
            "dga_score": summary.get("dga_score"),
            "registrar": domain_info.get("domain_registrar"),
            "created": domain_info.get("domain_created"),
            "report_time": data.get("report_time"),
            "abuse_critical": abuse_critical,
            "abuse_dangerous": abuse_dangerous,
            "fake_https": summary.get("fake_https_url"),
            "punycode": summary.get("punycode"),
            "cert_valid_to": cert_valid_to,
            "connected_ips": connected_ips_str,
            "ssl_vulns": ssl_vulns,
            "readable_output": readable,
            "raw": raw,
        },
        raw_response=raw,
    )


def micro_asm(client: Client, args: dict[str, Any]) -> CommandResults:
    domain, scan_id = args.get("domain"), args.get("scan_id")
    if not scan_id or not domain:
        return_error("Both scan_id and domain are required")

    scan_id = cast(str, scan_id)
    domain = cast(str, domain)

    raw = client.domain_full_scan_result(scan_id)
    if not raw or "error" in raw:
        return_error(f"CriminalIP Error: No scan result found for scan_id={scan_id}")

    data = raw.get("data", {}) or {}
    domain_info = data.get("main_domain_info", {}) or {}
    summary = data.get("summary", {}) or {}
    certs = data.get("certificates", []) or []
    ssl_detail = data.get("ssl_detail", {}) or {}
    connected_ips = data.get("connected_ip_info", []) or []

    abuse_record = summary.get("abuse_record", {}) or {}
    abuse_critical = abuse_record.get("critical", 0)
    abuse_dangerous = abuse_record.get("dangerous", 0)
    cert_valid_to = certs[0].get("valid_to") if certs else "N/A"

    connected_ips_str = (
        ", ".join([f"{ip.get('ip')}({ip.get('score')},{ip.get('country')})" for ip in connected_ips]) if connected_ips else "N/A"
    )
    ssl_vulns = ", ".join([k for k, v in (ssl_detail.get("vulnerable") or {}).items() if v]) or "None"
    domain_score = domain_info.get("domain_score") or {}

    flat = {
        "Domain": domain_info.get("main_domain") or domain,
        "Scan ID": scan_id,
        "Domain Score": domain_score.get("score", "N/A"),
        "Score %": domain_score.get("score_percentage", "N/A"),
        "Certificate Valid To": cert_valid_to,
        "Connected IPs": connected_ips_str,
        "Phishing Probability": summary.get("url_phishing_prob", "N/A"),
        "DGA Score": summary.get("dga_score", "N/A"),
        "Registrar": domain_info.get("domain_registrar", "N/A"),
        "Created": domain_info.get("domain_created", "N/A"),
        "Report Time": data.get("report_time", "N/A"),
        "Abuse Critical": abuse_critical,
        "Abuse Dangerous": abuse_dangerous,
        "Fake HTTPS": summary.get("fake_https_url", False),
        "Punycode": summary.get("punycode", False),
        "SSL Vulns": ssl_vulns,
    }

    readable = tableToMarkdown("CriminalIP - Micro ASM Report", [flat])

    return CommandResults(
        readable_output=readable,
        outputs_prefix="CriminalIP.Micro_ASM",
        outputs_key_field="scan_id",
        outputs={
            "domain": domain,
            "scan_id": scan_id,
            "domain_score": domain_score.get("score"),
            "phishing_prob": summary.get("url_phishing_prob"),
            "dga_score": summary.get("dga_score"),
            "registrar": domain_info.get("domain_registrar"),
            "created": domain_info.get("domain_created"),
            "report_time": data.get("report_time"),
            "abuse_critical": abuse_critical,
            "abuse_dangerous": abuse_dangerous,
            "fake_https": summary.get("fake_https_url"),
            "punycode": summary.get("punycode"),
            "cert_valid_to": cert_valid_to,
            "connected_ips": connected_ips_str,
            "ssl_vulns": ssl_vulns,
            "readable_output": readable,
            "raw": raw,
        },
        raw_response=raw,
    )


def test_module(client: Client) -> str:
    try:
        client.ip_lookup("8.8.8.8")
        return "ok"
    except Exception as e:
        return f"Test failed: {str(e)}"


def main() -> None:
    params = demisto.params()
    command = demisto.command()

    base_url = params.get("url")
    creds = params.get("credentials") or {}
    api_key = creds.get("password") or params.get("apikey") or ""
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    timeout = float(params.get("request_timeout") or 30)

    headers = {"x-api-key": api_key} if api_key else {}

    client = Client(base_url=base_url, verify=verify, proxy=proxy, headers=headers, timeout=timeout)

    commands: dict[str, Any] = {
        "test-module": lambda: test_module(client),
        "criminal-ip-ip-report": lambda: get_ip_report(client, demisto.args()),
        "criminal-ip-check-malicious-ip": lambda: check_malicious_ip(client, demisto.args()),
        "criminal-ip-check-last-scan-date": lambda: check_last_scan_date(client, demisto.args()),
        "criminal-ip-domain-quick-scan": lambda: domain_quick_scan(client, demisto.args()),
        "criminal-ip-domain-lite-scan": lambda: domain_lite_scan(client, demisto.args()),
        "criminal-ip-domain-lite-scan-status": lambda: domain_lite_scan_status(client, demisto.args()),
        "criminal-ip-domain-lite-scan-result": lambda: domain_lite_scan_result(client, demisto.args()),
        "criminal-ip-domain-full-scan": lambda: domain_full_scan(client, demisto.args()),
        "criminal-ip-domain-full-scan-status": lambda: domain_full_scan_status(client, demisto.args()),
        "criminal-ip-domain-full-scan-result": lambda: domain_full_scan_result(client, demisto.args()),
        "criminal-ip-domain-full-scan-make-email-body": lambda: make_email_body(client, demisto.args()),
        "criminal-ip-micro-asm": lambda: micro_asm(client, demisto.args()),
    }

    try:
        if command in commands:
            return_results(commands[command]())
        else:
            return_error(f"Command '{command}' is not implemented.")
    except Exception as e:
        return_error(f"Error: {str(e)}")


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
