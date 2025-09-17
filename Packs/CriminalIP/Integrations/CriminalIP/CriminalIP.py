import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401  # pylint: disable=import-error
from CommonServerUserPython import *  # noqa: F401  # pylint: disable=import-error
import requests
from datetime import datetime
import dateparser
from typing import Any


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
            data={"query": domain},
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

def _wrap_simple_output(prefix: str, raw: dict, key_field: str = "") -> CommandResults:

    flat: dict[str, Any] = {}
    data_obj = raw.get("data", {}) if isinstance(raw.get("data"), dict) else {}

    def extract_scan_id() -> Any:
        # prefer data.scan_id, else top-level
        return data_obj.get("scan_id", raw.get("scan_id"))

    def extract_progress() -> Any:
        if "scan_percentage" in data_obj:
            return data_obj.get("scan_percentage")
        if "scan_percentage" in raw:
            return raw.get("scan_percentage")
        if "progress" in data_obj:
            return data_obj.get("progress")
        if "progress" in raw:
            return raw.get("progress")
        if "percentage" in data_obj:
            return data_obj.get("percentage")
        if "percentage" in raw:
            return raw.get("percentage")
        # sometimes 'state' only (running/done/etc.)
        state = (raw.get("state") or data_obj.get("state") or "").lower()
        if state in {"done", "completed", "complete", "finished", "success"}:
            return 100
        if state in {"running", "in_progress", "scanning", "queued"}:
            return 0
        return None


    if prefix in {"CriminalIP.Full_Scan", "CriminalIP.Domain_Lite"}:
        scan_id = extract_scan_id()
        flat["scan_id"] = scan_id

        flat["data"] = {"scan_id": scan_id}

    elif prefix in {"CriminalIP.Full_Scan_Status", "CriminalIP.Domain_Lite_Status"}:
        pct = extract_progress()
        if pct is not None:
            flat["scan_percentage"] = pct
            flat["data"] = {"scan_percentage": pct}
     
        if "status" in raw:
            flat["status"] = raw["status"]
        if "state" in raw:
            flat["state"] = raw["state"]

    elif prefix == "CriminalIP.Domain_Quick":
     
        if "risk_score" in raw:
            flat["risk_score"] = raw["risk_score"]
        elif "summary" in raw and isinstance(raw["summary"], dict):
            rs = raw["summary"].get("risk_score")
            if rs is not None:
                flat["risk_score"] = rs
    
        if "domain" in raw:
            flat["domain"] = raw["domain"]
    
        flat["raw"] = raw

    elif prefix in {"CriminalIP.Domain_Lite_Result", "CriminalIP.Full_Scan_Result"}:
        flat = raw
    else:
        flat = raw

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
        raise ValueError("ip argument is required")

    raw = client.ip_lookup(ip)

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
        "TopPort": first_port.get("open_port_no"),
        "TopService": first_port.get("app_name"),
        "Vulnerabilities": len(raw.get("vulnerability", {}).get("data", [])),
        "TopCVE": first_vuln.get("cve_id"),
        "TopCVSS": first_vuln.get("cvssv3_score"),
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
        raise ValueError("ip argument is required")

    data = client.ip_lookup(ip)
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

    # Extract IP addresses from the list of dictionaries
    real_ips_str = ", ".join([item.get("ip_address", "") for item in real_ip_list]) if real_ip_list else "None"

    readable_output = (
        f"### CriminalIP - Malicious IP Check\n" f"- IP: {ip}\n" f"- Malicious: {malicious}\n" f"- Real IPs: {real_ips_str}"
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
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def check_last_scan_date(client: Client, args: dict[str, Any]) -> CommandResults:
    domain = args.get("domain")
    if not domain:
        raise ValueError("domain argument is required")

    raw = client.domain_reports(domain)
    reports = (raw.get("data") or {}).get("reports", [])

    if not reports:
        outputs = {"domain": domain, "scanned": False, "scan_id": "", "raw": raw}
        return CommandResults(
            readable_output="No scan result",
            outputs_prefix="CriminalIP.Scan_Date",
            outputs_key_field="scan_id",
            outputs=outputs,
            raw_response=raw,
        )

    report = reports[0]
    reg_dt = _to_aware_utc(dateparser.parse(report.get("reg_dtime", "")))
    now = datetime.now(timezone.utc)
    scanned_bool = bool(reg_dt and (now - reg_dt).days <= 7)

    outputs = {
        "domain": domain,
        "scanned": scanned_bool,
        "scan_id": report.get("scan_id", ""),
        "raw": raw,
    }

    readable_output = (
        f"### CriminalIP - Last Scan Date Check\n"
        f"- Domain: {domain}\n"
        f"- Scanned in last 7 days: {scanned_bool}\n"
        f"- Scan ID: {outputs['scan_id']}"
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CriminalIP.Scan_Date",
        outputs_key_field="scan_id",
        outputs=outputs,
        raw_response=raw,
    )


def make_email_body(client: Client, args: dict[str, Any]) -> CommandResults:
    domain, scan_id = args.get("domain"), args.get("scan_id")
    if not scan_id:
        raise ValueError("scan_id argument is required")

    raw = client.domain_full_scan_result(scan_id)
    summary_data = (raw.get("data") or {}).get("summary", {})

    results: list[str] = []
    now = datetime.now(timezone.utc)

    if summary_data.get("punycode"):
        results.append("Has punycode")
    if summary_data.get("dga_score", 0) >= 8:
        results.append(f"DGA score {summary_data['dga_score']}")
    if summary_data.get("newborn_domain"):
        nd = _to_aware_utc(dateparser.parse(summary_data.get("newborn_domain")))
        if nd and (now - nd).days < 30:
            results.append(f"Newborn: {summary_data['newborn_domain']}")

    if not results:
        summary = "No suspicious element"
        readable_output = "No suspicious element"
        body_output = ""
    else:
        summary = f"Domain {domain} scan summary:\n- " + "\n- ".join(results)
        readable_output = f"===== {domain} =====\n{summary}"
        body_output = readable_output

    summary = readable_output

    outputs = {
        "domain": domain,
        "scan_id": scan_id,
        "summary": summary,
        "body": body_output,
        "raw": raw,
    }

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CriminalIP.Email_Body",
        outputs_key_field="scan_id",
        outputs=outputs,
        raw_response=raw,
    )


def micro_asm(client: Client, args: dict[str, Any]) -> CommandResults:
    domain, scan_id = args.get("domain"), args.get("scan_id")
    if not scan_id:
        raise ValueError("scan_id argument is required")

    raw = client.domain_full_scan_result(scan_id)
    data = raw.get("data", {})
    results: list[str] = []
    suspicious_findings: list[str] = []
    now = datetime.now(timezone.utc)

    certs = data.get("certificates", [])
    if certs:
        vto = certs[0].get("valid_to")
        results.append(f"Certificate valid_to: {vto}")
        dt = _to_aware_utc(dateparser.parse(vto) if vto else None)
        if dt and (dt - now).days < 30:
            results.append("Certificate expiring soon")
            suspicious_findings.append("Certificate expiring soon")

    domain_score = (data.get("main_domain_info") or {}).get("domain_score", {})
    if domain_score:
        score_label = domain_score.get("score")
        results.append(f"Domain score: {score_label}")
        if score_label in ("Critical", "Dangerous"):
            suspicious_findings.append(f"Domain score: {score_label}")
    else:
        results.append("Domain score: N/A")

    phishing_prob = (data.get("summary") or {}).get("url_phishing_prob")
    if phishing_prob is not None:
        results.append(f"Phishing probability: {phishing_prob}%")
        if phishing_prob >= 80:
            suspicious_findings.append(f"High phishing probability: {phishing_prob}%")
    else:
        results.append("Phishing probability: N/A")

    summary_info = data.get("summary", {})
    hidden = summary_info.get("hidden_element", 0)
    obfuscated = summary_info.get("js_obfuscated", 0)
    results.append(f"Suspicious elements: hidden_element={hidden}, js_obfuscated={obfuscated}")
    if hidden > 0 or obfuscated > 0:
        suspicious_findings.append(f"Suspicious elements detected: hidden={hidden}, obfuscated={obfuscated}")

    abuse_record = (data.get("network_logs") or {}).get("abuse_record", {})
    if abuse_record and (abuse_record.get("critical", 0) > 0 or abuse_record.get("dangerous", 0) > 0):
        results.append("Abuse records detected")
        suspicious_findings.append("Abuse records detected")

    urls = (data.get("network_logs") or {}).get("data", [])
    for entry in urls:
        if entry.get("url", "").endswith(".exe"):
            results.append("Found .exe URL in logs")
            suspicious_findings.append("Found .exe URL in logs")
            break

    main_ip_info = (data.get("connected_ip_info") or [{}])[0] if data.get("connected_ip_info") else {}
    if main_ip_info and main_ip_info.get("ip"):
        ip = main_ip_info.get("ip", "N/A")
        results.append(f"Main IP: {ip}")
    else:
        results.append("Main IP: not found")

    vulnerable = (data.get("ssl_detail") or {}).get("vulnerable", {})
    if vulnerable and any(v for v in vulnerable.values()):
        vulns = [k for k, v in vulnerable.items() if v]
        results.append(f"SSL vulnerabilities: {', '.join(vulns)}")
        suspicious_findings.append(f"SSL vulnerabilities: {', '.join(vulns)}")
    else:
        results.append("SSL vulnerabilities: none detected")

    # Show "No suspicious element" only if there are no suspicious findings
    if not suspicious_findings:
        readable_output = "No suspicious element"
    else:
        readable_output = f"===== {domain} =====\n" + "\n".join(results)

    outputs = {
        "domain": domain,
        "scan_id": scan_id,
        "summary": readable_output,
        "raw": raw,
    }

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CriminalIP.Micro_ASM",
        outputs_key_field="scan_id",
        outputs=outputs,
        raw_response=raw,
    )


def make_email_body(client: Client, args: dict[str, Any]) -> CommandResults:
    domain, scan_id = args.get("domain"), args.get("scan_id")
    if not scan_id:
        raise ValueError("scan_id argument is required")

    raw = client.domain_full_scan_result(scan_id)
    summary_data = (raw.get("data") or {}).get("summary", {})

    results: list[str] = []
    now = datetime.now(timezone.utc)

    if summary_data.get("punycode"):
        results.append("Has punycode")
    if summary_data.get("dga_score", 0) >= 8:
        results.append(f"DGA score {summary_data['dga_score']}")
    if summary_data.get("newborn_domain"):
        nd = _to_aware_utc(dateparser.parse(summary_data.get("newborn_domain")))
        if nd and (now - nd).days < 30:
            results.append(f"Newborn: {summary_data['newborn_domain']}")

    if not results:
        summary = "No suspicious element"
        readable_output = "No suspicious element"
        body_output = ""
    else:
        summary = f"Domain {domain} scan summary:\n- " + "\n- ".join(results)
        readable_output = f"===== {domain} =====\n{summary}"
        body_output = readable_output

    summary = readable_output

    outputs = {
        "domain": domain,
        "scan_id": scan_id,
        "summary": summary,
        "body": body_output,
        "raw": raw,
    }

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CriminalIP.Email_Body",
        outputs_key_field="scan_id",
        outputs=outputs,
        raw_response=raw,
    )


def main() -> None:
    params = demisto.params()
    command = demisto.command()

    base_url = params.get("url")

    api_key = (params.get("credentials") or {}).get("password")
    headers: dict[str, str] = {}

    if api_key:
        headers["x-api-key"] = api_key

    client = Client(
        base_url=base_url,
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
        headers=headers,
        timeout=float(params.get("request_timeout", 30)),
    )

    try:
        if command == "test-module":
            try:
                resp = client.ip_lookup("8.8.8.8")
                if resp and "ip" in resp:
                    return_results("ok")
                else:
                    raise ValueError("Unexpected response from API. Please check your API Key and URL configuration.")
            except DemistoException as e:
                if "Unauthorized" in str(e) or "401" in str(e):
                    raise ValueError("Invalid API Key.")
                elif "404" in str(e):
                    raise ValueError("Invalid API URL.")
                else:
                    raise
            except requests.exceptions.ConnectionError:
                raise ValueError("Unable to connect. Check the URL and network connectivity.")
            return

        args = demisto.args()
        if command == "criminal-ip-ip-report":
            return_results(get_ip_report(client, args))

        elif command == "criminal-ip-check-malicious-ip":
            return_results(check_malicious_ip(client, args))

        elif command == "criminal-ip-check-last-scan-date":
            return_results(check_last_scan_date(client, args))

        elif command == "criminal-ip-domain-quick-scan":
            domain = args.get("domain") or ""
            raw = client.domain_quick_scan(domain)
            return_results(_wrap_simple_output("CriminalIP.Domain_Quick", raw))

        elif command == "criminal-ip-domain-lite-scan":
            domain = args.get("domain") or ""
            raw = client.domain_lite_scan(domain)
            return_results(_wrap_simple_output("CriminalIP.Domain_Lite", raw))

        elif command == "criminal-ip-domain-lite-scan-status":
            sid = args.get("scan_id") or ""
            raw = client.domain_lite_scan_status(sid)
            return_results(_wrap_simple_output("CriminalIP.Domain_Lite_Status", raw))

        elif command == "criminal-ip-domain-lite-scan-result":
            sid = args.get("scan_id") or ""
            raw = client.domain_lite_scan_result(sid)
            return_results(_wrap_simple_output("CriminalIP.Domain_Lite_Result", raw))

        elif command == "criminal-ip-domain-full-scan":
            domain = args.get("domain") or ""
            raw = client.domain_full_scan(domain)
            return_results(_wrap_simple_output("CriminalIP.Full_Scan", raw))

        elif command == "criminal-ip-domain-full-scan-status":
            sid = args.get("scan_id") or ""
            raw = client.domain_full_scan_status(sid)
            return_results(_wrap_simple_output("CriminalIP.Full_Scan_Status", raw))

        elif command == "criminal-ip-domain-full-scan-result":
            sid = args.get("scan_id") or ""
            raw = client.domain_full_scan_result(sid)
            return_results(_wrap_simple_output("CriminalIP.Full_Scan_Result", raw))

        elif command == "criminal-ip-domain-full-scan-make-email-body":
            return_results(make_email_body(client, args))

        elif command == "criminal-ip-micro-asm":
            return_results(micro_asm(client, args))

        else:
            raise NotImplementedError(f"Command {command} not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command}. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
