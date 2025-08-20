import demistomock as demisto  # for XSOAR testing
from CommonServerPython import *  # XSOAR common functions
from CommonServerUserPython import *  # XSOAR user functions

import datetime
import dateparser
from typing import Dict, Any, List

BASE_URL = "https://api.criminalip.io/"


class Client(BaseClient):
    """
    Criminal IP API Client using XSOAR BaseClient.
    """

    def ip_lookup(self, ip: str) -> dict:
        return self._http_request("GET", "/v1/asset/ip/report", params={"ip": ip, "full": "true"})

    def domain_quick_scan(self, domain: str) -> dict:
        return self._http_request("GET", "/v1/domain/quick/hash/view", params={"domain": domain})

    def domain_lite_scan(self, domain: str) -> dict:
        return self._http_request("GET", "/v1/domain/lite/scan", params={"query": domain})

    def domain_lite_scan_status(self, scan_id: str) -> dict:
        return self._http_request("GET", "/v1/domain/lite/progress", params={"scan_id": scan_id})

    def domain_lite_scan_result(self, scan_id: str) -> dict:
        return self._http_request("GET", f"/v1/domain/lite/report/{scan_id}")

    def domain_full_scan(self, domain: str) -> dict:
        return self._http_request("POST", "/v1/domain/scan", data={"query": domain})

    def domain_full_scan_status(self, scan_id: str) -> dict:
        return self._http_request("GET", f"/v1/domain/status/{scan_id}")

    def domain_full_scan_result(self, scan_id: str) -> dict:
        return self._http_request("GET", f"/v2/domain/report/{scan_id}")

    def domain_reports(self, domain: str) -> dict:
        return self._http_request("GET", "/v1/domain/reports", params={"query": domain, "offset": 0})


# ---------------- Commands ----------------

def get_ip_report(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get IP report from Criminal IP.

    Args:
        client (Client): API client.
        args (dict): Command args. Requires 'ip'.

    Returns:
        CommandResults: IP report.
    """
    ip = args.get("ip")
    raw = client.ip_lookup(ip)
    return CommandResults(
        readable_output=tableToMarkdown("Criminal IP - IP Report", [raw]),
        outputs_prefix="CriminalIP.IP",
        outputs_key_field="ip",
        outputs=raw,
        raw_response=raw,
    )


def check_malicious_ip(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Check if an IP is malicious.

    Args:
        client (Client): API client.
        args (dict): Command args. Requires 'ip'.

    Returns:
        CommandResults: Malicious flag and protected IPs.
    """
    ip = args.get("ip")
    data = client.ip_lookup(ip)

    malicious = False
    real_ip_list = []

    # Score check
    score = data.get("score", {})
    if score.get("inbound") in ("Dangerous", "Critical") or score.get("outbound") in ("Dangerous", "Critical"):
        malicious = True

    # Protected IP check
    protected = data.get("protected_ip", {})
    if protected.get("count", 0) > 0:
        malicious = True
        real_ip_list = protected.get("data", [])

    # Issue flags
    if any(data.get("issues", {}).values()):
        malicious = True

    return CommandResults(
        readable_output=f"Malicious: {malicious}, Protected IPs: {real_ip_list}",
        outputs_prefix="CriminalIP.Mal_IP",
        outputs_key_field="mal_ip",
        outputs={"ip": ip, "malicious": malicious, "real_ip_list": real_ip_list},
        raw_response=data,
    )


def check_last_scan_date(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Check if domain has scan result within 7 days.

    Args:
        client (Client): API client.
        args (dict): Command args. Requires 'domain'.

    Returns:
        CommandResults: Scanned flag and scan_id.
    """
    domain = args.get("domain")
    raw = client.domain_reports(domain)
    reports = (raw.get("data") or {}).get("reports", [])

    if not reports:
        return CommandResults("No scan result", "CriminalIP.Scan_Date", "scan_date",
                              {"scanned": False, "scan_id": ""}, raw)

    report = reports[0]
    reg_dt = dateparser.parse(report.get("reg_dtime", ""))
    scanned = bool(reg_dt and (datetime.datetime.now(reg_dt.tzinfo) - reg_dt).days <= 7)

    return CommandResults(
        readable_output=f"Scanned in 7 days: {scanned}",
        outputs_prefix="CriminalIP.Scan_Date",
        outputs_key_field="scan_date",
        outputs={"scanned": scanned, "scan_id": report.get("scan_id", "")},
        raw_response=raw,
    )


def make_email_body(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create short summary text for email.

    Args:
        client (Client): API client.
        args (dict): Command args. Requires 'domain' and 'scan_id'.

    Returns:
        CommandResults: Email body string.
    """
    domain, scan_id = args.get("domain"), args.get("scan_id")
    raw = client.domain_full_scan_result(scan_id)
    summary = (raw.get("data") or {}).get("summary", {})

    body: List[str] = []
    if summary.get("punycode"): body.append("Has punycode")
    if summary.get("dga_score", 0) >= 8: body.append(f"DGA score {summary['dga_score']}")
    if summary.get("newborn_domain"):
        nd = dateparser.parse(summary["newborn_domain"])
        if nd and (datetime.datetime.now() - nd).days < 30:
            body.append(f"Newborn: {summary['newborn_domain']}")

    if not body:
        return CommandResults("No suspicious element", "CriminalIP.Email_Body", "email_body",
                              {"domain": domain, "scan_id": scan_id, "body": ""}, raw)

    body_text = f"Domain {domain} scan summary:\n- " + "\n- ".join(body)
    return CommandResults(body_text, "CriminalIP.Email_Body", "email_body",
                          {"domain": domain, "scan_id": scan_id, "body": body_text}, raw)


def micro_asm(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create ASM style summary (open ports, CVEs, cert expiry, abuse logs).

    Args:
        client (Client): API client.
        args (dict): Command args. Requires 'domain' and 'scan_id'.

    Returns:
        CommandResults: Summary text.
    """
    domain, scan_id = args.get("domain"), args.get("scan_id")
    raw = client.domain_full_scan_result(scan_id)
    data = raw.get("data", {})

    results: List[str] = []

    # Certificate expiry
    for cert in data.get("certificates", []):
        vto = cert.get("valid_to")
        dt = dateparser.parse(vto) if vto else None
        if dt and (dt - datetime.datetime.now()).days < 30:
            results.append("Certificate expiring soon")

    # Abuse record
    abuse = (data.get("network_logs") or {}).get("abuse_record", {})
    if abuse.get("critical", 0) or abuse.get("dangerous", 0):
        results.append(f"Abuse records: {abuse}")

    # Suspicious logs
    logs = (data.get("network_logs") or {}).get("data", [])
    if any(log.get("url", "").endswith(".exe") for log in logs):
        results.append("Found .exe URL in logs")

    if not results:
        return CommandResults("No suspicious element", "CriminalIP.Micro_ASM", "micro_asm",
                              {"domain": domain, "scan_id": scan_id, "result": ""}, raw)

    text = f"===== {domain} =====\n" + "\n".join(results)
    return CommandResults(text, "CriminalIP.Micro_ASM", "micro_asm",
                          {"domain": domain, "scan_id": scan_id, "result": text}, raw)


# ---------------- Main ----------------

def main() -> None:
    params = demisto.params()
    command = demisto.command()

    client = Client(
        base_url=BASE_URL,
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
        headers={"x-api-key": (params.get("credentials") or {}).get("password")}
    )

    try:
        if command == "test-module":
            try:
                resp = client.ip_lookup("8.8.8.8")
                return_results("ok" if resp and "ip" in resp else "Test failed: Unexpected response")
            except Exception as e:
                return_results(f"Test failed: {str(e)}")
            return

        args = demisto.args()
        if command == "criminal-ip-ip-report":
            return_results(get_ip_report(client, args))
        elif command == "criminal-ip-check-malicious-ip":
            return_results(check_malicious_ip(client, args))
        elif command == "criminal-ip-check-last-scan-date":
            return_results(check_last_scan_date(client, args))
        elif command == "criminal-ip-domain-quick-scan":
            return_results(CommandResults(raw_response=client.domain_quick_scan(args.get("domain"))))
        elif command == "criminal-ip-domain-lite-scan":
            return_results(CommandResults(raw_response=client.domain_lite_scan(args.get("domain"))))
        elif command == "criminal-ip-domain-lite-scan-status":
            return_results(CommandResults(raw_response=client.domain_lite_scan_status(args.get("scan_id"))))
        elif command == "criminal-ip-domain-lite-scan-result":
            return_results(CommandResults(raw_response=client.domain_lite_scan_result(args.get("scan_id"))))
        elif command == "criminal-ip-domain-full-scan":
            return_results(CommandResults(raw_response=client.domain_full_scan(args.get("domain"))))
        elif command == "criminal-ip-domain-full-scan-status":
            return_results(CommandResults(raw_response=client.domain_full_scan_status(args.get("scan_id"))))
        elif command == "criminal-ip-domain-full-scan-result":
            return_results(CommandResults(raw_response=client.domain_full_scan_result(args.get("scan_id"))))
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
