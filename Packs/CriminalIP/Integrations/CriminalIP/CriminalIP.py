import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

from datetime import datetime, timezone
import dateparser
from typing import Any


class Client(BaseClient):
    """
    Criminal IP API Client using XSOAR BaseClient.
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, headers: dict[str, str], timeout: float | None = None):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
        self.base_url = (base_url or "").rstrip("/")
        self.timeout: float | None = float(timeout) if timeout is not None else None

    def ip_lookup(self, ip: str) -> dict:
        return self._http_request(
            "GET",
            "/v1/asset/ip/report",
            params={"ip": ip, "full": "true"},
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


def get_ip_report(client: Client, args: dict[str, Any]) -> CommandResults:
    ip = args.get("ip")
    if not ip:
        raise ValueError("ip argument is required")
    raw = client.ip_lookup(ip)
    return CommandResults(
        readable_output=tableToMarkdown("Criminal IP - IP Report", [raw]),
        outputs_prefix="CriminalIP.IP",
        outputs_key_field="ip",
        outputs=raw,
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

    return CommandResults(
        readable_output=f"Malicious: {malicious}, Protected IPs: {real_ip_list}",
        outputs_prefix="CriminalIP.Mal_IP",
        outputs_key_field="mal_ip",
        outputs={"ip": ip, "malicious": malicious, "real_ip_list": real_ip_list},
        raw_response=data,
    )


def _to_aware_utc(dt: datetime | None) -> datetime | None:
    """Normalize datetime to timezone-aware UTC."""
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
        return CommandResults(
            readable_output="No scan result",
            outputs_prefix="CriminalIP.Scan_Date",
            outputs_key_field="scan_date",
            outputs={"scanned": False, "scan_id": ""},
            raw_response=raw,
        )

    report = reports[0]
    reg_dt = _to_aware_utc(dateparser.parse(report.get("reg_dtime", "")))
    now = datetime.now(timezone.utc)
    scanned = bool(reg_dt and (now - reg_dt).days <= 7)

    return CommandResults(
        readable_output=f"Scanned in 7 days: {scanned}",
        outputs_prefix="CriminalIP.Scan_Date",
        outputs_key_field="scan_date",
        outputs={"scanned": scanned, "scan_id": report.get("scan_id", "")},
        raw_response=raw,
    )


def make_email_body(client: Client, args: dict[str, Any]) -> CommandResults:
    domain, scan_id = args.get("domain"), args.get("scan_id")
    if not scan_id:
        raise ValueError("scan_id argument is required")

    raw = client.domain_full_scan_result(scan_id)
    summary = (raw.get("data") or {}).get("summary", {})

    body: list[str] = []
    if summary.get("punycode"):
        body.append("Has punycode")
    if summary.get("dga_score", 0) >= 8:
        body.append(f"DGA score {summary['dga_score']}")

    now = datetime.now(timezone.utc)
    if summary.get("newborn_domain"):
        nd = _to_aware_utc(dateparser.parse(summary.get("newborn_domain")))
        if nd and (now - nd).days < 30:
            body.append(f"Newborn: {summary['newborn_domain']}")

    if not body:
        return CommandResults(
            readable_output="No suspicious element",
            outputs_prefix="CriminalIP.Email_Body",
            outputs_key_field="email_body",
            outputs={"domain": domain, "scan_id": scan_id, "body": ""},
            raw_response=raw,
        )

    body_text = f"Domain {domain} scan summary:\n- " + "\n- ".join(body)
    return CommandResults(
        readable_output=body_text,
        outputs_prefix="CriminalIP.Email_Body",
        outputs_key_field="email_body",
        outputs={"domain": domain, "scan_id": scan_id, "body": body_text},
        raw_response=raw,
    )


def micro_asm(client: Client, args: dict[str, Any]) -> CommandResults:
    domain, scan_id = args.get("domain"), args.get("scan_id")
    if not scan_id:
        raise ValueError("scan_id argument is required")

    raw = client.domain_full_scan_result(scan_id)
    data = raw.get("data", {})

    results: list[str] = []
    now = datetime.now(timezone.utc)

    for cert in data.get("certificates", []):
        vto = cert.get("valid_to")
        dt = _to_aware_utc(dateparser.parse(vto) if vto else None)
        if dt and (dt - now).days < 30:
            results.append("Certificate expiring soon")

    abuse = (data.get("network_logs") or {}).get("abuse_record", {})
    if abuse.get("critical", 0) or abuse.get("dangerous", 0):
        results.append(f"Abuse records: {abuse}")

    logs = (data.get("network_logs") or {}).get("data", [])
    if any((log.get("url") or "").endswith(".exe") for log in logs):
        results.append("Found .exe URL in logs")

    if not results:
        return CommandResults(
            readable_output="No suspicious element",
            outputs_prefix="CriminalIP.Micro_ASM",
            outputs_key_field="micro_asm",
            outputs={"domain": domain, "scan_id": scan_id, "result": ""},
            raw_response=raw,
        )

    text = f"===== {domain} =====\n" + "\n".join(results)
    return CommandResults(
        readable_output=text,
        outputs_prefix="CriminalIP.Micro_ASM",
        outputs_key_field="micro_asm",
        outputs={"domain": domain, "scan_id": scan_id, "result": text},
        raw_response=raw,
    )


def main() -> None:
    params = demisto.params()
    command = demisto.command()

    base_url = params.get("url", "https://api.criminalip.io/")

    client = Client(
        base_url=base_url,
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
        headers={"x-api-key": (params.get("credentials") or {}).get("password") or ""},
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
            return_results(CommandResults(raw_response=client.domain_quick_scan(args.get("domain") or "")))
        elif command == "criminal-ip-domain-lite-scan":
            return_results(CommandResults(raw_response=client.domain_lite_scan(args.get("domain") or "")))
        elif command == "criminal-ip-domain-lite-scan-status":
            return_results(CommandResults(raw_response=client.domain_lite_scan_status(args.get("scan_id") or "")))
        elif command == "criminal-ip-domain-lite-scan-result":
            return_results(CommandResults(raw_response=client.domain_lite_scan_result(args.get("scan_id") or "")))
        elif command == "criminal-ip-domain-full-scan":
            return_results(CommandResults(raw_response=client.domain_full_scan(args.get("domain") or "")))
        elif command == "criminal-ip-domain-full-scan-status":
            return_results(CommandResults(raw_response=client.domain_full_scan_status(args.get("scan_id") or "")))
        elif command == "criminal-ip-domain-full-scan-result":
            return_results(CommandResults(raw_response=client.domain_full_scan_result(args.get("scan_id") or "")))
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
