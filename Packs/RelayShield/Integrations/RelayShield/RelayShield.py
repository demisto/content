import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

from typing import Any

""" CONSTANTS """

# CRITICAL/HIGH findings are treated as Bad; MEDIUM/LOW findings (still real
# findings, just lower severity) are treated as Suspicious. no_known_finding
# is never mapped to Good -- RelayShield's own docs are explicit that a clean
# result means "nothing was found in the sources and scope actually queried,"
# not "verified safe." Consistent with the same principle already applied in
# relayshield_smolagents_tool.py and the TI demo.
DBOT_SCORE_MAP = {
    "CRITICAL": 3,  # Common.DBotScore.BAD
    "HIGH": 3,
    "MEDIUM": 2,  # Common.DBotScore.SUSPICIOUS
    "LOW": 2,
}


def score_for(verdict: str | None, found: bool) -> int:
    """Maps a RelayShield verdict + found flag to a DBotScore integer.

    Deliberately never returns Good(1) for a clean result -- only Unknown(0)
    or higher, per the no_known_finding-is-not-verified-safe principle.
    """
    if not found or verdict in (None, "NONE", "CLEAN"):
        return 0  # Common.DBotScore.NONE (Unknown)
    return DBOT_SCORE_MAP.get(verdict, 2)


""" CLIENT CLASS """


class Client(BaseClient):
    """Thin wrapper over RelayShield's metered API. All commands POST a
    payload and get back {"ok": bool, "data": {...}} or {"ok": false,
    "error": "..."} -- _http_request already raises DemistoException on a
    non-2xx response, so callers only need to unwrap "data"."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._api_key = api_key

    def call(self, path: str, payload: dict) -> dict:
        response = self._http_request(
            method="POST",
            url_suffix=path,
            json_data=payload,
            headers={"Content-Type": "application/json", "X-RS-API-KEY": self._api_key},
        )
        if not response.get("ok", True):
            raise DemistoException(response.get("error", "RelayShield API returned an error"))
        return response.get("data", {})


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    client.call("/v1/metered/domain", {"domain": "relayshield.net"})
    return "ok"


def domain_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    domains = argToList(args.get("domain"))
    if not domains:
        raise ValueError("domain is required")

    results = []
    for domain in domains:
        data = client.call("/v1/metered/domain", {"domain": domain})
        findings = data.get("findings", [])
        verdict = data.get("verdict")
        score = score_for(verdict, bool(findings))

        dbot_score = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name="RelayShield",
            score=score,
            reliability=DBotScoreReliability.B,
        )
        indicator = Common.Domain(domain=domain, dbot_score=dbot_score)

        readable = tableToMarkdown(
            f"RelayShield Domain Reputation: {domain}",
            {
                "Verdict": verdict or "no_known_finding",
                "Findings": len(findings),
                "Checked At": data.get("checked_at"),
            },
        )
        results.append(
            CommandResults(
                outputs_prefix="RelayShield.Domain",
                outputs_key_field="queried",
                outputs=data,
                indicator=indicator,
                readable_output=readable,
                raw_response=data,
            )
        )
    return results


def ip_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    ips = argToList(args.get("ip"))
    if not ips:
        raise ValueError("ip is required")

    results = []
    for ip in ips:
        data = client.call("/v1/metered/ip-intel", {"ip": ip})
        reputation = data.get("reputation", 0)
        malicious = data.get("malicious_votes", 0)
        found = bool(malicious) or reputation not in (0, None)
        verdict = "HIGH" if malicious else ("MEDIUM" if reputation and reputation > 0 else None)
        score = score_for(verdict, found)

        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name="RelayShield",
            score=score,
            reliability=DBotScoreReliability.B,
        )
        indicator = Common.IP(
            ip=ip,
            dbot_score=dbot_score,
            asn=data.get("as_owner"),
            geo_country=data.get("country"),
        )

        readable = tableToMarkdown(
            f"RelayShield IP Reputation: {ip}",
            {
                "Reputation": reputation,
                "Malicious Votes": malicious,
                "AS Owner": data.get("as_owner"),
                "Country": data.get("country"),
            },
        )
        results.append(
            CommandResults(
                outputs_prefix="RelayShield.IP",
                outputs_key_field="queried",
                outputs=data,
                indicator=indicator,
                readable_output=readable,
                raw_response=data,
            )
        )
    return results


def email_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    emails = argToList(args.get("email"))
    if not emails:
        raise ValueError("email is required")

    results = []
    for email in emails:
        breach_data = client.call("/v1/metered/breach", {"email": email})
        session_data = client.call("/v1/metered/session-risk", {"email": email})

        breach_found = bool(breach_data.get("found"))
        session_found = bool(session_data.get("found"))
        found = breach_found or session_found

        severities = [s.get("severity") for s in session_data.get("sessions", []) if s.get("severity")]
        highest = max(severities, key=lambda s: DBOT_SCORE_MAP.get(s, 0), default=None)
        if breach_found and highest is None:
            highest = "MEDIUM"
        score = score_for(highest, found)

        dbot_score = Common.DBotScore(
            indicator=email,
            indicator_type=DBotScoreType.EMAIL,
            integration_name="RelayShield",
            score=score,
            reliability=DBotScoreReliability.B,
        )
        indicator = Common.EMAIL(address=email, dbot_score=dbot_score)

        combined = {
            "queried": email,
            "breach_found": breach_found,
            "breach_sources": breach_data.get("sources", []),
            "session_risk_found": session_found,
            "sessions": session_data.get("sessions", []),
        }
        readable = tableToMarkdown(
            f"RelayShield Identity Exposure: {email}",
            {
                "Breach Found": breach_found,
                "Active Session Exposure": session_found,
            },
        )
        results.append(
            CommandResults(
                outputs_prefix="RelayShield.Email",
                outputs_key_field="queried",
                outputs=combined,
                indicator=indicator,
                readable_output=readable,
                raw_response=combined,
            )
        )
    return results


def mcp_registry_risk_command(client: Client, args: dict[str, Any]) -> CommandResults:
    server_url = args.get("server_url")
    package_name = args.get("package_name")
    if not server_url and not package_name:
        raise ValueError("server_url or package_name is required")

    payload = {k: v for k, v in {"server_url": server_url, "package_name": package_name}.items() if v}
    data = client.call("/v1/metered/mcp-registry-risk", payload)
    findings = data.get("findings", [])
    verdict = data.get("verdict")

    readable = tableToMarkdown(
        f"RelayShield MCP Registry Risk: {data.get('queried', server_url or package_name)}",
        {
            "Verdict": verdict or "no_known_finding",
            "Findings": [f.get("type", "unknown") for f in findings],
        },
    )
    return CommandResults(
        outputs_prefix="RelayShield.MCPRegistryRisk",
        outputs_key_field="queried",
        outputs=data,
        readable_output=readable,
        raw_response=data,
    )


def cert_expiry_command(client: Client, args: dict[str, Any]) -> CommandResults:
    domain = args.get("domain")
    if not domain:
        raise ValueError("domain is required")

    data = client.call("/v1/metered/cert-expiry", {"domain": domain})
    readable = tableToMarkdown(
        f"RelayShield Certificate Expiry: {domain}",
        {
            "Days Remaining": data.get("days_remaining"),
            "Risk Level": data.get("risk_level"),
        },
    )
    return CommandResults(
        outputs_prefix="RelayShield.CertExpiry",
        outputs_key_field="domain",
        outputs=data,
        readable_output=readable,
        raw_response=data,
    )


def supply_chain_command(client: Client, args: dict[str, Any]) -> CommandResults:
    vendor_domains = argToList(args.get("vendor_domains"))
    vendor_emails = argToList(args.get("vendor_emails"))
    if not vendor_domains and not vendor_emails:
        raise ValueError("vendor_domains or vendor_emails is required")

    payload: dict[str, Any] = {}
    if vendor_domains:
        payload["vendor_domains"] = vendor_domains
    if vendor_emails:
        payload["vendor_emails"] = vendor_emails

    data = client.call("/v1/metered/supply-chain", payload)
    readable = tableToMarkdown(
        "RelayShield Supply Chain Risk",
        {
            "Domains Checked": data.get("domains_checked", 0),
            "Highest Risk": data.get("highest_risk"),
            "Critical Vendors": data.get("critical_vendors", []),
        },
    )
    return CommandResults(
        outputs_prefix="RelayShield.SupplyChain",
        outputs_key_field="checked_at",
        outputs=data,
        readable_output=readable,
        raw_response=data,
    )


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get("credentials", {}).get("password") or params.get("api_key", {}).get("password")
    base_url = params.get("url", "https://api.relayshield.net").rstrip("/")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "domain":
            return_results(domain_command(client, args))
        elif command == "ip":
            return_results(ip_command(client, args))
        elif command == "email":
            return_results(email_command(client, args))
        elif command == "relayshield-mcp-registry-risk":
            return_results(mcp_registry_risk_command(client, args))
        elif command == "relayshield-cert-expiry":
            return_results(cert_expiry_command(client, args))
        elif command == "relayshield-supply-chain":
            return_results(supply_chain_command(client, args))
        else:
            raise NotImplementedError(f"{command} is not an implemented command.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
