"""DECTRAX Integration for Cortex XSOAR

Autonomous Cyber Deception, Canary Honeytokens & Line-Rate Firewall Interdiction Platform.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import urllib3
import requests

# Disable insecure warnings
urllib3.disable_warnings()

try:
    import demistomock as demisto  # noqa: F401
    from CommonServerPython import *  # noqa: F401
except ImportError:
    # Standalone compatibility fallback for testing outside Cortex container
    class BaseClient:
        def __init__(self, base_url: str, verify: bool = True, proxy: bool = False, headers: Optional[Dict] = None):
            self._base_url = base_url.rstrip("/")
            self._verify = verify
            self._proxy = proxy
            self._headers = headers or {}

        def _http_request(self, method: str, url_suffix: str = "", full_url: Optional[str] = None,
                          params: Optional[Dict] = None, json_data: Optional[Dict] = None,
                          resp_type: str = "json", ok_codes: Tuple[int, ...] = (200, 201, 204)):
            url = full_url if full_url else f"{self._base_url}/{url_suffix.lstrip('/')}"
            proxies = None
            if self._proxy:
                proxies = {}
            res = requests.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=self._headers,
                verify=self._verify,
                proxies=proxies,
                timeout=30
            )
            if res.status_code not in ok_codes:
                raise Exception(f"Error in API call [{res.status_code}] - {res.text}")
            if resp_type == "text":
                return res.text
            elif resp_type == "response":
                return res
            return res.json()

    class CommandResults:
        def __init__(self, readable_output: str = "", outputs_prefix: str = "",
                     outputs_key_field: str = "", outputs: Any = None,
                     raw_response: Any = None, indicator: Any = None):
            self.readable_output = readable_output
            self.outputs_prefix = outputs_prefix
            self.outputs_key_field = outputs_key_field
            self.outputs = outputs
            self.raw_response = raw_response
            self.indicator = indicator

        def to_context(self):
            return {
                f"{self.outputs_prefix}(val.{self.outputs_key_field} && val.{self.outputs_key_field} == obj.{self.outputs_key_field})": self.outputs
            }

    class Common:
        class IP:
            def __init__(self, ip: str, dbot_score: Any):
                self.ip = ip
                self.dbot_score = dbot_score

        class DBotScore:
            BAD = 3
            SUSPICIOUS = 2
            GOOD = 1
            NONE = 0

            def __init__(self, indicator: str, indicator_type: str, integration_name: str, score: int, reliability: str = "B"):
                self.indicator = indicator
                self.indicator_type = indicator_type
                self.integration_name = integration_name
                self.score = score
                self.reliability = reliability

    class DBotScoreType:
        IP = "ip"

    def return_results(results):
        return results

    def return_error(message: str):
        raise Exception(message)

    def tableToMarkdown(name: str, t: List[Dict], headers: Optional[List[str]] = None) -> str:
        if not t:
            return f"### {name}\nNo data returned."
        keys = headers if headers else list(t[0].keys())
        md = f"### {name}\n\n| " + " | ".join(keys) + " |\n| " + " | ".join(["---"] * len(keys)) + " |\n"
        for row in t:
            md += "| " + " | ".join(str(row.get(k, "")) for k in keys) + " |\n"
        return md


class Client(BaseClient):
    """Client for the DECTRAX API and External Dynamic List (EDL) feed."""

    def __init__(self, base_url: str, api_key: Optional[str] = None, verify: bool = True, proxy: bool = False):
        headers = {
            "User-Agent": "DECTRAX-Cortex-XSOAR/1.0.0",
            "Accept": "application/json, text/plain",
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def test_connection(self) -> str:
        """Test connection to the DECTRAX service."""
        try:
            self._http_request(method="GET", url_suffix="healthz", resp_type="response", ok_codes=(200, 204, 404))
            return "ok"
        except Exception:
            self._http_request(method="GET", url_suffix="api/v1/edl/firewall.txt", resp_type="text", ok_codes=(200, 204))
            return "ok"

    def get_edl_firewall(self) -> List[str]:
        """Fetch the list of blocked IPs from the /api/v1/edl/firewall.txt endpoint."""
        raw_text = self._http_request(method="GET", url_suffix="api/v1/edl/firewall.txt", resp_type="text")
        ips = []
        for line in raw_text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.append(line)
        return ips

    def get_ip_telemetry(self, ip: str) -> Dict[str, Any]:
        """Query DECTRAX telemetry for a specific IP."""
        try:
            return self._http_request(
                method="GET",
                url_suffix=f"api/v1/threats/intel/{ip}",
                ok_codes=(200, 404)
            )
        except Exception:
            return {}


def test_module(client: Client) -> str:
    """Test API connectivity and authentication."""
    client.test_connection()
    return "ok"


def get_blocked_ips_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """dectrax-get-blocked-ips: Fetch active threat actor IPs from the firewall EDL."""
    limit_arg = args.get("limit", 100)
    try:
        limit = int(limit_arg)
    except (ValueError, TypeError):
        limit = 100

    raw_ips = client.get_edl_firewall()
    selected_ips = raw_ips[:limit] if limit > 0 else raw_ips

    current_time = datetime.now(timezone.utc).isoformat()
    entries = [{"IP": ip, "Source": "EDL", "Timestamp": current_time} for ip in selected_ips]

    readable_output = tableToMarkdown(
        name="DECTRAX Active Blocked IPs (Firewall EDL)",
        t=entries,
        headers=["IP", "Source", "Timestamp"]
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="DECTRAX.BlockedIP",
        outputs_key_field="IP",
        outputs=entries,
        raw_response=selected_ips
    )


def check_ip_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """dectrax-check-ip: Verify whether an IP address is trapped or blocked."""
    ip = args.get("ip")
    if not ip:
        raise ValueError("Parameter 'ip' is required.")

    # Check if IP exists in active EDL list
    blocked_ips = set(client.get_edl_firewall())
    is_blocked = ip in blocked_ips

    telemetry = client.get_ip_telemetry(ip)
    interactions = telemetry.get("interactions", 1 if is_blocked else 0)

    # Determine DBotScore
    if is_blocked:
        dbot_score_val = Common.DBotScore.BAD
        score_desc = "Malicious (Quarantined in DECTRAX Firewall EDL)"
    elif interactions > 0:
        dbot_score_val = Common.DBotScore.SUSPICIOUS
        score_desc = "Suspicious (Decoy Interaction Detected)"
    else:
        dbot_score_val = Common.DBotScore.NONE
        score_desc = "Unknown / Clean"

    dbot_score = Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP if "DBotScoreType" in globals() else "ip",
        integration_name="DECTRAX",
        score=dbot_score_val,
        reliability="B"
    )

    ip_indicator = Common.IP(
        ip=ip,
        dbot_score=dbot_score
    )

    context_data = {
        "Address": ip,
        "Blocked": is_blocked,
        "Interactions": interactions,
        "Score": dbot_score_val,
        "Status": score_desc
    }

    readable_output = tableToMarkdown(
        name=f"DECTRAX Threat Assessment: {ip}",
        t=[context_data],
        headers=["Address", "Blocked", "Interactions", "Score", "Status"]
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="DECTRAX.IP",
        outputs_key_field="Address",
        outputs=context_data,
        indicator=ip_indicator,
        raw_response={"ip": ip, "blocked": is_blocked, "telemetry": telemetry}
    )


def main():
    """Main execution entry point."""
    params = demisto.params() if "demisto" in globals() and hasattr(demisto, "params") else {}
    command = demisto.command() if "demisto" in globals() and hasattr(demisto, "command") else ""
    args = demisto.args() if "demisto" in globals() and hasattr(demisto, "args") else {}

    base_url = params.get("url", "https://api.dectrax.com")
    api_key = params.get("apikey")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "dectrax-get-blocked-ips":
            return_results(get_blocked_ips_command(client, args))
        elif command == "dectrax-check-ip":
            return_results(check_ip_command(client, args))
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute command '{command}'. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
