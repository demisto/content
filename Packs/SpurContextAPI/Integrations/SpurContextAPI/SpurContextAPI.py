import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import ipaddress
import urllib3
import urllib.parse
import traceback
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):

    def ip(self, ip: str) -> dict:
        # Validate that the input is a valid IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")
        encoded_ip = urllib.parse.quote(ip)
        full_url = urljoin(self._base_url, "/v2/context")
        full_url = urljoin(full_url, encoded_ip)
        demisto.debug(f"SpurContextAPI full_url: {full_url}")

        # Make the request
        response = self._http_request(
            method="GET",
            full_url=full_url,
            headers=self._headers,
        )

        return response


""" SPUR IP INDICATOR CLASS """


class SpurIP(Common.IP):

    def __init__(self, client_types=None, risks=None, tunnels=None, **kwargs) -> None:

        super().__init__(**kwargs)

        self.client_types = client_types if client_types else []
        self.risks = risks if risks else []
        self.tunnels = tunnels if tunnels else {}

    def to_context(self) -> dict:
        context = super().to_context()

        context_path = context[super().CONTEXT_PATH]

        if self.risks:
            context_path["Risks"] = self.risks

        if self.client_types:
            context_path["ClientTypes"] = self.client_types

        if self.tunnels:
            context_path["Tunnels"] = self.tunnels

        return context


""" HELPER FUNCTIONS """


def fix_nested_client(data):
    new_dict = data.copy()
    if "client" in data:
        del new_dict["client"]
        client = data["client"]
        new_dict["client_behaviors"] = client.get("behaviors", [])
        new_dict["client_countries"] = client.get("countries", 0)
        new_dict["client_spread"] = client.get("spread", 0)
        new_dict["client_proxies"] = client.get("proxies", [])
        new_dict["client_count"] = client.get("count", 0)
        new_dict["client_types"] = client.get("types", [])
        new_dict["client_concentration"] = client.get("concentration", None)

    return new_dict


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:

    message: str = ""
    try:
        full_url = urljoin(client._base_url, "status")
        demisto.debug(f"SpurContextAPI full_url: {full_url}")

        client._http_request(
            method="GET",
            full_url=full_url,
            headers=client._headers,
            raise_on_status=True,
        )
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in "":  # TODO: make sure you capture authentication errors
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


def enrich_command(client: Client, args: dict[str, Any]) -> CommandResults:
    ip = args.get("ip", None)
    if not ip:
        raise ValueError("IP not specified")

    response = client.ip(ip)

    if not isinstance(response, dict):
        raise ValueError(f"Invalid response from API: {response}")

    response = fix_nested_client(response)
    return CommandResults(
        outputs_prefix="SpurContextAPI.Context",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )


def _build_dbot_score(ip: str) -> Common.DBotScore:
    reliability = demisto.params().get("reliability")
    return Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name="SpurContextAPI",
        score=Common.DBotScore.NONE,
        reliability=reliability,
    )


def _build_spur_indicator(ip: str, response: dict) -> SpurIP:
    response_as = response.get("as", {})
    response_location = response.get("location", {})
    return SpurIP(
        ip=ip,
        asn=response_as.get("number"),
        as_owner=response_as.get("organization"),
        dbot_score=_build_dbot_score(ip),
        organization_name=response.get("organization"),
        geo_country=response_location.get("country"),
        risks=response.get("risks"),
        client_types=response.get("client_types"),
        tunnels=response.get("tunnels"),
    )


def ip_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    ips = argToList(args["ip"])

    results: List[CommandResults] = []

    for ip in ips:
        response = client.ip(ip)

        if not isinstance(response, dict):
            raise ValueError(f"Invalid response from API: {response}")

        response = fix_nested_client(response)

        results.append(CommandResults(
            outputs_prefix="SpurContextAPI.Context",
            outputs_key_field="",
            outputs=response,
            raw_response=response,
            indicator=_build_spur_indicator(ip, response),
        ))

    return results


""" MAIN FUNCTION """


def main() -> None:
    api_key = demisto.params().get("credentials", {}).get("password")
    base_url = demisto.params().get("base_url")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    demisto.debug(f"Command being called is {demisto.command()}")

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        headers: dict = {"TOKEN": api_key}

        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        command = demisto.command()

        if command == "test-module":
            return_results(test_module(client))
        elif command == "ip":
            return_results(ip_command(client, demisto.args()))
        elif command == "spur-context-api-enrich":
            return_results(enrich_command(client, demisto.args()))

    except Exception:
        return_error(f"Error: {traceback.format_exc()}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
