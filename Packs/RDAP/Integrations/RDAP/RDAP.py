import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Any
from collections.abc import Callable
from collections import namedtuple


INTEGRATION_NAME = "RDAP"

VCARD_MAPPING = {"title": 0, "label": 1, "data_type": 2, "data": 3}

IndicatorResult = namedtuple("IndicatorResult", ["value", "context_output", "readable_output"])


class RDAPClient(BaseClient):
    def __init__(self, base_url, verify: bool):
        super().__init__(base_url=base_url, verify=verify)
        demisto.debug(f"RDAPClient initialized with base_url: {base_url}")

    def rdap_query(self, indicator_type: str, value: str):
        url_suffix = f"{indicator_type}/{value}"
        demisto.debug(f"Sending RDAP query for {indicator_type}: {value}")
        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
        )
        demisto.debug(f"RDAP query response received for {indicator_type}: {value}")
        return response


def parse_domain_response(indicator: str, response: dict[str, Any]) -> tuple[Common.Domain, dict[str, Any], str]:
    demisto.debug(f"Parsing domain response for: {indicator}")
    domain = Common.Domain(
        domain=indicator,
        dbot_score=Common.DBotScore(
            indicator=indicator,
            indicator_type=DBotScoreType.DOMAIN,
            score=Common.DBotScore.NONE,
            reliability=DBotScoreReliability.A,
        ),
    )

    if "Error" in response:
        context_output = {"Value": indicator, "IndicatorType": "Domain"}
        readable_output = f'### RDAP Information for {indicator}\n{response["Error"]}'
        return IndicatorResult(value=domain, context_output=context_output, readable_output=readable_output)

    events = response.get("events", []) if isinstance(response, dict) else []
    last_changed_date: str = ""

    for event in events:
        if isinstance(event, dict):
            if event.get("eventAction") == "registration":
                domain.creation_date = event.get("eventDate")
            elif event.get("eventAction") == "expiration":
                domain.expiration_date = event.get("eventDate")
            elif event.get("eventAction") == "last changed":
                last_changed_date = event.get("eventDate", "")

    secure_dns = response.get("secureDNS", {}) if isinstance(response, dict) else {}
    delegation_signed = secure_dns.get("delegationSigned", False) if isinstance(secure_dns, dict) else False

    # Human readable output
    readable_output = tableToMarkdown(
        name=f"RDAP Information for {indicator}",
        t=[
            {"Field": "Registration Date", "Value": domain.creation_date},
            {"Field": "Expiration Date", "Value": domain.expiration_date},
            {"Field": "Secure DNS", "Value": delegation_signed},
        ],
    )

    # Context output
    context_output = {
        "Value": indicator,
        "IndicatorType": "Domain",
        "RegistrationDate": domain.creation_date,
        "ExpirationDate": domain.expiration_date,
        "LastChangedDate": last_changed_date,
        "SecureDNS": str(delegation_signed),
    }

    return IndicatorResult(value=domain, context_output=context_output, readable_output=readable_output)


def parse_ip_response(indicator: str, response: dict[str, Any]) -> tuple[Common.IP, dict[str, Any], str]:
    """
    Parse the RDAP response for an IP address and return a Common.IP object.

    This function takes the RDAP response for an IP address and extracts relevant information
    to create a Common.IP object. It populates various fields of the IP object including
    IP type, geographical country, description, and registrar abuse contact information.

    Args:
        indicator (str): The IP address being queried.
        response (dict[str, Any]): The RDAP response dictionary for the IP address.

    Returns:
        tuple[Common.IP, dict[str, Any], str]: A tuple containing:
            - Common.IP object with parsed information about the IP address
            - Context data dictionary for XSOAR
            - Human readable output string
    """
    demisto.debug(f"Parsing IP response for: {indicator}")

    ip = Common.IP(
        ip=indicator,
        dbot_score=Common.DBotScore(
            indicator=indicator, indicator_type=DBotScoreType.IP, score=Common.DBotScore.NONE, reliability=DBotScoreReliability.A
        ),
    )

    ip.ip_type = "IP" if response.get("ipVersion", "") == "v4" else "IPv6"

    if "Error" in response:
        context_output = {"Value": indicator, "IndicatorType": "IP"}
        readable_output = f'### RDAP Information for {indicator}\n{response["Error"]}'
        return IndicatorResult(value=ip, context_output=context_output, readable_output=readable_output)

    ip.geo_country = response.get("country", "")

    for remark in response.get("remarks", []):
        if remark.get("title") == "description":
            ip.description = remark.get("description", "")[0]
            break

    entities = response.get("entities", [])

    for entity in entities:
        if "abuse" in entity.get("roles", []):
            vcard_array = entity.get("vcardArray", [])

            if len(vcard_array) >= 2:  # check if vcard array has info in it
                for vcard in vcard_array[1]:
                    match vcard[0]:
                        case "adr":  # Address
                            ip.registrar_abuse_address = vcard[VCARD_MAPPING["label"]]["label"] or ""

                        case "fn":  # Full Name
                            ip.organization_name = vcard[VCARD_MAPPING["data"]] or ""
                            ip.registrar_abuse_name = vcard[VCARD_MAPPING["data"]] or ""

                        case "email":  # Email Address
                            ip.registrar_abuse_email = vcard[VCARD_MAPPING["data"]] or ""

                        case "tel":  # Telephone Number
                            ip.registrar_abuse_phone = vcard[VCARD_MAPPING["data"]] or ""

    # Human readable output
    readable_output = tableToMarkdown(
        name=f"RDAP Information for {indicator}",
        t=[
            {"Field": "Abuse Address", "Value": ip.registrar_abuse_address},
            {"Field": "Abuse Name", "Value": ip.registrar_abuse_name},
            {"Field": "Abuse Email", "Value": ip.registrar_abuse_email},
        ],
        headers=["Field", "Value"],
        removeNull=True,
    )

    # Context output
    context_output = {
        "Value": indicator,
        "IndicatorType": "IP",
        "RegistrarAbuseAddress": ip.registrar_abuse_address,
        "RegistrarAbuseName": ip.registrar_abuse_name,
        "RegistrarAbuseEmail": ip.registrar_abuse_email,
    }

    return IndicatorResult(value=ip, context_output=context_output, readable_output=readable_output)


def test_module(client: RDAPClient) -> str | None:
    demisto.debug("Running test_module")
    try:
        client.rdap_query(indicator_type="domain", value="example.com")

    except Exception as e:
        raise e

    return "ok"


def build_results(
    client: "RDAPClient", parse_command: Callable, indicators: List[str], outputs_prefix: str, command: str
) -> List[CommandResults]:
    """
    Builds command results for the given indicators.

    Args:
        client (RDAPClient): The RDAP client to use for queries.
        parse_command (Callable): The function to parse the RDAP response.
        indicators (List[str]): List of indicators to query.
        outputs_prefix (str): The prefix for the outputs context data.
        command (str): The indicator type/command being executed.

    Returns:
        List[CommandResults]: List of command results for each indicator.
    """

    results = []

    for value in indicators:
        demisto.debug(f"Executing {demisto.command()} command for value: {value}")
        try:
            response = client.rdap_query(indicator_type=command, value=value)

        except requests.exceptions.RequestException as e:
            if e.response and e.response.status_code == 404:
                response = {"Error": "Indicator Not Found"}

            else:
                raise e

        except Exception as e:
            raise e

        result = parse_command(value, response)
        indicator = result.value
        context = result.context_output
        readable_output = result.readable_output

        results.append(
            CommandResults(
                outputs_prefix=f"{INTEGRATION_NAME}.{outputs_prefix}",
                outputs_key_field=outputs_prefix,
                outputs=context,
                indicator=indicator,
                readable_output=readable_output,
            )
        )

    return results


def main():
    args = demisto.args()
    base_url = args.get("base_url", "https://rdap.org")
    command = demisto.command()
    outputs_prefix = ""
    indicators = argToList(args.get("ip", []) or args.get("domain", []))
    verify = not argToBoolean(args.get("insecure", False))
    client = RDAPClient(base_url=base_url, verify=verify)
    parse_command: Callable = parse_ip_response

    try:
        if not indicators:
            raise ValueError("An indicator is required.")

        if command == "test-module":
            demisto.debug("Executing test-module command")
            return_results(test_module(client))

        elif command == "ip":
            outputs_prefix = "IP"

        elif command == "domain":
            outputs_prefix = "Domain"
            parse_command = parse_domain_response

        else:
            raise DemistoException(f"Unknown command '{demisto.command()}'")

        results = build_results(client, parse_command, indicators, outputs_prefix, command)

        return_results(results)

    except Exception as e:
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
