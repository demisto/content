import urllib3
import contextlib
from typing import Any
import re

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)

    def cve_latest(self, limit) -> list[dict[str, Any]]:
        return self._http_request(method="GET", url_suffix=f"/last/{limit}")

    def cve(self, cve_id) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=f"cve/{cve_id}")


def cve_to_context(cve) -> dict[str, str]:
    """
    Returning a cve structure with the following fields:
    * ID: The cve ID.
    * CVSS: The cve score scale/
    * Published: The date the cve was published.
    * Modified: The date the cve was modified.
    * Description: the cve's description

    Args:
        cve: The cve response from CVE-Search web site
    Returns:
        The cve structure.
    """
    cvss = cve.get("cvss")
    return {
        "ID": cve.get("id", ""),
        "CVSS": cvss or "N\\A",
        "Published": cve.get("Published", "").rstrip("Z"),
        "Modified": cve.get("Modified", "").rstrip("Z"),
        "Description": cve.get("summary", ""),
    }


def test_module(client: Client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    cve_latest_command(client, 1)
    return "ok"


def get_cvss_verion(cvss_vector: str) -> float:
    """
    Extracts the CVSS score version according to its vector.

    Args:
        cvss_vector: The CVSS of the CVE.

    Returns:
        The CVSS version as a float.

    """
    if not cvss_vector:
        return 0
    elif cvss_version_regex := re.match("CVSS:(?P<version>.+?)/", cvss_vector):
        return float(cvss_version_regex.group("version"))
    else:
        return 2.0


def cve_latest_command(client: Client, limit) -> list[CommandResults]:
    """
    Returns the 30 latest updated CVEs.

    Args:
         limit int: The amount of CVEs to display
    Returns:
         Latest 30 CVE details containing ID, CVSS, modified date, published date and description.
    """
    res = client.cve_latest(limit)
    command_results: list[CommandResults] = []
    for cve_details in res:
        data = cve_to_context(cve_details)
        indicator = generate_indicator(cve_details)
        readable_output = tableToMarkdown("Latest CVEs", data)
        command_results.append(
            CommandResults(
                outputs_prefix="CVE",
                outputs_key_field="ID",
                outputs=data,
                readable_output=readable_output,
                raw_response=res,
                indicator=indicator,
            )
        )

    if not res:
        command_results.append(CommandResults(readable_output="No results found"))
    return command_results


def cve_command(client: Client, args: dict) -> list[CommandResults] | CommandResults:
    """
    Search for cve with the given ID and returns the cve data if found.

    Args:
           client: Integration client
           args :The demisto args containing the cve_id
    Returns:
        CVE details containing ID, CVSS, modified date, published date and description.
    """
    cve_ids = argToList(args.get("cve", ""))
    command_results: list[CommandResults] = []

    for _id in cve_ids:
        if not valid_cve_id_format(_id):
            raise DemistoException(f'"{_id}" is not a valid cve ID')

        if response := client.cve(_id):
            data = cve_to_context(response)
            indicator = generate_indicator(response)
            cr = CommandResults(
                outputs_prefix="CVESearch.CVE",
                outputs_key_field="CVE",
                outputs=data,
                raw_response=response,
                indicator=indicator,
                relationships=indicator.relationships,
            )
        else:
            cr = CommandResults(readable_output=f"### No results found for cve {_id}")
        command_results.append(cr)

    return command_results


def parse_cpe(cpes: list[str], cve_id: str) -> tuple[list[str], list[EntityRelationship]]:
    """
    Parses a CPE to return the correct tags and relationships needed for the CVE.

    Args:
        cpe: A list representing a single CPE, see "https://nvlpubs.nist.gov/nistpubs/legacy/ir/nistir7695.pdf"

    Returns:
        A tuple consisting of a list of tags and a list of EntityRelationships.

    """

    cpe_parts = {"a": "Application", "o": "Operating-System", "h": "Hardware"}

    vendors = set()
    products = set()
    parts = set()

    for cpe in cpes:
        cpe_split = re.split("(?<!\\\):", cpe)

        with contextlib.suppress(IndexError):
            if vendor := cpe_split[3].capitalize().replace("\\", "").replace("_", " "):
                vendors.add(vendor)

        with contextlib.suppress(IndexError):
            if product := cpe_split[4].capitalize().replace("\\", "").replace("_", " "):
                products.add(product)

        with contextlib.suppress(IndexError):
            parts.add(cpe_parts[cpe_split[2]])

    relationships = [
        EntityRelationship(name="targets", entity_a=cve_id, entity_a_type="cve", entity_b=vendor, entity_b_type="identity")
        for vendor in vendors
    ]

    relationships.extend(
        [
            EntityRelationship(name="targets", entity_a=cve_id, entity_a_type="cve", entity_b=product, entity_b_type="software")
            for product in products
        ]
    )

    return list(vendors | products | parts), relationships


def generate_indicator(data: dict) -> Common.CVE:
    """
    Generating a single cve indicator with dbot score from cve data.

    Args:
        data: The cve data

    Returns:
        A CVE indicator with dbotScore
    """

    cve_id = data.get("id", "")
    if cpe := data.get("vulnerable_product", ""):
        tags, relationships = parse_cpe(cpe, cve_id)

    else:
        relationships = []
        tags = []

    cwe = data.get("cwe", "")

    if cwe and cwe != "NVD-CWE-noinfo":
        tags.append(cwe)

    cvss_table = []

    for category in ("impact", "access"):
        for key, value in data.get(category, []).items():
            cvss_table.append({"metrics": key, "value": value})

    vulnerable_products = [Common.CPE(cpe) for cpe in data.get("vulnerable_product", [])]
    vulnerable_configurations = [
        Common.CPE(cpe.get("id")) if isinstance(cpe, dict) else Common.CPE(cpe)
        for cpe in data.get("vulnerable_configuration", [])
    ]
    cpes = set(vulnerable_products) | set(vulnerable_configurations)

    cve_object = Common.CVE(
        id=cve_id,
        cvss=data.get("cvss"),
        cvss_vector=data.get("cvss-vector"),
        cvss_version=get_cvss_verion(data.get("cvss-vector", "")),
        cvss_table=cvss_table,
        published=data.get("Published"),
        modified=data.get("Modified"),
        description=data.get("summary"),
        vulnerable_products=cpes,
        publications=[
            Common.Publications(title=data.get("id"), link=reference, source="Circl.lu")
            for reference in data.get("references", [])
        ],
        tags=tags,
    )

    if relationships:
        cve_object.relationships = relationships
    return cve_object


def valid_cve_id_format(cve_id: str) -> bool:
    """
    Validates that the given cve_id is a valid cve ID.
    For more details see: https://cve.mitre.org/cve/identifiers/syntaxchange.html

    Args:
        cve_id: ID to validate
    Returns:
        True if cve_id is a valid cve ID else False
    """
    return bool(re.match(cveRegex, cve_id))


def main():
    params = demisto.params()
    proxy = params.get("proxy", False)
    use_ssl = not params.get("insecure", False)
    base_url = params.get("url", "https://cve.circl.lu/api/")
    client = Client(base_url=base_url, verify=use_ssl, proxy=proxy)
    command = demisto.command()
    LOG(f"Command being called is {command}")
    try:
        if demisto.command() == "test-module":
            return_results(test_module(client))

        elif demisto.command() == "cve-latest":
            return_results(cve_latest_command(client, demisto.args().get("limit", 30)))

        elif demisto.command() == "cve":
            return_results(cve_command(client, demisto.args()))

        else:
            raise NotImplementedError(f"{command} is not an existing CVE Search command")

    except DemistoException as err:
        if err.res.status_code == 404:
            return_error(f'Failed to execute {demisto.command()} command.\nError: {"Invalid server URL"}')
        else:
            return_error(f"Failed to execute {demisto.command()} command. Error: {str(err)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
