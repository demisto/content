import urllib3
from typing import Any
import re
from CommonServerPython import *
import contextlib
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

    def cve(self, cve_id) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=f"cve/{cve_id}")
    
    def cve_latest(self, limit) -> list[dict[str, Any]]:
        return self._http_request(method="GET", url_suffix=f"/last/{limit}")




def extract_cvss_info_from_vector(vector_str: str) -> str:
    """
    Parse a CVSS vector string using regex to determine score.

    Args:
        vector_str (str): A CVSS vector like "CVSS:3.1/AV:N/AC:L/..."

    Returns:
        base_score (str): base_score as str (estimated).
    """
    try:

        if not vector_str.startswith("CVSS:"):
            return "N\\A"

        vector = dict(item.split(":") for item in vector_str.split("/")[1:])

        impact_map = {"N": 0.0, "L": 0.22, "H": 0.56}
        C = impact_map.get(vector.get("C", "N"), 0.0)
        impact_i = impact_map.get(vector.get("I", "N"), 0.0)
        A = impact_map.get(vector.get("A", "N"), 0.0)
        impact = 1 - ((1 - C) * (1 - impact_i) * (1 - A))


        scope = vector.get("S")
        impact_score = 7.52 * impact if scope == "C" else 6.42 * impact

        score = round(min(impact_score + 3.9, 10.0), 1)
        return str(score)
    except Exception as e:
        demisto.info(f"[CVSS Parse Error] {str(e)}")
        return "N\\A"

def detect_format(cve_data: dict) -> str:
    """
    Detects the format of a given CVE data dictionary.

    Supports detection of:
    - CVE 5.1 format (e.g., NVD, VulDB)
    - Legacy format (old CIRCL style)
    - CSAF format
    - GHSA format

    Args:
        cve_data: The CVE data as a dictionary.

    Returns:
        A string representing the CVE format: 'cve_5_1' or 'legacy'.

    Raises:
        ValueError: If the format is unrecognized.
    """
    if 'cveMetadata' in cve_data:
        return 'cve_5_1'
    elif 'document' in cve_data and 'vulnerabilities' in cve_data:
        return 'csaf'
    elif 'schema_version' in cve_data and 'id' in cve_data:
        return 'ghsa'
    elif 'sourceIdentifier' in cve_data:
        return 'nvd_cve_5_1'
    elif 'id' in cve_data and 'summary' in cve_data:
        return 'legacy'
    else:
        raise ValueError("Unknown CVE format: Unable to detect CVE structure")


def process_cve_data(cve: dict) -> dict:
    """
    Normalizes any supported CVE format into a unified structure expected by the `generate_indicator()` function.

    Supported formats include:
    - CVE 5.1
    - Legacy CVE format (older format used by CIRCL)

    Args:
        cve: The raw CVE data dictionary, from any supported source.

    Returns:
        A normalized dictionary with unified keys for downstream processing.

    Raises:
        ValueError: If the format is unrecognized or processing fails.
    """
    try:
        
        format_type = detect_format(cve)
        standardized_cve: dict

        if format_type == "cve_5_1":
            standardized_cve = handle_cve_5_1(cve)
        elif format_type == "legacy":
            standardized_cve = handle_legacy(cve)
        elif format_type == 'ghsa':
            standardized_cve = handle_ghsa(cve)
        elif format_type == 'nvd_cve_5_1':
            standardized_cve = handle_NVD_cve_5_1(cve)
        else:
            raise ValueError(f"Unsupported CVE format type: {format_type}")
        
        return standardized_cve
    
    except Exception as e:
        raise ValueError(f"Failed to process CVE data: {e}")


def handle_NVD_cve_5_1(cve_data):
    """
    Converts a CVE entry in NVD 5.1 format into a legacy CVE dictionary structure.

    This includes extracting:
    - CVE ID
    - Summary description (EN language)
    - CVSS base score and vector (version 3.1)
    - CWE identifiers (from the weaknesses list)
    - References (URLs)
    - Vulnerable products and configurations (including version ranges)

    Args:
        cve_data: A dictionary representing a CVE in the NVD 5.1 format, typically retrieved from NVD API.

    Returns:
        A dictionary in legacy CVE format for internal compatibility and indicator generation.
        Contains keys like id, summary, cvss, cvss-vector, Published, Modified, references, cwe,
        vulnerable_product, and vulnerable_configuration.
    """
    legacy = {
        "id": cve_data.get("id", ""),
        "cvss": "",
        "cvss-vector": "",
        "Published": cve_data.get("published", ""),
        "Modified": cve_data.get("lastModified", ""),
        "summary": "",
        "cwe": "",
        "references": [],
        "vulnerable_product": [],
        "vulnerable_configuration": [],
        "impact": {},
        "access": {}
    }

    descriptions = cve_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            legacy["summary"] = desc.get("value", "")
            break

    metrics = cve_data.get("metrics", {})
    cvss_metrics = metrics.get("cvssMetricV31", [])
    if cvss_metrics:
        cvss_data = cvss_metrics[0].get("cvssData", {})
        legacy["cvss"] = str(cvss_data.get("baseScore", ""))
        legacy["cvss-vector"] = cvss_data.get("vectorString", "")

    weaknesses = cve_data.get("weaknesses", [])
    cwe_list = []
    for weakness in weaknesses:
        descriptions = weakness.get("description", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                cwe_list.append(desc.get("value", ""))
    legacy["cwe"] = ", ".join(cwe_list)

    references = cve_data.get("references", [])
    for ref in references:
        url = ref.get("url", "")
        if url:
            legacy["references"].append(url)

    configurations = cve_data.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for cpe in cpe_matches:
                criteria = cpe.get("criteria", "")
                if criteria:
                    legacy["vulnerable_product"].append(criteria)
                    config_entry = {"criteria": criteria}
                    version_start = cpe.get("versionStartIncluding")
                    version_end = cpe.get("versionEndExcluding")
                    if version_start:
                        config_entry["version_start_including"] = version_start
                    if version_end:
                        config_entry["version_end_excluding"] = version_end
                    legacy["vulnerable_configuration"].append(config_entry)

    return legacy

def handle_cve_5_1(cve: dict) -> dict:
    """
    Converts a CVE 5.1 formatted record into a normalized legacy-like dictionary format
    used throughout the integration.

    Args:
        cve: The CVE data in CVE 5.1 format as a dictionary.

    Returns:
        A normalized dictionary containing common CVE attributes including ID, CVSS data, CWE, vulnerable products,
        references, and other relevant fields.
    """
    metadata = cve.get("cveMetadata", {})
    cna = cve.get("containers", {}).get("cna", {})
    cwe = next(
        (
            d.get("cweId")
            for p in cna.get("problemTypes", [])
            for d in p.get("descriptions", [])
            if d.get("lang") == "en" and d.get("cweId")
        ),
        "NVD-CWE-noinfo",
    )
    
    legacy = {
        "id": metadata.get("cveId", ""),
        "Published": metadata.get("datePublished", ""),
        "Modified": metadata.get("dateUpdated", ""),
        "last-modified": metadata.get("dateUpdated", ""),
        "summary": next((d.get("value") for d in cna.get("descriptions", []) if d.get("lang") in ("en", "en-US")), ""),
        "cvss": None,
        "cvss-vector": "",
        "cvss-time": metadata.get("dateUpdated", ""),
        "cwe": cwe,
        "references": [r.get("url") for r in cna.get("references", []) if r.get("url")],
        "vulnerable_product": [],
        "vulnerable_configuration": [],
        "access": {},
        "impact": {},
    }

    vector_str = ""
    for m in cna.get("metrics", []):
        for key in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
            if key in m:
                cvss = m[key]
                legacy["cvss"] = cvss.get("baseScore")
                vector_str = cvss.get("vectorString", "")
                legacy["cvss-vector"] = vector_str
                break

    if vector_str:
        parts = vector_str.split("/")
        vector_map = {p.split(":")[0]: p.split(":")[1] for p in parts if ":" in p}

        legacy["access"] = {
            "vector": vector_map.get("AV", ""),
            "complexity": vector_map.get("AC", ""),
            "authentication": vector_map.get("Au", "NONE")  # CVSSv3 omits this
        }
        legacy["impact"] = {
            "confidentiality": vector_map.get("C", ""),
            "integrity": vector_map.get("I", ""),
            "availability": vector_map.get("A", "")
        }

    for affected in cna.get("affected", []):
        vendor = affected.get("vendor", "").lower().replace(" ", "_")
        product = affected.get("product", "").lower().replace(" ", "_")
        versions = affected.get("versions", [])

        for version_entry in versions:
            version = version_entry.get("version")
            if vendor and product and version:
                cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                legacy["vulnerable_product"].append(cpe)
                legacy["vulnerable_configuration"].append({"id": cpe, "title": cpe})

        for cpe in affected.get("cpes", []):
            legacy["vulnerable_product"].append(cpe)
            legacy["vulnerable_configuration"].append({"id": cpe, "title": cpe})

    return legacy


def handle_legacy(cve: dict) -> dict:
    """
    Normalizes a legacy CVE format dictionary (from CIRCL, etc.) to the expected internal structure.

    Args:
        cve: A dictionary containing CVE fields in legacy format.

    Returns:
        A normalized dictionary containing CVE ID, CVSS, CWE, references, vulnerable products, and other metadata.
    """
    legacy = {
        "id": cve.get("id", ""),
        "cvss": cve.get("cvss", ""),
        "cvss-vector": cve.get("cvss-vector", ""),
        "Published": cve.get("Published", ""),
        "Modified": cve.get("Modified", ""),
        "summary": cve.get("summary", ""),
        "cwe": cve.get("cwe", ""),
        "references": cve.get("references", []),
        "vulnerable_product": cve.get("vulnerable_product", []),
        "vulnerable_configuration": cve.get("vulnerable_configuration", []),
        "impact": cve.get("impact", {}),
        "access": cve.get("access", {}),
    }
    return legacy

def handle_ghsa(cve: dict) -> dict:
    """
    Converts a CVE entry in GitHub Security Advisory (GHSA) format into a legacy CVE dictionary structure.

    The function extracts relevant fields such as CVE ID, CVSS vector and score, summary, publication dates,
    references, and CWE (Common Weakness Enumeration) values.

    Args:
        cve: A dictionary representing a CVE in GHSA format (as provided by GitHub's advisory API).

    Returns:
        A dictionary in legacy CVE format, compatible with downstream processing.
        The dictionary contains the following keys: id, Published, Modified, summary, cvss, cvss-vector,
        references, cwe, and placeholders for access/impact fields.
    """
    legacy = {
        "id": "",
        "Published": "",
        "Modified": "",
        "last-modified": "",
        "summary": "",
        "cvss": "",
        "cvss-vector": "",
        "cvss-time": "",
        "cwe": "",
        "references": "",
        "vulnerable_product": "",
        "vulnerable_configuration": "",
        "access": {},
        "impact": {},
    }
        
    legacy["id"] = cve.get("id", "")
    legacy["summary"] = cve.get("details", "")

    cvss_vector = ""
    for s in cve.get("severity", []):
        if s.get("type", "").upper() == "CVSS_V3":
            cvss_vector = s.get("score", "")
            break

    legacy["cvss-vector"] = cvss_vector

    if cvss_vector:
        try:
            legacy["cvss"] = str(extract_cvss_info_from_vector(cvss_vector))
        except Exception as e:
            demisto.info(f"Failed to parse CVSS vector: {cvss_vector}, error: {str(e)}")
            legacy["cvss"] = "N\\A"
    else:
        legacy["cvss"] = "N\\A"

    legacy["Published"] = cve.get("published", "")
    legacy["Modified"] = cve.get("modified", "")
    legacy["references"] = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]

    cwe_ids = cve.get("database_specific", {}).get("cwe_ids", [])
    if cwe_ids:
        legacy["cwe"] = cwe_ids[0]

    return legacy

def create_cve_summary(cve: dict) -> dict:
    """
    Extracts and summarizes the key fields from the normalized CVE data for presentation or context.

    Args:
        cve: A normalized CVE dictionary.

    Returns:
        A dictionary with simplified fields: ID, CVSS score, publish and modification dates, and a short description.
    """
    return {
        "ID": cve.get("id", ""),
        "CVSS": cve.get("cvss", "N/A"),
        "Published": cve.get("Published", "").rstrip("Z"),
        "Modified": cve.get("Modified", "").rstrip("Z"),
        "Description": cve.get("summary", "")
    }


def test_module(client: Client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    cve_command(client, {'cve': 'CVE-2023-3982'})
    return "ok"


def get_cvss_version(cvss_vector: str) -> float:
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
            
            try:
                full_data = process_cve_data(response)
            except ValueError as ve:
                if "Unsupported CVE format type" in str(ve):
                    continue
                elif "Failed to process CVE data" in str(ve):
                    continue
            
            data = create_cve_summary(full_data)
            indicator = generate_indicator(full_data)
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

        try:
            full_data = process_cve_data(cve_details)
        except ValueError as ve:
            if "Unsupported CVE format type" in str(ve):
                continue
            elif "Failed to process CVE data" in str(ve):
                continue
        data = create_cve_summary(full_data)
        indicator = generate_indicator(full_data)
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
        cpe_split = re.split(r"(?<!\\):", cpe)

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
        cvss_version=get_cvss_version(data.get("cvss-vector", "")),
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

    #return_results(json.dumps(cve_object.to_context(), indent=4))

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
        elif demisto.command() == "cve":
            return_results(cve_command(client, demisto.args()))
        elif demisto.command() == "cve-latest":
            return_results(cve_latest_command(client, demisto.args().get("limit", 30)))
        else:
            raise NotImplementedError(f"{command} is not an existing CVE Search command")

    except DemistoException as err:
        if err.res.status_code == 404:
            return_error(f'Failed to execute {demisto.command()} command.\nError: {"Invalid server URL"}')
        else:
            return_error(f"Failed to execute {demisto.command()} command. Error: {str(err)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
