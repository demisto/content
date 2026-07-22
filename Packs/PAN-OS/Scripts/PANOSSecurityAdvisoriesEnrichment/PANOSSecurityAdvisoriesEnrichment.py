import re
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

OUTPUT_PREFIX = "PANOSSecurityAdvisories"
BASE_URL = "https://security.paloaltonetworks.com"
CVE_JSON = "/json/"
CVE_CSAF = "/csaf/"


class Client:
    """The client that connects to the advisories JSON endpoint"""

    def __init__(self):
        self.base_url = BASE_URL
        self.advisories_url = f"{self.base_url}{CVE_JSON}"
        self.csaf_url = f"{self.base_url}{CVE_CSAF}"

    def get_cve(self, cve_id: str):
        """
        Gets a specific CVE advisory
        """
        url = f"{self.advisories_url}{cve_id}"
        response = requests.get(url)
        if response.status_code != 404 and response.status_code != 200:
            response.raise_for_status()
        return response.json()

    def get_pan_sa_advisories(self, pan_sa_id: str):
        """
        Gets a specific PAN-SA advisory
        """
        url = f"{self.csaf_url}{pan_sa_id}"
        response = requests.get(url)
        if response.status_code == 404:
            demisto.debug(f"CSAF not available for {pan_sa_id}")
            return f"CSAF not available for {pan_sa_id}"
        response.raise_for_status()
        return response.json()


def parse_version(version: str) -> tuple[int, ...]:
    parts = re.match(r"(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?", version)
    if parts:
        return tuple(int(p) if p else 0 for p in parts.groups())
    return (0, 0, 0, 0)


def sort_versions_and_changes(data: List[Dict]) -> List[Dict]:
    for item in data:
        if "versions" in item:
            item["versions"] = sorted(item["versions"], key=lambda x: parse_version(x["version"]), reverse=True)
            for version in item["versions"]:
                if "changes" in version:
                    version["changes"] = sorted(version["changes"], key=lambda x: parse_version(x["at"]))
    return data


def create_product_platform_tables(sorted_data: List[Dict]) -> List[Dict]:
    result = []

    for item in sorted_data:
        product = item.get("product", "")
        platforms = item.get("platforms", [])
        default_status = item.get("defaultStatus", "Unknown")

        for version in item.get("versions", []):
            start_version = version.get("version", "")
            end_version = version.get("lessThan") or version.get("lessThanOrEqual", "")
            status = version.get("status", default_status)

            for platform in platforms or [""]:
                version_key = f"{product}{' - ' + platform if platform else ''} - {start_version}"

                affected_versions = []
                unaffected_versions = []
                unknown_versions = []

                if not end_version:
                    # Single version case
                    if status == "affected":
                        affected_versions.append("All")
                        unaffected_versions.append("None")
                    elif status == "unaffected":
                        unaffected_versions.append("All")
                        affected_versions.append("None")
                    else:
                        unknown_versions.append(start_version)
                else:
                    # Range case
                    range_str = f"{start_version} - {end_version}"
                    changes = sorted(version.get("changes", []), key=lambda x: parse_version(x["at"]))

                    for change in changes:
                        change_version = change.get("at", "")
                        change_status = change.get("status", "")

                        if change_status == "unaffected":
                            affected_versions.append(f"< {change_version}")
                            unaffected_versions.append(f">= {change_version}")
                            unknown_versions.append("N/A")
                        elif change_status == "affected":
                            affected_versions.append(f">= {change_version}")
                            unaffected_versions.append(f"< {change_version}")
                            unknown_versions.append("N/A")
                        elif change_status == "unknown":
                            unknown_versions.append(f"< {change_version}")
                            unknown_versions.append(f">= {change_version}")

                    # Add the default status for the range if no changes
                    if not changes:
                        if status == "affected":
                            affected_versions.append(range_str)
                            unaffected_versions.append("None")
                            unknown_versions.append("N/A")
                        elif status == "unaffected":
                            unaffected_versions.append(range_str)
                            affected_versions.append("None")
                            unknown_versions.append("N/A")
                        else:
                            unknown_versions.append(range_str)
                            affected_versions.append("N/A")
                            unaffected_versions.append("N/A")

                result.append(
                    {
                        "Product": version_key,
                        "Affected": affected_versions,
                        "Unaffected": unaffected_versions,
                        "Unknown": unknown_versions,
                    }
                )

    return result


def flatten_advisory_dict(advisory_dict: dict, external_cves: list) -> Dict:
    """Given a dictionary advisory, return a flattened dictionary object with required CVE parameters"""
    if "cveMetadata" in advisory_dict:  # CVE-2012-6602.json format
        cna = advisory_dict.get("containers", {}).get("cna", {})
        metrics = sorted(
            cna.get("metrics", [{}]),
            key=lambda x: x.get("cvssV3_1", {}).get("baseScore", 0) or x.get("cvssV4_0", {}).get("baseScore", 0),
            reverse=True,
        )
        top_metric = metrics[0].get("cvssV3_1", {}) or metrics[0].get("cvssV4_0", {})
        affected_list = cna.get("affected", [])
        return {
            "cve_id": advisory_dict.get("cveMetadata", {}).get("cveId", ""),
            "title": cna.get("title", ""),
            "description": cna.get("descriptions", [{}])[0].get("value", ""),
            "cvss_score": top_metric.get("baseScore"),
            "cvethreatscore": top_metric.get("threatScore"),
            "cvethreatseverity": top_metric.get("threatSeverity"),
            "cvss_severity": top_metric.get("baseSeverity", ""),
            "cvss_vector_string": [
                metric.get("cvssV3_1", {}).get("vectorString", "") or metric.get("cvssV4_0", {}).get("vectorString", "")
                for metric in metrics
            ],
            "affected_list": sort_versions_and_changes(affected_list),
            "published_date": advisory_dict.get("cveMetadata", {}).get("datePublished", "") or cna.get("datePublic", ""),
            "last_updated_date": max((event.get("time") for event in cna.get("timeline", [])), default="")
            or cna.get("providerMetadata", {}).get("dateUpdated", ""),
            "workaround": "\n".join([w.get("value", "") for w in cna.get("workarounds", [{}])]),
            "configurations": "\n".join([cfg.get("value", "") for cfg in cna.get("configurations", [])]),
            "exploits": "\n".join([e.get("value", "") for e in cna.get("exploits", [])]),
            "cvss_table": [{"metrics": k, "value": v} for k, v in top_metric.items()],
            "solution": cna.get("solutions", [{}])[0].get("value", ""),
            "cve_url": "https://security.paloaltonetworks.com/{}".format(advisory_dict.get("cveMetadata", {}).get("cveId", "")),
            "impact": cna.get("impacts", [{}])[0].get("descriptions", [{}])[0].get("value", ""),
            "cpes": [cpe for affected in affected_list if "cpes" in affected for cpe in affected.get("cpes", [])],
            "cveproductstatus": create_product_platform_tables(affected_list),
            "external_cve_list": external_cves,
        }
    else:
        return {}


def get_external_cves(client: Client, pan_sa_id: str) -> List[Dict[str, str]]:
    if not re.match(r"^PAN-SA-\d{4}-\d{4}$", pan_sa_id):
        raise ValueError("Invalid PAN-SA ID format")

    response = client.get_pan_sa_advisories(pan_sa_id)

    # If response is a string (meaning CSAF not available), return empty list
    if isinstance(response, str):
        demisto.info(response)
        return []

    external_cves = []

    if "vulnerabilities" in response:
        for vuln in response["vulnerabilities"]:
            cve = vuln.get("cve")
            if cve and "CVE-" in cve:
                external_link = next(
                    (ref["url"] for ref in vuln.get("references", []) if ref.get("category") == "external"), None
                )
                cve_text = next((note["text"] for note in vuln.get("notes", []) if note.get("category") == "description"), None)

                if cve and external_link and cve_text:
                    external_cves.append({"id": cve, "link": external_link, "description": cve_text})

    return external_cves


def enrich_cve(client: Client, cve_id: str) -> Dict:
    """
    Enriches a specific CVE with data from Palo Alto Networks
    """
    cve_data = client.get_cve(cve_id)
    if "PAN-SA" in cve_id:
        external_cves = get_external_cves(client, cve_id)
    else:
        external_cves = []  # Initialize as empty list instead of empty dict
    if "error" not in cve_data:
        advisory = flatten_advisory_dict(cve_data, external_cves)
    else:
        advisory = {"error": "This is not a valid Palo Alto Networks CVE ID"}
    return {
        "Type": entryTypes["note"],
        "EntryContext": {f"{OUTPUT_PREFIX}.Advisory": advisory},
        "Contents": advisory,
        "ContentsFormat": formats["json"],
        "HumanReadable": tableToMarkdown("CVE Vulnerability Assessment", advisory),
        "ReadableContentsFormat": formats["markdown"],
    }


def main():
    """Main entrypoint for script"""
    client = Client()
    args = demisto.args()

    try:
        cve_ids = argToList(args.get("cve_id", ""))
        for cve_id in cve_ids:
            result = enrich_cve(client, cve_id.upper())
            if "error" in result:
                return_results(result.get("error"))
            else:
                return_results(result)
    except Exception as err:
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
