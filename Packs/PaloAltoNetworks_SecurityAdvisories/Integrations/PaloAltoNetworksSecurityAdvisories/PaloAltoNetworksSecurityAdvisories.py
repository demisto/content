import demistomock as demisto
from CommonServerPython import *

from dataclasses import dataclass
import enum

OUTPUT_PREFIX = "PANSecurityAdvisory."


class Client(BaseClient):
    """The client that conects to the advisories API"""
    PRODUCTS_ENDPOINT = "/products"
    ADVISORIES_ENDPOINT = "/advisories"

    def __init__(self, base_url, api_timeout=60, verify=True, proxy=False,
                 ok_codes=(), headers=None):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers)
        self.api_timeout = api_timeout

    def get_products(self):
        """
        Gets the list of Supported Products by the Advisories API
        """
        return self._http_request(
            method='GET',
            url_suffix=Client.PRODUCTS_ENDPOINT,
            timeout=self.api_timeout
        )

    def get_advisories(self, product: str, params: dict):
        """
        Gets the list of advisories
        :product: Required Product name to list advisories for
        :params: Optional list of GET parameters to include in the request.
        """
        params = params or {}
        return self._http_request(
            method='GET',
            url_suffix=f"{Client.PRODUCTS_ENDPOINT}/{product}{Client.ADVISORIES_ENDPOINT}",
            timeout=self.api_timeout,
            params=params
        )


def dataclass_to_command_results(result: Any, raw_response: Union[list, dict]) -> CommandResults:
    """Takes a list, or a single, dataclass instance and converts it to a CommandResult instance."""
    if not result:
        command_result = CommandResults(
            readable_output="No results.",
        )
        return command_result

    outputs: Union[list[dict], dict, Any]
    if isinstance(result, list):
        outputs = [vars(x) for x in result]
        summary_list = [vars(x) for x in result]
        title = result[0]._title
        output_prefix = result[0]._output_prefix
    else:
        outputs = vars(result)
        summary_list = [vars(result)]
        title = result._title
        output_prefix = result._output_prefix

    extra_args = {}
    if hasattr(result, "_outputs_key_field"):
        extra_args["outputs_key_field"] = result._outputs_key_field

    readable_output = tableToMarkdown(title, summary_list)
    command_result = CommandResults(
        outputs_prefix=output_prefix,
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
        **extra_args
    )
    return command_result


@dataclass
class Advisory:
    """
    :param data_type: The type of advisory this is
    :param data_format: The format of the advisory, such as MITRE
    :param cve_id: The ID of the CVE described by this advisory
    :param cve_date_public: The date this CVE was released
    :param cve_title: The name of this CVE
    :param affects_product_name: The name of the product this affects, such as PAN-OS
    :param description: Human readable description of Advisory
    :param affected_version_list: List of affected versions strings
    """
    data_type: str
    data_format: str
    cve_id: str
    cve_date_public: str
    cve_title: str
    description: str
    cvss_score: int
    cvss_severity: str
    cvss_vector_string: str
    affected_version_list: list

    _output_prefix = OUTPUT_PREFIX + "Advisory"
    _title = "Palo Alto Networks Security Advisories"


class SeverityEnum(enum.Enum):
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


def flatten_advisory_dict(advisory_dict: dict) -> Advisory:
    """Given a dictionary advisory, return an `Advisory` object"""

    return Advisory(
        data_type=advisory_dict.get("data_type", ""),
        data_format=advisory_dict.get("data_format", ""),
        cve_id=advisory_dict.get("CVE_data_meta", {}).get("ID", ""),
        cve_title=advisory_dict.get("CVE_data_meta", {}).get("TITLE", ""),
        cve_date_public=advisory_dict.get("CVE_data_meta", {}).get("DATE_PUBLIC", ""),
        description=advisory_dict.get("description", {}).get("description_data", [])[0].get("value", ""),
        cvss_score=advisory_dict.get("impact", {}).get("cvss", {}).get("baseScore", ""),
        cvss_severity=advisory_dict.get("impact", {}).get("cvss", {}).get("baseSeverity", ""),
        cvss_vector_string=advisory_dict.get("impact", {}).get("cvss", {}).get("vectorString", ""),
        affected_version_list=advisory_dict.get("x_affectedList", ""),
    )


def test_module(client: Client):
    """Test the connectivity to the advisory API by checking for products"""
    request_result = client.get_products()
    if request_result.get("success"):
        return "ok"
    return None


def get_advisories(client: Client, product: str, sort: str = "-date", severity: SeverityEnum = None, q: str = "") \
        -> CommandResults:
    """
    Gets all the advisories for the given product.
    :param client: HTTP Client !no-auto-argument
    :param product: Product name to search for advisories
    :param sort: Sort returned advisories by this value, can be date, cvss, etc. Leading hyphpen (-) indicates reverse search.
    :param severity: Filter advisories to this severity level only.
    :param q: Text search query
    """
    params_dict = {
        "severity": severity,
        "sort": sort,
        "product": product
    }
    if q:
        params_dict["q"] = f"\"{q}\""

    advisory_data = client.get_advisories(product, params_dict).get("data", {})

    advisory_object_list: list[Advisory] = []
    advisory_dict: dict
    for advisory_dict in advisory_data:
        advisory_object_list.append(flatten_advisory_dict(advisory_dict))

    return dataclass_to_command_results(advisory_object_list, raw_response=advisory_data)


def advisory_to_indicator(advisory_dict: dict) -> dict:
    """Convert the advisory dictionary into an indicator dictionary

    Args:
        advisory_dict: advisory dictionary
    Returns:
        indicator dictionary
    """

    fields: dict = {}

    if problem_type := advisory_dict.get("problemtype"):
        tags = []  # holds cwe information as tags
        # the dict that holds the advisory information fo CWE data
        cwe_str: str = problem_type.get('problemtype_data', [{}])[0].get('description', [{}])[0].get('value', "")

        if cwe_str and cwe_str.startswith('CWE-'):
            # split this string after the CWE-\d* first space
            # CWE-754 Improper Check for Unusual or Exceptional Conditions
            cwe = cwe_str.split(" ", 1)
            cwe[0] = cwe[0].rstrip(':')

            tags.append(cwe[0])
            fields['tags'] = tags

    if references := advisory_dict.get("references"):
        references_list: list[dict] = references.get('reference_data', [{}])
        fields['publications'] = [
            {
                "link": x.get('url'),
                "title": x.get('name'),
                "source": x.get('refsource')
            } for x in references_list]

    impact: dict = advisory_dict.get("impact", {})
    cvss: dict = impact.get("cvss", {})
    # score mirrored to both fields so that default cve layout displays with full data
    fields['cvss'] = cvss.get("baseScore", "")
    fields['cvssscore'] = cvss.get("baseScore", "")
    fields['cvssvector'] = cvss.get("vectorString", "")
    fields['sourceoriginalseverity'] = cvss.get("baseSeverity", "")
    # mirror data in these fields so default CVE layout does not need to be changed
    # cvedescription not in default cve layout
    advisory_description = advisory_dict.get("description", {}).get("description_data", [{}])[0].get("value", "")
    fields['cvedescription'] = advisory_description
    # description in default cve layout
    fields['description'] = advisory_description
    fields['published'] = advisory_dict.get("CVE_data_meta", {}).get("DATE_PUBLIC", "")
    fields['name'] = advisory_dict.get("CVE_data_meta", {}).get("TITLE", [])

    if impact and cvss.get("version") in ['3.1', '4.0']:
        fields['cvssversion'] = cvss.get("version", "")

        # is this v3/v4 cvss?
        # fills out the cvsstable in default cve layout - different table column names
        cvss_data = []
        for k, v in cvss.items():
            cvss_data.append(
                {
                    "metrics": camel_case_to_underscore(k).replace("_", " ").title(),
                    "value": v
                }
            )
        fields['cvsstable'] = cvss_data

    return {
        "value": advisory_dict.get("CVE_data_meta", {}).get("ID", ""),
        "type": FeedIndicatorType.CVE,
        "rawJSON": advisory_dict,
        "fields": fields
    }


def fetch_indicators(client: Client, fetch_product_name="PAN-OS") -> list[dict]:
    """
    Fetch Advisories as CVE indicators.
    :param client: Client instance
    :param fetch_product_name: The name of the product to fetch indicators for.
    """
    advisory_data = client.get_advisories(fetch_product_name, {}).get("data", {})
    indicator_objects = []
    for advisory_dict in advisory_data:
        indicator_objects.append(advisory_to_indicator(advisory_dict))

    return indicator_objects


def main():
    """Main entrypoint for script"""

    client = Client(
        base_url=demisto.params().get("url")
    )
    command_name = demisto.command()
    demisto.info(f'Command being called is {command_name}')

    try:
        if command_name == "test-module":
            return_results(test_module(client))
        elif command_name == "pan-advisories-get-advisories":
            return_results(get_advisories(client, **demisto.args()))
        elif command_name == "fetch-indicators":
            for b in batch(fetch_indicators(client, demisto.params().get("fetch_product_name"))):
                demisto.createIndicators(b)
        else:
            raise NotImplementedError(f"command {command_name} is not implemented.")

    except Exception as err:
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
