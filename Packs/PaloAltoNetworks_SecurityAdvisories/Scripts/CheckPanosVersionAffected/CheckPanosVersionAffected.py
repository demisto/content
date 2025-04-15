import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

"""
This automation compares a given PAN-OS version (ex. 9.1.1) with a list of PAN-OS advisories from the
pan-advisories-get-advisors command to see if it is affected by any in the list.
"""

from dataclasses import dataclass


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
    :param affected_version_list: List of PAN-OS affected versions exactly
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

    _title = "Matching advisories"
    _output_prefix = "MatchingSecurityAdvisory"


def return_result_dataclass(result: list[Advisory]):
    """Converts the resultant dataclasses into command results"""
    if not result:
        command_result = CommandResults(
            readable_output="No results.",
        )
        return command_result

    if type(result) is list:
        outputs = [vars(x) for x in result]
        summary_list = [vars(x) for x in result]
        title = result[0]._title
        output_prefix = result[0]._output_prefix
    else:
        title = ''
        summary_list = []
        outputs = []
        output_prefix = ''
        demisto.debug(f"The result isn't of type list. {title=} {summary_list=} {outputs=} {output_prefix=}")

    readable_output = tableToMarkdown(title, summary_list)
    command_result = CommandResults(
        outputs_prefix=output_prefix,
        outputs=outputs,
        readable_output=readable_output,
    )
    return command_result


def simplify_affected_version_list(affected_version_list: list[str]):
    """
    The affected version list includes the platform prefixed (PAN-OS 9.1.1) - trim the PAN-OS out and return the list.
    """
    simplified_version_list: list[str] = []
    for version_string in affected_version_list:
        simplified_version_list.append(version_string.split(" ")[1])

    return simplified_version_list


def compare_version_with_advisories(panos_version: str, advisories_list: list[Advisory]):
    """
    Given a list of PAN-OS security advisories, compare the given panos-version to see if the version matches the affected list

    :param panos_version: The string version of PAN-OS, such as 9.1.1
    :param advisories_list: The list of Security Advisories
    """
    matched_advisories: list[Advisory] = []
    for advisory in advisories_list:
        if panos_version in simplify_affected_version_list(advisory.affected_version_list):
            matched_advisories.append(advisory)

    return matched_advisories


def main():
    """
    Main function
    Reads advisories from the pan-advisories-get-advisories command and compares them with the provided PAN-OS version to check
    for a match - if so, returns the matching advisories.
    """

    advisories_list: list = demisto.args().get("advisories")

    advisories_objects: list[Advisory] = [Advisory(**advisory_dict) for advisory_dict in advisories_list]
    panos_version: str = demisto.args().get("version")
    matched_advisories = compare_version_with_advisories(panos_version, advisories_list=advisories_objects)
    return_results(return_result_dataclass(matched_advisories))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
