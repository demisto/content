import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback
import re
import itertools


def version_compare(v1: str, v2: str) -> int:
    """
    Compare two version strings and return their relative ordering.

    This function compares two version strings by parsing them into numeric components
    and performing a lexicographic comparison. It handles PAN-OS version formats that
    use dots (.) and hyphens (-) as separators.

    Args:
        v1 (str): The first version string to compare (e.g., "10.2.3", "11.0.1-h2").
        v2 (str): The second version string to compare (e.g., "10.2.4", "11.0.0").

    Returns:
        int:
            -1 if v1 < v2 (v1 is older than v2)
             0 if v1 == v2 (versions are equal)
             1 if v1 > v2 (v1 is newer than v2)

    Note:
        - Versions are split on dots (.) and hyphens (-) into components
        - Only the first 3 components are considered for comparison
        - Non-numeric components are treated as 0
        - Missing components are treated as 0 (e.g., "10.2" is treated as "10.2.0")

    Examples:
        version_compare("10.2.3", "10.2.4") returns -1
        version_compare("11.0.0", "10.2.9") returns 1
        version_compare("10.2.3", "10.2.3") returns 0
        version_compare("10.2.3-h1", "10.2.3-h2") returns 0 (hotfix part ignored)
    """

    v1_parts = [int(x) if x.isdigit() else 0 for x in re.split(r"[\.\-]", v1)[:3]]
    v2_parts = [int(x) if x.isdigit() else 0 for x in re.split(r"[\.\-]", v2)[:3]]

    for v1_part, v2_part in itertools.zip_longest(v1_parts, v2_parts, fillvalue=0):
        if v1_part < v2_part:
            return -1
        elif v1_part > v2_part:
            return 1

    return 0


""" FUNCTION TO CHECK IF THE PAN-OS VERSION IS AFFECTED BY ANY CVE"""


def check_fw_version(
    fw_versions_checked: list[str], pan_os_affected_versions: list[dict], pan_os_system_info: dict[str, str]
) -> bool:  # noqa: E501
    """
    Check if a PAN-OS firewall version is affected by a CVE.

    This function determines whether the PAN-OS software version from the system
    information is affected by a given CVE by comparing it against the affected
    version ranges and applying any status changes (hotfixes/patches). It implements
    the algorithm provided on https://cveproject.github.io/cve-schema/schema/docs.

    Args:
        fw_versions_checked (list[str]): A list to track PAN-OS versions that
            have already been checked. The current version will be appended to this
            list if it falls back to the default status check.
        pan_os_affected_versions (list[dict]): A list of dictionaries containing affected
            version information for PAN-OS. Each dictionary should contain:
            - 'versions' (list): List of version entries with status information
            - 'defaultStatus' (str): Default status if version doesn't match any entry
        pan_os_system_info (dict[str, str]): Dictionary containing system information
            with 'sw_version' key containing the PAN-OS software version to check.

    Returns:
        bool: True if the PAN-OS version is affected by the CVE, False otherwise.

    Note:
        - Version entries can contain exact matches or range specifications using
          'lessThan'/'lessThanOrEqual' fields
        - Status changes (hotfixes) are applied in chronological order, with hotfix
          versions (containing '-') requiring exact matches
        - If no matching version entry is found, the defaultStatus is used
        - An empty string is used as fallback if 'sw_version' is not found in system info
    """
    v = pan_os_system_info.get("sw_version", "")
    fw_versions_checked.append(v)
    product_versions = pan_os_affected_versions[0].get("versions", []) if len(pan_os_affected_versions) > 0 else []
    default_status = (
        pan_os_affected_versions[0].get("defaultStatus", "unknown") if len(pan_os_affected_versions) > 0 else "unknown"
    )

    for entry in product_versions:
        if "lessThan" not in entry and "lessThanOrEqual" not in entry and v == entry["version"]:
            return entry["status"] == "affected"

        if ("lessThan" in entry and version_compare(entry["version"], v) <= 0 and version_compare(v, entry["lessThan"]) < 0) or (
            "lessThanOrEqual" in entry
            and version_compare(entry["version"], v) <= 0
            and version_compare(v, entry["lessThanOrEqual"]) <= 0
        ):
            status = entry["status"]
            for change in entry.get("changes", []):
                if "-" in change["at"]:  # Check if change['at'] is a hotfix
                    if change["at"] == v:  # Exact match for hotfix
                        status = change["status"]
                        break
                elif version_compare(change["at"], v) <= 0:
                    status = change["status"]
            return status == "affected"

    return default_status == "affected"


def check_gp_version(gp_version_checked: list[str], gp_affected_versions: list[dict], pan_os_system_info: dict[str, str]) -> bool:  # noqa: E501
    """
    Check if a GlobalProtect version is affected by a CVE.

    This function determines whether the GlobalProtect client package version from the
    system information is affected by a given CVE by comparing it against the affected
    version ranges and applying any status changes (hotfixes/patches). It implements
    the algorithm provided on https://cveproject.github.io/cve-schema/schema/docs.

    Args:
        gp_version_checked (list[str]): A list to track GlobalProtect versions that
            have already been checked. The current version will be appended to this
            list if it falls back to the default status check.
        gp_affected_versions (list[dict]): A list of dictionaries containing affected
            version information for GlobalProtect. Each dictionary should contain:
            - 'versions' (list): List of version entries with status information
            - 'defaultStatus' (str): Default status if version doesn't match any entry
        pan_os_system_info (dict[str, str]): Dictionary containing system information
            with 'global_protect_client_package_version' key containing the version
            to check.

    Returns:
        bool: True if the GlobalProtect version is affected by the CVE, False otherwise.

    Note:
        - Version entries can contain exact matches or range specifications using
          'lessThan'/'lessThanOrEqual' fields
        - Status changes (hotfixes) are applied in chronological order, with hotfix
          versions (containing '-') requiring exact matches
        - If no matching version entry is found, the defaultStatus is used
    """
    v = pan_os_system_info.get("global_protect_client_package_version", "")
    gp_version_checked.append(v)
    product_versions = gp_affected_versions[0].get("versions", []) if gp_affected_versions else []
    default_status = gp_affected_versions[0].get("defaultStatus", "unknown") if gp_affected_versions else "unknown"

    for entry in product_versions:
        if "lessThan" not in entry and "lessThanOrEqual" not in entry and v == entry["version"]:
            return entry["status"] == "affected"

        if ("lessThan" in entry and version_compare(entry["version"], v) <= 0 and version_compare(v, entry["lessThan"]) < 0) or (
            "lessThanOrEqual" in entry
            and version_compare(entry["version"], v) <= 0
            and version_compare(v, entry["lessThanOrEqual"]) <= 0
        ):
            status = entry["status"]
            for change in entry.get("changes", []):
                if "-" in change["at"]:  # Check if change['at'] is a hotfix
                    if change["at"] == v:  # Exact match for hotfix
                        status = change["status"]
                        break
                elif version_compare(change["at"], v) <= 0:
                    status = change["status"]
            return status == "affected"

    return default_status == "affected"


def main():
    args = demisto.args()
    pan_os_system_info_list = argToList(args.get("pan_os_system_info_list"))
    cve_json_list = argToList(args.get("cve_json"))

    try:
        for cve_json in cve_json_list:
            fw_versions_checked: list[str] = []
            gp_version_checked: list[str] = []
            result = {
                "CVE_ID": cve_json.get("cve_id", ""),
                "Severity": cve_json.get("cvethreatseverity") or cve_json.get("cvss_severity"),
                "Result": [],
            }
            affected_versions_in_cve = cve_json.get("affected_list", [])
            pan_os_affected_versions = [item for item in affected_versions_in_cve if item.get("product") == "PAN-OS"]
            gp_affected_versions = [item for item in affected_versions_in_cve if item.get("product") == "GlobalProtect App"]

            if len(pan_os_affected_versions) == 0 and len(gp_affected_versions) == 0:
                # return_results("CVE is not applicable to PAN-OS or GlobalProtect")
                for firewall in pan_os_system_info_list:
                    result["Result"].append(
                        {
                            "Hostname": firewall.get("hostname", ""),
                            "IPAddress": firewall.get("ip_address", ""),
                            "SWVersion": firewall.get("sw_version", ""),
                            "IsFirewallVersionAffected": False,
                            "GlobalProtectVersion": firewall.get("global_protect_client_package_version", ""),
                            "IsGlobalProtectVersionAffected": False,
                        }
                    )

            else:
                for firewall in pan_os_system_info_list:
                    """ USE fw_versions_checked TO SEE IF THIS VERSION WAS ALREADY CHECKED """
                    if firewall.get("sw_version") in fw_versions_checked:
                        IsFirewallVersionAffected = [
                            r.get("IsFirewallVersionAffected")
                            for r in result["Result"]
                            if r.get("SWVersion") == firewall.get("sw_version")
                        ][0]
                    else:
                        IsFirewallVersionAffected = check_fw_version(fw_versions_checked, pan_os_affected_versions, firewall)

                    """ USE gp_version_checked TO SEE IF THIS VERSION WAS ALREADY CHECKED """
                    if (
                        firewall.get("global_protect_client_package_version", "") in gp_version_checked
                        and len(result["Result"]) != 0
                    ):
                        IsGlobalProtectVersionAffected = [
                            r.get("IsGlobalProtectVersionAffected")
                            for r in result["Result"]
                            if r.get("GlobalProtectVersion") == firewall.get("global_protect_client_package_version", "")
                        ][0]
                    else:
                        IsGlobalProtectVersionAffected = check_gp_version(gp_version_checked, gp_affected_versions, firewall)

                    result["Result"].append(
                        {
                            "Hostname": firewall.get("hostname", ""),
                            "IPAddress": firewall.get("ip_address", ""),
                            "SWVersion": firewall.get("sw_version", ""),
                            "IsFirewallVersionAffected": IsFirewallVersionAffected,
                            "GlobalProtectVersion": firewall.get("global_protect_client_package_version", ""),
                            "IsGlobalProtectVersionAffected": IsGlobalProtectVersionAffected,
                        }
                    )

            context_output = result
            str_result = [{k: str(v) if isinstance(v, bool) else v for k, v in item.items()} for item in result["Result"]]
            md = tableToMarkdown(
                result["CVE_ID"],
                str_result,
                headers=[
                    "Hostname",
                    "IPAddress",
                    "SWVersion",
                    "IsFirewallVersionAffected",
                    "GlobalProtectVersion",
                    "IsGlobalProtectVersionAffected",
                ],
                is_auto_json_transform=True,
            )
            command_results = CommandResults(
                outputs_prefix="CVE_Check",
                outputs_key_field="",
                outputs=context_output,
                raw_response=context_output,
                readable_output=md,
            )

            return_results(command_results)

    except Exception as ex:
        # print the traceback
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute CheckFirewallVersionForCVEs_feed. Error: {str(ex)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
