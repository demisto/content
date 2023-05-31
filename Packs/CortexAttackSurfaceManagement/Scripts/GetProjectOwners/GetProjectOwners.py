import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Script for identifying and recommending the most likely owners of a discovered service
from those surfaced by Cortex ASM Enrichment.
"""


from typing import Optional, Dict, List, Any
import traceback
import re


def is_gcp_iam_account(service_account: str) -> bool:
    """
    Determine whether service account is user-managed

    Docs: https://cloud.google.com/iam/docs/service-account-types
    """
    return service_account.endswith("iam.gserviceaccount.com")


def extract_project_name(service_account: str) -> Optional[str]:
    """
    Extract project name from GCP IAM service account
    """
    match = re.search(r"(?<=@)[^\.]+(?=\.iam\.gserviceaccount\.com)", service_account)
    if match:
        return match.group()
    else:
        demisto.info(f"Could not extract project name from service account {service_account}")
        return None


def get_iam_policy(project_name: str) -> Optional[List[Dict[str, Any]]]:
    """
    Retrieve IAM policy for project
    """
    try:
        return demisto.executeCommand("gcp-iam-project-iam-policy-get", args={"project_name": f"projects/{project_name}"})
    except Exception as e:
        demisto.info(f"Error retrieving IAM policy for GCP project {project_name}. Error: {str(e)}")
        return None


def get_project_owners(results: List[Dict[str, Any]]) -> Optional[List[str]]:
    """
    Return list of principals with the "owner" role from results of get_iam_policy
    """
    try:
        policy = results[0]["Contents"]["bindings"]
        owners: List[str] = []
        for group in policy:
            if group["role"] == "roles/owner":
                owners.extend(member.replace("user:", "") for member in group["members"])
        return owners
    except Exception as e:
        demisto.info(f"Error getting project owners from IAM policy. Error: {str(e)}")
        return None


def main():
    try:
        unranked = demisto.args().get("owners", [])
        external_service = demisto.args().get("external_service", "")
        found_owners = False

        # only handle GCP for now
        if "Google" in external_service:
            for owner in unranked:
                if is_gcp_iam_account(owner["email"]):
                    project_name = extract_project_name(owner["email"])
                    if project_name:
                        results = get_iam_policy(project_name)
                        if results:
                            owners = get_project_owners(results)
                            if owners:
                                found_owners = True
                                current_owners = demisto.incident().get("CustomFields").get("asmserviceownerunrankedraw")
                                if not isinstance(current_owners, list):
                                    # cast to list because if there's only one element, it will be returned as a dict
                                    current_owners = [current_owners]
                                for email in owners:
                                    current_owners.append({
                                        "name": "n/a",
                                        "email": email,
                                        "source": "GCP project owner of service account",
                                        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                    })
                                demisto.executeCommand("setAlert", {"asmserviceownerunrankedraw": current_owners})
                            else:
                                demisto.info(f"No principals found with role `owner` on GCP project {project_name}")
        if found_owners:
            return_results(CommandResults(
                readable_output='Project owners of service accounts written to asmserviceownerunrankedraw'
            ))
        else:
            return_results(CommandResults(readable_output='No additional project owners found'))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GetProjectOwners. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
