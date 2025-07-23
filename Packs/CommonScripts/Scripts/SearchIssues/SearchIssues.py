from enum import Enum

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DEFAULT_LIMIT = 100
DEFAULT_PAGE_SIZE = 100
STARTING_PAGE_NUMBER = 1


class IssueSeverity(Enum):
    UNKNOWN = 0
    INFO = 0.5
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class IssueStatus(Enum):
    PENDING = 0
    ACTIVE = 1
    DONE = 2
    ARCHIVE = 3

    """
    1. Go over the script and check that all parts are relevant only for agentix (issues).
    2. Edit the .yml file to get the arguments and see if need to map them to the clinames for the query.
    3. check regarding the startdate end fromdate how to use.
    4. Check pagination.
    5. Sha256 expose only one argument and build the query with or's between all sha256 values.
    6. description and name with contain operator
    7. Think of argument names and if they will need mapping to cli name.
    
    """


query_filters = [
    "filesha256",
    "initiatorsha256",
    "filemacrosha256",
    "targetprocesssha256",
    "osparentsha256",
    "cgosha256",
    "domain",
    "severity",
    "details",
    "name",
    "categoryname",
    "type",
    "assetids",
    "status",
    "sourcebrand",
]

SHA256_FIELDS = ["filesha256", "initiatorsha256", "filemacrosha256", "targetprocesssha256", "osparentsha256", "cgosha256"]


FIELD_TO_MACHINE_NAME = {"category": "categoryname", "description": "details", "detectionmethod": "sourcebrand"}


def prepare_query(args: dict) -> str:
    """
    Prepares a query for list-based searches with safe handling.
    name and details should be with contains operator.
    not status should be -status.
    all the shas will be entered all the time to all of the types with OR's.
    Args:
        key (str): Field/attribute to search
        value (str/list): Value or list of values to match
    Returns:
        str: Formatted query string
    """
    query_sections = []

    # Special handling for sha256
    if "sha256" in args and args["sha256"]:
        sha256_values = argToList(args["sha256"])
        for sha in sha256_values:
            or_group = " OR ".join(f'{field}:"{sha.strip()}"' for field in SHA256_FIELDS)
            query_sections.append(f"({or_group})")

    for key, values in args.items():
        if key == "sha256":
            continue
        if not values:
            continue

        # Map field names to machine/query names
        machine_key = FIELD_TO_MACHINE_NAME.get(key.lower(), key)
        values_as_list = argToList(values)
        # Use contains/wildcard for name/details
        if machine_key in ["name", "details"]:
            if len(values_as_list) > 1:
                query = " OR ".join(f"{machine_key}:*{str(v).strip()}*" for v in values_as_list)
            else:
                query = f"{machine_key}:*{str(values_as_list[0]).strip()}*"

        # notstatus -> -status
        elif machine_key == "notstatus":
            if len(values_as_list) > 1:
                query = " AND ".join(f'-status:"{str(v).strip()}"' for v in values_as_list)
            else:
                query = f'-status:"{str(values_as_list[0]).strip()}"'
        else:
            if len(values_as_list) > 1:
                query = " OR ".join(f'{machine_key}:"{str(v).strip()}"' for v in values_as_list)
            else:
                query = f'{machine_key}:"{str(values_as_list[0]).strip()}"'
        query_sections.append(query)

    return " AND ".join(f"({qs})" for qs in query_sections) if query_sections else ""


def check_if_found_issue(res: list):
    if res and isinstance(res, list) and isinstance(res[0].get("Contents"), dict):
        if "data" not in res[0]["Contents"]:
            raise DemistoException(res[0].get("Contents"))
        elif res[0]["Contents"]["data"] is None:
            return False
        return True
    else:
        raise DemistoException(f"failed to get issues.\nGot: {res}")


def add_issue_link(data: list):
    server_url = "https://" + demisto.getLicenseCustomField("Http_Connector.url")
    for issue in data:
        issue_link = urljoin(server_url, f'issues?action:openAlertDetails={issue.get("id")}-investigation')
        issue["issueLink"] = issue_link
    return data


def transform_to_issue_data(issues: List): # todo verify customfields
    for issue in issues:
        issue["hostname"] = issue.get("CustomFields", {}).get("hostname")
        issue["initiatedby"] = issue.get("CustomFields", {}).get("initiatedby")
        issue["targetprocessname"] = issue.get("CustomFields", {}).get("targetprocessname")
        issue["username"] = issue.get("CustomFields", {}).get("username")
        issue["status"] = IssueStatus(issue.get("status")).name
        issue["severity"] = IssueSeverity(issue.get("severity")).name

    return issues

def search_issues(args: Dict):
    hr_prefix = ""

    args["query"] = prepare_query(args)
    if fromdate := arg_to_datetime(args.get("fromdate", None)):
        from_date = fromdate.isoformat()
        args["fromdate"] = from_date

    if todate := arg_to_datetime(args.get("todate")):
        to_date = todate.isoformat()
        args["todate"] = to_date

    if args.get("trimevents") == "0":
        args.pop("trimevents")

    res: list = execute_command("getIssues", args, extract_contents=False)

    issue_found: bool = check_if_found_issue(res)
    if not issue_found:
        if hr_prefix:
            hr_prefix = f"{hr_prefix}\n"
        return f"{hr_prefix}Issues not found.", {}, {}

    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    all_found_issues = res[0]["Contents"]["data"]
    demisto.debug(f"Amount of issues before filtering = {len(all_found_issues)} with args {args} before pagination")

    page_size = args.get("size") or DEFAULT_PAGE_SIZE
    more_pages = len(all_found_issues) == page_size
    all_found_issues = add_issue_link(all_found_issues)
    demisto.debug(f"Amount of issues after filtering = {len(all_found_issues)} before pagination")
    page = STARTING_PAGE_NUMBER

    if all_found_issues and "todate" not in args:
        # In case todate is not part of the arguments we add it to avoid duplications
        first_issue = all_found_issues[0]
        args["todate"] = first_issue.get("created")
        demisto.info(f"Setting todate argument to be {first_issue.get('created')} to avoid duplications")

    while more_pages and len(all_found_issues) < limit:
        args["page"] = page
        current_page_found_issues = execute_command("getIssues", args).get("data") or []

        # When current_page_found_issues is None it means the requested page was empty
        if not current_page_found_issues:
            break

        demisto.debug(f"before filtering {len(current_page_found_issues)=} {args=} {page=}")
        more_pages = len(current_page_found_issues) == page_size

        current_page_found_issues = add_issue_link(current_page_found_issues, args)
        demisto.debug(f"after filtering = {len(current_page_found_issues)=}")
        all_found_issues.extend(current_page_found_issues)
        page += 1

    all_found_issues = all_found_issues[:limit]

    additional_headers: List[str] = []

    headers: List[str]
    headers = ["id", "name", "severity", "status", "owner", "created", "closed", "issueLink"]
    all_found_issues = transform_to_issue_data(all_found_issues)
    md = tableToMarkdown(name="Issues found", t=all_found_issues, headers=headers + additional_headers, url_keys=["issueLink"])

    if hr_prefix:
        md = f"{hr_prefix}\n{md}"
    demisto.debug(f"amount of all the issues that were found {len(all_found_issues)}")

    return md, all_found_issues, res


def main():  # pragma: no cover
    args: Dict = demisto.args()
    try:
        readable_output, outputs, raw_response = search_issues(args)
        if search_results_label := args.get("searchresultslabel"):
            for output in outputs:
                output["searchResultsLabel"] = search_results_label
        results = CommandResults(
            outputs_prefix="foundIssues",
            outputs_key_field="id",
            readable_output=readable_output,
            outputs=outputs,
            raw_response=raw_response,
        )
        return_results(results)
    except DemistoException as error:
        return_error(str(error), error)


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
