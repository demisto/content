"""Main file for BitSightForSecurityPerformanceManagement Integration."""

from datetime import datetime

import demistomock as demisto  # noqa: F401
import requests
import urllib3
from CommonServerPython import *  # noqa: F401

"""CONSTANTS"""
BITSIGHT_DATE_TIME_FORMAT = "%Y-%m-%d"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
DEFAULT_FIRST_FETCH_DAYS = 3
DEFAULT_FETCH_LIMIT = 25
MAX_FETCH_LIMIT = 200
BASE_URL = "https://api.bitsighttech.com"
MAX_LIMIT = 1000
DEFAULT_LIMIT = 100
DEFAULT_OFFSET = 0
MAX_FINDINGS_MIRRORING_LIMIT = 5000
OUTGOING_MIRROR_DIRECTION = "outgoing"
INCOMING_AND_OUTGOING_MIRROR_DIRECTION = "incoming and outgoing"
DEFAULT_CLOSE_STATUS_OF_BITSIGHT = "Resolved"
DEFAULT_OPEN_STATUS_OF_BITSIGHT = "Open"

ERROR_MESSAGES = {
    "GUID_REQUIRED": "Must provide a GUID.",
    "GUID_NOT_FETCHED": "Unable to fetch GUID.",
    "GUID_NOT_AVAILABLE": "Provided 'Company's GUID' is not available/valid."
    ' Please input a GUID retrieved using the command "bitsight-companies-guid-get".',
    "INVALID_SELECT": "'{}' is an invalid value for '{}'. Value must be in {}.",
    "INVALID_MAX_FETCH": f"Parameter 'Max Fetch' is not a valid number. Please provide a number in range 1 to {MAX_FETCH_LIMIT}.",
    "NEGATIVE_FIRST_FETCH": "Parameter 'First fetch time in days' should be a number greater than or equal to 0.",
    "LIMIT_GREATER_THAN_ALLOWED": f"Argument 'limit' should be a number less than or equal to {MAX_LIMIT}.",
    "USER_EMAIL_REQUIRED": "User email address is required for outgoing mirroring.",
    "USER_GUID_NOT_FOUND": "User GUID not found for the provided user email.",
}

SEVERITY_MAPPING = {"minor": 1, "moderate": 4, "material": 7, "severe": 9}

ASSET_CATEGORY_MAPPING = {
    "low": "low,medium,high,critical",
    "medium": "medium,high,critical",
    "high": "high,critical",
    "critical": "critical",
}

VALID_AFFECT_RATING_REASON = ["Yes", "No: Grace Period", "No: Incubation Period"]
AFFECT_RATING_REASON_MAPPING = {
    "yes": "AFFECTS_RATING",
    "no: grace period": "GRACE_PERIOD",
    "no: incubation period": "INCUBATION_PERIOD",
}

RISK_VECTOR_MAPPING = {
    "web application headers": "application_security",
    "botnet infections": "botnet_infections",
    "breaches": "data_breaches",
    "desktop software": "desktop_software",
    "dkim": "dkim",
    "dnssec": "dnssec",
    "file sharing": "file_sharing",
    "insecure systems": "insecure_systems",
    "malware servers": "malware_servers",
    "mobile app publications": "mobile_app_publications",
    "mobile application security": "mobile_application_security",
    "mobile software": "mobile_software",
    "open ports": "open_ports",
    "patching cadence": "patching_cadence",
    "potentially exploited": "potentially_exploited",
    "server software": "server_software",
    "spam propagation": "spam_propagation",
    "spf": "SPF",
    "ssl certificates": "ssl_certificates",
    "ssl configurations": "ssl_configurations",
    "unsolicited communications": "unsolicited_comm",
    "web application security": "web_appsec",
    "dmarc": "dmarc",
}
MIRROR_DIRECTION = {
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}

PACK_VERSION = get_pack_version() or "1.3.0"
CALLING_PLATFORM_VERSION = "XSOAR"
CONNECTOR_NAME_VERSION = f"Bitsight - {PACK_VERSION}"
# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """Client will implement the service API, should not contain Cortex XSOAR logic. \
    Should do requests and return data."""

    def get_companies_guid(self):
        """Retrieve subscribed company details."""
        uri = "v1/companies"
        return self._http_request(method="GET", url_suffix=uri)

    def get_company_detail(self, guid):
        """
        Retrieve company details based on its Guid.

        :param guid: guid of the company whose details need to be retrieved
        """
        uri = f"v1/companies/{encode_string_results(guid)}"
        return self._http_request(method="GET", url_suffix=uri)

    def get_company_findings(self, guid, first_seen, last_seen, optional_params=None):
        """
        Retrieve company findings based on its Guid.

        :param guid: guid of the company whose findings need to be retrieved
        :param first_seen: first seen date (YYYY-MM-DD) of the findings
        :param last_seen: last seen date (YYYY-MM-DD) of the findings
        :param optional_params: params to be passed to the findings endpoint
        """
        uri = f"v1/companies/{encode_string_results(guid)}/findings"

        params = {"first_seen_gte": first_seen, "last_seen_lte": last_seen, "unsampled": "true", "expand": "attributed_companies"}
        if optional_params:
            params.update(optional_params)
        remove_nulls_from_dictionary(params)

        return self._http_request(method="GET", url_suffix=uri, params=params)

    def get_finding_comments(self, company_guid, rolledup_observation_id):
        """
        Retrieve finding comments based on its Guid.

        :param company_guid: guid of the company whose comments need to be retrieved
        :param rolledup_observation_id: rolledup_observation_id of the finding
        """
        encoded_company_guid = encode_string_results(company_guid)
        encoded_rolledup_observation_id = encode_string_results(rolledup_observation_id)
        uri = f"ratings/v1/companies/{encoded_company_guid}/findings/{encoded_rolledup_observation_id}/comments"
        return self._http_request(method="GET", url_suffix=uri)

    def get_remediations(self, params=None):
        """
        Retrieve remediations.

        :param params: params to be passed to the remediations endpoint
        """
        uri = "ratings/v1/remediations"
        remove_nulls_from_dictionary(params)
        return self._http_request(method="GET", url_suffix=uri, params=params)

    def update_external_status(self, company_guid, body):
        """
        Update external status of a finding.

        :param company_guid: guid of the company whose findings need to be updated
        :param body: body to be passed to the findings endpoint
        """
        uri = f"ratings/v1/remediations/{encode_string_results(company_guid)}"
        remove_nulls_from_dictionary(body)
        return self._http_request(method="PATCH", url_suffix=uri, json_data=body)

    def create_finding_comment(self, company_guid: str, rolledup_observation_id: str, thread_guid: str, body: dict):
        """
        Create a finding comment based on its Guid.

        :param company_guid: guid of the company whose comments need to be retrieved
        :param rolledup_observation_id: rolledup_observation_id of the finding
        :param thread_guid: thread_guid of the finding
        :param body: body to be passed to the findings endpoint
        """
        encoded_company_guid = encode_string_results(company_guid)
        encoded_rolledup_observation_id = encode_string_results(rolledup_observation_id)
        encoded_thread_guid = encode_string_results(thread_guid)

        if thread_guid:
            uri = f"annotations/v1/threads/{encoded_thread_guid}/comments"
            return self._http_request(method="POST", url_suffix=uri, json_data=body, ok_codes=[200, 201])
        else:
            params = {"company_guid": encoded_company_guid, "record_id": encoded_rolledup_observation_id}
            uri = "annotations/v1/threads"
            return self._http_request(method="POST", url_suffix=uri, params=params, json_data=body, ok_codes=[200, 201])

    def get_users(self, params=None):
        """
        Retrieve user details from BitSight platform.

        :param params: Optional parameters to be passed to the users endpoint
        :return: Response containing user details
        """
        uri = "ratings/v2/users"

        remove_nulls_from_dictionary(params)
        return self._http_request(method="GET", url_suffix=uri, params=params)


"""HELPER FUNCTIONS"""


def trim_spaces_from_args(args):
    """
    Trim spaces from values of the args dict.

    :param args: Dict to trim spaces from
    :type args: dict
    :return:
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def camelize_strings_with_underscore(string: str):
    """
    Wrap CommonServerPython's camelize_string to also convert Pascal strings.

    :param string: string to convert to camel case
    """
    if string.find("_") == -1:
        return string[0].lower() + string[1:]
    else:
        return camelize_string(string, upper_camel=False)


def camelize_dict_recursively(src):
    """
    Camelize all the keys in a dictionary with nested dictionaries and lists.

    :param src: the dictionary to camelize
    """
    destination = {}
    for key, value in src.items():
        if isinstance(value, dict):
            destination[camelize_strings_with_underscore(key)] = camelize_dict_recursively(value)
        elif isinstance(value, list):
            if value and isinstance(value[0], dict):
                destination[camelize_strings_with_underscore(key)] = [
                    camelize_dict_recursively(list_value) for list_value in value
                ]
            else:
                destination[camelize_strings_with_underscore(key)] = value
        else:
            destination[camelize_strings_with_underscore(key)] = value
    return destination


def get_mirroring():
    """
    Get the mirroring configuration parameters from the Demisto integration parameters.

    :return: A dictionary containing the mirroring configuration parameters.
    :rtype: dict
    """
    params = demisto.params()
    mirror_direction = params.get("mirror_direction", "None").strip()
    mirror_tags = params.get("note_tag", "").strip()
    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_tags": mirror_tags,
        "mirror_instance": demisto.integrationInstance(),
    }


def prepare_and_validate_company_findings_get_filter_args(risk_vector_list, severity, asset_category):
    """
    Prepare and validate arguments for bitsight-company-findings-get.

    :param risk_vector_list: input from argument risk_vector_label
    :param severity: input from argument severity
    :param asset_category: input from argument asset_category
    """
    risk_vector = ""
    for vector in risk_vector_list:
        if vector.lower() in RISK_VECTOR_MAPPING:
            risk_vector += RISK_VECTOR_MAPPING[vector.lower()] + ","
        else:
            raise ValueError(
                ERROR_MESSAGES["INVALID_SELECT"].format(
                    vector.lower(), "risk_vector_label", ", ".join(RISK_VECTOR_MAPPING.keys())
                )
            )

    risk_vector = risk_vector[:-1]

    severity_gte = None
    if severity:
        if severity in SEVERITY_MAPPING:
            severity_gte = SEVERITY_MAPPING[severity]
        else:
            raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(severity, "severity", ", ".join(SEVERITY_MAPPING.keys())))

    asset_category_eq = None
    if asset_category:
        if asset_category in ASSET_CATEGORY_MAPPING:
            asset_category_eq = ASSET_CATEGORY_MAPPING[asset_category]
        else:
            raise ValueError(
                ERROR_MESSAGES["INVALID_SELECT"].format(
                    asset_category, "asset_category", ", ".join(ASSET_CATEGORY_MAPPING.keys())
                )
            )
    return risk_vector, severity_gte, asset_category_eq


def prepare_and_validate_fetch_findings_args(client, args):
    """
    Prepare and validate arguments for company_findings_get_command when fetch_incidents is true.

    :param client: client to use
    :param args: arguments obtained from demisto.args()
    """
    guid = args.get("guid", None)
    if not guid:
        res = client.get_companies_guid()
        if res.status_code == 200:
            res_json = res.json()
            guid = res_json.get("my_company", {}).get("guid")
        else:
            raise DemistoException(ERROR_MESSAGES["GUID_NOT_FETCHED"])
    severity = args.get("findings_min_severity", None)
    if severity:
        severity = severity.lower()
    grade_list = args.get("findings_grade", None)
    grade = ",".join(grade_list) if grade_list else None
    asset_category = args.get("findings_min_asset_category", None)
    if asset_category:
        asset_category = asset_category.lower()
    risk_vector_list = argToList(args.get("risk_vector"))
    if "All" in risk_vector_list:
        risk_vector_list = []
    limit = arg_to_number(args.get("max_fetch", DEFAULT_FETCH_LIMIT), "Max Fetch", True)
    if limit and (limit < 1 or limit > MAX_FETCH_LIMIT):  # type: ignore
        raise ValueError(ERROR_MESSAGES["INVALID_MAX_FETCH"])

    affect_rating_reason_list = argToList(args.get("findings_affect_rating_reason", ""))
    valid_affect_rating_reasons = []
    for affect_rating_reason in affect_rating_reason_list:
        affect_rating_reason = affect_rating_reason.strip()
        if affect_rating_reason and affect_rating_reason.lower() not in AFFECT_RATING_REASON_MAPPING:
            raise ValueError(
                ERROR_MESSAGES["INVALID_SELECT"].format(
                    affect_rating_reason, "Findings Affect Rating Reason", ", ".join(VALID_AFFECT_RATING_REASON)
                )
            )

        if affect_rating_reason:
            valid_affect_rating_reasons.append(AFFECT_RATING_REASON_MAPPING.get(affect_rating_reason.lower()))

    valid_affect_rating_reasons: list = list(set(valid_affect_rating_reasons))
    affect_rating_reason = ",".join(valid_affect_rating_reasons)

    return guid, severity, grade, asset_category, risk_vector_list, limit, affect_rating_reason


def close_in_xsoar(entries: list, rolledup_observation_id: str, remidiation_status: str):
    """
    Close the XSOAR incident for the given finding.

    :type entries: list
    :param entries: List of entries where the closing entry will be appended.
    :type rolledup_observation_id: str
    :param rolledup_observation_id: The rolledup observation ID.
    :type remidiation_status: str
    :param remidiation_status: The BitSight remediation status that triggered the closure.
    """
    demisto.debug(
        f"Closing XSOAR incident for BitSight finding {rolledup_observation_id} via Incoming Mirroring. "
        f"Due to remediation status: {remidiation_status} is same as configured close status."
    )
    entries.append(
        {
            "Type": EntryType.NOTE,
            "Contents": {
                "dbotIncidentClose": True,
                "closeReason": "Other",
                "closeNotes": f"Incident closed because BitSight finding remediation status '{remidiation_status}' "
                "matches the configured close status.",
            },
            "ContentsFormat": EntryFormat.JSON,
        }
    )


def reopen_in_xsoar(entries: list, rolledup_observation_id: str, remidiation_status: str):
    """
    Reopen the XSOAR incident for the given finding.

    :type entries: list
    :param entries: List of entries where the reopening entry will be appended.
    :type rolledup_observation_id: str
    :param rolledup_observation_id: The rolledup observation ID.
    :type remidiation_status: str
    :param remidiation_status: The BitSight remediation status that triggered the reopen.
    """
    demisto.debug(
        f"Reopening XSOAR incident for BitSight finding {rolledup_observation_id}. "
        f"Due to remediation status: {remidiation_status} is same as configured open status."
    )
    entries.append({"Type": EntryType.NOTE, "Contents": {"dbotIncidentReopen": True}, "ContentsFormat": EntryFormat.JSON})


def add_comments_to_finding(
    client: Client, company_guid: str, rolledup_observation_id: str, user_guid: Any, comments_to_add: list[dict]
):
    """
    Add comments to a BitSight finding. Handles thread creation and comment addition.

    :type client: Client
    :param client: BitSight API client instance

    :type company_guid: str
    :param company_guid: GUID of the company

    :type rolledup_observation_id: str
    :param rolledup_observation_id: Rolled up observation ID of the finding

    :type user_guid: Any
    :param user_guid: GUID of the user adding comments

    :type comments_to_add: list[dict]
    :param comments_to_add: List of comment dictionaries with 'message' key

    :return: None
    """
    if not user_guid:
        demisto.debug("Skipping the comment(s) because User GUID is not found.")
        return
    # Fetch existing comments to check if thread exists
    comments_response = client.get_finding_comments(company_guid=company_guid, rolledup_observation_id=rolledup_observation_id)
    existing_comments = comments_response.get("results", [])
    thread_guid = ""

    if existing_comments and isinstance(existing_comments, list):
        demisto.debug(f"Found {len(existing_comments)} existing comments for finding {rolledup_observation_id}.")
        thread_guid = existing_comments[0].get("thread_guid", "")

    # If thread exists, add comments individually; otherwise, batch create
    if thread_guid:
        # Add each comment to the existing thread
        for comment_data in comments_to_add:
            comment_info = {"author_guid": user_guid, "message": comment_data.get("message", ""), "public": False}
            client.create_finding_comment(
                company_guid=company_guid,
                rolledup_observation_id=rolledup_observation_id,
                thread_guid=thread_guid,
                body=comment_info,
            )
    else:
        # Create new thread with all comments
        new_comments = [
            {"author_guid": user_guid, "message": comment.get("message", ""), "public": False} for comment in comments_to_add
        ]
        comments_body = {"comments": new_comments}
        client.create_finding_comment(
            company_guid=company_guid,
            rolledup_observation_id=rolledup_observation_id,
            thread_guid=thread_guid,
            body=comments_body,
        )


"""COMMAND FUNCTIONS"""


def fetch_incidents(client, last_run, params):
    """
    Fetch Bitsight Findings.

    :param client: client to use
    :param last_run: last run object obtained from demisto.getLastRun()
    :param params: arguments obtained from demisto.params()
    """
    events = []
    try:
        if "offset" in last_run:
            params["offset"] = last_run["offset"]
            last_run_date = last_run["first_fetch"]
        else:
            first_fetch = arg_to_number(params.get("first_fetch", DEFAULT_FIRST_FETCH_DAYS), "First fetch time in days", True)
            if first_fetch < 0:  # type: ignore
                raise ValueError(ERROR_MESSAGES["NEGATIVE_FIRST_FETCH"])
            today = datetime.now()
            last_run_date = (today - timedelta(days=first_fetch)).strftime(BITSIGHT_DATE_TIME_FORMAT)  # type: ignore

        already_fetched_findings = last_run.get("already_fetched_findings") or []
        report_entries = []
        findings_res = company_findings_get_command(client, params, last_run_date, True)
        report_entries.extend(findings_res.get("results", []))

        duplicate_findings = []
        ingested_findings = []

        for entry in report_entries:
            key_field = entry.get("rolledup_observation_id", "") + "-#-" + entry.get("first_seen", "")
            if key_field in already_fetched_findings:
                duplicate_findings.append(key_field)
                continue

            # Updating mirroring fields
            mirroring_fields = get_mirroring()
            mirroring_fields.update({"mirror_id": key_field})
            entry.update(mirroring_fields)

            incident_name = "Bitsight Finding"

            risk_vector_label = entry.get("risk_vector_label", "")
            evidence_key = entry.get("evidence_key", "")
            rollup_start_date = entry.get("details", {}).get("rollup_start_date", "")

            incident_detail_name = " - ".join([x for x in [risk_vector_label, evidence_key, rollup_start_date] if x])
            if incident_detail_name:
                incident_name += " - " + incident_detail_name

            # Set the Raw JSON to the event. Mapping will be done at the classification and mapping
            event = {
                "name": incident_name,
                "occurred": entry.get("first_seen") + "T00:00:00Z",
                "rawJSON": json.dumps(entry),
            }
            events.append(event)
            ingested_findings.append(key_field)
            already_fetched_findings.append(key_field)

        demisto.debug(f"Skipped {len(duplicate_findings)} duplicate findings: {duplicate_findings}")
        demisto.debug(f"Fetched {len(ingested_findings)} findings: {ingested_findings}")
        last_run = {
            "first_fetch": last_run_date,
            "offset": params["offset"] + len(report_entries) if params.get("offset") else len(report_entries),
        }
        demisto.debug(
            f"Updated the last run state - first fetch : {last_run.get('first_fetch')}, offset: {last_run.get('offset')}"
        )
        last_run.update({"already_fetched_findings": already_fetched_findings})

    except Exception as e:
        demisto.error("Failed to fetch events.")
        raise e

    return last_run, events


def test_module(client, params):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. \
    Connection to the service is successful. Anything else will fail the test.

    :param client: client to use
    :param params: parameters obtained from demisto.params()
    """
    res = client.get_companies_guid()
    mirror_direction = params.get("mirror_direction", "")

    if mirror_direction.lower() in [OUTGOING_MIRROR_DIRECTION, INCOMING_AND_OUTGOING_MIRROR_DIRECTION]:
        user_email = params.get("user_email", "").strip()
        if not user_email:
            raise ValueError(ERROR_MESSAGES["USER_EMAIL_REQUIRED"])
        user_guid = get_current_user_guid(client, user_email, True)
        if not user_guid:
            raise ValueError(ERROR_MESSAGES["USER_GUID_NOT_FOUND"])

    if params.get("isFetch", False):
        available_guids = {c["guid"] for c in res["companies"]}
        requested_guid = params.get("guid")

        if not requested_guid:
            raise ValueError(ERROR_MESSAGES["GUID_REQUIRED"])

        if requested_guid not in available_guids:
            raise ValueError(ERROR_MESSAGES["GUID_NOT_AVAILABLE"])
        fetch_incidents(client, {}, params)
    return "ok"


def companies_guid_get_command(client, *args):
    """
    Retrieve subscribed company details.

    :param client: client to use
    """
    res_json = client.get_companies_guid()
    outputs = camelize_dict_recursively(remove_empty_elements(res_json))
    context_output = {
        "BitSight.Company(val.guid == obj.guid)": outputs.get("companies", []),
        "BitSight.MyCompany(val.guid == obj.guid)": outputs.get("myCompany", {}),
    }
    hr = []
    companies_list = outputs.get("companies", [])
    for company in companies_list:
        hr.append(
            {
                "Company Name": company.get("name"),
                "Company Short Name": company.get("shortname"),
                "GUID": company.get("guid"),
                "Rating": company.get("rating"),
            }
        )

    readable_output = tableToMarkdown(
        name="Companies:",
        metadata=f"My Company: {outputs.get('myCompany', {}).get('guid')}",
        t=hr,
        headers=["Company Name", "Company Short Name", "GUID", "Rating"],
        removeNull=True,
    )

    return CommandResults(readable_output=readable_output, outputs=context_output, raw_response=outputs)


def company_details_get_command(client, args):
    """
    Retrieve company details based on its Guid.

    :param client: client to use
    :param args: arguments obtained from demisto.args()
    """
    guid = args.get("guid")
    res_json = client.get_company_detail(guid)

    outputs = camelize_dict_recursively(remove_empty_elements(res_json))

    outputs["ratingDetails"] = [value for _, value in outputs.get("ratingDetails", {}).items()]

    company_info = {
        "guid": res_json.get("guid"),
        "customId": res_json.get("custom_id"),
        "name": res_json.get("name"),
        "description": res_json.get("description"),
        "ipv4Count": res_json.get("ipv4_count"),
        "peopleCount": res_json.get("people_count"),
        "shortName": res_json.get("shortname"),
        "industry": res_json.get("industry"),
        "industrySlug": res_json.get("industry_slug"),
        "subIndustry": res_json.get("sub_industry"),
        "subIndustrySlug": res_json.get("sub_industry_slug"),
        "homePage": res_json.get("homepage"),
        "primaryDomain": res_json.get("primary_domain"),
        "type": res_json.get("type"),
        "displayURL": res_json.get("display_url"),
    }
    ratings = []
    for rating in res_json.get("ratings", []):
        rating_dict = {"rating": rating.get("rating"), "rating_date": rating.get("rating_date"), "range": rating.get("range")}
        ratings.append(rating_dict)

    rating_details = []
    for rating_detail_key in res_json.get("rating_details", {}):
        rating_detail = res_json.get("rating_details", {}).get(rating_detail_key, {})
        rating_detail_dict = {
            "name": rating_detail.get("name"),
            "rating": rating_detail.get("rating"),
            "percentile": rating_detail.get("percentile"),
            "display_url": rating_detail.get("display_url"),
        }
        rating_details.append(rating_detail_dict)

    readable = {"Company Info": company_info, "Ratings": ratings, "Rating Details": rating_details}

    readable_output = tableToMarkdown(
        name="Company Details:", t=readable, headers=["Company Info", "Ratings", "Rating Details"], removeNull=True
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="BitSight.Company",
        outputs=outputs,
        outputs_key_field="guid",
        raw_response=res_json,
    )


def company_findings_get_command(client, args, first_seen=None, fetch_incidents=False):
    """
    Retrieve company findings based on its Guid.

    :param client: client to use
    :param args: arguments obtained from demisto.args()
    :param first_seen: first seen of the finding
    :param fetch_incidents: whether the command is called from fetch_incidents
    """
    last_seen = None
    affect_rating_reason = ""
    if fetch_incidents:
        guid, severity, grade, asset_category, risk_vector_list, limit, affect_rating_reason = (
            prepare_and_validate_fetch_findings_args(client, args)
        )
        offset = arg_to_number(args.get("offset", DEFAULT_OFFSET), "offset")
    else:
        guid = args.get("guid")
        severity = args.get("severity", None)
        grade = args.get("grade", None)
        asset_category = args.get("asset_category", None)
        limit = arg_to_number(args.get("limit", DEFAULT_LIMIT), "limit")
        if limit and limit > MAX_LIMIT:  # type: ignore
            raise ValueError(ERROR_MESSAGES["LIMIT_GREATER_THAN_ALLOWED"])
        offset = arg_to_number(args.get("offset", DEFAULT_OFFSET), "offset")
        if severity:
            severity = severity.lower()
        if grade:
            grade = grade.upper()
        if asset_category:
            asset_category = asset_category.lower()
        risk_vector_list = argToList(args.get("risk_vector_label", []))
        first_seen = args.get("first_seen")
        last_seen = args.get("last_seen")

    risk_vector, severity_gte, asset_category_eq = prepare_and_validate_company_findings_get_filter_args(
        risk_vector_list, severity, asset_category
    )
    res_json = client.get_company_findings(
        guid,
        first_seen,
        last_seen,
        {
            "severity_gte": severity_gte,
            "details.grade": grade,
            "assets.category": asset_category_eq,
            "risk_vector": risk_vector,
            "limit": limit,
            "offset": offset,
            "impacts_risk_vector_details": affect_rating_reason,
        },
    )

    if fetch_incidents:
        return res_json
    res_json_cleaned = camelize_dict_recursively(remove_empty_elements(res_json))
    readable_list = []
    outputs = None
    if res_json_cleaned.get("results", []):
        for finding in res_json_cleaned.get("results", []):
            readable = {
                "Evidence Key": finding.get("evidenceKey"),
                "Risk Vector Label": finding.get("riskVectorLabel"),
                "First Seen": finding.get("firstSeen"),
                "Last Seen": finding.get("lastSeen"),
                "ID": finding.get("temporaryId"),
                "Risk Category": finding.get("riskCategory"),
                "Severity": finding.get("severityCategory"),
                "Asset Category": "\n".join(
                    [f"{asset.get('asset')}: {asset.get('category', '').title()}" for asset in finding.get("assets", [])]
                ),
                "Finding Grade": finding.get("details", {}).get("grade", "").title(),
            }
            readable_list.append(readable)
        outputs = {
            "BitSight.Company(val.guid == obj.guid)": {
                "guid": guid.lower(),
                "CompanyFinding": res_json_cleaned.get("results", []),
            },
            "BitSight.Page(val.name == obj.name)": {
                "name": "bitsight-company-findings-get",
                "next": res_json_cleaned.get("links", {}).get("next"),
                "previous": res_json_cleaned.get("links", {}).get("previous"),
                "count": res_json_cleaned.get("count"),
            },
        }

    readable_output = tableToMarkdown(
        name="Company findings:",
        t=readable_list,
        metadata=f"Total Findings: {res_json_cleaned.get('count')}",
        headers=[
            "Evidence Key",
            "Risk Vector Label",
            "First Seen",
            "Last Seen",
            "ID",
            "Risk Category",
            "Severity",
            "Asset Category",
            "Finding Grade",
        ],
        removeNull=True,
    )
    return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=res_json)


def get_current_user_guid(client: Client, user_email: str, is_test: bool = False):
    """
    Get the GUID of the current user based on their email.

    :param client: client to use
    :param user_email: Email address of the user
    :return: GUID of the user
    """
    integration_context = demisto.getIntegrationContext()
    users_guids = integration_context.get("users_guids", {})

    if user_email in users_guids and not is_test:
        return users_guids[user_email]

    user_guid = None
    user_info = client.get_users(params={"email": user_email})
    if user_info.get("results") and isinstance(user_info["results"], list):
        user_guid = user_info["results"][0].get("guid")
        users_guids[user_email] = user_guid

    integration_context["users_guids"] = users_guids
    demisto.setIntegrationContext(integration_context)
    return user_guid


def get_modified_remote_data_command(client: Client, args: Dict) -> GetModifiedRemoteDataResponse:
    """
    Get modified findings from the BitSight platform and prepare it for mirroring.

    :type client: Client
    :param client: client to use

    :type args: Dict[str, str]
    :param args: arguments obtained from demisto.args()

    :return: GetModifiedRemoteDataResponse with list of modified incident IDs
    :rtype: GetModifiedRemoteDataResponse
    """
    company_guid = args.get("guid", "")

    command_args = GetModifiedRemoteDataArgs(args)
    command_last_run_date = dateparser.parse(
        command_args.last_update,  # type: ignore
        settings={"TIMEZONE": "UTC"},  # type: ignore
    )
    command_last_run_date_time = command_last_run_date.strftime(DATE_FORMAT)  # type: ignore
    demisto.debug(f"Last update date of get-modified-remote-data command is {command_last_run_date_time}.")

    last_update_date = command_last_run_date.strftime(BITSIGHT_DATE_TIME_FORMAT)  # type: ignore

    optional_params = {
        "limit": MAX_FINDINGS_MIRRORING_LIMIT,
        "sort": "-last_seen",
        "last_remediation_status_date_gte": last_update_date,
    }
    # Fetch the findings modified since the last update.
    response = client.get_company_findings(guid=company_guid, first_seen=None, last_seen=None, optional_params=optional_params)

    modified_findings_ids = []
    findings = response.get("results", [])
    for finding in findings:
        rolledup_observation_id = finding.get("rolledup_observation_id")
        first_seen = finding.get("first_seen")
        key_field = f"{rolledup_observation_id}-#-{first_seen}"

        modified_findings_ids.append(key_field)

    modified_findings_ids: List[str] = list(filter(None, modified_findings_ids))  # type: ignore
    demisto.debug(
        f"Performing get-modified-remote-data command. Numbers Findings IDs to update in XSOAR: {len(modified_findings_ids)}"
    )
    demisto.debug(f"Performing get-modified-remote-data command. Findings IDs to update in XSOAR: {modified_findings_ids}")
    # Filter out duplicate findings IDs.
    unique_findings_ids = list(set(modified_findings_ids))

    return GetModifiedRemoteDataResponse(modified_incident_ids=unique_findings_ids)


def get_remote_data_command(client: Client, args: Dict) -> GetRemoteDataResponse:
    """
    Get remote data for a specific finding from the BitSight platform for mirroring.

    :type client: Client
    :param client: client to use

    :type args: Dict[str, str]
    :param args: arguments obtained from demisto.args()

    :return: GetRemoteDataResponse with finding data and new entries
    :rtype: GetRemoteDataResponse
    """
    new_entries_to_return: list = []

    dbot_mirror_id: str = args.get("id")  # type: ignore
    demisto.debug(f"dbot_mirror_id:{dbot_mirror_id}")

    dbot_mirror_id_parts = dbot_mirror_id.split("-#-")
    finding_rolledup_observation_id: str = dbot_mirror_id_parts[0] if len(dbot_mirror_id_parts) > 0 else ""
    first_seen: str = dbot_mirror_id_parts[1] if len(dbot_mirror_id_parts) > 1 else ""
    demisto.debug(f"Bitsight finding with rolledup_observation_id:{finding_rolledup_observation_id}")
    demisto.debug(f"Getting update for remote {finding_rolledup_observation_id}.")

    command_last_run_dt = arg_to_datetime(args.get("lastUpdate"), arg_name="lastUpdate", required=True)
    command_last_run_timestamp = command_last_run_dt.strftime(DATE_FORMAT)  # type: ignore
    demisto.debug(
        f"The time when the last time get-remote-data command is called for current incident is {command_last_run_timestamp}."
    )
    integration_params = demisto.params()
    close_status_of_bitsight = integration_params.get("close_status_of_bitsight") or DEFAULT_CLOSE_STATUS_OF_BITSIGHT
    open_status_of_bitsight = integration_params.get("open_status_of_bitsight") or DEFAULT_OPEN_STATUS_OF_BITSIGHT
    close_active_incident = integration_params.get("close_active_incident", False)
    reopen_closed_incident = integration_params.get("reopen_closed_incident", False)

    company_guid = args.get("guid", "")
    params = {
        "rolledup_observation_id": finding_rolledup_observation_id,
        "first_seen": first_seen,
        "sort": "-last_seen",
    }

    # Fetch the findings modified since the last update.
    remote_incident_data = client.get_company_findings(guid=company_guid, first_seen=None, last_seen=None, optional_params=params)

    findings = remote_incident_data.get("results", [])
    finding = {}
    for f in findings:
        if f.get("affects_rating", ""):
            finding = f
            break

    # Handle the scenario where all findings have affects_rating as false
    if not finding:
        finding = findings[0] if findings else {}
    if not finding:
        return GetRemoteDataResponse({}, [])

    params = {
        "company_guid": company_guid,
        "rolledup_observation_id": finding_rolledup_observation_id,
        "evidence_key": finding.get("evidence_key", ""),
        "risk_vector": finding.get("risk_vector", ""),
    }
    integration_context = demisto.getIntegrationContext()
    processed_findings = integration_context.get("processed_findings") or []
    try:
        remidiations_response = client.get_remediations(params=params)
        remidiations = remidiations_response.get("results")
        remidiation_status = ""
        if remidiations:
            remidiation_status = remidiations[0].get("status", {}).get("value", "")
            finding.update({"remediation_status": remidiation_status})

        if remidiation_status == close_status_of_bitsight and dbot_mirror_id in processed_findings and close_active_incident:
            close_in_xsoar(new_entries_to_return, finding_rolledup_observation_id, remidiation_status)
            processed_findings.remove(dbot_mirror_id)
            demisto.debug(f"Removed {dbot_mirror_id} finding from processed findings.")
        elif (
            remidiation_status == open_status_of_bitsight and dbot_mirror_id not in processed_findings and reopen_closed_incident
        ):
            reopen_in_xsoar(new_entries_to_return, finding_rolledup_observation_id, remidiation_status)
            processed_findings.append(dbot_mirror_id)
            demisto.debug(f"Added {dbot_mirror_id} finding to processed findings.")
    except DemistoException as e:
        demisto.debug(
            f"Failed to fetch remediation status for finding {finding_rolledup_observation_id}: {str(e)}. "
            "Continuing without remediation data."
        )

    try:
        comments = client.get_finding_comments(company_guid=company_guid, rolledup_observation_id=finding_rolledup_observation_id)
        comments = comments.get("results")
    except DemistoException as e:
        demisto.debug(
            f"Failed to fetch comments for finding {finding_rolledup_observation_id}: {str(e)}. Continuing without comments data."
        )
        comments = None
    if comments:
        for comment in comments:
            if "[Mirrored From XSOAR]" in comment.get("message"):
                demisto.debug(f"Skipping the comment {comment.get('guid')} as it is mirrored from XSOAR.")
                continue

            comment_created_time = arg_to_datetime(comment.get("created_time"))
            comment_updated_time = arg_to_datetime(comment.get("last_update_time"))
            if comment_updated_time:
                if comment_updated_time <= command_last_run_dt:  # type: ignore
                    demisto.debug(
                        f"Skipping comment {comment.get('guid')} - updated time {comment_updated_time} is "
                        f"before sync timestamp {command_last_run_dt}."
                    )
                    continue
            else:
                if comment_created_time <= command_last_run_dt:  # type: ignore
                    demisto.debug(
                        f"Skipping the comment {comment.get('guid')} - created time {comment_created_time} is "
                        f"before sync timestamp {command_last_run_dt}."
                    )
                    continue
            new_entries_to_return.append(
                {
                    "Type": EntryType.NOTE,
                    "Contents": f"[Mirrored From Bitsight]\n"
                    f"Added By: {comment.get('author', {}).get('name', '')}\n"
                    f"Added At: {comment_created_time} UTC\n"
                    f"Note: {comment.get('message')}",
                    "ContentsFormat": EntryFormat.TEXT,
                    "Note": True,
                }
            )
    demisto.debug(f"remote_incident_data_finding:{finding}")

    processed_findings = processed_findings[-MAX_FINDINGS_MIRRORING_LIMIT:]
    integration_context["processed_findings"] = processed_findings
    demisto.setIntegrationContext(integration_context)

    return GetRemoteDataResponse(finding, new_entries_to_return)


def update_remote_system_command(client: Client, args: Dict, close_status_of_bitsight: str, open_status_of_bitsight: str) -> str:
    """
    Update the remote system with the provided data.

    :type client: Client
    :param client: client to use.

    :type args: Dict[str, str]
    :param args: arguments obtained from demisto.args()

    :type close_status_of_bitsight: str
    :param close_status_of_bitsight: Remediation status value for closing findings

    :type open_status_of_bitsight: str
    :param open_status_of_bitsight: Remediation status value for opening findings

    :return: remote incident ID
    :rtype: str
    """
    company_guid = args.get("guid", "")
    user_email = args.get("user_email", "").strip()
    user_guid = None
    if user_email:
        user_guid = get_current_user_guid(client, user_email)
    else:
        demisto.debug(ERROR_MESSAGES["USER_EMAIL_REQUIRED"])
    parsed_args = UpdateRemoteSystemArgs(args)

    # Get remote incident ID
    remote_incident_id = parsed_args.remote_incident_id

    rolledup_observation_id = parsed_args.data.get("bitsightrolledupobservationid", "")
    risk_vector = parsed_args.data.get("bitsightriskvector", "")
    evidence_key = parsed_args.data.get("bitsightevidencekey", "")

    incident_status = parsed_args.inc_status
    delta = parsed_args.delta
    xsoar_incident_id = parsed_args.data.get("id", "")
    new_entries = parsed_args.entries or []
    if new_entries:
        demisto.debug(f"Updating remote system with {len(new_entries)} new entries for incident {remote_incident_id}.")
        # Prepare comments from entries
        comments_to_add = []
        for entry in new_entries:
            entry_id = entry.get("id")
            demisto.debug(f"Sending the entry with ID: {entry_id} and Type: {entry.get('type')}")
            # Get note content and user
            entry_content = re.sub(r"([^\n])\n", r"\1\n\n", entry.get("contents", ""))
            entry_user = entry.get("user", "dbot") or "dbot"

            note_str = (
                f"[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id}\n\nNote: {entry_content}\n\nAdded By: {entry_user}"
            )
            comments_to_add.append({"message": note_str})

        # Add all comments using the helper function
        add_comments_to_finding(client, company_guid, rolledup_observation_id, user_guid, comments_to_add)

    # Get integration context to track processed findings
    integration_context = demisto.getIntegrationContext()
    processed_findings = integration_context.get("processed_findings") or []

    incident_reopened = False
    # Check if incident is reopened
    if delta and delta.get("closingUserId") == "" and delta.get("runStatus") == "":
        demisto.debug(f"Incident {xsoar_incident_id} is reopened.")
        incident_reopened = True

    if (incident_status == IncidentStatus.ACTIVE and remote_incident_id in processed_findings) or (
        incident_status == IncidentStatus.DONE and remote_incident_id not in processed_findings
    ):
        demisto.debug(f"Skipping status update for finding {remote_incident_id} to prevent mirroring loop.")
        return remote_incident_id

    # Update external status when incident is closed or when incident is active with no changes
    should_update_status = (
        incident_status == IncidentStatus.DONE or (incident_status == IncidentStatus.ACTIVE and not delta) or incident_reopened
    )

    if parsed_args.incident_changed and should_update_status:
        demisto.debug(f"Remote Incident ID: {remote_incident_id}")
        demisto.debug(f"XSOAR Incident ID: {xsoar_incident_id}")
        demisto.debug(f"Delta information for incident: {delta}")

        company_guid = args.get("guid", "")
        # Set status value based on incident status (closed if DONE, opened otherwise)
        status_value = close_status_of_bitsight if incident_status == IncidentStatus.DONE else open_status_of_bitsight
        demisto.debug(f"Updating remediation status of finding {remote_incident_id} to {status_value}")

        body = {
            "rolledup_observation_id": rolledup_observation_id,
            "evidence_key": evidence_key,
            "risk_vector": risk_vector,
            "status": {"value": status_value, "public": False},
        }
        client.update_external_status(company_guid=company_guid, body=body)
        if incident_status == IncidentStatus.ACTIVE:
            processed_findings.append(remote_incident_id)
            demisto.debug(f"Added {remote_incident_id} finding to processed findings.")
        elif incident_status == IncidentStatus.DONE:
            if remote_incident_id in processed_findings:
                processed_findings.remove(remote_incident_id)
                demisto.debug(f"Removed {remote_incident_id} finding from processed findings.")

    processed_findings = processed_findings[-MAX_FINDINGS_MIRRORING_LIMIT:]
    integration_context["processed_findings"] = processed_findings
    demisto.setIntegrationContext(integration_context)

    # For Closing notes
    delta_keys = parsed_args.delta.keys()
    if "closingUserId" in delta_keys and parsed_args.incident_changed and parsed_args.inc_status == IncidentStatus.DONE:
        # Check if incident status is Done
        close_notes = parsed_args.data.get("closeNotes", "")
        close_reason = parsed_args.data.get("closeReason", "")
        close_user_id = parsed_args.data.get("closingUserId", "")

        closing_note = (
            f"[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id}\n\n"
            f"Close Reason: {close_reason}\n\n"
            f"Closed By: {close_user_id}\n\n"
            f"Close Notes: {close_notes}"
        )
        demisto.debug(f"Closing Comment: {closing_note}")

        # Add closing comment using the helper function
        add_comments_to_finding(client, company_guid, rolledup_observation_id, user_guid, [{"message": closing_note}])

    return remote_incident_id


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS."""
    command = demisto.command()
    params = demisto.params()
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    api_key = params.get("apikey", {})

    demisto.info(f"Command being called is {command}")

    client = Client(
        base_url=BASE_URL,
        verify=verify_certificate,
        proxy=proxy,
        ok_codes=[200],
        auth=requests.auth.HTTPBasicAuth(api_key, ""),
        headers={
            "X-BITSIGHT-CALLING-PLATFORM_VERSION": CALLING_PLATFORM_VERSION,
            "X-BITSIGHT-CONNECTOR-NAME-VERSION": CONNECTOR_NAME_VERSION,
        },
    )

    try:
        """EXECUTION CODE"""
        args = demisto.args()
        args.update({"guid": params.get("guid")})
        args.update({"user_email": params.get("user_email")})
        close_status_of_bitsight = params.get("close_status_of_bitsight") or DEFAULT_CLOSE_STATUS_OF_BITSIGHT
        open_status_of_bitsight = params.get("open_status_of_bitsight") or DEFAULT_OPEN_STATUS_OF_BITSIGHT
        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, params))
        elif demisto.command() == "fetch-incidents":
            last_run = demisto.getLastRun()
            last_run_curr, events = fetch_incidents(client, last_run, params)

            demisto.setLastRun(last_run_curr)
            demisto.incidents(events)
        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, args))
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, args))
        elif command == "update-remote-system":
            return_results(update_remote_system_command(client, args, close_status_of_bitsight, open_status_of_bitsight))
        else:
            COMMAND_TO_FUNCTION = {
                "bitsight-company-details-get": company_details_get_command,
                "bitsight-company-findings-get": company_findings_get_command,
                "bitsight-companies-guid-get": companies_guid_get_command,
            }
            if COMMAND_TO_FUNCTION.get(demisto.command()):
                args = demisto.args()
                remove_nulls_from_dictionary(trim_spaces_from_args(args))

                return_results(COMMAND_TO_FUNCTION[demisto.command()](client, args))  # type: ignore
            else:
                raise NotImplementedError(f"Command {demisto.command()} is not implemented")

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
