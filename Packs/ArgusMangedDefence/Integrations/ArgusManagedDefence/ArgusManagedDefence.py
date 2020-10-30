import demistomock as demisto
from CommonServerPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

import logging
from argus_cli.utils import formatting  # Common helper for creating nice outputs
from argus_cli.settings import settings

from argus_api.api.currentuser.v1.user import get_current_user

from argus_api.api.cases.v2.case import (
    add_case_tag,
    add_comment,
    advanced_case_search,
    close_case,
    create_case,
    delete_case,
    delete_comment,
    download_attachment,
    edit_comment,
    get_attachment,
    get_case_metadata_by_id,
    list_case_attachments,
    list_case_tags,
    list_case_comments,
    remove_case_tag_by_id,
    remove_case_tag_by_key_value,
    update_case,
)

from argus_api.api.events.v1 import get_event_by_path
from argus_api.api.events.v1.case.case import get_events_for_case
from argus_api.api.events.v1.aggregated import (
    find_aggregated_events,
    list_aggregated_events,
)
from argus_api.api.events.v1.payload import get_payload
from argus_api.api.events.v1.pcap import get_pcap
from argus_api.api.events.v1.nids import find_n_i_d_s_events, list_n_i_d_s_events

from argus_api.api.pdns.v3.search import search_records

from argus_api.api.reputation.v1.observation import (
    fetch_observations_for_domain,
    fetch_observations_for_i_p,
)

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_INCIDENTS_TO_FETCH = 50
FETCH_TAG = demisto.params().get("fetch_tag")
services = [
    {
        "id": 2,
        "shortName": "ids",
        "name": "Security Monitoring",
        "caseTypes": [
            "operationalIncident",
            "change",
            "securityIncident",
            "informational",
        ],
        "workflows": [
            "severityAlert",
            "escalateInfra",
            "escalateTI",
            "escalateDEV",
            "validation",
            "customerUpdate",
            "slaViolation",
            "escalateNSA",
            "escalateLog",
            "internalSlaViolation",
            "escalateMSSAnalyst",
            "escalation",
            "tuning",
        ],
    },
    {
        "id": 6,
        "shortName": "support",
        "name": "Support",
        "caseTypes": ["informational", "operationalIncident"],
        "workflows": ["customerUpdate", "escalateDEV"],
    },
    {
        "id": 13,
        "shortName": "administrative",
        "name": "Administrative",
        "caseTypes": ["informational"],
        "workflows": [
            "escalateTRS",
            "customerUpdate",
            "escalateNSA",
            "escalateInfra",
            "escalateTI",
            "escalateLog",
            "escalateMSSAnalyst",
            "escalateDEV",
        ],
    },
    {
        "id": 221,
        "shortName": "advisory",
        "name": "Advisory",
        "caseTypes": ["informational"],
        "workflows": ["customerUpdate", "escalateMSSAnalyst"],
    },
    {
        "id": 260,
        "shortName": "vulnscan",
        "name": "Vulnerability Scanning",
        "caseTypes": ["informational", "operationalIncident"],
        "workflows": ["escalateTRS", "customerUpdate", "escalateDEV"],
    },
]

""" CLIENT CLASS """

""" HELPER FUNCTIONS """


def set_argus_settings(api_key, api_url):
    settings["api"]["api_key"] = api_key
    settings["api"]["api_url"] = api_url


def argus_priority_to_demisto_severity(priority: str) -> int:
    mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return mapping.get(priority, 0)


def argus_status_to_demisto_status(status: str) -> int:
    mapping = {
        "pendingCustomer": 0,
        "pendingSoc": 0,
        "pendingVendor": 0,
        "pendingClose": 0,
        "workingSoc": 1,
        "workingCustomer": 1,
        "closed": 2,
    }
    return mapping.get(status, 0)


def build_argus_priority_from_min_severity(min_severity: str) -> List[str]:
    severities = ["low", "medium", "high", "critical"]
    min_severity_list = []
    for severity in severities:
        if argus_priority_to_demisto_severity(
            min_severity.lower()
        ) <= argus_priority_to_demisto_severity(severity):
            min_severity_list.append(severity)
    return min_severity_list


def parse_first_fetch(first_fetch: Any) -> Any:
    if isinstance(first_fetch, str):
        if first_fetch[0] != "-":
            first_fetch = f"-{first_fetch}"
    return first_fetch


def build_tags_from_list(lst: list) -> List[Dict]:
    if not lst:
        return None
    tags = []
    for i in range(0, len(lst), 2):
        tags.append({"key": lst[i], "value": lst[i + 1]})
    return tags


def str_to_list(string: str) -> list:
    return string.strip().split(",") if string else None


def str_to_dict(string: str) -> dict:
    if not string:
        return None
    lst = str_to_list(string)
    return {lst[i]: lst[i + 1] for i in range(0, len(lst), 2)}


def pretty_print_case_metadata(
    result: dict, title: str = None
) -> str:  # TODO improve: markdownify
    data = result["data"]
    string = title if title else f"# #{data['id']}: {data['subject']}\n"
    string += f"_Priority: {data['priority']}, status: {data['status']}, last updated: {data['lastUpdatedTime']}_\n"
    string += (
        f"Reported by {data['publishedByUser']['name']} at {data['publishedTime']}\n\n"
    )
    string += data["description"]  # TODO DisplayHTML playbook# ?
    return string


def is_valid_service(service: str) -> bool:
    return any(s["shortName"] == service for s in services)


def is_valid_case_type(service: str, case_type: str) -> bool:
    return is_valid_service(service) and (
        case_type
        in next((s for s in services if s["shortName"] == service), {})["caseTypes"]
    )


""" COMMAND FUNCTIONS """


def test_module_command() -> str:
    response = get_current_user()
    if response["responseCode"] == 200:
        return "ok"
    else:
        return_error(
            "Unable to communicate with Argus API", response["responseCode"], response
        )


def fetch_incidents(last_run: dict, first_fetch_period: str):
    start_timestamp = last_run.get("start_time", None) if last_run else None
    # noinspection PyTypeChecker
    result = advanced_case_search(
        startTimestamp=start_timestamp if start_timestamp else first_fetch_period,
        endTimestamp="now",
        limit=demisto.params().get("max_fetch", 0),
        sortBy=["createdTimestamp"],
        priority=build_argus_priority_from_min_severity(
            demisto.params().get("min_severity", "medium")
        ),
        subCriteria=[
            {"exclude": True, "status": ["closed"]},
        ],
        timeFieldStrategy=["createdTimestamp"],
    )
    incidents = []
    for case in result["data"]:
        incidents.append(
            {
                "name": f"#{case['id']}: {case['subject']}",
                "occurred": case["createdTime"],
                "severity": argus_priority_to_demisto_severity(case["priority"]),
                "status": argus_status_to_demisto_status(case["status"]),
                "details": case["description"]
                + str(demisto.getLastRun()),  # TODO markdownify
                "customFields": {
                    "argus_id": str(case["id"]),
                    "type": case["type"],
                    "category": case["category"]["name"] if case["category"] else None,
                    "service": case["service"]["name"],
                    "lastUpdatedTime": case["lastUpdatedTime"],
                    "createdTimestamp": case["createdTimestamp"],
                    "customer": case["customer"]["shortName"],
                },
                "rawJson": json.dumps(case),
            }
        )
    if result["data"]:
        last_run["start_time"] = result["data"][-1]["createdTimestamp"] + 1

    return last_run, incidents


def add_case_tag_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    key = args.get("key", None)
    value = args.get("value", None)
    if not case_id:
        raise ValueError("case_id not specified")
    if not key:
        raise ValueError("key not specified")
    if not value:
        raise ValueError("value not specified")

    tag = {"key": key, "value": value}
    result = add_case_tag(caseID=case_id, tags=tag)
    headers = ["key", "value", "addedTime"]
    readable_output = tableToMarkdown(
        f"#{case_id}: Tags", result["data"], headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Argus.Tags',
        outputs=result,
        raw_response=result,
    )


def add_comment_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    comment = args.get("comment", None)
    if not case_id:
        raise ValueError("case_id not specified")
    if not comment:
        raise ValueError("comment not specified")

    result = add_comment(
        caseID=case_id,
        comment=comment,
        asReplyTo=args.get("as_reply_to", None),
        internal=args.get("internal", None),
        originEmailAddress=args.get("origin_email_address", None),
        associatedAttachmentID=args.get("associated_attachement_id", None),
    )
    readable_output = f"# #{case_id}: Added comment\n"
    readable_output += f"#### *{result['data']['addedByUser']['userName']} - {result['data']['addedTime']}*\n"
    readable_output += f"{result['data']['comment']}\n\n"
    readable_output += f"_id: {result['data']['id']}_\n"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Argus.Comment',
        outputs=result,
        raw_response=result,
    )


def advanced_case_search_command(args: Dict[str, Any]) -> CommandResults:
    result = advanced_case_search(
        startTimestamp=args.get("start_timestamp", None),
        endTimestamp=args.get("end_timestamp", None),
        limit=args.get("limit", None),
        offset=args.get("offset", None),
        includeDeleted=args.get("include_deleted", None),
        subCriteria=args.get("sub_criteria", None),
        exclude=args.get("exclude", None),
        required=args.get("required", None),
        customerID=args.get("customer_id", None),
        caseID=args.get("case_id", None),
        customer=args.get("customer", None),
        type=args.get("type", None),
        service=args.get("service", None),
        category=args.get("category", None),
        status=args.get("status", None),
        priority=args.get("priority", None),
        assetID=args.get("asset_id", None),
        tag=args.get("tag", None),
        workflow=args.get("workflow", None),
        field=args.get("field", None),
        keywords=args.get("keywords", None),
        timeFieldStrategy=args.get("time_field_strategy", None),
        timeMatchStrategy=args.get("time_match_strategy", None),
        keywordFieldStrategy=args.get("keyword_field_strategy", None),
        keywordMatchStrategy=args.get("keyword_match_strategy", None),
        user=args.get("user", None),
        userFieldStrategy=args.get("user_field_strategy", None),
        userAssigned=args.get("user_assigned", None),
        techAssigned=args.get("tech_assigned", None),
        includeWorkflows=args.get("include_workflows", None),
        includeDescription=args.get("include_description", None),
        accessMode=args.get("access_mode", None),
        explicitAccess=args.get("explicit_access", None),
        sortBy=args.get("sort_by", None),
        includeFlags=args.get("include_flags", None),
        excludeFlags=args.get("exclude_flags", None),
    )
    readable_output = f"Advanced Case Search: {result['count']} result(s)\n"
    readable_output += tableToMarkdown(
        "Output not suitable for playground", result["data"]
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Argus.Cases',
        outputs=result,
        raw_response=result,
    )


def close_case_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    if not case_id:
        raise ValueError("case_id not specified")

    result = close_case(
        caseID=case_id,
        comment=args.get("comment", None),
        # notification=notifcation, TODO implement
    )
    readable_output = f"# #{case_id}: close case\n"
    readable_output += (
        f"_Status: {result['data']['status']}, at: {result['data']['closedTime']}_"
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Argus.Case',
        outputs=result,
        raw_response=result,
    )


def create_case_command(args: Dict[str, Any]) -> CommandResults:
    subject = args.get("subject", None)
    description = args.get("description", None)
    service = args.get("service", None)
    case_type = args.get("type", None)
    tags = args.get("tags", None)
    if not subject:
        raise ValueError("subject not specified")
    if not description:
        raise ValueError("description not specified")
    if not service:
        raise ValueError("service not specified")
    if not case_type:
        raise ValueError("case_type not specified")
    if not is_valid_case_type(service, case_type):
        raise ValueError("invalid service: case type combination")
    if tags:
        tags = str(tags).split(",")
        if len(tags) % 2 != 0:
            raise ValueError("tags list must be of even number", tags)
        tags = build_tags_from_list(tags)

    result = create_case(
        customer=args.get("customer", None),
        service=service,
        category=args.get("category", None),
        type=case_type,
        status=args.get("status", None),
        # watchers=args.get("watchers", None), TODO implement
        # fields=args.get("fields", None), TODO needed?
        tags=tags,
        subject=subject,
        description=description,
        customerReference=args.get("customer_reference", None),
        priority=args.get("priority", None),
        accessMode=args.get("access_mode", None),
        # aclMembers=args.get("acl_members", None), TODO needed?
        # notification=args.get("notification", None), TODO implement
        originEmailAddress=args.get("origin_email_address", None),
        # triggers=args.get("triggers", None), TODO needed?
        publish=args.get("publish", None),
        defaultWatchers=args.get("default_watchers", None),
    )

    return CommandResults(
        readable_output=pretty_print_case_metadata(result),
        outputs_prefix='Argus.Case',
        outputs=result,
        raw_response=result,
    )


def delete_case_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    if not case_id:
        raise ValueError("case id not specified")

    result = delete_case(caseID=case_id)

    return CommandResults(
        readable_output=pretty_print_case_metadata(result, "Case deleted"),
        outputs_prefix='Argus.Case',
        outputs=result,
        raw_response=result,
    )


def delete_comment_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    comment_id = args.get("comment_id", None)
    if not case_id:
        raise ValueError("case id not specified")
    if not comment_id:
        raise ValueError("comment id not specified")

    result = delete_comment(caseID=case_id, commentID=comment_id)
    readable_output = f"# #{case_id}: Deleted comment\n"
    readable_output += f"#### *{result['data']['addedByUser']['userName']} - {result['data']['lastUpdatedTime']}*\n"
    readable_output += f"{result['data']['comment']}"
    readable_output += f"Flags: {str(result['data']['flags'])}"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Argus.Comment',
        outputs=result,
        raw_response=result,
    )


def download_attachment_command(args: Dict[str, Any]) -> fileResult:
    case_id = args.get("case_id", None)
    attachment_id = args.get("attachment_id", None)
    if not case_id:
        raise ValueError("case id not specified")
    if not attachment_id:
        raise ValueError("attachment id not specified")

    result = download_attachment(caseID=case_id, attachmentID=attachment_id)

    return fileResult(attachment_id, result.content)


def edit_comment_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    comment_id = args.get("comment_id", None)
    comment = args.get("comment", None)
    if not case_id:
        raise ValueError("case id not specified")
    if not comment_id:
        raise ValueError("comment id not specified")
    if not comment:
        raise ValueError("comment not specified")

    result = edit_comment(caseID=case_id, commentID=comment_id, comment=comment)
    readable_output = f"# #{case_id}: Updated comment\n"
    readable_output += f"#### *{result['data']['addedByUser']['userName']} - {result['data']['lastUpdatedTime']}*\n"
    readable_output += f"{result['data']['comment']}\n\n"
    readable_output += f"_id: {result['data']['id']}_\n"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Argus.Comment',
        outputs=result,
        raw_response=result,
    )


def get_attachment_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    attachment_id = args.get("attachment_id", None)
    if not case_id:
        raise ValueError("case id not specified")
    if not attachment_id:
        raise ValueError("attachment id not specified")

    result = get_attachment(caseID=case_id, attachmentID=attachment_id)
    readable_output = f"# #{case_id}: attachment metadata\n"
    readable_output += f"#### *{result['data']['addedByUser']['userName']} - {result['data']['addedTime']}*\n"
    readable_output += f"{result['data']['name']} ({result['data']['mimeType']}, {result['data']['size']} bytes)\n\n"
    readable_output += f"_id: {result['data']['id']}_\n"

    return CommandResults(
        readable_output=readable_output,
        outputs={"Argus.Attachment(val.id === obj.id)": result["data"]},
        raw_response=result,
    )


def get_case_metadata_by_id_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    if not case_id:
        raise ValueError("case id not specified")

    result = get_case_metadata_by_id(
        id=case_id, skipRedirect=args.get("skip_redirect", None)
    )

    return CommandResults(
        readable_output=pretty_print_case_metadata(result),
        outputs_prefix='Argus.Case',
        outputs=result,
        raw_response=result,
    )


def list_case_attachments_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    if not case_id:
        raise ValueError("case_id not specified")

    result = list_case_attachments(
        caseID=case_id, limit=args.get("limit", None), offset=args.get("offset", None)
    )
    readable_output = f"# #{case_id}: Case attachments\n"
    for attachment in result["data"]:
        readable_output += f"#### *{attachment['addedByUser']['userName']} - {attachment['addedTime']}*\n"
        readable_output += f"{attachment['name']} ({attachment['mimeType']}, {attachment['size']} kb)\n\n"
        readable_output += f"_id: {attachment['id']}_\n"
        readable_output += "* * *\n"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Argus.Attachment',
        outputs=result,
        raw_response=result,
    )


def list_case_tags_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    if not case_id:
        raise ValueError("case_id not specified")

    result = list_case_tags(
        caseID=case_id, limit=args.get("limit", None), offset=args.get("offset", None)
    )
    headers = ["key", "value", "addedTime", "id"]
    readable_output = tableToMarkdown(
        f"#{case_id}: Tags", result["data"], headers=headers
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Argus.Tags',
        outputs=result,
        raw_response=result,
    )


def list_case_comments_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    sort_by = args.get("sort_by", None)
    if not case_id:
        raise ValueError("case_id not specified")
    if sort_by:
        sort_by = ["addedTimestamp"] if sort_by == "ascending" else ["-addedTimestamp"]

    result = list_case_comments(
        caseID=case_id,
        beforeComment=args.get("before_comment", None),
        afterComment=args.get("after_comment", None),
        offset=args.get("offset", None),
        limit=args.get("limit", None),
        sortBy=sort_by,
    )
    readable_output = f"# #{case_id}: Comments\n"
    for comment in result["data"]:
        readable_output += (
            f"#### *{comment['addedByUser']['userName']} - {comment['addedTime']}*\n"
        )
        readable_output += f"{comment['comment']}\n\n"
        readable_output += f"_id: {comment['id']}_\n"
        readable_output += "* * *\n"

    return CommandResults(
        readable_output=readable_output,
        outputs={"Argus.Comment(val.id === obj.id)": result["data"]},
        raw_response=result,
    )


def remove_case_tag_by_id_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    tag_id = args.get("tag_id", None)
    if not case_id:
        raise ValueError("case id not specified")
    if not tag_id:
        raise ValueError("tag id not specified")

    result = remove_case_tag_by_id(caseID=case_id, tagID=tag_id)
    headers = ["key", "value", "addedTime", "id", "flags"]
    readable_output = tableToMarkdown(
        f"#{case_id}: Delete tags", result["data"], headers=headers
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Argus.Tags',
        outputs=result,
        raw_response=result,
    )


def remove_case_tag_by_key_value_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    key = args.get("key", None)
    value = args.get("value", None)
    if not case_id:
        raise ValueError("case id not specified")
    if not key:
        raise ValueError("key not specified")
    if not value:
        raise ValueError("value not specified")

    result = remove_case_tag_by_key_value(caseID=case_id, tagKey=key, tagValue=value)
    headers = ["key", "value", "addedTime", "id", "flags"]
    readable_output = tableToMarkdown(
        f"#{case_id}: Delete tags", result["data"], headers=headers
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Argus.Tags',
        outputs=result,
        raw_response=result,
    )


def update_case_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    if not case_id:
        raise ValueError("case id not specified")

    result = update_case(
        id=case_id,
        subject=args.get("subject", None),
        description=args.get("description", None),
        status=args.get("status", None),
        priority=args.get("priority", None),
        category=args.get("category", None),
        reporter=args.get("reporter", None),
        assignedUser=args.get("assigned_user", None),
        assignedTech=args.get("assigned_tech", None),
        customerReference=args.get("customer_reference", None),
        comment=args.get("comment", None),
        # notification=args.get("notification", None), TODO needed?
        originEmailAddress=args.get("origin_email_address", None),
        hasEvents=args.get("has_events", None),
        internalComment=args.get("internal_comment", None),
    )

    return CommandResults(
        readable_output=pretty_print_case_metadata(result),
        outputs={"Argus.Case(val.id === obj.id)": result["data"]},
        raw_response=result,
    )


def get_event_command(args: Dict[str, Any]) -> CommandResults:
    event_type = args.get("type", None)
    timestamp = args.get("timestamp", None)
    customer_id = args.get("customer_id", None)
    event_id = args.get("event_id", None)
    if not event_type:
        raise ValueError("event type not specified")
    if not timestamp:
        raise ValueError("timestamp not specified")
    if not customer_id:
        raise ValueError("customer id not specified")
    if not event_id:
        raise ValueError("event id not specified")

    result = get_event_by_path(
        type=event_type, timestamp=timestamp, customerID=customer_id, eventID=event_id
    )

    return CommandResults(
        readable_output=tableToMarkdown(f"Event: {event_id}", result["data"]),
        outputs={"Argus.Event(val.id === obj.id)": result["data"]},
        raw_response=result,
    )


def get_events_for_case_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    if not case_id:
        raise ValueError("case id not specified")

    result = get_events_for_case(
        caseID=case_id, limit=args.get("limit", None), offset=args.get("offset", None)
    )
    readable_output = f"# #{case_id}: Associated Events\n"
    readable_output += f"_Count: {result['count']}, showing {result['size']} events, from {result['offset']} to {result['limit']}_\n"
    readable_output += tableToMarkdown("Events", result["data"])

    return CommandResults(
        readable_output=readable_output,
        outputs={"Argus.Event(val.id === obj.id)": result["data"]},
        raw_response=result,
    )


def find_aggregated_events_command(args: Dict[str, Any]) -> CommandResults:
    result = find_aggregated_events(
        skipFutureEvents=args.get("skip_future_events", None),
        exclude=args.get("exclude", None),
        eventIdentifier=str_to_list(args.get("event_identifier", None)),  # TODO fix
        locationID=str_to_list(args.get("location_id", None)),
        severity=str_to_list(args.get("severity", None)),
        customer=str_to_list(args.get("customer", None)),
        alarmID=str_to_list(args.get("alarm_id", None)),
        attackCategoryID=str_to_list(args.get("attack_category_id", None)),
        sourceGeoCountry=str_to_list(args.get("source_geo_country", None)),
        destinationGeoCountry=str_to_list(args.get("destination_geo_country", None)),
        geoCountry=str_to_list(args.get("geo_country", None)),
        properties=str_to_dict(args.get("properties", None)),
        exactMatchProperties=args.get("exact_match_properties", None),
        subCriteria=str_to_list(args.get("sub_criteria", None)),
        signature=str_to_list(args.get("signature", None)),
        lastUpdatedTimestamp=args.get("last_updated_timestamp", None),
        indexStartTime=args.get("index_start_time", None),
        indexEndTime=args.get("index_end_time", None),
        destinationIP=str_to_list(args.get("destination_ip", None)),
        sourceIP=str_to_list(args.get("source_ip", None)),
        ip=str_to_list(args.get("ip", None)),
        destinationPort=str_to_list(args.get("destination_port", None)),
        sourcePort=str_to_list(args.get("source_port", None)),
        port=str_to_list(args.get("port", None)),
        minSeverity=args.get("min_severity", None),
        maxSeverity=args.get("max_severity", None),
        limit=args.get("limit", 25),
        offset=args.get("offset", None),
        includeDeleted=args.get("include_deleted", None),
        minCount=args.get("min_count", None),
        associatedCaseID=str_to_list(args.get("associated_case_id", None)),
        sourceIPMinBits=args.get("source_ip_min_bits", None),
        destinationIPMinBits=args.get("destination_ip_min_bits", None),
        startTimestamp=args.get("start_timestamp", "-24hours"),
        endTimestamp=args.get("end_timestamp", "now"),
        sortBy=str_to_list(args.get("sort_by", None)),
        includeFlags=str_to_list(args.get("include_flags", None)),
        excludeFlags=str_to_list(args.get("exclude_flags", None)),
    )
    readable_output = f"# List Events\n"
    readable_output += f"_Count: {result['count']}, showing {result['size']} events, from {result['offset']} to {result['limit']}_\n"
    readable_output += tableToMarkdown("Events", result["data"])

    return CommandResults(
        readable_output=readable_output,
        outputs={"Argus.Event(val.id === obj.id)": result["data"]},
        raw_response=result,
    )


def list_aggregated_events_command(args: Dict[str, Any]) -> CommandResults:
    result = list_aggregated_events(
        customerID=args.get("customer_id", None),
        signature=args.get("signature", None),
        ip=args.get("ip", None),
        startTimestamp=args.get("start_timestamp", None),
        endTimestamp=args.get("end_timestamp", None),
        limit=args.get("limit", None),
        offset=args.get("offset", None),
    )
    readable_output = f"# List Events\n"
    readable_output += f"_Count: {result['count']}, showing {result['size']} events, from {result['offset']} to {result['limit']}_\n"
    readable_output += tableToMarkdown("Events", result["data"])

    return CommandResults(
        readable_output=readable_output,
        outputs={"Argus.Event(val.id === obj.id)": result["data"]},
        raw_response=result,
    )


def get_payload_command(args: Dict[str, Any]) -> CommandResults:
    event_type = args.get("type", None)
    timestamp = args.get("timestamp", None)
    customer_id = args.get("customer_id", None)
    event_id = args.get("event_id", None)
    if not event_type:
        raise ValueError("event type not specified")
    if not timestamp:
        raise ValueError("timestamp not specified")
    if not customer_id:
        raise ValueError("customer id not specified")
    if not event_id:
        raise ValueError("event id not specified")
    result = get_payload(
        type=event_type, timestamp=timestamp, customerID=customer_id, eventID=event_id
    )
    readable_output = f"# Event payload\n"
    readable_output += f"Event: {event_id}, type: {result['data']['type']}\n"
    readable_output += result["data"]["payload"]

    return CommandResults(
        readable_output=readable_output,
        outputs={"Argus.Payload(val.id === obj.id)": result["data"]},
        raw_response=result,
    )


def get_pcap_command(args: Dict[str, Any]) -> fileResult:
    event_type = args.get("type", None)
    timestamp = args.get("timestamp", None)
    customer_id = args.get("customer_id", None)
    event_id = args.get("event_id", None)
    if not event_type:
        raise ValueError("event type not specified")
    if not timestamp:
        raise ValueError("timestamp not specified")
    if not customer_id:
        raise ValueError("customer id not specified")
    if not event_id:
        raise ValueError("event id not specified")
    result = get_pcap(
        type=event_type, timestamp=timestamp, customerID=customer_id, eventID=event_id
    )

    return fileResult(f"{event_id}_pcap", result.content)


def find_nids_events_command(args: Dict[str, Any]) -> CommandResults:
    result = find_n_i_d_s_events(
        skipFutureEvents=args.get("skip_future_events", None),
        exclude=args.get("exclude", None),
        eventIdentifier=str_to_list(args.get("event_identifier", None)),
        locationID=str_to_list(args.get("location_id", None)),
        severity=str_to_list(args.get("severity", None)),
        customer=str_to_list(args.get("customer", None)),
        alarmID=str_to_list(args.get("alarm_id", None)),
        attackCategoryID=str_to_list(args.get("attack_category_id", None)),
        sourceGeoCountry=str_to_list(args.get("source_geo_country", None)),
        destinationGeoCountry=str_to_list(args.get("destination_geo_country", None)),
        geoCountry=str_to_list(args.get("geo_country", None)),
        properties=str_to_dict(args.get("properties", None)),
        exactMatchProperties=args.get("exact_match_properties", None),
        sensorID=str_to_list(args.get("sensor_id", None)),
        subCriteria=str_to_list(args.get("sub_criteria", None)),
        signature=str_to_list(args.get("signature", None)),
        lastUpdatedTimestamp=args.get("last_updated_timestamp", None),
        indexStartTime=args.get("index_start_time", None),
        indexEndTime=args.get("index_end_time", None),
        destinationIP=str_to_list(args.get("destination_ip", None)),
        sourceIP=str_to_list(args.get("source_ip", None)),
        ip=str_to_list(args.get("ip", None)),
        destinationPort=str_to_list(args.get("destination_port", None)),
        sourcePort=str_to_list(args.get("source_port", None)),
        port=str_to_list(args.get("port", None)),
        minSeverity=args.get("min_severity", None),
        maxSeverity=args.get("max_severity", None),
        limit=args.get("limit", 25),
        offset=args.get("offset", None),
        includeDeleted=args.get("include_deleted", None),
        startTimestamp=args.get("start_timestamp", "-24hours"),
        endTimestamp=args.get("end_timestamp", "now"),
        sortBy=str_to_list(args.get("sort_by", None)),
        includeFlags=str_to_list(args.get("include_flags", None)),
        excludeFlags=str_to_list(args.get("exclude_flags", None)),
    )
    readable_output = f"# Find NIDS Events\n"
    readable_output += f"_Count: {result['count']}, showing {result['size']} events, from {result['offset']} to {result['limit']}_\n"
    readable_output += tableToMarkdown("Events", result["data"])

    return CommandResults(
        readable_output=readable_output,
        outputs={"Argus.NIDS_Event(val.id === obj.id)": result["data"]},
        raw_response=result,
    )


def list_nids_events_command(args: Dict[str, Any]) -> CommandResults:
    result = list_n_i_d_s_events(
        customerID=args.get("customer_id", None),
        signature=args.get("signature", None),
        ip=args.get("ip", None),
        startTimestamp=args.get("start_timestamp", None),
        endTimestamp=args.get("end_timestamp", None),
        limit=args.get("limit", None),
        offset=args.get("offset", None),
    )
    readable_output = f"# List NIDS Events\n"
    readable_output += f"_Count: {result['count']}, showing {result['size']} events, from {result['offset']} to {result['limit']}_\n"
    readable_output += tableToMarkdown("Events", result["data"])

    return CommandResults(
        readable_output=readable_output,
        outputs={"Argus.NIDS_Event(val.id === obj.id)": result["data"]},
        raw_response=result,
    )


def search_records_command(args: Dict[str, Any]) -> CommandResults:
    query = args.get("query", None)
    if not query:
        raise ValueError("query not specified")
    result = search_records(
        query=query,
        aggregateResult=args.get("aggregate_result", None),
        includeAnonymousResults=args.get("include_anonymous_results", None),
        rrClass=str_to_list(args.get("rr_class", None)),
        rrType=str_to_list(args.get("rr_type", None)),
        customerID=str_to_list(args.get("customer_id", None)),
        tlp=str_to_list((args.get("tlp", None))),
        limit=args.get("limit", 25),
        offset=args.get("offset", None),
    )
    return CommandResults(
        readable_output=tableToMarkdown("PDNS records", result["data"]),
        outputs={"Argus.PDNS(val.id === obj.id)": result["data"]},
        raw_response=result,
    )


def fetch_observations_for_domain_command(args: Dict[str, Any]) -> CommandResults:
    fqdn = args.get("fqdn", None)
    if not fqdn:
        raise ValueError("fqdn not specified")

    result = fetch_observations_for_domain(fqdn=fqdn)
    return CommandResults(
        readable_output=tableToMarkdown(
            f'Domain observations for "{fqdn}"', result["data"]
        ),
        outputs={"Argus.Domain_Observation(val.id === onj.id)": result["data"]},
        raw_response=result,
    )


def fetch_observations_for_i_p_command(args: Dict[str, Any]) -> CommandResults:
    ip = args.get("ip", None)
    if not ip:
        raise ValueError("ip not specified")

    result = fetch_observations_for_i_p(ip=ip)
    return CommandResults(
        readable_output=tableToMarkdown(f'IP observations for "{ip}"', result["data"]),
        outputs={"Argus.IP_Observation(val.id === onj.id)": result["data"]},
        raw_response=result,
    )


""" MAIN FUNCTION """


def main() -> None:
    # TODO test argus-cli
    logging.getLogger("argus_cli").setLevel("WARNING")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    first_fetch_period = parse_first_fetch(
        demisto.params().get("first_fetch_period", "-1 day")
    )

    demisto.debug(f"Command being called is {demisto.command()}")
    try:

        set_argus_settings(
            demisto.params().get("api_key"), demisto.params().get("api_url")
        )

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module_command())

        elif demisto.command() == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                last_run=demisto.getLastRun(),
                first_fetch_period=first_fetch_period,
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == "argus_add_case_tag":
            return_results(add_case_tag_command(demisto.args()))

        elif demisto.command() == "argus_add_comment":
            return_results(add_comment_command(demisto.args()))

        elif demisto.command() == "argus_advanced_case_search":
            return_results(advanced_case_search_command(demisto.args()))

        elif demisto.command() == "argus_close_case":
            return_results(close_case_command(demisto.args()))

        elif demisto.command() == "argus_create_case":
            return_results(create_case_command(demisto.args()))

        elif demisto.command() == "argus_delete_case":
            return_results(delete_case_command(demisto.args()))

        elif demisto.command() == "argus_delete_comment":
            return_results(delete_comment_command(demisto.args()))

        elif demisto.command() == "argus_download_attachment":
            return_results(download_attachment_command(demisto.args()))

        elif demisto.command() == "argus_edit_comment":
            return_results(edit_comment_command(demisto.args()))

        elif demisto.command() == "argus_get_attachment":
            return_results(get_attachment_command(demisto.args()))

        elif demisto.command() == "argus_get_case_metadata_by_id":
            return_results(get_case_metadata_by_id_command(demisto.args()))

        elif demisto.command() == "argus_list_case_attachments":
            return_results(list_case_attachments_command(demisto.args()))

        elif demisto.command() == "argus_list_case_tags":
            return_results(list_case_tags_command(demisto.args()))

        elif demisto.command() == "argus_list_case_comments":
            return_results(list_case_comments_command(demisto.args()))

        elif demisto.command() == "argus_remove_case_tag_by_id":
            return_results(remove_case_tag_by_id_command(demisto.args()))

        elif demisto.command() == "argus_remove_case_tag_by_key_value":
            return_results(remove_case_tag_by_key_value_command(demisto.args()))

        elif demisto.command() == "argus_update_case":
            return_results(update_case_command(demisto.args()))

        elif demisto.command() == "argus_get_event":
            return_results(get_event_command(demisto.args()))

        elif demisto.command() == "argus_get_events_for_case":
            return_results(get_events_for_case_command(demisto.args()))

        elif demisto.command() == "argus_find_aggregated_events":
            return_results(find_aggregated_events_command(demisto.args()))

        elif demisto.command() == "argus_list_aggregated_events":
            return_results(list_aggregated_events_command(demisto.args()))

        elif demisto.command() == "argus_get_payload":
            return_results(get_payload_command(demisto.args()))

        elif demisto.command() == "argus_get_pcap":
            return_results(get_pcap_command(demisto.args()))

        elif demisto.command() == "argus_find_nids_events":
            return_results(find_nids_events_command(demisto.args()))

        elif demisto.command() == "argus_list_nids_events":
            return_results(list_nids_events_command(demisto.args()))

        elif demisto.command() == "argus_pdns_search_records":
            return_results(search_records_command(demisto.args()))

        elif demisto.command() == "argus_fetch_observations_for_domain":
            return_results(fetch_observations_for_domain_command(demisto.args()))

        elif demisto.command() == "argus_fetch_observations_for_ip":
            return_results(fetch_observations_for_i_p_command(demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
