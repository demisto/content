import demistomock as demisto
from CommonServerPython import *

""" IMPORTS """

import json
import urllib3

import dateparser
import traceback
from typing import Any, Dict, List, Union

import logging

from argus_api import session as argus_session

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

from argus_api.exceptions.http import ArgusException

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
PRETTY_DATE_FORMAT = "%b %d, %Y, %H:%M:%S"
FETCH_TAG = demisto.params().get("fetch_tag")


""" HELPER FUNCTIONS """


def set_argus_settings(
    api_key: str, base_url: str = None, proxies: dict = None, verify: bool = None
):
    argus_session.api_key = api_key
    argus_session.base_url = base_url
    argus_session.proxies = proxies
    argus_session.verify = verify


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
        return []
    if len(lst) % 2 != 0:
        return []
    tags = []
    for i in range(0, len(lst), 2):
        tags.append({"key": lst[i], "value": lst[i + 1]})
    return tags


def str_to_dict(string: str) -> dict:
    if not string:
        return {}
    lst = argToList(string)
    if len(lst) % 2 != 0:
        return {}
    return {lst[i]: lst[i + 1] for i in range(0, len(lst), 2)}


def date_time_to_epoch_milliseconds(date_time: Union[datetime, str] = None) -> int:
    if isinstance(date_time, datetime):
        return int(date_time.timestamp() * 1000)
    if isinstance(date_time, str):
        return date_time_to_epoch_milliseconds(dateparser.parse(date_time))
    return int(datetime.now().timestamp() * 1000)


def pretty_print_date(date_time: Union[datetime, str] = None) -> str:
    if isinstance(date_time, datetime):
        return date_time.strftime(PRETTY_DATE_FORMAT)
    if isinstance(date_time, str):
        return pretty_print_date(dateparser.parse(date_time))
    return datetime.now().strftime(PRETTY_DATE_FORMAT)


def pretty_print_case_metadata(result: dict, title: str = None) -> str:
    data = result["data"]
    string = title if title else f"# #{data['id']}: {data['subject']}\n"
    string += "_Priority: {}, status: {}, last updated: {}_\n".format(
        data["priority"], data["status"], pretty_print_date(data["lastUpdatedTime"])
    )
    string += "Reported by {} at {}\n\n".format(
        data["publishedByUser"]["name"], pretty_print_date(data["publishedTime"])
    )
    string += data["description"]
    return string


def pretty_print_comment(comment: dict, title: str = None) -> str:
    string = title if title else ""
    string += f"#### *{comment['addedByUser']['userName']} - {pretty_print_date(comment['addedTime'])}*\n"
    string += (
        f"_Last updated {pretty_print_date(comment['lastUpdatedTime'])}_\n"
        if comment["lastUpdatedTime"]
        else ""
    )
    string += f"{comment['comment']}\n\n"
    string += f"_id: {comment['id']}_\n"
    string += f"_Flags: {str(comment['flags'])}_\n" if comment["flags"] else ""
    string += "* * *\n"
    return string


def pretty_print_comments(comments: list, title: str = None) -> str:
    string = title if title else ""
    for comment in comments:
        string += pretty_print_comment(comment)
    return string


def pretty_print_events(result: dict, title: str = None) -> str:
    string = title if title else ""
    string += "_Count: {}, showing {} events, from {} to {}_\n".format(
        result["count"], result["size"], result["offset"], result["limit"]
    )
    string += tableToMarkdown("Events", result["data"])
    return string


""" COMMAND FUNCTIONS """


def test_module_command() -> str:
    response = get_current_user()
    if response["responseCode"] == 200:
        return "ok"
    return (
        f"Unable to communicate with Argus API {response['responseCode']}, {response}"
    )


def fetch_incidents(
    last_run: dict, first_fetch_period: str, limit: int = 25, min_severity: str = "low"
):
    start_timestamp = last_run.get("start_time", None) if last_run else None
    # noinspection PyTypeChecker
    result = advanced_case_search(
        startTimestamp=start_timestamp if start_timestamp else first_fetch_period,
        endTimestamp="now",
        limit=limit,
        sortBy=["createdTimestamp"],
        priority=build_argus_priority_from_min_severity(min_severity),
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
                "details": case["description"],
                "customFields": {
                    "argus_id": str(case["id"]),
                    "type": case["type"],
                    "category": case["category"]["name"] if case["category"] else None,
                    "service": case["service"]["name"],
                    "lastUpdatedTime": case["lastUpdatedTime"],
                    "createdTimestamp": case["createdTimestamp"],
                    "customer": case["customer"]["shortName"],
                },
                "rawJSON": json.dumps(case),
            }
        )
    if result["data"]:
        last_run["start_time"] = str(result["data"][-1]["createdTimestamp"] + 1)

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
        outputs_prefix="Argus.Tags",
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
        associatedAttachmentID=args.get("associated_attachment_id", None),
    )

    return CommandResults(
        readable_output=pretty_print_comment(
            result["data"], f"# #{case_id}: Added comment\n"
        ),
        outputs_prefix="Argus.Comment",
        outputs=result,
        raw_response=result,
    )


def advanced_case_search_command(args: Dict[str, Any]) -> CommandResults:
    # noinspection PyTypeChecker
    result = advanced_case_search(
        startTimestamp=args.get("start_timestamp", None),
        endTimestamp=args.get("end_timestamp", None),
        limit=args.get("limit", None),
        offset=args.get("offset", None),
        includeDeleted=args.get("include_deleted", None),
        subCriteria=argToList(args.get("sub_criteria", None)),
        exclude=args.get("exclude", None),
        required=args.get("required", None),
        customerID=argToList(args.get("customer_id", None)),
        caseID=argToList(args.get("case_id", None)),
        customer=argToList(args.get("customer", None)),
        type=argToList(args.get("case_type", None)),
        service=argToList(args.get("service", None)),
        category=argToList(args.get("category", None)),
        status=argToList(args.get("status", None)),
        priority=argToList(args.get("priority", None)),
        assetID=argToList(args.get("asset_id", None)),
        tag=argToList(args.get("tag", None)),
        workflow=argToList(args.get("workflow", None)),
        field=argToList(args.get("field", None)),
        keywords=argToList(args.get("keywords", None)),
        timeFieldStrategy=argToList(args.get("time_field_strategy", None)),
        timeMatchStrategy=args.get("time_match_strategy", None),
        keywordFieldStrategy=argToList(args.get("keyword_field_strategy", None)),
        keywordMatchStrategy=args.get("keyword_match_strategy", None),
        user=argToList(args.get("user", None)),
        userFieldStrategy=argToList(args.get("user_field_strategy", None)),
        userAssigned=args.get("user_assigned", None),
        techAssigned=args.get("tech_assigned", None),
        includeWorkflows=args.get("include_workflows", None),
        includeDescription=args.get("include_description", None),
        accessMode=argToList(args.get("access_mode", None)),
        explicitAccess=argToList(args.get("explicit_access", None)),
        sortBy=argToList(args.get("sort_by", None)),
        includeFlags=argToList(args.get("include_flags", None)),
        excludeFlags=argToList(args.get("exclude_flags", None)),
    )
    readable_output = f"Advanced Case Search: {result['count']} result(s)\n"
    readable_output += tableToMarkdown(
        "Output not suitable for playground", result["data"]
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Argus.Cases",
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
    )
    readable_output = f"# #{case_id}: close case\n"
    readable_output += (
        f"_Status: {result['data']['status']}, at: {result['data']['closedTime']}_"
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Argus.Case",
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
        tags=tags,
        subject=subject,
        description=description,
        customerReference=args.get("customer_reference", None),
        priority=args.get("priority", None),
        accessMode=args.get("access_mode", None),
        originEmailAddress=args.get("origin_email_address", None),
        publish=args.get("publish", None),
        defaultWatchers=args.get("default_watchers", None),
    )

    return CommandResults(
        readable_output=pretty_print_case_metadata(result),
        outputs_prefix="Argus.Case",
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
        outputs_prefix="Argus.Case",
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

    return CommandResults(
        readable_output=pretty_print_comment(
            result["data"], f"# #{case_id}: Deleted comment\n"
        ),
        outputs_prefix="Argus.Comment",
        outputs=result,
        raw_response=result,
    )


def download_attachment_command(args: Dict[str, Any]) -> Any:
    case_id = args.get("case_id", None)
    attachment_id = args.get("attachment_id", None)
    if not case_id:
        raise ValueError("case id not specified")
    if not attachment_id:
        raise ValueError("attachment id not specified")

    try:
        result = download_attachment(caseID=case_id, attachmentID=attachment_id)
    except ArgusException as e:
        return_warning(
            message=str(e),
            warning=e.parsed_resp if e.parsed_resp else None,
            exit=True
        )

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

    return CommandResults(
        readable_output=pretty_print_comment(
            result["data"], f"# #{case_id}: Updated comment\n"
        ),
        outputs_prefix="Argus.Comment",
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
        outputs_prefix="Argus.Attachments",
        outputs=result,
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
        outputs_prefix="Argus.Case",
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
        outputs_prefix="Argus.Attachments",
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
        outputs_prefix="Argus.Tags",
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

    return CommandResults(
        readable_output=pretty_print_comments(
            result["data"], f"# #{case_id}: Comments\n"
        ),
        outputs_prefix="Argus.Comments",
        outputs=result,
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
        outputs_prefix="Argus.Tags",
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
        outputs_prefix="Argus.Tags",
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
        originEmailAddress=args.get("origin_email_address", None),
        hasEvents=args.get("has_events", None),
        internalComment=args.get("internal_comment", None),
    )

    return CommandResults(
        readable_output=pretty_print_case_metadata(result),
        outputs_prefix="Argus.Case",
        outputs=result,
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
        outputs_prefix="Argus.Event",
        outputs=result,
        raw_response=result,
    )


def get_events_for_case_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    if not case_id:
        raise ValueError("case id not specified")

    result = get_events_for_case(
        caseID=case_id, limit=args.get("limit", None), offset=args.get("offset", None)
    )

    return CommandResults(
        readable_output=pretty_print_events(
            dict(result), f"# #{case_id}: Associated Events\n"
        ),
        outputs_prefix="Argus.Events",
        outputs=result,
        raw_response=result,
    )


def find_aggregated_events_command(args: Dict[str, Any]) -> CommandResults:
    # noinspection PyTypeChecker
    result = find_aggregated_events(
        skipFutureEvents=args.get("skip_future_events", None),
        exclude=args.get("exclude", None),
        locationID=argToList(args.get("location_id", None)),
        severity=argToList(args.get("severity", None)),
        customer=argToList(args.get("customer", None)),
        alarmID=argToList(args.get("alarm_id", None)),
        attackCategoryID=argToList(args.get("attack_category_id", None)),
        sourceGeoCountry=argToList(args.get("source_geo_country", None)),
        destinationGeoCountry=argToList(args.get("destination_geo_country", None)),
        geoCountry=argToList(args.get("geo_country", None)),
        properties=str_to_dict(args.get("properties", None)),
        exactMatchProperties=args.get("exact_match_properties", None),
        subCriteria=argToList(args.get("sub_criteria", None)),
        signature=argToList(args.get("signature", None)),
        lastUpdatedTimestamp=args.get("last_updated_timestamp", None),
        indexStartTime=args.get("index_start_time", None),
        indexEndTime=args.get("index_end_time", None),
        destinationIP=argToList(args.get("destination_ip", None)),
        sourceIP=argToList(args.get("source_ip", None)),
        ip=argToList(args.get("ip", None)),
        destinationPort=argToList(args.get("destination_port", None)),
        sourcePort=argToList(args.get("source_port", None)),
        port=argToList(args.get("port", None)),
        minSeverity=args.get("min_severity", None),
        maxSeverity=args.get("max_severity", None),
        limit=args.get("limit", 25),
        offset=args.get("offset", None),
        includeDeleted=args.get("include_deleted", None),
        minCount=args.get("min_count", None),
        associatedCaseID=argToList(args.get("associated_case_id", None)),
        sourceIPMinBits=args.get("source_ip_min_bits", None),
        destinationIPMinBits=args.get("destination_ip_min_bits", None),
        startTimestamp=args.get("start_timestamp", "-24hours"),
        endTimestamp=args.get("end_timestamp", "now"),
        sortBy=argToList(args.get("sort_by", None)),
        includeFlags=argToList(args.get("include_flags", None)),
        excludeFlags=argToList(args.get("exclude_flags", None)),
    )

    return CommandResults(
        readable_output=pretty_print_events(dict(result), "# Find events\n"),
        outputs_prefix="Argus.Events",
        outputs=result,
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

    return CommandResults(
        readable_output=pretty_print_events(dict(result), "# List Events\n"),
        outputs_prefix="Argus.Events",
        outputs=result,
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
    readable_output = "# Event payload\n"
    readable_output += f"Event: {event_id}, type: {result['data']['type']}\n"
    readable_output += result["data"]["payload"]

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Argus.Payload",
        outputs=result,
        raw_response=result,
    )


def get_pcap_command(args: Dict[str, Any]) -> Any:
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
    # noinspection PyTypeChecker
    result = find_n_i_d_s_events(
        skipFutureEvents=args.get("skip_future_events", None),
        exclude=args.get("exclude", None),
        eventIdentifier=argToList(args.get("event_identifier", None)),
        locationID=argToList(args.get("location_id", None)),
        severity=argToList(args.get("severity", None)),
        customer=argToList(args.get("customer", None)),
        alarmID=argToList(args.get("alarm_id", None)),
        attackCategoryID=argToList(args.get("attack_category_id", None)),
        sourceGeoCountry=argToList(args.get("source_geo_country", None)),
        destinationGeoCountry=argToList(args.get("destination_geo_country", None)),
        geoCountry=argToList(args.get("geo_country", None)),
        properties=str_to_dict(args.get("properties", None)),
        exactMatchProperties=args.get("exact_match_properties", None),
        sensorID=argToList(args.get("sensor_id", None)),
        subCriteria=argToList(args.get("sub_criteria", None)),
        signature=argToList(args.get("signature", None)),
        lastUpdatedTimestamp=args.get("last_updated_timestamp", None),
        indexStartTime=args.get("index_start_time", None),
        indexEndTime=args.get("index_end_time", None),
        destinationIP=argToList(args.get("destination_ip", None)),
        sourceIP=argToList(args.get("source_ip", None)),
        ip=argToList(args.get("ip", None)),
        destinationPort=argToList(args.get("destination_port", None)),
        sourcePort=argToList(args.get("source_port", None)),
        port=argToList(args.get("port", None)),
        minSeverity=args.get("min_severity", None),
        maxSeverity=args.get("max_severity", None),
        limit=args.get("limit", 25),
        offset=args.get("offset", None),
        includeDeleted=args.get("include_deleted", None),
        startTimestamp=args.get("start_timestamp", "-24hours"),
        endTimestamp=args.get("end_timestamp", "now"),
        sortBy=argToList(args.get("sort_by", None)),
        includeFlags=argToList(args.get("include_flags", None)),
        excludeFlags=argToList(args.get("exclude_flags", None)),
    )

    return CommandResults(
        readable_output=pretty_print_events(dict(result), "# Find NIDS Events\n"),
        outputs_prefix="Argus.NIDS",
        outputs=result,
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

    return CommandResults(
        readable_output=pretty_print_events(dict(result), "# List NIDS Events\n"),
        outputs_prefix="Argus.NIDS",
        outputs=result,
        raw_response=result,
    )


def search_records_command(args: Dict[str, Any]) -> CommandResults:
    query = args.get("query", None)
    if not query:
        raise ValueError("query not specified")
    # noinspection PyTypeChecker
    result = search_records(
        query=query,
        aggregateResult=args.get("aggregate_result", None),
        includeAnonymousResults=args.get("include_anonymous_results", None),
        rrClass=argToList(args.get("rr_class", None)),
        rrType=argToList(args.get("rr_type", None)),
        customerID=argToList(args.get("customer_id", None)),
        tlp=argToList((args.get("tlp", None))),
        limit=args.get("limit", 25),
        offset=args.get("offset", None),
    )
    return CommandResults(
        readable_output=tableToMarkdown("PDNS records", result["data"]),
        outputs_prefix="Argus.PDNS",
        outputs=result,
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
        outputs_prefix="Argus.ObservationsDomain",
        outputs=result,
        raw_response=result,
    )


def fetch_observations_for_i_p_command(args: Dict[str, Any]) -> CommandResults:
    ip = args.get("ip", None)
    if not ip:
        raise ValueError("ip not specified")

    result = fetch_observations_for_i_p(ip=ip)
    return CommandResults(
        readable_output=tableToMarkdown(f'IP observations for "{ip}"', result["data"]),
        outputs_prefix="Argus.ObservationsIP",
        outputs=result,
        raw_response=result,
    )


""" MAIN FUNCTION """


def main() -> None:
    logging.getLogger("argus_cli").setLevel("WARNING")

    first_fetch_period = parse_first_fetch(
        demisto.params().get("first_fetch_period", "-1 day")
    )

    set_argus_settings(
        demisto.params().get("api_key"),
        demisto.params().get("api_url"),
        handle_proxy(),
        demisto.params().get("insecure", None),
    )

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module_command())

        elif demisto.command() == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                last_run=demisto.getLastRun(),
                first_fetch_period=first_fetch_period,
                limit=demisto.params().get("max_fetch", 25),
                min_severity=demisto.params().get("min_severity", "low"),
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == "argus-add-case-tag":
            return_results(add_case_tag_command(demisto.args()))

        elif demisto.command() == "argus-add-comment":
            return_results(add_comment_command(demisto.args()))

        elif demisto.command() == "argus-advanced-case-search":
            return_results(advanced_case_search_command(demisto.args()))

        elif demisto.command() == "argus-close-case":
            return_results(close_case_command(demisto.args()))

        elif demisto.command() == "argus-create-case":
            return_results(create_case_command(demisto.args()))

        elif demisto.command() == "argus-delete-case":
            return_results(delete_case_command(demisto.args()))

        elif demisto.command() == "argus-delete-comment":
            return_results(delete_comment_command(demisto.args()))

        elif demisto.command() == "argus-download-attachment":
            return_results(download_attachment_command(demisto.args()))

        elif demisto.command() == "argus-edit-comment":
            return_results(edit_comment_command(demisto.args()))

        elif demisto.command() == "argus-get-attachment":
            return_results(get_attachment_command(demisto.args()))

        elif demisto.command() == "argus-get-case-metadata-by-id":
            return_results(get_case_metadata_by_id_command(demisto.args()))

        elif demisto.command() == "argus-list-case-attachments":
            return_results(list_case_attachments_command(demisto.args()))

        elif demisto.command() == "argus-list-case-tags":
            return_results(list_case_tags_command(demisto.args()))

        elif demisto.command() == "argus-list-case-comments":
            return_results(list_case_comments_command(demisto.args()))

        elif demisto.command() == "argus-remove-case-tag-by-id":
            return_results(remove_case_tag_by_id_command(demisto.args()))

        elif demisto.command() == "argus-remove-case-tag-by-key-value":
            return_results(remove_case_tag_by_key_value_command(demisto.args()))

        elif demisto.command() == "argus-update-case":
            return_results(update_case_command(demisto.args()))

        elif demisto.command() == "argus-get-event":
            return_results(get_event_command(demisto.args()))

        elif demisto.command() == "argus-get-events-for-case":
            return_results(get_events_for_case_command(demisto.args()))

        elif demisto.command() == "argus-find-aggregated-events":
            return_results(find_aggregated_events_command(demisto.args()))

        elif demisto.command() == "argus-list-aggregated-events":
            return_results(list_aggregated_events_command(demisto.args()))

        elif demisto.command() == "argus-get-payload":
            return_results(get_payload_command(demisto.args()))

        elif demisto.command() == "argus-get-pcap":
            return_results(get_pcap_command(demisto.args()))

        elif demisto.command() == "argus-find-nids-events":
            return_results(find_nids_events_command(demisto.args()))

        elif demisto.command() == "argus-list-nids-events":
            return_results(list_nids_events_command(demisto.args()))

        elif demisto.command() == "argus-pdns-search-records":
            return_results(search_records_command(demisto.args()))

        elif demisto.command() == "argus-fetch-observations-for-domain":
            return_results(fetch_observations_for_domain_command(demisto.args()))

        elif demisto.command() == "argus-fetch-observations-for-ip":
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
