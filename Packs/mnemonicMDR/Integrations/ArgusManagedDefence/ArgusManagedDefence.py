import demistomock as demisto
from CommonServerPython import *

""" IMPORTS """

import json
import urllib3
import mimetypes

import dateparser
import traceback
from typing import Any, Dict, List, Union

import logging

from argus_api import session as argus_session
from argus_api.exceptions.http import AccessDeniedException
from argus_api.lib.currentuser.v1.user import get_current_user

from argus_api.lib.cases.v2.case import (
    add_attachment,
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

from argus_api.lib.events.v1 import get_event_by_path
from argus_api.lib.events.v1.case.case import get_events_for_case
from argus_api.lib.events.v1.aggregated import (
    find_aggregated_events,
    list_aggregated_events,
)
from argus_api.lib.events.v1.payload import get_payload
from argus_api.lib.events.v1.pcap import get_pcap
from argus_api.lib.events.v1.nids import find_n_i_d_s_events, list_n_i_d_s_events

from argus_api.lib.pdns.v3.search import search_records

from argus_api.lib.reputation.v1.observation import (
    fetch_observations_for_domain,
    fetch_observations_for_i_p,
)

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
PRETTY_DATE_FORMAT = "%b %d, %Y, %H:%M:%S"
FETCH_TAG = demisto.params().get("fetch_tag")
ATTACHMENT_SUBSTRING = "_xsoar-upload"

MIRROR_DIRECTION = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}
ARGUS_STATUS_MAPPING = {
    "pendingCustomer": 0,
    "pendingSoc": 0,
    "pendingVendor": 0,
    "pendingClose": 0,
    "workingSoc": 1,
    "workingCustomer": 1,
    "closed": 2,
}
ARGUS_PRIORITY_MAPPING = {"low": 1, "medium": 2, "high": 3, "critical": 4}

""" HELPER FUNCTIONS """


def set_argus_settings(
    api_key: str, base_url: str = None, proxies: dict = None, verify: bool = None
):
    argus_session.api_key = api_key
    argus_session.base_url = base_url
    argus_session.proxies = proxies
    argus_session.verify = verify


def argus_priority_to_demisto_severity(priority: str) -> int:
    return ARGUS_PRIORITY_MAPPING.get(priority, 0)


def argus_status_to_demisto_status(status: str) -> int:
    return ARGUS_STATUS_MAPPING.get(status, 0)


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


def pretty_print_case_metadata_html(case: dict, title: str = None) -> str:
    string = title if title else f"<h2>#{case['id']}: {case['subject']}</h2>"
    string += "<em>Priority: {}, status: {}, last updated: {}</em><br>".format(
        case["priority"], case["status"], pretty_print_date(case["lastUpdatedTime"])
    )
    string += "Reported by {} at {}<br><br>".format(
        case["publishedByUser"]["name"], pretty_print_date(case["publishedTime"])
    )
    string += case["description"]
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


def pretty_print_comment_html(comment: dict, title: str = None) -> str:
    string = f"<h2>{title}</h2>" if title else ""
    string += "<small>"
    string += f"<em>Added by {comment['addedByUser']['userName']} at "
    string += f"{pretty_print_date(comment['addedTime'])}</em><br>"
    string += (
        f"<em>Last updated {pretty_print_date(comment['lastUpdatedTime'])}</em><br>"
        if comment["lastUpdatedTime"]
        else ""
    )
    if comment["associatedAttachments"]:
        string += "<em>Associated attachment(s): "
        for attachment in comment["associatedAttachments"]:
            string += f"{attachment.get('name', '')} "
        string += "</em><br>"
    string += "</small>"
    string += f"{comment['comment']}"
    return string


def pretty_print_comments(comments: list, title: str = None) -> str:
    string = title if title else ""
    for comment in comments:
        string += pretty_print_comment(comment)
    return string


def pretty_print_comments_html(comments: list, title: str = None) -> str:
    string = title if title else ""
    for comment in comments:
        string += pretty_print_comment_html(comment)
        string += "<hr>"
    return string


def pretty_print_events(result: dict, title: str = None) -> str:
    string = title if title else ""
    string += "_Count: {}, showing {} events, from {} to {}_\n".format(
        result["count"], result["size"], result["offset"], result["limit"]
    )
    string += tableToMarkdown("Events", result["data"])
    return string


def pretty_print_attachment_metadata(result: dict, title: str = None) -> str:
    string = title if title else ""
    string += f"#### *{result['data']['addedByUser']['userName']} - {result['data']['addedTime']}*\n"
    string += f"{result['data']['name']} ({result['data']['mimeType']}, {result['data']['size']} bytes)\n\n"
    string += f"_id: {result['data']['id']}_\n"
    return string


def add_attachment_helper(case_id: int, file_id: str) -> dict:
    path_res = demisto.getFilePath(file_id)
    full_file_name = path_res.get("name")
    file_name, file_extension = os.path.splitext(full_file_name)
    file_name = f"{file_name}{ATTACHMENT_SUBSTRING}{file_extension}"
    mime_type = mimetypes.guess_type(full_file_name)
    if not mime_type[0]:
        error = f"File {full_file_name} mimetype unknown, not sending. Consider zipping file."
        demisto.error(error)
        return {"error": error}
    with open(path_res.get("path"), "rb") as file_to_send:
        # noinspection PyTypeChecker
        return add_attachment(
            caseID=case_id,
            name=file_name,
            mimeType=mime_type[0],
            data=b64_encode(file_to_send.read()),
        )


""" COMMAND FUNCTIONS """


def test_module_command() -> str:
    response = get_current_user()
    if response["responseCode"] == 200:
        return "ok"
    return (
        f"Unable to communicate with Argus API {response['responseCode']}, {response}"
    )


def fetch_incidents(
    last_run: dict,
    first_fetch_period: str,
    limit: int = 25,
    min_severity: str = "low",
    integration_instance: str = "",
    mirror_direction: str = "None",
    mirror_tags: str = "argus_mirror",
    exclude_tag: str = "",
):
    start_timestamp = last_run.get("start_time") if last_run else None
    # Exclude closed cases
    sub_criteria = [{"exclude": True, "status": ["closed"]}]
    # Exclude cases with {key} or {key: value} tags
    if exclude_tag:
        tag_list = exclude_tag.strip().split(",")
        if len(tag_list) == 1:
            sub_criteria.append({"exclude": True, "tag": {"key": tag_list[0]}})
        elif len(tag_list) == 2:
            sub_criteria.append(
                {"exclude": True, "tag": {"key": tag_list[0], "values": tag_list[1]}}
            )
    # noinspection PyTypeChecker
    result = advanced_case_search(
        startTimestamp=start_timestamp if start_timestamp else first_fetch_period,
        endTimestamp="now",
        limit=limit,
        sortBy=["createdTimestamp"],
        priority=build_argus_priority_from_min_severity(min_severity),
        subCriteria=sub_criteria,
        timeFieldStrategy=["createdTimestamp"],
    )
    incidents = []
    for case in result.get("data", []):
        case["xsoar_mirroring"] = {
            "dbotMirrorId": str(case["id"]),
            "dbotMirrorInstance": integration_instance,
            "dbotMirrorDirection": MIRROR_DIRECTION[mirror_direction],
            "dbotMirrorTags": argToList(mirror_tags),
        }
        case["url"] = f"https://portal.mnemonic.no/spa/case/view/{case['id']}"
        incident = {
            "name": f"#{case['id']}: {case['subject']}",
            "occurred": case["createdTime"],
            "severity": argus_priority_to_demisto_severity(case["priority"]),
            "status": argus_status_to_demisto_status(case["status"]),
            "details": json.dumps(case),
            "rawJSON": json.dumps(case),
        }
        incidents.append(incident)

    if result.get("data", []):
        last_run["start_time"] = str(result.get("data")[-1]["createdTimestamp"] + 1)

    return last_run, incidents


def get_remote_data_command(
    args: Dict[str, Any],
    integration_instance: str = "",
    mirror_direction: str = "None",
    mirror_tags: str = "argus_mirror",
) -> GetRemoteDataResponse:
    remote_args = GetRemoteDataArgs(args)
    case_id = remote_args.remote_incident_id
    if not case_id:
        case_id = args.get("id", "")
    if not case_id:
        raise ValueError("case id not found")
    demisto.debug(f"Getting update for remote [{case_id}]")

    last_mirror_update = dateparser.parse(remote_args.last_update)
    if not last_mirror_update:
        last_mirror_update = dateparser.parse(args.get("lastUpdate", ""))
    if not last_mirror_update:
        raise ValueError("last update not found")
    demisto.debug(f"Getting update with last update [{last_mirror_update}]")

    case = get_case_metadata_by_id(id=int(case_id)).get("data", {})

    # There are no updates to case, return empty
    if last_mirror_update > dateparser.parse(case.get("lastUpdatedTime", "")):  # type: ignore
        return GetRemoteDataResponse({}, [])

    entries = []
    last_update_timestamp = date_time_to_epoch_milliseconds(last_mirror_update)

    # Update status and severity (updates whether there are changes or not)
    entries.append(
        {"severity": argus_priority_to_demisto_severity(case.get("priority"))}
    )
    entries.append({"arguscasestatus": case.get("status")})
    entries.append({"status": argus_status_to_demisto_status(case.get("status"))})

    # Add new attachments
    case_attachments = list_case_attachments(caseID=int(case_id)).get("data", [])
    for attachment in case_attachments:
        if ATTACHMENT_SUBSTRING in attachment["name"]:  # file already uploaded by xsoar
            demisto.debug(
                f"Ignoring file {attachment['name']} "
                f"since it contains {ATTACHMENT_SUBSTRING}"
            )
        elif last_update_timestamp < attachment.get("addedTimestamp", 0):
            entries.append(
                fileResult(
                    attachment["name"],
                    download_attachment(
                        caseID=int(case_id), attachmentID=attachment["id"]
                    ).content,
                )
            )

    # Attach comments as notes
    case_comments = list_case_comments(caseID=int(case_id)).get("data", [])
    for comment in case_comments:
        # New comment
        if last_update_timestamp < comment.get("addedTimestamp", 0):
            entries.append(
                {
                    "Note": True,
                    "Type": entryTypes["note"],
                    "ContentsFormat": formats["html"],  # type: ignore
                    "Contents": pretty_print_comment_html(comment),  # type: ignore
                }
            )
        # Existing comment has been updated
        elif (
            comment.get("addedTimestamp", 0)
            < last_update_timestamp
            < comment.get("lastUpdatedTimestamp", "")
        ):
            entries.append(
                {
                    "Note": True,
                    "Type": entryTypes["note"],
                    "ContentsFormat": formats["html"],  # type: ignore
                    "Contents": (pretty_print_comment_html(comment, "Comment updated")),  # type: ignore
                }
            )

    # Re-attach xsoar mirroring tags, otherwise mirroring breaks
    case["xsoar_mirroring"] = {
        "dbotMirrorId": str(case["id"]),
        "dbotMirrorInstance": integration_instance,
        "dbotMirrorDirection": MIRROR_DIRECTION[mirror_direction],
        "dbotMirrorTags": argToList(mirror_tags),
    }

    # Close case?
    close_incident = demisto.params().get("close_incident", True)
    if case.get("status", "") == "closed" and close_incident:
        entries.append(
            {
                "Type": EntryType.NOTE,
                "ContentsFormat": EntryFormat.JSON,  # type: ignore
                "Contents": {  # type: ignore
                    "dbotIncidentClose": True,
                    "closeReason": "Argus Case closed",
                    "closeNotes": "Argus Case was marked as closed remotely, incident closed.",
                },
            }
        )

    return GetRemoteDataResponse(case, entries)


def update_remote_system_command(args: Dict[str, Any]) -> CommandResults:
    parsed_args = UpdateRemoteSystemArgs(args)
    if parsed_args.delta:
        demisto.debug(
            f"Got the following delta keys {str(list(parsed_args.delta.keys()))}"
        )
    demisto.debug(
        f"Sending incident with remote ID [{parsed_args.remote_incident_id}] to remote system\n"
    )

    if parsed_args.incident_changed and parsed_args.delta:
        demisto.debug(f"Incident {parsed_args.remote_incident_id} changed, updating")
        to_update = {}
        for key, value in parsed_args.delta.items():
            # Allow changing status of case from XSOAR layout
            if key == "arguscasestatus":
                if value in ARGUS_STATUS_MAPPING.keys():
                    to_update["status"] = value
            # Allow changing argus priority based upon XSOAR severity
            elif key == "severity":
                for priority, severity in ARGUS_PRIORITY_MAPPING.items():
                    if severity == value:
                        to_update["priority"] = priority
                        break

        if to_update:
            updates = "<b>Following keys have been updated by XSOAR</b><br>"
            for key, value in to_update.items():
                updates += f"{key}: {value}<br>"
            to_update["comment"] = updates
            to_update["internal_comment"] = True

        update_case(
            id=parsed_args.remote_incident_id,
            status=to_update.get("status"),
            priority=to_update.get("priority"),
            comment=to_update.get("comment"),
            internalComment=to_update.get("internal_comment"),
        )
    else:
        demisto.debug(
            f"Skipping updating remote incident fields [{parsed_args.remote_incident_id}] as it is "
            f"not new nor changed."
        )

    # Send over comments and new files
    if parsed_args.entries:
        for entry in parsed_args.entries:
            demisto.debug(f'Sending entry {entry.get("id")}')
            append_demisto_entry_to_argus_case(
                int(parsed_args.remote_incident_id), entry
            )

    # Close incident if relevant
    close_argus_case = demisto.params().get("close_argus_case", True)
    if parsed_args.inc_status == IncidentStatus.DONE and close_argus_case:
        demisto.debug(f"Closing remote incident {parsed_args.remote_incident_id}")
        close_case(
            caseID=parsed_args.remote_incident_id,
            comment=(
                f"<h3>Case closed by XSOAR</h3>"
                f"<b>Reason:</b> {parsed_args.data.get('closeReason')}<br>"
                f"<b>Closing notes:</b><br>{parsed_args.data.get('closeNotes')}"
            ),
        )
    return parsed_args.remote_incident_id


def append_demisto_entry_to_argus_case(case_id: int, entry: Dict[str, Any]) -> None:
    demisto.debug(f"Appending entry to case {case_id}: {str(entry)}")
    if entry.get("type") == 1:  # type note / chat
        comment = "<h3>Note mirrored from XSOAR</h3>"
        comment += (
            f"<i>Added by {entry.get('user')} at "
            f"{pretty_print_date(entry.get('created'))}</i><br><br>"
        )
        comment += str(entry.get("contents"))
        add_comment(caseID=case_id, comment=comment)
    elif entry.get("type") == 3:  # type file
        add_attachment_helper(case_id, str(entry.get("id")))


def add_attachment_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    file_id = args.get("file_id")
    if not case_id:
        raise ValueError("case_id not specified")
    if not file_id:
        raise ValueError("file_id not specified")

    result = add_attachment_helper(case_id, file_id)
    if "error" in result.keys():
        raise Exception(result["error"])

    readable_output = pretty_print_attachment_metadata(
        result, f"# #{case_id}: attachment metadata\n"
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Argus.Attachments",
        outputs=result,
        raw_response=result,
    )


def add_case_tag_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    key = args.get("key")
    value = args.get("value")
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
    case_id = args.get("case_id")
    comment = args.get("comment")
    if not case_id:
        raise ValueError("case_id not specified")
    if not comment:
        raise ValueError("comment not specified")

    result = add_comment(
        caseID=case_id,
        comment=comment,
        asReplyTo=args.get("as_reply_to"),
        internal=args.get("internal"),
        originEmailAddress=args.get("origin_email_address"),
        associatedAttachmentID=args.get("associated_attachment_id"),
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
        startTimestamp=args.get("start_timestamp"),
        endTimestamp=args.get("end_timestamp"),
        limit=args.get("limit"),
        offset=args.get("offset"),
        includeDeleted=args.get("include_deleted"),
        subCriteria=argToList(args.get("sub_criteria")),
        exclude=args.get("exclude"),
        required=args.get("required"),
        customerID=argToList(args.get("customer_id")),
        caseID=argToList(args.get("case_id")),
        customer=argToList(args.get("customer")),
        type=argToList(args.get("case_type")),
        service=argToList(args.get("service")),
        category=argToList(args.get("category")),
        status=argToList(args.get("status")),
        priority=argToList(args.get("priority")),
        assetID=argToList(args.get("asset_id")),
        tag=argToList(args.get("tag")),
        workflow=argToList(args.get("workflow")),
        field=argToList(args.get("field")),
        keywords=argToList(args.get("keywords")),
        timeFieldStrategy=argToList(args.get("time_field_strategy")),
        timeMatchStrategy=args.get("time_match_strategy"),
        keywordFieldStrategy=argToList(args.get("keyword_field_strategy")),
        keywordMatchStrategy=args.get("keyword_match_strategy"),
        user=argToList(args.get("user")),
        userFieldStrategy=argToList(args.get("user_field_strategy")),
        userAssigned=args.get("user_assigned"),
        techAssigned=args.get("tech_assigned"),
        includeWorkflows=args.get("include_workflows"),
        includeDescription=args.get("include_description"),
        accessMode=argToList(args.get("access_mode")),
        explicitAccess=argToList(args.get("explicit_access")),
        sortBy=argToList(args.get("sort_by")),
        includeFlags=argToList(args.get("include_flags")),
        excludeFlags=argToList(args.get("exclude_flags")),
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
    case_id = args.get("case_id")
    if not case_id:
        raise ValueError("case_id not specified")

    result = close_case(
        caseID=case_id,
        comment=args.get("comment"),
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
    subject = args.get("subject")
    description = args.get("description")
    service = args.get("service")
    case_type = args.get("type")
    tags = args.get("tags")
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
        customer=args.get("customer"),
        service=service,
        category=args.get("category"),
        type=case_type,
        status=args.get("status"),
        tags=tags,
        subject=subject,
        description=description,
        customerReference=args.get("customer_reference"),
        priority=args.get("priority"),
        accessMode=args.get("access_mode"),
        originEmailAddress=args.get("origin_email_address"),
        publish=args.get("publish"),
        defaultWatchers=args.get("default_watchers"),
    )

    return CommandResults(
        readable_output=pretty_print_case_metadata(result),
        outputs_prefix="Argus.Case",
        outputs=result,
        raw_response=result,
    )


def delete_case_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
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
    case_id = args.get("case_id")
    comment_id = args.get("comment_id")
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


def download_attachment_by_filename_command(args: Dict[str, Any]) -> dict:
    case_id = args.get("case_id")
    file_name = args.get("file_name")
    if case_id is None:
        raise ValueError("case id not specified")
    if not file_name:
        raise ValueError("file name not given")
    attachment_id = ""
    case_attachments = list_case_attachments(caseID=case_id).get("data", [])
    for attachment in case_attachments:
        if file_name in attachment.get("name", ""):
            attachment_id = attachment.get("id", "")
            file_name = attachment.get("name", "")
            break
    if not attachment_id:
        raise ValueError("file name not found in case")

    result = download_attachment(caseID=case_id, attachmentID=attachment_id)

    return fileResult(file_name, result.content)


def download_attachment_command(args: Dict[str, Any]) -> dict:
    case_id = args.get("case_id")
    attachment_id = args.get("attachment_id")
    file_name = args.get("file_name", attachment_id)
    if case_id is None:
        raise ValueError("case id not specified")
    if not attachment_id:
        raise ValueError("attachment id not given")

    result = download_attachment(caseID=case_id, attachmentID=attachment_id)

    return fileResult(file_name, result.content)


def download_case_attachments_command(args: Dict[str, Any]) -> List[Dict]:
    case_id = args.get("case_id")
    if case_id is None:
        raise ValueError("case id not specified")
    case_attachments = list_case_attachments(caseID=int(case_id)).get("data", [])
    incident_files = []
    for attachment in case_attachments:
        incident_files.append(
            fileResult(
                attachment["name"],
                download_attachment(
                    caseID=int(case_id), attachmentID=attachment["id"]
                ).content,
            )
        )
    return incident_files


def edit_comment_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    comment_id = args.get("comment_id")
    comment = args.get("comment")
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
    case_id = args.get("case_id")
    attachment_id = args.get("attachment_id")
    if not case_id:
        raise ValueError("case id not specified")
    if not attachment_id:
        raise ValueError("attachment id not specified")

    result = get_attachment(caseID=case_id, attachmentID=attachment_id)

    return CommandResults(
        readable_output=pretty_print_attachment_metadata(
            result, f"# #{case_id}: attachment metadata\n"
        ),
        outputs_prefix="Argus.Attachments",
        outputs=result,
        raw_response=result,
    )


def get_case_metadata_by_id_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    if not case_id:
        raise ValueError("case id not specified")

    result = get_case_metadata_by_id(id=case_id, skipRedirect=args.get("skip_redirect"))

    return CommandResults(
        readable_output=pretty_print_case_metadata(result),
        outputs_prefix="Argus.Case",
        outputs=result,
        raw_response=result,
    )


def print_case_metadata_by_id_command(args: Dict[str, Any]) -> Dict:
    case_id = args.get("case_id")
    if not case_id:
        raise ValueError("case id not specified")

    result = get_case_metadata_by_id(id=case_id, skipRedirect=args.get("skip_redirect"))

    return {
        "ContentsFormat": formats["html"],
        "Type": EntryType.NOTE,
        "Contents": pretty_print_case_metadata_html(result.get("data")),
        # "Note": True,
    }


def list_case_attachments_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    if not case_id:
        raise ValueError("case_id not specified")

    result = list_case_attachments(
        caseID=case_id, limit=args.get("limit"), offset=args.get("offset")
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
    case_id = args.get("case_id")
    if not case_id:
        raise ValueError("case_id not specified")

    result = list_case_tags(
        caseID=case_id, limit=args.get("limit"), offset=args.get("offset")
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


def print_case_comments_command(args: Dict[str, Any]) -> List[Dict]:
    case_id = args.get("case_id")
    sort_by = args.get("sort_by")
    if not case_id:
        raise ValueError("case_id not specified")
    if sort_by:
        sort_by = ["addedTimestamp"] if sort_by == "ascending" else ["-addedTimestamp"]

    result = list_case_comments(
        caseID=case_id,
        beforeComment=args.get("before_comment"),
        afterComment=args.get("after_comment"),
        offset=args.get("offset"),
        limit=args.get("limit"),
        sortBy=sort_by,
    )
    notes = []
    for comment in result.get("data", []):
        notes.append(
            {
                "ContentsFormat": formats["html"],
                "Type": entryTypes["note"],
                "Contents": pretty_print_comment_html(comment),
                "Note": True,
            }
        )
    return notes


def list_case_comments_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id")
    sort_by = args.get("sort_by")
    if not case_id:
        raise ValueError("case_id not specified")
    if sort_by:
        sort_by = ["addedTimestamp"] if sort_by == "ascending" else ["-addedTimestamp"]

    result = list_case_comments(
        caseID=case_id,
        beforeComment=args.get("before_comment"),
        afterComment=args.get("after_comment"),
        offset=args.get("offset"),
        limit=args.get("limit"),
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
    case_id = args.get("case_id")
    tag_id = args.get("tag_id")
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
    case_id = args.get("case_id")
    key = args.get("key")
    value = args.get("value")
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
    case_id = args.get("case_id")
    if not case_id:
        raise ValueError("case id not specified")

    result = update_case(
        id=case_id,
        subject=args.get("subject"),
        description=args.get("description"),
        status=args.get("status"),
        priority=args.get("priority"),
        category=args.get("category"),
        reporter=args.get("reporter"),
        assignedUser=args.get("assigned_user"),
        assignedTech=args.get("assigned_tech"),
        customerReference=args.get("customer_reference"),
        comment=args.get("comment"),
        originEmailAddress=args.get("origin_email_address"),
        hasEvents=args.get("has_events"),
        internalComment=args.get("internal_comment"),
    )

    return CommandResults(
        readable_output=pretty_print_case_metadata(result),
        outputs_prefix="Argus.Case",
        outputs=result,
        raw_response=result,
    )


def get_event_command(args: Dict[str, Any]) -> CommandResults:
    event_type = args.get("type")
    timestamp = args.get("timestamp")
    customer_id = args.get("customer_id")
    event_id = args.get("event_id")
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
    case_id = args.get("case_id")
    if not case_id:
        raise ValueError("case id not specified")

    result = get_events_for_case(
        caseID=case_id, limit=args.get("limit"), offset=args.get("offset")
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
        skipFutureEvents=args.get("skip_future_events"),
        exclude=args.get("exclude"),
        locationID=argToList(args.get("location_id")),
        severity=argToList(args.get("severity")),
        customer=argToList(args.get("customer")),
        alarmID=argToList(args.get("alarm_id")),
        attackCategoryID=argToList(args.get("attack_category_id")),
        sourceGeoCountry=argToList(args.get("source_geo_country")),
        destinationGeoCountry=argToList(args.get("destination_geo_country")),
        geoCountry=argToList(args.get("geo_country")),
        properties=str_to_dict(args.get("properties", "")),
        exactMatchProperties=args.get("exact_match_properties"),
        subCriteria=argToList(args.get("sub_criteria")),
        signature=argToList(args.get("signature")),
        lastUpdatedTimestamp=args.get("last_updated_timestamp"),
        indexStartTime=args.get("index_start_time"),
        indexEndTime=args.get("index_end_time"),
        destinationIP=argToList(args.get("destination_ip")),
        sourceIP=argToList(args.get("source_ip")),
        ip=argToList(args.get("ip")),
        destinationPort=argToList(args.get("destination_port")),
        sourcePort=argToList(args.get("source_port")),
        port=argToList(args.get("port")),
        minSeverity=args.get("min_severity"),
        maxSeverity=args.get("max_severity"),
        limit=args.get("limit", 25),
        offset=args.get("offset"),
        includeDeleted=args.get("include_deleted"),
        minCount=args.get("min_count"),
        associatedCaseID=argToList(args.get("associated_case_id")),
        sourceIPMinBits=args.get("source_ip_min_bits"),
        destinationIPMinBits=args.get("destination_ip_min_bits"),
        startTimestamp=args.get("start_timestamp", "-24hours"),
        endTimestamp=args.get("end_timestamp", "now"),
        sortBy=argToList(args.get("sort_by")),
        includeFlags=argToList(args.get("include_flags")),
        excludeFlags=argToList(args.get("exclude_flags")),
    )

    return CommandResults(
        readable_output=pretty_print_events(dict(result), "# Find events\n"),
        outputs_prefix="Argus.Events",
        outputs=result,
        raw_response=result,
    )


def list_aggregated_events_command(args: Dict[str, Any]) -> CommandResults:
    result = list_aggregated_events(
        customerID=args.get("customer_id"),
        signature=args.get("signature"),
        ip=args.get("ip"),
        startTimestamp=args.get("start_timestamp"),
        endTimestamp=args.get("end_timestamp"),
        limit=args.get("limit"),
        offset=args.get("offset"),
    )

    return CommandResults(
        readable_output=pretty_print_events(dict(result), "# List Events\n"),
        outputs_prefix="Argus.Events",
        outputs=result,
        raw_response=result,
    )


def get_payload_command(args: Dict[str, Any]) -> CommandResults:
    event_type = args.get("type")
    timestamp = args.get("timestamp")
    customer_id = args.get("customer_id")
    event_id = args.get("event_id")
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
    event_type = args.get("type")
    timestamp = args.get("timestamp")
    customer_id = args.get("customer_id")
    event_id = args.get("event_id")
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
        skipFutureEvents=args.get("skip_future_events"),
        exclude=args.get("exclude"),
        eventIdentifier=argToList(args.get("event_identifier")),
        locationID=argToList(args.get("location_id")),
        severity=argToList(args.get("severity")),
        customer=argToList(args.get("customer")),
        alarmID=argToList(args.get("alarm_id")),
        attackCategoryID=argToList(args.get("attack_category_id")),
        sourceGeoCountry=argToList(args.get("source_geo_country")),
        destinationGeoCountry=argToList(args.get("destination_geo_country")),
        geoCountry=argToList(args.get("geo_country")),
        properties=str_to_dict(args.get("properties", "")),
        exactMatchProperties=args.get("exact_match_properties"),
        sensorID=argToList(args.get("sensor_id")),
        subCriteria=argToList(args.get("sub_criteria")),
        signature=argToList(args.get("signature")),
        lastUpdatedTimestamp=args.get("last_updated_timestamp"),
        indexStartTime=args.get("index_start_time"),
        indexEndTime=args.get("index_end_time"),
        destinationIP=argToList(args.get("destination_ip")),
        sourceIP=argToList(args.get("source_ip")),
        ip=argToList(args.get("ip")),
        destinationPort=argToList(args.get("destination_port")),
        sourcePort=argToList(args.get("source_port")),
        port=argToList(args.get("port")),
        minSeverity=args.get("min_severity"),
        maxSeverity=args.get("max_severity"),
        limit=args.get("limit", 25),
        offset=args.get("offset"),
        includeDeleted=args.get("include_deleted"),
        startTimestamp=args.get("start_timestamp", "-24hours"),
        endTimestamp=args.get("end_timestamp", "now"),
        sortBy=argToList(args.get("sort_by")),
        includeFlags=argToList(args.get("include_flags")),
        excludeFlags=argToList(args.get("exclude_flags")),
    )

    return CommandResults(
        readable_output=pretty_print_events(dict(result), "# Find NIDS Events\n"),
        outputs_prefix="Argus.NIDS",
        outputs=result,
        raw_response=result,
    )


def list_nids_events_command(args: Dict[str, Any]) -> CommandResults:
    result = list_n_i_d_s_events(
        customerID=args.get("customer_id"),
        signature=args.get("signature"),
        ip=args.get("ip"),
        startTimestamp=args.get("start_timestamp"),
        endTimestamp=args.get("end_timestamp"),
        limit=args.get("limit"),
        offset=args.get("offset"),
    )

    return CommandResults(
        readable_output=pretty_print_events(dict(result), "# List NIDS Events\n"),
        outputs_prefix="Argus.NIDS",
        outputs=result,
        raw_response=result,
    )


def search_records_command(args: Dict[str, Any]) -> CommandResults:
    query = args.get("query")
    if not query:
        raise ValueError("query not specified")
    # noinspection PyTypeChecker
    result = search_records(
        query=query,
        aggregateResult=args.get("aggregate_result"),
        includeAnonymousResults=args.get("include_anonymous_results"),
        rrClass=argToList(args.get("rr_class")),
        rrType=argToList(args.get("rr_type")),
        customerID=argToList(args.get("customer_id")),
        tlp=argToList((args.get("tlp"))),
        limit=args.get("limit", 25),
        offset=args.get("offset"),
    )
    return CommandResults(
        readable_output=tableToMarkdown("PDNS records", result["data"]),
        outputs_prefix="Argus.PDNS",
        outputs=result,
        raw_response=result,
    )


def fetch_observations_for_domain_command(args: Dict[str, Any]) -> CommandResults:
    fqdn = args.get("fqdn")
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
    ip = args.get("ip")
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
        demisto.params().get("first_fetch", "-1 day")
    )

    set_argus_settings(
        demisto.params().get("api_key"),
        demisto.params().get("api_url"),
        handle_proxy(),
        demisto.params().get("insecure"),
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
                min_severity=demisto.params().get("min_severity", "low").lower(),
                integration_instance=demisto.integrationInstance(),
                mirror_direction=demisto.params().get("mirror_direction", "None"),
                mirror_tags=demisto.params().get("mirror_tag"),
                exclude_tag=demisto.params().get("exclude_tag"),
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == "get-remote-data":
            return_results(
                get_remote_data_command(
                    demisto.args(),
                    integration_instance=demisto.integrationInstance(),
                    mirror_direction=demisto.params().get("mirror_direction", "None"),
                    mirror_tags=demisto.params().get("mirror_tag"),
                )
            )

        if demisto.command() == "get-modified-remote-data":
            # Hotfix for mirroring issues.
            raise NotImplementedError('The "get-modified-remote-data" command is not implemented')

        elif demisto.command() == "argus-add-attachment":
            return_results(add_attachment_command(demisto.args()))

        elif demisto.command() == "update-remote-system":
            return_results(update_remote_system_command(demisto.args()))

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

        elif demisto.command() == "argus-download-attachment-by-filename":
            return_results(download_attachment_by_filename_command(demisto.args()))

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

        elif demisto.command() == "argus-print-case-comments":
            return_results(print_case_comments_command(demisto.args()))

        elif demisto.command() == "argus-print-case-metadata-by-id":
            return_results(print_case_metadata_by_id_command(demisto.args()))

        elif demisto.command() == "argus-download-case-attachments":
            return_results(download_case_attachments_command(demisto.args()))

    # Log exceptions and return errors
    except AccessDeniedException as denied:
        demisto.info(denied.message)
        return_warning(denied.message)
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
