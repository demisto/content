from copy import deepcopy
from datetime import datetime, UTC
from typing import Any, Final, TypedDict, NewType, cast
from collections.abc import Generator
from collections import Counter

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3


DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
STATUS_MSG_TYPES = {
    "IncidentMuted",
    "IncidentUnmuted",
    "IncidentClosed",
    "IncidentCommentAdded",
}
NEW_MESSAGE_TYPE = "NewIncidentCreated"
UPDATE_MESSAGE_TYPE = "IncidentUpdated"

PERMITTED_MESSAGE_TYPES = {
    NEW_MESSAGE_TYPE,
    UPDATE_MESSAGE_TYPE,
}.union(STATUS_MSG_TYPES)

IncidentID = NewType("IncidentID", str)


class SourceRecord(TypedDict):
    event_type: str
    raw: dict


CollectedIncident = dict[IncidentID, SourceRecord]


class LabelDictType(TypedDict):
    id: int
    name: str
    relevance: int


class UserDictType(TypedDict):
    id: int
    role: str
    email: str
    name: str
    time_zone: str
    deactivated: bool


params = demisto.params()
MIRROR_DIRECTION = {
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}.get(params.get("mirror_direction"))
MIRROR_TAGS = params.get("mirror_tags") or []
INTEGRATION_INSTANCE = demisto.integrationInstance()
COMMENT_MARK = "Operated by Lumu Integration with Cortex Xsoar:"


def format_description_comment(incident_id: str, first_event_timestamp: str, source_description, adversaries_types: list[str]):
    adversaries = ", ".join(adversaries_types)

    return f"""<div class=\"sdp-ze-default-wrapper\" style=\"font-family: Roboto, Arial; font-size: 10pt\">
<div>Lumu has detected an incident of type [{adversaries}] with description: {source_description} at {first_event_timestamp}<br/>
</div><div><br/></div>
<div>See more at:&nbsp;<a href=\"https://portal.lumu.io/compromise/incidents/show/{incident_id}/detections\"
 target=\"_blank\" rel=\"noopener noreferrer\">https://portal.lumu.io/compromise/incidents/show/{incident_id}/detections</a><br/></div>
</div>"""


def format_description_plain_text(
    incident_id: str, first_event_timestamp: str, source_description: str, adversaries_types: list[str]
) -> str:
    adversaries = ", ".join(adversaries_types)
    return (
        f"Lumu has detected an incident of type [{adversaries}] with description: {source_description} "
        f"at {first_event_timestamp}\n\nSee more at: https://portal.lumu.io/compromise/incidents/show/{incident_id}/detections"
    )


def format_comment(event_type: str, username: str, status_timestamp: str, comment: str) -> str:
    return (
        f"Incident {re.sub('incident', '', event_type, flags=re.IGNORECASE)} "
        f"by {username} on {datetime.fromisoformat(status_timestamp):%B %d, %Y %I:%M %p %Z} "
        f"Comment: {comment}"
    )


def format_updates_comment(incident: dict, labels_cache: dict) -> str:
    total_events = incident.get("totalEvents", 1)

    affected_targets_users = {
        target.get("name", "") for target in incident.get("targetsSamples", []) if target.get("type", "") == "user"
    }
    affected_targets_endpoints = {
        target.get("name", "") for target in incident.get("targetsSamples", []) if target.get("type", "") != "user"
    }

    affected_environments_users = {
        target.get("realm", "Unknown Env") for target in incident.get("targetsSamples", []) if target.get("type", "") == "user"
    }
    affected_environments_endpoints = {
        labels_cache.get(str(target.get("label", "0")), {"name": "Unknown Label"})["name"]
        for target in incident.get("targetsSamples", [])
        if target.get("type", "") != "user"
    }

    offenders: set[str] = {offender.get("value") or offender.get("name", "") for offender in incident.get("offendersSamples", [])}
    offenders = {offender.replace(".", "[.]") for offender in offenders}

    affected_targets_endpoints_block = f"""
            <div>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; Endpoints: {len(affected_targets_endpoints)} <br/></div>
    <div>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; {", ".join(affected_targets_endpoints)} <br/></div>"""

    affected_targets_users_block = f"""<div>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; Users: {len(affected_targets_users)} <br/>
    </div><div>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; {", ".join(affected_targets_users)} <br/></div>"""

    affected_environments_endpoints_block = f"""
            <div>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; Label: {", ".join(affected_environments_endpoints)} <br/></div>"""

    affected_environments_users_block = f"""
            <div>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; Realm: {", ".join(affected_environments_users)} <br/></div>"""

    offenders_block = f"""
    <div>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; {", ".join(offenders)} <br/></div>"""
    return f"""<div class=\"sdp-ze-default-wrapper\" style=\"font-family: Roboto, Arial; font-size: 10pt\">
<div><br/></div>
<div><b>Incident information updated by Lumu.</b><br/></div>
<div>Incident now has...<br/></div>
<div>&nbsp; &nbsp; &nbsp; Events: {total_events}<br/></div>
<div>&nbsp; &nbsp; &nbsp; -- Affected Entities --<br/></div>
{affected_targets_endpoints_block if affected_targets_endpoints else ""}
{affected_targets_users_block if affected_targets_users else ""}
<div>&nbsp; &nbsp; &nbsp; -- Affected Environment --<br/></div>
{affected_environments_endpoints_block if affected_environments_endpoints else ""}
{affected_environments_users_block if affected_environments_users else ""}
<div>&nbsp; &nbsp; &nbsp; -- Offenders --<br/></div>
{offenders_block if offenders_block else ""}
</div>
"""


class Client(BaseClient):
    def __init__(self, server_url: str, verify: bool, proxy: bool, headers: dict[str, str], api_key: str):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=None)
        self.api_key = api_key

    def list_all_labels(
        self,
        *,
        items_per_page: int = 100,
        start_page: int = 1,
        max_pages: int | None = None,
    ) -> Generator[LabelDictType, None, None]:
        page = start_page
        pages_fetched = 0

        while True:
            payload = self.retrieve_labels_request(page=page, items=items_per_page)

            labels = payload.get("labels", [])
            if not labels:
                break

            yield from labels

            pages_fetched += 1
            if max_pages is not None and pages_fetched >= max_pages:
                break

            pagination = payload.get("paginationInfo", {})
            returned_items = pagination.get("items", len(labels))

            if returned_items < items_per_page:
                break

            page += 1

    def list_all_users(
        self,
        *,
        items_per_page: int = 100,
        start_page: int = 1,
        max_pages: int | None = None,
    ) -> Generator[UserDictType, None, None]:
        page = start_page
        pages_fetched = 0

        while True:
            payload = self.retrieve_users_request(page=page, items=items_per_page)

            users = payload.get("users", [])
            if not users:
                break

            yield from users

            pages_fetched += 1
            if max_pages is not None and pages_fetched >= max_pages:
                break

            pagination = payload.get("paginationInfo", {})
            returned_items = pagination.get("items", len(users))

            if returned_items < items_per_page:
                break

            page += 1

    def _build_params(self, **kwargs: Any) -> dict[str, Any]:
        return assign_params(key=self.api_key, **kwargs)

    def retrieve_users_request(self, page, items):
        params = self._build_params(page=page, items=items)

        response = self._http_request("GET", "api/administration/users", params=params)

        return response

    def retrieve_a_specific_user_request(self, user_id):
        params = self._build_params()

        response = self._http_request("GET", f"api/administration/users/{user_id}", params=params)

        return response

    def retrieve_labels_request(self, page, items):
        params = self._build_params(page=page, items=items)

        response = self._http_request("GET", "api/administration/labels", params=params)

        return response

    def retrieve_a_specific_label_request(self, label_id):
        params = self._build_params()

        response = self._http_request("GET", f"api/administration/labels/{label_id}", params=params)

        return response

    def get_all_incidents_request(
        self,
        page: int | None,
        items: int | None,
        status: list[str] | None,
        from_date: str | None,
        to_date: str | None,
        adversary_types: list[str] | None,
        labels: list[int] | None,
    ) -> dict[str, Any]:
        return self._http_request(
            "POST",
            "api/secops/incidents/all",
            params=self._build_params(page=page, items=items),
            json_data=assign_params(
                status=status, from_date=from_date, to_date=to_date, adversary_types=adversary_types, labels=labels
            ),
        )

    def get_open_incidents_request(
        self, page: int | None, items: int | None, adversary_types: list[str] | None, labels: list[int] | None
    ) -> dict[str, Any]:
        return self._http_request(
            "POST",
            "api/secops/incidents/open",
            params=self._build_params(page=page, items=items),
            json_data=assign_params(adversary_types=adversary_types, labels=labels),
        )

    def get_muted_incidents_request(
        self, page: int | None, items: int | None, adversary_types: list[str] | None, labels: list[int] | None
    ) -> dict[str, Any]:
        return self._http_request(
            "POST",
            "api/secops/incidents/muted",
            params=self._build_params(page=page, items=items),
            json_data=assign_params(adversary_types=adversary_types, labels=labels),
        )

    def get_closed_incidents_request(
        self, page: int | None, items: int | None, adversary_types: list[str] | None, labels: list[int] | None
    ) -> dict[str, Any]:
        return self._http_request(
            "POST",
            "api/secops/incidents/closed",
            params=self._build_params(page=page, items=items),
            json_data=assign_params(adversary_types=adversary_types, labels=labels),
        )

    def get_incident_events_groupings_request(
        self, incident_id: str, page: int | None, items: int | None, status: list[str] | None
    ) -> dict[str, Any]:
        return self._http_request(
            "POST",
            f"api/secops/incidents/{incident_id}/events-groupings",
            params=self._build_params(page=page, items=items),
            json_data=assign_params(status=status),
        )

    def get_incident_details_request(self, incident_id: str) -> dict[str, Any]:
        return self._http_request("GET", f"api/secops/incidents/{incident_id}/details", params=self._build_params())

    def mark_incident_as_read_request(self, incident_id: str) -> str:
        return self._http_request(
            "POST", f"api/secops/incidents/{incident_id}/mark-as-read", params=self._build_params(), resp_type="text"
        )

    def begin_incident_work_request(self, incident_id: str) -> str:
        return self._http_request(
            "POST",
            f"api/secops/incidents/{incident_id}/begin-work",
            params=self._build_params(),
            json_data=assign_params(comment="Beginning work on the incident. Cortex XSOAR"),
            resp_type="text",
        )

    def comment_incident_request(self, incident_id: str, comment: str) -> str:
        return self._http_request(
            "POST",
            f"api/secops/incidents/{incident_id}/comment",
            params=self._build_params(),
            json_data={"comment": comment},
            resp_type="text",
        )

    def mute_incident_request(self, incident_id: str, comment: str) -> str:
        return self._http_request(
            "POST",
            f"api/secops/incidents/{incident_id}/mute",
            params=self._build_params(),
            json_data={"comment": comment},
            resp_type="text",
        )

    def unmute_incident_request(self, incident_id: str, comment: str) -> str:
        return self._http_request(
            "POST",
            f"api/secops/incidents/{incident_id}/unmute",
            params=self._build_params(),
            json_data={"comment": comment},
            resp_type="text",
        )

    def close_incident_request(self, incident_id: str, comment: str) -> str:
        return self._http_request(
            "POST",
            f"api/secops/incidents/{incident_id}/close",
            params=self._build_params(),
            json_data={"comment": comment},
            resp_type="text",
        )

    def consult_incidents_updates_request(self, offset: int | None, items: int | None, time: int | None) -> dict[str, Any]:
        return self._http_request(
            "GET", "api/secops/incidents/updates", params=self._build_params(offset=offset, items=items, time=time)
        )

    def get_security_event_details_request(
        self, incident_id: str, event_id: str, page: int | None, items: int | None
    ) -> dict[str, Any]:
        return self._http_request(
            "POST",
            f"api/secops/incidents/{incident_id}/security-events/{event_id}/details",
            params=self._build_params(page=page, items=items),
            json_data={},
        )

    def get_incident_security_events_details_request(
        self, incident_id: str, page: int | None, items: int | None, events_grouping_id: str | None
    ) -> dict[str, Any]:
        return self._http_request(
            "POST",
            f"api/secops/incidents/{incident_id}/security-events/details",
            params=self._build_params(page=page, items=items),
            json_data=assign_params(events_grouping_id=events_grouping_id),
        )


def is_msg_from_third_party(comment: str | None) -> bool:
    return bool(comment and comment.startswith(COMMENT_MARK))


def add_prefix_to_comment(comment: str | None) -> str:
    return f"Cortex XSOAR: {comment or ''},"


def build_command_results(title: str, output_prefix: str, response: dict[str, Any], outputs: Any = None) -> CommandResults:
    result_outputs = response if outputs is None else outputs
    return CommandResults(
        outputs_prefix=output_prefix,
        outputs=result_outputs,
        raw_response=response,
        readable_output=tableToMarkdown(title, result_outputs, headerTransform=pascalToSpace, removeNull=True),
    )


def build_success_response(prefix: str, message: str) -> CommandResults:
    response = {"statusCode": 200, "message": message}
    return CommandResults(outputs_prefix=prefix, outputs=response, raw_response=response, readable_output=message)


def extract_latest_action(actions: Any) -> dict[str, Any]:
    if not isinstance(actions, list) or not actions:
        return {}

    latest_action = actions[0]
    if not isinstance(latest_action, dict):
        return {}

    return {
        "lumu_secops_last_action": latest_action.get("action", ""),
        "lumu_secops_last_comment": latest_action.get("comment", ""),
        "lumu_secops_last_action_time": latest_action.get("datetime", ""),
        "lumu_secops_last_action_user_id": str(latest_action.get("userId", "")),
    }


def normalize_adversary_types(adversary_types: Any) -> list[str]:
    if isinstance(adversary_types, list):
        return [str(adversary_type) for adversary_type in adversary_types if adversary_type is not None]

    if adversary_types in (None, ""):
        return []

    return [str(adversary_types)]


def normalize_incident_grouping_fields(grouping_fields: Any) -> str:
    if isinstance(grouping_fields, dict):
        return json.dumps(grouping_fields, sort_keys=True)

    if grouping_fields in (None, ""):
        return ""

    if isinstance(grouping_fields, str):
        return grouping_fields

    return json.dumps(grouping_fields)


def retrieve_labels_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page = args.get("page")
    items = args.get("limit")

    response = client.retrieve_labels_request(page, items)
    command_results = CommandResults(
        outputs_prefix="LumuSecops.RetrieveLabels",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown("Labels", response.get("labels", []), headerTransform=pascalToSpace, removeNull=True)
        + "\n"
        + tableToMarkdown("paginationInfo", response.get("paginationInfo", []), headerTransform=pascalToSpace, removeNull=True),
    )

    return command_results


def retrieve_a_specific_label_command(client: Client, args: dict[str, Any]) -> CommandResults:
    label_id = args.get("label_id")

    response = client.retrieve_a_specific_label_request(label_id)

    command_results = CommandResults(
        outputs_prefix="LumuSecops.RetrieveASpecificLabel",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown("Label", response, headerTransform=pascalToSpace, removeNull=True),
    )

    return command_results


def get_all_incidents_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page = args.get("page")
    items = args.get("items")
    status = argToList(args.get("status"))
    adversary_types = argToList(args.get("adversary_types"))
    labels = [int(label) for label in argToList(args.get("labels"))]
    from_date = args.get("from_date")
    to_date = args.get("to_date")
    response = client.get_all_incidents_request(page, items, status, from_date, to_date, adversary_types, labels)
    return build_command_results("All Incidents", "LumuSecops.GetAllIncidents", response, response.get("items", []))


def get_open_incidents_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page = args.get("page")
    items = args.get("items")
    adversary_types = argToList(args.get("adversary_types"))
    labels = [int(label) for label in argToList(args.get("labels"))]
    response = client.get_open_incidents_request(page, items, adversary_types, labels)
    return build_command_results("Open Incidents", "LumuSecops.GetOpenIncidents", response, response.get("items", []))


def get_muted_incidents_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page = args.get("page")
    items = args.get("items")
    adversary_types = argToList(args.get("adversary_types"))
    labels = [int(label) for label in argToList(args.get("labels"))]
    response = client.get_muted_incidents_request(page, items, adversary_types, labels)
    return build_command_results("Muted Incidents", "LumuSecops.GetMutedIncidents", response, response.get("items", []))


def get_closed_incidents_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page = args.get("page")
    items = args.get("items")
    adversary_types = argToList(args.get("adversary_types"))
    labels = [int(label) for label in argToList(args.get("labels"))]
    response = client.get_closed_incidents_request(page, items, adversary_types, labels)
    return build_command_results("Closed Incidents", "LumuSecops.GetClosedIncidents", response, response.get("items", []))


def get_incident_events_groupings_command(client: Client, args: dict[str, Any]) -> CommandResults:
    incident_id = args.get("incident_id", "")
    page = args.get("page")
    items = args.get("items")
    status = argToList(args.get("status"))
    response = client.get_incident_events_groupings_request(incident_id, page, items, status)
    return build_command_results(
        "Incident Events Groupings", "LumuSecops.GetIncidentEventsGroupings", response, response.get("items", [])
    )


def get_incident_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
    incident_id = args.get("incident_id", "")
    response = client.get_incident_details_request(incident_id)
    return build_command_results("Incident Details", "LumuSecops.GetIncidentDetails", response)


def mark_incident_as_read_command(client: Client, args: dict[str, Any]) -> CommandResults:
    incident_id = args.get("incident_id", "")
    client.mark_incident_as_read_request(incident_id)
    url = f"https://portal.lumu.io/compromise/incidents/show/{incident_id}/detections"
    return build_success_response("LumuSecops.MarkIncidentAsRead", f"Incident marked as read successfully. Visit [Lumu]({url})")


def begin_incident_work_command(client: Client, args: dict[str, Any]) -> CommandResults:
    incident_id = args.get("incident_id", "")
    client.begin_incident_work_request(incident_id)
    url = f"https://portal.lumu.io/compromise/incidents/show/{incident_id}/detections"
    return build_success_response("LumuSecops.BeginIncidentWork", f"Incident work started successfully. Visit [Lumu]({url})")


def comment_incident_command(client: Client, args: dict[str, Any]) -> CommandResults:
    comment = f"{COMMENT_MARK} {args.get('comment', '')}"
    incident_id = args.get("incident_id", "")
    client.comment_incident_request(incident_id, comment)
    url = f"https://portal.lumu.io/compromise/incidents/show/{incident_id}/detections"
    return build_success_response("LumuSecops.CommentIncident", f"Comment added successfully." f" Visit [Lumu]({url})")


def mute_incident_command(client: Client, args: dict[str, Any]) -> CommandResults:
    comment = f"{COMMENT_MARK} {args.get('comment', '')}"
    incident_id = args.get("incident_id", "")
    client.mute_incident_request(incident_id, comment)
    url = f"https://portal.lumu.io/compromise/incidents/show/{incident_id}/detections"
    return build_success_response("LumuSecops.MuteIncident", f"Incident muted successfully." f" Visit [Lumu]({url})")


def unmute_incident_command(client: Client, args: dict[str, Any]) -> CommandResults:
    comment = f"{COMMENT_MARK} {args.get('comment', '')}"
    incident_id = args.get("incident_id", "")
    client.unmute_incident_request(incident_id, comment)
    url = f"https://portal.lumu.io/compromise/incidents/show/{incident_id}/detections"
    return build_success_response("LumuSecops.UnmuteIncident", f"Incident unmuted successfully." f" Visit [Lumu]({url})")


def close_incident_command(client: Client, args: dict[str, Any]) -> CommandResults:
    comment = f"{COMMENT_MARK} {args.get('comment', '')}"
    incident_id = args.get("incident_id", "")
    client.close_incident_request(incident_id, comment)
    url = f"https://portal.lumu.io/compromise/incidents/show/{incident_id}/detections"
    return build_success_response("LumuSecops.CloseIncident", f"Incident closed successfully." f" Visit [Lumu]({url})")


def consult_incidents_updates_command(client: Client, args: dict[str, Any]) -> CommandResults:
    response = client.consult_incidents_updates_request(args.get("offset"), args.get("items"), args.get("time"))
    return build_command_results("Incident Updates", "LumuSecops.ConsultIncidentsUpdates", response)


def get_security_event_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page = args.get("page")
    items = args.get("items")
    incident_id = args.get("incident_id", "")
    event_id = args.get("event_id", "")
    response = client.get_security_event_details_request(incident_id, event_id, page, items)

    command_results = CommandResults(
        outputs_prefix="LumuSecops.GetSecurityEventDetails",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            "Event Details", response.get("items", []), headerTransform=pascalToSpace, removeNull=True
        )
        + "\n"
        + tableToMarkdown("Summary", response.get("summary", []), headerTransform=pascalToSpace, removeNull=True),
    )

    return command_results


def get_incident_security_events_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page = args.get("page")
    items = args.get("items")
    incident_id = args.get("incident_id", "")
    events_grouping_id = args.get("events_grouping_id")
    response = client.get_incident_security_events_details_request(incident_id, page, items, events_grouping_id)
    return build_command_results(
        "Incident Security Events Details", "LumuSecops.GetIncidentSecurityEventsDetails", response, response.get("items", [])
    )


def normalize_incident_record(record: dict[str, Any], event_type: str) -> dict[str, Any]:
    incident_id = str(record.get("id", record.get("incidentId", "")))
    normalized = record.copy()
    normalized["lumu_secops_source_name"] = "lumusecops"
    normalized["lumu_secops_event_type"] = event_type
    normalized["lumu_secops_incident_id"] = incident_id
    normalized["lumu_secops_status"] = normalized.get("status", "")
    normalized["lumu_secops_total_events"] = normalized.get("totalEvents", 0)
    counts = normalized.get("counts", {}) if isinstance(normalized.get("counts"), dict) else {}
    normalized["lumu_secops_endpoint_targets_count"] = counts.get("endpointTargetsCount", 0)
    normalized["lumu_secops_user_targets_count"] = counts.get("userTargetsCount", 0)
    normalized["lumu_secops_other_targets_count"] = counts.get("otherTargetsCount", 0)
    normalized["lumu_secops_total_targets_count"] = counts.get("totalTargetsCount", 0)
    normalized["lumu_secops_offenders_count"] = counts.get("offendersCount", 0)
    normalized["lumu_secops_actions_count"] = len(normalized.get("actions") or [])
    normalized["lumu_secops_detector_type"] = str(normalized.get("detectorType") or "")
    normalized["lumu_secops_incident_type"] = str(normalized.get("incidentType") or "")
    normalized["lumu_secops_incident_grouping_fields"] = normalize_incident_grouping_fields(
        normalized.get("incidentGroupingFields")
    )
    normalized["lumu_secops_adversary_types"] = normalize_adversary_types(normalized.get("adversaryTypes"))
    normalized["lumu_secops_description"] = str(normalized.get("description") or "")
    normalized.update(extract_latest_action(normalized.get("actions")))
    normalized["mirror_instance"] = INTEGRATION_INSTANCE
    normalized["mirror_id"] = incident_id
    normalized["mirror_direction"] = MIRROR_DIRECTION
    normalized["mirror_last_sync"] = datetime.now().strftime(DATE_FORMAT)
    normalized["mirror_tags"] = MIRROR_TAGS
    normalized["severity"] = 2
    normalized["status"] = 1
    return normalized


def fetch_incidents(
    client: Client, first_fetch_offset: str, last_run: dict[str, Any], items: int, max_time: int
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    last_fetch = int(last_run.get("last_fetch") or first_fetch_offset)
    response = client.consult_incidents_updates_request(offset=last_fetch, items=items, time=max_time)
    updates = response.get("updates", [])
    next_offset = str(response.get("offset", last_fetch))

    incidents: list[dict[str, Any]] = []
    incidents_collected: CollectedIncident = {}
    incidents_ids: list[str] = []
    now_time = datetime.now().strftime(DATE_FORMAT)

    incidents_to_push: list[dict[str, Any]] = []
    cache = get_integration_context() or {
        "cache": [],
        "lumu_secops_incident_ids": [],
        "source_records": {},
        "users": {},
        "labels": {},
    }
    cache.setdefault("cache", [])
    cache.setdefault("lumu_secops_incident_ids", [])
    cache.setdefault("source_records", {})

    for update_item in updates:
        if not isinstance(update_item, dict) or not update_item:
            continue
        if "OpenIncidentsStatusUpdated" in update_item:
            continue

        event_type = next(iter(update_item.keys()))
        event_payload = update_item.get(event_type, {})
        if "openIncidentsStats" in event_payload:
            del event_payload["openIncidentsStats"]

        incident = event_payload.get("incident", {})

        if not incident:
            continue

        comment = event_payload.get("payload", {}).get("comment") or ""
        if event_type in STATUS_MSG_TYPES and is_msg_from_third_party(comment):
            demisto.debug(f"Comment contains similar marks, ignoring message to avoid loops for event {event_type}.")
            continue

        incident_id = str(incident.get("id", ""))
        if not incident_id:
            continue

        if event_type not in PERMITTED_MESSAGE_TYPES:
            demisto.debug(f"Skipping event type {event_type} of incident {incident_id} as it is not permitted.")
            continue

        event_data = event_payload.get("event") if isinstance(event_payload.get("event"), dict) else {}
        incident.setdefault("detectorType", "")
        incident.setdefault("incidentType", event_data.get("event_data") or "")
        incident.setdefault("incidentGroupingFields", event_data.get("incidentGroupingFields") or {})
        incident.setdefault(
            "adversaryTypes",
            incident.get("adversaryTypes") or event_data.get("adversaryTypes") or [],
        )
        incident.setdefault(
            "description",
            incident.get("description") or event_data.get("eventDescription") or "",
        )

        flattened = normalize_incident_record(incident, event_type)
        if event_payload.get("comment") or event_payload.get("payload"):
            flattened["comment"] = event_payload.get("comment") or event_payload.get("payload", {}).get("comment") or ""
        if event_payload.get("companyId"):
            flattened["companyId"] = event_payload.get("companyId")

        incident_name = flattened.get("description") or f"LumuSecops Incident {incident_id}"
        incidents.append(
            {
                "name": f"lumusecops - {incident_name} - {incident_id}",
                "occurred": flattened.get("timestamp", now_time),
                "dbotMirrorId": incident_id,
                "rawJSON": json.dumps(flattened),
            }
        )
        incidents_ids.append(incident_id)
        incidents_collected[IncidentID(incident_id)] = {"raw": update_item, "event_type": event_type}

    unique_pending_ids = list(set(incidents_ids))
    if unique_pending_ids:
        cache["cache"].append(unique_pending_ids)
        cache["source_records"].update(incidents_collected)
        known_ids = set(cache["lumu_secops_incident_ids"])
        for incident in incidents:
            if incident["dbotMirrorId"] in known_ids:
                demisto.debug(f"Skipping already known incident {incident['dbotMirrorId']}")
                continue
            incidents_to_push.append(incident)
            known_ids.add(incident["dbotMirrorId"])
        cache["lumu_secops_incident_ids"] = list(known_ids)
        demisto.debug(f'There are {len(cache["cache"])} events queued ready to process their updates')
        set_integration_context(cache)

    return {"last_fetch": next_offset}, incidents_to_push


def get_modified_remote_data_command(client: Client, args: dict[str, Any]) -> GetModifiedRemoteDataResponse:
    cache = get_integration_context() or {
        "cache": [],
        "lumu_secops_incident_ids": [],
        "source_records": {},
        "users": {},
        "labels": {},
    }
    queued_pending_ids = cache.get("cache", [])
    incidents_ids = queued_pending_ids.pop(0) if queued_pending_ids else []
    cache["cache"] = queued_pending_ids
    set_integration_context(cache)
    return GetModifiedRemoteDataResponse(incidents_ids)


def get_remote_data_command(client: Client, args: dict[str, Any]) -> GetRemoteDataResponse | None:
    user_id: int | None = None

    cache = get_integration_context() or {
        "cache": [],
        "lumu_secops_incident_ids": [],
        "source_records": {},
        "users": {},
        "labels": {},
    }
    if not cache.get("users") or len(cache["users"]) == 1:
        demisto.info("Initializing users cache with API User and all other users from the system")
        cache["users"] = {
            "0": UserDictType(
                {
                    "id": 0,
                    "role": "",
                    "email": "",
                    "name": "API User",
                    "time_zone": "",
                    "deactivated": False,
                }
            )
        }
        for user in client.list_all_users():
            cache["users"][str(user["id"])] = cast(UserDictType, user)

    if not cache.get("labels") or len(cache["labels"]) == 1:
        demisto.info("Initializing labels cache with Unlabeled activity and all other labels from the system")
        cache["labels"] = {
            "0": LabelDictType(
                {
                    "id": 0,
                    "name": "Unlabeled activity",
                    "relevance": 1,
                }
            )
        }
        for label in client.list_all_labels():
            cache["labels"][str(label["id"])] = label

    demisto.info(
        f"Retrieved integration context: {cache.keys()}, size: {len(cache)}, {[f'{key}: {len(cache[key])}' for key in cache]}"
    )
    parsed_args = GetRemoteDataArgs(args)
    incident_id = parsed_args.remote_incident_id
    source_record: SourceRecord = deepcopy(cache["source_records"].get(incident_id, {}))
    details: dict = {}
    if not source_record:
        details = client.get_incident_details_request(parsed_args.remote_incident_id)
        event_type = "IncidentUpdated"
        comment = ""

    else:
        del cache["source_records"][incident_id]
        set_integration_context(cache)
        event_type = source_record["event_type"]
        event_data: dict = source_record["raw"].get(event_type, {})
        demisto.info(f"Event: {event_type} - Processing pending Incident: {incident_id}")
        details = event_data.get("incident", {})
        comment = event_data.get("payload", {}).get("comment", "")
        user_id = event_data.get("userId", None)
    try:
        status = details.get("status", "open")
        incident_id = details.get("id", parsed_args.remote_incident_id)
        details["lumu_secops_incident_id"] = incident_id
        details["lumu_secops_status"] = status
        details["lumu_secops_event_type"] = event_type
        details["lumu_secops_source_name"] = "lumusecops"
        details["lumu_secops_total_events"] = details.get("totalEvents", 0)
        counts = details.get("counts", {}) if isinstance(details.get("counts"), dict) else {}
        details["lumu_secops_endpoint_targets_count"] = counts.get("endpointTargetsCount", 0)
        details["lumu_secops_user_targets_count"] = counts.get("userTargetsCount", 0)
        details["lumu_secops_other_targets_count"] = counts.get("otherTargetsCount", 0)
        details["lumu_secops_total_targets_count"] = counts.get("totalTargetsCount", 0)
        details["lumu_secops_offenders_count"] = counts.get("offendersCount", 0)
        details["lumu_secops_actions_count"] = len(details.get("actions") or [])
        details["lumu_secops_detector_type"] = str(details.get("detectorType") or "")
        details["lumu_secops_incident_type"] = str(details.get("incidentType") or "")
        details["lumu_secops_incident_grouping_fields"] = normalize_incident_grouping_fields(
            details.get("incidentGroupingFields")
        )
        details["lumu_secops_adversary_types"] = normalize_adversary_types(details.get("adversaryTypes"))
        details.update(extract_latest_action(details.get("actions")))
        details["incomming_mirror_error"] = ""

        parsed_entries: list[dict[str, Any]] = []

        adversary_types: list[str] = details["lumu_secops_adversary_types"]
        first_event_timestamp = details.get("firstEvent", {}).get("timestamp", datetime.now(UTC).isoformat())
        source_description = str(details.get("description") or "")

        details["lumu_secops_description"] = format_description_plain_text(
            incident_id, first_event_timestamp, source_description, adversary_types
        )

        if event_type in STATUS_MSG_TYPES:
            status_timestamp = details.get("statusTimestamp", datetime.now(UTC).isoformat())
            user_id = user_id or details.get("lastAssignee", 0)
            if not cache["users"].get(str(user_id)):
                cache["users"][str(user_id)] = client.retrieve_a_specific_user_request(user_id=user_id)
            username = cache["users"][str(user_id)]["name"]
            text = format_comment(event_type, username, status_timestamp, comment)
            parsed_entries.append(
                {
                    "Type": EntryType.NOTE,
                    "Contents": text,
                    "ContentsFormat": EntryFormat.MARKDOWN,
                    "Note": True,
                }
            )

        if event_type in [NEW_MESSAGE_TYPE]:
            html_text_title = format_description_comment(incident_id, first_event_timestamp, source_description, adversary_types)
            demisto.info(f"Event: {event_type} - Incident: {incident_id} - posting Title on WarRoom")
            parsed_entries.append(
                {
                    "Type": EntryType.NOTE,
                    "Contents": html_text_title,
                    "ContentsFormat": EntryFormat.HTML,
                    "Note": True,
                }
            )

        if event_type in [UPDATE_MESSAGE_TYPE, NEW_MESSAGE_TYPE]:
            label_cache = cache.get("labels") or {}
            html_text_content = format_updates_comment(details, label_cache)
            demisto.info(f"Event: {event_type} - Incident: {incident_id} - posting Content on WarRoom")
            parsed_entries.append(
                {
                    "Type": EntryType.NOTE,
                    "Contents": html_text_content,
                    "ContentsFormat": EntryFormat.HTML,
                    "Note": True,
                }
            )
        set_integration_context(cache)

        if details.get("status") == "closed":
            close_note = comment if comment else "Closed by remote system"
            demisto.info(f"Event: {event_type} - Incident: {incident_id} - posting Close on WarRoom")
            parsed_entries.append(
                {
                    "Type": EntryType.NOTE,
                    "Contents": {"dbotIncidentClose": True, "closeReason": f"Lumu SecOps: {close_note}"},
                    "ContentsFormat": EntryFormat.JSON,
                }
            )
        demisto.info(f"Event: {event_type} - Incident: {incident_id} - keys: {details.keys()}")
        return GetRemoteDataResponse(details, parsed_entries)
    except Exception as e:
        demisto.debug(f"get_remote_data_command error {e}")
        if "Rate limit exceeded" in str(e):  # modify this according to the vendor's spesific message
            return_error("API rate limit")
        return None


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    scheme = SchemeTypeMapping(type_name="incident type LumuSecops")
    for field in [
        "comment",
        "close",
        "mute",
        "unmute",
        "lumu_secops_status",
        "lumu_secops_detector_type",
        "lumu_secops_incident_type",
        "lumu_secops_incident_grouping_fields",
        "lumu_secops_adversary_types",
        "lumu_secops_description",
        "lumu_secops_endpoint_targets_count",
        "lumu_secops_user_targets_count",
        "lumu_secops_other_targets_count",
        "lumu_secops_total_targets_count",
        "lumu_secops_offenders_count",
        "lumu_secops_last_action",
        "lumu_secops_last_action_time",
        "lumu_secops_last_action_user_id",
        "lumu_secops_last_comment",
        "lumu_secops_actions_count",
        "status",
    ]:
        scheme.add_field(name=field, description="LumuSecops mirror field")
    return GetMappingFieldsResponse(scheme)


def update_remote_system_command(client: Client, args: dict[str, Any]) -> str:
    parsed_args = UpdateRemoteSystemArgs(args)
    remote_incident_id = parsed_args.remote_incident_id

    if (not parsed_args.entries) and (not parsed_args.delta):
        return remote_incident_id

    delta = parsed_args.delta or {}
    demisto.info(f"[update_remote_system_command] Remote incident ID: {remote_incident_id} - Parsed delta: {delta}")
    raw_comment = delta.get("comment", "")
    comment = f"{COMMENT_MARK} {raw_comment}"

    try:
        if delta.get("closeReason"):
            close_notes = delta.get("closeNotes", "")
            close_reason = delta.get("closeReason", "")
            user_id = delta.get("closingUserId", "N/A")
            close_comment = f"Close - Notes={close_notes}, Reason={close_reason}, User={user_id}"
            comment = f"{COMMENT_MARK} {close_comment}"
            response_text = client.close_incident_request(remote_incident_id, comment)
            demisto.debug(f"Closed incident {remote_incident_id} with Lumu Response: {response_text}")
            return remote_incident_id

        lumu_status = str(delta.get("Take Status Action") or delta.get("lumusecopstakestatusaction") or "").lower()
        if lumu_status in {"mute", "muted"}:
            comment = f"{comment} Mute"
            response_text = client.mute_incident_request(remote_incident_id, comment)
            demisto.debug(f"Muted incident {remote_incident_id} with Lumu Response: {response_text}")
        elif lumu_status in {"unmute", "unmuted"}:
            comment = f"{comment} Unmute"
            response_text = client.unmute_incident_request(remote_incident_id, comment)
            demisto.debug(f"Unmuted incident {remote_incident_id} with Lumu Response: {response_text}")
        elif raw_comment:
            response_text = client.comment_incident_request(remote_incident_id, comment)
            demisto.debug(f"Commented on incident {remote_incident_id} with Lumu Response: {response_text}")

        return remote_incident_id
    except DemistoException as err:
        raise DemistoException(repr(err))


def test_module(client: Client, args: dict[str, Any]) -> str:
    try:
        cache = get_integration_context() or {
            "cache": [],
            "lumu_secops_incident_ids": [],
            "source_records": {},
            "users": {},
            "labels": {},
        }

        for label in client.list_all_labels():
            cache["labels"][str(label["id"])] = cast(LabelDictType, label)

        for user in client.list_all_users():
            cache["users"][str(user["id"])] = cast(UserDictType, user)
        set_integration_context(cache)
        return "ok"
    except Exception as e:
        msg_err = f"verify Lumu API Key and Network Connections - {type(e).__name__} - {repr(e)} - {e}"
        return msg_err


test_module.__test__ = False  # type: ignore[attr-defined]


def clear_cache_command():
    cache: dict = {}
    cache["cache"] = []
    cache["lumu_incidentsId"] = []
    set_integration_context(cache)
    command_results = CommandResults(
        outputs_prefix="LumuSecops.ClearCache",
        outputs=f"cache cleared {get_integration_context()=}",
        raw_response=f"cache cleared {get_integration_context()=}",
        readable_output=f"cache cleared {get_integration_context()=}",
    )

    return command_results


def get_cache_command():
    cache = get_integration_context()
    command_results = CommandResults(
        outputs_prefix="LumuSecops.GetCache",
        outputs=cache,
        raw_response=cache,
        readable_output=tableToMarkdown("Cache", cache, headerTransform=pascalToSpace, removeNull=True),
    )

    return command_results


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    url = params.get("url", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    api_key = params.get("api_key", "")

    offset_set_off = params.get("fetch_offset", "0")
    items = int(params.get("total_items_per_lumu_fetch", 30))
    time_last = int(params.get("max_time_fetching_lumu_incident", 4))

    instance_name: str = get_integration_instance_name() or "default"
    USER_AGENT: Final[str] = f"LumuIncidentsAPI/CortexXsoar ({instance_name})"

    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}

    try:
        urllib3.disable_warnings()
        client = Client(server_url=url, verify=verify_certificate, proxy=proxy, headers=headers, api_key=api_key)

        commands = {
            "lumusecops-retrieve-labels": retrieve_labels_command,
            "lumusecops-retrieve-a-specific-label": retrieve_a_specific_label_command,
            "lumusecops-get-all-incidents": get_all_incidents_command,
            "lumusecops-get-open-incidents": get_open_incidents_command,
            "lumusecops-get-muted-incidents": get_muted_incidents_command,
            "lumusecops-get-closed-incidents": get_closed_incidents_command,
            "lumusecops-get-incident-events-groupings": get_incident_events_groupings_command,
            "lumusecops-get-incident-details": get_incident_details_command,
            "lumusecops-mark-incident-as-read": mark_incident_as_read_command,
            "lumusecops-begin-incident-work": begin_incident_work_command,
            "lumusecops-comment-incident": comment_incident_command,
            "lumusecops-mute-incident": mute_incident_command,
            "lumusecops-unmute-incident": unmute_incident_command,
            "lumusecops-close-incident": close_incident_command,
            "lumusecops-consult-incidents-updates": consult_incidents_updates_command,
            "lumusecops-get-security-event-details": get_security_event_details_command,
            "lumusecops-get-incident-security-events-details": get_incident_security_events_details_command,
            "get-modified-remote-data": get_modified_remote_data_command,
            "get-remote-data": get_remote_data_command,
            "update-remote-system": update_remote_system_command,
        }

        if command == "test-module":
            return_results(test_module(client, args))
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            demisto.info(f"Executing fetch-incidents command, last run: {last_run}")
            next_run, incidents = fetch_incidents(client, offset_set_off, last_run, items, time_last)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
            count = Counter([inc["dbotMirrorId"] for inc in incidents])
            demisto.debug(f"total inc found: {len(incidents)}, {count=} {last_run=} {next_run=}")

        elif command == "get-modified-remote-data":
            demisto.info("Executing get-modified-remote-data command")
            incidents_id = get_modified_remote_data_command(client, args)
            return_results(incidents_id)

        elif command == "get-remote-data":
            demisto.info("Executing get-remote-data command")
            return_results(get_remote_data_command(client, args))

        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())

        elif command == "update-remote-system":
            demisto.info("Executing update-remote-system command")
            return_results(update_remote_system_command(client, args))

        elif command == "lumusecops-clear-cache":
            return_results(clear_cache_command())

        elif command == "lumusecops-get-cache":
            demisto.info("Executing lumusecops-get-cache command")
            return_results(get_cache_command())
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")
    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
