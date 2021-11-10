import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
import re
from typing import Dict

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

INCIDENT_FIELDS = {
    "status": {
        "description": "Current status of the incident",
        "field": "ztapstatus",
    },
}

XSOAR_STATUS_TO_ZTAP = {
    "Other": "unresolved",
    "Duplicate": "resolved",
    "False Positive": "resolved",
    "Resolved": "resolved",
}

ZTAP_STATUS_TO_XSOAR = {
    "unresolved": "Other",
    "resolved": "Resolved",
}

ESCALATE_REASON = "User escalated back to CriticalStart."

# Ignore new comments with this string
XSOAR_EXCLUDE_MESSAGE = "via Cortex XSOAR"

# ISO8601 format with UTC, default in XSOAR
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Default time string
EPOCH = "0001-01-01T00:00:00Z"

MIRROR_DIRECTION = {"None": None, "Incoming": "In", "Outgoing": "Out", "Both": "Both"}

# These audit logs are redundant and not synced
LOG_NO_SYNC = [
    "Added a comment",
]

SORT_ORDER_LOG = 0
SORT_ORDER_COMMENT = 1

""" CLIENT CLASS """


class Client(BaseClient):
    PAGINATE_LIMIT = 100
    MAXIMUM_EVENTS = 1000
    FIELD_LIMIT = 1000

    def __init__(
        self,
        base_url,
        verify_certificate=True,
        api_key=None,
        proxy=None,
        comment_tag="",
        escalate_tag="",
        input_tag="",
        max_match=100,
        get_attachments=False,
        close_incident=False,
        reopen_incident=False,
        reopen_group="",
    ):
        headers = {
            "Authorization": api_key,
        }

        super().__init__(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )
        self.comment_tag = comment_tag
        self.escalate_tag = escalate_tag
        self.input_tag = input_tag
        self.max_match = max_match
        self.get_attachments = get_attachments
        self.close_incident = close_incident
        self.reopen_incident = reopen_incident
        self.reopen_group = reopen_group
        self._active_user = None

    @property
    def active_user(self):
        if not self._active_user:
            self._active_user = self.get_active_user()
        return self._active_user

    def http_request(self, method, url_suffix, params, json_data=None):
        response = self._http_request(
            method=method, url_suffix=url_suffix, params=params, json_data=json_data
        )
        return response

    def get_organizations(self, params):
        response = self.http_request(
            method="GET", url_suffix="/organizations/", params=params
        )
        return response["objects"]

    def get_groups(self):
        return self.paginate(method="GET", url_suffix="/groups/", params={})

    def get_alerts(self, params):
        response = self.http_request(
            method="GET", url_suffix="/incidents/", params=params
        )
        return response["objects"]

    def get_all_alerts(self, params):
        return self.paginate(method="GET", url_suffix="/incidents/", params=params)

    def get_alert(self, alert_id):
        response = self.http_request(
            method="GET", url_suffix=f"/incidents/{alert_id}/", params={}
        )
        return response

    def get_escalation_path(self, alert_id):
        response = self.http_request(
            method="GET",
            url_suffix=f"/incidents/{alert_id}/escalation_path/",
            params={},
        )
        return response["escalation_path"]

    def get_comments(self, alert_id, created_since):
        params = {
            "model": "incident",
            "object_id": alert_id,
            "created": created_since.isoformat(),
        }
        return self.paginate(method="GET", url_suffix="/comments/", params=params)

    def get_logs(self, alert_id, created_since):
        params = {
            "model": "incident",
            "object": alert_id,
            "created": created_since.isoformat(),
        }
        return self.paginate(method="GET", url_suffix="/auditlogs/", params=params)

    def get_events(self, alert_id):
        params = {
            "incident": alert_id,
            "category": "tier1",
            "fields": self.FIELD_LIMIT,
        }
        return self.paginate(method="GET", url_suffix="/events/", params=params)

    def upload_comment(self, alert_id, text):
        json_data = {
            "comment": text,
            "model": "incident",
            "object_id": alert_id,
            "type": "public",
        }
        self.http_request(
            method="POST", url_suffix="/comments/", params={}, json_data=json_data
        )

    def close_alert(self, alert_id, description, outcome):
        json_data = {
            "description": description,
            "outcome": outcome,
            "user_confirmed": True,
        }
        self.http_request(
            method="PUT",
            url_suffix=f"/incidents/{alert_id}/close/",
            params={},
            json_data=json_data,
        )

    def download_attachment(self, link):
        return self._http_request(method="GET", full_url=link, resp_type="content")

    def reopen_alert(self, alert_id, group_id, description):
        return self.reassign_alert_to_group(alert_id, group_id, description)

    def reassign_alert_to_group(self, alert_id, group_id, description):
        json_data = {
            "group_id": group_id,
            "type": "Group",
            "comment": description,
            "user_confirmed": True,
        }
        self.escalate_alert(alert_id, json_data)

    def reassign_alert_to_org(self, alert_id, org_id, description):
        json_data = {
            "org_id": org_id,
            "type": "Organization",
            "comment": description,
            "user_confirmed": True,
        }
        self.escalate_alert(alert_id, json_data)

    def escalate_alert(self, alert_id, json_data):
        self.http_request(
            method="PUT",
            url_suffix=f"/incidents/{alert_id}/escalate/",
            params={},
            json_data=json_data,
        )

    def get_escalate_org_id(self):
        org = self.get_escalation_organization()
        return org["monitoring_organization"]["id"]

    def get_reopen_group_id(self):
        group = self.get_reopen_group()
        return group["id"]

    def get_active_user(self):
        params = {"active_only": True}
        response = self.http_request(method="GET", url_suffix="/users/", params=params)
        return response["objects"][0]

    def get_reopen_group(self):
        active_org_name = self.active_user["organization"]["name"]
        for group in self.get_groups():
            if group["organization"]["name"].lower() == active_org_name.lower():
                if group["name"].lower() == self.reopen_group.lower():
                    return group
        full_name = self.get_full_escalation_name()
        raise ValueError(f"Escalation group {full_name} not found")

    def get_escalation_organization(self):
        active_psa_id = self.active_user["organization"]["psa_id"]
        params = {"q": active_psa_id}
        for org in self.get_organizations(params):
            if org["psa_id"] == active_psa_id:
                return org
        raise ValueError(f"Escalation organization ({active_psa_id}) not found")

    def get_full_escalation_name(self):
        active_org_name = self.active_user["organization"]["name"]
        return f"{self.reopen_group} ({active_org_name})"

    def paginate(self, method, url_suffix, params, json_data=None):
        limit = self.PAGINATE_LIMIT
        if "limit" not in params:
            params["limit"] = self.PAGINATE_LIMIT
        else:
            limit = params["limit"]

        page = 1

        # First request
        response = self.http_request(
            method=method, url_suffix=url_suffix, params=params, json_data=json_data
        )
        objects = response["objects"]

        view_id = response.get("view")
        if view_id:
            params["view"] = view_id

        # Additional requests
        total = response["total"]
        while total > limit * page:
            page += 1
            if limit * page > self.MAXIMUM_EVENTS:
                break

            params["page"] = page
            response = self.http_request(
                method=method, url_suffix=url_suffix, params=params, json_data=json_data
            )
            objects.extend(response["objects"])

        return objects


""" HELPER FUNCTIONS """


def epoch():
    return dateparser.parse(EPOCH)


def get_sort(occurred: str, sort_order: int, oid: str):
    return f"{occurred}_{sort_order}_{oid}"


def delta_or_data(remote_args, key):
    if remote_args.delta.get(key):
        return remote_args.delta.get(key)
    else:
        return remote_args.data.get(key)


def alert_to_incident(alert: Dict):
    alert_id = alert["id"]
    description = alert["description"]
    return {
        "name": f"ZTAP Alert ({alert_id}) {description}",
        "occurred": alert["datetime_firstevent"],
        "rawJSON": json.dumps(alert),
    }


def get_last_closed(investigation):
    return dateparser.parse(investigation.get("closed", EPOCH))


def get_last_reopened(investigation):
    return dateparser.parse(investigation.get("lastOpen", EPOCH))


def get_alert_last_closed(alert):
    return dateparser.parse(alert.get("datetime_closed") or EPOCH)


def get_alert_last_reopened(alert):
    return get_alert_org_escalation_time(alert)


def get_alert_org_escalation_time(alert):
    return dateparser.parse(alert.get("datetime_org_assigned") or EPOCH)


def get_alert_last_new_event(alert):
    return dateparser.parse(alert.get("datetime_events_added") or EPOCH)


def get_comments_for_alert(
    client: Client,
    alert_id: str,
    last_update: datetime,
):
    """
    Gets comments associated with an incident
    """
    all_comments = client.get_comments(alert_id, last_update)

    comments = []
    for c in all_comments:
        if XSOAR_EXCLUDE_MESSAGE in ["comment"]:
            continue

        if dateparser.parse(c["datetime_created"]) <= last_update:
            continue

        comments.append(c)

    return comments


def comments_to_notes(client: Client, comments: List):
    """
    Turns comments into XSOAR entries
    """

    def to_note(comment, filenames):
        occurred = comment["datetime_created"]
        oid = comment["id"]
        readable = {
            "occurred": occurred,
            "contents": comment["comment"],
            "type": "comment",
            "files": filenames,
        }
        return {
            "Type": EntryType.NOTE,
            "ContentsFormat": EntryFormat.JSON,
            "Contents": comment,
            "HumanReadable": readable,
            "ReadableContentsFormat": EntryFormat.JSON,
            "Note": True,
            "Tags": [client.input_tag],
            "occurred": get_sort(occurred, SORT_ORDER_COMMENT, oid),
        }

    entries = []
    for c in comments:
        filenames = []
        if client.get_attachments:
            for filename, link in get_comment_links(c):
                entries.append(attachment_note_from_link(client, filename, link))
                filenames.append(filename)

        strip_comment_links(c)
        entries.append(to_note(c, filenames))

    return entries


def get_audit_logs_for_alert(
    client: Client,
    alert_id: str,
    last_update: datetime,
):
    all_logs = client.get_logs(alert_id, last_update)

    logs = []
    for log in all_logs:
        if log["action"] in LOG_NO_SYNC:
            continue

        logs.append(log)

    return logs


def audit_logs_to_notes(
    client: Client,
    logs: List,
    last_update: datetime,
):
    def to_note(audit_log):
        occurred = audit_log["datetime"]
        oid = audit_log["id"]
        readable = {
            "occurred": occurred,
            "contents": audit_log["action"],
            "type": "log",
        }
        return {
            "Type": EntryType.NOTE,
            "ContentsFormat": EntryFormat.JSON,
            "Contents": audit_log,
            "HumanReadable": readable,
            "ReadableContentsFormat": EntryFormat.JSON,
            "Note": True,
            "Tags": [client.input_tag],
            "occurred": get_sort(occurred, SORT_ORDER_LOG, oid),
        }

    entries = [to_note(log) for log in logs]
    return entries


def get_notes_for_alert(
    client: Client,
    investigation: Dict,
    alert: Dict,
    last_update: datetime,
    update_status: bool,
):
    """
    Retrieve any logs/comments/attachments as XSOAR entries
    """

    alert_id = str(alert["id"])

    entries = []

    comments = get_comments_for_alert(client, alert_id, last_update)
    entries.extend(comments_to_notes(client, comments))

    audit_logs = get_audit_logs_for_alert(client, alert_id, last_update)
    entries.extend(audit_logs_to_notes(client, audit_logs, last_update))

    entries = sorted(entries, key=lambda x: x["occurred"] if "occurred" in x else "")

    # Times for syncing
    local_last_closed = get_last_closed(investigation)
    local_last_reopened = get_last_reopened(investigation)
    remote_last_closed = get_alert_last_closed(alert)
    remote_last_reopened = get_alert_last_reopened(alert)

    if (
        update_status
        and alert["status"] == "closed"
        and client.close_incident
        and remote_last_closed > local_last_reopened
    ):
        # Use the last comment as a close comment
        if comments:
            last_comment = comments[-1]["comment"]
        else:
            last_comment = ""
        close_reason = ZTAP_STATUS_TO_XSOAR.get(alert["review_outcome"], "Other")
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": close_reason,
                    "closeNotes": f"From ZTAP: {last_comment}",
                },
                "ContentsFormat": EntryFormat.JSON,
            }
        )
        demisto.info(f"Closing incident from ZTAP {alert_id}")

    if (
        update_status
        and alert["status"] != "closed"
        and remote_last_reopened > local_last_closed
        and client.reopen_incident
    ):
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentReopen": True,
                },
                "ContentsFormat": EntryFormat.JSON,
            }
        )
        demisto.info(f"Reopening incident from ZTAP {alert_id}")

    return entries


def get_comment_links(comment: Dict):
    # Format [description](link)
    # Extract description, link
    link_regex = re.compile(r"\[([^\]]+)\]\(([^)]+incident_uploads[^)]+)\)")
    return link_regex.findall(comment["comment"])


def strip_comment_links(comment: Dict):
    # Format [description](link)
    # Remove the (link)
    strip_regex = re.compile(r"(\[[^\]]+\])\([^)]+incident_uploads[^)]+\)")
    comment["comment"] = strip_regex.sub(r"\1", comment["comment"])
    return comment


def attachment_note_from_link(
    client: Client,
    filename: str,
    link: str,
):
    text = client.download_attachment(link)
    result = fileResult(filename, text)
    result["Note"] = True
    result["Tags"] = [client.input_tag]
    return result


def was_alert_first_escalated(
    client: Client, alert_id: str, org_name: str, since: datetime
):
    """
    We are searching by alert org assignment time, however an alert could have
    been escalated to a different org. Make sure the alert was escalated
    to the escalation organization within the time window we are searching (last update -> now)
    """
    # Group names are in the format "PATH NAME (GROUP NAME)"
    end_of_group = ("(" + org_name + ")").lower()
    escalation_path = client.get_escalation_path(alert_id)

    for escalation in escalation_path:
        if escalation["type"] == "Group" and escalation["group"].lower().endswith(
            end_of_group
        ):
            escalation_time = dateparser.parse(escalation["time"])
            # Only check against the first escalation to this organization
            return escalation_time > since

    return False


""" COMMAND FUNCTIONS """


def fetch_incidents(
    client: Client,
    last_run: Dict,
    first_fetch_time: str,
    max_fetch: int,
    mirror_direction: Optional[str],
    integration_instance: str,
):
    """
    Fetches incidents from ZTAP
    """
    if last_run:
        oldest_alert_time = dateparser.parse(last_run["last_run"])
        existing_ids = last_run.get("existing_ids", [])
    else:
        oldest_alert_time = dateparser.parse(
            first_fetch_time,
            settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True},
        )
        existing_ids = []

    org_name = client.active_user["organization"]["name"]
    org_psa_id = client.active_user["organization"]["psa_id"]
    start_time_iso = oldest_alert_time.isoformat()
    now_iso = datetime.now().isoformat() + "Z"
    params = {
        "sort by": "last time org assigned",
        "last time org assigned": f"{start_time_iso}&{now_iso}",
        "incident status": ["open"],
        "assigned organization": org_psa_id,
        "limit": max_fetch,
    }
    alerts = client.get_alerts(params=params)

    incidents = []
    newest_ids = []
    escalation_time = oldest_alert_time
    for alert in alerts:
        escalation_time = max(escalation_time, get_alert_org_escalation_time(alert))
        alert_id = str(alert["id"])

        if alert_id in existing_ids:
            newest_ids.append(alert_id)
            continue

        if not was_alert_first_escalated(client, alert_id, org_name, oldest_alert_time):
            continue

        newest_ids.append(alert_id)

        trigger_events = client.get_events(alert_id)
        alert["xsoar_trigger_events"] = trigger_events

        # Mirroring fields
        alert["xsoar_mirror_direction"] = mirror_direction
        alert["xsoar_mirror_instance"] = integration_instance
        alert["xsoar_mirror_id"] = alert_id
        alert["xsoar_mirror_tags"] = [client.comment_tag, client.escalate_tag]
        alert["xsoar_input_tag"] = client.input_tag

        incident = alert_to_incident(alert)
        incidents.append(incident)

    new_last_run = {
        "last_run": escalation_time.isoformat().replace("+00:00", "Z"),
        "existing_ids": newest_ids,
    }

    return incidents, new_last_run


def get_mapping_fields():
    """
    Gets mapping fields for ZTAP
    """
    type_scheme = SchemeTypeMapping(type_name="ZTAP Alert")
    for field, info in INCIDENT_FIELDS.items():
        type_scheme.add_field(name=field, description=info["description"])

    return GetMappingFieldsResponse([type_scheme])


def get_remote_data(
    client: Client,
    investigation: Dict,
    args: Dict,
):
    """
    Gets updated data from ZTAP for an alert that has changed
    """
    parsed_args = GetRemoteDataArgs(args)

    try:
        alert_id = parsed_args.remote_incident_id

        alert = client.get_alert(alert_id)

        last_update_utc = dateparser.parse(
            parsed_args.last_update,
            settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True},
        )

        entries = get_notes_for_alert(
            client,
            investigation,
            alert,
            last_update_utc,
            update_status=True,
        )

        if last_update_utc <= get_alert_last_new_event(alert):
            trigger_events = client.get_events(alert_id)
            alert["xsoar_trigger_events"] = trigger_events

        alert["in_mirror_error"] = ""

        return GetRemoteDataResponse(alert, entries)
    except Exception as e:
        if "Rate limit" in str(e):
            raise Exception("API rate limit")

        raise Exception(str(e))


def get_modified_remote_data(client: Client, args: Dict):
    """
    Gets ZTAP alerts that have been modified since the last check
    """
    parsed_args = GetModifiedRemoteDataArgs(args)
    last_update = parsed_args.last_update

    now_iso = datetime.now().isoformat() + "Z"

    params = {
        "sort by": "incident updated",
        "incident updated": f"{last_update}&{now_iso}",
        "incident status": ["open", "closed", "reviewing"],
    }
    alerts = client.get_all_alerts(params=params)

    modified_incident_ids = []
    for alert in alerts:
        modified_incident_ids.append(str(alert["id"]))

    return GetModifiedRemoteDataResponse(modified_incident_ids)


def update_remote_system(
    client: Client,
    investigation: Dict,
    args: Dict,
):
    """
    Updates ZTAP with new comments and/or closes the alert if closed in XSOAR
    """
    parsed_args = UpdateRemoteSystemArgs(args)

    alert_id = parsed_args.remote_incident_id

    if parsed_args.entries:
        for entry in parsed_args.entries:
            user = str(entry.get("user", ""))
            contents = str(entry.get("contents", ""))
            footer = f"Sent by {user} {XSOAR_EXCLUDE_MESSAGE}"
            if client.comment_tag in entry["tags"]:
                text = f"{contents}\n\n---\n\n{footer}"
                client.upload_comment(alert_id, text)
            elif client.escalate_tag in entry["tags"]:
                footer = ESCALATE_REASON + "\n\n" + footer
                text = f"{contents}\n\n---\n\n{footer}"
                try:
                    client.reassign_alert_to_org(
                        alert_id, client.get_escalate_org_id(), text
                    )
                except Exception as e:
                    if "already assigned" in str(e):
                        client.upload_comment(alert_id, text)
                    else:
                        raise e

    alert = client.get_alert(alert_id)

    local_last_closed = get_last_closed(investigation)
    local_last_reopened = get_last_reopened(investigation)
    remote_last_closed = get_alert_last_closed(alert)
    remote_last_reopened = get_alert_last_reopened(alert)

    # Close remote alert
    if parsed_args.incident_changed and client.close_incident:
        if (
            parsed_args.inc_status == IncidentStatus.DONE
            and alert["status"] != "closed"
            and local_last_closed > remote_last_reopened
        ):
            demisto.info(f"Closing ZTAP Alert {alert_id}")
            close_notes = delta_or_data(parsed_args, "closeNotes")
            close_reason = delta_or_data(parsed_args, "closeReason")
            close_description = f"{close_notes}\n\nClose Reason: {close_reason}"
            close_description += "\n\n---\n\nIncident closed in XSOAR."
            close_description += f"\n\nSent {XSOAR_EXCLUDE_MESSAGE}"
            outcome = XSOAR_STATUS_TO_ZTAP.get(close_reason, "unresolved")
            client.close_alert(alert_id, close_description, outcome)

    # Re-open remote alert
    if parsed_args.incident_changed and client.reopen_incident:
        if (
            parsed_args.inc_status != IncidentStatus.DONE
            and alert["status"] == "closed"
            and local_last_reopened > remote_last_closed
        ):
            demisto.info(f"Reopening ZTAP Alert {alert_id}")
            close_description = f"Incident reopened in XSOAR.---\n\nSent {XSOAR_EXCLUDE_MESSAGE}"
            client.reopen_alert(
                alert_id, client.get_reopen_group_id(), close_description
            )

    return alert_id


def ztap_get_alert_entries(
    client: Client,
    args: Dict,
):
    """
    Gets all entries (comments/logs) for an alert
    """
    try:
        alert_id = args.get("id")

        alert = {
            "status": "assigned",
            "id": alert_id,
            "datetime_created": EPOCH,
            "datetime_closed": None,
        }

        investigation: Dict = {}
        entries = get_notes_for_alert(
            client, investigation, alert, epoch(), update_status=False
        )

        return entries
    except Exception as e:
        if "Rate limit" in str(e):
            raise Exception("API rate limit")

        raise Exception(str(e))


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    params = {"limit": 1}

    try:
        client.get_alerts(params=params)
        client.get_escalation_organization()
        client.get_reopen_group()
        message = "ok"
    except DemistoException as e:
        if "Unauthorized" in str(e):
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


""" MAIN FUNCTION """


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()

    # Authentication
    api_key = params.get("apikey")

    # get the service API url
    base_url = urljoin(params["url"], "/api/1.5/")

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    comment_tag = params.get("comment_tag")
    escalate_tag = params.get("escalate_tag")
    input_tag = params.get("input_tag")
    get_attachments = params.get("get_attachments", False)
    close_incident = params.get("close_incident", False)
    reopen_incident = params.get("reopen_incident", False)
    reopen_group = params.get("reopen_group", "Default")

    demisto.debug(f"Command being called is {demisto.command()}")
    try:

        client = Client(
            base_url=base_url,
            verify_certificate=verify_certificate,
            api_key=api_key,
            proxy=proxy,
            comment_tag=comment_tag,
            escalate_tag=escalate_tag,
            input_tag=input_tag,
            get_attachments=get_attachments,
            close_incident=close_incident,
            reopen_incident=reopen_incident,
            reopen_group=reopen_group,
        )

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == "fetch-incidents":
            max_fetch = params.get("max_fetch", 100)
            last_run = demisto.getLastRun()
            first_fetch_timestamp = params.get(
                "first_fetch_timestamp", "7 days"
            ).strip()
            mirror_direction = MIRROR_DIRECTION.get(
                demisto.params().get("mirror_direction", "None"), None
            )
            integration_instance = demisto.integrationInstance()
            incidents, new_last_run = fetch_incidents(
                client=client,
                last_run=last_run,
                max_fetch=max_fetch,
                first_fetch_time=first_fetch_timestamp,
                mirror_direction=mirror_direction,
                integration_instance=integration_instance,
            )
            demisto.setLastRun(new_last_run)
            demisto.incidents(incidents)

        elif demisto.command() == "get-mapping-fields":
            result = get_mapping_fields()
            return_results(result)

        elif demisto.command() == "get-remote-data":
            investigation = demisto.investigation()
            result = get_remote_data(client, investigation, demisto.args())
            return_results(result)

        elif demisto.command() == "get-modified-remote-data":
            result = get_modified_remote_data(client, demisto.args())
            return_results(result)

        elif demisto.command() == "update-remote-system":
            investigation = demisto.investigation()
            result = update_remote_system(client, investigation, demisto.args())
            return_results(result)

        elif demisto.command() == "ztap-get-alert-entries":
            result = ztap_get_alert_entries(client, demisto.args())
            return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
