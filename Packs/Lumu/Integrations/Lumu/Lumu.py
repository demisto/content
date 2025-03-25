import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """


import hashlib
import urllib3
import hmac
from collections import Counter

""" CONSTANTS """

params = demisto.params()
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
MIRROR_DIRECTION = {
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}.get(params.get("mirror_direction"))
MIRROR_TAGS = params.get("mirror_tags") or []
INTEGRATION_INSTANCE = demisto.integrationInstance()
FIELDS_TO_REMOVE_FROM_MIROR_IN = ["url", "id", "created_at"]

status_msg_types = [
    "IncidentMuted",
    "IncidentUnmuted",
    "IncidentClosed",
    "IncidentCommentAdded",
]

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers):
        super().__init__(
            base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=None
        )
        self.api_key = None

    def retrieve_labels_request(self, page, items):
        params = assign_params(page=page, items=items, key=self.api_key)

        response = self._http_request(
            "GET", "api/administration/labels", params=params
        )

        return response

    def retrieve_a_specific_label_request(self, label_id):
        params = assign_params(key=self.api_key)

        response = self._http_request(
            "GET",
            f"api/administration/labels/{label_id}",
            params=params
        )

        return response

    def retrieve_incidents_request(
        self, page, items, fromdate, todate, status, adversary_types, labels
    ):
        params = assign_params(page=page, items=items, key=self.api_key)
        data = {
            "adversary-types": adversary_types,
            "fromDate": fromdate,
            "labels": labels,
            "status": status,
            "toDate": todate,
        }

        response = self._http_request(
            "POST", "api/incidents/all", params=params, json_data=data
        )

        return response

    def retrieve_a_specific_incident_details_request(self, lumu_incident_id):
        params = assign_params(key=self.api_key)

        response = self._http_request(
            "GET",
            f"api/incidents/{lumu_incident_id}/details",
            params=params
        )

        return response

    def retrieve_a_specific_incident_context_request(self, lumu_incident_id, hash):
        params = assign_params(hash=hash, key=self.api_key)

        response = self._http_request(
            "GET",
            f"api/incidents/{lumu_incident_id}/context",
            params=params
        )

        return response

    def comment_a_specific_incident_request(self, lumu_incident_id, comment):
        params = assign_params(key=self.api_key)
        data = {"comment": comment}

        response = self._http_request(
            "POST",
            f"api/incidents/{lumu_incident_id}/comment",
            params=params,
            json_data=data,
            resp_type="text"
        )

        return response

    def retrieve_open_incidents_request(self, page, items, adversary_types, labels):
        params = assign_params(page=page, items=items, key=self.api_key)
        data = {"adversary-types": adversary_types, "labels": labels}

        response = self._http_request(
            "POST", "api/incidents/open", params=params, json_data=data
        )

        return response

    def retrieve_muted_incidents_request(self, page, items, adversary_types, labels):
        params = assign_params(page=page, items=items, key=self.api_key)
        data = {"adversary-types": adversary_types, "labels": labels}

        response = self._http_request(
            "POST",
            "api/incidents/muted",
            params=params,
            json_data=data,
        )

        return response

    def retrieve_closed_incidents_request(self, page, items, adversary_types, labels):
        params = assign_params(page=page, items=items, key=self.api_key)
        data = {"adversary-types": adversary_types, "labels": labels}

        response = self._http_request(
            "POST",
            "api/incidents/closed",
            params=params,
            json_data=data
        )

        return response

    def retrieve_endpoints_by_incident_request(self, lumu_incident_id, page, items):
        params = assign_params(page=page, items=items, key=self.api_key)

        response = self._http_request(
            "POST",
            f"api/incidents/{lumu_incident_id}/endpoints-contacts",
            params=params
        )

        return response

    def mark_incident_as_read_request(self, lumu_incident_id):
        params = assign_params(key=self.api_key)

        response = self._http_request(
            "POST",
            f"api/incidents/{lumu_incident_id}/mark-as-read",
            params=params,
            resp_type="text"
        )

        return response

    def mute_incident_request(self, lumu_incident_id, comment):
        params = assign_params(key=self.api_key)
        data = {"comment": comment}

        response = self._http_request(
            "POST",
            f"api/incidents/{lumu_incident_id}/mute",
            params=params,
            json_data=data,
            resp_type="text"
        )

        return response

    def unmute_incident_request(self, lumu_incident_id, comment):
        params = assign_params(key=self.api_key)
        data = {"comment": comment}

        response = self._http_request(
            "POST",
            f"api/incidents/{lumu_incident_id}/unmute",
            params=params,
            json_data=data,
            resp_type="text"
        )

        return response

    def consult_incidents_updates_through_rest_request(self, offset, items, time):
        params = assign_params(offset=offset, items=items, time=time, key=self.api_key)

        response = self._http_request(
            "GET",
            "api/incidents/open-incidents/updates",
            params=params
        )

        return response

    def close_incident_request(self, lumu_incident_id, comment):
        params = assign_params(key=self.api_key)
        data = {"comment": comment}

        response = self._http_request(
            "POST",
            f"api/incidents/{lumu_incident_id}/close",
            params=params,
            json_data=data,
            resp_type="text"
        )

        return response


""" HELPER FUNCTIONS """


def get_hmac_sha256(key: Optional[str], comment: str):
    if key is None:
        key = ''
    return hmac.new(key.encode(), comment.encode(), hashlib.sha256).hexdigest()


def generate_hmac_sha256_msg(key: Optional[str], comment: str):
    hmac_code = get_hmac_sha256(key, comment)
    return f"{comment} hmacsha256:{hmac_code}"


def validate_hmac_sha256(key: str, comment_w_hmac: str, separator="hmacsha256:"):
    """

    :param key:
    :param comment_w_hmac: Resolved, from: ServiceNow Thu Nov 10 2022 07:56:13 GMT-0800 (PST),
    close_code: Solution provided, close_notes: ddddddddddddd hmacsha256:
    a9d7947047c371a10a44d07b381152951c46b0c954f8ddf1eeefc29fd120b8ae
    :param separator:
    :return:
    """
    result = [piece.strip() for piece in comment_w_hmac.split(separator)]
    if len(result) != 2:
        return False
    comment, hash_mac = result
    if get_hmac_sha256(key, comment) == hash_mac:
        return True
    return False


def is_msg_from_third_party(key, comment):
    if comment and validate_hmac_sha256(key=key, comment_w_hmac=comment):
        return True
    return False


def add_prefix_to_comment(commnet: Optional[str]) -> str:
    return f"from XSOAR Cortex {datetime.today():%Y%m%d_%H%M%S} {commnet},"


""" COMMAND FUNCTIONS """


def retrieve_labels_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page = args.get("page")
    items = args.get("limit")

    response = client.retrieve_labels_request(page, items)
    command_results = CommandResults(
        outputs_prefix="Lumu.RetrieveLabels",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Labels', response.get('labels', []), headerTransform=pascalToSpace, removeNull=True)
        + '\n'
        + tableToMarkdown('paginationInfo', response.get('paginationInfo', []), headerTransform=pascalToSpace, removeNull=True)
    )

    return command_results


def retrieve_a_specific_label_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    label_id = args.get("label_id")

    response = client.retrieve_a_specific_label_request(label_id)

    command_results = CommandResults(
        outputs_prefix="Lumu.RetrieveASpecificLabel",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Label', response, headerTransform=pascalToSpace, removeNull=True)
    )

    return command_results


def retrieve_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page = args.get("page")
    items = args.get("limit")
    fromdate = args.get("fromdate")
    todate = args.get("todate")
    status = args.get("status")
    adversary_types = args.get("adversary_types")
    labels = args.get("labels")

    status = argToList(status)
    adversary_types = argToList(adversary_types)
    labels = argToList(labels)
    labels = [int(label) for label in labels]

    response = client.retrieve_incidents_request(
        page, items, fromdate, todate, status, adversary_types, labels
    )
    command_results = CommandResults(
        outputs_prefix="Lumu.RetrieveIncidents",
        outputs_key_field="id",
        outputs=response.get("items"),
        raw_response=response,
        readable_output=tableToMarkdown('Incidents', response.get('items', []), headerTransform=pascalToSpace, removeNull=True)
        + '\n'
        + tableToMarkdown('paginationInfo', response.get('paginationInfo', []), headerTransform=pascalToSpace, removeNull=True)
    )
    return command_results


def retrieve_a_specific_incident_details_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    lumu_incident_id = args.get("lumu_incident_id")

    response = client.retrieve_a_specific_incident_details_request(lumu_incident_id)
    human_response = response.copy()
    actions = human_response.pop("actions", [])
    command_results = CommandResults(
        outputs_prefix="Lumu.RetrieveASpecificIncidentDetails",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Incident', human_response, headerTransform=pascalToSpace, removeNull=True)
        + '\n'
        + tableToMarkdown('Actions', actions, headerTransform=pascalToSpace, removeNull=True)
    )

    return command_results


def retrieve_a_specific_incident_context_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    lumu_incident_id = args.get("lumu_incident_id")
    hash = args.get("hash")

    response = client.retrieve_a_specific_incident_context_request(
        lumu_incident_id, hash
    )
    command_results = CommandResults(
        outputs_prefix="Lumu.RetrieveASpecificIncidentContext",
        outputs_key_field="adversary_id",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Incident', response, headerTransform=pascalToSpace, removeNull=True)
    )

    return command_results


def comment_a_specific_incident_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    lumu_incident_id = args.get("lumu_incident_id")
    comment = generate_hmac_sha256_msg(
        client.api_key, add_prefix_to_comment(args.get("comment"))
    )

    response = client.comment_a_specific_incident_request(lumu_incident_id, comment)
    response = {"statusCode": 200, "response": response}

    command_results = CommandResults(
        outputs_prefix="Lumu.CommentASpecificIncident",
        outputs=response,
        raw_response=response,
        readable_output='Comment added to the incident successfully.'
    )

    return command_results


def retrieve_open_incidents_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    page = args.get("page")
    items = args.get("limit")
    adversary_types = args.get("adversary_types")
    labels = args.get("labels")

    adversary_types = argToList(adversary_types)
    labels = argToList(labels)
    labels = [int(label) for label in labels]

    response = client.retrieve_open_incidents_request(
        page, items, adversary_types, labels
    )
    command_results = CommandResults(
        outputs_prefix="Lumu.RetrieveOpenIncidents",
        outputs_key_field="id",
        outputs=response.get("items"),
        raw_response=response,
        readable_output=tableToMarkdown('Incidents', response.get('items', []), headerTransform=pascalToSpace, removeNull=True)
        + '\n'
        + tableToMarkdown('paginationInfo', response.get('paginationInfo', []), headerTransform=pascalToSpace, removeNull=True)
    )

    return command_results


def retrieve_muted_incidents_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    page = args.get("page")
    items = args.get("limit")
    adversary_types = args.get("adversary_types")
    labels = args.get("labels")

    adversary_types = argToList(adversary_types)
    labels = argToList(labels)
    labels = [int(label) for label in labels]

    response = client.retrieve_muted_incidents_request(
        page, items, adversary_types, labels
    )
    command_results = CommandResults(
        outputs_prefix="Lumu.RetrieveMutedIncidents",
        outputs_key_field="id",
        outputs=response.get("items"),
        raw_response=response,
        readable_output=tableToMarkdown('Incidents', response.get('items', []), headerTransform=pascalToSpace, removeNull=True)
        + '\n'
        + tableToMarkdown('paginationInfo', response.get('paginationInfo', []), headerTransform=pascalToSpace, removeNull=True)
    )

    return command_results


def retrieve_closed_incidents_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    page = args.get("page")
    items = args.get("limit")
    adversary_types = args.get("adversary_types")
    labels = args.get("labels")

    adversary_types = argToList(adversary_types)
    labels = argToList(labels)
    labels = [int(label) for label in labels]

    response = client.retrieve_closed_incidents_request(
        page, items, adversary_types, labels
    )
    command_results = CommandResults(
        outputs_prefix="Lumu.RetrieveClosedIncidents",
        outputs_key_field="id",
        outputs=response.get("items"),
        raw_response=response,
        readable_output=tableToMarkdown('Incidents', response.get('items', []), headerTransform=pascalToSpace, removeNull=True)
        + '\n'
        + tableToMarkdown('paginationInfo', response.get('paginationInfo', []), headerTransform=pascalToSpace, removeNull=True)
    )

    return command_results


def retrieve_endpoints_by_incident_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    lumu_incident_id = args.get("lumu_incident_id")
    page = args.get("page")
    items = args.get("limit")

    response = client.retrieve_endpoints_by_incident_request(
        lumu_incident_id, page, items
    )
    command_results = CommandResults(
        outputs_prefix="Lumu.RetrieveEndpointsByIncident",
        outputs_key_field="label",
        outputs=response.get("items"),
        raw_response=response,
        readable_output=tableToMarkdown('Incident endpoints', response.get('items', []),
                                        headerTransform=pascalToSpace, removeNull=True)
        + '\n'
        + tableToMarkdown('paginationInfo', response.get('paginationInfo', []), headerTransform=pascalToSpace, removeNull=True)
    )

    return command_results


def mark_incident_as_read_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    lumu_incident_id = args.get("lumu_incident_id")
    try:
        response = client.mark_incident_as_read_request(lumu_incident_id)
    except DemistoException as err:

        error_msg = "Failed to parse json object from response: b''"
        if str(err) == error_msg:
            response = {"statusCode": 200}
        else:
            raise DemistoException(err)
    command_results = CommandResults(
        outputs_prefix="Lumu.MarkIncidentAsRead",
        outputs=response,
        raw_response=response,
        readable_output='Marked as read the incident successfully.'
    )

    return command_results


def mute_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    lumu_incident_id = args.get("lumu_incident_id")
    comment = generate_hmac_sha256_msg(
        client.api_key, add_prefix_to_comment(args.get("comment"))
    )
    response = client.mute_incident_request(lumu_incident_id, comment)
    response = {"statusCode": 200, "response": response}

    command_results = CommandResults(
        outputs_prefix="Lumu.MuteIncident",
        outputs=response,
        raw_response=response,
        readable_output='Muted the incident successfully.'
    )

    return command_results


def unmute_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    lumu_incident_id = args.get("lumu_incident_id")
    comment = generate_hmac_sha256_msg(
        client.api_key, add_prefix_to_comment(args.get("comment"))
    )
    response = client.unmute_incident_request(lumu_incident_id, comment)
    response = {"statusCode": 200, "response": response}

    command_results = CommandResults(
        outputs_prefix="Lumu.UnmuteIncident",
        outputs=response,
        raw_response=response,
        readable_output='Unmute the incident successfully.'
    )

    return command_results


def close_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    lumu_incident_id = args.get("lumu_incident_id")
    comment = generate_hmac_sha256_msg(
        client.api_key, add_prefix_to_comment(args.get("comment"))
    )
    response = client.close_incident_request(lumu_incident_id, comment)
    response = {"statusCode": 200, "response": response}

    command_results = CommandResults(
        outputs_prefix="Lumu.CloseIncident",
        outputs=response,
        raw_response=response,
        readable_output='Closed the incident successfully.'
    )

    return command_results


def consult_incidents_updates_through_rest_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    offset = args.get("offset")
    items = args.get("limit")
    time = args.get("time")

    response = client.consult_incidents_updates_through_rest_request(
        offset, items, time
    )
    command_results = CommandResults(
        outputs_prefix="Lumu.ConsultIncidentsUpdatesThroughRest",
        outputs=response,
        raw_response=response,
    )

    return command_results


def fetch_incidents(client: Client, first_fetch_time, last_run, items, time):
    last_fetch = last_run.get("last_fetch", None)
    last_fetch = int(last_fetch or first_fetch_time)

    response = client.consult_incidents_updates_through_rest_request(
        last_fetch, items, time
    )

    events = response["updates"]
    next_start_time = str(response["offset"])
    incidents = []
    incidents_id = []
    today = datetime.now().strftime(DATE_FORMAT)

    for event in events:
        if "OpenIncidentsStatusUpdated" in event:
            continue
        lumu_event_type_name = list(event.keys())[0]
        event_doc = event[lumu_event_type_name]
        event_doc["lumu_event_type"] = lumu_event_type_name
        event_doc["lumu_source_name"] = "lumu"

        if "openIncidentsStats" in event_doc:
            del event_doc["openIncidentsStats"]

        if "incident" in event_doc:
            inc_id = event_doc["incident"]["id"]
            del event_doc["incident"]["id"]
            event_doc.update(event_doc["incident"].copy())
            del event_doc["incident"]
        else:
            inc_id = event_doc["incidentId"]

        event_doc["lumu_incidentId"] = inc_id
        event_doc["lumu_status"] = event_doc.get("status", "N/A")

        if lumu_event_type_name in status_msg_types:
            if is_msg_from_third_party(
                key=client.api_key, comment=event_doc.get("comment", "na")
            ):
                # ignore to avoid a loop
                demisto.debug(
                    f"Ignoring Message ({lumu_event_type_name} - {inc_id}) from Cortex to not create a loop between both "
                    f"parties"
                )
                continue

        event_doc["comment"] = event_doc.get("comment") or "from fetching process"

        event_doc |= {
            "severity": 2,
            "status": 1,
            "mirror_instance": INTEGRATION_INSTANCE,
            "mirror_id": str(inc_id),
            "mirror_direction": MIRROR_DIRECTION,
            "mirror_last_sync": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mirror_tags": MIRROR_TAGS,
        }

        incident = {
            "name": f'lumu - {event_doc.get("description","")} - {inc_id}',
            "occurred": event_doc["timestamp"] if "timestamp" in event_doc else today,
            "dbotMirrorId": str(inc_id),
            "rawJSON": json.dumps(event_doc),
        }
        incidents.append(incident)
        incidents_id.append(str(inc_id))

    incs_to_cortex = []
    if incidents_id:
        cache = get_integration_context()
        if not cache:
            cache["cache"] = []
            cache["lumu_incidentsId"] = []

        incidents_id = list(set(incidents_id))
        cache["cache"].append(incidents_id)

        for inc in incidents:
            if inc["dbotMirrorId"] in cache["lumu_incidentsId"]:
                # skip incident, avoid duplication in cortex
                # do not add the incident, already exist
                continue
            else:
                incs_to_cortex.append(inc)
                cache["lumu_incidentsId"].append(inc["dbotMirrorId"])
        cache["lumu_incidentsId"] = list(set(cache["lumu_incidentsId"]))
        demisto.debug(
            f'There are {len(cache["cache"])} events queued ready to process their updates'
        )
        set_integration_context(cache)
    next_run = {"last_fetch": str(next_start_time)}

    return next_run, incs_to_cortex


def get_modified_remote_data_command(
    client: Client, args: Dict[str, str]
) -> GetModifiedRemoteDataResponse:
    incidents_id = []
    try:

        cache = get_integration_context()

        incidents_id = cache["cache"].pop(0)
        demisto.debug(
            f'FIFO processing, there are {len(cache["cache"])} events left to process'
        )

    except IndexError:
        incidents_id = []
    finally:

        set_integration_context(cache)
        return GetModifiedRemoteDataResponse(incidents_id)


def get_remote_data_command(client, args):
    parsed_args = GetRemoteDataArgs(args)
    try:
        new_incident_data: Dict = client.retrieve_a_specific_incident_details_request(
            parsed_args.remote_incident_id
        )

        parsed_entries = []

        new_incident_data["lumu_incidentId"] = new_incident_data["id"]

        if lumu_actions := new_incident_data.get("actions"):
            new_incident_data[
                "comment"
            ] = f'{lumu_actions[0]["action"]} - {lumu_actions[0]["comment"]}'

            entry_comment = {
                "Type": EntryType.NOTE,
                "Contents": f'{lumu_actions[0]["action"]} - {lumu_actions[0]["comment"]}',
                "ContentsFormat": EntryFormat.MARKDOWN,
                "Note": True,
            }
            parsed_entries.append(entry_comment)

        new_incident_data["incomming_mirror_error"] = ""

        if inc_desc := new_incident_data.get("description"):
            new_incident_data[
                "name"
            ] = f'lumu - {inc_desc} - {new_incident_data["lumu_incidentId"]}'

        for field_to_delete in FIELDS_TO_REMOVE_FROM_MIROR_IN:
            if field_to_delete in new_incident_data:
                del new_incident_data[field_to_delete]

        inc_id = new_incident_data["lumu_incidentId"]
        lumu_first_contact = new_incident_data.get("firstContactDetails", {}).get(
            "datetime", "N/A"
        )
        lumu_adversary_types = ", ".join(new_incident_data.get("adversaryTypes", ""))
        lumu_desc = new_incident_data.get("description")
        lumu_total_contacts = new_incident_data.get("contacts", "N/A")
        lumu_total_endpoint = new_incident_data.get("totalEndpoints", "N/A")
        lumu_url = (
            f"https://portal.lumu.io/compromise/incidents/show/{inc_id}/detections"
        )

        description = (
            f"Incident ID:  {inc_id} \nDate of first contact: {lumu_first_contact} \nAdversary type:"
            f" {lumu_adversary_types} \nDescription: {lumu_desc} \nTotal contacts: {lumu_total_contacts} "
            f"\nTotal Endpoints: {lumu_total_endpoint} "
            f"\nURL: {lumu_url}"
        )

        new_incident_data["description"] = (
            new_incident_data["description"] + " - " + description
        )
        entry_comment = {
            "Type": EntryType.NOTE,
            "Contents": description,
            "ContentsFormat": EntryFormat.MARKDOWN,
            "Note": True,
        }
        parsed_entries.append(entry_comment)

        if "close" in new_incident_data.get("status", ""):
            entry_comment = {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": f'Lumu Portal : {lumu_actions[0]["comment"]}',  # type: ignore[index]
                },
                "ContentsFormat": EntryFormat.JSON,
            }
            parsed_entries.append(entry_comment)
            demisto.debug(
                f"incident closed from Lumu, sync with Cortex {lumu_desc:$^40}"
            )
        new_incident_data["lumu_status"] = new_incident_data.get("status", "N/A")

        return GetRemoteDataResponse(new_incident_data, parsed_entries)
    except Exception as e:
        demisto.debug(f"get_remote_data_command error {e}")
        if "Rate limit exceeded" in str(
            e
        ):  # modify this according to the vendor's spesific message
            return_error("API rate limit")


def get_mapping_fields_command():
    lumu_type_scheme = SchemeTypeMapping(type_name="incident type Lumu")
    for field in [
        "mute",
        "comment",
        "unmute",
        "close",
        "description",
        "lumu_status",
        "status",
    ]:
        lumu_type_scheme.add_field(
            name=field, description="the description for the Lumu field"
        )

    return GetMappingFieldsResponse(lumu_type_scheme)


def update_remote_system_command(client: Client, args: Dict[str, Any]) -> str:
    """update-remote-system command: pushes local changes to the remote system

    :type client: ``Client``
    :param client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id

    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely

    :rtype: ``str``
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    new_incident_id: str = parsed_args.remote_incident_id

    if (not parsed_args.entries) and (not parsed_args.delta):
        return new_incident_id

    if parsed_args.delta:
        original_commnet = parsed_args.delta.get("comment", "")
        new_comment = add_prefix_to_comment(original_commnet)
        key = client.api_key
        try:
            if reason := parsed_args.delta.get("closeReason"):
                notes = parsed_args.delta.get("closeNotes", "")
                user = parsed_args.delta.get("closingUserId", "")
                new_comment += f", {notes=}, {reason=}, {user=}"
                new_comment = generate_hmac_sha256_msg(key, new_comment)
                response = client.close_incident_request(new_incident_id, new_comment)
                response = {"statusCode": 200, "response": response}

            elif (lumu_status := parsed_args.delta.get("lumustatus")) or (
                lumu_status := parsed_args.delta.get("lumu_status")
            ):
                if lumu_status in ["mute", "muted"]:

                    new_comment = generate_hmac_sha256_msg(key, new_comment)

                    response = client.mute_incident_request(
                        new_incident_id, new_comment
                    )
                    response = {"statusCode": 200, "response": response}

                elif lumu_status in ["unmute", "unmuted"]:
                    new_comment = generate_hmac_sha256_msg(key, new_comment)
                    response = client.unmute_incident_request(
                        new_incident_id, new_comment
                    )
                    response = {"statusCode": 200, "response": response}

                elif lumu_status in ["close", "closed"]:
                    msg = "to close an incident, it has to be in the CLOSE INCIDENT option in the ACTION button"
                    response = {"statusCode": 404, "reason": msg}
                    demisto.debug(msg)

                elif original_commnet:
                    new_comment = generate_hmac_sha256_msg(key, new_comment)
                    response = client.comment_a_specific_incident_request(
                        new_incident_id, new_comment
                    )
                    response = {"statusCode": 200, "response": response}

                else:
                    response = {"statusCode": 404, "reason": "lumu status not found"}

            elif original_commnet:

                new_comment = generate_hmac_sha256_msg(key, new_comment)

                response = client.comment_a_specific_incident_request(
                    new_incident_id, new_comment
                )
                response = {"statusCode": 200, "response": response}

        except DemistoException as err:
            raise DemistoException(repr(err))

    demisto.debug(
        f"{response=}, {parsed_args.delta=}, {parsed_args.remote_incident_id=}, {parsed_args.incident_changed}"
    )

    return new_incident_id


def clear_cache_command():
    cache: Dict = {}
    cache["cache"] = []
    cache["lumu_incidentsId"] = []
    set_integration_context(cache)
    command_results = CommandResults(
        outputs_prefix="Lumu.ClearCache",
        outputs=f"cache cleared {get_integration_context()=}",
        raw_response=f"cache cleared {get_integration_context()=}",
        readable_output=f"cache cleared {get_integration_context()=}"
    )

    return command_results


def get_cache_command():

    cache = get_integration_context()
    command_results = CommandResults(
        outputs_prefix="Lumu.GetCache",
        outputs=cache,
        raw_response=cache,
        readable_output=tableToMarkdown('Cache', cache, headerTransform=pascalToSpace, removeNull=True)
    )

    return command_results


def test_module(client: Client, args: Dict[str, Any]) -> None:
    # Test functions here
    try:
        page = args.get("page")
        items = args.get("limit")
        client.retrieve_labels_request(page, items)
        return_results("ok")
    except Exception as e:
        msg_err = f"verify Lumu API Key and Network Connections - {e.__class__} - {repr(e)} - {e}"
        return_results(msg_err)


""" MAIN FUNCTION """


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get("url")
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    offset_set_off = params.get("fetch_offset", "0")
    items = int(params.get("total_items_per_lumu_fetch", 30))
    time_last = int(params.get("max_time_fetching_lumu_incident", 4))

    headers: Dict = {"Content-Type": "application/json"}

    command = demisto.command()
    demisto.debug(f"Command being called is {command.upper():*^40}")

    try:
        urllib3.disable_warnings()
        client: Client = Client(url, verify_certificate, proxy, headers=headers)
        client.api_key = params.get("api_key")
        commands = {
            "lumu-retrieve-labels": retrieve_labels_command,
            "lumu-retrieve-a-specific-label": retrieve_a_specific_label_command,
            "lumu-retrieve-incidents": retrieve_incidents_command,
            "lumu-retrieve-a-specific-incident-details": retrieve_a_specific_incident_details_command,
            "lumu-retrieve-a-specific-incident-context": retrieve_a_specific_incident_context_command,
            "lumu-comment-a-specific-incident": comment_a_specific_incident_command,
            "lumu-retrieve-open-incidents": retrieve_open_incidents_command,
            "lumu-retrieve-muted-incidents": retrieve_muted_incidents_command,
            "lumu-retrieve-closed-incidents": retrieve_closed_incidents_command,
            "lumu-retrieve-endpoints-by-incident": retrieve_endpoints_by_incident_command,
            "lumu-mark-incident-as-read": mark_incident_as_read_command,
            "lumu-mute-incident": mute_incident_command,
            "lumu-unmute-incident": unmute_incident_command,
            "lumu-consult-incidents-updates-through-rest": consult_incidents_updates_through_rest_command,
            "lumu-close-incident": close_incident_command,
            "get-modified-remote-data": get_modified_remote_data_command,
            "get-remote-data": get_remote_data_command,
            "update-remote-system": update_remote_system_command,
        }

        if command == "test-module":
            test_module(client, args)
        elif (
            "fetch-incidents" in command
            or command == "fetch-incidents"
        ):

            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, offset_set_off, last_run, items, time_last)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
            count = Counter([inc["dbotMirrorId"] for inc in incidents])
            demisto.debug(
                f"total inc found: {len(incidents)}, {count=} {last_run=} {next_run=}"
            )

        elif command == "get-modified-remote-data":
            incidents_id = get_modified_remote_data_command(client, args)
            return_results(incidents_id)

        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, args))

        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())

        elif command == "update-remote-system":
            return_results(update_remote_system_command(client, args))

        elif command == "lumu-clear-cache":
            return_results(clear_cache_command())

        elif command == "lumu-get-cache":
            return_results(get_cache_command())

        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
