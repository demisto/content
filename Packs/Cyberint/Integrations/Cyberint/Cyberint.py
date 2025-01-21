# pylint: disable=unsubscriptable-object
""" IMPORTS """

import copy
from contextlib import closing
from collections.abc import Iterable

from CommonServerPython import *
from requests import Response

""" CONSTANTS """
STRFTIME = "%Y-%m-%d"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SEVERITIES = {"low": 1, "medium": 2, "high": 3, "very_high": 4}
CSV_FIELDS_TO_EXTRACT = ["Username", "Password"]

MIRROR_DIRECTION_MAPPING = {
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}

MIRRORING_FIELDS_XSOAR = [
    "cyberintstatus",
    "cyberintclosurereason",
    "cyberintclosurereasondescription",
]

MIRRORING_FIELDS_ARGOS = [
    "status",
    "closure_reason",
    "closure_reason_description",
]

MIRRORING_FIELDS_MAPPER = {
    "cyberintstatus": "status",
    "cyberintclosurereason": "closure_reason",
    "cyberintclosurereasondescription": "closure_reason_description",
}


class Client(BaseClient):
    """
    API Client to communicate with Cyberint API endpoints.
    """

    def __init__(self, base_url: str, access_token: str, verify_ssl: bool, proxy: bool):
        """
        Client for Cyberint RESTful API.

        Args:
            base_url (str): URL to access when getting alerts.
            access_token (str): Access token for authentication.
            verify_ssl (bool): specifies whether to verify the SSL certificate or not.
            proxy (bool): specifies if to use XSOAR proxy settings.
        """
        params = demisto.params()
        self._cookies = {"access_token": access_token}
        self._headers = {
            "X-Integration-Type": "XSOAR",
            "X-Integration-Instance-Name": demisto.integrationInstance(),
            "X-Integration-Instance-Id": "",
            "X-Integration-Customer-Name": params.get("client_name", ""),
            "X-Integration-Version": "1.1.4"
        }
        super().__init__(base_url=base_url, verify=verify_ssl, proxy=proxy)

    @logger
    def list_alerts(
        self,
        page: str | None,
        page_size: int | None,
        created_date_from: str | None,
        created_date_to: str | None,
        modification_date_from: str | None,
        modification_date_to: str | None,
        update_date_from: str | None,
        update_date_to: str | None,
        environments: list[str] | None,
        statuses: list[str] | None,
        severities: list[str] | None,
        types: list[str] | None,
    ) -> dict:
        """
        Retrieve a list of alerts according to parameters.

        Args:
            page (str): Index of page to return.
            page_size (int): Size of the page to return.
            created_date_from (str): Minimal ISO-Formatted creation date.
            created_date_to (str): Maximal ISO-Formatted creation date.
            modification_date_from (str): Minimal ISO-Formatted modification date.
            modification_date_to (str): Maximal ISO-Formatted modification date.
            update_date_from (str): Minimal ISO-Formatted update date.
            update_date_to (str): Maximal ISO-Formatted update date.
            environments (list(str)): Environments in which the alerts were created.
            statuses (list(str)): Alerts statuses.
            severities (list(str)): Alerts severities.
            types (list(str)): Alerts type.

        Returns:
            response (Response): API response from Cyberint.
        """
        body = {
            "page": page,
            "size": page_size,
            "include_csv_attachments_as_json_content": True,
            "filters": {
                "created_date": {"from": created_date_from, "to": created_date_to},
                "modification_date": {"from": modification_date_from, "to": modification_date_to},
                "update_date": {"from": update_date_from, "to": update_date_to},
                "environments": environments,
                "status": statuses,
                "severity": severities,
                "type": types,
            },
        }
        body = remove_empty_elements(body)
        response = self._http_request(method="POST", json_data=body, cookies=self._cookies, url_suffix="api/v1/alerts")
        return response

    def update_alerts(
        self,
        alerts: list[str],
        status: str | None,
        closure_reason: str | None = None,
        closure_reason_description: str | None = None,
    ) -> dict:
        """
        Update the status of one or more alerts

        Args:
            alerts (list(str)): Reference IDs for the alert(s)
            status (str): Desired status to update for the alert(s)
            closure_reason (str): Reason for updating the alerts status to closed.
            closure_reason_description (str): Reason for updating the alerts status to closed.

        Returns:
            response (Response): API response from Cyberint.
        """
        body = {
            "alert_ref_ids": alerts,
            "data": {
                "status": status,
                "closure_reason": closure_reason,
                "closure_reason_description": closure_reason_description,
            },
        }
        body = remove_empty_elements(body)
        response = self._http_request(
            method="PUT", json_data=body, cookies=self._cookies, url_suffix="api/v1/alerts/status"
        )
        return response

    def get_csv_file(self, alert_id: str, attachment_id: str, delimiter: bytes = b"\r\n") -> Iterable[str]:
        """
        Stream a CSV file attachment in order to extract data out of it.

        Args:
            alert_id (str): ID of the alert the CSV belongs to.
            attachment_id (str): ID of the specific CSV file.
            delimiter (str): Delimiter for the CSV file.

        Returns:
            row (generator(str)): Generator containing each line of the CSV.
        """
        url_suffix = f"api/v1/alerts/{alert_id}/attachments/{attachment_id}"
        with closing(
            self._http_request(method="GET", url_suffix=url_suffix, cookies=self._cookies, resp_type="all", stream=True)
        ) as r:
            for line in r.iter_lines(delimiter=delimiter):
                yield line.decode("utf-8").strip('"')

    def get_alert_attachment(self, alert_ref_id: str, attachment_id: str) -> Response:
        """
        Retrieve attachment by alert reference ID and attachment ID.

        Args:
            alert_ref_id (str): Reference ID of the alert.
            attachment_id (str): The ID of the attachment.

        Returns:
            Response: API response from Cyberint.
        """

        url_suffix = f"api/v1/alerts/{alert_ref_id}/attachments/{attachment_id}"
        return self._http_request(method="GET", cookies=self._cookies, url_suffix=url_suffix, resp_type="response")

    def get_alert(
        self,
        alert_ref_id: str,
    ) -> dict:
        """
        Retrieve attachment by alert reference ID and attachment ID.

        Args:
            alert_ref_id (str): Reference ID of the alert.

        Returns:
            Response: API response from Cyberint.
        """

        url_suffix = f"api/v1/alerts/{alert_ref_id}"
        return self._http_request(method="GET", cookies=self._cookies, url_suffix=url_suffix)

    def get_analysis_report(self, alert_ref_id: str) -> Response:
        """
        Retrieve analysis report by alert reference ID.

        Args:
            alert_ref_id (str): Reference ID of the alert.

        Returns:
            Response: API response from Cyberint.

        """
        url_suffix = f"api/v1/alerts/{alert_ref_id}/analysis_report"
        return self._http_request(method="GET", cookies=self._cookies, url_suffix=url_suffix, resp_type="response")


def test_module(client: Client):
    """
    Test the connection to the API by sending a normal request.

    Args:
        client (Client): Cyberint API  client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        result = client.list_alerts(*([None] * 12))
        if result:
            return "ok"
    except DemistoException as exception:
        if "Invalid token or token expired" in str(exception):
            error_message = (
                "Error verifying access token and / or URL, make sure the "
                "configuration parameters are correct."
            )
        else:
            error_message = str(exception)
        return error_message


def verify_input_date_format(date: str | None) -> str | None:
    """
    Make sure a date entered by the user is in the correct string format (with a Z at the end).

    Args:
        date (str): Date string given by the user. Can be None.

    Returns:
        str: Fixed date in the same format as the one needed by the API.
    """
    if date and not date.endswith("Z"):
        date += "Z"
    return date


def set_date_pair(start_date_arg: str | None, end_date_arg: str | None, date_range_arg: str | None
                  ) -> tuple[str | None, str | None]:
    """
    Calculate the date range to send to the API based on the arguments from the user.

    Args:
        start_date_arg (str): Optional start_date from the user.
        end_date_arg (str): Optional end_date from the user.
        date_range_arg (str): Optional date range from the user.

    Returns:
        start_date (str): Start date to send to the API.
        end_date (str): End date to send to the API.
    """
    if date_range_arg:
        start_date, end_date = parse_date_range(date_range=date_range_arg, date_format=DATE_FORMAT, utc=False)
        return start_date, end_date
    min_date = datetime.fromisocalendar(2020, 2, 1)
    start_date_arg = verify_input_date_format(start_date_arg)
    end_date_arg = verify_input_date_format(end_date_arg)
    if start_date_arg and not end_date_arg:
        end_date_arg = datetime.strftime(datetime.now(), DATE_FORMAT)
    elif end_date_arg and not start_date_arg:
        start_date_arg = datetime.strftime(min_date, DATE_FORMAT)
    return start_date_arg, end_date_arg


def extract_data_from_csv_stream(client: Client, alert_id: str, attachment_id: str, delimiter: bytes = b"\r\n"
                                 ) -> list[dict]:
    """
    Call the attachment download API and parse required fields.

    Args:
        client (Client): Cyberint API client.
        alert_id (str): ID of the alert the attachment belongs to.
        attachment_id (str): ID of the attachment itself.
        delimiter (bytes): Delimeter for the CSV file.

    Returns:
        list(dict): List of all the data found using the wanted fields.
    """
    first_line = True
    field_indexes = {}  # {wanted_field_name: wanted_field_index...}
    information_found = []
    for csv_line in client.get_csv_file(alert_id, attachment_id, delimiter):
        csv_line_separated = csv_line.split(",")
        if first_line:
            for field in CSV_FIELDS_TO_EXTRACT:
                try:
                    field_indexes[field] = csv_line_separated.index(field)
                except ValueError:
                    pass
            first_line = False
        else:
            try:
                extracted_field_data = {
                    field_name.lower(): csv_line_separated[field_index]
                    for field_name, field_index in field_indexes.items()
                }
                if extracted_field_data:
                    information_found.append(extracted_field_data)
            except IndexError:
                pass
    return information_found


def cyberint_alerts_fetch_command(client: Client, args: dict) -> CommandResults:
    """
    List alerts on cyberint according to parameters.

    Args:
        client (Client): Cyberint API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    created_date_from, created_date_to = set_date_pair(
        args.get("created_date_from", None),
        args.get("created_date_to", None),
        args.get("created_date_range", None),
    )
    modify_date_from, modify_date_to = set_date_pair(
        args.get("modification_date_from", None),
        args.get("modification_date_to", None),
        args.get("modification_date_range", None),
    )
    update_date_from, update_date_to = set_date_pair(
        args.get("updated_date_from", None),
        args.get("updated_date_to", None),
        args.get("updated_date_range", None),
    )
    if int(args.get("page_size", 10)) < 10 or int(args.get("page_size", 10)) > 100:
        raise DemistoException("Page size must be between 10 and 100.")
    result = client.list_alerts(
        args.get("page"),
        args.get("page_size"),
        created_date_from,
        created_date_to,
        modify_date_from,
        modify_date_to,
        update_date_from,
        update_date_to,
        argToList(args.get("environments")),
        argToList(args.get("statuses")),
        argToList(args.get("severities")),
        argToList(args.get("types")),
    )
    alerts = result.get("alerts", [])
    outputs = []
    for alert in alerts:
        alert_csv_id = alert.get("alert_data", {}).get("csv", {}).get("id", "")
        if alert_csv_id:
            alert["csv_data"] = {
                "csv_id": alert_csv_id,
                "name": dict_safe_get(alert, ["alert_data", "csv", "name"]),
                "content": dict_safe_get(alert, ["alert_data", "csv", "content"]),
            }
            extracted_csv_data = extract_data_from_csv_stream(client, alert.get("ref_id", ""), alert_csv_id)
            alert["alert_data"]["csv"] = extracted_csv_data
        outputs.append(alert)
    total_alerts = result.get("total")
    table_headers = ["id", "ref_id", "title", "status", "severity", "created_date", "update_date", "type", "environment"]
    readable_output = f'Total alerts: {total_alerts}\nCurrent page: {args.get("page", 1)}\n'
    readable_output += tableToMarkdown(name="Cyberint alerts:", t=outputs, headers=table_headers, removeNull=True)
    return CommandResults(
        outputs_key_field="ref_id",
        outputs_prefix="Cyberint.Alert",
        readable_output=readable_output,
        raw_response=result,
        outputs=outputs,
    )


def cyberint_alerts_status_update(client: Client, args: dict) -> CommandResults:
    """
        Update the status of one or more alerts

        Args:
        client (Client): Cyberint API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_ids = argToList(args.get("alert_ref_ids"))
    status = args.get("status")
    closure_reason = args.get("closure_reason")
    closure_reason_description = args.get("closure_reason_description")

    if status == "closed" and not closure_reason:
        raise DemistoException("You must supply a closure reason when closing an alert.")

    if closure_reason == "other" and not closure_reason_description:
        raise DemistoException("You must supply a closure_reason_description when specify closure_reason to 'other'.")

    response = client.update_alerts(
        alerts=alert_ids,
        status=status,
        closure_reason=closure_reason,
        closure_reason_description=closure_reason_description,
    )
    table_headers = ["ref_id", "status", "closure_reason", "closure_reason_description"]
    outputs = []
    for alert_id in alert_ids:
        outputs.append(
            {
                "ref_id": alert_id,
                "status": status,
                "closure_reason": closure_reason,
                "closure_reason_description": closure_reason_description,
            }
        )

    readable_output = tableToMarkdown(
        name="Cyberint alerts updated information:", t=outputs, headers=table_headers, removeNull=True
    )
    return CommandResults(
        outputs_key_field="ref_id",
        outputs_prefix="Cyberint.Alert",
        readable_output=readable_output,
        raw_response=response,
        outputs=outputs,
    )


def cyberint_alerts_get_attachment_command(client: Client, alert_ref_id: str, attachment_id: str, attachment_name: str
                                           ) -> dict:
    """
    Retrieve attachment by alert reference ID and attachment internal ID.
    Attachments includes: CSV files , Screenshots, and alert attachments files.

    Args:
        client (Client): Cyberint API client.
        alert_ref_id (str): Reference ID of the alert.
        attachment_id (str): The ID of the alert attachment.
        attachment_name (str): The file name of the alert attachment.

    Returns:
        Dict: Alert attachment file result.

    """

    raw_response = client.get_alert_attachment(alert_ref_id, attachment_id)

    return fileResult(filename=attachment_name, data=raw_response.content)


def cyberint_alerts_get_analysis_report_command(client: Client, alert_ref_id: str, report_name: str) -> dict:
    """
    Retrieve expert analysis report by alert reference ID and report name.

    Args:
        client (Client): Cyberint API client.
        alert_ref_id (str): Reference ID of the alert.
        report_name (str): The name of the alert expert analysis report.

    Returns:
        Dict: Alert attachment file result.

    """
    raw_response = client.get_analysis_report(alert_ref_id)
    return fileResult(filename=report_name, data=raw_response.content)


def get_attachment_name(attachment_name: str) -> str:
    """
    Retrieve attachment name or error string if none is provided.

    Args:
        attachment_name (str): Attachment name to retrieve.

    Returns:
        str: The attachment file name or 'xsoar_untitled_attachment' by default.

    """
    if attachment_name is None or attachment_name == "":
        return "xsoar_untitled_attachment"
    return attachment_name


def create_fetch_incident_attachment(raw_response: Response, attachment_file_name: str) -> dict:
    """
    Create suitable attachment information dictionary object.
    This dictionary object will be used as an entry in the fetch-incidents attachments list.
    For each attachment file, it is necessary to save the relevant fields that return from this function,
    in order to represent the attachment in the layout.

    Args:
        raw_response (Response): Cyberint API response from retrieving the alert attachment.
        attachment_file_name (str): The name of the attachment.

    Returns:
        dict: Attachment file information.Includes - path, name, and showMediaFile.
    """

    attachment_name = get_attachment_name(attachment_file_name)
    file_result = fileResult(filename=attachment_name, data=raw_response.content)

    return {"path": file_result["FileID"], "name": attachment_name, "showMediaFile": True}


def get_alert_attachments(client: Client, attachment_list: list, attachment_type: str, alert_id: str) -> list:
    """
    Retrieve all alert attachments files - Attachments, CSV, Screenshot, and Analysis report.
    For each attachment, we save and return the relevant fields in order to represent the attachment in the layout.

    Args:
        client (Client): Cyberint API client.
        attachment_list (List): Alert attachments list. Each element in the list contains id, mimetype and name fields.
        attachment_type (str): The type of the attachment. Can be 'attachment' or 'analysis_report'.
        alert_id (str): The ID of the alert.

    Returns:
        (List): incident attachments details - contains the file details of the attachment.

    """
    incident_attachments = []

    for attachment in attachment_list:
        if attachment:
            if attachment_type == "analysis_report":
                raw_response = client.get_analysis_report(alert_id)
                incidents_attachment = create_fetch_incident_attachment(raw_response, attachment.get("name", None))
            else:
                raw_response = client.get_alert_attachment(alert_id, attachment.get("id", None))
                incidents_attachment = create_fetch_incident_attachment(raw_response, attachment.get("name", None))

            if incidents_attachment:
                incident_attachments.append(incidents_attachment)

    return incident_attachments


def convert_date_time_args(date_time: str) -> str:
    """Convert str to datetime.

    Args:
        date_time (str): The datetime str.

    Returns:
        str: The updated datetime.
    """
    if datetime_arg := arg_to_datetime(date_time, required=False):
        return datetime_arg.strftime(DATE_FORMAT)
    return ""


def get_modified_remote_data(client: Client, args: dict[str, Any]) -> GetModifiedRemoteDataResponse:
    """
    Queries for incidents that were modified since the last update.

    Args:
        client: Cyberint API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        GetModifiedRemoteDataResponse: modified tickets from Cyberint.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = remote_args.last_update

    demisto.debug(f"******** Get modified remote data from {last_update}")
    update_date_from = convert_date_time_args(last_update)
    update_date_to = datetime.strftime(datetime.now(), DATE_FORMAT)
    demisto.debug(f"******** Get modified remote data {update_date_from=} {update_date_to=}")
    modified_tickets = []

    response = client.list_alerts(
        page="1",
        page_size=50,
        update_date_from=update_date_from,
        update_date_to=update_date_to,
        created_date_from=None,
        created_date_to=None,
        modification_date_from=None,
        modification_date_to=None,
        environments=None,
        statuses=None,
        severities=None,
        types=None,
    )

    for ticket in response["alerts"]:
        modified_tickets.append(ticket["ref_id"])

    demisto.debug(f"******** There are {len(modified_tickets)} modified incidents from Cyberint")

    return GetModifiedRemoteDataResponse(modified_tickets)


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
    Pulls the remote schema for the different incident types, and their associated incident fields, from the remote system.

    Returns:
    GetMappingFieldsResponse: Dictionary with keys as field names.
    """
    demisto.debug("******** Get Cyberint mapping fields")
    mapping_response = GetMappingFieldsResponse()

    incident_type_scheme = SchemeTypeMapping(type_name="Cyberint Incident")

    for field in MIRRORING_FIELDS_ARGOS:
        incident_type_scheme.add_field(field)

    mapping_response.add_scheme_type(incident_type_scheme)
    return mapping_response


def update_remote_system(client: Client, args: dict[str, Any],
                         ) -> str:
    """
    This command pushes local changes to the remote system.
    Args:
        client: XSOAR Client to use.
        args:
            args['data']: the data to send to the remote system.
            args['entries']: the entries to send to the remote system.
            args['incident_changed']: boolean telling us if the local incident indeed changed or not.
            args['remote_incident_id']: the remote incident id.
    Returns: The remote incident id - ticket_id
    """
    parsed_args = UpdateRemoteSystemArgs(args)

    incident_id = parsed_args.remote_incident_id

    demisto.debug(
        f"******** Got the following delta keys {str(list(parsed_args.delta.keys()))}"
        if parsed_args.delta
        else "******** There is no delta fields in Cyberint"
    )

    try:
        if parsed_args.incident_changed:
            demisto.debug(f"******** Incident changed: {parsed_args.incident_changed}, {parsed_args.delta=}")

            update_args = parsed_args.delta
            demisto.debug(f"******** Sending incident with remote ID [{incident_id}] to Cyberint\n")

            updated_arguments = {}
            if updated_status := update_args.get("status"):
                closure_reason = update_args.get("closure_reason", "other")
                closure_reason_description = (
                    update_args.get("closure_reason_description", "user wasn't specified closure reason when closed alert"))
                if updated_status != "closed":
                    updated_arguments["status"] = updated_status
                else:
                    updated_arguments["status"] = updated_status
                    updated_arguments["closure_reason"] = closure_reason
                    updated_arguments["closure_reason_description"] = closure_reason_description
            else:
                cyberint_response = client.get_alert(alert_ref_id=incident_id)
                cyberint_alert: dict[str, Any] = cyberint_response["alert"]
                cyberint_status = cyberint_alert.get("status")
                updated_arguments["status"] = cyberint_status

            updated_arguments["alerts"] = [incident_id]

            demisto.debug(f"******** Remote ID [{incident_id}] to Cyberint. {updated_arguments=}|| {update_args=}")

            client.update_alerts(**updated_arguments)

        demisto.debug(f"******** Remote data of {incident_id}: {parsed_args.data}")

    except Exception as error:
        demisto.error(
            f"Error in Cyberint outgoing mirror for incident {incident_id}\nError message: {error}"
        )

    finally:
        return incident_id


def get_remote_data_command(
    client: Client,
    args: dict[str, Any],
    params: dict[str, Any],
) -> GetRemoteDataResponse:
    """
    Gets new information about the incidents in the remote system
    and updates existing incidents in Cortex XSOAR.
    Args:
        client: Cyberint API client.
        args (Dict[str, Any]): command arguments.
    Returns:
        List[Dict[str, Any]]: first entry is the incident (which can be completely empty) and the new entries.
    """
    parsed_args = GetRemoteDataArgs(args)
    incident_id = parsed_args.remote_incident_id
    last_update = date_to_epoch_for_fetch(arg_to_datetime(parsed_args.last_update))
    demisto.debug(f"******** Check {incident_id} update from {last_update}")

    response = client.get_alert(alert_ref_id=incident_id)
    if not isinstance(response, dict):
        response = json.loads(response)

    if response is None:
        demisto.error("Invalid response from Cyberint")
        return GetRemoteDataResponse({}, [])

    mirrored_ticket: dict[str, Any] = response.get("alert", {})

    if mirrored_ticket is None or not mirrored_ticket:
        return GetRemoteDataResponse({}, [])

    ticket_last_update = date_to_epoch_for_fetch(arg_to_datetime(mirrored_ticket.get("update_date")))

    mirrored_ticket["cyberintstatus"] = MIRRORING_FIELDS_MAPPER.get(mirrored_ticket["status"])
    mirrored_ticket["cyberintclosurereason"] = mirrored_ticket.get("closure_reason")
    mirrored_ticket["cyberintclosurereasondescription"] = mirrored_ticket.get("closure_reason_description")

    demisto.debug(f"******** Alert {incident_id} - {ticket_last_update=} {last_update=}")

    entries = []

    if mirrored_ticket.get("status") == "closed" and params.get("close_incident"):
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": "Closed from Cyberint.",
                },
                "ContentsFormat": EntryFormat.JSON,
            }
        )

    return GetRemoteDataResponse(mirrored_ticket, entries)


def date_to_epoch_for_fetch(date: datetime | None) -> int:
    """
    Converts datetime object to date in epoch timestamp (in seconds),
    for fetch command.

    Args:
        date (Optional[datetime]): The datetime to convert.

    Returns:
        int: date in epoch timestamp.
    """
    if date is None:
        return int(datetime.now().timestamp())
    return date_to_timestamp(date) // 1000


def fetch_incidents(
    client: Client,
    last_run: dict[str, int],
    first_fetch_time: str,
    fetch_severity: list[str] | None,
    fetch_status: list[str] | None,
    fetch_type: list[str] | None,
    fetch_environment: list[str] | None,
    max_fetch: int | None,
    duplicate_alert: bool,
    mirror_direction: str | None,
    close_alert: bool,
) -> tuple[dict[str, int], list[dict]]:
    """
    Fetch incidents (alerts) each minute (by default).
    Args:
        client (Client): Cyberint Client.
        last_run (dict): Dict with last_fetch object,
                                  saving the last fetch time(in millisecond timestamp).
        first_fetch_time (dict): Dict with first fetch time in str (ex: 3 days ago).
        fetch_severity (list(str)): Severities to fetch.
        fetch_status (list(str)): Statuses to fetch.
        fetch_type (list(str)): Types to fetch.
        fetch_environment (list(str)): Environments to fetch.
        max_fetch (int): Max number of alerts to fetch.
        duplicate_alert (bool): Whether to duplicate alerts.
        mirror_direction (str): Direction to mirror.
        close_alert (bool): Whether to close alerts.
    Returns:
        Tuple of next_run (seconds timestamp) and the incidents list
    """
    #  Start by setting the time to fetch from.
    # use condition statement to avoid mypy error

    last_fetch_timestamp = last_run.get("last_fetch", None)
    if last_fetch_timestamp:
        last_fetch_date = datetime.fromtimestamp(last_fetch_timestamp / 1000)
        last_fetch = last_fetch_date
    else:
        first_fetch_date = dateparser.parse(first_fetch_time)
        last_fetch = first_fetch_date  # type: ignore
    incidents = []
    next_run = last_fetch
    #  Send the API request to fetch the alerts.
    alerts = client.list_alerts(
        page="1",
        page_size=max_fetch,
        created_date_from=datetime.strftime(last_fetch, DATE_FORMAT),
        created_date_to=datetime.strftime(datetime.now(), DATE_FORMAT),
        modification_date_from=None,
        modification_date_to=None,
        update_date_from=None,
        update_date_to=None,
        environments=fetch_environment,
        statuses=fetch_status,
        severities=fetch_severity,
        types=fetch_type,
    )

    for alert_object in alerts.get("alerts", []):
        alert = dict(alert_object)
        #  Create the XS0AR incident.
        alert_created_time = datetime.strptime(alert.get("created_date"), "%Y-%m-%dT%H:%M:%S")  # type: ignore

        alert_id = alert["ref_id"]
        alert_title = alert.get("title")
        attachments = []
        incident_attachments = []

        attachments_keys = {
            "attachment": [["attachments"], ["alert_data", "screenshot"], ["alert_data", "csv"]],
            "analysis_report": [["analysis_report"]],
        }
        for attachment_type, attachments_path in attachments_keys.items():
            for path in attachments_path:
                current_attachments = dict_safe_get(alert, path, default_return_value=[])
                attachment_list = (
                    current_attachments if isinstance(current_attachments, list) else [current_attachments]
                )
                # Retrieve alert Incident attachments files - Attachments, CSV, Screenshot, and Analysis report.
                current_incident_attachments = get_alert_attachments(
                    client, attachment_list, attachment_type, alert_id
                )  # type: ignore

                incident_attachments.extend(current_incident_attachments)
                for tmp_attachment in attachment_list:
                    if tmp_attachment:
                        attachments.append(tmp_attachment)

        alert["attachments"] = attachments
        alert_data = dict_safe_get(alert, ["alert_data", "csv"], {})
        incident_csv_records = alert_data.get("content", [])

        alert_csv_id = dict_safe_get(alert, ["alert_data", "csv", "id"])

        if alert_csv_id:
            extracted_csv_data = extract_data_from_csv_stream(client, alert_id, alert_csv_id)  # type: ignore
            alert["alert_data"]["csv"] = extracted_csv_data

        # add alert_name key to alert response
        alert_name = f"Cyberint alert {alert_id}: {alert_title}"
        alert.update({"alert_name": alert_name})

        alert["closure_reason_description"] = "none"
        alert["incident_id"] = alert_id
        alert["mirror_direction"] = mirror_direction
        alert["mirror_instance"] = demisto.integrationInstance()

        incident = {
            "name": alert_name,
            "occurred": datetime.strftime(alert_created_time, DATE_FORMAT),
            "rawJSON": json.dumps(alert),
            "severity": SEVERITIES.get(alert.get("severity", "low")),
            "attachment": incident_attachments,
            "mirror_direction": mirror_direction,
            "mirror_instance": demisto.integrationInstance(),
        }

        if duplicate_alert and incident_csv_records:
            for index, incident_csv_record in enumerate(incident_csv_records):
                alert_data.update({"content": incident_csv_record})
                alert.update({"attachments": alert_data})

                alert_name = f"Cyberint alert {alert_id} ({index+1}): {alert_title}"
                alert.update({"alert_name": alert_name})

                incident.update({"name": alert_name, "rawJSON": json.dumps(alert)})
                incidents.append(copy.deepcopy(incident))
        else:
            incidents.append(incident)

        # close Cyberint alert if required
        if close_alert:
            client.update_alerts(
                alerts=argToList(alert_id),
                status="closed",
                closure_reason="resolved",
            )

    if incidents:
        #  Update the time for the next fetch so that there won't be duplicates.
        last_incident_time = max(incidents, key=lambda item: item["occurred"])
        next_run = datetime.strptime(str(last_incident_time["occurred"]), DATE_FORMAT)
    next_run += timedelta(seconds=1)
    next_run_timestamp = int(datetime.timestamp(next_run) * 1000)
    return {"last_fetch": next_run_timestamp}, incidents


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    command = demisto.command()
    access_token = params.get("access_token")
    url = params.get("environment")

    verify_certificate = not params.get("insecure", False)
    first_fetch_time = params.get("first_fetch", "3 days").strip()
    proxy = params.get("proxy", False)
    base_url = f"{url}/alert/"
    demisto.info(f"Command being called is {command}")
    try:
        client = Client(
            base_url=base_url,
            verify_ssl=verify_certificate,
            access_token=access_token,
            proxy=proxy,
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "fetch-incidents":
            fetch_environment = argToList(params.get("fetch_environment", ""))
            fetch_status = params.get("fetch_status", [])
            fetch_type = params.get("fetch_type", [])
            fetch_severity = params.get("fetch_severity", [])
            max_fetch = int(params.get("max_fetch", "50"))
            duplicate_alert = params.get("duplicate_alert", False)
            mirror_direction = (
                None
                if params.get("mirror_direction") == "None"
                else MIRROR_DIRECTION_MAPPING[params["mirror_direction"]]
            )
            close_alert = params.get("close_alert", False)
            next_run, incidents = fetch_incidents(
                client,
                demisto.getLastRun(),
                first_fetch_time,
                fetch_severity,
                fetch_status,
                fetch_type,
                fetch_environment,
                max_fetch,
                duplicate_alert,
                mirror_direction,
                close_alert,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "cyberint-alerts-fetch":
            return_results(cyberint_alerts_fetch_command(client, demisto.args()))
        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, demisto.args(), params))
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data(client, demisto.args()))
        elif command == "update-remote-system":
            return_results(update_remote_system(client, demisto.args()))
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())

        elif command == "cyberint-alerts-status-update":
            return_results(cyberint_alerts_status_update(client, demisto.args()))

        elif command == "cyberint-alerts-get-attachment":
            return_results(cyberint_alerts_get_attachment_command(client, **demisto.args()))

        elif command == "cyberint-alerts-analysis-report":
            return_results(cyberint_alerts_get_analysis_report_command(client, **demisto.args()))
    except Exception as e:
        if "Invalid token or token expired" in str(e):
            error_message = (
                "Error verifying access token and / or URL, make sure the "
                "configuration parameters are correct."
            )
        elif "datetime" in str(e).lower():
            error_message = (
                "Invalid time specified, "
                "make sure the arguments are correctly formatted and are not "
                "earlier than 2020 or later than the current time."
            )
        elif "Unauthorized alerts requested" in str(e):
            error_message = "Some of the alerts selected to update are either blocked or not found."
        else:
            error_message = f"Failed to execute {command} command. Error: {str(e)}"
        return_error(error_message)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
