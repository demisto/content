import demistomock as demisto
from urllib3 import disable_warnings
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from requests.auth import HTTPBasicAuth
import json
from xmltodict import parse

disable_warnings()

""" CONSTANTS """

VENDOR = "Genetec"
PRODUCT = "Security center"
DATE_FORMAT_EVENT = "%Y-%m-%dT%H:%M:%S"
AUDIT_TRAIL_ENDPOINT = "/WebSdk/report/AuditTrail"
GET_EVENTS_HEADERS = [
    "Id", "Guid", "ModificationTimeStamp", "ModifiedBy", "SourceApplicationGuid", "Name", "ModifiedByAsString",
    "SourceApplicationAsString", "Machine", "SourceApplicationType", "OldValue", "NewValue", "CustomFieldId", "CustomFieldName",
    "CustomFieldValueType", "AuditTrailModificationType", "Type", "Description", "AuditTrailModificationSubTypes", "Value"
]


""" CLIENT CLASS """


class NoContentException(Exception):
    """
    Error definition for API response with status code 204
    Makes it possible to identify a specific exception
    that arises from the API and to handle this case correctly
    see `handle_error_no_content` method
    """

    ...


class Client(BaseClient):
    """Client class to interact with the service API

    :param base_url (str): The server URL.
    :param username (str): The account username.
    :param password (str): The account password.
    :param app_id (str): The app ID.
    :param max_fetch (str): The maximum number of events to fetch per interval.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(
        self, base_url: str, username: str, password: str, verify: bool, proxy: bool, max_fetch: str, app_id: str
    ):
        auth = self._encode_authorization(username, password, app_id)
        self.limit = max_fetch

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)

    def _encode_authorization(self, username: str, password: str, app_id: str):
        updated_username = f"{username};{app_id}"
        return HTTPBasicAuth(updated_username, password)


""" COMMAND FUNCTIONS """


def test_module(client: Client):
    """
    Testing we have a valid connection to trend_micro.
    """
    return "ok"


def fetch_events_command(
    client: Client,
    args: dict[str, str],
    last_run: dict,
) -> list[dict]:
    """
    Args:
        client (Client): The client for api calls.
        args (dict[str, str]): The args.
        last_run (dict): The last run dict.

    Returns:
        tuple[list[dict], dict]: List of all event logs of all types,
                                 The updated `last_run` obj.
    """
    time_now: datetime = datetime.utcnow()
    start_time: datetime
    if not last_run:
        start_time = time_now - timedelta(minutes=1)
    else:
        start_time = last_run.get("start_time", time_now - timedelta(minutes=1))
    time_now_str = time_now.strftime(DATE_FORMAT_EVENT)
    start_time_str = start_time.strftime(DATE_FORMAT_EVENT)
    time_range = f"TimeRange.SetTimeRange({start_time_str},{time_now_str})"
    limit: int = int(args.get("limit") or client.limit)
    query: str = f"{time_range},MaximumResultCount={limit},SortOrder=Ascending"
    url_suffix = f"{AUDIT_TRAIL_ENDPOINT}?q={query}"
    demisto.info(f"executing fetch events with the following query: {query}")
    response_audit = client._http_request('GET', url_suffix=url_suffix, resp_type='response')
    content = json.loads(response_audit.content)
    data_audit_ls = content["Rsp"]["Result"]
    for data_audit in data_audit_ls:
        data_audit["Value"] = parse(data_audit.get("Value"))

    return data_audit_ls


def genetec_security_center_get_events_command(args: Dict[str, Any], client: Client):
    time_now = datetime.utcnow()
    start_time = time_now - timedelta(minutes=1)
    limit: int = int(args.get("limit") or client.limit)
    time_now_str = time_now.strftime(DATE_FORMAT_EVENT)
    start_time_str = start_time.strftime(DATE_FORMAT_EVENT)
    url_suffix = f"{AUDIT_TRAIL_ENDPOINT}?q=TimeRange.SetTimeRange({start_time_str},{time_now_str}),MaximumResultCount={limit},SortOrder=Ascending"
    response_audit = client._http_request('GET', url_suffix=url_suffix, resp_type='response')
    content = json.loads(response_audit.content)
    data_audit_ls = content["Rsp"]["Result"]
    for data_audit in data_audit_ls:
        data_audit["Value"] = parse(data_audit.get("Value"))
    return data_audit_ls, {}


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    base_url = params["url"].strip("/")
    username = params["credentials"]["identifier"]
    password = params["credentials"]["password"]
    app_id = params["app_id"]
    max_fetch = params.get("max_fetch", "1000")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    should_push_events = argToBoolean(args.get("should_push_events", False))

    command = demisto.command()
    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            max_fetch=max_fetch,
            app_id=app_id,
            verify=verify,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "genetec-security-center-get-events":
            events = fetch_events_command(client, args, {})
            return_results(
                CommandResults(readable_output=tableToMarkdown("Events:", events, headers=GET_EVENTS_HEADERS))
            )

        elif command == "fetch-events":
            should_push_events = True
            last_run = demisto.getLastRun()
            events = fetch_events_command(
                client, params, last_run=last_run
            )
            last_run_time = datetime.strptime(events[-1]["ModificationTimeStamp"],
                                              "%Y-%m-%dT%H:%M:%S.%fZ").strftime(DATE_FORMAT_EVENT)
            last_run = {"start_time": last_run_time}
            demisto.setLastRun(last_run)
            demisto.debug(f"set {last_run=}")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

        if should_push_events:
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"{len(events)} events were pushed to XSIAM")

    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error in Genetec Security Center Event Collector Integration [{e}]."
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
