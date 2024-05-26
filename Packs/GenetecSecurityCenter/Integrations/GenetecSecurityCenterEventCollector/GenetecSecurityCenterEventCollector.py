import html
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

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth, headers={"Accept": "text/json"})

    def _encode_authorization(self, username: str, password: str, app_id: str):
        updated_username = f"{username};{app_id}"
        return HTTPBasicAuth(updated_username, password)

    def http_request(self, url_suffix):
        response_audit = self._http_request('GET', url_suffix=url_suffix, resp_type='response')
        response = json.loads(response_audit.content)["Rsp"]
        if response["Status"] == "Fail":
            raise DemistoException(response["Result"])
        return response["Result"]


""" COMMAND FUNCTIONS """


def test_module(client: Client):
    """
    Testing we have a valid connection to Genetec security center.
    """
    time_now: datetime = datetime.utcnow()
    start_time: datetime = time_now - timedelta(minutes=1)
    time_now_str = time_now.strftime(DATE_FORMAT_EVENT)
    start_time_str = start_time.strftime(DATE_FORMAT_EVENT)
    query = f"TimeRange.SetTimeRange({start_time_str},{time_now_str})"
    url_suffix = f"{AUDIT_TRAIL_ENDPOINT}?q={query}"
    client.http_request(url_suffix=url_suffix)
    return "ok"


def fetch_events_command(
    client: Client,
    args: dict[str, str],
    last_run: dict,
) -> tuple[list[dict], dict]:
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
    start_time_str: str = ""
    if args.get("start_time"):
        start_time_str = args.get("start_time", "")
    elif not last_run:
        start_time = time_now - timedelta(minutes=1)
        start_time_str = start_time.strftime(DATE_FORMAT_EVENT)
    else:
        start_time_str = last_run.get("start_time", "")
    time_now_str = time_now.strftime(DATE_FORMAT_EVENT)
    if end_time := args.get("end_time"):
        time_now_str = end_time
    time_range = f"TimeRange.SetTimeRange({start_time_str},{time_now_str})"
    limit: int = int(args.get('limit') or client.limit)
    query: str = f"{time_range},SortOrder=Ascending"
    url_suffix = f"{AUDIT_TRAIL_ENDPOINT}?q={query}"
    demisto.info(f"executing fetch events with the following query: {query}")
    response = client.http_request(url_suffix=url_suffix)
    results = response[:limit]
    for result in results:
        result["Value"] = parse(html.unescape(result.get("Value")))
        result['_time'] = result["ModificationTimeStamp"]
    cached_audits: List[str] = last_run.get('audit_cache', [])
    updated_results, updated_cached_audits = remove_duplicated_events(results, cached_audits)
    last_run['audit_cache'] = updated_cached_audits
    if updated_results:
        last_run["start_time"] = (datetime.strptime(updated_results[-1]["ModificationTimeStamp"],
                                                    "%Y-%m-%dT%H:%M:%S.%fZ")).strftime(DATE_FORMAT_EVENT)
    else:
        demisto.info("No new events were fetched. Therefore, setting last_run object to point to now.")
        last_run["start_time"] = time_now_str
    return updated_results, last_run


def remove_duplicated_events(results: List[dict], cached_audits: List[str]) -> tuple[List[dict], List[str]]:
    updated_results: List[dict] = []
    updated_cached_audits: List[str] = []
    removed_events: List[str] = []
    for result in results:
        if (event_guid := result.get("Guid", "")) in cached_audits:
            removed_events.append(str(event_guid))
        else:
            updated_results.append(result)
            updated_cached_audits.append(event_guid)
    if removed_events:
        demisto.info(f"The following events were deduplicated: {', '.join(removed_events)}.")
    return updated_results, updated_cached_audits


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
    should_save_last_run = False

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
            events, _ = fetch_events_command(client, args, {})
            return_results(
                CommandResults(readable_output=tableToMarkdown("Events:", events, headers=GET_EVENTS_HEADERS))
            )

        elif command == "fetch-events":
            should_push_events, should_save_last_run = True, True
            last_run = demisto.getLastRun()
            events, last_run = fetch_events_command(
                client, params, last_run=last_run
            )
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
        if should_push_events:
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT, add_proxy_to_request=proxy)
            demisto.info(f"{len(events)} events were pushed to XSIAM")

        if should_save_last_run:
            demisto.setLastRun(last_run)
            demisto.info(f"set last run time: {last_run.get('start_time')}")

    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error in Genetec Security Center Event Collector Integration [{e}]."
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
