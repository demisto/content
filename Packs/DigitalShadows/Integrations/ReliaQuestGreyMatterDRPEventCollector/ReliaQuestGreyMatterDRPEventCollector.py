import dateparser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
from requests.exceptions import ConnectionError, Timeout

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # ISO8601 format
DEFAULT_MAX_FETCH = 1000
VENDOR = "ReliaQuest"
PRODUCT = "GreyMatter DRP"
LAST_FETCHED_EVENT_NUM = "last_fetched_event_num"
RATE_LIMIT_LAST_RUN = "rate_limit_retry_after"
MAX_PAGE_SIZE = 1000

''' CLIENT CLASS '''


class RateLimitError(Exception):

    def __init__(self, message: str, retry_after: str):
        self.retry_after = retry_after
        super().__init__(message)


class ReilaQuestClient(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, url: str, account_id: str, username: str, password: str, verify_ssl: bool = False, proxy: bool = False):
        super().__init__(base_url=url, verify=verify_ssl, proxy=proxy, auth=(username, password))
        self.account_id = account_id

    @retry(times=5, exceptions=(ConnectionError, Timeout, DemistoException))
    def http_request(
        self,
        url_suffix: str,
        method: str = "GET",
        headers: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None
    ) -> List[dict[str, Any]]:
        demisto.debug(f'Running http request for url: {url_suffix} with params {params}')
        try:
            response = self._http_request(
                method,
                url_suffix=url_suffix,
                headers=headers or {"searchlight-account-id": self.account_id},
                params=params,
                resp_type="response",
                ok_codes=(200, 429)
            )
            json_response = response.json()
            if response.status_code == 429:
                raise RateLimitError(
                    f'Rate-limit when running http-request to {url_suffix} with params {params}, error: {json_response}',
                    retry_after=json_response.get("retry-after", "")
                )

            return json_response
        except DemistoException as error:
            if isinstance(error.exception, ConnectionError):
                # raise connection error to re-trigger the retry for temporary connection/timeout errors
                raise error.exception
            raise

    def list_triage_item_events(
        self,
        event_num_after: int | None = None,
        event_created_before: str | None = None,
        event_created_after: str | None = None,
        limit: int = MAX_PAGE_SIZE
    ):
        """
        A generator to retrieve the list of events according to the limit.

        Args:
            event_num_after (int): After which event number to continue retrieving the events
            event_created_before (str): retrieve events occurred before a specific time (included),format: YYYY-MM-DDThh:mm:ssTZD.
            event_created_after (str): retrieve events occurred after a specific time (included), format: YYYY-MM-DDThh:mm:ssTZD.
            limit (int): the maximum number of events to retrieve
        """
        page_size = min(MAX_PAGE_SIZE, limit)
        params: dict = {"limit": page_size}
        if event_created_before:
            params["event-created-before"] = event_created_before
        if event_created_after:
            params["event-created-after"] = event_created_after

        amount_of_fetched_events = 0
        latest_event = None
        while amount_of_fetched_events < limit:
            params["event-num-after"] = latest_event or event_num_after
            events = self.http_request("/triage-item-events", params=params)
            amount_of_fetched_events += len(events)
            end_index = min(amount_of_fetched_events - limit, limit) if amount_of_fetched_events > limit else MAX_PAGE_SIZE
            events = events[:end_index]
            event_numbers = []
            for event in events:
                event_numbers.append(event.get("event-num"))
                # if event-action = create (its a new event) we enrich the _time with event-created and _ENTRY_STATUS with new
                if event.get("event-action") == "create" and (event_created := event.get("event-created")):
                    event["_time"] = event_created
                    event["_ENTRY_STATUS"] = "new"
            if event_numbers:
                latest_event = max(event_numbers)
            demisto.debug(f'Fetched {len(events)} events')
            demisto.debug(f'Fetched the following event IDs: {event_numbers}, latest event is {latest_event}')
            yield events, latest_event
            if len(events) < page_size:
                break

    def triage_items(self, triage_item_ids: list[str]) -> List[dict[str, Any]]:
        """
        Args:
            triage_item_ids: a list of triage item IDs.
            from api:
                One or more triage item identifiers to resolve
                Must provide between 1 and 100 items.
        """
        return self.do_pagination(triage_item_ids, url_suffix="/triage-items")

    def get_alerts_by_ids(self, alert_ids: list[str]) -> List[dict[str, Any]]:
        """
        List of alerts was created from alert_id fields of /triage-items  response

        Args:
            alert_ids: List of alerts was created from alert_id fields of /triage-items  response
            from api:
                One or more alert identifiers to resolve
                Must provide between 1 and 100 items.
        """
        return self.do_pagination(alert_ids, url_suffix="/alerts")

    def get_incident_ids(self, incident_ids: list[str]) -> List[dict[str, Any]]:
        """
        List of alerts was created from incident-id fields of /triage-items response

        Args:
            incident_ids: a list of incident-IDs.
        """
        return self.do_pagination(incident_ids, url_suffix="/incidents")

    def get_asset_ids(self, asset_ids: list[str]) -> List[dict[str, Any]]:
        """
        Retrieve the Asset Information for the Alert or Incident

        Args:
            asset_ids: a list of asset-IDs.
        """
        return self.do_pagination(asset_ids, url_suffix="/assets")

    def do_pagination(self, _ids: list[str], url_suffix: str, page_size: int = 100) -> list[dict[str, Any]]:
        """
        Args:
            _ids: the list of IDs of events to retrieve
            url_suffix: The URL suffix
            page_size (int): the size of each page

        Note:
            by default the maximum size page for each request is 100.
        """
        demisto.debug(f'Starting pagination on {url_suffix} for the following IDs {_ids} with page size {page_size}')
        chunk = 0
        response = []
        while chunk < len(_ids):
            response.extend(self.http_request(url_suffix, params={"id": _ids[chunk: chunk + page_size]}))
            chunk += page_size
        return response


def test_module(client: ReilaQuestClient) -> str:
    """
    Tests that the credentials and the connection to Relia Quest is ok

    Args:
        client: the relia quest client
    """
    for _, _ in client.list_triage_item_events(limit=1):
        # no exception means api is valid
        return "ok"
    return ""


def get_triage_item_ids_to_events(events: list[dict]) -> tuple[dict[str, list[dict]], int | None]:
    """
    Maps the triage item IDs to events.
    Triage item ID can refer to multiple events.

    Returns:
        {"id-1": ["event-1", "event-2"]...}
    """
    _triage_item_ids_to_events: dict[str, list[dict]] = {}

    for event in events:
        triage_item_id = event.get("triage-item-id")
        if triage_item_id:
            if triage_item_id not in _triage_item_ids_to_events:
                _triage_item_ids_to_events[triage_item_id] = []
            _triage_item_ids_to_events[triage_item_id].append(event)
        else:
            demisto.error(f'event {event} does not have triage-item-id fields, skipping it')

    return _triage_item_ids_to_events, get_largest_event_num(events)


def get_largest_event_num(events: List[Dict]) -> int | None:
    """
    Get the latest event number that was fetched
    """
    if not events:
        return None
    event_maxes = [event["event-num"] for event in events]
    largest_event = max(event_maxes)
    demisto.info(f'Largest fetched event is {largest_event}')
    return largest_event


def enrich_events_with_triage_item(
    client: ReilaQuestClient, triage_item_ids_to_events: dict[str, List[dict]]
) -> tuple[dict[str, str], dict[str, str]]:
    """
    Enrich the events with triage-item response and return a mapping between incident|alert IDs to the triage-item-ids

    Returns:
        mapping between alert|incident IDs to the triage-IDs
    """
    triage_item_ids = list(triage_item_ids_to_events.keys())
    demisto.debug(f"Fetched the following item IDs: {triage_item_ids}")
    triaged_items = client.triage_items(triage_item_ids)

    alert_ids_to_triage_ids: dict[str, str] = {}
    incident_ids_to_triage_ids: dict[str, str] = {}

    for triaged_item in triaged_items:
        item_id = triaged_item.get("id", "")
        if item_id in triage_item_ids_to_events:
            for event in triage_item_ids_to_events[item_id]:
                event["triage-item"] = triaged_item
                if event.get("event-action") == "update" and (updated := triaged_item.get("updated")):
                    event["_time"] = updated
                    event["_ENTRY_STATUS"] = "updated"

        source = triaged_item.get("source") or {}
        if alert_id := source.get("alert-id"):
            alert_ids_to_triage_ids[alert_id] = item_id

        if incident_id := source.get("incident-id"):
            incident_ids_to_triage_ids[incident_id] = item_id

    return alert_ids_to_triage_ids, incident_ids_to_triage_ids


def get_mitre_attack_ids(_dict: dict, mitre_ids: Optional[set] = None) -> set[str]:
    if not mitre_ids:
        mitre_ids = set()

    for key, value in _dict.items():
        if key == "id":
            mitre_ids.add(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    return get_mitre_attack_ids(item, mitre_ids=mitre_ids)

    return mitre_ids


def enrich_event_with_mitre_attack_mapping(alert_incident: dict) -> tuple[list[str], list[str], list[str]]:
    """
    Enrich a specific with mitre attack metadata

    Args:
        alert_incident: incident/alert raw response

    Returns:
        mitre-tactic-names, mitre-technique names and all mitre attack IDs within the mitre-attack-mapping response
    """
    mitre_tactic_names, mitre_technique_names = set(), set()
    for tactic in (alert_incident.get("mitre-attack-mapping") or {}).get("tactics") or []:
        mitre_tactic_names.add(tactic.get("name"))
        for technique in tactic.get("techniques") or []:
            mitre_technique_names.add(technique.get("name"))

    return (
        list(mitre_tactic_names),
        list(mitre_technique_names),
        list(get_mitre_attack_ids(alert_incident.get("mitre-attack-mapping") or {}))
    )


def enrich_events_with_incident_or_alert_metadata(
    alerts_incidents: List[dict],
    triage_item_ids_to_events: dict[str, List[dict]],
    event_ids_to_triage_ids: dict[str, str],
    event_type: str,
    assets_ids_to_triage_ids: dict[str, List[str]]
):
    """
    Enrich events with incident/alerts metadata including mitre attack metadata

    Args:
        alerts_incidents: a list of raw response of incidents OR a list of raw response of alerts
        triage_item_ids_to_events: This is a mapping between the triage item IDs to their events, each triage ID can have several
            events associated with it
        event_ids_to_triage_ids: mapping between the event IDs to the triage IDs to enrich events easily
        event_type (str): The event type (incident or alert)
        assets_ids_to_triage_ids: Will populate the asset-IDS to the triage IDs.
    """
    for alert_incident in alerts_incidents:
        _id = alert_incident.get("id")
        # get mitre attack metadata
        mitre_tactic_names, mitre_technique_names, mitre_ids = enrich_event_with_mitre_attack_mapping(alert_incident)
        for event in triage_item_ids_to_events[event_ids_to_triage_ids[_id]]:  # type: ignore[index]
            # enrich the alert/incident with mitre-attack metadata.
            event[event_type] = alert_incident
            event["mitre_tactics"] = mitre_tactic_names
            event["mitre_techniques"] = mitre_technique_names
            event["mitre_ids"] = mitre_ids
        # enrich the alert/incident with assets
        for asset in alert_incident.get("assets") or []:
            if asset_id := asset.get("id"):
                if asset_id not in event_ids_to_triage_ids:
                    assets_ids_to_triage_ids[asset_id] = []
                assets_ids_to_triage_ids[asset_id].append(event_ids_to_triage_ids[_id])  # type: ignore[index]


def enrich_events_with_assets_metadata(
    client: ReilaQuestClient,
    assets_ids_to_triage_ids: dict[str, List[str]],
    triage_item_ids_to_events: dict[str, List[dict]],
):
    """
    Enrich events with assets metadata

    Args:
        client: the ReilaQuestClient client.
        assets_ids_to_triage_ids: a mapping between the asset IDs to triage IDs to enrich them easily
        triage_item_ids_to_events: a mapping between the triage item IDs to events.
    """
    asset_ids = list(assets_ids_to_triage_ids.keys())
    demisto.info(f'Fetched the following asset-IDs {asset_ids}')

    assets = client.get_asset_ids(asset_ids)
    for asset in assets:
        _id = asset.get("id")
        for triage_item_id in assets_ids_to_triage_ids[_id]:  # type: ignore[index]
            for event in triage_item_ids_to_events[triage_item_id]:
                if "assets" not in event:
                    event["assets"] = []
                event["assets"].append(asset)


def enrich_events(client: ReilaQuestClient, events: list[dict]) -> list[dict]:
    """
    Enrich the events with more data from the api.

    Args:
        client: The ReilaQuestClient client
        events: a list of raw-response of events

    Returns:
        All the events enriched with assets/alert/incident/mitre-mapping metadata.
    """
    triage_item_ids_to_events, largest_event_num = get_triage_item_ids_to_events(events)

    alert_ids_to_triage_ids, incident_ids_to_triage_ids = enrich_events_with_triage_item(
        client, triage_item_ids_to_events=triage_item_ids_to_events
    )

    alert_ids = list(alert_ids_to_triage_ids.keys())
    incident_ids = list(incident_ids_to_triage_ids.keys())

    demisto.info(f'Fetched the following alerts IDs: {alert_ids}')
    demisto.info(f'Fetched the following incidents IDs: {incident_ids}')

    alerts = client.get_alerts_by_ids(alert_ids)
    incidents = client.get_incident_ids(incident_ids)

    assets_ids_to_triage_ids: dict[str, List[str]] = {}

    enrich_events_with_incident_or_alert_metadata(
        alerts,
        triage_item_ids_to_events=triage_item_ids_to_events,
        event_ids_to_triage_ids=alert_ids_to_triage_ids,
        event_type="alert",
        assets_ids_to_triage_ids=assets_ids_to_triage_ids
    )

    enrich_events_with_incident_or_alert_metadata(
        incidents,
        triage_item_ids_to_events=triage_item_ids_to_events,
        event_ids_to_triage_ids=incident_ids_to_triage_ids,
        event_type="incident",
        assets_ids_to_triage_ids=assets_ids_to_triage_ids
    )

    enrich_events_with_assets_metadata(
        client,
        assets_ids_to_triage_ids=assets_ids_to_triage_ids,
        triage_item_ids_to_events=triage_item_ids_to_events
    )

    enriched_events = []
    for event in triage_item_ids_to_events.values():
        enriched_events.extend(event)

    return enriched_events


def fetch_events(client: ReilaQuestClient, last_run: dict[str, Any], max_fetch: int = DEFAULT_MAX_FETCH):
    """
    Fetch flow:
     - Check if there was any rate-limit error, if not continue the fetch normally, if yes, exit gracefully and wait for
       the api to recover
     - each iteration maximum of 1000 events will be fetched from the api until max_fetch is reached
     - find the largest event fetched, keep it in the last run and use it to continue pagination to the new events
     - in case of a rate-limit error, the api returns the "retry-after" argument to inform the
        client when a new request can be made, keep it in the last-run and wait until this time has reached
    """
    new_last_run = last_run.copy()
    events_sent = 0
    try:
        if retry_after := last_run.get(RATE_LIMIT_LAST_RUN):
            retry_after_datetime = dateparser.parse(retry_after)
        else:
            retry_after_datetime = None
        now = datetime.now(timezone.utc).astimezone()
        demisto.info(f'now: {now}, retry-after: {retry_after}')
        if retry_after_datetime and now < retry_after_datetime:
            demisto.info(
                'Waiting for the api to recover from rate-limit,'
                f' need to wait {(retry_after - now).total_seconds()} seconds'  # type: ignore[operator]
            )
            return
        for events, largest_event in client.list_triage_item_events(
            event_num_after=last_run.get(LAST_FETCHED_EVENT_NUM), limit=max_fetch
        ):
            if not events:
                demisto.info(f'There are no events to fetch when last run is {last_run}, hence exiting')
                break
            enriched_events = enrich_events(client, events=events)
            send_events_to_xsiam(enriched_events, vendor=VENDOR, product=PRODUCT, should_update_health_module=False)
            events_sent += len(enriched_events)
            new_last_run.update({LAST_FETCHED_EVENT_NUM: largest_event})
            demisto.info(f'Sent the following events {[event.get("event-num") for event in events]} successfully')
    except RateLimitError as rate_limit_error:
        demisto.error(str(rate_limit_error))
        new_last_run.update(
            {RATE_LIMIT_LAST_RUN: rate_limit_error.retry_after}
        )
    finally:
        demisto.updateModuleHealth({'eventsPulled': events_sent})
        demisto.setLastRun(new_last_run)
        demisto.info(f'Updated the last run from {last_run} to {new_last_run} successfully')


def get_events_command(client: ReilaQuestClient, args: dict) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or DEFAULT_MAX_FETCH

    if start_time := args.get("start_time"):
        start_time_datetime = dateparser.parse(start_time)
        if not start_time_datetime:
            raise ValueError(f'Invalid value for start_time={start_time}')
        start_time = start_time_datetime.strftime(DATE_FORMAT)

    if end_time := args.get("end_time"):
        end_time_datetime = dateparser.parse(end_time)
        if not end_time_datetime:
            raise ValueError(f'Invalid value for end_time={end_time_datetime}')
        end_time = end_time_datetime.strftime(DATE_FORMAT)

    events: list[dict] = []

    for current_events, _ in client.list_triage_item_events(
        event_num_after=arg_to_number(args.get("event_num_after")),
        event_created_after=start_time,
        event_created_before=end_time,
        limit=limit
    ):
        current_enriched_events = enrich_events(client, events=current_events)
        events.extend(current_enriched_events)

    return CommandResults(
        outputs_prefix='ReliaQuest.Events',
        outputs_key_field='event-num',
        outputs=events,
        raw_response=events,
        readable_output=tableToMarkdown(
            "Relia Quest Events", t=events, headers=["event-num", "triage-item-id", "event-created"]
        )
    )


def main() -> None:
    params = demisto.params()
    url = params.get("url")
    account_id = params.get("account_id") or ""
    max_fetch = arg_to_number(params.get("max_fetch_events")) or DEFAULT_MAX_FETCH
    credentials = params.get("credentials") or {}
    username = credentials.get("identifier") or ""
    password = credentials.get("password") or ""
    verify_ssl = not argToBoolean(params.get("insecure", True))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:

        client = ReilaQuestClient(
            url, account_id=account_id, username=username, password=password, verify_ssl=verify_ssl, proxy=proxy
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif command == "fetch-events":
            fetch_events(client, last_run=demisto.getLastRun(), max_fetch=max_fetch)
        elif command == "relia-quest-get-events":
            return_results(get_events_command(client, args=demisto.args()))
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as exc:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(exc)}, error:{str(exc)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
