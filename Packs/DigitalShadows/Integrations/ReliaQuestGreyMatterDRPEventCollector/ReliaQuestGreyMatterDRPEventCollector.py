import time

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
DEFAULT_MAX_FETCH = 200
VENDOR = "ReliaQuest"
PRODUCT = "GreyMatter DRP"
FETCHED_TIME_LAST_RUN = "time"
FOUND_IDS_LAST_RUN = "fetched_ids"

''' CLIENT CLASS '''



class RateLimit(Exception):
    pass


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

    @retry(times=5, exceptions=(ConnectionError, Timeout, RateLimit))
    def http_request(self, url_suffix: str, method: str = "GET", headers: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> List[dict[str, Any]]:
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
                rate_limit_error = f'Rate-limit when requesting {url_suffix} with params {params}, error: {json_response}, ' \
                                   f'sleeping for 60 seconds to let the api recover'
                time.sleep(60)
                demisto.error(rate_limit_error)
                raise RateLimit(rate_limit_error)
            return json_response
        except DemistoException as error:
            if isinstance(error.exception, ConnectionError):
                # raise connection error to re-trigger the retry for temporary connection/timeout errors
                raise error.exception
            raise

    def list_triage_item_events(self, event_created_before: str | None = None, event_created_after: str | None = None, limit: int = 1000) -> List[dict[str, Any]]:
        """
        Args:
                api docs:
                    Return events with an event-num greater than this value
                    Must be greater than or equal to 0.
            event_created_before (str): retrieve events occurred before a specific time (included), format:  YYYY-MM-DDThh:mm:ssTZD.
            event_created_after (str): retrieve events occurred after a specific time (included), format:  YYYY-MM-DDThh:mm:ssTZD.
            limit (int): the maximum number of events to retrieve
        """

        params: dict = {"limit": limit}
        if event_created_before:
            params["event-created-before"] = event_created_before
        if event_created_after:
            params["event-created-after"] = event_created_after

        events = self.http_request("/triage-item-events", params=params)
        demisto.info(f'Fetched {len(events)} events')
        demisto.info(f'Fetched the following event IDs: {[event.get("triage-item-id") for event in events]}')

        if events:
            while len(events) < limit and "event-num" in events[-1]:
                params.update({"event-num-after": events[-1]["event-num"]})
                current_events = self.http_request("/triage-item-events", params=params)
                demisto.info(f'Fetched {len(current_events)} events')
                demisto.info(f'Fetched the following event IDs: {[event.get("triage-item-id") for event in current_events]}')
                events.extend(current_events)

        return events

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
    client.list_triage_item_events(limit=1)
    return "ok"


def get_event_latest_created_time(events: List[Dict], created_time_field: str, date_format=DATE_FORMAT):
    try:
        latest_event_time = datetime.strptime(events[0][created_time_field], date_format)
    except ValueError:
        # The api might return rarely DATE_FORMAT only in seconds
        latest_event_time = datetime.strptime(events[0][created_time_field], '%Y-%m-%dT%H:%M:%SZ')

    for event in events:
        try:
            event_time = datetime.strptime(event[created_time_field], date_format)
        except ValueError:
            # The api might return rarely DATE_FORMAT only in seconds
            event_time = datetime.strptime(event[created_time_field], '%Y-%m-%dT%H:%M:%SZ')
        if event_time > latest_event_time:
            latest_event_time = event_time

    demisto.info(f'event latest created {latest_event_time}')
    return latest_event_time.strftime(date_format)


def get_triage_item_ids_to_events(client: ReilaQuestClient, last_run: Dict[str, Any], max_fetch: int = DEFAULT_MAX_FETCH) -> tuple[dict[str, List[dict]], Optional[str]]:
    """
    Maps the triage item IDs to events.
    Triage item ID can refer to multiple events.

    Returns:
        {"id-1": ["event-1", "event-2"]...}
    """
    events = client.list_triage_item_events(event_created_after=last_run.get(FETCHED_TIME_LAST_RUN), limit=max_fetch)
    events = dedup_fetched_events(events, last_run)
    latest_created_item = None
    if events:
        latest_created_item = get_event_latest_created_time(
            events, created_time_field="event-created", date_format=DATE_FORMAT
        )

    _triage_item_ids_to_events = {}
    for event in events:
        if triage_item_id := event.get("triage-item-id"):
            if triage_item_id not in _triage_item_ids_to_events:
                _triage_item_ids_to_events[triage_item_id] = []
            _triage_item_ids_to_events[triage_item_id].append(event)
    return _triage_item_ids_to_events, latest_created_item


def enrich_events_with_triage_item(client: ReilaQuestClient, triage_item_ids_to_events: dict[str, List[dict]]) -> tuple[dict[str, str], dict[str, str]]:
    """
    Enrich the events with triage-item response and return a mapping between incident|alert IDs to the triage-item-ids

    Returns:
        mapping between alert|incident IDs to the triage-IDs
    """
    triage_item_ids = list(triage_item_ids_to_events.keys())
    demisto.info(f"Fetched the following item IDs: {triage_item_ids}")
    triaged_items = client.triage_items(triage_item_ids)

    alert_ids_to_triage_ids, incident_ids_to_triage_ids = {}, {}

    for triaged_item in triaged_items:
        item_id = triaged_item.get("id")
        if item_id in triage_item_ids_to_events:
            for event in triage_item_ids_to_events[item_id]:
                event["triage-item"] = triaged_item

        source = triaged_item.get("source") or {}
        if alert_id := source.get("alert-id"):
            alert_ids_to_triage_ids[alert_id] = item_id

        if incident_id := source.get("incident-id"):
            incident_ids_to_triage_ids[incident_id] = item_id

    return alert_ids_to_triage_ids, incident_ids_to_triage_ids


def enrich_events_with_incident_or_alert_metadata(
    alerts_incidents: List[dict],
    triage_item_ids_to_events: dict[str, List[dict]],
    event_ids_to_triage_ids: dict[str, str],
    event_type: str,
    assets_ids_to_triage_ids: dict[str, List[str]]
):

    for alert_incident in alerts_incidents:
        _id = alert_incident.get("id")
        for event in triage_item_ids_to_events[event_ids_to_triage_ids[_id]]:
            event[event_type] = alert_incident
        for asset in alert_incident.get("assets") or []:
            if asset_id := asset.get("id"):
                if asset_id not in event_ids_to_triage_ids:
                    assets_ids_to_triage_ids[asset_id] = []
                assets_ids_to_triage_ids[asset_id].append(event_ids_to_triage_ids[_id])


def enrich_events_with_assets_metadata(
    client: ReilaQuestClient,
    assets_ids_to_triage_ids: dict[str, List[str]],
    triage_item_ids_to_events: dict[str, List[dict]],
):
    asset_ids = list(assets_ids_to_triage_ids.keys())
    demisto.info(f'Fetched the following asset-IDs {asset_ids}')

    assets = client.get_asset_ids(asset_ids)
    for asset in assets:
        _id = asset.get("id")
        for triage_item_id in assets_ids_to_triage_ids[_id]:
            for event in triage_item_ids_to_events[triage_item_id]:
                if "assets" not in event:
                    event["assets"] = []
                event["assets"].append(asset)


def dedup_fetched_events(
    events: List[dict],
    last_run: Dict[str, Any],
) -> List[dict]:
    """
    Returns a list of all the events that were not fetched yet.

    Args:
        events (list): the events to dedup
        last_run (dict): the last run object.

    Returns: all the events that were not fetched yet
    """
    last_run_found_event_ids = set(last_run.get(FOUND_IDS_LAST_RUN) or [])
    demisto.info(f'last-run found events: {last_run_found_event_ids}')
    if not last_run_found_event_ids:
        return events

    un_fetched_events = []

    for event in events:
        _id = event.get("triage-item-id")
        if _id not in last_run_found_event_ids:
            demisto.info(f'Item with ID {_id} with type has not been fetched.')
            un_fetched_events.append(event)
        else:
            demisto.info(f'Item with ID {_id} has been fetched')

    demisto.info(f'Fetching the following item-IDs after dedup: { {event.get("id") for event in un_fetched_events} }')
    return un_fetched_events


def get_events_with_latest_created_time(events: List[Dict], latest_created_time: Optional[str]) -> List[Dict]:
    """
    Get the events with the latest created time
    """
    if not latest_created_time:
        return []
    latest_create_time_date = dateparser.parse(latest_created_time)
    return [
        event.get("triage-item-id") for event in events
        if event.get("event-created") and dateparser.parse(event.get("event-created")) == latest_create_time_date
    ]


def fetch_events(client: ReilaQuestClient, last_run: dict[str, Any], max_fetch: int = DEFAULT_MAX_FETCH) -> tuple[List[dict], dict[str, str]]:

    _time = last_run.get("time")
    triage_item_ids_to_events, latest_created_item = get_triage_item_ids_to_events(
        client, last_run=last_run, max_fetch=max_fetch)

    alert_ids_to_triage_ids, incident_ids_to_triage_ids = enrich_events_with_triage_item(
        client, triage_item_ids_to_events=triage_item_ids_to_events
    )

    alert_ids = list(alert_ids_to_triage_ids.keys())
    incident_ids = list(incident_ids_to_triage_ids.keys())

    demisto.info(f'Fetched the following alerts {alert_ids}')
    demisto.info(f'Fetched the following incidents {incident_ids}')

    alerts = client.get_alerts_by_ids(alert_ids)
    incidents = client.get_incident_ids(incident_ids)

    assets_ids_to_triage_ids = {}

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

    events = []
    for items in triage_item_ids_to_events.values():
        events.extend(items)

    fetched_events_with_latest_created_time = get_events_with_latest_created_time(events, latest_created_item)

    # if latest_created_item = None, no new events were fetched, keep the same last-run until new events will be created
    new_last_run = {
        FETCHED_TIME_LAST_RUN: latest_created_item or _time,
        FOUND_IDS_LAST_RUN: fetched_events_with_latest_created_time
    }
    demisto.info(f'updated last run: {new_last_run}')
    return events, new_last_run


def main() -> None:
    params = demisto.params()
    url = params.get("url")
    account_id = params.get("account_id")
    max_fetch = arg_to_number(params.get("max_fetch_events")) or DEFAULT_MAX_FETCH
    credentials = params.get("credentials") or {}
    username = credentials.get("identifier")
    password = credentials.get("password")
    verify_ssl = not argToBoolean(params.get("insecure", True))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:

        client = ReilaQuestClient(url, account_id=account_id, username=username,
                                  password=password, verify_ssl=verify_ssl, proxy=proxy)
        if command == 'test-module':
            return_results(test_module(client))
        elif command == "fetch-events":
            events, new_last_run = fetch_events(client, last_run=demisto.getLastRun(), max_fetch=max_fetch)
            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )
            demisto.setLastRun(new_last_run)
        elif command == "reila-quest-get-events":
            pass
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as exc:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(exc)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
