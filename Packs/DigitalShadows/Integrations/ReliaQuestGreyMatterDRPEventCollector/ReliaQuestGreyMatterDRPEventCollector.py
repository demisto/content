import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any, Tuple
from requests.exceptions import ConnectionError, Timeout

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # ISO8601 format
DEFAULT_MAX_FETCH = 200
VENDOR = "ReliaQuest"
PRODUCT = "GreyMatter DRP"

''' CLIENT CLASS '''


class ReilaQuestClient(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, url: str, account_id: str, username: str, password: str, verify_ssl: bool = False, proxy: bool = False):
        self.url = url
        self.account_id = account_id
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        super().__init__(base_url=url, verify=verify_ssl, proxy=proxy, auth=(username, password))

    @retry(times=5, exceptions=(ConnectionError, Timeout))
    def http_request(self, url_suffix: str, method: str = "GET", headers: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> List[Dict[str, Any]]:
        try:
            return self._http_request(method, url_suffix=url_suffix, headers=headers or {"searchlight-account-id": self.account_id}, params=params)
        except DemistoException as error:
            if isinstance(error.exception, ConnectionError):
                # raise connection error to re-trigger the retry for temporary connection/timeout errors
                raise error.exception
            raise

    def list_triage_item_events(self, event_created_before: str | None = None, event_created_after: str | None = None, limit: int = 1000) -> List[Dict[str, Any]]:
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

    def triage_items(self, triage_item_ids: list[str]) -> List[Dict[str, Any]]:
        """
        Args:
            triage_item_ids: a list of triage item IDs.
            from api:
                One or more triage item identifiers to resolve
                Must provide between 1 and 100 items.
        """
        return self.do_pagination(triage_item_ids, url_suffix="/triage-items")

    def get_alerts_by_ids(self, alert_ids: list[str]) -> List[Dict[str, Any]]:
        """
        List of alerts was created from alert_id fields of /triage-items  response

        Args:
            alert_ids: List of alerts was created from alert_id fields of /triage-items  response
            from api:
                One or more alert identifiers to resolve
                Must provide between 1 and 100 items.
        """
        return self.do_pagination(alert_ids, url_suffix="/alerts")

    def get_incident_ids(self, incident_ids: list[str]) -> List[Dict[str, Any]]:
        """
        List of alerts was created from incident-id fields of /triage-items response

        Args:
            incident_ids: a list of incident-IDs.
        """
        return self.do_pagination(incident_ids, url_suffix="/incidents")

    def get_asset_ids(self, asset_ids: list[str]) -> List[Dict[str, Any]]:
        """
        Retrieve the Asset Information for the Alert or Incident

        Args:
            asset_ids: a list of asset-IDs.
        """
        return self.do_pagination(asset_ids, url_suffix="/assets")

    def do_pagination(self, _ids: list[str], url_suffix: str) -> list[dict[str, Any]]:
        chunk = 0
        response = []
        while chunk < len(_ids):
            response.extend(self.http_request(url_suffix, params={"id": _ids[chunk: chunk + 100]}))
            chunk += 100
        return response


def test_module(client: ReilaQuestClient) -> str:
    """
    Tests that the credentials and the connection to Relia Quest is ok

    Args:
        client: the relia quest client
    """
    client.list_triage_item_events(limit=1)
    return "ok"


def get_triage_item_ids_to_events(client: ReilaQuestClient, event_created_after: str, max_fetch: int = DEFAULT_MAX_FETCH) -> Dict[str, List[Dict]]:
    """
    Maps the triage item IDs to events.
    Triage item ID can refer to multiple events.

    Returns:
        {"id-1": ["event-1", "event-2"]...}
    """
    events = client.list_triage_item_events(event_created_after=event_created_after, limit=max_fetch)
    latest_created_item = get_latest_incident_created_time(events, created_time_field="event-created", date_format=DATE_FORMAT)
    _triage_item_ids_to_events = {}
    for event in events:
        if triage_item_id := event.get("triage-item-id"):
            if triage_item_id not in _triage_item_ids_to_events:
                _triage_item_ids_to_events[triage_item_id] = []
            _triage_item_ids_to_events[triage_item_id].append(event)
    return _triage_item_ids_to_events, latest_created_item


def enrich_events_with_triage_item(client: ReilaQuestClient, triage_item_ids_to_events: Dict[str, List[Dict]]) -> Tuple[Dict[str, str], Dict[str, str]]:
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
    alerts_incidents: List[Dict],
    triage_item_ids_to_events: Dict[str, List[Dict]],
    event_ids_to_triage_ids: Dict[str, str],
    event_type: str,
    assets_ids_to_triage_ids: Dict[str, List[str]]
):

    for alert_incident in alerts_incidents:
        _id = alert_incident.get("id")
        for event in triage_item_ids_to_events[event_ids_to_triage_ids[_id]]:
            event[event_type] = event
        for asset in alert_incident.get("assets") or []:
            if asset_id := asset.get("id"):
                if asset_id not in event_ids_to_triage_ids:
                    assets_ids_to_triage_ids[asset_id] = []
                assets_ids_to_triage_ids[asset_id].append(event_ids_to_triage_ids[_id])


def enrich_events_with_assets_metadata(
    client: ReilaQuestClient,
    assets_ids_to_triage_ids: Dict[str, List[str]],
    triage_item_ids_to_events: Dict[str, List[Dict]],
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


def fetch_events(client: ReilaQuestClient, last_run: Dict[str, Any], max_fetch: int = DEFAULT_MAX_FETCH) -> list[dict]:

    _time = last_run.get("time")
    triage_item_ids_to_events, latest_created_item = get_triage_item_ids_to_events(client, event_created_after=_time, max_fetch=max_fetch)

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

    demisto.setLastRun({"time": latest_created_item})
    return events


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
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

        client = ReilaQuestClient(url, account_id=account_id, username=username, password=password, verify_ssl=verify_ssl, proxy=proxy)
        if command == 'test-module':
            return_results(test_module(client))
        elif command == "fetch-events":
            send_events_to_xsiam(
                fetch_events(client, last_run=demisto.getLastRun(), max_fetch=max_fetch),
                vendor=VENDOR,
                product=PRODUCT
            )
        elif command == "reila-quest-get-events":
            pass
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        raise e
        # import traceback
        # return_error(f'Failed to execute {command} command.\nError:\n{str(e)}, {traceback.format_exc()}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
