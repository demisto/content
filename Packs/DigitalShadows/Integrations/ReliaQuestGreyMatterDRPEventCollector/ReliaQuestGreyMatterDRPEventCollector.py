import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any
from requests.exceptions import ConnectionError, Timeout

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # ISO8601 format
DEFAULT_MAX_FETCH = 200

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

        if events:
            while len(events) < limit and "event-num" in events[-1]:
                params.update({"event-num-after": events[-1]["event-num"]})
                events.extend(self.http_request("/triage-item-events", params=params))

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
        """
        Do pagination
        """
        chunk = 0
        response = []
        while chunk < len(_ids):
            response.extend(self.http_request(url_suffix, params={"id": _ids[chunk: chunk + 100]}))
            chunk += 100
        return response


class TriagedItemEvent:

    def __init__(self, event: Dict):
        self.event = event

    def __eq__(self, other):
        return hashlib.sha256(
            json.dumps(self.event, sort_keys=True).encode()
        ).hexdigest() == hashlib.sha256(
            json.dumps(other.event, sort_keys=True).encode()
        ).hexdigest()

    def __hash__(self):
        return hash(hashlib.sha256(
            json.dumps(self.event, sort_keys=True).encode()
        ).hexdigest())


def test_module(client: ReilaQuestClient) -> str:
    """
    Tests that the credentials to ReliaQuest is ok

    Args:
        client: the relia quest client
    """
    client.list_triage_item_events(limit=1)
    return "ok"


def fetch_events(client: ReilaQuestClient, last_run: Dict[str, Any], max_fetch: int = DEFAULT_MAX_FETCH):

    _time = last_run.get("time")
    events = {
        event.get("triage-item-id"): event for event in
        client.list_triage_item_events(event_created_after=_time, limit=max_fetch)
    }
    triage_item_ids = list(events.keys())
    demisto.info(f"Fetched the following event IDs: {triage_item_ids}")
    triage_items = client.triage_items(triage_item_ids)

    alert_ids_to_triage_ids, incident_ids_to_triage_ids = {}, {}

    for triaged_item in triage_items:
        unique_item_id = triaged_item.get("id")
        if unique_item_id in events:
            events[unique_item_id]["triage-item"] = triaged_item

        source = triaged_item.get("source") or {}
        if alert_id := source.get("alert-id"):
            alert_ids_to_triage_ids[alert_id] = unique_item_id

        if incident_id := source.get("incident-id"):
            incident_ids_to_triage_ids[incident_id] = unique_item_id

    alert_ids = list(alert_ids_to_triage_ids.keys())
    incident_ids = list(incident_ids_to_triage_ids.keys())

    demisto.info(f'Fetched the following alerts {alert_ids}')
    demisto.info(f'Fetched the following incidents {incident_ids}')

    alerts = client.get_alerts_by_ids(alert_ids)
    incidents = client.get_incident_ids(incident_ids)

    assets_ids_to_triage_ids = {}

    for alert in alerts:
        _id = alert.get("id")
        events[alert_ids_to_triage_ids[_id]]["alert"] = alert
        for asset in alert.get("assets") or []:
            if asset_id := asset.get("id"):
                if asset_id in alert_ids_to_triage_ids:
                    assets_ids_to_triage_ids[asset_id].append(alert_ids_to_triage_ids[_id])
                else:
                    assets_ids_to_triage_ids[asset_id] = [alert_ids_to_triage_ids[_id]]

    for incident in incidents:
        _id = incident.get("id")
        events[incident_ids_to_triage_ids[_id]]["incident"] = incident
        for asset in incident.get("assets") or []:
            if asset_id := asset.get("id"):
                assets_ids_to_triage_ids[asset_id] = alert_ids_to_triage_ids[_id]

    asset_ids = list(assets_ids_to_triage_ids.keys())
    assets = client.get_asset_ids(asset_ids)
    for asset in assets:
        _id = asset.get("id")
        if "assets" in events[assets_ids_to_triage_ids[_id]]:
            events[assets_ids_to_triage_ids[_id]]["assets"].append(asset)
        else:
            events[assets_ids_to_triage_ids[_id]]["assets"] = [asset]

    print()

''' MAIN FUNCTION '''


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
            fetch_events(client, last_run=demisto.getLastRun(), max_fetch=max_fetch)
        elif command == "reila-quest-get-events":
            pass
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        import traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}, {traceback.format_exc()}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
