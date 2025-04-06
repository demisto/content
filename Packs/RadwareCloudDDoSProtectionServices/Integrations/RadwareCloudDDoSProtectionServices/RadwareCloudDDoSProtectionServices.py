import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
from requests import Response
import time

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
VENDOR = "Radware"
PRODUCT = "cloud ddos"

PAGE_SIZE = 700


class Client(BaseClient):

    def __init__(self, base_url: str, account_id: str, api_key: str, verify: bool, proxy: bool):
        self.account_id = account_id
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers={'x-api-key': api_key, 'Context': account_id})

    def get_events(self, start_time=None, end_time=None, skip=0, take=PAGE_SIZE) -> dict[str, Any] | Response:
        """
        Fetches events from a specific time range with pagination support.
        Args:
            start_time(int): The start time for fetching events in milliseconds since epoch.
            end_time(int): The end time for fetching events in milliseconds since epoch.
            skip(int): The number of events to skip for pagination (default: 0).
            take(int): The number of events to take for pagination (default: 700).
        return dict[str, Any] | Response: A dictionary containing the fetched events and related metadata.
        """

        params = {
            "criteria": [
                {
                    "key": "startTimestamp",
                    "value": [start_time, None]
                },
                {
                    "key": "endTimestamp",
                    "value": [None, end_time]
                },
                {
                    "key": "risk",
                    "value": ["Info", "Low", "Medium", "High", "Critical"]
                }
            ],
            "skip": skip,
            "take": take
        }
        return self._http_request(
            method="POST",
            url_suffix="/api/sdcc/attack/core/analytics/object/vision/securityevents",
            json_data=params,
        )

    def get_alerts(self, start_time=None, end_time=None, skip=0, take=PAGE_SIZE) -> dict[str, Any] | Response:
        """
        Fetches alerts from a specific time range with pagination support.
        Args:
            start_time(int): The start time for fetching alerts in milliseconds since epoch.
            end_time(int): The end time for fetching alerts in milliseconds since epoch.
            skip(int): The number of alerts to skip for pagination (default: 0).
            take(int): The number of alerts to take for pagination (default: 700).
        return: A dictionary containing the fetched alerts and related metadata.
        """

        params = {
            "criteria": [
                {
                    "key": "timestamp",
                    "value": [start_time, end_time]
                },
                {
                    "key": "severity",
                    "value": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                }
            ],
            "skip": skip,
            "take": take
        }

        return self._http_request(
            method="POST",
            url_suffix="/api/sdcc/infrastructure/core/analytics/object/operationalmessages/virtual",
            json_data=params,
        )


def format_data_fields(events: list[dict], evnet_type: str | None):
    """
    Gets a list of events of a specific event type and adds the `_time` & `source_log_type` fields to the event.
    Args:
        events: A list of events.
        evnet_type: The event type.
    """
    for event in events:
        event['_time'] = event.get('timestamp')
        event['source_log_type'] = evnet_type


def fetch_data(client, last_run, data_type):
    """
    Fetch data of a specified type (either 'events' or 'alerts') from the client.

    Args:
        client (Client): The client instance to fetch the data from.
        last_run (dict): the last run data.
        data_type (str): The type of data to fetch ('events' or 'alerts').

    Returns:
        tuple: Contains the fetched documents and updated last run dictionary.
    """
    end_time = int(time.time() * 1000)
    last_fetch_key = f'last_fetch_{data_type}'
    continue_fetch_key = f'continue_fetch_{data_type}'

    start_time = last_run.get(last_fetch_key, end_time - 2) + 1
    continue_fetch_data = last_run.get(continue_fetch_key, None)
    skip = 0

    if continue_fetch_data:
        end_time = continue_fetch_data.get('end_time')
        start_time = continue_fetch_data.get('start_time')
        skip = continue_fetch_data.get('fetched_' + data_type)

    demisto.debug(f'RadwareCloudDDoS: {data_type=} {start_time=}, {end_time=}, {skip=}')

    if data_type == 'events':
        response = client.get_events(start_time, end_time, skip, PAGE_SIZE)
    elif data_type == 'alerts':
        response = client.get_alerts(start_time, end_time, skip, PAGE_SIZE)
    else:
        raise ValueError("Invalid data_type. Expected 'events' or 'alerts'.")

    documents = response.get("documents")
    demisto.debug(f'RadwareCloudDDoS: {data_type=} {len(documents)=}')
    new_continue_fetch_data = {}

    if documents:
        if data_type == 'events':
            latest_timestamp = documents[0].get("endTimestamp")
        elif data_type == 'alerts':
            latest_timestamp = documents[0].get('context', {}).get("_timestamp")

        demisto.debug(f'RadwareCloudDDoS: {data_type=} {latest_timestamp=}')

        if len(documents) == PAGE_SIZE:
            demisto.debug(f'RadwareCloudDDoS: {data_type=} found next page')
            new_continue_fetch_data = {'end_time': end_time, 'start_time': start_time,
                                       'fetched_' + data_type: len(documents) + skip}

        if not continue_fetch_data:
            last_run[last_fetch_key] = latest_timestamp
            demisto.debug(f'RadwareCloudDDoS: {data_type=} saved {latest_timestamp=}')

        if new_continue_fetch_data:
            last_run['nextTrigger'] = '0'

        last_run[continue_fetch_key] = new_continue_fetch_data
        demisto.debug(f'RadwareCloudDDoS: {data_type=} set {new_continue_fetch_data=}')

        if data_type == 'events':
            format_data_fields(documents, 'security_events')
        elif data_type == 'alerts':
            format_data_fields(documents, 'operational_alerts')

    return documents, last_run


''' MAIN FUNCTION '''


def main() -> None:

    params = demisto.params()
    account_id: str = params.get('credentials', {}).get('identifier', '')
    api_key: str = params.get('credentials', {}).get('password', '')
    base_url: str = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    event_types = argToList(params.get("event_types"))
    last_run = demisto.getLastRun()
    demisto.debug(f'RadwareCloudDDoS: {last_run=}')

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            account_id=account_id,
            api_key=api_key,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy
        )
        if command == 'test-module':
            client.get_events(take=1)
            return_results('ok')
        elif command == 'fetch-events':
            events = []
            alerts = []
            if 'Events' in event_types:
                events, last_run = fetch_data(client, last_run=last_run, data_type='events')
            if 'Alerts' in event_types:
                alerts, last_run = fetch_data(client, last_run=last_run, data_type='alerts')

            demisto.setLastRun(last_run)
            send_events_to_xsiam(events+alerts, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f'Successfully sent {len(events)}events and {len(alerts)}alerts to XSIAM')

        elif command == "radware-cloud-ddos-protection-services-get-events":
            events = []
            alerts = []
            if 'Events' in event_types:
                events, _ = fetch_events(client, last_run=last_run)
            if 'Alerts' in event_types:
                alerts, _ = fetch_alerts(client, last_run=last_run)
            return_results(events+alerts)

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(e)}, error:{str(e)}")


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
