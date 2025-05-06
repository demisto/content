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


def filter_documents(documents: List[Dict[str, Union[str, Dict]]],
                     timestamp: Union[str, None], ids: List[str], data_type: str) -> List[Dict[str, Union[str, Dict]]]:
    """
    Filters out documents from the given list based on the specified timestamp and ids.
    Args:
        documents (List[Dict[str, Union[str, Dict]]]): The list of documents to filter.
        timestamp (Union[str, None]): The timestamp to filter against.
        ids (List[str]): The list of ids to filter against.
        data_type (str): The type of data.
    Returns: (List[Dict[str, Union[str, Dict]]]): The filtered list of documents.
    """
    if not documents or not timestamp or not ids:
        return documents

    def get_timestamp(data: Dict[str, Union[str, Dict]]) -> Optional[str | dict[Any, Any] | None]:
        if data_type == 'events':
            return data.get('endTimestamp')
        else:
            return data.get('context', {}).get('_timestamp')  # type: ignore[union-attr]
    if get_timestamp(documents[-1]) != timestamp:
        return documents
    filtered_documents = []
    for doc in documents:  # Iterate through the original list
        if get_timestamp(doc) == timestamp and doc.get('_id') in ids:
            continue
        filtered_documents.append(doc)

    return filtered_documents


def get_latest_timestamp_and_ids(documents: List[Dict[str, Union[str, Dict]]],
                                 data_type: str) -> tuple[Any, list[str | dict[Any, Any] | None]]:
    """
    Retrieves the latest timestamp and the corresponding ids from the given list of documents.
    args:
        documents (List[Dict[str, Union[str, Dict]]]): The list of documents.
        data_type (str): The type of data.
    Returns: (Tuple[Union[str, None], List[str]]): A tuple containing the latest timestamp and a list of corresponding ids.
    """
    if not documents:
        return None, []

    def get_timestamp(data):
        if data_type == 'events':
            return data.get('endTimestamp')
        else:
            return data.get('context', {}).get('_timestamp')

    latest_timestamp = get_timestamp(documents[0])
    ids = [documents[0].get('_id')]

    for doc in documents[1:]:
        if get_timestamp(doc) == latest_timestamp:
            ids.append(doc.get('_id'))
        else:
            break

    return latest_timestamp, ids


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
    # we are initiating variables based on the data type.
    last_fetch_key = f'last_fetch_{data_type}'
    iteration_cache_fetch_key = f'iteration_cache_fetch_{data_type}'

    end_time = int(time.time() * 1000)
    latest_fetch = last_run.get(last_fetch_key, {})
    start_time = latest_fetch.get('latest_timestamp', end_time - 1)
    iteration_cache = last_run.get(iteration_cache_fetch_key, None)
    skip = 0

    if iteration_cache:
        end_time = iteration_cache.get('end_time')
        start_time = iteration_cache.get('start_time')
        skip = iteration_cache.get('fetched_' + data_type)

    demisto.debug(f'{data_type=} {start_time=}, {end_time=}, {skip=}')

    if data_type == 'events':
        response = client.get_events(start_time, end_time, skip, PAGE_SIZE)
    elif data_type == 'alerts':
        response = client.get_alerts(start_time, end_time, skip, PAGE_SIZE)
    else:
        raise ValueError("Invalid data_type. Expected 'events' or 'alerts'.")

    documents = response.get("documents")
    demisto.debug(f'got {len(documents)} documents in the response')
    new_iteration_cache = {}

    filtered_documents = filter_documents(documents, timestamp=latest_fetch.get('latest_timestamp'),
                                          ids=latest_fetch.get('latest_ids'), data_type=data_type)
    demisto.debug(f'after filter remains {len(filtered_documents)} documents')

    if filtered_documents:

        if len(filtered_documents) == PAGE_SIZE:
            demisto.debug('found next page')
            new_iteration_cache = {'end_time': end_time, 'start_time': start_time,
                                       'fetched_' + data_type: len(filtered_documents) + skip}

        if not iteration_cache:
            latest_timestamp, latest_ids = get_latest_timestamp_and_ids(filtered_documents, data_type)
            last_run[last_fetch_key] = {'latest_timestamp': latest_timestamp, 'latest_ids': latest_ids}
            demisto.debug(f'saved {last_run[last_fetch_key]=}')

        if new_iteration_cache:
            last_run['nextTrigger'] = '0'

        if data_type == 'events':
            format_data_fields(filtered_documents, 'security_events')
        elif data_type == 'alerts':
            format_data_fields(filtered_documents, 'operational_alerts')
    else:
        if not latest_fetch.get('latest_timestamp'):
            last_run[last_fetch_key] = {'latest_timestamp': start_time, 'latest_ids': []}

    last_run[iteration_cache_fetch_key] = new_iteration_cache
    demisto.debug(f'set {new_iteration_cache=}')

    return filtered_documents, last_run


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    params = demisto.params()
    account_id: str = params.get('credentials', {}).get('identifier', '')
    api_key: str = params.get('credentials', {}).get('password', '')
    base_url: str = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    event_types = argToList(params.get("event_types"))
    last_run = demisto.getLastRun()
    demisto.debug(f'{last_run=}')

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
            demisto.debug(f'Successfully sent {len(events)} events and {len(alerts)} alerts to XSIAM')
            # demisto.debug(f'Successfully sent event {[event.get("_id") for event in events]} IDs to XSIAM')
            # demisto.debug(f'Successfully sent alert {[alert.get("_id") for alert in alerts]} IDs to XSIAM')
        elif command == "radware-cloud-ddos-protection-services-get-events":
            events = []
            alerts = []
            if 'Events' in event_types:
                events, _ = fetch_data(client, last_run=last_run, data_type='events')
            if 'Alerts' in event_types:
                alerts, _ = fetch_data(client, last_run=last_run, data_type='alerts')
            return_results(events+alerts)

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(e)}, error:{str(e)}")


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
