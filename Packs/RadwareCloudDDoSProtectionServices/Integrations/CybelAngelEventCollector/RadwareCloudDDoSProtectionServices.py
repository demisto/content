import dateparser

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


class Client(BaseClient):

    def __init__(self, base_url: str, account_id: str, api_key: str, verify: bool, proxy: bool):
        self.account_id = account_id
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers={'x-api-key': api_key, 'Context': account_id})

    def get_events1(self, start_time=None, end_time=None, skip=0, take=700) -> dict[str, Any] | Response:

        return {
            "documents": [
                {
                    "_id": "6551d4b85d13027652c67da6",
                    "accountId": "521e0817f9be710d549363a3",
                    "attackId": "1659144-1686794222",
                    "accountName": "John Doe Corp",
                    "action": "Drop",
                    "assetName": "test_asset3",
                    "averageBitRate": 0,
                    "averageByteRate": 0,
                    "averagePacketRate": 1,
                    "category": "ErtFeed",
                    "classification": "EAAF",
                    "collectorType": "CLOUD",
                    "duration": 0,
                    "endTimestamp": 1699861688986,
                    "lastPeriodBitRate": 0,
                    "lastPeriodByteRate": 0,
                    "lastPeriodPacketRate": 0,
                    "maxBitRate": 0,
                    "maxByteRate": 0,
                    "maxPacketRate": 0,
                    "packetBandwidth": 0,
                    "packetCount": 1,
                    "protocol": "TCP",
                    "risk": "High",
                    "siteName": "JD-HK",
                    "sourceCountry": "United Kingdom",
                    "sourceCountryCode": "GB",
                    "startTimestamp": 1699861688986,
                    "status": "Occurred",
                    "targetAddress": "141.226.109.40",
                    "targetAddressValue": 2380426536,
                    "targetPort": "28015",
                    "timestamp": "2023-11-13T07:48:08.986+00:00",
                    "vectorId": 1282,
                    "vectorName": "ERT Active Attacker: ERT;SCN"
                }
            ],
            "pageDescriptor": {
                "total": 0,
                "pageSize": 3,
                "pageIndex": 0,
                "pageCount": 0
            }
        }

    def get_events(self, start_time=None, end_time=None, skip=0, take=700) -> dict[str, Any] | Response:
        """
        Submits a remediation request for events.

        Args:
            data (dict): The remediation request data.

        Returns:
            dict[str, Any] | Response: The response from the API.
        """
        params = {
            "criteria": [
                {
                    "key": "accountId",
                    "value": self.account_id
                },
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
            params=params,
        )

    def get_alerts(self, start_time=None, end_time=None, skip=0, take=700) -> dict[str, Any] | Response:
        """
        Submits a remediation request for events.

        Args:
            data (dict): The remediation request data.

        Returns:
            dict[str, Any] | Response: The response from the API.
        """
        params = {
            "criteria": [
                {
                    "key": "accountId",
                    "value": self.account_id
                },
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
            params=params,
        )


def fetch_events(client, last_run):
    demisto.debug(f'RadwareCloudDDoS: {last_run=}')
    end_time = int(time.time() * 1000)
    start_time = last_run.get('last_fetch_events', end_time - 1)
    demisto.debug(f'RadwareCloudDDoS: {start_time=}, {end_time=}')
    response = client.get_events(start_time, end_time, 0, 700)
    demisto.debug(f'RadwareCloudDDoS: {response.status_code=}')
    demisto.debug(f'RadwareCloudDDoS: {response.content=}')

    documents = response.get("documents")
    if documents:
        latest_timestamp = max(date_to_timestamp(doc["timestamp"], date_format="%Y-%m-%dT%H:%M:%S.%f%z") for doc in documents)
        demisto.debug(f'RadwareCloudDDoS: {latest_timestamp=}')
        if response.get('pageIndex', 0) < response.get('pageCount', 0):
            demisto.debug(f'RadwareCloudDDoS: found next page')
            last_run['nextTrigger'] = 0
        last_run['last_fetch_events'] = latest_timestamp
    return documents, last_run


def fetch_alerts(client, last_run):
    demisto.debug(f'RadwareCloudDDoS: {last_run=}')
    end_time = int(time.time() * 1000)
    start_time = last_run.get('last_fetch_alerts', end_time - 1)
    demisto.debug(f'RadwareCloudDDoS: {start_time=}, {end_time=}')
    response = client.get_alerts(start_time, end_time, 0, 700)
    demisto.debug(f'RadwareCloudDDoS: {response.status_code=}')
    demisto.debug(f'RadwareCloudDDoS: {response.content=}')

    documents = response.get("reply")
    if documents:
        latest_timestamp = max(date_to_timestamp(doc["timestamp"]['_date_time'], date_format="%Y-%m-%dT%H:%M:%S.%f%z") for doc in documents)
        demisto.debug(f'RadwareCloudDDoS: {latest_timestamp=}')
        if response.get('pageIndex', 0) < response.get('pageCount', 0):
            demisto.debug(f'RadwareCloudDDoS: found next page')
            last_run['nextTrigger'] = 0
        last_run['last_fetch_alerts'] = latest_timestamp
    return documents, last_run


''' MAIN FUNCTION '''


def main() -> None:

    params = demisto.params()
    args = demisto.args()
    account_id: str = params.get('credentials', {}).get('identifier', '')
    api_key: str = params.get('credentials', {}).get('password', '')
    base_url: str = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch_events = arg_to_number(params.get("max_fetch_events"))
    max_fetch_alerts = arg_to_number(params.get("max_fetch_alerts"))
    event_types = argToList(params.get("event_types"))
    last_run = demisto.getLastRun()

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
            if 'Events' in event_types:
                events, last_run = fetch_events(client, last_run=last_run)
            if 'Alerts' in event_types:
                alerts, last_run = fetch_alerts(client, last_run=last_run)

            demisto.setLastRun(last_run)
            send_events_to_xsiam(events+alerts, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f'Successfully sent event {[event.get("_id") for event in events]} IDs to XSIAM')
        elif command == "RadwareCloudDDoSProtectionServices-get-events":
            events, _ = fetch_events(client, last_run=demisto.getLastRun())
            return_results(events)

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(e)}, error:{str(e)}")


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
