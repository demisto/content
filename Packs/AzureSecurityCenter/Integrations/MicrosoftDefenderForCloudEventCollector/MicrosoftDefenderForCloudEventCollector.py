from requests import Response
import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any, Dict, Tuple, List, Optional, Union, cast
from MicrosoftApiModule import *  # noqa: E402
from datetime import datetime
# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

VENDOR = 'micrsoft'
PRODUCT = 'defender_for_cloud'
API_VERSION = '2022-01-01'
OLD_API_VERSION = "2019-01-01"
APP_NAME = "ms-azure-sc"

''' CLIENT CLASS '''


class MsClient:
    """
    Microsoft Client enables authorized access to Azure Security Center.
    """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, server, verify, proxy, self_deployed, subscription_id,
                 ok_codes, certificate_thumbprint, private_key):
        base_url_with_subscription = f"{server}subscriptions/{subscription_id}/"
        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
            base_url=base_url_with_subscription, verify=verify, proxy=proxy, self_deployed=self_deployed,
            ok_codes=ok_codes, scope="https://management.azure.com/.default",
            certificate_thumbprint=certificate_thumbprint, private_key=private_key)
        self.server = server
        self.subscription_id = subscription_id

    
    def get_event_list(self, last_run) -> dict:
        
        """Listing alerts
        Args: 
            last_run (str): last run
        Returns:
            dict: contains response body with events
        """
        cmd_url = "/providers/Microsoft.Security/alerts"
        params = {'api-version': OLD_API_VERSION}
        # example = f'Properties/reportedTimeUtc gt 2023-01-01T15:36:50.6288854Z'
        filter_query = f'Properties/reportedTimeUtc ge {last_run}'
        params['$filter'] = filter_query
        # data = { 'filters' : "Properties.timeGeneratedUtc" : {
        #         "gt": last_run
        #     }}
        events = self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)
        return events


def test_module(client: MsClient, last_run: str):
    """
       Performs basic GET request to check if the API is reachable and authentication is successful.
       Returns ok if successful.
       """
    evetns_res = client.get_event_list(last_run)
    if 'value' in evetns_res:
        demisto.results('ok')


def get_events(client: MsClient, last_run: str, args:dict):
    """
     Args: 
            client (MsClient): The microsoft client.
            last_run (str): The last run.
            args (dict) : The demisto args.
        Returns:
            The raw events and a CommandResults object. 
    """
    limit = arg_to_number(args.get('limit', 50))
    events = client.get_event_list(last_run)
    events = events.get('value', [])
    events_list = events
    sort_events(events_list)

    if limit: 
        events_list = events_list[:limit]

    outputs = list()
    for alert in events_list:
        properties = alert.get("properties")
        if properties:
            outputs.append(
                {
                    "DisplayName": properties.get("alertDisplayName"),
                    "CompromisedEntity": properties.get("compromisedEntity"),
                    "DetectedTime": properties.get("timeGeneratedUtc"),
                    "ReportedSeverity": properties.get("severity"),
                    "Description": properties.get("description"),
                    "ID": alert.get("name"),
                }
            )

    md = tableToMarkdown(
        f"Microsft Defender For Cloud - List Alerts {limit} latests events",
        outputs,
        [
            "DisplayName",
            "CompromisedEntity",
            "DetectedTime",
            "ReportedSeverity",
            "Description",
            "ID",
        ],
        removeNull=True,
    )
    cr =  CommandResults(outputs_prefix="MicrosoftDefenderForCloud.Alerts", outputs=outputs, readable_output=md, raw_response=events)
    return events, cr


def find_next_run(events_list : list, last_run: str) -> str:
    """
    Args:
        events (list): The list of events from the API call
        last_run (str): The prevision last run
    Returns:
        The next run for the next fetch-event command. 
    """
    if not events_list:
        # No new events fetched we will keep the previos last_run.
        return last_run
    else:
        # New events fetched set the latest timeGeneratedUtc for next run.
        sort_events(events_list)
        return events_list[0].get('properties').get('timeGeneratedUtc')


def sort_events(events: list) -> None:
    """
    Sorts the list inplace by the timeGeneratedUtc
    """
    return events.sort(reverse=True, key=lambda event: event.get('properties').get('timeGeneratedUtc'))
  

def fetch_events(client: MsClient, last_run: str) -> list:
    """
    Args:
        client (MsClient): The microsoft client.
        last_run (str): The last run.
        first_fetch_time(int): The first_fetch_time If last_run is None (first time we are fetching)
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
    Returns:
        next_run: A time for the next run.
        list: List of events that will be created in XSIAM.
    """
    events = client.get_event_list(last_run)
    events = events.get("value", [])
    demisto.info(f'Fetched {len(events)} events.')

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = find_next_run(events, last_run)
    demisto.info(f'Setting next run {next_run}.')
    return next_run, events


def handle_last_run(first_fetch: str) -> str:
    """
    Args:
        first_fetch (str) : The first_fetch_time argument
    Returns:
        last_run (str): This will be the first_fetch on the first run and then the previos last_run
    """
    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=first_fetch,
        arg_name='First fetch time',
        required=True
    )
    last_run = demisto.getLastRun().get('time')
    if not last_run:
        # here we would convert the first fetch time to be compatible with the microsoft api
        last_run = first_fetch_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    demisto.info(f'Last run is set to be {last_run}')
    return last_run


def add_time_key_to_events(events: list) -> list:
    """
    Adds the _time key to the events.
    Args:
        events: list, the events to add the time key to.
    Returns:
        list: The events with the _time key.
    """
    for event in events:
        event["_time"] = event.get("properties").get('timeGeneratedUtc')
    return events

''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    params: dict = demisto.params()
    server = params.get('server_url', '').rstrip('/') + '/'
    tenant = params.get('tenant_id')
    auth_and_token_url = params.get('auth_id', '')
    enc_key = params.get('enc_key')
    use_ssl = not params.get('unsecure', False)
    proxy = params.get('proxy', False)
    subscription_id = params.get("sub_id")
    ok_codes = (200, 201, 202, 204)
    certificate_thumbprint = params.get('certificate_thumbprint')
    private_key = params.get('private_key')

    if not enc_key and not (certificate_thumbprint and private_key):
        raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.'
                               'For further information see '
                               'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')

    demisto.debug(f'Command being called is {command}')
    try:

        # @TODO: CHANGE THE SELF DEPLOYTED

        client = MsClient(tenant_id=tenant, auth_id=auth_and_token_url, enc_key=enc_key, app_name=APP_NAME, proxy=proxy,
                          server=server, verify=use_ssl, self_deployed=False, subscription_id=subscription_id,
                          ok_codes=ok_codes, certificate_thumbprint=certificate_thumbprint, private_key=private_key)

        first_fetch = params.get('first_fetch', '3 days')
        last_run = handle_last_run(first_fetch)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            test_module(client, last_run)

        elif command in ('ms-defender-for-cloud-get-events', 'fetch-events'):
            
            if command == 'ms-defender-for-cloud-get-events':
                should_push_events = argToBoolean(args.pop('should_push_events'))
                events, results = get_events(client, last_run, args)
                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                next_run, events = fetch_events(
                    client=client,
                    last_run=last_run
                )
                # saves next_run for the time fetch-events is invoked
                demisto.setLastRun({'time' : next_run})

            events = add_time_key_to_events(events)
        
            if should_push_events:
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()