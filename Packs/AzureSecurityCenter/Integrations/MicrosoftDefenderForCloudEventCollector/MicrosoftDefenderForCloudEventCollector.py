from requests import Response
import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any, Dict, Tuple, List, Optional, Union, cast
from MicrosoftApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'Micrsoft'
PRODUCT = 'Microsoft_defender_for_cloud'
API_VERSION = '2022-01-01'

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

    
    def get_event_list(self, last_run, args: dict):
        
        """Listing alerts
        Args: 
            filter_query (str): what to filter
            select_query (str): what to select
            expand_query (str): what to expand
        Returns:
            dict: contains response body
        """
        filter_query = args.get("filter")
        select_query = args.get("select")
        expand_query = args.get("expand")
        
        cmd_url = "/providers/Microsoft.Security/alerts"

        params = {'api-version': API_VERSION}
        if filter_query:
            params['$filter'] = filter_query
        if select_query:
            params['$select'] = select_query
        if expand_query:
            params['$expand'] = expand_query

        events = self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)
        return events


def test_module(client: MsClient):
    """
       Performs basic GET request to check if the API is reachable and authentication is successful.
       Returns ok if successful.
       """
    if client.subscription_id:
        client.list_locations()
    else:
        client.list_sc_subscriptions()
    demisto.results('ok')


def get_events(client: MsClient, last_run, args:dict):
    events = client.get_event_list(last_run, args)
    events.get("value")
    outputs = list()
    for alert in events:
        properties = alert.get("properties")
        if properties:
            outputs.append(
                {
                    "DisplayName": properties.get("alertDisplayName"),
                    "CompromisedEntity": properties.get("compromisedEntity"),
                    "DetectedTime": properties.get("detectedTimeUtc"),
                    "ReportedSeverity": properties.get("reportedSeverity"),
                    "State": properties.get("state"),
                    "ActionTaken": properties.get("actionTaken"),
                    "Description": properties.get("description"),
                    "ID": alert.get("name"),
                }
            )

    md = tableToMarkdown(
        "Microsft Defender For Cloud - List Alerts",
        outputs,
        [
            "DisplayName",
            "CompromisedEntity",
            "DetectedTime",
            "ReportedSeverity",
            "State",
            "ActionTaken",
            "Description",
            "ID",
        ],
        removeNull=True,
    )
    cr =  CommandResults(outputs_prefix="Microsoft-Defender-For-Cloud.Alerts", outputs=outputs, readable_output=md, raw_response=events)
    return events, cr

def find_next_run():
    pass 


def fetch_events(client: MsClient, last_run, args: dict):
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    search_filter = 'filter'

    events = client.get_event_list(last_run, args)
    demisto.info(f'Fetched event with id: {prev_id + 1}.')

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = find_next_run()
    demisto.info(f'Setting next run {next_run}.')
    return next_run, events


def handle_last_run(params: dict):
    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    last_run = demisto.getLastRun()
    if not last_run:
        # here we would convert the first fetch time to be compatible with the microsoft api
        last_run = first_fetch_time
    
    demisto.info(f'Last run is set to be {last_run}')
    return last_run

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
    self_deployed: bool = params.get('self_deployed', False)
    proxy = params.get('proxy', False)
    subscription_id = demisto.args().get("subscription_id") or params.get("default_sub_id")
    ok_codes = (200, 201, 202, 204)
    certificate_thumbprint = params.get('certificate_thumbprint')
    private_key = params.get('private_key')
    verify_certificate = not params.get('insecure', False)

    if not enc_key and not (certificate_thumbprint and private_key):
        raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.'
                               'For further information see '
                               'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')

    demisto.debug(f'Command being called is {command}')
    try:
        client = MsClient(tenant_id=tenant, auth_id=auth_and_token_url, enc_key=enc_key, app_name=APP_NAME, proxy=proxy,
                          server=server, verify=use_ssl, self_deployed=self_deployed, subscription_id=subscription_id,
                          ok_codes=ok_codes, certificate_thumbprint=certificate_thumbprint, private_key=private_key)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            test_module(client)

        elif command in ('ms-defender-for-cloud-get-events', 'fetch-events'):
            
            last_run = handle_last_run(params)

            if command == 'ms-defender-for-cloud-get-events':
                should_push_events = argToBoolean(args.pop('should_push_events'))
                events, results = get_events(client, last_run, args)
                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                next_run, events = fetch_events(
                    client=client,
                    last_run=last_run,
                    args=args
                )
                # saves next_run for the time fetch-events is invoked
                demisto.setLastRun(next_run)

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