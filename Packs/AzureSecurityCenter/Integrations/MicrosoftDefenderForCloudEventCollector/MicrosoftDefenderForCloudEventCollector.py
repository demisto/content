import demistomock as demisto
from CommonServerPython import *
import urllib3
from MicrosoftApiModule import *  # noqa: E402
urllib3.disable_warnings()

''' CONSTANTS '''

VENDOR = 'microsoft'
PRODUCT = 'defender_for_cloud'
API_VERSION = '2022-01-01'
DEFAULT_LIMIT = 50
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

''' CLIENT CLASS '''


class MsClient:
    """
    Microsoft Client enables authorized access to Azure Security Center.
    """

    def __init__(self, tenant_id, auth_id, enc_key, server, verify, proxy, self_deployed, subscription_id,
                 ok_codes, certificate_thumbprint, private_key):
        base_url_with_subscription = f"{server}subscriptions/{subscription_id}/"
        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key,
            base_url=base_url_with_subscription, verify=verify, proxy=proxy, self_deployed=self_deployed,
            ok_codes=ok_codes, scope="https://management.azure.com/.default",
            certificate_thumbprint=certificate_thumbprint, private_key=private_key,
            command_prefix="ms-defender-for-cloud",
        )
        self.server = server
        self.subscription_id = subscription_id

    def get_event_list_basic(self):
        cmd_url = "/providers/Microsoft.Security/alerts"
        params = {'api-version': API_VERSION}
        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def get_event_list(self, last_run: dict) -> list:
        """Listing alerts
        Args:
            last_run (str): last run
        Returns:
            tuple: (events, last_run)
        """
        cmd_url = "/providers/Microsoft.Security/alerts"
        params = {'api-version': API_VERSION}
        events: list = []
        response = self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params,
                                               scope="https://management.azure.com/.default",
                                               resource=Resources.management_azure)
        curr_events = response.get("value", [])

        curr_filtered_events = filter_out_previosly_digested_events(curr_events, last_run)
        if check_events_were_filtered_out(curr_events, curr_filtered_events):
            return curr_filtered_events

        events.extend(curr_filtered_events)

        while nextLink := response.get('nextLink', None):
            response = self.ms_client.http_request(method="GET", full_url=nextLink)
            curr_events = response.get("value", [])
            curr_filtered_events = filter_out_previosly_digested_events(curr_events, last_run)
            events.extend(curr_filtered_events)
            if check_events_were_filtered_out(curr_events, curr_filtered_events):
                break

        return events


def filter_out_previosly_digested_events(events: list, last_run: dict) -> list:
    """
    Args:
        - events (list): The events list response from the API
        - last_run (dict): The last run dict
    Returns:
        (list): A list with all the duplicates from lastrun filtered out
    """
    if not last_run:
        return events
    events = [event for event in events if event.get('properties', {}).get(
        'startTimeUtc', '') >= last_run.get('last_run', '')
        and event.get('id', '') not in last_run.get('dup_digested_time_id', [])]
    return events


def check_events_were_filtered_out(events: list, filtered_events: list) -> bool:
    """
    Args:
        - events (list): The events list response from the API
        - filtered_events (list): The filtered event list (no dups)
    Returns:
        (bool): Whether events were filtered out
    """
    return len(events) > len(filtered_events)


def test_module(client: MsClient):    # pragma: no cover
    """
       Performs basic GET request to check if the API is reachable and authentication is successful.
       Returns ok if successful.
    """
    evetns_res = client.get_event_list_basic()
    if 'value' in evetns_res:
        demisto.results('ok')


def get_events(client: MsClient, last_run: dict, limit: int) -> tuple:
    """
     Args:
        client (MsClient): The microsoft client.
        last_run (dict): The last run object.
    Returns:
        (tuple): (events_list, CommandResults)
    """
    events_list = client.get_event_list(last_run)

    if limit and len(events_list) > limit:
        events_list = events_list[-limit:]

    outputs = []
    for alert in events_list:
        if properties := alert.get("properties"):
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
        "Microsft Defender For Cloud - List Alerts",
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
    cr = CommandResults(outputs_prefix="MicrosoftDefenderForCloud.Alert",
                        outputs=outputs, readable_output=md, raw_response=events_list)
    return events_list, cr


def find_next_run(events_list: list, last_run: dict) -> dict:
    """
    Args:
        events (list): The list of events from the API call
        last_run (str): The prevision last run
    Returns:
        The next run for the next fetch-event command.
    """
    if not events_list:
        return last_run

    next_run = events_list[0].get('properties', {}).get('startTimeUtc', '')
    id_same_next_run_list = [event.get('id') for event in events_list if event.get('properties', {}).get(
        'startTimeUtc') == next_run]
    demisto.info(f'Setting next run time to {next_run}, events with same time are {id_same_next_run_list}.')
    return {'last_run': next_run, 'dup_digested_time_id': id_same_next_run_list}


def fetch_events(client: MsClient, last_run: dict) -> list:
    """
    Args:
        client (MsClient): The microsoft client.
        last_run (str): The last run.
    Returns:
        events: The list of fetched events.
    """
    events = client.get_event_list(last_run)
    demisto.info(f'Fetched {len(events)} events.')
    return events


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


def handle_last_run(first_fetch_time: str) -> dict:
    """
    In the first run init with the first_fetch_time after use the previos last_run.
    Args:
        - first_fetch_time(str): The first fetch time arg
    Returns:
        The last run object.
    """
    return demisto.getLastRun() or {
        'last_run': first_fetch_time,
        'dup_digested_time_id': [],
    }


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    args = demisto.args()
    command = demisto.command()
    params: dict = demisto.params()
    server = params.get('server_url', '').rstrip('/') + '/'
    tenant = params.get('tenant_id', {}).get('password')
    client_id = params.get('client_id', {}).get('password')
    enc_key = params.get('enc_key', {}).get('password')
    use_ssl = not params.get('unsecure', False)
    proxy = params.get('proxy', False)
    subscription_id = params.get("sub_id", {}).get('password')
    ok_codes = (200, 201, 202, 204)
    certificate_thumbprint = params.get('certificate_thumbprint', {}).get('password')
    private_key = params.get('private_key')
    first_fetch_time = params.get("first_fetch", "3 days")

    if not enc_key and not (certificate_thumbprint and private_key):
        raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.'
                               'For further information see '
                               'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')

    first_fetch_time: datetime = arg_to_datetime(   # type: ignore
        arg=first_fetch_time,
        arg_name="First fetch time",
        required=True,
    )

    first_fetch_time_strftime = first_fetch_time.strftime(
        DATE_FORMAT
    )

    demisto.debug(f'Command being called is {command}')
    try:
        client = MsClient(tenant_id=tenant, auth_id=client_id, enc_key=enc_key, proxy=proxy,
                          server=server, verify=use_ssl, self_deployed=True, subscription_id=subscription_id,
                          ok_codes=ok_codes, certificate_thumbprint=certificate_thumbprint, private_key=private_key)

        last_run = handle_last_run(first_fetch_time_strftime)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            test_module(client)

        elif command == 'ms-defender-for-cloud-auth-reset':
            return_results(reset_auth())

        elif command in ('ms-defender-for-cloud-get-events', 'fetch-events'):

            if command == 'ms-defender-for-cloud-get-events':
                limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
                should_push_events = argToBoolean(args.pop('should_push_events', False))
                events, results = get_events(client, last_run, limit=limit)  # type: ignore
                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                events = fetch_events(
                    client=client,
                    last_run=last_run
                )

            events = add_time_key_to_events(events)

            if should_push_events:
                # saves next_run for the time fetch-events is invoked
                demisto.setLastRun(find_next_run(events, last_run))
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
