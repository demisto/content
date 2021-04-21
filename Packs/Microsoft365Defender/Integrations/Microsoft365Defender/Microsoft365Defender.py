import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

MAX_ENTRIES = '100'
TIMEOUT = 30

''' CLIENT CLASS '''


class Client(BaseClient):
    @logger
    def __init__(self, app_id: str, verify: bool, proxy: bool):
        client_args = {
            'self_deployed': True,  # We always set the self_deployed key as True because when not using a self
            # deployed machine, the DEVICE_CODE flow should behave somewhat like a self deployed
            # flow and most of the same arguments should be set, as we're !not! using OProxy.
            'auth_id': app_id,
            'token_retrieval_url': 'https://login.windows.net/organizations/oauth2/v2.0/token',
            'grant_type': DEVICE_CODE,
            'base_url': 'https://api.security.microsoft.com',
            'verify': verify,  # Todo fix
            'proxy': proxy,
            'scope': 'offline_access https://security.microsoft.com/mtp/.default',
            'ok_codes': (200, 201, 202, 204),
            'resource': 'https://api.security.microsoft.com'
        }
        self.ms_client = MicrosoftClient(**client_args)

    @logger
    def incidents_list(self, limit: int, status: Optional[str], assigned_to: Optional[str], timeout: int = TIMEOUT) -> \
            List[Dict]:
        """
        GET request from the client using OData operators:
            - $top: how many incidents to receive, maximum value is 100
            - $filter: OData query to filter the the list on the properties:
                                                                lastUpdateTime, createdTime, status, and assignedTo
        Args:
            limit: how many incidents to receive, maximum value is 100
            status: filter list to contain only incidents with the given status (Active, Resolved or Redirected)
            assigned_to: Owner of the incident, or None if no owner is assigned.
            timeout: The amount of time (in seconds) that a request will wait for a client to
                establish a connection to a remote machine before a timeout occurs.

        Returns: list of incidents

        """
        params = {'$top': limit}
        if status:
            params['$filter'] = 'status eq ' + status

        if assigned_to:
            params['$filter'] += 'and' if status else ''
            params['$filter'] += 'assignedTo eq ' + assigned_to

        response = self.ms_client.http_request(method='GET', url_suffix='api/incidents', timeout=timeout,
                                               params=params)
        return response.get('value')


@logger
def start_auth(client: Client) -> CommandResults:
    result = client.ms_client.start_auth('!microsoft-365-defender-auth-complete')
    return CommandResults(readable_output=result)


@logger
def complete_auth(client: Client) -> CommandResults:
    client.ms_client.get_access_token()
    return CommandResults(readable_output='✅ Authorization completed successfully.')


@logger
def reset_auth() -> CommandResults:
    set_integration_context({})
    return CommandResults(readable_output='Authorization was reset successfully. You can now run '
                                          '**!microsoft-365-defender-auth-start** and **!microsoft-365-defender-auth-complete**.')


@logger
def test_connection(client: Client) -> CommandResults:
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return CommandResults(readable_output='✅ Success!')


''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


# todo ask roy
def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.

        test_connection(client)

        message = 'ok'

    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return message


def convert_incident_to_readable(raw_incident: Dict) -> Dict:
    """
    Converts incident received from microsoft 365 defender to readable format
    Args:
        raw_incident: The incident as received from microsoft 365 defender

    Returns: new dictionary with new mapping.

    """
    if not raw_incident:
        raw_incident = {}
    alerts_list = raw_incident.get('alerts', [])

    alerts_status = [alert.get('status') for alert in alerts_list]
    return {
        'Incident name': raw_incident.get('incidentName'),
        'Tags': raw_incident.get('tags'),
        'Severity': raw_incident.get('severity'),
        'Incident ID': raw_incident.get('incidentId'),
        # investigation state - relevant only for alerts.
        'Categories': ', '.join({alert.get('category') for alert in alerts_list}),
        'Impacted entities': ', '.join({entity.get('accountName') for alert in alerts_list
                                        for entity in alert.get('entities') if entity.get('entityType') == 'User'}),
        'Active alerts': f'{alerts_status.count("Active")} / {len(alerts_status)}',
        'Service sources': ', '.join({alert.get('serviceSource') for alert in alerts_list}),
        'Detection sources': ', '.join({alert.get('detectionSource') for alert in alerts_list}),
        # Data sensitivity - is not relevant
        'First activity': alerts_list[0].get('firstActivity') if alerts_list else '',
        'Last activity': alerts_list[-1].get('lastActivity') if alerts_list else '',
        'Status': raw_incident.get('status'),
        'Assigned to': raw_incident.get('assignedTo', 'Unassigned'),
        'Classification': raw_incident.get('classification', 'Not set'),
        'Device groups': ', '.join({device.get('deviceDnsName') for alert in alerts_list
                                    for device in alert.get('devices')})
    }


@logger
def microsoft_365_defender_incidents_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Returns list of the latest incidents in microsoft 365 defender in readable table.
    The list can be filtered using the following arguments:
        - limit - number of incidents in the list, integer between 0 to 100.
        - status - fetch only incidents with the given status (
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        args(Dict): Demisto arguments:
              - limit - integer between 0 to 100
              - status - get incidents with the given status (Active, Resolved or Redirected)
              - assigned_to - get incidents assigned to the given user
    Returns: CommandResults

    """
    limit = arg_to_number(args.get('limit', MAX_ENTRIES), arg_name='limit', required=True)
    status = args.get('status')
    assigned_to = args.get('assigned_to')

    raw_incidents = client.incidents_list(limit=limit, status=status, assigned_to=assigned_to)

    readable_incidents = [convert_incident_to_readable(incident) for incident in raw_incidents]
    # the table headers are the incident keys. creates dummy incident to manage a situation of empty list.
    headers = list(convert_incident_to_readable({}).keys())
    human_readable_table = tableToMarkdown(name="Incidents:", t=readable_incidents, headers=headers)

    return CommandResults(outputs_prefix='Microsoft365Defender.Incident', outputs_key_field='incidentId',
                          outputs=raw_incidents,
                          readable_output=human_readable_table)


@logger
def microsoft_365_defender_incident_update_command(client: Client, args: Dict) -> CommandResults:
    # func: microsoft - 365 - defender - incident - update
    # params:
    # - incident_id
    # - status = Active, Resolved
    # Redirected(Drop
    # down)
    # - assigned_to = ???
    # - classification = Unknown, FalsePositive, TruePositive(Drop
    # down)
    # - determination = NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other(
    #     drop
    # down)
    # - tags = ?
    pass


@logger
def fetch_incidents(client: Client, fetch_time: Optional[str], incident_status: str, default_severity: str,
                    max_fetch: str, last_run: Dict) \
        -> list:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        incident_status: Incident statuses to fetch, can be: all, opened, closed, updated
        default_severity: Default incoming incident severity
        last_run: Last fetch object.
        max_fetch: maximum amount of incidents to fetch

    Returns:
        incidents, new last_run
    """
    # timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
    # if not last_run:  # if first time running
    #     new_last_run = {'time': parse_date_range(fetch_time, date_format=timestamp_format)[0]}
    # else:
    #     new_last_run = last_run
    #
    # demisto_incidents: List = list()
    # from_epoch = date_to_timestamp(new_last_run.get('time'), date_format=timestamp_format)
    # to_epoch = date_to_timestamp(datetime.now(), date_format=timestamp_format)
    # # Get incidents from Securonix
    # demisto.info(f'Fetching Securonix incidents. From: {from_epoch}. To: {to_epoch}')
    # securonix_incidents = client.list_incidents_request(from_epoch, to_epoch, incident_status, max_fetch)
    #
    # if securonix_incidents:
    #     already_fetched = last_run.get('already_fetched', [])
    #     incidents_items = list(securonix_incidents.get('incidentItems'))  # type: ignore
    #     for incident in incidents_items:
    #         incident_id = str(incident.get('incidentId', 0))
    #         # check if incident was already fetched due to updating over lastUpdateDate
    #         if incident_id not in already_fetched:
    #             incident_name = get_incident_name(incident, incident_id)  # Try to get incident reason as incident name
    #             demisto_incidents.append({
    #                 'name': incident_name,
    #                 'occurred': timestamp_to_datestring(incident.get('lastUpdateDate')),
    #                 'severity': incident_priority_to_dbot_score(incident.get('priority'), default_severity),
    #                 'rawJSON': json.dumps(incident)
    #             })
    #             already_fetched.append(str(incident_id))  # add already fetched incidents ids to the set
    #
    #     if incidents_items:
    #         now = timestamp_to_datestring(incidents_items[-1].get('lastUpdateDate'))
    #     else:
    #         now = datetime.now().strftime(timestamp_format)
    #     new_last_run.update({'time': now, 'already_fetched': already_fetched})
    #
    # demisto.setLastRun({'value': json.dumps(new_last_run)})
    # return demisto_incidents
    pass


@logger
def microsoft_365_defender_advanced_hunting_command(client: Client, args: Dict) -> CommandResults:
    # func: microsoft - 365 - defender - advanced - hunting
    # params:
    # - query

    pass


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)
    app_id = demisto.params().get('app_id')
    demisto.debug(f'Command being called is {demisto.command()}')

    command = demisto.command()
    args = demisto.args()

    try:
        client = Client(
            app_id=app_id,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'microsoft-365-defender-auth-start':
            return_results(start_auth(client))

        elif command == 'microsoft-365-defender-auth-complete':
            return_results(complete_auth(client))

        elif command == 'microsoft-365-defender-auth-reset':
            return_results(reset_auth())

        elif command == 'microsoft-365-defender-auth-test':
            return_results(test_connection(client))

        elif command == 'microsoft-365-defender-incidents-list':

            # Debugging
            # start_auth(client)
            # complete_auth(client)
            # context = {
            #     'device_code': 'DAQABAAEAAAD--DLA3VO7QrddgJg7Wevr4tsrU37JvtuJ_g0YozW5PbHybfgLteR0z6WHvIamyFmtoCPKXL2rKgWDGPExAWJ3M0892FglrbooD3dqSNMySaMAN1DJUlb1tCcwF9hYKhc9Gvd1nsoQ92FTNJWf0rD0PnA5bsE1fZQwWCVgK0Nt-oqqJxk0AeMPOzluTtLBWO4gAA',
            #     'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im5PbzNaRHJPRFhFSzFqS1doWHNsSFJfS1hFZyIsImtpZCI6Im5PbzNaRHJPRFhFSzFqS1doWHNsSFJfS1hFZyJ9.eyJhdWQiOiJodHRwczovL3NlY3VyaXR5Lm1pY3Jvc29mdC5jb20vbXRwIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZWJhYzFhMTYtODFiZi00NDliLThkNDMtNTczMmMzYzFkOTk5LyIsImlhdCI6MTYxODk3ODA4MSwibmJmIjoxNjE4OTc4MDgxLCJleHAiOjE2MTg5ODE5ODEsImFjciI6IjEiLCJhaW8iOiJBVFFBeS84VEFBQUFuZis0STJnaXFFRUpIWHlMVHRzVWE1TXArMytZUGl0NHcybVZsby9ybVhYS3FTYkxjdG8zMk9EbWpNVTdOZlBuIiwiYW1yIjpbInB3ZCJdLCJhcHBpZCI6IjkwOTNjMzU0LTYzMGEtNDdmMS1iMDg3LTY3NjhlYjk0MjdlNiIsImFwcGlkYWNyIjoiMCIsImZhbWlseV9uYW1lIjoiQnJhbmRlaXMiLCJnaXZlbl9uYW1lIjoiQXZpc2hhaSIsImlwYWRkciI6IjE5OS4yMDMuMTYyLjIxMyIsIm5hbWUiOiJBdmlzaGFpIEJyYW5kZWlzIiwib2lkIjoiM2ZhOWYyOGItZWIwZS00NjNhLWJhN2ItODA4OWZlOTk5MWUyIiwicHVpZCI6IjEwMDMwMDAwOUFCQzI4NzgiLCJyaCI6IjAuQVhNQUZocXM2Ny1CbTBTTlExY3l3OEhabVZURGs1QUtZX0ZIc0lkbmFPdVVKLVp6QUhBLiIsInNjcCI6IkFkdmFuY2VkSHVudGluZy5SZWFkIEluY2lkZW50LlJlYWRXcml0ZSIsInN1YiI6ImVqUXAyalZVbmpYN0thUnVqbFVma1k3QmJUcnJjT1I5LWFaSVhPZDNEZTAiLCJ0ZW5hbnRfcmVnaW9uX3Njb3BlIjoiRVUiLCJ0aWQiOiJlYmFjMWExNi04MWJmLTQ0OWItOGQ0My01NzMyYzNjMWQ5OTkiLCJ1bmlxdWVfbmFtZSI6ImF2aXNoYWlAZGVtaXN0b2Rldi5vbm1pY3Jvc29mdC5jb20iLCJ1cG4iOiJhdmlzaGFpQGRlbWlzdG9kZXYub25taWNyb3NvZnQuY29tIiwidXRpIjoiek1KTHRQNGt6VTZrZ09yZ2NwMXBBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiM2EyYzYyZGItNTMxOC00MjBkLThkNzQtMjNhZmZlZTVkOWQ1IiwiNjJlOTAzOTQtNjlmNS00MjM3LTkxOTAtMDEyMTc3MTQ1ZTEwIiwiYjc5ZmJmNGQtM2VmOS00Njg5LTgxNDMtNzZiMTk0ZTg1NTA5Il19.Dk-agXqrtxgwsSEyeQtiiRbQLN3WEF38HXhqt7MoZ5t9pvJt8KKp6kgSx0JA-Bl_lEci82qUHN7r_pzRoPRgrQaiMIW2LdxV6bip6eoiVdAc0l5RR3vQM-zrixSNZ6I8Fjf5YX1CRljuYO2XmFHseqD1JIqK_M-xAHm8EUwi4FftzCZthYtESxFR70A7vQEam2NXQaWcI8CQ8tAJ6X_nXQizcGmDAsX4H3PeIFdZhwtfB-xX5Zbq4Oaypr--Kwp9z74H1wcqCs99vQCbwytTVp5QCujB3MMVYOPkT_7bH6qqlYpD7ce9eEWWOqGygvY1AePlSeafzKov_gllYLT_Mg',
            #     'valid_until': 1618981975,
            #     'current_refresh_token': '0.AXMAFhqs67-Bm0SNQ1cyw8HZmVTDk5AKY_FHsIdnaOuUJ-ZzAHA.AgABAAAAAAD--DLA3VO7QrddgJg7WevrAgDs_wQA9P-x217XtA0x0zKDcRf5nhhDxLArgRFuZ6kFeKGvyLJnv0r0DC7qm3d1xnSvUtMUgq6XrLsKq7HvHMxdojE5ZyL_U1_xn-lihq6e1pKEp2bgPbxL4PhLOvZfa-W25B8YH7GZS4t71WBT_xehzfI2rdAAiwNDCYGPlrfLXlaXKpzKC0e7kK24v6bEtUDMiqNPcxYMQL4RXsePdNBgqd4K1-dNFgoKGAc-kXiOGJT4UdB4GWQQrGNqtLr5tvOCdoj60--FAJ1lFx8UquhE80uM6cqT13yJOKbzjaI9V4iAmo_E0Ovko6_-AlvyvIqgfzf0gSp4NyIyhpU4JCTwEA9D1-tV8SZmdLX0h_OG4I4FwLb3-pKCqJirq48KlxfB9P68rCmfPETlAhih_419ik3fFh9ItOTQ-uC1oDsP-uLr2CP-aG5YlRuTyuR03O8cPxm7NGLRNRtrkf9jaq-AgouJ_hpa1XQ86AifzEJz2sbRW-d9m0d-cOg7F-41ijV5rngPFSH1LhYGGRq5tJECsaJUsFgearrAw2S41uWAGQlowfIMMQuR4tmk7iPj_yShBLlE67vHXdnglyDYSa0EgzTyEchltaMnKIiEQsaehkQMeHkKwO9tT9cz-emqTcBy_wW3XxSsnWVZG9-HYwYodRypUd-U6eNUsfLbMtwBfbQHQu2HX-rA78CL-OvhPcNsAQbKD6QyGktYm8LfEHaTIJzJtLONoN1qBSf6GV9VxGuLv0-Ql1w2eWpXkCYdkip78HO9MGjWk0zuJwdRp9-I9keboDubqaQEwZHqWZswk-GKnyWdbhof-VyZLEslRFnkJNxxezAzGG-kg6TfnEawXI4zj2x7ANNHyZ1sDfZhWyJyVKE1cRPUAMb7ODh9zG2_3DaQIv-oNZV5unipir9duX-YUI5w01DelE7oYRUM3doVlv6UH7JqslKJK5Mc'}
            # set_integration_context(context)
            # Debugging

            return_results(microsoft_365_defender_incidents_list_command(client, args))

        elif command == 'microsoft-365-defender-incident-update':
            return_results(microsoft_365_defender_incident_update_command(client, args))

        elif command == 'microsoft-365-defender-advanced-hunting':
            results = microsoft_365_defender_advanced_hunting_command(client, args)
            return_results(results)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


from MicrosoftApiModule import *  # noqa: E402

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
