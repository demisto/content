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
            'verify': verify,
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
        # todo cant use assign params because the key starts with $
        # todo is it required to write test for this function? if so how?
        params = {'$top': limit}
        if status:
            params['$filter'] = 'status eq ' + status

        if assigned_to:
            params['$filter'] += 'and' if status else ''
            params['$filter'] += 'assignedTo eq ' + assigned_to

        response = self.ms_client.http_request(method='GET', url_suffix='api/incidents', timeout=timeout,
                                               params=params)
        return response.get('value')


# todo ask roy why not put this in client
@logger
def start_auth(client: Client) -> CommandResults:
    result = client.ms_client.start_auth('!ms-365-defender-auth-complete')
    return CommandResults(readable_output=result)


# todo ask roy is it not better for the client to just do this for every command he calls?
@logger
def complete_auth(client: Client) -> CommandResults:
    client.ms_client.get_access_token()
    return CommandResults(readable_output='✅ Authorization completed successfully.')


@logger
def reset_auth() -> CommandResults:
    set_integration_context({})
    return CommandResults(readable_output='Authorization was reset successfully. You can now run '
                                          '**!ms-365-defender-auth-start** and **!ms-365-defender-auth-complete**.')


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

        test_connection()

        message = 'ok'

    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return message


def convert_incident(raw_incident: Dict) -> Dict:
    """
    Converts incident received from microsoft 365 defender to local incident
    Args:
        raw_incident: The incident as recieved from microsoft 365 defender

    Returns: new dictionary with new mapping.

    """
    if not raw_incident:
        raw_incident = {}

    return {
        'ID': raw_incident.get('incidentId'),
        'Display Name': raw_incident.get('incidentName'),
        'Assigned User': raw_incident.get('assignedTo'),
        'Classification': raw_incident.get('classification'),
        'Event Type': raw_incident.get('determination'),
        'Occurred': raw_incident.get('createdTime'),
        'Updated': raw_incident.get('lastUpdateTime'),
        'Status': raw_incident.get('status'),
        'Severity': raw_incident.get('severity'),
        'Tags': raw_incident.get('tags'),
        'RawJSON': json.dumps(raw_incident)
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
    # todo help building test functions
    limit = arg_to_number(args.get('limit', MAX_ENTRIES), arg_name='limit', required=True)
    status = args.get('status')
    assigned_to = args.get('assigned_to')

    raw_incidents = client.incidents_list(limit=limit, status=status, assigned_to=assigned_to)

    incidents = [convert_incident(incident) for incident in raw_incidents]

    headers = ['ID', 'Display Name', 'Assigned User', 'Classification', 'Event Type', 'Occurred', 'Updated', 'Status',
               'Severity', 'Tags']
    human_readable = tableToMarkdown(name="Incidents:", t=incidents, headers=headers)
    return CommandResults(readable_output=human_readable, raw_response=incidents)


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
            return_results(client.start_auth())

        elif command == 'microsoft-365-defender-auth-complete':
            return_results(client.complete_auth())

        elif command == 'microsoft-365-defender-auth-reset':
            return_results(client.reset_auth())

        elif command == 'microsoft-365-defender-auth-test':
            return_results(client.test_connection())

        elif command == 'microsoft-365-defender-incidents-list':

            # Debugging
            # client.start_auth()
            # client.complete_auth()
            # context = {
            #     'device_code': 'CAQABAAEAAAD--DLA3VO7QrddgJg7Wevr_SR05SpbKXTXINGcnJjWk_Y7zP837_Yv855tH4Ys24IvRE6VJZIun-1lgfMpSRAw-H0uaSwHLXHT4VloTSG4niC2KHLL_vUHctz7QGzo-fO0I0kh351-3lF6TLg35ve06obpSMY6ppvRSpueM0Q0p33R2CDGWk6ON9gcCRixUcIgAA',
            #     'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im5PbzNaRHJPRFhFSzFqS1doWHNsSFJfS1hFZyIsImtpZCI6Im5PbzNaRHJPRFhFSzFqS1doWHNsSFJfS1hFZyJ9.eyJhdWQiOiJodHRwczovL3NlY3VyaXR5Lm1pY3Jvc29mdC5jb20vbXRwIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZWJhYzFhMTYtODFiZi00NDliLThkNDMtNTczMmMzYzFkOTk5LyIsImlhdCI6MTYxODgzMTU2NywibmJmIjoxNjE4ODMxNTY3LCJleHAiOjE2MTg4MzU0NjcsImFjciI6IjEiLCJhaW8iOiJBVFFBeS84VEFBQUFFTHpDOVZHUnd0dEg4aWZ2MnFlWmlOejgyUGJPSExmTHdWbE9TaUpHSTg5S0ROSlRSbmcrTzdCTU9WR2JGNzhNIiwiYW1yIjpbInB3ZCJdLCJhcHBpZCI6IjkwOTNjMzU0LTYzMGEtNDdmMS1iMDg3LTY3NjhlYjk0MjdlNiIsImFwcGlkYWNyIjoiMCIsImZhbWlseV9uYW1lIjoiQnJhbmRlaXMiLCJnaXZlbl9uYW1lIjoiQXZpc2hhaSIsImlwYWRkciI6IjMxLjE1NC4xNjYuMTQ4IiwibmFtZSI6IkF2aXNoYWkgQnJhbmRlaXMiLCJvaWQiOiIzZmE5ZjI4Yi1lYjBlLTQ2M2EtYmE3Yi04MDg5ZmU5OTkxZTIiLCJwdWlkIjoiMTAwMzAwMDA5QUJDMjg3OCIsInJoIjoiMC5BWE1BRmhxczY3LUJtMFNOUTFjeXc4SFptVlREazVBS1lfRkhzSWRuYU91VUotWnpBSEEuIiwic2NwIjoiQWR2YW5jZWRIdW50aW5nLlJlYWQgSW5jaWRlbnQuUmVhZFdyaXRlIiwic3ViIjoiZWpRcDJqVlVualg3S2FSdWpsVWZrWTdCYlRycmNPUjktYVpJWE9kM0RlMCIsInRlbmFudF9yZWdpb25fc2NvcGUiOiJFVSIsInRpZCI6ImViYWMxYTE2LTgxYmYtNDQ5Yi04ZDQzLTU3MzJjM2MxZDk5OSIsInVuaXF1ZV9uYW1lIjoiYXZpc2hhaUBkZW1pc3RvZGV2Lm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6ImF2aXNoYWlAZGVtaXN0b2Rldi5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiJkazVsNk9idlhVZXpHaElvWjBFM0FBIiwidmVyIjoiMS4wIiwid2lkcyI6WyIzYTJjNjJkYi01MzE4LTQyMGQtOGQ3NC0yM2FmZmVlNWQ5ZDUiLCI2MmU5MDM5NC02OWY1LTQyMzctOTE5MC0wMTIxNzcxNDVlMTAiLCJiNzlmYmY0ZC0zZWY5LTQ2ODktODE0My03NmIxOTRlODU1MDkiXX0.duqu6Ut-JRhmDMRGN7rUiuDP4Tk9pn1Ir8Kt3CYzjhtNKZMHTkJVn7mtlyUsg_pcDtnA97sCtTb0QYOdTMjnnG9ZEt51J0eSeIa-brVzmRV8DthwPnjQ4usdaa3A3v7bXuvltGuE0YmOYZcVbAFq21JokMXLdrcNJV9ZZAhth8FPKbrxTDxjdpcgyTzS7tGR2_O1Puk4atb2wRhwSR7GTVdzWxl4PEW5p9vfTl3OFVcHNhDCzPs9vqT5C_mmzjyJEXER8LBSHx3XDFMHRYzFr4InHVYJmxgc-XNMpxQP4hI29i0bkVbHHXVodCC0lUtDsg_NcL3nlQfJvYqizhmDwg',
            #     'valid_until': 1618835461,
            #     'current_refresh_token': '0.AXMAFhqs67-Bm0SNQ1cyw8HZmVTDk5AKY_FHsIdnaOuUJ-ZzAHA.AgABAAAAAAD--DLA3VO7QrddgJg7WevrAgDs_wQA9P9CBGSsfUPHOrDdp2MEEJjTaaMiTP75WHk825iNRWT9uKUeUNxYlo8vRqaJvWioBQOXf4AI0oh-3QIGGVZYn0y3XNxIlfRQOmJ56CuhmkyqJlmQz6BQukO5_smqV9E4sCed5IzBkZmahq2gw5EFC7icgDf_sCB-GwFbP3AxlUturk9dMwp8s96XuEUii1VDzXCU6ryuisHGAobRmHKDOeEQdsguPc_dYpukC6MAINK-Q89eK5plC1P7qYOzr2rQsGDGlAfze1LjN63TXdduN5Shkk0M4yU5BUnvmJX1NbHPJT5H4qJeqUYT4jS73fJzPWIPYYaCd-XlpA9IdYA7iy33vLnvNqIAHRqJxiVr6VKn__PzONbbxP5VyGYyHVDG1cG6V8kqaYp6FEj-CtlKW5m3qODA2PItLEvPCmxnypFkJccsG37voO7HOARWilcRyFOwASCIEm-anXzcWZJH4oUKahb-vic4EggA23-YNx2eGecesZ7IJKyJn3HTTkGn9vQ_IcbyFU-C87skEKTjbE0nxLlZaj7YMvOH7bc1jwlqmbzN6IaJtDNU5uidAIMPJNlmVVaw2DgQq2ahcdmHuJaxnJ6qxrMlnVQ8K_xrfH9QuhO6llP2MFyP_XDpf_zw3IJ5qeJl65wMnTBUAyy6RInwZ0Dafj3hkArKsvlutGZaQlzTKm7t6FmZlaN2w77EyeTXfeQWkmvm9G71lGOSZIWCHJhchup5KdMKjfjb8tP32AagMyovx3V0kXdw6kliwW5Jpov8idSuHmALxS0ZNkac-cVu-g0_x_C7Gfii5NwW6aKfd4mfASNiHgR5QqDzLLzzjs1A6Q4sv0IDQlB0yEU2HrBWM-9rTYxn_EbB-0thbUTLce23PjL8ctGeRzLfJngTN1auWNl1UK6oS98goqz1SpbjlzH_o_pcyFZdNfL6U-eHlq1nUiY'}
            # set_integration_context(context)
            # Debugging

            results = microsoft_365_defender_incidents_list_command(client, args)
            return_results(results)

        elif command == 'microsoft-365-defender-incident-update':
            results = microsoft_365_defender_incident_update_command(client, args)
            return_results(results)

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
