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
START_DATE = "2018-10-24T14:13:20+00:00"
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
    def incidents_list(self, limit: int = MAX_ENTRIES, status: Optional[str] = None, assigned_to: Optional[str] = None,
                       timeout: int = TIMEOUT, from_date: Optional[datetime] = None) -> Dict:
        """
        GET request from the client using OData operators:
            - $top: how many incidents to receive, maximum value is 100
            - $filter: OData query to filter the the list on the properties:
                                                                lastUpdateTime, createdTime, status, and assignedTo
            - '$orderby': order the result in asc or desc order
        Args:
            limit: how many incidents to receive, maximum value is 100
            status: filter list to contain only incidents with the given status (Active, Resolved or Redirected)
            assigned_to: Owner of the incident, or None if no owner is assigned.
            timeout: The amount of time (in seconds) that a request will wait for a client to
                establish a connection to a remote machine before a timeout occurs.
            from_date: get incident with creation date more recent than from_date


        Returns: request results as dict:
                    { '@odata.context',
                      'value': list of incidents,
                      '@odata.nextLink'
                    }

        """
        params = {'$top': limit}

        filter_query = ''
        if status:
            filter_query += 'status eq ' + status

        if assigned_to:
            filter_query += ' and ' if filter_query else ''
            filter_query += 'assignedTo eq ' + assigned_to

        # fetch incidents
        if from_date:
            filter_query += ' and ' if filter_query else ''
            filter_query += f"createdTime gt {from_date}"

        if filter_query:
            params['$filter'] = filter_query
        return self.ms_client.http_request(method='GET', url_suffix='api/incidents', timeout=timeout,
                                           params=params)

    # def list_incidents_request(self, from_epoch: str, to_epoch: str, incident_status: str, max_incidents: str = '50') \
    #         -> Dict:
    #     """List all incidents by sending a GET request.
    #
    #     Args:
    #         from_epoch: from time in epoch
    #         to_epoch: to time in epoch
    #         incident_status: incident status e.g:closed, opened
    #         max_incidents: max incidents to get
    #
    #     Returns:
    #         Response from API.
    #     """
    #     params = {
    #         'type': 'list',
    #         'from': from_epoch,
    #         'to': to_epoch,
    #         'rangeType': incident_status,
    #         'max': max_incidents,
    #         'order': 'asc',
    #     }
    #     incidents = self.http_request('GET', '/incident/get', headers={'token': self._token}, params=params)
    #     return incidents.get('result').get('data')

    @logger
    def update_incident(self, incident_id: int, status: Optional[str], assigned_to: Optional[str],
                        classification: Optional[str],
                        determination: Optional[str], tags: Optional[List[str]]) -> Dict:
        """
        PATCH request to update single incident.
        Args:
            incident_id: incident's id
            status - Specifies the current status of the alert. Possible values are: (Active, Resolved or Redirected)
            assigned_to - Owner of the incident.
            classification - Specification of the alert. Possible values are: Unknown, FalsePositive, TruePositive.
            determination -  Specifies the determination of the alert. Possible values are: NotAvailable, Apt,
                                 Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other.
            tags - Custom tags associated with an incident. Separated by commas without spaces (CSV)
                 for example: tag1,tag2,tag3.
        Returns:

        """
        body = assign_params(status=status, assignedTo=assigned_to, classification=classification,
                             determination=determination, tags=tags)
        updated_incident = self.ms_client.http_request(method='PATCH', url_suffix=f'api/incidents/{incident_id}',
                                                       json_data=body)
        return updated_incident

    @logger
    def advanced_hunting(self, query: str, timeout: int = TIMEOUT):
        """
        POST request to the advanced hunting API:
        Args:
            query: query advanced hunting query language
            timeout: The amount of time (in seconds) that a request will wait for a client to
                     establish a connection to a remote machine before a timeout occurs.

        Returns:
            The response object contains three top-level properties:

                Stats - A dictionary of query performance statistics.
                Schema - The schema of the response, a list of Name-Type pairs for each column.
                Results - A list of advanced hunting events.
        """
        return self.ms_client.http_request(method='POST', url_suffix='api/advancedhunting/run',
                                           json_data={"Query": query}, timeout=timeout)


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

    Returns: new dictionary with keys mapping.

    """
    if not raw_incident:
        raw_incident = {}
    alerts_list = raw_incident.get('alerts', [])

    alerts_status = [alert.get('status') for alert in alerts_list]
    return {
        'Incident name': raw_incident.get('incidentName'),
        'Tags': ', '.join(raw_incident.get('tags', [])),
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

    response = client.incidents_list(limit=limit, status=status, assigned_to=assigned_to)
    raw_incidents = response.get('value')
    readable_incidents = [convert_incident_to_readable(incident) for incident in raw_incidents]
    # the table headers are the incident keys. creates dummy incident to manage a situation of empty list.
    headers = list(convert_incident_to_readable({}).keys())
    human_readable_table = tableToMarkdown(name="Incidents:", t=readable_incidents, headers=headers)

    return CommandResults(outputs_prefix='Microsoft365Defender.Incident', outputs_key_field='incidentId',
                          outputs=raw_incidents, readable_output=human_readable_table)


@logger
def microsoft_365_defender_incident_update_command(client: Client, args: Dict) -> CommandResults:
    """
    Update an incident.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        args(Dict): Demisto arguments:
              - id - incident's id (required)
              - status - Specifies the current status of the alert. Possible values are: (Active, Resolved or Redirected)
              - assigned_to - Owner of the incident.
              - classification - Specification of the alert. Possible values are: Unknown, FalsePositive, TruePositive.
              - determination -  Specifies the determination of the alert. Possible values are: NotAvailable, Apt,
                                 Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other.
              - tags - Custom tags associated with an incident. Separated by commas without spaces (CSV)
                       for example: tag1,tag2,tag3.

    Returns: CommandResults
    """
    raw_tags = args.get('tags')
    tags = raw_tags.split(',') if raw_tags else None

    status = args.get('status')
    assigned_to = args.get('assigned_to')
    classification = args.get('classification')
    determination = args.get('determination')
    incident_id = arg_to_number(args.get('id'))

    updated_incident = client.update_incident(incident_id=incident_id, status=status, assigned_to=assigned_to,
                                              classification=classification,
                                              determination=determination, tags=tags)
    readable_incident = convert_incident_to_readable(updated_incident)
    human_readable_table = tableToMarkdown(name=f"Updated incident No. {incident_id}:", t=readable_incident,
                                           headers=list(readable_incident.keys()))

    return CommandResults(outputs_prefix='Microsoft365Defender.Incident', outputs_key_field='incidentId',
                          outputs=updated_incident,
                          readable_output=human_readable_table)


@logger
def fetch_incidents(client: Client, first_fetch_time: str, fetch_limit: int) -> List[Dict]:
    """
    Uses to fetch incidents into Demisto
    Documentation: https://xsoar.pan.dev/docs/integrations/fetching-incidents#the-fetch-incidents-command

    Args:
    TODO

    Returns:
        incidents, new last_run
    """
    last_run = demisto.getLastRun().get('last_run')

    if not last_run:  # this is the first run
        last_run = dateparser.parse(first_fetch_time)
    else:
        last_run = dateparser.parse(last_run)
    # todo time zone
    incidents = list()

    raw_incidents = client.incidents_list(from_date=last_run.strftime(DATE_FORMAT), limit=fetch_limit)
    for incident in raw_incidents:
        created_time = dateparser.parse(incident.get('createdTime'))
        demisto_incident = {
            "name": f"Microsoft 365 Defender {incident.get('incidentId')}",
            "occurred": created_time.strftime(DATE_FORMAT),
            "rawJSON": json.dumps(incident)
        }

        incidents.append(demisto_incident)
        last_run = created_time

    demisto.setLastRun({'last_run': last_run.strftime(DATE_FORMAT)})
    return incidents


@logger
def microsoft_365_defender_advanced_hunting_command(client: Client, args: Dict) -> CommandResults:
    """
    Sends a query for the advanced hunting tool.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        args(Dict): Demisto arguments:
              - query - The query to run (required)

    Returns:

    """
    query = args.get('query')
    response = client.advanced_hunting(query)
    results = response.get('Results')
    results_element = results[0] if results else {}  # returns {} if the list is empty other wise the first elemnt
    human_readable_table = tableToMarkdown(name=f" Result of query: {query}:", t=results,
                                           headers=list(results_element.keys()))
    # todo ask if the prefix is fine
    return CommandResults(outputs_prefix='Microsoft365Defender.Hunt', outputs_key_field='',
                          outputs=response,
                          readable_output=human_readable_table)


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
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()
    fetch_limit = demisto.params().get('fetch_limit', 10)
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
            # todo ask roy
            return_results(test_connection(client))

        elif command == 'microsoft-365-defender-auth-start':
            return_results(start_auth(client))

        elif command == 'microsoft-365-defender-auth-complete':
            return_results(complete_auth(client))

        elif command == 'microsoft-365-defender-auth-reset':
            return_results(reset_auth())

        elif command == 'microsoft-365-defender-auth-test':
            return_results(test_connection(client))

        elif command == 'microsoft-365-defender-incidents-list':
            return_results(microsoft_365_defender_incidents_list_command(client, args))

        elif command == 'microsoft-365-defender-incident-update':
            return_results(microsoft_365_defender_incident_update_command(client, args))

        elif command == 'microsoft-365-defender-advanced-hunting':
            return_results(microsoft_365_defender_advanced_hunting_command(client, args))

        elif command == 'fetch-incidents':
            # todo add auth-test check?
            # todo add fetch limit arg
            # start_auth(client)
            # complete_auth(client)
            context = {'device_code': 'CAQABAAEAAAD--DLA3VO7QrddgJg7WevrFaANEQkqpZkGX8IZhLMLMWTfYfWRvhywWU3sH_Qlo__QA0vKoBT63dBrSVVRLmjDRGAtHFHlWcDgmO3-tXUob5PRmsEfZ4Qx7yAYzBAi7Ig3-A1uZP2iCRrAHk1QP6jQGd8-3f77peeSB8tz1pwuhK6U8w7DMS5I97lqQkdWknUgAA', 'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im5PbzNaRHJPRFhFSzFqS1doWHNsSFJfS1hFZyIsImtpZCI6Im5PbzNaRHJPRFhFSzFqS1doWHNsSFJfS1hFZyJ9.eyJhdWQiOiJodHRwczovL3NlY3VyaXR5Lm1pY3Jvc29mdC5jb20vbXRwIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZWJhYzFhMTYtODFiZi00NDliLThkNDMtNTczMmMzYzFkOTk5LyIsImlhdCI6MTYxOTA5NDIwNiwibmJmIjoxNjE5MDk0MjA2LCJleHAiOjE2MTkwOTgxMDYsImFjciI6IjEiLCJhaW8iOiJBVFFBeS84VEFBQUFyVmNvS1kraVFoQWZIenFVTDV5cFBMcGZYQXJubnMvYzFsZFJMOFlpZDB1VDN4WGt0L1o4TTRwLzdTdGRiOWs5IiwiYW1yIjpbInB3ZCJdLCJhcHBpZCI6IjkwOTNjMzU0LTYzMGEtNDdmMS1iMDg3LTY3NjhlYjk0MjdlNiIsImFwcGlkYWNyIjoiMCIsImZhbWlseV9uYW1lIjoiQnJhbmRlaXMiLCJnaXZlbl9uYW1lIjoiQXZpc2hhaSIsImlwYWRkciI6IjMxLjE1NC4xNjYuMTQ4IiwibmFtZSI6IkF2aXNoYWkgQnJhbmRlaXMiLCJvaWQiOiIzZmE5ZjI4Yi1lYjBlLTQ2M2EtYmE3Yi04MDg5ZmU5OTkxZTIiLCJwdWlkIjoiMTAwMzAwMDA5QUJDMjg3OCIsInJoIjoiMC5BWE1BRmhxczY3LUJtMFNOUTFjeXc4SFptVlREazVBS1lfRkhzSWRuYU91VUotWnpBSEEuIiwic2NwIjoiQWR2YW5jZWRIdW50aW5nLlJlYWQgSW5jaWRlbnQuUmVhZFdyaXRlIiwic3ViIjoiZWpRcDJqVlVualg3S2FSdWpsVWZrWTdCYlRycmNPUjktYVpJWE9kM0RlMCIsInRlbmFudF9yZWdpb25fc2NvcGUiOiJFVSIsInRpZCI6ImViYWMxYTE2LTgxYmYtNDQ5Yi04ZDQzLTU3MzJjM2MxZDk5OSIsInVuaXF1ZV9uYW1lIjoiYXZpc2hhaUBkZW1pc3RvZGV2Lm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6ImF2aXNoYWlAZGVtaXN0b2Rldi5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiIzdm80TXVIRTAwQy16QnE3bTM0YkFBIiwidmVyIjoiMS4wIiwid2lkcyI6WyIzYTJjNjJkYi01MzE4LTQyMGQtOGQ3NC0yM2FmZmVlNWQ5ZDUiLCI2MmU5MDM5NC02OWY1LTQyMzctOTE5MC0wMTIxNzcxNDVlMTAiLCJiNzlmYmY0ZC0zZWY5LTQ2ODktODE0My03NmIxOTRlODU1MDkiXX0.Xot3PplUU2rednMM1IC5tAXt5JicXg9S9w6ZNOvlv7XP0ERV0CA8VzOyd6xGbQuI7_Siu3vJJrcbVjHK09-KFId2qNo8-2_2sS0yr5q2WGQgTI4WPb_tTY0Oglmd1r3OavDgVIQ_N-8pghGjDogkEXNpzuuCgPDxiCcFc_6Y0VwyQLd9VMwasEYyIQLBwPdHg4MZDF60WhvyCPbPAqqeGzDF1DupZeZlBIApA0JdPzCDc3_sEr94RGWNEz5pc-tgl5OYTCADjkerhhHHVqhzJ-l5MOzXuJLM2hKt6N-x-_ni0X-DFa274iWSm89hUdhd7ONc0kEkMaZpENPNiwtCfw', 'valid_until': 1619098100, 'current_refresh_token': '0.AXMAFhqs67-Bm0SNQ1cyw8HZmVTDk5AKY_FHsIdnaOuUJ-ZzAHA.AgABAAAAAAD--DLA3VO7QrddgJg7WevrAgDs_wQA9P-5AmwwN_zlezd--pFRut9nCgnAzGHoD51E07kN3nf_WPzUyNX6xnivJf0X-9ny9D74qDFlmBHlpeHwlDRUufY5NcWR_5QJZ2TLAVHJ4JxyKZnhut2IshMS3yuwRxx3eUUbGaJwUrzKLVdL0PInULJrmSjVGciecKHxsLyxYNLGab_VJcK--B_qUXI6OjluGHVlGSmeaOwgh9aWMvVbnFFverAdg0cZXfJ1xM1Ae6rnrd_auaJgoovh1tl_Oqb9zba7WGyCENP-OKaVVp7UoyahGN523ZFBiZZcWizorO2lSSNM1hlr4MKEnwlWhjfFvlAGEP-nNS71dxJXAbApPtpSjPw5ppoGV91CBgp7TP8YbSuijWJhrbjCOGOZs3A62wz1kWBDa4Az-nIQ_wfBli86EYmGqu0Pr7tnvjn5Jpzg0f7GAYOLXExprqsXDwuAwt4XiJgF3YKW-IYZ7RpSLN4aViSpH5lqrzv5tEPgGlkxyWpslejiv-nxqWDoUTzWSSHTIe4MVRFonxwVb2fgdd7tOns2jhT2_7x2mIxv_6FV7XvN9925T22P93g4CbDqg8NFymk1r8fQAS-IQK9yyCg5xuwlgsXBwMd9-ow8K9IXK6oxwVHXHIESPPnJFkG4fKaEkbilpYf0Q9XaUDd6pjl_3z13q7euJ-zhG34S5a6pnwiOxSiv4Uouvzoa14aV5MVlCEkGu2I8aGKs9mGr6HwPmUenL-gpPV-LIXpEYOphc1CzusP64eZXkAt1r4zn69OLPXomud7FhQKFRX1erAvGefBojhHSG1znfYGWQ-siBbdaCeMwCcqSutJga87AFsNKyysOr7I5q0ZmXNvjKTPzFvL-63YASQHhOF5rS3Uy4wWkZIdgMZhW74PD-kKWCmT1lUaTFBo9gTmHdP4qQ5XT8U3cRl7MuEjADLiBoDIZwEvUw2Pj6oI'}
            set_integration_context(context)
            incidents = fetch_incidents(client, first_fetch_time, fetch_limit)
            demisto.incidents(incidents)


    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


from MicrosoftApiModule import *  # noqa: E402

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
