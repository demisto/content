import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import urllib3
import dateparser

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

PARAMS: dict = demisto.params()
API_MAX_FETCH = 100_000
DEFAULT_REGION_ARG = {'region': PARAMS['region']}

TAKEDOWN_CLOSE_ON_STATUSES = {
    'resolved', 'stale', 'invalid'
}
SERVICE_TO_URL_MAP = {
    'takedown': PARAMS['takedown_url'],
    'submission': PARAMS['submission_url'],
}
MIRROR_DIRECTION_DICT = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}

''' CLIENT CLASS '''


class Client(BaseClient):
    def _http_request(self, method, service, url_suffix='', headers=None, json_data=None, **kwargs):
        remove_nulls_from_dictionary(headers or {})
        remove_nulls_from_dictionary(json_data or {})
        return super()._http_request(
            method, full_url=urljoin(PARAMS[service], url_suffix),
            headers=headers, json_data=json_data, **kwargs)

    def test_module(self):
        return 'ok'

    def get_takedowns(self, headers: dict) -> list[dict]:
        '''Used by fetch-incidents and incoming mirroring commands'''
        return self._http_request(
            'GET', 'takedown', 'attacks/', headers
        )

    def update_remote_system(self, headers: dict) -> Any:
        return self._http_request(
            'GET', 'takedown', 'attacks/', headers
        )


''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    '''
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    '''

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error
    try:
        if PARAMS.get('isFetch'):  # Tests fetch incident:
            if not dateparser.parse(PARAMS['first_fetch']):
                raise ValueError(f'{PARAMS["first_fetch"]!r} is not a valid time.')
            else:
                return 'ok'

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def fetch_incidents(client: Client) -> list[dict[str, str]]:  # LIVE TESTS NEEDED
    # demisto.getLastRun and demisto.setLastRun hold takedown IDs
    def to_xsoar_incident(incident: dict) -> dict:
        return {
            'name': f'Submission ID: {incident["id"]!r}',
            'occurred': arg_to_datetime(incident['date_submitted']).isoformat(),
            'dbotMirrorId': incident['id'],
            'rawJSON': json.dumps(
                incident | {
                    'mirror_direction': MIRROR_DIRECTION_DICT[PARAMS.get('mirror_direction')],
                    'mirror_instance': demisto.integrationInstance()
                }),
        }

    headers = {
        'max_results': min(
            arg_to_number(PARAMS['max_fetch']) or 10,
            API_MAX_FETCH
        ),
        'sort': 'id',
    }

    if last_id := demisto.getLastRun():
        headers['id_after'] = last_id
    else:
        headers['date_from'] = str(
            arg_to_datetime(
                PARAMS['first_fetch'],
                required=True
            ).replace(tzinfo=None))

    incidents = client.get_takedowns(headers) or []

    if incidents:
        demisto.setLastRun(incidents[-1]['id'])

        # the first incident from the API call should be a duplicate of last_id
        if incidents[0]['id'] == last_id:
            incidents.pop(0)

    return list(map(to_xsoar_incident, incidents))


def get_modified_remote_data(client: Client, args: dict) -> GetModifiedRemoteDataResponse:
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = dateparser.parse(remote_args.last_update)
    incidents = client.get_takedowns({
        'updated_since': last_update,
    })
    return GetModifiedRemoteDataResponse(incidents)


# def get_modified_remote_data(client: Client, args: dict) -> GetModifiedRemoteDataResponse:
#     remote_args = GetModifiedRemoteDataArgs(args)
#     last_update = dateparser.parse(remote_args.last_update)
#     raw_incidents = client.get_takedowns({
#         'updated_since': last_update,
#         'response_include': 'id'
#     })
#     ids = [inc['id'] for inc in raw_incidents]
#     return GetModifiedRemoteDataResponse(ids)


# def get_remote_data(client: Client, args: dict) -> GetRemoteDataResponse:
#     remote_args = GetRemoteDataArgs(args)
#     incident = client.get_takedowns({
#         'id': remote_args.remote_incident_id,
#     })[0]
#     return GetRemoteDataResponse(incident, {})


def update_remote_system(client: Client, args: dict) -> Any:
    """update-remote-system command: pushes local changes to the remote system

    :type client: ``Client``
    :param client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id

    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely

    :rtype: ``str``
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    if parsed_args.delta:
        demisto.debug(f'Got the following delta keys {list(parsed_args.delta)}')

    demisto.debug(f'Sending incident with remote ID [{parsed_args.remote_incident_id}] to remote system\n')
    new_incident_id: str = parsed_args.remote_incident_id
    updated_incident = {}
    if not parsed_args.remote_incident_id or parsed_args.incident_changed:
        if parsed_args.remote_incident_id:
            # First, get the incident as we need the version
            old_incident = client.get_incident(incident_id=parsed_args.remote_incident_id)
            for changed_key in parsed_args.delta.keys():
                old_incident[changed_key] = parsed_args.delta[changed_key]  # type: ignore

            parsed_args.data = old_incident

        else:
            parsed_args.data['createInvestigation'] = True

        updated_incident = client.update_incident(incident=parsed_args.data)
        new_incident_id = updated_incident['id']
        demisto.debug(f'Got back ID [{new_incident_id}]')

    else:
        demisto.debug(f'Skipping updating remote incident fields [{parsed_args.remote_incident_id}] as it is '
                      f'not new nor changed.')

    if parsed_args.entries:
        for entry in parsed_args.entries:
            demisto.debug(f'Sending entry {entry.get("id")}')
            client.add_incident_entry(incident_id=new_incident_id, entry=entry)

    # Close incident if relevant
    if updated_incident and parsed_args.inc_status == IncidentStatus.DONE:
        demisto.debug(f'Closing remote incident {new_incident_id}')
        client.close_incident(
            new_incident_id,
            updated_incident.get('version'),  # type: ignore
            parsed_args.data.get('closeReason'),
            parsed_args.data.get('closeNotes')
        )

    return new_incident_id
    


''' MAIN FUNCTION '''


def main() -> None:

    args = demisto.args()
    command = demisto.command()

    client = Client(
        ...
    )

    demisto.debug(f'Command being called is {command}')
    try:

        match command:
            case 'test-module':
                return_results(test_module(client))
            case 'fetch-incidents':
                demisto.incidents(fetch_incidents(client))
            case 'get-modified-remote-data':
                return_results(get_modified_remote_data(client, args))
            # case 'get-remote-data':
            #     return_results(get_remote_data(client, args))
            # case 'update-remote-system':
            #     return_results(update_remote_system(client, args))

            case _:
                raise NotImplementedError(f'{command!r} is not a Netcraft command.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
