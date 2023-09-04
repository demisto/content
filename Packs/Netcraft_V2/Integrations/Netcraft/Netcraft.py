import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections.abc import Iterable


''' CONSTANTS '''

PARAMS: dict = demisto.params()
API_MAX_FETCH = 100_000
DEFAULT_REGION_ARG = {
    'region': PARAMS['region']
}
AUTH_HEADERS = {
    'Authorization': f'Bearer {PARAMS["credentials"]["password"]}'
}

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
RES_CODE_TO_MESSAGE = {
    'TD_OK': 'The attack was submitted to Netcraft successfully.',
    'TD_EXISTS': 'The attack was not submitted to Netcraft because it already exists in the system.',
    'TD_WILDCARD': 'The attack was not submitted because it is a wildcard sub-domain variation of an existing takedown.',
    'TD_VERIFY':
        'The submitted content is undergoing additional verification to ensure that it is a valid takedown target.'
        ' If verification is successful, a new takedown will be submitted. If not, no takedown will be created.',
}

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, verify, proxy, ok_codes, headers, **kwargs):
        super().__init__(None, verify, proxy, ok_codes, headers, **kwargs)

    def _http_request(self, method, service, url_suffix='', params=None, json_data=None, resp_type='json', **kwargs):
        remove_nulls_from_dictionary(params or {})
        remove_nulls_from_dictionary(json_data or {})
        return super()._http_request(
            method, full_url=urljoin(SERVICE_TO_URL_MAP[service], url_suffix),
            params=params, json_data=json_data, resp_type=resp_type, **kwargs)

    def test_module(self):
        ...

    def get_takedowns(self, params: dict) -> list[dict]:
        '''Used by fetch-incidents and incoming mirroring commands'''
        return self._http_request(
            'GET', 'takedown', 'attacks/', params
        )

    def update_remote_system(self, params: dict) -> Any:
        return self._http_request(
            'GET', 'takedown', 'attacks/', params
        )

    def attack_report(self, body: dict) -> str:
        return self._http_request(
            'POST', 'takedown',
            json_data=body, resp_type='text'
        )

    def takedown_list(self, params: dict) -> Any:
        ...

    def takedown_update(self, params: dict) -> Any:
        ...

    def takedown_escalate(self, params: dict) -> Any:
        ...

    def takedown_note_create(self, params: dict) -> Any:
        ...

    def takedown_note_list(self, params: dict) -> Any:
        ...

    def attack_type_list(self, params: dict) -> Any:
        ...

    def file_report_submit(self, params: dict) -> Any:
        ...

    def url_report_submit(self, params: dict) -> Any:
        ...

    def email_report_submit(self, params: dict) -> Any:
        ...

    def submission_list(self, params: dict) -> Any:
        ...

    def submission_file_list(self, params: dict) -> Any:
        ...

    def file_screenshot_get(self, params: dict) -> Any:
        ...

    def submission_mail_list(self, params: dict) -> Any:
        ...

    def mail_screenshot_get(self, params: dict) -> Any:
        ...

    def submission_url_list(self, params: dict) -> Any:
        ...

    def url_screenshot_get(self, params: dict) -> Any:
        ...


''' HELPER FUNCTIONS '''


def sub_dict(d: dict, keys: Iterable, change_keys: dict = None) -> dict:
    '''Returns a sub-dict of "d" with the given keys.
    change_keys maps the key names in "d" to the
    corresponding key name needed in the output'''
    res = {
        k: d[k]
        for k in keys
    }
    res |= {
        v: res.pop(k, None)
        for k, v in change_keys or {}
    }
    return res


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
        demisto.debug(inc_id := incident['id'])
        return {
            'name': f'Takedown-{inc_id}',
            'occurred': arg_to_datetime(incident['date_submitted']).isoformat(),
            'dbotMirrorId': inc_id,
            'rawJSON': json.dumps(
                incident | {
                    'mirror_direction': MIRROR_DIRECTION_DICT[PARAMS['mirror_direction']],
                    'mirror_instance': demisto.integrationInstance()
                }),
        }

    params = {
        'max_results': min(
            arg_to_number(PARAMS['max_fetch']) or 10,
            API_MAX_FETCH
        ),
        'sort': 'id',
        'region': PARAMS['region']
    }

    if last_id := demisto.getLastRun():
        demisto.debug(f'{last_id=}')
        params['id_after'] = last_id
    else:
        params['date_from'] = str(
            arg_to_datetime(
                PARAMS['first_fetch'],
                required=True
            ))
        demisto.debug(f'First fetch date: {params["date_from"]}')

    incidents = client.get_takedowns(params) or []
    if incidents:
        demisto.setLastRun(incidents[-1]['id'])

        # the first incident from the API call should be a duplicate of last_id
        if incidents[0]['id'] == last_id:
            incidents.pop(0)
    return list(map(to_xsoar_incident, incidents))


def get_modified_remote_data(client: Client, args: dict) -> GetModifiedRemoteDataResponse:
    demisto.debug(f'\n{"#"*50}\nEntering get_modified_remote_data({client=}, {args=})\n')
    remote_args = GetModifiedRemoteDataArgs(args)
    demisto.debug(f'{remote_args.last_update=}')
    last_update = dateparser.parse(remote_args.last_update)
    incidents = client.get_takedowns({
        'updated_since': last_update,
        'region': PARAMS['region']
    })
    demisto.debug(f'{incidents=}'.replace('\n', '\n\t\t'))
    demisto.debug(f'\nExiting get_modified_remote_data()\n{"#"*50}\n')
    return GetModifiedRemoteDataResponse(incidents)


# def get_modified_remote_data(client: Client, args: dict) -> GetModifiedRemoteDataResponse:
#     remote_args = GetModifiedRemoteDataArgs(args)
#     last_update = dateparser.parse(remote_args.last_update)
#     raw_incidents = client.get_takedowns({
#         'updated_since': last_update,
#         'response_include': 'id',
#         'region': PARAMS['region']
#     })
#     ids = [inc['id'] for inc in raw_incidents]
#     return GetModifiedRemoteDataResponse(ids)


# def get_remote_data(client: Client, args: dict) -> GetRemoteDataResponse:
#     remote_args = GetRemoteDataArgs(args)
#     incident = client.get_takedowns({
#         'id': remote_args.remote_incident_id,
#         'region': PARAMS['region']
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
            for changed_key in parsed_args.delta:
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

    return new_incident_id


def netcraft_attack_report_command(client: Client, args: dict) -> CommandResults:
    args |= {
        'type': args.pop('attack_type'),
        'suspected_fraudulent_domain': args.pop('suspected_fraud_domain'),
        'region': args.get('region') or PARAMS['region']
    }
    response = client.attack_report(args)
    lines = response.splitlines() + ['', '']
    return CommandResults(
        outputs_prefix='Netcraft.Takedown',
        outputs_key_field='id',
        outputs={  # TODO finalize with TPM and add to yml
            'responseCode': lines[0],
            'id': lines[1]
        },
        raw_response=response,
        readable_output=(
            f'##### {RES_CODE_TO_MESSAGE.get(lines[0], "Unrecognized response from Netcraft.")}\n'
            f'Response code: {lines[0]}\n'
            f'Takedown ID: {lines[1]}\n'
        )
    )


def netcraft_takedown_list_command(client: Client, args: dict) -> CommandResults:

    def args_to_params(args: dict) -> dict:
        report_source = args.pop('report_source')
        return args | {
            'authgiven': args.pop('auth_given', '').lower().replace(' ', ':'),
            'report_source':
                'phish_feed'
                if report_source == 'Phishing Feed'
                else report_source.lower().replace(' ', '_'),
            'sort': args.pop('sort').lower().replace(' ', '_'),
            'dir': args.pop('sort_direction'),
            'max_results':
                arg_to_number(args.pop('limit'))
                if not argToBoolean(args.pop('all_results'))
                else API_MAX_FETCH
        }

    def response_to_readable(response: list[dict]) -> str:
        return tableToMarkdown(
            'Netcraft Takedowns',
            [
                # TODO get TPM input on ...
                {
                    'ID': d.get('id'),
                    'Auth': {'0': 'No', '1': 'Yes'}.get(d.get('authgiven')),
                    'Level': ...,
                    'Customer': (..., 'TODO', {"customer_label": "", "customer_tag": ""}),
                    'Brand': d.get('target_brand'),
                    'Attack Type': d.get('attack_type'),
                    'Status': d.get('status'),
                    'Pageset': ...,
                    'Attack URL': d.get('attack_url'),
                    'Date Reported': d.get('date_submitted'),
                    'Last Updated': d.get('last_updated'),
                    'Date Authorised': d.get('date_authed') or 'N/A',
                    'Date Escalated': d.get('date_escalated') or 'N/A',
                    'First Response from Netcraft': (..., d.get('first_contact')),
                    'First Inactive (Monitoring)': d.get('first_inactive') or 'N/A',
                    'First Resolved': d.get('first_resolved') or 'N/A',
                }
                for d in response
            ],
            [
                'ID', 'Auth', 'Level', 'Customer', 'Brand', 'Attack Type', 'Status', 'Pageset',
                'Attack URL', 'Date Reported', 'Last Updated', 'Date Authorised', 'Date Escalated',
                'First Response from Netcraft', 'First Inactive (Monitoring)', 'First Resolved',
            ],
            removeNull=True
        )

    response = client.get_takedowns(
        args_to_params(args)
    )
    return CommandResults(
        outputs_prefix='Netcraft.Takedown',
        outputs_key_field='id',
        outputs=response,
        readable_output=response_to_readable(response)
    )


def netcraft_takedown_update_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_takedown_escalate_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_takedown_note_create_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_takedown_note_list_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_attack_type_list_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_file_report_submit_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_url_report_submit_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_email_report_submit_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_submission_list_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_submission_file_list_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_file_screenshot_get_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_submission_mail_list_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_mail_screenshot_get_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_submission_url_list_command(client: Client, args: dict) -> CommandResults:
    ...


def netcraft_url_screenshot_get_command(client: Client, args: dict) -> CommandResults:
    ...


''' MAIN FUNCTION '''


def main() -> None:

    args = demisto.args()
    command = demisto.command()

    client = Client(
        verify=(not PARAMS['insecure']),
        proxy=PARAMS['proxy'],
        ok_codes=(200,),
        headers=AUTH_HEADERS
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

            case 'netcraft-attack-report':
                return_results(netcraft_attack_report_command(client, args))
            case 'netcraft-takedown-list':
                return_results(netcraft_takedown_list_command(client, args))
            case 'netcraft-takedown-update':
                return_results(netcraft_takedown_update_command(client, args))
            case 'netcraft-takedown-escalate':
                return_results(netcraft_takedown_escalate_command(client, args))
            case 'netcraft-takedown-note-create':
                return_results(netcraft_takedown_note_create_command(client, args))
            case 'netcraft-takedown-note-list':
                return_results(netcraft_takedown_note_list_command(client, args))
            case 'netcraft-attack-type-list':
                return_results(netcraft_attack_type_list_command(client, args))
            case 'netcraft-file-report-submit':
                return_results(netcraft_file_report_submit_command(client, args))
            case 'netcraft-url-report-submit':
                return_results(netcraft_url_report_submit_command(client, args))
            case 'netcraft-email-report-submit':
                return_results(netcraft_email_report_submit_command(client, args))
            case 'netcraft-submission-list':
                return_results(netcraft_submission_list_command(client, args))
            case 'netcraft-submission-file-list':
                return_results(netcraft_submission_file_list_command(client, args))
            case 'netcraft-file-screenshot-get':
                return_results(netcraft_file_screenshot_get_command(client, args))
            case 'netcraft-submission-mail-list':
                return_results(netcraft_submission_mail_list_command(client, args))
            case 'netcraft-mail-screenshot-get':
                return_results(netcraft_mail_screenshot_get_command(client, args))
            case 'netcraft-submission-url-list':
                return_results(netcraft_submission_url_list_command(client, args))
            case 'netcraft-url-screenshot-get':
                return_results(netcraft_url_screenshot_get_command(client, args))
            case _:
                raise NotImplementedError(f'{command!r} is not a Netcraft command.')

    except Exception as e:
        return_error(f'Failed to execute {command!r}.\nError: {e.__class__.__name__}\nCause: {e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
