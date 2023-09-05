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
MIRROR_DIRECTION_MAP = {
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
        ' If verification is successful, a new takedown will be submitted. If not, no takedown will be created.\n'
        'To get a list of all takedowns, run the command: "netcraft-takedown-list"',
}

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, verify, proxy, ok_codes, headers, **kwargs):
        super().__init__(None, verify, proxy, ok_codes, headers, **kwargs)

    def _http_request(self, method, service, url_suffix='', params=None, json_data=None, resp_type='json', **kwargs) -> Any:
        remove_nulls_from_dictionary(params or {})
        remove_nulls_from_dictionary(json_data or {})
        return super()._http_request(
            method, full_url=urljoin(SERVICE_TO_URL_MAP[service], url_suffix),
            params=params, json_data=json_data, resp_type=resp_type, **kwargs)

    def client_error_handler(self, res: requests.Response):
        '''Error handler for Netcraft API call error'''
        err_msg = f'Error in Netcraft API call [{res.status_code}] - {res.reason}\n'
        try:
            # Try to parse json error response
            error_entry: dict[str, Any] = res.json()
            err_msg += '\n'.join(
                f'{k.replace("_", " ").title()}: {v}'
                for k, v in error_entry.items()
            )
        except ValueError:
            err_msg += res.text
        raise DemistoException(err_msg, res=res)

    def test_module(self):
        ...

    def get_takedowns(self, params: dict) -> list[dict]:
        '''Used by fetch-incidents and netcraft-takedown-list'''
        return self._http_request(
            'GET', 'takedown', 'attacks/', params
        )

    def attack_report(self, body: dict) -> str:
        return self._http_request(
            'POST', 'takedown', 'report/',
            json_data=body, resp_type='text'
        )

    def takedown_update(self, body: dict) -> dict:
        return self._http_request(
            'POST', 'takedown', 'update-attack/', json_data=body,
        )

    def takedown_escalate(self, body: dict) -> dict:
        return self._http_request(
            'POST', 'takedown', 'escalate/', json_data=body,
        )

    def takedown_note_create(self, body: dict) -> dict:
        return self._http_request(
            'POST', 'takedown', 'notes/', json_data=body,
        )

    def takedown_note_list(self, params: dict) -> None:
        ...

    def attack_type_list(self, params: dict) -> None:
        ...

    def file_report_submit(self, params: dict) -> None:
        ...

    def url_report_submit(self, params: dict) -> None:
        ...

    def email_report_submit(self, params: dict) -> None:
        ...

    def submission_list(self, params: dict) -> None:
        ...

    def submission_file_list(self, params: dict) -> None:
        ...

    def file_screenshot_get(self, params: dict) -> None:
        ...

    def submission_mail_list(self, params: dict) -> None:
        ...

    def mail_screenshot_get(self, params: dict) -> None:
        ...

    def submission_url_list(self, params: dict) -> None:
        ...

    def url_screenshot_get(self, params: dict) -> None:
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


# TODO test_module
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


def fetch_incidents(client: Client) -> list[dict[str, str]]:
    # demisto.getLastRun and demisto.setLastRun hold takedown IDs
    def to_xsoar_incident(incident: dict) -> dict:
        demisto.debug(inc_id := incident['id'])
        return {
            'name': f'Takedown-{inc_id}',
            'occurred': arg_to_datetime(incident['date_submitted']).isoformat(),
            'dbotMirrorId': inc_id,
            'rawJSON': json.dumps(
                incident | {
                    'mirror_direction': MIRROR_DIRECTION_MAP[PARAMS['mirror_direction']],
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


def netcraft_attack_report_command(client: Client, args: dict) -> CommandResults:
    args |= {
        'type': args.pop('attack_type'),
        'suspected_fraudulent_domain': argToBoolean(args.pop('suspected_fraud_domain')),
        'region': args.get('region') or PARAMS['region'],
        'malware': json.loads(args.get('malware', 'null')),
        'force_auth': json.loads(args.get('force_auth', 'null')),
        'inactive': json.loads(args.get('inactive', 'null')),
        'tags': ','.join(argToList(args.get('tags'))),
    }
    response = client.attack_report(args)
    code, takedown_id, *_ = response.splitlines() + ['', '']
    return CommandResults(
        outputs_prefix='Netcraft.Takedown',
        outputs_key_field='id',
        outputs={'id': takedown_id} if code == 'TD_OK' else None,
        raw_response=response,
        readable_output=(
            f'##### {RES_CODE_TO_MESSAGE.get(code, "Unrecognized response from Netcraft.")}\n'
            f'Response code: {code}\n'
            f'Takedown ID: {takedown_id}\n'
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
                else (report_source or '').lower().replace(' ', '_'),
            'sort': args.pop('sort').lower().replace(' ', '_'),
            'dir': args.pop('sort_direction'),
            'max_results':
                arg_to_number(args.pop('limit'))
                if not argToBoolean(args.pop('all_results'))
                else API_MAX_FETCH,
            'region': args.get('region') or PARAMS['region']
        }

    def response_to_readable(response: list[dict]) -> str:
        return tableToMarkdown(
            'Netcraft Takedowns',
            [
                {
                    'ID': d.get('id'),
                    'Auth': {'0': 'No', '1': 'Yes'}.get(d.get('authgiven')),
                    'Brand': d.get('target_brand'),
                    'Attack Type': d.get('attack_type'),
                    'Status': d.get('status'),
                    'Attack URL': d.get('attack_url'),
                    'Date Reported': d.get('date_submitted'),
                    'Last Updated': d.get('last_updated'),
                    'Date Authorised': d.get('date_authed') or 'N/A',
                    'Date Escalated': d.get('date_escalated') or 'N/A',
                    'First Contact': d.get('first_contact'),
                    'First Inactive (Monitoring)': d.get('first_inactive') or 'N/A',
                    'First Resolved': d.get('first_resolved') or 'N/A',
                }
                for d in response
            ],
            [
                'ID', 'Auth', 'Brand', 'Attack Type', 'Status', 'Attack URL',
                'Date Reported', 'Last Updated', 'Date Authorised', 'Date Escalated',
                'First Contact', 'First Inactive (Monitoring)', 'First Resolved',
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

    def args_to_params(args: dict) -> dict:
        return args | {
            key: args.get(value)
            for key, value in
            (
                ('set_customer_label', 'customer_label'),
                ('set_description', 'description'),
                ('set_region', 'region'),
                ('set_brand', 'brand'),
                ('set_suspected_fraudulent_domain', 'suspected_fraud_domain'),
                ('set_suspected_fraudulent_hostname', 'suspected_fraud_hostname'),
            )
        } | {
            'add_tags': ','.join(argToList(args.get('add_tags'))),
            'remove_tags': ','.join(argToList(args.get('remove_tags'))),
        }

    response = client.takedown_update(
        args_to_params(args)
    )
    return CommandResults(
        readable_output=f'##### Takedown successfully updated.\nID: {response["id"]}'
    )


def netcraft_takedown_escalate_command(client: Client, args: dict) -> CommandResults:
    return CommandResults(
        raw_response=client.takedown_escalate(args),
        readable_output=f'##### Takedown successfully escalated.\nTakedown ID: {args["takedown_id"]}',
    )


def netcraft_takedown_note_create_command(client: Client, args: dict) -> CommandResults:
    response = client.takedown_note_create(
        args | {'text': args.pop('note_text')}
    )
    return CommandResults(
        outputs_prefix='Netcraft.TakedownNote',
        outputs=response,
        outputs_key_field='note_id',
        readable_output=(
            '##### Note successfully added to takedown.\n'
            f'Note ID: {response["note_id"]}'
            f'Takedown ID: {args["takedown_id"]}'
        )
    )


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
