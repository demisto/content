import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections.abc import Iterable


''' CONSTANTS '''

PARAMS: dict = demisto.params()
TAKEDOWN_API_LIMIT = 100_000
SUBMISSION_API_LIMIT = 1000
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

    def _http_request(self, method: str, service: str, url_suffix: str,
                      params: dict = None, json_data: dict = None,
                      files: dict = None, resp_type: str = 'json', 
                      ok_codes: Any = None, **kwargs) -> Any:
        '''
        A wrapper for BaseClient._http_request that supports Netcraft specific functions.

        Args:
            method (str): 
                The HTTP method, for example: GET, POST, and so on.

            service (str):
                The Netcraft service URL to use. should be a key in SERVICE_TO_URL_MAP.

            url_suffix (str):
                The API endpoint.

            params (dict):
                URL parameters to specify the query.

            json_data (dict):
                The dictionary to send in a 'POST' request.

            files (dict):
                The file data to send in a 'POST' request.

            resp_type (str):
                Determines which data format to return from the HTTP request. The default
                is 'json'. Other options are 'text', 'content', 'xml' or 'response'. Use 'response'
                    to return the full response object.
            
            ok_codes (tuple[int]):
                The request codes to accept as OK, for example: (200, 201, 204). If you specify "None", will use self._ok_codes.

        Returns:
            dict | str | bytes | xml.etree.ElementTree.Element | requests.Response: Depends on the resp_type parameter
        '''
        remove_nulls_from_dictionary(params or {})
        remove_nulls_from_dictionary(json_data or {})
        return super()._http_request(
            method, full_url=urljoin(SERVICE_TO_URL_MAP[service], url_suffix),
            params=params, json_data=json_data, files=files, resp_type=resp_type,
            ok_codes=ok_codes, **kwargs)

    def client_error_handler(self, res: requests.Response):
        '''Error handler for Netcraft API call error'''
        err_msg = f'Error in Netcraft API call [{res.status_code}] - {res.reason}\n'
        try:
            # Try to parse json error response
            error_entry: dict[str, Any] = res.json()
            err_msg += '\n'.join(
                f'{string_to_table_header(k)}: {v}'
                for k, v in error_entry.items()
            )
        except ValueError:
            err_msg += res.text
        raise DemistoException(err_msg, res=res)

    def get_takedowns(self, params: dict) -> list[dict]:
        '''Used by fetch-incidents and netcraft-takedown-list'''
        return self._http_request(
            'GET', 'takedown', 'attacks/', params,
        )

    def attack_report(self, body: dict, file: dict | None) -> str:
        return self._http_request(
            'POST', 'takedown', 'report/',
            json_data=body, resp_type='text', files=file,
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

    def takedown_note_list(self, params: dict) -> list[dict]:
        return self._http_request(
            'GET', 'takedown', 'notes/', params=params,
        )

    def attack_type_list(self, params: dict) -> list[dict]:
        return self._http_request(
            'GET', 'takedown', 'attack-types/', params=params,
        )

    def submission_list(self, params: dict) -> dict:
        return self._http_request(
            'GET', 'submission', 'submission/', params=params,
        )

    def get_submission(self, uuid: str) -> dict:
        return self._http_request(
            'GET', 'submission', f'submission/{uuid}',
        )

    def file_report_submit(self, body: dict) -> dict:
        return self._http_request(
            'POST', 'submission', 'report/files/', json_data=body, 
        )

    def submission_file_list(self, uuid: str, params: dict) -> dict:
        return self._http_request(
            'GET', 'submission', f'submission/{uuid}/files', params=params,
        )

    def file_screenshot_get(self, submission_uuid: str, file_hash: str) -> bytes:
        return self._http_request(
            'GET', 'submission',
            f'submission/{submission_uuid}/files/{file_hash}/screenshot',
            resp_type='content',
        )

    def url_report_submit(self, body: dict) -> dict:
        return self._http_request(
            'POST', 'submission', 'report/urls/', json_data=body,
        )

    def submission_mail_get(self, uuid: str) -> dict:
        return self._http_request(
            'GET', 'submission', f'submission/{uuid}/mail',
        )

    def mail_screenshot_get(self, submission_uuid: str) -> bytes:
        return self._http_request(
            'GET', 'submission',
            f'submission/{submission_uuid}/mail/screenshot',
            resp_type='content',
        )

    def email_report_submit(self, body: dict) -> dict:
        return self._http_request(
            'POST', 'submission', 'report/mail/', json_data=body,
        )

    def submission_url_list(self, uuid: str, params: dict) -> dict:
        return self._http_request(
            'GET', 'submission', f'submission/{uuid}/urls', params=params,
        )

    def url_screenshot_get(self, submission_uuid: str, url_uuid: str, screenshot_hash: str) -> requests.Response:
        return self._http_request(
            'GET', 'submission',
            f'submission/{submission_uuid}/urls/{url_uuid}/screenshots/{screenshot_hash}',
            resp_type='response',
        )


''' HELPER FUNCTIONS '''


def int_to_readable_bool(val: str | int | None) -> str | None:
    '''
    Converts the 1 or 0 values returned by netcraft to a human readable string.
    The val provided can be an int, str or None (in which case None should be returned).
    '''
    return {'0': 'No', '1': 'Yes'}.get(str(val))


def int_to_bool(val: str | int | None) -> bool | None:
    '''
    Converts the 1 or 0 values returned by netcraft to a boolean for the context, if possible.
    The val provided can be an int, str or None (in which case None should be returned).
    '''
    return {'0': False, '1': True}.get(str(val))


def convert_keys_to_bool(d: dict, *keys):
    '''
    Applies int_to_bool() on the given 'keys' of 'd', in place.
    '''
    d |= {
        key: int_to_bool(d.get(key))
        for key in keys
    }


# def paginate1(
#         api_limit=None,
#         key_to_pages=None,
#         page_start_index=1):
#     """
#     Decorator for paginating an API in a request function.

#     :param api_limit: The maximum limit supported by the API for a single request. Used only with "limit" when "page" and
#                       "page_size" are not defined. Use None if there is no API limit. Default is None.
#     :type api_limit: int | None

#     :param keys_to_pages: Key(s) to access the paginated data within the response dictionary. When the data is nested in multiple
#                           dictionaries, use a list of keys as a path to the data. The function will return the combined pages
#                           without surrounding dictionaries. Default is None.
#     :type keys_to_pages: Iterable | str | None

#     :param page_start_index: The starting page index. Default is 1.
#     :type page_start_index: int
#     """
#     def dec(func):
#         def inner(*args, limit=50, page=0, page_size=None, **kwargs):

#             def get_page(**page_args):
#                 return dict_safe_get(
#                     func(*args, **page_args, **kwargs),
#                     [key_to_pages], return_type=list
#                 )

#             pages: list = []

#             page = arg_to_number(page)
#             page_size = arg_to_number(page_size)
#             if isinstance(page, int) and isinstance(page_size, int):
#                 limit = page_size
#                 offset = (page - page_start_index) * page_size

#             else:
#                 limit = int(limit)
#                 offset = 0

#                 if api_limit:
#                     for offset in range(0, limit - api_limit, api_limit):
#                         pages += get_page(
#                             limit=api_limit,
#                             offset=offset)

#                     # the remaining call can be less than OR equal the api_limit but not empty
#                     limit = limit % api_limit or api_limit
#                     offset += api_limit

#             pages += get_page(
#                 limit=limit,
#                 offset=offset)

#             return pages

#         return inner

#     return dec

# def paginate(func, key_to_pages: str, api_limit: int, limit=50, page=0, page_size=None, *args, **kwargs) -> list[dict]:
#     def get_page(**page_args):
#         return dict_safe_get(
#             func(*args, **page_args, **kwargs),
#             [key_to_pages], return_type=list
#         )
#     pages: list = []

#     page = arg_to_number(page)
#     count = arg_to_number(page_size)
#     if not (isinstance(page, int) and isinstance(page_size, int)):
#         limit = int(limit)

#         for offset in range(0, limit - api_limit, api_limit):
#             pages += get_page(
#                 limit=api_limit,
#                 offset=offset)

#             # the remaining call can be less than OR equal the api_limit but not empty
#             limit = limit % api_limit or api_limit
#             offset += api_limit

#     pages += get_page(
#         limit=limit,
#         offset=offset)

#     return pages

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    if PARAMS.get('isFetch') and not arg_to_datetime(PARAMS['first_fetch']):
        raise ValueError(f'{PARAMS["first_fetch"]!r} is not a valid time.')
    # test takedown service
    client.get_takedowns({'page_size': 1})
    # test submission service
    client.submission_list({'max_results': 1})
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
            TAKEDOWN_API_LIMIT
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


def attack_report_command(client: Client, args: dict) -> CommandResults:

    def args_to_params(args: dict) -> tuple[dict, dict | None]:
        if entry_id := args.get('entryId'):
            file_contents = demisto.getFilePath(entry_id)
            file = {'evidence': open(file_contents['path'], 'rb')}
        else:
            file = None

        return args | {
            'type': args.pop('attack_type'),
            'suspected_fraudulent_domain': argToBoolean(args.pop('suspected_fraud_domain')),
            'region': args.get('region') or PARAMS['region'],
            'malware': json.loads(args.get('malware', 'null')),
            'force_auth': json.loads(args.get('force_auth', 'null')),
            'inactive': json.loads(args.get('inactive', 'null')),
            'tags': ','.join(argToList(args.get('tags'))),
        }, file

    response = client.attack_report(
        *args_to_params(args)
    )
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


def takedown_list_command(client: Client, args: dict) -> CommandResults:

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
                else TAKEDOWN_API_LIMIT,
            'region': args.get('region') or PARAMS['region']
        }

    def response_to_readable(response: list[dict]) -> str:
        return tableToMarkdown(
            'Netcraft Takedowns',
            [
                {
                    'ID': d.get('id'),
                    'Auth': int_to_readable_bool(d.get('authgiven')),
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

    def response_to_context(response: list[dict]) -> list[dict]:
        for takedown in response:
            convert_keys_to_bool(takedown, 'authgiven', 'has_phishing_kit', 'escalated')
        return response

    response = client.get_takedowns(
        args_to_params(args)
    )
    return CommandResults(
        readable_output=response_to_readable(response),
        outputs_prefix='Netcraft.Takedown',
        outputs_key_field='id',
        outputs=response_to_context(response),
    )


def takedown_update_command(client: Client, args: dict) -> CommandResults:

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


def takedown_escalate_command(client: Client, args: dict) -> CommandResults:
    return CommandResults(
        raw_response=client.takedown_escalate(args),
        readable_output=f'##### Takedown successfully escalated.\nTakedown ID: {args["takedown_id"]}',
    )


def takedown_note_create_command(client: Client, args: dict) -> CommandResults:
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


def takedown_note_list_command(client: Client, args: dict) -> CommandResults:

    def response_to_readable(response: list[dict]) -> str:
        return tableToMarkdown(
            'Takedown Notes', response,
            ['Note', 'Note ID', 'Takedown ID', 'Group ID', 'Author', 'Time'],
            headerTransform={
                'note_id': 'Note ID',
                'takedown_id': 'Takedown ID',
                'group_id': 'Group ID',
                'time': 'Time',
                'author': 'Author',
                'note': 'Note'
            }.get,
            removeNull=True
        )
    response = client.takedown_note_list({
        'takedown_id': args.get('takedown_id'),
        'author': args.get('author_mail')
    })
    response = response if argToBoolean(args['all_results']) else response[:50]
    return CommandResults(
        outputs_prefix='Netcraft.TakedownNote',
        outputs=response,
        outputs_key_field='note_id',
        readable_output=response_to_readable(response)
    )


def attack_type_list_command(client: Client, args: dict) -> CommandResults:

    def response_to_readable(response: list[dict]) -> str:
        return tableToMarkdown(
            'Takedown Notes', response,
            [
                'name', 'display_name', 'base_type', 'description',
                'automated', 'auto_escalation', 'auto_authorise',
            ],
            headerTransform=string_to_table_header,
            removeNull=True
        )
    response = client.attack_type_list({
        'auto_escalation': args.get('auto_escalation'),
        'auto_authorise': args.get('auto_authorise'),
        'automated': args.get('automated'),
        'region': args.get('region') or PARAMS['region'],
    })
    response = response if argToBoolean(args['all_results']) else response[:50]
    return CommandResults(
        outputs_prefix='Netcraft.AttackType',
        outputs=response,
        readable_output=response_to_readable(response)
    )

@polling_function(
    name='netcraft-submission-list',
    interval=arg_to_number(demisto.getArg('interval_in_seconds')),
    timeout=arg_to_number(demisto.getArg('timeout')),
    poll_message='Processing:'
)
def submission_list_command(client: Client, args: dict) -> PollResult:

    def response_to_readable(submissions: list[dict]) -> str:
        return ''  # TODO get UI layout

    def with_uuid_response_to_readable(submission: dict) -> str:
        '''Called only when the "submission_uuid" is provided.'''
        return ''  # TODO get UI layout

    def with_uuid_response_to_context(response: dict, uuid) -> dict:
        '''
        Called only when the "submission_uuid" is provided and does the following:
        1. adds the uuid the output so that there is a uuid for every submission under 'Netcraft.Submission'.
        2. keeps the context output somewhat similar to the output of the non uuid call by aligning keys that differ in name only.
        3. converts 1 or 0 values into their corresponding boolean values.
        '''
        response |= {
            'uuid': uuid,
            'source_name': response.get('source', {}).pop('name', None),
            'submitter_email': response.pop('submitter', {}).get('email'),
        }
        convert_keys_to_bool(
            response,
            'has_cryptocurrency_addresses', 'has_files', 'has_issues', 'has_mail',
            'has_phone_numbers', 'has_urls', 'is_archived', 'pending'
        )
        return response

    if uuid := args.pop('submission_uuid', None):
        response = client.get_submission(uuid)
        return PollResult(
            CommandResults(
                readable_output=with_uuid_response_to_readable(response),
                outputs_prefix='Netcraft.Submission',
                outputs_key_field='uuid',
                outputs=with_uuid_response_to_context(response, uuid),
            ),
            continue_to_poll=(response.get('state') == 'processing')
        )
    else:
        # TODO pagination
        response = client.submission_list(args | {
            'marker': (marker := args.pop('next_token')),
            'page_size': args.pop('limit')
        })
        submissions = response.get('submissions', [])
        return PollResult(
            CommandResults(
                readable_output=response_to_readable(submissions),
                raw_response=response,
                # this method is used so that the key Netcraft.SubmissionNextToken is overridden on each run
                outputs={
                    'Netcraft.Submission(val.uuid && val.uuid == obj.uuid)': submissions,
                    'Netcraft.SubmissionNextToken(val.NextPageToken)': {'NextPageToken': response.get('marker', marker)}
                },
            ),
        )


def file_report_submit_command(client: Client, args: dict) -> CommandResults:
    response = client.file_report_submit(
        args  # TODO
    )
    requests.Response.
    return submission_list_command(client, args | {'submission_uuid': response['uuid']})


def submission_file_list_command(client: Client, args: dict) -> CommandResults:

    def response_to_readable(files: list[dict]) -> str:
        return ''  # TODO get UI layout

    def response_to_context(files: list[dict]) -> list[dict]:
        for file in files:
            convert_keys_to_bool(file, 'has_screenshot')
        return files

    response = client.submission_file_list(args['submission_uuid'], args)  # TODO pagination
    files = response.get('files', [])
    return CommandResults(
        readable_output=response_to_readable(files),
        outputs=response_to_context(files),
        outputs_prefix='Netcraft.SubmissionFile',
        outputs_key_field='hash',
        raw_response=response
    )


def file_screenshot_get_command(client: Client, args: dict) -> dict:
    return fileResult(
        f'file_screenshot_{args["file_hash"]}.png',
        client.file_screenshot_get(**args),
        EntryType.ENTRY_INFO_FILE,
    )


def email_report_submit_command(client: Client, args: dict) -> CommandResults:

    response = client.email_report_submit({
        'email': args.pop('reporter_email'),
        'message': args.pop('message'),
        'password': args.pop('password', None),
    })
    return submission_list_command(client, args | {'submission_uuid': response['uuid']})


def submission_mail_get_command(client: Client, args: dict) -> CommandResults:
    response = client.submission_mail_get(**args)
    return CommandResults(
        outputs=response,
        outputs_prefix='Netcraft.SubmissionMail',
        outputs_key_field='hash',
        readable_output='',  # TODO get UI layout
    )


def mail_screenshot_get_command(client: Client, args: dict) -> dict:
    return fileResult(
        f'mail_screenshot_{args["submission_uuid"]}.png',
        client.mail_screenshot_get(**args),
        EntryType.ENTRY_INFO_FILE,
    )


def url_report_submit_command(client: Client, args: dict) -> CommandResults:

    response = client.url_report_submit({
        'email': args.pop('reporter_email'),
        'reason': args.pop('reason', None),
        'urls': [
            {'url': url} for url in argToList(args.pop('urls'))
        ]
    })
    return submission_list_command(client, args | {'submission_uuid': response['uuid']})


def submission_url_list_command(client: Client, args: dict) -> CommandResults:

    # TODO int_to_bool(tags.submitter_tag)
    response = client.submission_url_list(**args)  # TODO pagination
    urls = response.get('urls', [])
    return CommandResults(
        outputs=urls,
        outputs_key_field='uuid',
        outputs_prefix='Netcraft.SubmissionURL',
        readable_output='',  # TODO get UI layout
        raw_response=response
    )


def url_screenshot_get_command(client: Client, args: dict) -> dict:
    response = client.url_screenshot_get(**args)
    # type of screenshot can be gif or png, the Content-Type key returns: "image/{file_type}"
    file_type = response.headers.get('Content-Type', '').partition('/')[2]
    return fileResult(
        f'url_screenshot_{args["screenshot_hash"]}.{file_type}',
        response.content,
        EntryType.ENTRY_INFO_FILE
    )


''' MAIN FUNCTION '''


def main() -> None:

    args = demisto.args()
    command = demisto.command()

    client = Client(
        verify=(not PARAMS['insecure']),
        proxy=PARAMS['proxy'],
        ok_codes=(200,),
        headers=AUTH_HEADERS,
    )

    demisto.debug(f'Command being called is {command}')
    try:
        match command:
            case 'test-module':
                return_results(test_module(client))
            case 'fetch-incidents':
                demisto.incidents(fetch_incidents(client))
            case 'netcraft-attack-report':
                return_results(attack_report_command(client, args))
            case 'netcraft-takedown-list':
                return_results(takedown_list_command(client, args))
            case 'netcraft-takedown-update':
                return_results(takedown_update_command(client, args))
            case 'netcraft-takedown-escalate':
                return_results(takedown_escalate_command(client, args))
            case 'netcraft-takedown-note-create':
                return_results(takedown_note_create_command(client, args))
            case 'netcraft-takedown-note-list':
                return_results(takedown_note_list_command(client, args))
            case 'netcraft-attack-type-list':
                return_results(attack_type_list_command(client, args))
            case 'netcraft-submission-list':
                return_results(submission_list_command(client, args))
            case 'netcraft-submission-file-list':
                return_results(submission_file_list_command(client, args))
            case 'netcraft-file-screenshot-get':
                return_results(file_screenshot_get_command(client, args))
            case 'netcraft-submission-mail-get':
                return_results(submission_mail_get_command(client, args))
            case 'netcraft-mail-screenshot-get':
                return_results(mail_screenshot_get_command(client, args))
            case 'netcraft-submission-url-list':
                return_results(submission_url_list_command(client, args))
            case 'netcraft-url-screenshot-get':
                return_results(url_screenshot_get_command(client, args))
            case 'netcraft-file-report-submit':
                return_results(file_report_submit_command(client, args))
            case 'netcraft-url-report-submit':
                return_results(url_report_submit_command(client, args))
            case 'netcraft-email-report-submit':
                return_results(email_report_submit_command(client, args))
            case _:
                raise NotImplementedError(f'{command!r} is not a Netcraft command.')

    except Exception as e:
        return_error(f'Failed to execute {command!r}.\nError: {e.__class__.__name__}\nCause: {e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
