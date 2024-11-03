import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *


class BloxOneTDClient(BaseClient):
    def __init__(self, api_key, verify=True, proxy=False):
        super(BloxOneTDClient, self).__init__(
            headers={'Authorization': f'Token {api_key}'},
            base_url='https://csp.infoblox.com',
            verify=verify,
            proxy=proxy
        )

    def dossier_source_list(self) -> list[str]:
        url_suffix = '/tide/api/services/intel/lookup/sources'
        res = self._http_request('GET', url_suffix=url_suffix)
        return [source for source, enabled in res.items() if enabled]

    def lookalike_domain_list(self, user_filter: Optional[str] = None,
                              target_domain: Optional[str] = None, detected_at: Optional[str] = None,
                              limit: int = 50, offset: Optional[int] = None) -> List[Dict]:
        url_suffix = '/api/tdlad/v1/lookalike_domains'
        filter_params: Dict[str, Any] = {key: val for key, val in [('_limit', limit), ('_offset', offset)] if val}

        # there is no reference in the docs but it seems that one of the following is correct
        # - the filters combination is OR
        # - we can't filter by more than filter
        # as a result we decided to allow just one filter at a time
        if user_filter:
            _filter = user_filter
        elif target_domain:
            _filter = f'target_domain=="{target_domain}"'
        else:  # detected_at != None
            _filter = f'detected_at>="{detected_at}"'

        filter_params['_filter'] = _filter

        return self._http_request('GET', url_suffix=url_suffix, params=filter_params)['results']

    def dossier_lookup_get_create(self, indicator_type: str, value: str, sources: Optional[List[str]] = None) -> str:
        url_suffix = f'/tide/api/services/intel/lookup/indicator/{indicator_type}'
        params: Dict[str, Any] = {'value': value}
        if sources:
            params['source'] = sources

        data = self._http_request('GET', url_suffix=url_suffix, params=params)
        return data['job_id']

    def dossier_lookup_get_is_done(self, job_id: str) -> bool:
        url_suffix = f'/tide/api/services/intel/lookup/jobs/{job_id}/pending'
        data = self._http_request('GET', url_suffix=url_suffix)
        if data['state'] == 'completed':
            if data['status'] == 'success':
                return True
            raise DemistoException(f'job {job_id} is completed with status: {data["status"]}\ndetails: {data}')
        return False

    def dossier_lookup_get_results(self, job_id: str) -> Dict:

        url_suffix = f'/tide/api/services/intel/lookup/jobs/{job_id}/results'
        return self._http_request('GET', url_suffix=url_suffix)


def dossier_lookup_task_output(task: Dict) -> Dict:
    params = task.get('params', {})
    return {
        'Task Id': task.get('task_id'),
        'Type': params.get('type'),
        'Target': params.get('target'),
        'Source': params.get('source')
    }


def dossier_source_list_command(client: BloxOneTDClient) -> CommandResults:
    sources = client.dossier_source_list()
    return CommandResults(
        outputs_prefix='BloxOneTD',
        outputs={'DossierSource': sources},
    )


def validate_and_format_lookalike_domain_list_args(args: Dict) -> Dict:
    if len(list(filter(bool, [args.get('filter'), args.get('target_domain'), args.get('detected_at')]))) != 1:
        raise DemistoException(
            "Please provide one of the following arguments 'target_domain', 'detected_at' or 'filter'"
            " (Exactly one of them, more than one is argument is not accepted)."
        )

    if args.get('detected_at'):
        detected_at = dateparser.parse(args['detected_at'], settings={'TIMEZONE': 'UTC', 'TO_TIMEZONE': 'UTC'})
        if detected_at is None:
            raise DemistoException(f"could not parse {args['detected_at']} as a time value.")
        args['detected_at'] = detected_at.replace(tzinfo=None).isoformat(timespec='milliseconds')
    return args


def lookalike_domain_list_command(client: BloxOneTDClient, args: Dict) -> CommandResults:
    args = validate_and_format_lookalike_domain_list_args(args)

    data = client.lookalike_domain_list(
        user_filter=args.get('filter'),
        target_domain=args.get('target_domain'),
        detected_at=args.get('detected_at'),
        limit=arg_to_number(args.get('limit')) or 50,
        offset=arg_to_number(args.get('offset')) or 0
    )
    readable_outputs = tableToMarkdown('Results', data, headerTransform=camelize_string)
    return CommandResults(
        outputs_prefix='BloxOneTD.LookalikeDomain',
        outputs=data,
        readable_output=readable_outputs
    )


def dossier_lookup_get_command_results(data: Dict) -> CommandResults:
    headers = ['Task Id', 'Type', 'Target', 'Source']
    outputs = data.get('results', [])
    readable_output_data = list(map(dossier_lookup_task_output, outputs))
    readable_output = tableToMarkdown(name='Lookalike Domain List', t=readable_output_data, headers=headers)
    return CommandResults(
        outputs_prefix='BloxOneTD.DossierLookup',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=data
    )


def dossier_lookup_get_schedule_polling_result(args: Dict, first_time: bool = False) -> CommandResults:
    next_run_in_seconds = arg_to_number(args.get('interval_in_seconds')) or 10
    timeout_in_seconds = arg_to_number(args.get('timeout')) or 600
    args['timeout'] = timeout_in_seconds - next_run_in_seconds
    scheduled_command = ScheduledCommand(
        command='bloxone-td-dossier-lookup-get',
        next_run_in_seconds=next_run_in_seconds,
        timeout_in_seconds=timeout_in_seconds,
        args=args
    )
    readable_output = None if not first_time else f"Job '{args['job_id']}' is still running, it may take a little while..."

    return CommandResults(readable_output=readable_output, scheduled_command=scheduled_command)


def dossier_lookup_get_command(client: BloxOneTDClient, args: Dict) -> CommandResults:
    job_id = args.get('job_id')
    first_time = False
    if job_id is None:
        job_id = client.dossier_lookup_get_create(args['indicator_type'], args['value'], sources=argToList(args.get('sources')))
        first_time = True

    if client.dossier_lookup_get_is_done(job_id):
        data = client.dossier_lookup_get_results(job_id)
        return dossier_lookup_get_command_results(data)
    args['job_id'] = job_id
    return dossier_lookup_get_schedule_polling_result(args, first_time)


def command_test_module(client: BloxOneTDClient) -> str:
    client.dossier_source_list()
    return 'ok'


def main():
    params = demisto.params()
    client = BloxOneTDClient(
        api_key=params['credentials']['password'],
        verify=not argToBoolean(params.get('insecure', False)),
        proxy=argToBoolean(params.get('proxy', False))
    )
    commands_with_args = {
        'bloxone-td-dossier-lookup-get': dossier_lookup_get_command,
        'bloxone-td-lookalike-domain-list': lookalike_domain_list_command,
    }

    commands_without_args = {
        'test-module': command_test_module,
        'bloxone-td-dossier-source-list': dossier_source_list_command,

    }

    command = demisto.command()
    try:
        if command in commands_without_args:
            results = commands_without_args[command](client)
        elif command in commands_with_args:
            results = commands_with_args[command](client, demisto.args())
        else:
            raise NotImplementedError(f'command {command} is not implemented.')
        return_results(results)
    except Exception as e:
        auth_error = isinstance(e, DemistoException) and e.res is not None and \
            e.res.status_code == 401  # pylint: disable=E1101
        if auth_error:
            error_msg = 'authentication error'
        else:
            error_msg = f'an error occurred while executing command {command}\nerror: {e}'

        return_error(error_msg, e)


if __name__ in ('__main__', 'builtins'):
    main()
