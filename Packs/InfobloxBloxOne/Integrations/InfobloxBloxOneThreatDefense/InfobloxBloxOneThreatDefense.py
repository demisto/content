from CommonServerPython import *
from CommonServerUserPython import *
import demistomock as demisto


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

    def lookalike_domain_list(self, *, user_filter: Optional[str] = None,
                              target_domain: Optional[str] = None, detected_at: Optional[str] = None,
                              limit: int = 50, offset: Optional[int] = None) -> List[Dict]:
        url_suffix = '/api/tdlad/v1/lookalike_domains'
        filter_params = {key: val for key, val in [('_limit', limit), ('_offset', offset)] if val}

        if user_filter:
            _filter = user_filter
        elif target_domain:
            _filter = f'target_domain=="{target_domain}"'
        else: # detected_at != None
            _filter = f'detected_at>="{detected_at}"'

        filter_params['_filter'] = _filter

        return self._http_request('GET', url_suffix=url_suffix, params=filter_params).get('results', [])

    def dossier_lookup_get_create(self, indicator_type: str, value: str, *, sources: Optional[List[str]] = None) -> str:
        url_suffix = f'/tide/api/services/intel/lookup/indicator/{indicator_type}'
        params = {'value': value}
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
        'task_id': task.get('task_id'),
        'type': params.get('type'),
        'target': params.get('target'),
        'source': params.get('source')
    }


def dossier_source_list_command(client: BloxOneTDClient) -> CommandResults:
    sources = client.dossier_source_list()
    return CommandResults(
        outputs_prefix='BloxOneTD',
        outputs={'DossierSource': sources},
    )


def validate_and_format_lookalike_domain_list_args(args: Dict) -> Dict:
    match len(list(filter(bool, [args.get('filter'), args.get('target_domain'), args.get('detected_at')]))):
        case 0:
            raise ValueError("You must spesify one of the following arguments 'target_domain', 'detected_at' or 'filter'.")
        case 1:
            pass
        case _:
            raise ValueError("You can spesify one of the following arguments 'target_domain', 'detected_at' or 'filter' not more.")

    if args.get('detected_at'):
        try:
            args['detected_at'] = dateparser.parse(args['detected_at']).isoformat()
        except AttributeError:
            raise DemistoException(f"could not parse {args['detected_at']} as a time value.")
    return args


def lookalike_domain_list_command(client: BloxOneTDClient, args: Dict) -> CommandResults:
    args = validate_and_format_lookalike_domain_list_args(args)

    data = client.lookalike_domain_list(
        user_filter=args.get('filter'),
        target_domain=args.get('target_domain'),
        detected_at=args.get('detected_at'),
        limit=int(args.get('limit', 50)),
        offset=int(args.get('offset', 0))
    )
    return CommandResults(
        outputs_prefix='BloxOneTD.LookalikeDomain',
        outputs=data,
    )


def dossier_lookup_get_command_results(data: Dict) -> CommandResults:
    headers_map = {'task_id': 'Task Id', 'type': 'Type', 'target': 'Target', 'source': 'Source'}
    outputs = list(map(dossier_lookup_task_output, data.get('results', [])))
    readable_output = tableToMarkdown(name='Lookalike Domain List', t=outputs, headers=[], headerTransform=lambda x: headers_map[x])
    return CommandResults(
        outputs_prefix='BloxOneTD.DossierLookup',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=data
    )


def dossier_lookup_get_schedule_polling_result(args: Dict) -> CommandResults:
    next_run_in_seconds = int(args.get('interval_in_seconds', 10))
    timeout_in_seconds = int(args.get('timeout', 600))
    args['timeout'] = timeout_in_seconds - next_run_in_seconds
    scheduled_command = ScheduledCommand(
        command='bloxone-td-dossier-lookup-get',
        next_run_in_seconds=next_run_in_seconds,
        timeout_in_seconds=timeout_in_seconds,
        args=args
    )

    return CommandResults(
        readable_output='Job is still running, it may take a little while...',
        scheduled_command=scheduled_command
    )


def dossier_lookup_get_command(client: BloxOneTDClient, args: Dict) -> CommandResults:
    job_id = args.get('job_id')
    if job_id is not None:
        if client.dossier_lookup_get_is_done(job_id):
            data = client.dossier_lookup_get_results(job_id)
            return dossier_lookup_get_command_results(data)
    else:
        job_id = client.dossier_lookup_get_create(args['indicator_type'], args['value'], sources=argToList(args.get('sources')))
    args['job_id'] = job_id
    return dossier_lookup_get_schedule_polling_result(args)


def test_module_command(client: BloxOneTDClient) -> str:
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
        'test-module': test_module_command,
        'bloxone-td-dossier-source-list': dossier_source_list_command,

    }

    command = demisto.command()
    try:
        if command in commands_with_args:
            results = commands_with_args[command](client, demisto.args())
        elif command in commands_without_args:
            results = commands_without_args[command](client)
        else:
            raise NotImplementedError(f'command {command} is not implemented.')
        return_results(results)
    except SyntaxError as e:
        return_error(f'an error occurred while executing command {command}\nerror: {e}', e)


if __name__ in ('__main__', 'builtins'):
    main()
