import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
import requests
import traceback
from typing import Dict, Any, Callable

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member
SERVER_URL = 'https://www.hybrid-analysis.com/api/v2'
SEARCH_TERM_QUERY_ARGS = ('filename', 'filetype', 'filetype_desc', 'env_id', 'country', 'verdict', 'av_detect',
                          'vx_family', 'tag', 'date_from', 'date_to', 'port', 'host', 'domain', 'url', 'similar_to',
                          'context', 'imp_hash', 'ssdeep', 'authentihash')
# envid repeated for bw compatibility. Must be in this order so old overrides new default
SUBMISSION_PARAMETERS = ('environmentID', 'environmentId', 'no_share_third_party', 'allow_community_access',
                         'no_hash_lookup',
                         'action_script', 'hybrid_analysis', 'experimental_anti_evasion', 'script_logging',
                         'input_sample_tampering', 'network_settings', 'email', 'comment', 'custom_cmd_line',
                         'custom_run_time', 'submit_name', 'priority', 'document_password', 'environment_variable',
                         )


class Client(BaseClient):

    def get_environments(self):
        return self._http_request(method='GET', url_suffix='/system/environments')

    def get_screenshots(self, key: str):
        return self._http_request(method='GET', url_suffix=f'/report/{key}/screenshots')

    def search(self, query_args: Dict[str, Any]):
        self._headers['Content-Type'] = 'application/x-www-form-urlencoded'
        return self._http_request(method='POST', url_suffix='/search/terms', data=query_args)

    def scan(self, files: List[str]):
        self._headers['Content-Type'] = 'application/x-www-form-urlencoded'
        return self._http_request(method='POST', url_suffix='/search/hashes', data={'hashes[]': files})

    def analysis_overview(self, sha256hash: str):
        return self._http_request(method='GET', url_suffix=f'/overview/{sha256hash}')

    def analysis_overview_summary(self, sha256hash: str):
        return self._http_request(method='GET', url_suffix=f'/overview/{sha256hash}/summary')

    def analysis_overview_refresh(self, sha256hash: str):
        self._http_request(method='GET', url_suffix=f'/overview/{sha256hash}/refresh')

    def get_report(self, key: str, filetype: str):
        return self._http_request(method='GET', url_suffix=f'/report/{key}/report/{filetype}', resp_type='all',
                                  ok_codes=(200, 404))

    def get_state(self, key: str):
        return self._http_request(method='GET', url_suffix=f'/report/{key}/state')

    def submit_url(self, url: str, params: Dict[str, Any]):
        return self._http_request(method='POST', data={'url': url, **params},
                                  url_suffix='/submit/url')

    def submit_file(self, file_contents: Dict, params: Dict[str, Any]):
        return self._http_request(method='POST', data=params, url_suffix='/submit/file',
                                  files={'file': (file_contents['name'], open(file_contents['path'], 'rb'))})

    def download_sample(self, sha256hash: str):
        return self._http_request(method='GET', url_suffix=f'/overview/{sha256hash}/sample', resp_type='response')


# for BW compatibility with v1 we need to return same object keys
def map_dict_keys(obj: Dict, map_rules: Dict[str, str], only_given_fields: bool = False) -> Dict[Any, Any]:
    """
    This function will switch the keys of a dictionary according to the provided map_rules.
    Example: map_dict_keys( {'a' : 'b', 'c' : 'd' }, {'a' : 'y', 'c' : 'z' }) -> {'y' : 'b' , 'z' : 'd'}

    @param obj: The original dictionary
    @param map_rules: The mapping the keys should be changed by
    @param only_given_fields: whether fields besides for those in map_rules should be used
    @return: a Dict according to the map_rules
    """
    return {map_rules.get(key, key): obj[key] for key in obj.keys() if not only_given_fields or key in map_rules}


def translate_verdict(param: str) -> int:
    return {
        'Whitelisted': 1,
        'NoVerdict': 2,
        'NoSpecificThreat': 3,
        'Suspicious': 4,
        'Malicious': 5
    }[param]


def split_query_to_term_args(query: str) -> Dict[str, Any]:
    def get_value(term: str) -> str:
        return term[term.index(':') + 1:].strip()

    def get_key(term: str) -> str:
        return term[:term.index(':')].strip()

    return {get_key(term): get_value(term) for term in query.split(',') if get_value(term)}


def validated_term(key: str, val):
    if key == 'verdict':
        return translate_verdict(val)
    if key == 'country' and len(val) != 3:
        raise ValueError('Country ISO code should be 3 characters long')
    return val


def validated_search_terms(query_args: Dict[str, Any]) -> Dict[str, Any]:
    if len(query_args) == 0:
        raise ValueError('Must have at least one search term')
    return {key: validated_term(key, query_args[key]) for key in query_args}


def get_search_term_args(args: Dict[str, Any]) -> Dict[str, Any]:
    if args.get('query'):
        return split_query_to_term_args(args['query'])
    else:
        return {term: args[term] for term in SEARCH_TERM_QUERY_ARGS if args.get(term, None)}


def get_api_id(args: Dict[str, Any]) -> str:
    # must fist check environmentId (deprecated) to override default args of environmentID
    if args.get('file') and (args.get('environmentId') or args.get('environmentID')):
        return f"{args['file']}:{args.get('environmentId') or args.get('environmentID')}"
    elif args.get('JobID'):
        return args['JobID']
    else:
        raise ValueError('Must supply JobID or environmentID and file')


def test_module(client: Client, _) -> str:
    """Tests API connectivity and authentication'
    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.get_environments()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_default_file_name(filetype: str) -> str:
    return f'CrowdStrike_report_{round(time.time())}.{get_file_suffix(filetype)}'


def get_file_suffix(filetype: str = 'bin') -> str:  # check this
    if filetype in ('pcap', 'bin', 'xml', 'html'):
        return 'gz'
    if filetype == 'json':
        return 'json'
    if filetype in ('misp', 'stix'):
        return 'xml'
    return filetype


def has_error_state(client: Client, key: str) -> bool:
    state = client.get_state(key)
    demisto.debug(f'state to check if should poll response: {state}')
    if state['state'] == 'ERROR':
        raise Exception(f'Got Error state from server: {state}')
    return False


class BWCFile(Common.File):
    def __init__(self, bwc_fields: Dict, key_change_map: Dict, only_given_fields, *args, **kwargs):
        super(BWCFile, self).__init__(*args, **kwargs)
        self.bwc_fields = bwc_fields
        self.key_change_map = key_change_map
        self.only_given_fields = only_given_fields

    def to_context(self):
        super_ret = super().to_context()
        for key in super_ret.keys():
            if key.startswith('File'):
                super_ret[key].update(map_dict_keys(self.bwc_fields, self.key_change_map, self.only_given_fields))
        return super_ret


def create_scan_results_readable_output(scan_response):
    table_field_dict = {
        'submit_name': 'submit name',
        'threat_level': 'threat level',
        'threat_score': 'threat score',
        'verdict': 'verdict',
        'total_network_connections': 'total network connections',
        'target_url': 'target url',
        'classification_tags': 'classification tags',
        'total_processes': 'total processes',
        'environment_description': 'environment description',
        'interesting': 'interesting',
        'environment_id': 'environment id',
        'url_analysis': 'url analysis',
        'analysis_start_time': 'analysis start time',
        'total_signatures': 'total signatures',
        'type': 'type',
        'type_short': 'type short',
        'vx_family': 'Malware Family',
        'sha256': 'sha256'

    }
    return tableToMarkdown('Scan Results:', scan_response, headers=list(table_field_dict.keys()),
                           headerTransform=lambda x: table_field_dict.get(x, x), removeNull=True)


def get_dbot_score(filehash, threat_score: int) -> Common.DBotScore:
    def calc_score():
        return {3: 0,
                2: 3,
                1: 2,
                0: 1}.get(threat_score, 0)

    return Common.DBotScore(indicator=filehash, integration_name='CrowdStrike Falcon Sandbox V2',
                            indicator_type=DBotScoreType.FILE, score=calc_score(),
                            malicious_description=f'Score of {calc_score()}',
                            reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(
                                demisto.params().get('integrationReliability')))


def get_submission_arguments(args: Dict[str, Any]) -> Dict[str, Any]:
    return {camel_case_to_underscore(arg): args[arg] for arg in SUBMISSION_PARAMETERS if args.get(arg)}


def submission_response(client, response, polling) -> List[CommandResults]:
    submission_res = [CommandResults(outputs_prefix='CrowdStrike.Submit', outputs_key_field='submission_id',
                                     raw_response=response, outputs=response,
                                     readable_output=tableToMarkdown('Submission Data:', response,
                                                                     headerTransform=underscore_to_space)),
                      CommandResults('CrowdStrike.JobID', outputs=response.get('job_id'),
                                     readable_output=f"JobID: {response.get('job_id')}"),
                      CommandResults('CrowdStrike.EnvironmentID', outputs=response.get('environment_id'),
                                     readable_output=f"EnvironmentID: {response.get('environment_id')}")]

    if not polling:
        return submission_res
    else:
        return_results(submission_res)  # return early
    return crowdstrike_scan_command(client, {'file': response.get('sha256'), 'JobID': response.get('job_id'),
                                             'polling': True})


def crowdstrike_submit_url_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    submission_args = get_submission_arguments(args)
    url = args['url']
    response = client.submit_url(url, submission_args)
    return submission_response(client, response, args.get('polling'))


def crowdstrike_submit_sample_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    file_contents = demisto.getFilePath(args['entryId'])
    submission_args = get_submission_arguments(args)
    response = client.submit_file(file_contents, submission_args)
    return submission_response(client, response, args.get('polling'))


def crowdstrike_analysis_overview_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.analysis_overview(args['file'])
    file = Common.File(Common.DBotScore.NONE, sha256=result.get('sha256'), size=result.get('size'),
                       file_type=result.get('type'), name=result.get('last_file_name'))

    table_cols = ['last_file_name', 'threat_score', 'other_file_name', 'sha256', 'verdict', 'url_analysis', 'size',
                  'type', 'type_short']

    return CommandResults(
        outputs_prefix='CrowdStrike.AnalysisOverview',
        outputs_key_field='sha256',
        outputs=result,
        raw_response=result,
        indicator=file,
        readable_output=tableToMarkdown('Analysis Overview:', result, headers=table_cols,
                                        headerTransform=underscore_to_space,
                                        removeNull=True)
    )


def crowdstrike_search_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    query_args: Dict = get_search_term_args(args)
    query_args = validated_search_terms(query_args)
    response = client.search(query_args)

    key_name_changes = {'job_id': 'JobID',
                        'sha256': 'SHA256',
                        'environment_id': 'environmentId',
                        'threat_score': 'threatscore',
                        'environment_description': 'environmentDescription',
                        'submit_name': 'submitname',
                        'analysis_start_time': 'start_time'}

    # each indicator needs its own CR since indicators is deprecated.
    def convert_to_file_res(res) -> CommandResults:
        return CommandResults(
            readable_output=tableToMarkdown('Search Results:', res, removeNull=True,
                                            headerTransform=underscore_to_space,
                                            headers=['submit_name', 'verdict', 'vx_family', 'threat_score', 'sha256',
                                                     'size',
                                                     'environment_id', 'type', 'type_short', 'analysis_start_time']),
            indicator=BWCFile(res, key_name_changes, False, size=res.get('size'),
                              sha256=res.get('sha256'),
                              dbot_score=Common.DBotScore.NONE,
                              extension=res.get('type_short'),
                              name=res.get('submit_name'),
                              malware_family=res.get('vx_family')))

    return [CommandResults(
        raw_response=response, outputs_prefix='CrowdStrike.Search',
        outputs_key_field='sha256', outputs=response.get('result'),
        readable_output=f"Search returned {response.get('count')} results"),
        *[convert_to_file_res(res) for res in response.get('result')]]


@poll('cs-falcon-sandbox-scan')
def crowdstrike_scan_command(client: Client, args: Dict[str, Any]):
    hashes = args['file'].split(',')
    scan_response = client.scan(hashes)

    def file_with_bwc_fields(res):
        return CommandResults(
            readable_output=create_scan_results_readable_output(res),
            indicator=BWCFile(res, only_given_fields=False, size=res.get('size'),
                              file_type=res.get('type'), sha1=res.get('sha1'),
                              sha256=res.get('sha256'), md5=res.get('md5'), sha512=res.get('sha512'),
                              name=res.get('submit_name'),
                              ssdeep=res.get('ssdeep'), malware_family=res.get('vx_family'),
                              dbot_score=get_dbot_score(res.get('sha256'), res.get('threat_level')),
                              key_change_map={
                                  'sha1': 'SHA1', 'sha256': 'SHA256', 'md5': 'MD5',
                                  'job_id': 'JobID', 'environment_id': 'environmentId',
                                  'threat_score': 'threatscore', 'environment_description': 'environmentDescription',
                                  'submit_name': 'submitname', 'url_analysis': 'isurlanalysis',
                                  'interesting:': 'isinteresting', 'vx_family': 'family'},
                              )
        )

    command_result = [CommandResults(outputs_prefix='CrowdStrike.Report',
                                     raw_response=scan_response, outputs=scan_response,
                                     readable_output=f'Scan returned {len(scan_response)} results'),
                      *[file_with_bwc_fields(res) for res in scan_response]]
    if len(scan_response) != 0:
        return PollResult(command_result)
    try:
        if len(hashes) == 1:
            key = get_api_id(args)
            demisto.debug(f'key found for poll state: {key}')
            return PollResult(continue_to_poll=lambda: not has_error_state(client, key), response=command_result)
    except ValueError:
        demisto.debug(f'Cannot get a key to check state for {hashes}')
    return PollResult(continue_to_poll=True, response=command_result)


def crowdstrike_analysis_overview_summary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.analysis_overview_summary(args['file'])
    return CommandResults(
        outputs_prefix='CrowdStrike.AnalysisOverview',
        outputs_key_field='sha256',
        outputs=result,
        raw_response=result,
        readable_output=tableToMarkdown('Analysis Overview Summary:', result,
                                        headerTransform=lambda x: {'analysis_start_time': 'Analysis Start Time',
                                                                   'last_multi_scan': 'Last Multi Scan',
                                                                   'multiscan_result': 'Multiscan Result',
                                                                   'threat_score': 'Threat Score',
                                                                   'verdict': 'Verdict',
                                                                   'sha256': 'Sha256'
                                                                   }.get(x, x), removeNull=True)

    )


def crowdstrike_analysis_overview_refresh_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    client.analysis_overview_refresh(args['file'])
    return CommandResults(readable_output='The request to refresh the analysis overview was sent successfully.')


@poll('cs-falcon-sandbox-result')
def crowdstrike_result_command(client: Client, args: Dict[str, Any]):
    key = get_api_id(args)
    report_response = client.get_report(key, args['file-type'])
    demisto.debug(f'get report response code: {report_response.status_code}')
    successful_response = report_response.status_code == 200

    if successful_response:
        ret_list = [fileResult(get_default_file_name(args['file-type']), report_response.content,
                               file_type=EntryType.ENTRY_INFO_FILE)]
        if args.get('file'):
            ret_list.append(crowdstrike_scan_command(client, args))
        return PollResult(ret_list)

    else:
        error_response = CommandResults(raw_response=report_response,
                                        readable_output='Falcon Sandbox returned an error: status code '
                                                        + f'{report_response.status_code}, response: '
                                                        + f'{report_response.text}',
                                        entry_type=entryTypes['error'])

        return PollResult(continue_to_poll=lambda: not has_error_state(client, key), response=error_response)


def underscore_to_space(x: str) -> str:
    return pascalToSpace(underscoreToCamelCase(x))


def crowdstrike_report_state_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    key = get_api_id(args)
    state = client.get_state(key)
    return CommandResults(outputs_prefix='CrowdStrike.State', raw_response=state, outputs=state,
                          readable_output=tableToMarkdown('State', state, headerTransform=underscore_to_space))


def crowdstrike_get_environments_command(client: Client, _) -> CommandResults:
    environments = client.get_environments()
    environments = [map_dict_keys(env, {'environment_id': 'ID', 'total_virtual_machines': 'VMs_total',
                                        'analysis_mode': 'analysisMode', 'group_icon': 'groupicon',
                                        'busy_virtual_machines': 'VMs_busy'}) for env in environments]

    readable_output_column_conversion = {
        'ID': '_ID', 'description': 'Description', 'architecture': 'Architecture',
        'VMs_total': 'Total VMS', 'VMs_busy': 'Busy VMS', 'analysisMode': 'Analysis mode',
        'groupicon': 'Group icon'
    }
    return CommandResults(
        outputs_prefix='CrowdStrike.Environment',
        outputs_key_field='id',
        outputs=environments,
        readable_output=tableToMarkdown('Execution Environments:',
                                        environments, list(readable_output_column_conversion.keys()), removeNull=True,
                                        headerTransform=lambda x: readable_output_column_conversion[x]),
        raw_response=environments
    )


def crowdstrike_get_screenshots_command(client: Client, args: Dict[str, Any]):
    def to_image_result(image: Dict):
        return fileResult(image['name'], base64.b64decode(image['image']), entryTypes['entryInfoFile'])

    key = get_api_id(args)
    ret = [to_image_result(image) for image in client.get_screenshots(key)]
    return ret if len(ret) > 0 else CommandResults(readable_output='No screenshots returned')


def crowdstrike_sample_download_command(client: Client, args: Dict[str, Any]) -> List:
    hash_value = args['file']
    response = client.download_sample(hash_value)
    file_name = response.headers.get('Vx-Filename', hash_value + '.gz')

    command_results = CommandResults(
        readable_output=f'Requested sample is available for download under the name {file_name}'
    )
    return [command_results, fileResult(file_name, data=response.content, file_type=EntryType.FILE)]


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: Dict = {
            'api-key': demisto.params().get('credentials', {}).get('password'),
            'User-Agent': 'Falcon Sandbox'
        }

        client = Client(
            base_url=SERVER_URL,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)
        command: Callable
        if demisto.command() in ['test-module']:
            command = test_module
        elif demisto.command() in ['cs-falcon-sandbox-search', 'crowdstrike-search']:
            command = crowdstrike_search_command
        elif demisto.command() in ['cs-falcon-sandbox-scan', 'crowdstrike-scan', 'file']:
            command = crowdstrike_scan_command
        elif demisto.command() in ['crowdstrike-get-environments', 'cs-falcon-sandbox-get-environments']:
            command = crowdstrike_get_environments_command
        elif demisto.command() in ['cs-falcon-sandbox-get-screenshots', 'crowdstrike-get-screenshots']:
            command = crowdstrike_get_screenshots_command
        elif demisto.command() in ['cs-falcon-sandbox-result', 'crowdstrike-result']:
            command = crowdstrike_result_command
        elif demisto.command() in ['cs-falcon-sandbox-analysis-overview']:
            command = crowdstrike_analysis_overview_command
        elif demisto.command() in ['cs-falcon-sandbox-analysis-overview-summary']:
            command = crowdstrike_analysis_overview_summary_command
        elif demisto.command() in ['cs-falcon-sandbox-analysis-overview-refresh']:
            command = crowdstrike_analysis_overview_refresh_command
        elif demisto.command() in ['crowdstrike-submit-sample', 'cs-falcon-sandbox-submit-sample']:
            command = crowdstrike_submit_sample_command
        elif demisto.command() in ['cs-falcon-sandbox-submit-url', 'crowdstrike-submit-url']:
            command = crowdstrike_submit_url_command
        elif demisto.command() in ['cs-falcon-sandbox-sample-download']:
            command = crowdstrike_sample_download_command
        elif demisto.command() in ['cs-falcon-sandbox-report-state']:
            command = crowdstrike_report_state_command
        else:
            raise NotImplementedError(f'Command not implemented: {demisto.command()}')

        return_results(command(client, args))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
