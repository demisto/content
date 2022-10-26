from typing import Tuple
from CommonServerPython import *
from html_to_json import convert


BASE_URL = 'https://api.threatvault.paloaltonetworks.com/service/v1/'
SCORE_TABLE_FILE = {
    'unknown': Common.DBotScore.NONE,
    'benign': Common.DBotScore.GOOD,
    'grayware': Common.DBotScore.SUSPICIOUS,
    'malicious': Common.DBotScore.BAD
}
LIST_OF_RN_KEYS = [
    'spyware',
    'vulnerability',
    'fileformat',
    'antivirus',
    'file_type', 
    'data_correlation',
    'decoders',
    'applications'
]


class Client(BaseClient):
    """
    Client to use in the Threat Vault integration. Overrides BaseClient.
    """

    def __init__(self, api_key: str, verify: bool, proxy: bool, reliability: str):
        super().__init__(base_url=BASE_URL, verify=verify, proxy=proxy,
                         headers={'Content-Type': 'application/json', 'X-API-KEY': api_key})

        self.name = 'ThreatVault'
        self.reliability = reliability

    def antivirus_signature_get_request(self, arg: str, value: str) -> dict:

        params = {arg: value}
        suffix = 'threats'

        return self._http_request(method='GET', url_suffix=suffix, params=params)

    def release_notes_get_request(self, type_: str, version: str) -> dict:

        params = {'type': type_, 'version': version}
        suffix = 'release-notes'

        return self._http_request(method='GET', url_suffix=suffix, params=params)

    def threat_batch_search_request(self, arg: str, value: list, type_: str) -> dict:

        params: dict[str, Union[list, str]] = {arg: value}
        if type_:
            params['type'] = type_
        params = json.dumps(params)
        suffix = 'threats'

        return self._http_request(method='POST', url_suffix=suffix, data=params)

    def threat_search_request(self, args: dict) -> dict:

        suffix = 'threats'
        return self._http_request(method='GET', url_suffix=suffix, params=args)


'''
HELP FUNCTIONS
'''


def pagination(page: Optional[int], page_size: Optional[int], limit: Optional[int]) -> Tuple[Optional[int], Optional[int]]:

    if page and page_size:
        if page < 0:
            raise ValueError('The page argument ')
        return page * page_size, page_size

    if not page and not page_size:
        return 0, limit

    raise ValueError("When using a pagination, it must be used with the following two arguments -> "
                     "[page, page_size]")


def resp_to_hr(response: dict, type_: str, extra: bool = False) -> dict:

    match type_:
        case 'file':
            antivirus = (response.get('signatures', {}).get('antivirus', [])[0]
                         if response.get('signatures', {}).get('antivirus', []) else {})
            table_for_md = {'Active': antivirus.get('status', None),
                            'CreateTime': response.get('create_time', None),
                            'Release': antivirus.get('release', None),
                            'SignatureId': antivirus.get('id', None),
                            'FileType': response.get('filetype', None),
                            'MD5': response.get('md5', None),
                            'SHA256': response.get('sha256', None),
                            'SHA1': response.get('sha1', None),
                            }
            if extra:
                table_for_md.update({
                    'Family': response.get('family', None),
                    'Platform': response.get('platform', None),
                    'Signature Name': antivirus.get('name', None),
                    'Severity': antivirus.get('severity', None),
                    'Description': antivirus.get('description', None),
                    'Size': response.get('size', None),
                    'Wildfire verdict': response.get('wildfire_verdict', None),
                })

        case 'fileformat':
            table_for_md = {'ID': response.get('id'),
                            'Name': response.get('name', None),
                            'Description': response.get('Description', None),
                            'Category': response.get('category', None),
                            'Severity': response.get('severity', None),
                            'Default action': response.get('default_action', None),
                            'Vendor': response.get('vendor', None),
                            'Reference': response.get('reference', None),
                            'Status': response.get('status', None),
                            'Ori release version': response.get('ori_release_version', None),
                            'Latest release version': response.get('latest_release_version', None),
                            'Ori release time': response.get('ori_release_time', None),
                            'Latest release time': response.get('latest_release_time', None),
                            }

        case 'vulnerability':
            table_for_md = {'ID': response.get('id'),
                            'Name': response.get('name', None),
                            'Description': response.get('Description', None),
                            'Category': response.get('category', None),
                            'Severity': response.get('severity', None),
                            'Default action': response.get('default_action', None),
                            'Vendor': response.get('vendor', None),
                            'Reference': response.get('reference', None),
                            'Status': response.get('status', None),
                            'Ori release version': response.get('ori_release_version', None),
                            'Latest release version': response.get('latest_release_version', None),
                            'Ori release time': response.get('ori_release_time', None),
                            'Latest release time': response.get('latest_release_time', None),
                            'CVE': response.get('cve', None),
                            }

        case 'antivirus':
            table_for_md = {'ID': response.get('id'),
                            'Name': response.get('name', None),
                            'Description': response.get('Description', None),
                            'Subtype': response.get('subtype', None),
                            'Severity': response.get('severity', None),
                            'Default action': response.get('default_action', None),
                            'Create time': response.get('create_time', None),
                            'Related sha256 hashes': response.get('related_sha256_hashes', None),
                            'Release': response.get('release', None),
                            }

        case 'spyware':
            table_for_md = {'ID': response.get('id'),
                            'Name': response.get('name', None),
                            'Description': response.get('description', None),
                            'Vendor': response.get('vendor', None),
                            'Severity': response.get('severity', None),
                            'Default action': response.get('default_action', None),
                            'Details': response.get('details', None),
                            'Reference': response.get('reference', None),
                            'Status': response.get('status', None),
                            'Min version': response.get('min_version', None),
                            'Max version': response.get('max_version', None),
                            'CVE': response.get('cve', None),
                            }

        case 'release_notes':
            applications = response.get('release_notes', {}).get('applications', {})
            spyware = response.get('release_notes', {}).get('spyware', {})
            vulnerability = response.get('release_notes', {}).get('vulnerability', {})
            table_for_md = {
                'Release version': response.get('release_version'),
                'Content version': response.get('content_version'),
                'type': response.get('type'),
                'Notes': response.get('release_notes', {}).get('notes'),
                'New applications': applications.get('new'),
                'Modified applications': applications.get('modified'),
                'Obsoleted applications': applications.get('obsoleted'),
                'New Spyware': spyware.get('new'),
                'Modified Spyware': spyware. get('modified'),
                'Disabled Spyware': spyware. get('modified'),
                'New Vulnerability': vulnerability.get('new')[0] if vulnerability.get('new') else None,
                'Modified Vulnerability': vulnerability.get('modified')[0] if vulnerability.get('modified') else None,
                'Disabled Vulnerability': vulnerability.get('disabled')[0] if vulnerability.get('disabled') else None,
                'Release time': response.get('release_time'),
            }

        case _:
            return {}

    return table_for_md


def parse_resp_by_type(response: dict, expanded: bool = False) -> List[CommandResults]:

    command_results_list: List[CommandResults] = []

    if 'antivirus' in response['data']:
        if expanded:
            antiviruses = response.get('data', {}).get('antivirus', [])
        else:
            antiviruses = [response.get('data', {}).get('antivirus', [])[0]]

        for antivirus in antiviruses:
            table_for_md = resp_to_hr(response=antivirus, type_='antivirus')
            readable_output = tableToMarkdown(name=f"{antivirus.get('id')} antivirus reputation:", t=table_for_md,
                                              removeNull=True)
            command_results_list.append(
                CommandResults(
                    outputs_prefix='ThreatVault.antivirus',
                    outputs_key_field='id',
                    outputs=response.get('data', {}).get('antivirus', []),
                    readable_output=readable_output,
                )
            )

    if 'spyware' in response['data']:
        if expanded:
            spywares = response.get('data', {}).get('spyware', [])
        else:
            spywares = [response.get('data', {}).get('spyware', [])[0]]
        for spyware in spywares:
            table_for_md = resp_to_hr(response=spyware, type_='spyware')
            readable_output = tableToMarkdown(name=f"{spyware.get('id')} spyware reputation:", t=table_for_md,
                                              removeNull=True)
            command_results_list.append(
                CommandResults(
                    outputs_prefix='ThreatVault.spyware',
                    outputs_key_field='id',
                    outputs=response.get('data', {}).get('spyware', []),
                    readable_output=readable_output,
                )
            )

    if 'vulnerability' in response['data']:
        if expanded:
            vulnerabilities = response.get('data', {}).get('vulnerability', [])
        else:
            vulnerabilities = [response.get('data', {}).get('vulnerability', [])[0]]
        for vulnerability in vulnerabilities:
            table_for_md = resp_to_hr(response=vulnerability, type_='vulnerability')
            readable_output = tableToMarkdown(name=f"{vulnerability.get('id')} vulnerability reputation:", t=table_for_md,
                                              removeNull=True)
            command_results_list.append(
                CommandResults(
                    outputs_prefix='ThreatVault.vulnerability',
                    outputs_key_field='id',
                    outputs=response.get('data', {}).get('vulnerability', []),
                    readable_output=readable_output,
                )
            )

    if 'fileformat' in response['data']:
        if expanded:
            filesformat = response.get('data', {}).get('fileformat', [])
        else:
            filesformat = [response.get('data', {}).get('fileformat', [])[0]]
        for fileformat in filesformat:
            table_for_md = resp_to_hr(response=vulnerability, type_='fileformat')
            readable_output = tableToMarkdown(name=f"{fileformat.get('id')} fileformat reputation:", t=table_for_md,
                                              removeNull=True)
            command_results_list.append(
                CommandResults(
                    outputs_prefix='ThreatVault.fileformat',
                    outputs_key_field='id',
                    outputs=response.get('data', {}).get('fileformat', []),
                    readable_output=readable_output,
                )
            )

    return command_results_list


def extract_rn_from_html_to_json(raw_incident):

    values: list = []
    if isinstance(raw_incident, list):
        for item in raw_incident:
            if isinstance(item, dict):
                values.extend(extract_rn_from_html_to_json(item))
    if isinstance(raw_incident, dict):
        for key in raw_incident.keys():
            if key == '_values':
                values.append({'Values': raw_incident['_values']})
            else:
                values.extend(extract_rn_from_html_to_json(raw_incident[key]))
    return values


def organization_release_notes(rn: list):

    release_notes = []
    for release_note in rn:
        rn_one = ' '.join(release_note['Values']).replace('\xa0', ' ')
        release_notes.append({'Release Note': rn_one})
    return release_notes


def parse_incident(incident: dict):

    table_for_md = organization_release_notes(
        extract_rn_from_html_to_json(
            convert(
                incident['data'][0]['release_notes']['notes'][0]
            )
        )
    )

    incident['data'][0]['release_notes_md'] = tableToMarkdown(
        name=f"Release version {incident['data'][0]['release_version']}:",
        t=table_for_md,
        removeNull=True
    )

    incident['data'][0]['Source name'] = 'THREAT VAULT - RELEASE NOTES'

    for key in incident['data'][0]['release_notes'].copy():
        if key in LIST_OF_RN_KEYS and not incident['data'][0]['release_notes'][key]['new']:
            del incident['data'][0]['release_notes'][key]

    return incident


'''
COMMANDS
'''


def file_command(client: Client, args: Dict) -> List[CommandResults]:
    """Get the reputation of a sha256 or a md5 representing an antivirus
    Args:
        client: Client object with request.
        args: Usually demisto.args()
    Returns:
        list of CommandResults.
    """
    hashes = argToList(args.get('file'))
    command_results_list: List[CommandResults] = []
    dbot_reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(client.reliability)

    for _hash in hashes:
        type_hash = get_hash_type(_hash)
        try:
            response = client.antivirus_signature_get_request(arg=type_hash, value=_hash)
            file_info: dict = response.get('data', {}).get('fileinfo')[0]
            dbot_score = Common.DBotScore(
                indicator=_hash,
                indicator_type=DBotScoreType.FILE,
                integration_name=client.name,
                score=SCORE_TABLE_FILE[file_info.get('wildfire_verdict', 'unknown')],
                reliability=dbot_reliability
            )
            file = Common.File(
                sha256=file_info.get('sha256', None),
                md5=file_info.get('md5', None),
                sha1=file_info.get('sha1', None),
                dbot_score=dbot_score
            )

            table_for_md = resp_to_hr(response=file_info, type_='file', extra=args.get('extra', False))

            readable_output = tableToMarkdown(name=f"Hash {_hash} antivirus reputation:", t=table_for_md,
                                              removeNull=True)
        except Exception as err:
            if 'Error in API call [404] - Not Found' in str(err):
                response = {}
                dbot_score = Common.DBotScore(
                    indicator=_hash,
                    indicator_type=DBotScoreType.FILE,
                    integration_name=client.name,
                    reliability=dbot_reliability,
                    score=Common.DBotScore.NONE
                )
                file = Common.File(
                    sha256=_hash if type_hash == 'sha256' else None,
                    md5=_hash if type_hash == 'md5' else None,
                    dbot_score=dbot_score
                )

                readable_output = f"Hash {_hash} antivirus reputation is unknown to Threat Vault."
            else:
                raise Exception(err)

        command_results = CommandResults(
            readable_output=readable_output,
            indicator=file
        )
        command_results_list.append(command_results)

    return command_results_list


def cve_command(client: Client, args: Dict) -> List[CommandResults]:

    cves = argToList(args.get('cve'))
    command_results_list: List[CommandResults] = []

    for cve in cves:
        try:
            response = client.antivirus_signature_get_request(arg='cve', value=cve)
            vulnerability = response.get('data', {}).get('vulnerability', [])[0]
            _cve = Common.CVE(
                id=vulnerability.get('cve')[0],
                cvss=vulnerability.get('severity'),
                published=vulnerability.get('ori_release_time'),
                modified=vulnerability.get('latest_release_time'),
                description=vulnerability.get('description'),
            )
            table_for_md = resp_to_hr(response=vulnerability, type_='vulnerability')
            readable_output = tableToMarkdown(name=f"CVE {cve} vulnerability reputation:", t=table_for_md,
                                              removeNull=True)
        except Exception as err:
            if 'Error in API call [404] - Not Found' in str(err):
                readable_output = f'CVE {cve} vulnerability reputation is unknown to Threat Vault.'
                _cve = None
            else:
                raise Exception(err)

        command_results = CommandResults(
            readable_output=readable_output,
            indicator=_cve
        )
        command_results_list.append(command_results)

    return command_results_list


def threat_signature_get_command(client: Client, args: Dict) -> List[CommandResults]:

    args['file'] = args.get('sha256', '')
    if md5 := args.get('md5', ''):
        args['file'] += f",{md5}" if args['file'] else md5
    args['extra'] = True
    ids = argToList(args.get('signature_id'))

    if not ids and not args['file']:
        raise ValueError('One of following arguments is required -> [signature_id, sha256, md5]')

    if ids and args['file']:
        raise ValueError('The command cannot be run with more than one argument.')

    command_results_list: List[CommandResults] = []

    if args['file']:
        command_results_list.extend(file_command(client=client, args=args))
        return command_results_list

    for _id in ids:
        try:
            response = client.antivirus_signature_get_request(arg='id', value=_id)
            command_results_list.extend(parse_resp_by_type(response=response))
        except Exception as err:
            if 'Error in API call [404] - Not Found' in str(err):
                readable_output = f'{_id} reputation is unknown to Threat Vault.'
                command_results_list.append(
                    CommandResults(
                        readable_output=readable_output
                    )
                )
            else:
                raise ValueError(err)
    return command_results_list


def release_note_get_command(client: Client, args: Dict) -> CommandResults:

    if 'type' not in args or 'version' not in args:
        raise ValueError('The following arguments are required -> [type, version]')

    type_ = args['type']
    version = args['version']
    try:
        response = client.release_notes_get_request(type_, version)
        data = response.get('data', [])[0] if response.get('data') else []
    except Exception as err:
        if 'Error in API call [404] - Not Found' in str(err):
            return CommandResults(
                readable_output=f'{version} release note not found.'
            )
        else:
            raise ValueError(err)

    table_for_md = resp_to_hr(response=data, type_='release_notes')
    readable_output = tableToMarkdown(name="Release notes:", t=table_for_md,
                                      removeNull=True)
    return CommandResults(outputs_prefix='ThreatVault.ReleaseNote',
                          outputs_key_field='',  ## not done
                          outputs=data,
                          readable_output=readable_output)


def threat_batch_search_command(client: Client, args: Dict) -> List[CommandResults]:

    ids = argToList(args.get('id'))
    md5 = argToList(args.get('md5'))
    sha256 = argToList(args.get('sha256'))
    names = argToList(args.get('name'))
    threat_type = args.get('type', '')

    if len([x for x in (ids, md5, sha256, names) if x]) > 1:
        raise ValueError('There can only be one argument from the following list in the command -> [id, md5, sha256, name]')
    if not [x for x in (ids, md5, sha256, names) if x]:
        raise ValueError('One of following arguments is required -> [id, sha256, md5, name]')

    command_results_list: List[CommandResults] = []

    if ids or names:
        type_ = 'id' if ids else 'name'
        response = client.threat_batch_search_request(arg=type_, value=ids if ids else names, type_=threat_type)
        command_results_list.extend(parse_resp_by_type(response, True))

    elif md5 or sha256:
        dbot_reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(client.reliability)

        type_ = 'md5' if md5 else 'sha256'
        response = client.threat_batch_search_request(arg=type_, value=md5 if md5 else sha256, type_=threat_type)
        files_info: List[dict] = response.get('data', {}).get('fileinfo', [])
        for file_info in files_info:

            dbot_score = Common.DBotScore(
                indicator=file_info.get('sha256'),
                indicator_type=DBotScoreType.FILE,
                integration_name=client.name,
                score=SCORE_TABLE_FILE[file_info.get('wildfire_verdict', 'unknown')],
                reliability=dbot_reliability
            )
            file = Common.File(
                sha256=file_info.get('sha256', None),
                md5=file_info.get('md5', None),
                sha1=file_info.get('sha1', None),
                dbot_score=dbot_score
            )

            table_for_md = resp_to_hr(response=file_info, type_='file', extra=True)
            readable_output = tableToMarkdown(name=f"File {file_info.get('sha256')}:", t=table_for_md,
                                              removeNull=True)
            command_results_list.append(
                CommandResults(
                    outputs_prefix='ThreatVault.FileInfo',
                    readable_output=readable_output,
                    outputs_key_field='sha256',
                    outputs=file_info,
                    indicator=file,
                )
            )

    return command_results_list


def threat_search_command(client: Client, args: Dict) -> List[CommandResults]:

    cve = args.get('cve')
    vendor = args.get('vendor')
    name = args.get('signature-name')

    length = len([x for x in (cve, vendor, name) if x])
    if length == 0:
        raise ValueError('One of following arguments is required -> [cve, vendor, signature-name]')
    elif length > 1:
        raise ValueError('There can only be one argument from the following list in the command ->'
                         '[release-date, release-version]')

    from_release_date = args.get('from-release-date')
    to_release_date = args.get('to-release-date')

    if len([x for x in (from_release_date, to_release_date) if x]) == 1:
        raise ValueError('When using a release date range in a query, it must be used with the following two arguments ->'
                         '[from-release-date, to-release-date]')

    from_release_version = args.get('from-release-version')
    to_release_version = args.get('to-release-version')

    if len([x for x in (from_release_version, to_release_version) if x]) == 1:
        raise ValueError('When using a release version range in a query, it must be used with the following two arguments ->'
                         '[from-release-version, to-release-version]')

    release_date = args.get('release-date')
    release_version = args.get('release-version')

    if release_date and release_version:
        raise ValueError('There can only be one argument from the following list in the command ->'
                         '[release-date, release-version]')

    if (from_release_date or from_release_version) and (release_date or release_version):
        raise ValueError('')  ## not done

    if from_release_date and from_release_version:
        raise ValueError('')  ## not done

    type_ = args.get('type')
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    offset, limit = pagination(page, page_size, arg_to_number(args.get('limit')))

    query = assign_params(cve=cve,
                          vendor=vendor,
                          name=name,
                          fromReleaseDate=from_release_date,
                          toReleaseDate=to_release_date,
                          fromReleaseVersion=from_release_version,
                          toRelaseVersion=to_release_version,
                          releaseDate=release_date,
                          releaseVersion=release_version,
                          type=type_,
                          offset=offset,
                          limit=limit)

    command_results_list: List[CommandResults] = []

    try:
        response = client.threat_search_request(args=query)
        command_results_list.extend(parse_resp_by_type(response, True))
    except Exception as err:
        if 'Error in API call [404] - Not Found' in str(err):
            readable_output = f'{cve or vendor or name} reputation is unknown to Threat Vault.'
            command_results_list.append(
                CommandResults(
                    readable_output=readable_output
                )
            )
        else:
            raise ValueError(err)

    return command_results_list


'''
FETCH INCIDENT
'''


def fetch_incidents(client: Client, args: dict) -> List:

    today = datetime.now(timezone.utc).date().strftime('%Y-%m-%d')
    try:
        demisto.debug(f'Time for request fetch-incidents -> {today}')
        response = client.threat_search_request({'releaseDate': '2022-10-17'})
    except Exception as err:
        if 'Error in API call [404] - Not Found' in str(err):
            return []
        else:
            raise ValueError(err)

    if keys_of_resp := [x for x in response['data'].keys() if x in ('spyware', 'vulnerability', 'fileformat', 'antivirus')]:
        number_version = response['data'][keys_of_resp[0]][0]['latest_release_version']
        release = client.release_notes_get_request('content', number_version)

        incident = {
            'name': 'THREAT VAULT - RELEASE NOTES',
            'occurred': release['data'][0]['release_time'],
            'rawJSON': json.dumps(parse_incident(release))
        }
        return [incident]
    else:
        return []


def test_module(client: Client, *_) -> str:
    """Performs basic get request to get ip geo data.

    Args:
        client: Client object with request.

    Returns:
        string.
    """
    return 'ok'


def main():

    params = demisto.params()
    '''PARAMS'''

    api_key = params.get('api_key')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy')
    reliability = params.get('integrationReliability', 'D - Not usually reliable')

    if not DBotScoreReliability.is_valid_type(reliability):
        raise Exception("Please provide a valid value for the Source Reliability parameter.")

    try:
        command = demisto.command()
        demisto.debug(f'Command being called is {demisto.command()}')
        client = Client(api_key=api_key,
                        verify=verify,
                        proxy=proxy,
                        reliability=reliability)

        commands = {
            'file': file_command,
            'cve': cve_command,
            'threatvault-threat-signature-get': threat_signature_get_command,
            'threatvault-release-note-get': release_note_get_command,
            'threatvault-threat-batch-search': threat_batch_search_command,
            'threatvault-threat-search': threat_search_command,
        }
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            incidents = fetch_incidents(client, params)
            demisto.incidents(incidents)
        elif command in commands:
            return_results(commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" was not implemented.')

    except Exception as err:
        return_error(str(err), err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
