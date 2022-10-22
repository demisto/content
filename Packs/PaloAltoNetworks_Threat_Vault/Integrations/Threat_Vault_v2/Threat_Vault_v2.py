from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

BASE_URL = 'https://api.threatvault.paloaltonetworks.com/service/v1/'
SCORE_TABLE_FILE = {
    'unknown': Common.DBotScore.NONE,
    'benign': Common.DBotScore.GOOD,
    'grayware': Common.DBotScore.SUSPICIOUS,
    'malicious': Common.DBotScore.BAD
}
SCORE_TABLE_CVE = {
    'low': 0,
    'informational': 1,
    'medium': 2,
    'critical': 3,
    'high': 3
}


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

    def threat_batch_search_request(self, arg: str, value: list) -> dict:

        params = json.dumps({arg: value})
        suffix = 'threats'

        return self._http_request(method='POST', url_suffix=suffix, data=params)


def resp_to_hr(response: dict, type_: str, extra: bool = False) -> dict:

    match type_:
        case 'file':
            table_for_md = {'Active': response.get('signatures', {}).get('antivirus', [])[0].get('status', None),
                            'CreateTime': response.get('create_time', None),
                            'Release': response.get('signatures', {}).get('antivirus', [])[0].get('release', None),
                            'SignatureId': response.get('signatures', {}).get('antivirus', [])[0].get('id', None),
                            'FileType': response.get('filetype', None),
                            'MD5': response.get('md5', None),
                            'SHA256': response.get('sha256', None),
                            'SHA1': response.get('sha1', None),
                            }
            if extra:
                table_for_md.update({
                    'Family': response.get('family', None),
                    'Platform': response.get('platform', None),
                    'Signature Name': response.get('signatures', {}).get('antivirus', [])[0].get('name', None),
                    'Severity': response.get('signatures', {}).get('antivirus', [])[0].get('severity', None),
                    'Description': response.get('signatures', {}).get('antivirus', [])[0].get('description', None),
                    'Size': response.get('size', None),
                    'Wildfire verdict': response.get('wildfire_verdict', None),
                })

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
            file_info: dict = response.get('data', {}).get('fileinfo', [])[0]
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

            readable_output = tableToMarkdown(name=f"Hash {_hash} Antivirus reputation:", t=table_for_md,
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

                readable_output = f"Hash {_hash} Antivirus reputation is unknown to Threat Vault."
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
                id=vulnerability.get('cve'),
                cvss=vulnerability.get('severity'),
                published=vulnerability.get('ori_release_time'),
                modified=vulnerability.get('latest_release_time'),
                description=vulnerability.get('description'),
                cvss_score=SCORE_TABLE_CVE[vulnerability.get('severity')]
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

    args['file'] = args.get('sha256', '') + args.get('md5', '')
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
        response = client.antivirus_signature_get_request(arg='id', value=_id)
        if 'antivirus' in response['data']:
            antivirus = response.get('data', {}).get('antivirus', [])[0]
            table_for_md = resp_to_hr(response=antivirus, type_='antivirus')
            readable_output = tableToMarkdown(name=f"{_id} antivirus reputation:", t=table_for_md,
                                              removeNull=True)
            command_results_list.append(
                CommandResults(
                    outputs_prefix='ThreatVault.Antivirus',
                    outputs_key_field='id',
                    outputs=response.get('data', {}).get('antivirus', []),
                    readable_output=readable_output,
                )
            )

        if 'spyware' in response['data']:
            spyware = response.get('data', {}).get('spyware', [])[0]
            table_for_md = resp_to_hr(response=spyware, type_='spyware')
            readable_output = tableToMarkdown(name=f"{_id} spyware reputation:", t=table_for_md,
                                              removeNull=True)
            command_results_list.append(
                CommandResults(
                    outputs_prefix='ThreatVault.Spyware',
                    outputs_key_field='id',
                    outputs=response.get('data', {}).get('spyware', []),
                    readable_output=readable_output,
                )
            )

        if 'vulnerability' in response['data']:
            vulnerability = response.get('data', {}).get('vulnerability', [])[0]
            table_for_md = resp_to_hr(response=vulnerability, type_='vulnerability')
            readable_output = tableToMarkdown(name=f"{_id} vulnerability reputation:", t=table_for_md,
                                              removeNull=True)
            command_results_list.append(
                CommandResults(
                    outputs_prefix='ThreatVault.vulnerability',
                    outputs_key_field='id',
                    outputs=response.get('data', {}).get('vulnerability', []),
                    readable_output=readable_output,
                )
            )

    return command_results_list


def release_note_get_command(client: Client, args: Dict) -> CommandResults:

    if 'type' not in args or 'version' not in args:
        raise ValueError('The following arguments are required -> [type, version]')

    type_ = args['type']
    version = args['version']

    response = client.release_notes_get_request(type_, version)
    data = response.get('data', [None])[0] ## require correction

    table_for_md = resp_to_hr(response=data, type_='release_notes')
    readable_output = tableToMarkdown(name="Release notes:", t=table_for_md,
                                      removeNull=True)
    return CommandResults(outputs_prefix='ThreatVault.RelaseNote',
                          outputs_key_field='',
                          outputs=data,
                          readable_output=readable_output)


def threat_batch_search_command(client: Client, args: Dict) -> List[CommandResults]:

    ids = argToList(args.get('id'))
    md5 = argToList(args.get('md5'))
    sha256 = argToList(args.get('sha256'))
    name = argToList(args.get('name'))

    if len([x for x in (ids, md5, sha256, name) if x]) > 1:
        raise ValueError('There can only be one argument from the following list in the command -> [id, md5, sha256, name]')
    if not [x for x in (ids, md5, sha256, name) if x]:
        raise ValueError('One of following arguments is required -> [id, sha256, md5]')

    command_results_list: List[CommandResults] = []

    if ids:
        response = client.threat_batch_search_request(arg='id', value=ids)
        if 'antivirus' in response['data']:
            antiviruses: List[dict] = response['data']['antivirus']

            for antivirus in antiviruses:
                table_for_md = resp_to_hr(response=antivirus, type_='antivirus')
                readable_output = tableToMarkdown(name=f"Antivirus {antivirus.get('id')}:", t=table_for_md,
                                                  removeNull=True)
                command_results_list.append(
                    CommandResults(
                        outputs_prefix='ThreatVault.Antivirus',
                        readable_output=readable_output,
                        outputs_key_field='id',
                        outputs=antivirus,
                    )
                )

        if 'spyware' in response['data']:
            spywares: List[dict] = response['data']['spyware']

            for spyware in spywares:
                table_for_md = resp_to_hr(response=spyware, type_='spyware')
                readable_output = tableToMarkdown(name=f"Spyware {spyware.get('id')}:", t=table_for_md,
                                                  removeNull=True)
                command_results_list.append(
                    CommandResults(
                        outputs_prefix='ThreatVault.Spyware',
                        readable_output=readable_output,
                        outputs_key_field='id',
                        outputs=spyware,
                    )
                )
            pass

        if 'vulnerability' in response['data']:
            vulnerabilities: List[dict] = response['data']['vulnerability']

            for vulnerability in vulnerabilities:
                table_for_md = resp_to_hr(response=vulnerability, type_='vulnerability')
                readable_output = tableToMarkdown(name=f"Vulnerability {vulnerability.get('id')}:", t=table_for_md,
                                                  removeNull=True)
                command_results_list.append(
                    CommandResults(
                        outputs_prefix='ThreatVault.Vulnerability',
                        readable_output=readable_output,
                        outputs_key_field='id',
                        outputs=vulnerability,
                    )
                )

        else:
            raise ValueError('') ## not done

    elif md5 or sha256:
        dbot_reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(client.reliability)

        type_ = 'md5' if md5 else 'sha256'
        response = client.threat_batch_search_request(arg=type_, value=md5 if md5 else sha256)
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

    elif name:
        response = client.threat_batch_search_request(arg='name', value=name)

    return command_results_list


def threat_search_command(client: Client, args: Dict) -> List[CommandResults]:

    cve = args.get('cve')
    vendor = args.get('vendor')

    if not cve and not vendor:
        raise ValueError('One of following arguments is required -> [cve, vendor]')

    from_release_date = args.get('from-release-date')
    to_release_date = args.get('to-release-date')

    if len([x for x in (from_release_date, to_release_date) if x]) == 1:
        raise ValueError('When using a release date range in a query, it must be used with the following two arguments -> \
                         [from-release-date, to-release-date]')

    from_release_version = args.get('from-release-version')
    to_release_version = args.get('to-release-version')

    if len([x for x in (from_release_version, to_release_version) if x]) == 1:
        raise ValueError('When using a release version range in a query, it must be used with the following two arguments -> \
                         [from-release-version, to-release-version]')

    release_date = args.get('release-date')
    release_version = args.get('release-version')

    if (from_release_date or from_release_version) and (release_date or release_version):
        raise ValueError('') ## not done


    pass


def test_module(client: Client, *_) -> str:
    """Performs basic get request to get ip geo data.

    Args:
        client: Client object with request.

    Returns:
        string.
    """
    client.ip_geo_get_request(ip_='1.1.1.1')
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
        elif command in commands:
            return_results(commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" was not implemented.')

    except Exception as err:
        return_error(str(err), err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
