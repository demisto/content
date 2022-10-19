from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

BASE_URL = 'https://api.threatvault.paloaltonetworks.com/service/v1/'
ARGS_FOR_API = {
    'sha256': 'sha256',
    'md5': 'md5',
    'cve': 'cve',
    'id': 'id',
}
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

        params = {ARGS_FOR_API[arg]: value}
        suffix = 'threats'

        return self._http_request(method='GET', url_suffix=suffix, params=params)


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
            pass

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

    command_results_list: List[CommandResults] = []

    if args['file']:
        command_results_list.extend(file_command(client=client, args=args))

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

    return command_results_list


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
