from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

BASE_URL = 'https://api.threatvault.paloaltonetworks.com/service/v1/'
ARGS_FOR_API = {
    'file': {
        'sha256': 'sha256',
        'md5': 'md5'
    },
    'cve': {
        'cve': 'cve'
    }
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

    def antivirus_signature_get_request(self, command: str, arg: str, value: str) -> dict:

        params = {ARGS_FOR_API[command][arg]: value}
        suffix = 'threats'

        return self._http_request(method='GET', url_suffix=suffix, params=params)


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
            response = client.antivirus_signature_get_request(command='file', arg=type_hash, value=_hash)
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

            table_for_md = {'Active': file_info.get('signatures', {}).get('antivirus', [])[0].get('status', None),
                            'CreateTime': file_info.get('create_time', None),
                            'Release': file_info.get('signatures', {}).get('antivirus', [])[0].get('release', None),
                            'SignatureId': file_info.get('signatures', {}).get('antivirus', [])[0].get('id', None),
                            'FileType': file_info.get('filetype', None),
                            'MD5': file_info.get('md5', None),
                            'SHA256': file_info.get('sha256', None),
                            'SHA1': file_info.get('sha1', None)}

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
            response = client.antivirus_signature_get_request(command='cve', arg='cve', value=cve)
            vulnerability = response.get('data', {}).get('vulnerability', [])[0]
            _cve = Common.CVE(
                id=vulnerability.get('cve'),
                description=vulnerability.get('description'),
                cvss_score=SCORE_TABLE_CVE[vulnerability.get('severity')]
            )
            table_for_md = {'id': vulnerability.get('id'),
                            'Name': vulnerability.get('name', None),
                            'Description': vulnerability.get('Description', None),
                            'Category': vulnerability.get('category', None),
                            'Severity': vulnerability.get('severity', None),
                            'Default action': vulnerability.get('default_action', None),
                            'Vendor': vulnerability.get('vendor', None),
                            'Reference': vulnerability.get('reference', None),
                            'Status': vulnerability.get('status', None),
                            'Ori release version': vulnerability.get('ori_release_version', None),
                            'Latest release version': vulnerability.get('latest_release_version', None),
                            'Ori release time': vulnerability.get('ori_release_time', None),
                            'Latest release time': vulnerability.get('latest_release_time', None)}

            readable_output = tableToMarkdown(name=f"CVE {cve} Antivirus reputation:", t=table_for_md,
                                              removeNull=True)
        except Exception as err:
            if 'Error in API call [404] - Not Found' in str(err):
                raise

        command_results = CommandResults(
            readable_output=readable_output,
            indicator=_cve
        )
        command_results_list.append(command_results)

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
