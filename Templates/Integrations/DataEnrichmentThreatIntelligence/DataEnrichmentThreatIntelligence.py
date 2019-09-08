from CommonServerPython import *
from CommonServerUserPython import *
import demistomock as demisto

''' IMPORTS '''
from typing import Dict, Tuple, Optional
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
# Setting global params, initiation in main() function
FILE_HASHES: Tuple = ('md5', 'ssdeep', 'sha1', 'sha256')  # hashes as described in API
''' HELPER FUNCTIONS '''


class Client(BaseClient):
    """
    """

    def __init__(self, server, base_suffix, integration_name, integration_command_name, integration_context_name,
                 threshold: int, **kwargs):
        # added threshold
        self._threshold = threshold
        super().__init__(server, base_suffix, integration_name,
                         integration_command_name, integration_context_name, **kwargs)

    """ HELPER FUNCTIONS """

    def calculate_dbot_score(self, score: int, threshold: Optional[int] = None) -> int:
        """Transforms `severity` from API to DBot Score and using threshold.

        Args:
            score: Severity from API
            threshold: Any value above this number is malicious. if None, will use self._threshold

        Returns:
            Score representation in DBot
        """
        high_score = threshold if threshold else self._threshold
        # Malicious
        if score > high_score:
            return 3
        # Suspicious
        if score > 30:
            return 2
        # Good
        if score >= 0:
            return 1
        # Unknown
        return 0

    def test_module_request(self) -> bool:
        """Performs basic get request to see if the API is reachable and authentication works.

        Returns:
            True if request succeeded, else raises exception
        """
        self._http_request('GET', 'version')
        return True

    def get_ip_request(self, ip: str) -> Dict:
        suffix = 'ip'
        params = {'ip': ip}
        return self._http_request('GET', suffix, params=params)

    def get_url_request(self, url: str) -> Dict:
        """Gets an analysis from the API for given url.

        Args:
            url: URL to get analysis on

        Returns:
            Dict:
        """
        suffix = 'analysis'
        params = {'url': url}
        return self._http_request('GET', suffix, params=params)

    def search_file_request(self, file_hash: str) -> Dict:
        """Building request for file command

        Args:
            file_hash: Hash to search in API

        Returns:
            Dict: results from API
        """
        suffix = 'analysis'
        params = {'hash': file_hash}
        return self._http_request('GET', suffix, params=params)


''' COMMANDS '''


def search_ip(client: Client, args: Dict):
    """Gets results for the API.
    """
    ip = args.get('ip', '')
    raw_response: Dict = client.get_ip_request(ip)
    results = raw_response.get('results')
    if results:
        title = f'{client.integration_name} - Analysis results for IP: {ip}'
        context_entry = {
            'ID': results.get('id'),
            'Severity': results.get('severity'),
            'IP': ip,
            'Description': results.get('description')
        }
        # Building a score for DBot
        score = client.calculate_dbot_score(results.get('severity'))
        dbot_entry = build_dbot_entry(ip, 'ip', score, client.integration_name, results.get('description'))
        context = {
            f'{client.integration_context_name}.Analysis(val.ID && val.ID === obj.ID)': context_entry
        }
        context.update(dbot_entry)

        human_readable: str = tableToMarkdown(title, context_entry, removeNull=True)
        return human_readable, context, raw_response
    else:
        return f'{client.integration_name} - Found no results for IP: {ip}', {}, raw_response


def search_url(client: Client, args: Dict):
    """Gets a job from the API. Used mostly for polling playbook
    """
    url = args.get('url', '')
    raw_response = client.get_url_request(url)
    results = raw_response.get('results', {})
    if results:
        title: str = f'{client.integration_name} - Analysis results for URL: {url}'
        context_entry = {
            'ID': results.get('id'),
            'Severity': results.get('severity'),
            'URL': url,
            'Description': results.get('description')
        }
        # Building a score for DBot
        score = client.calculate_dbot_score(results.get('severity'))
        dbot_entry = build_dbot_entry(url, 'url', score,
                                      client.integration_name, results.get('description'))
        context = {
            f'{client.integration_context_name}.Analysis(val.ID && val.ID === obj.ID)': context_entry
        }
        context.update(dbot_entry)
        human_readable: str = tableToMarkdown(title, context_entry, removeNull=True)
        return_outputs(human_readable, context, results)
    else:
        return_warning(f'{client.integration_name} - Found no results for URL: {url}')


def search_file(client: Client, args: Dict):
    """Searching for given file hash
    """
    file_hash: str = args.get('file')
    raw_response: Dict = client.search_file_request(file_hash)
    if raw_response:
        title: str = f'{client.integration_name} - Analysis results for file hash: {file_hash}'
        context_entry: Dict = {
            'ID': raw_response.get('id'),
            'Severity': raw_response.get('severity'),
            'MD5': raw_response.get('md5'),
            'SHA1': raw_response.get('sha1'),
            'SHA256': raw_response.get('sha256'),
            'SSDeep': raw_response.get('ssdeep'),
            'Description': raw_response.get('description')
        }
        # Gets DBot score
        score = client.calculate_dbot_score(raw_response.get('severity', ''))
        # Building a score for DBot
        dbot_score = [
            {
                'Indicator': raw_response.get(hash_name),
                'Type': 'hash',
                'Vendor': f'{client.integration_name}',
                'Score': score
            } for hash_name in FILE_HASHES if raw_response.get(hash_name)
        ]
        context: Dict = {
            outputPaths['dbotscore']: dbot_score,
            f'{client.integration_context_name}.Analysis(val.ID && val.ID === obj.ID)': context_entry
        }

        if score == 3:  # If file is malicious, adds a malicious entry
            context[outputPaths['file']] = [{
                hash_name.upper(): raw_response.get(hash_name),
                'Malicious': {
                    'Vendor': f'{client.integration_name}',
                    'Description': raw_response.get('description')
                }
            } for hash_name in FILE_HASHES if raw_response.get(hash_name)]
        human_readable: str = tableToMarkdown(title, context_entry, removeNull=True)
        return_outputs(human_readable, context, raw_response)
    else:
        return_warning(f'{client.integration_name} - Could not find results for file hash: [{file_hash}')


def test_module(client: Client, *args):
    if client.test_module_request():
        return 'ok'
    raise DemistoException('Test module failed')


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    integration_name = 'Data Enrichment Threat Intelligence'
    # lowercase with `-` dividers
    integration_command_name = 'data-enrichment-threat-intelligence'
    # No dividers
    integration_context_name = 'DataEnrichmentThreatIntelligence'
    suffix = '/api/v2'
    params = demisto.params()
    server = params.get('url')
    verify = not params.get('insecure', False)
    proxy: Optional[bool] = params.get('proxy')
    threshold = params.get('threshold')
    client = Client(
        server,
        suffix,
        integration_name,
        integration_command_name,
        integration_context_name,
        verify=verify,
        proxy=proxy,
        threshold=threshold
    )
    command: str = demisto.command()
    demisto.info(f'Command being called is {command}')
    commands: Dict = {
        'test-module': test_module,
        f'{client.integration_command_name}-search-ip': search_ip,
        'ip': search_ip,
        f'{client.integration_command_name}-search-url': search_url,
        'url': search_url,
        f'{client.integration_command_name}-search-file': search_file,
        'file': search_file,
    }
    try:
        if command in commands:
            human_readable, context, raw_response = commands[command](client, demisto.args())
            return_outputs(human_readable, context, raw_response)

    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {integration_name} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
