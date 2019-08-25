from CommonServerPython import *
from CommonServerUserPython import *
import demistomock as demisto

''' IMPORTS '''
from typing import Dict, Tuple, Any, cast, AnyStr, List
import xml.etree.ElementTree as ElementTree
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
# Setting global params, initiation in main() function
FILE_HASHES: Tuple = ('md5', 'ssdeep', 'sha1', 'sha256')  # hashes as described in API
''' HELPER FUNCTIONS '''


class Client:
    def __init__(self, server: str, use_ssl: bool):
        self.server: str = server.rstrip(chars='/')
        self.use_ssl: bool = use_ssl
        self.base_url: str = self.server + '/api/v2.0/'

    def http_request(self, method: str, url_suffix: str, full_url: str = None, headers: Dict = None,
                     auth: Tuple = None, params: Dict = None, data: Dict = None, files: Dict = None,
                     timeout: float = 10, resp_type: str = 'json') -> Any:
        """A wrapper for requests lib to send our requests and handle requests
        and responses better

        Args:
            method:
                HTTP method, e.g. 'GET', 'POST' ... etc.
            url_suffix:
                API endpoint.
            full_url:
                Bypasses the use of BASE_URL + url_suffix. Useful if there is a need to
                make a request to an address outside of the scope of the integration
                API.
            headers:
                Headers to send in the request.
            auth:
                Auth tuple to enable Basic/Digest/Custom HTTP Auth.
            params:
                URL parameters.
            data:
                Data to be sent in a 'POST' request.
            files:
                File data to be sent in a 'POST' request.
            timeout:
                The amount of time in seconds a Request will wait for a client to
                establish a connection to a remote machine.
            resp_type:
                Determines what to return from having made the HTTP request. The default
                is 'json'. Other options are 'text', 'content' or 'response' if the user
                would like the full response object returned.

        Returns:
                Response JSON from having made the request.
        """
        try:
            address = full_url if full_url else self.base_url + url_suffix
            res = requests.request(
                method,
                address,
                verify=self.use_ssl,
                params=params,
                data=data,
                files=files,
                headers=headers,
                auth=auth,
                timeout=timeout
            )

            # Handle error responses gracefully
            if res.status_code not in (200, 201):
                err_msg = 'Error in DataEnrichmentThreatIntell' \
                          'igence Integration API call [{}] - {}'.format(res.status_code, res.reason)
                try:
                    # Try to parse json error response
                    res_json = res.json()
                    message = res_json.get('message')
                    return_error(message)
                except json.decoder.JSONDecodeError:
                    if res.status_code in {400, 401, 501}:
                        # Try to parse xml error response
                        resp_xml = ElementTree.fromstring(res.content)
                        codes = [child.text for child in resp_xml.iter() if child.tag == 'CODE']
                        messages = [child.text for child in resp_xml.iter() if child.tag == 'MESSAGE']
                        err_msg += ''.join([f'\n{code}: {msg}' for code, msg in zip(codes, messages)])
                    return_error(err_msg)

            resp_type = resp_type.casefold()
            try:
                if resp_type == 'json':
                    return res.json()
                elif resp_type == 'text':
                    return res.text
                elif resp_type == 'content':
                    return res.content
                else:
                    return res
            except json.decoder.JSONDecodeError:
                return_error(f'Failed to parse json object from response: {res.content}')

        except requests.exceptions.ConnectTimeout:
            err_msg = 'Connection Timeout Error - potential reasons may be that the Server URL parameter' \
                      ' is incorrect or that the Server is not accessible from your host.'
            return_error(err_msg)
        except requests.exceptions.SSLError:
            err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' in' \
                      ' the integration configuration.'
            return_error(err_msg)
        except requests.exceptions.ProxyError:
            err_msg = 'Proxy Error - if \'Use system proxy\' in the integration configuration has been' \
                      ' selected, try deselecting it.'
            return_error(err_msg)
        except requests.exceptions.ConnectionError as e:
            # Get originating Exception in Exception chain
            while '__context__' in dir(e) and e.__context__:
                e = cast(Any, e.__context__)

            error_class = str(e.__class__)
            err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
            err_msg = f'\nError Type: {err_type}\nError Number: [{e.errno}]\nMessage: {e.strerror}\n' \
                f'ADVICE: Check that the Server URL parameter is correct and that you' \
                f' have access to the Server from your host.'  # TODO send alex
            return_error(err_msg)

    def test_module(self) -> bool:
        """Performs basic get request to get item samples

        Returns:
            True if request succeeded
        """
        self.http_request('GET', 'version')
        return True

    def get_ip_request(self, ip: str) -> Dict:
        suffix: str = 'ip'
        params = {'ip': ip}
        return self.http_request('GET', suffix, params=params).get('results')

    def get_url_request(self, url: str) -> Dict:
        """Gets an analysis from the API for given url.

        Args:
            url: URL to get analysis on

        Returns:
            Dict:
        """
        suffix: str = 'analysis'
        params = {'url': url}
        return self.http_request('GET', suffix, params=params).get('results')

    def search_file_request(self, file_hash: str) -> Dict:
        """Building request for file command

        Args:
            file_hash: Hash to search in API

        Returns:
            Dict: results from API
        """
        suffix = 'analysis'
        params = {'hash': file_hash}
        return self.http_request('GET', suffix, params=params).get('results')


def calculate_dbot_score(score: AnyStr) -> int:
    """Transforms `severity` from API to DBot Score.

    Args:
        score: Severity from API

    Returns:
        Score representation in DBot
    """
    if score == 'HIGH':
        return 3
    elif score in ('MED', 'LOW'):
        return 2
    elif score == 'GOOD':
        return 1
    return 0  # Unknown


''' COMMANDS '''


def search_ip(client: Client):
    """Gets results for the API.
    """
    ip: str = demisto.args().get('ip', '')
    raw_response: Dict = client.get_ip_request(ip)
    if raw_response:
        title: str = f'DataEnrichmentThreatIntelligence - Analysis results for IP: {ip}'
        context_entry: Dict = {
            'ID': raw_response.get('id'),
            'Severity': raw_response.get('severity'),
            'IP': ip,
            'Description': raw_response.get('description')
        }
        # Gets DBot score
        score: int = calculate_dbot_score(raw_response.get('severity', ''))
        # Building a score for DBot
        dbot_score: Dict = {
            'Indicator': ip,
            'Type': 'ip',
            'Vendor': 'DataEnrichmentThreatIntelligence',
            'Score': score
        }

        context: Dict = {
            outputPaths['dbotscore']: dbot_score,
            'DataEnrichmentThreatIntelligence.Analysis(val.ID && val.ID === obj.ID)': context_entry
        }

        if score == 3:  # If file is malicious, adds a malicious entry
            context[outputPaths['ip']] = {
                'Address': ip,
                'Malicious': {
                    'Vendor': 'DataEnrichmentThreatIntelligence',
                    'Description': raw_response.get('description')
                }
            }
        human_readable: str = tableToMarkdown(title, context_entry, removeNull=True)
        return_outputs(human_readable, context, raw_response)
    else:
        return_warning(f'DataEnrichmentThreatIntelligence - Found no results for IP: {ip}')


def search_url(client: Client):
    """Gets a job from the API. Used mostly for polling playbook
    """
    url: str = demisto.args().get('url', '')
    raw_response: Dict = client.get_url_request(url)
    if raw_response:
        title: str = f'DataEnrichmentThreatIntelligence - Analysis results for URL: {url}'
        context_entry: Dict = {
            'ID': raw_response.get('id'),
            'Severity': raw_response.get('severity'),
            'IP': url,
            'Description': raw_response.get('description')
        }
        # Gets DBot score
        score: int = calculate_dbot_score(raw_response.get('severity', ''))
        # Building a score for DBot
        dbot_score: Dict = {
            'Indicator': url,
            'Type': 'url',
            'Vendor': 'DataEnrichmentThreatIntelligence',
            'Score': score
        }

        context: Dict = {
            outputPaths['dbotscore']: dbot_score,
            'DataEnrichmentThreatIntelligence.Analysis(val.ID && val.ID === obj.ID)': context_entry
        }

        if score == 3:  # If file is malicious, adds a malicious entry
            context[outputPaths['url']] = {
                'Data': url,
                'Malicious': {
                    'Vendor': 'DataEnrichmentThreatIntelligence',
                    'Description': raw_response.get('description')
                }
            }
        human_readable: str = tableToMarkdown(title, context_entry, removeNull=True)
        return_outputs(human_readable, context, raw_response)
    else:
        return_warning(f'DataEnrichmentThreatIntelligence - Found no results for URL: {url}')


def search_file(client: Client):
    """Searching for given file hash
    """
    file_hash: str = demisto.args().get('file')
    raw_response: Dict = client.search_file_request(file_hash)
    if raw_response:
        title: str = f'DataEnrichmentThreatIntelligence - Analysis results for file hash: {file_hash}'
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
        score: int = calculate_dbot_score(raw_response.get('severity', ''))
        # Building a score for DBot
        dbot_score: List[Dict] = [
            {
                'Indicator': raw_response.get(hash_name),
                'Type': 'hash',
                'Vendor': 'DataEnrichmentThreatIntelligence',
                'Score': score
            } for hash_name in FILE_HASHES if raw_response.get(hash_name)
        ]
        context: Dict = {
            outputPaths['dbotscore']: dbot_score,
            'DataEnrichmentThreatIntelligence.Analysis(val.ID && val.ID === obj.ID)': context_entry
        }

        if score == 3:  # If file is malicious, adds a malicious entry
            context[outputPaths['file']] = [{
                hash_name.upper(): raw_response.get(hash_name),
                'Malicious': {
                    'Vendor': 'DataEnrichmentThreatIntelligence',
                    'Description': raw_response.get('description')
                }
            } for hash_name in FILE_HASHES if raw_response.get(hash_name)]
        human_readable: str = tableToMarkdown(title, context_entry, removeNull=True)
        return_outputs(human_readable, context, raw_response)
    else:
        return_warning(f'DataEnrichmentThreatIntelligence - Could not find results for file hash: {file_hash}')


def test_module(client: Client):
    if client.test_module():
        demisto.results('ok')


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    server = demisto.getArg('url')
    use_ssl = not demisto.params().get('insecure', False)
    client = Client(server, use_ssl)
    command: str = demisto.command()
    demisto.info(f'Command being called is {command}')
    commands = {
        'test-module': test_module,
        'data-enrichment-threat-intelligence-search-ip': search_ip,
        'ip': search_ip,
        'data-enrichment-threat-intelligence-search-url': search_url,
        'url': search_url,
        'data-enrichment-threat-intelligence-search-file': search_file,
        'file': search_file
    }
    try:
        if command in commands:
            commands[command](client)

    # Log exceptions
    except Exception as e:
        err_msg = f'Error in DataEnrichmentThreatIntelligence Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__builtin__', 'builtins'):
    main()
