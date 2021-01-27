import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class ViperClient(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def sample_information(self, file_hash):
        '''Get Sample instance information from Viper'''
        return self._http_request(
            method='GET',
            url_suffix=f'/malware/{file_hash}/'
        )

    def test_module(self):
        return self._http_request(
            method='GET',
            url_suffix='/'
        )


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: Viper client

    Returns:
        'ok' if test passed, anything else will fail the test
    """
    client.test_module()
    return 'ok'


def sample_download_helper(file_hash):
    api_key = demisto.params().get('apikey')
    viper_project = demisto.params().get('viper_project')
    base_url = urljoin(demisto.params()['url'], f'/api/v3/project/{viper_project}')
    verify_certificate = not demisto.params().get('insecure', False)
    url = f'{base_url}/malware/{file_hash}/download/'
    authorization = f'Token {api_key}'
    try:
        sample = requests.get(
            url, verify=verify_certificate, headers={
                'Authorization': authorization,
                'Accept': 'application/json'
            }
        )
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')

    return sample


def viper_download(client, args):
    file_hash = args.get('file_hash')
    if len(file_hash) == 64:
        filename = viper_search(client, args)
        sample = sample_download_helper(file_hash)

        if sample.status_code == 200:
            return_results(fileResult(filename, sample.content))
        else:
            raise DemistoException('No valid sample found')
    else:
        return_error('Hash length is invalid.')


def viper_search(client, args):
    file_hash = args.get('file_hash')
    if len(file_hash) == 64:
        sample_info = client.sample_information(file_hash)

        if sample_info['data']:
            filename = sample_info['data']['name']
            viper_id = sample_info['data']['id']
            mime = sample_info['data']['mime']
            file_type = sample_info['data']['type']
            size = sample_info['data']['size']
            viper_search_results = CommandResults(
                outputs_prefix='Viper',
                outputs_key_field='ViperID',
                outputs={
                    'Name': filename,
                    'SHA256': file_hash,
                    'ViperID': viper_id,
                    'MIME': mime,
                    'Type': file_type,
                    'Size': size
                }
            )
            return_results(viper_search_results)
            return filename
        else:
            return_error('No valid sample found')
    else:
        raise DemistoException('Hash length is invalid.')


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # Parse parameters
    api_key = demisto.params().get('apikey')
    viper_project = demisto.params().get('viper_project')
    base_url = urljoin(demisto.params()['url'], f'/api/v3/project/{viper_project}')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Token {api_key}',
            'Accept': 'application/json'
        }

        client = ViperClient(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif demisto.command() == 'viper-download':
            viper_download(client, demisto.args())

        elif demisto.command() == 'viper-search':
            viper_search(client, demisto.args())

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
