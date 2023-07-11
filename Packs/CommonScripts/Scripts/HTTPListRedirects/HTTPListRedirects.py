import demistomock as demisto
from CommonServerPython import *
import requests
import os
import urllib3

urllib3.disable_warnings()


def get_response(url: str, use_head: str, verify_ssl: bool) -> requests.Response:
    if use_head == 'true':
        response = requests.head(url, allow_redirects=True, verify=verify_ssl)
    else:
        response = requests.get(url, allow_redirects=True, verify=verify_ssl)
    return response


def create_command_result(history_urls: List[Dict[str, Union[str, int]]]):
    ec = {'URL(val.Data == obj.Data)': [{'Data': history_url['Data']} for history_url in history_urls]}
    return {'ContentsFormat': formats['json'], 'Type': entryTypes['note'], 'Contents': history_urls,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('URLs', history_urls, ['Data', 'Status']), 'EntryContext': ec}


def get_response_history(response: requests.Response):
    urls = []
    if response.history:
        for resp in response.history:
            urls.append({'Data': resp.url, 'Status': resp.status_code})
    urls.append({'Data': response.url, 'Status': response.status_code})
    return urls


def delete_environment_variables(use_system_proxy: str):
    if use_system_proxy == 'false':
        env_variables = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']
        for env_var in env_variables:
            if(env_var in os.environ):
                del os.environ[env_var]


def main():
    url = demisto.args().get('url')
    try:
        delete_environment_variables(use_system_proxy=demisto.args().get('use_system_proxy').lower())
        url = f'http://{url}' if not url.lower().startswith('http') else url

        response = get_response(url=url,
                                use_head=demisto.args()['useHead'],
                                verify_ssl=demisto.args().get('trust_any_certificate', 'true').lower() != 'true')
        history_urls = get_response_history(response=response)
        demisto.results(create_command_result(history_urls=history_urls))

    except Exception as e:
        return_error(f'Failed to execute script. Error:\n{str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
