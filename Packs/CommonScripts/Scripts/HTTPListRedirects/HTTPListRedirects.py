import demistomock as demisto
from CommonServerPython import *
import requests
import os

requests.packages.urllib3.disable_warnings()


def get_response(url: str, use_head: str, verify_ssl: str) -> requests.Response:
    if use_head == 'true':
        response = requests.head(url, allow_redirects=True, verify=verify_ssl)
    else:
        response = requests.get(url, allow_redirects=True, verify=verify_ssl)

    return response


def get_response_history(response: requests.Response):
    urls = []
    if response.history:
        for resp in response.history:
            urls.append({'Data': resp.url, 'Status': resp.status_code})
    urls.append({'Data': response.url, 'Status': response.status_code})
    return urls


def main():
    use_system_proxy = demisto.args().get('use_system_proxy')
    url = demisto.args().get('url')
    use_head = demisto.args()['useHead']
    trust_any_certificate = demisto.args().get('trust_any_certificate')
    try:
        if use_system_proxy == 'false':
            del os.environ['HTTP_PROXY']
            del os.environ['HTTPS_PROXY']
            del os.environ['http_proxy']
            del os.environ['https_proxy']
        verify_ssl = trust_any_certificate != 'true'

        if not url.lower().startswith('http'):
            url = f'http://{url}'

        response = get_response(url=url,
                                use_head=use_head,
                                verify_ssl=verify_ssl)

        history_urls = get_response_history(response=response)

        ec = {'URL(val.Data == obj.Data)': [{'Data': history_url['Data']} for history_url in history_urls]}

        demisto.results({'ContentsFormat': formats['json'], 'Type': entryTypes['note'], 'Contents': history_urls,
                         'ReadableContentsFormat': formats['markdown'],
                         'HumanReadable': tableToMarkdown('URLs', history_urls, ['Data', 'Status']), 'EntryContext': ec})

    except Exception as e:
        return_error(f'Failed to execute script.\nError:\n{str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
