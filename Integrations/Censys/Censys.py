import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import requests

''' GLOBAL VARIABLES '''
API_URL = demisto.params()['url']
API_ID = demisto.params()['apiid']
API_SECRET = demisto.params()['secret']
USE_SSL = not demisto.params().get('insecure', False)


def test_module():
    url_suffix = "view/ipv4/8.8.8.8"
    res = send_request('GET', url_suffix)
    if res is not None:
        demisto.results('OK')
    else:
        return_error('Error 404: Test failed.')


def send_request(method, url_suffix, data=None):
    res = requests.request(method, API_URL + url_suffix,
                           auth=(API_ID, API_SECRET),
                           data=json.dumps(data),
                           verify=USE_SSL)
    data = json.loads(res.text)

    if res.status_code == 404:
        return None
    elif res.status_code >= 400:
        return_error(
            "Received an error - status code {0}, error message: {1}".format(res.status_code, data["error"].title()))

    return data


def censys_view_command(query, index):
    # query = args.get()
    url_suffix = 'view/{0}/{1}'.format(index, query)
    raw = send_request('GET', url_suffix)
    if raw:
        demisto.results(raw)
    else:
        demisto.results("No view results for {0}.".format(query))


def censys_search_command(query, index):
    url_suffix = 'search/{0}'.format(index)
    data = {
        "query": query,
        "page": 1
    }
    raw = send_request('POST', url_suffix, data)
    readable = tableToMarkdown("Search results for {0} in {1}".format(query, index), raw["results"])
    return_outputs(readable, raw)


''' EXECUTION CODE '''
command = demisto.command()
LOG('command is {0}'.format(command))
try:
    handle_proxy()
    args = demisto.args()
    if command == 'test-module':
        test_module()
    elif command == 'cen-view':
        censys_view_command()
    elif command == 'cen-search':
        censys_search_command()

except Exception as ex:
    LOG(ex)
    return_error(str(ex))
