import demistomock as demisto
from CommonServerPython import *
import requests

requests.packages.urllib3.disable_warnings()


def sendRequest(method, url, uri, user, passwd, data=None):
    res = None

    if method.lower() == 'get':
        res = requests.get(url + uri, auth=(user, passwd), verify=False)
    if method.lower() == 'post':
        try:
            json.loads(data)
        except ValueError:
            return '### Error: Data is not in JSON format'

        res = requests.post(url + uri, auth=(user, passwd), data=data, verify=False)

    if res.status_code >= 400:
        if res.text.startswith('{'):
            return '### Error: ' + str(res.status_code) + ': ' + res.json()["error"]
        else:
            return '### Error: ' + str(res.status_code)

    return res.text


res = []

apiid = demisto.params()['apiid']
secret = demisto.params()['secret']
url = demisto.params()['url']

# What happens when the 'Test' button is pressed
if demisto.command() == 'test-module':
    res = sendRequest('get', url, "view/ipv4/8.8.8.8", apiid, secret)
    if res.startswith('### Error:'):
        demisto.results({'Type': entryTypes['error'], 'ContentsFormat': 'text', 'Contents': res})
    elif 'Google' in res:
        demisto.results('ok')
else:
    query = demisto.args()['query']
    index = demisto.args()['index']

    if demisto.command() == 'cen-view':
        uri = 'view/' + index + '/' + query
        method = 'get'
        data = None
    elif demisto.command() == 'cen-search':
        uri = 'search/' + index
        method = 'post'
        if not query.startswith('{'):
            data = '{ "query" : "' + query + '", "page" : 1 }'

    res = sendRequest(method, url, uri, apiid, secret, data)

    if res.startswith('### Error:'):
        demisto.results({'Type': entryTypes['error'], 'ContentsFormat': 'text', 'Contents': res})
        sys.exit(0)
    elif res.startswith('{'):
        res = json.loads(res)

    demisto.results(res)

sys.exit(0)
