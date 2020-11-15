import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

server = demisto.params()["Server"]
token = demisto.params()["Api-Token"]
ssl_check = not demisto.params().get('unsecure', False)
headers = {'Authorization': token}

if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    url = 'https://' + server + '/external/v1/alerts/'
    response = requests.put(url, headers=headers, verify=ssl_check)
    # This is the call made when pressing the integration test button.
    if response.status_code == requests.codes.ok:
        demisto.results('ok')
    else:
        demisto.results(response.status_code)
    sys.exit(0)

# This command takes a UUID as argument to update the according incident
if demisto.command() == 'cyberx-update-alert':
    url = 'https://' + server + '/external/v1/alerts/' + demisto.args()["cyberx_uuid"]
    payload = {"action": demisto.args()["action"]}
    response = requests.put(url, data=json.dumps(payload), headers=headers, verify=ssl_check)
    demisto.results(response.content)
    sys.exit(0)
