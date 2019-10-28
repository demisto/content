import demistomock as demisto
from CommonServerPython import *
import requests
import json
import collections
# disable insecure warnings
requests.packages.urllib3.disable_warnings()

BASE_URL = demisto.params().get('url', 'https://www.securityadvisor.io')
INSECURE = demisto.params().get('insecure')
PROXY = demisto.params().get('proxy')
API_KEY = demisto.params().get('apikey')
URL_SUFFIX = 'apis/coachuser/'
if not demisto.params().get('proxy', False):
    try:
        del os.environ['HTTP_PROXY']
        del os.environ['HTTPS_PROXY']
        del os.environ['http_proxy']
        del os.environ['https_proxy']
    except KeyError:
        pass

# Allows nested keys to be accesible


def makehash():
    return collections.defaultdict(makehash)


'''MAIN FUNCTIONS'''


def send_message(user, context):
    query = {'username': user, 'context': context}
    search = json.dumps(query)
    r = http_request('POST', URL_SUFFIX, search)
    return r


def coach_end_user_command():
    user = demisto.args().get('user')
    context = demisto.args().get('context')
    res = send_message(user, context)
    # demisto.log(json.dumps(res))
    # contents = res['message']
    res_message = res['message']
    res_coaching_status = res['coaching_status']
    res_coaching_score = res['coaching_score']
    res_coaching_date = res['coaching_date']
    contxt = makehash()
    human_readable = makehash()
    human_readable['user'] = user
    human_readable['context'] = context
    human_readable['message'] = res_message
    human_readable['coaching_status'] = res_coaching_status
    human_readable['coaching_score'] = res_coaching_score
    human_readable['coaching_date'] = res_coaching_date
    contxt['user'] = user
    contxt['context'] = context
    contxt['message'] = res_message
    contxt['coaching_status'] = res_coaching_status
    contxt['coaching_score'] = res_coaching_score
    contxt['coaching_date'] = res_coaching_date
    ec = {'SecurityAdvisor.CoachUser(val.user == obj.user && val.context == obj.context)': contxt}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': res,
        'HumanReadable': tableToMarkdown('SecurityAdvisorBot says...', human_readable),
        'EntryContext': ec
    })


'''HELPER FUNCTIONS'''


def http_request(method, URL_SUFFIX, json=None):
    if method == 'GET':
        headers = {}  # type: Dict
    elif method == 'POST':
        if not API_KEY:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        else:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'Token ' + API_KEY
            }
    # LOG(json)
    # LOG.print_log()
    r = requests.request(
        method,
        BASE_URL + URL_SUFFIX,
        data=json,
        headers=headers,
        verify=INSECURE
    )
    if r.status_code != 200:
        return_error('Error in API call [%d] - %s' % (r.status_code, r.reason))
    return r.json()


''' EXECUTION '''
LOG('command is %s' % (demisto.command(), ))
try:
    if demisto.command() == 'coach-end-user':
        coach_end_user_command()
    elif demisto.command() == 'test-module':
        user = 'track@securityadvisor.io'
        context = "malware"
        send_message(user, context)
        demisto.results('ok')
except Exception, e:
    demisto.debug('Error in SecurityAdvisor')
    LOG(e.message)
    return_error(e.message)
