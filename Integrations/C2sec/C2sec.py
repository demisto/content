import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

API_KEY = demisto.params()['apikey']
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

DOMAIN = demisto.params()['domainName']
if demisto.params()['endpointURL'].count("/") == 3:
    ENDPOINTURL = demisto.params()['endpointURL'] + "/"
else:
    ENDPOINTURL = demisto.params()['endpointURL']

USE_SSL = not demisto.params().get('unsecure', False)


def addcompany(domain, newscan):
    if newscan == 'true':
        newscan = 1
    else:
        newscan = 0

    params = {
        'apikey': API_KEY,
        'domain': domain,
        'newscan': newscan
    }
    call = requests.get(ENDPOINTURL + 'iriskaddcompany', headers=HEADERS, verify=USE_SSL, params=params)

    if call.status_code == requests.codes.ok:
        md = tableToMarkdown('Add Company Result', call.json())
        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': call.json(),
            'HumanReadable': md,
            'EntryContext': {
                "C2sec.Company": call.json()
            }
        }
    else:
        return 'Error adding a new company - status code: [%d] - reason: %s' % (call.status_code, call.text)


def queryWorkitem(workitemid):
    params = {
        'apikey': API_KEY,
        'workitemid': workitemid
    }
    call = requests.get(ENDPOINTURL + '/iriskqueryapistatus', headers=HEADERS, verify=USE_SSL, params=params)
    if call.status_code == requests.codes.ok:
        resp = call.json()
        resp['apistatus']['workitemid'] = workitemid
        md = tableToMarkdown('Query WorkItem Result', resp['apistatus'])
        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': resp,
            'HumanReadable': md,
            'EntryContext': {
                "C2sec.Scan(val.workitemid && val.workitemid == obj.workitemid)": resp['apistatus']
            }
        }
    else:
        return 'Error querying a workitem [%d] - reason: %s' % (call.status_code, call.text)


def queryIssues(domain):
    params = {
        'apikey': API_KEY,
        'domain': domain
    }
    call = requests.get(ENDPOINTURL + 'iRiskQueryIssues', headers=HEADERS, verify=USE_SSL, params=params)
    if call.status_code == requests.codes.ok:
        contexts = []
        for issue in call.json()['issueList']:
            context = {
                'ID': issue['id'],
                'issue': issue['issue'],
                'severity': issue['severity'],
                'component': issue['component'],
                'componentDisplay': issue['componentDisplay'],
                'details': issue['detail'],
                'asset': issue['asset'],
                'rec': issue['rec'],
            }
            contexts.append(context)

        md = tableToMarkdown('Query Issues Result', contexts, ['ID', 'issue', 'severity', 'component',
                                                               'componentDisplay', 'details', 'asset', 'rec'])
        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': call.json(),
            'HumanReadable': md,
            'EntryContext': {
                "C2sec.Issue(val.ID && val.ID == obj.ID)": contexts
            }
        }
    else:
        return 'Error querying for issues [%d] - reason: %s' % (call.status_code, call.text)


def rescan(domain):
    params = {
        'apikey': API_KEY,
        'domain': domain
    }
    call = requests.get(ENDPOINTURL + 'iRiskRescanCompany', headers=HEADERS, verify=USE_SSL, params=params)
    if call.status_code == requests.codes.ok:
        md = tableToMarkdown('Rescan Results', call.json())
        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': call.json(),
            'HumanReadable': md,
            'EntryContext': {
                "C2sec.Scan(val.workitemid && val.workitemid == obj.workitemid)": call.json()
            }
        }
    else:
        return 'Error rescanning the company  [%d] - reason: %s' % (call.status_code, call.text)


def queryComponent(domain, component):
    params = {
        'apikey': API_KEY,
        'domain': domain,
        'component': component
    }
    call = requests.get(ENDPOINTURL + 'iRiskQueryComponentData', headers=HEADERS, verify=USE_SSL, params=params)

    if call.status_code == requests.codes.ok:
        resp = call.json()
        if 'data' in resp:
            for index, _ in enumerate(resp['data']):
                resp['data'][index]['component'] = component

        resp['domain'] = domain
        md = tableToMarkdown('Query Component Result', resp, ['result', 'domain', 'component'],
                             metadata="The results can be found in the context")

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': call.json(),
            'HumanReadable': md,
            'EntryContext': {
                "C2sec.Query(val.domain && val.domain == obj.domain && val.component == obj.component)": resp
            }
        }
    else:
        return_error('Error querying for component [{}] - reason: {}'.format(call.status_code, call.text))


LOG('Command being called is {}'.format(demisto.command()))
try:
    # The command demisto.command() holds the command sent from the user.
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test = addcompany(demisto.params()['domainName'], newscan='false')
        if not isinstance(test, tuple):
            demisto.results("ok")
        else:
            demisto.results(test)
    elif demisto.command() == 'irisk-add-company':
        result = addcompany(demisto.args().get('domain', DOMAIN), demisto.args()['newscan'])
        demisto.results(result)
    elif demisto.command() == 'irisk-query-workitem':
        result = queryWorkitem(demisto.args()['id'])
        demisto.results(result)
    elif demisto.command() == 'irisk-rescan-company':
        result = rescan(demisto.args().get('domain', DOMAIN))
        demisto.results(result)
    elif demisto.command() == 'irisk-query-issues':
        result = queryIssues(demisto.args().get('domain', DOMAIN))
        demisto.results(result)
    elif demisto.command() == 'irisk-query-component':
        domain = demisto.args().get('domain', DOMAIN)
        result = queryComponent(domain, demisto.args()['component'])
        demisto.results(result)

# Log exceptions
except Exception as e:
    return_error(str(e))
