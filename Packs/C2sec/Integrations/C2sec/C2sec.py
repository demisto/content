import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import requests
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

API_KEY = demisto.params().get('apikey_creds', {}).get('password') or demisto.params().get('apikey')
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


def add_domain(domain, newscan):
    if newscan == 'true':
        newscan = 1
    else:
        newscan = 0

    params = {
        'apikey': API_KEY,
        'domain': domain,
        'newscan': newscan
    }
    call = requests.get(ENDPOINTURL + '/iriskaddcompany', headers=HEADERS, verify=USE_SSL, params=params)

    if call.status_code == requests.codes.ok:
        result_dictionary = {
            'result': call.json()['result'],
            'Name': domain
        }

        md = tableToMarkdown('Add domain Result', result_dictionary)
        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': call.json(),
            'HumanReadable': md,
            'EntryContext': {
                "C2sec.Domain(val.Name && val.Name == obj.Name)": result_dictionary
            }
        }
    else:
        return 'Error searching domain - status code: [%d] - reason: %s' % (call.status_code, call.text)


def get_scan_status(workitemid):
    params = {
        'apikey': API_KEY,
        'workitemid': workitemid
    }
    call = requests.get(ENDPOINTURL + '/iriskqueryapistatus', headers=HEADERS, verify=USE_SSL, params=params)
    if call.status_code == requests.codes.ok:
        resp = call.json()
        resp['apistatus']['workitemid'] = workitemid
        md = tableToMarkdown('Get scan Result', resp['apistatus'], removeNull=True)
        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': resp,
            'HumanReadable': md,
            'EntryContext': {
                "C2sec.Domain.Scan(val.workitemid && val.workitemid == obj.workitemid)": resp['apistatus']
            }
        }
    else:
        return 'Error getting scan results [%d] - reason: %s' % (call.status_code, call.text)


def get_domain_issues(domain, severity=None):
    params = {
        'apikey': API_KEY,
        'domain': domain
    }
    call = requests.get(ENDPOINTURL + '/iRiskQueryIssues', headers=HEADERS, verify=USE_SSL, params=params)
    if call.status_code == requests.codes.ok:
        contexts = []
        for issue in call.json().get('issueList', []):
            if severity and severity != issue['severity']:
                continue

            context = {
                'ID': issue['id'],
                'Issue': issue['issue'],
                'Severity': issue['severity'],
                'Component': issue['component'],
                'ComponentDisplay': issue['componentDisplay'],
                'Details': issue['detail'],
                'Asset': issue['asset'],
                'Rec': issue['rec'],
            }
            contexts.append(context)

        md = tableToMarkdown('Get domain Issues Result', contexts,
                             ['ID', 'Issue', 'Severity', 'Component', 'ComponentDisplay', 'Details', 'Asset', 'Rec'])
        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': call.json(),
            'HumanReadable': md,
            'EntryContext': {
                "C2sec.Domain(val.Name && val.Name == obj.Name)": {
                    'Name': domain,
                    'Issue': contexts
                }
            }
        }
    else:
        return 'Error getting issues [%d] - reason: %s' % (call.status_code, call.text)


def rescan_domain(domain):
    params = {
        'apikey': API_KEY,
        'domain': domain
    }
    call = requests.get(ENDPOINTURL + '/iRiskRescanCompany', headers=HEADERS, verify=USE_SSL, params=params)
    if call.status_code == requests.codes.ok:
        md = tableToMarkdown('Rescan domain Results', call.json())
        context = call.json()
        context['domain'] = domain

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': call.json(),
            'HumanReadable': md,
            'EntryContext': {
                "C2sec.Domain.Scan(val.workitemid && val.workitemid == obj.workitemid)": context
            }
        }
    else:
        return 'Error rescanning the domain [%d] - reason: %s' % (call.status_code, call.text)


def get_scan_results(domain, component):
    params = {
        'apikey': API_KEY,
        'domain': domain,
        'component': component
    }
    call = requests.get(ENDPOINTURL + '/iRiskQueryComponentData', headers=HEADERS, verify=USE_SSL, params=params)

    if call.status_code == requests.codes.ok:
        resp = call.json()

        resp['Domain'] = domain
        md = tableToMarkdown('Get Scan Result', resp, ['result', 'Domain', 'component'],
                             metadata="The results can be found in the context")

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': call.json(),
            'HumanReadable': md,
            'EntryContext': {
                f"C2sec.Domain.{component}(val.Domain && val.Domain == obj.Domain)": resp
            }
        }
    else:
        return_error(f'Error getting the scan results [{call.status_code}] - reason: {call.text}')


LOG(f'Command being called is {demisto.command()}')
try:
    handle_proxy()
    # The command demisto.command() holds the command sent from the user.
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test = add_domain(demisto.params()['domainName'], newscan='false')
        if isinstance(test, dict) and "HTTPSConnectionPool" not in test and \
                'error' not in test.get('Contents', {}).get('result', ''):
            demisto.results("ok")
        else:
            demisto.results(test)
    elif demisto.command() == 'irisk-add-domain':
        result = add_domain(demisto.args().get('domain', DOMAIN), demisto.args()['newscan'])
        demisto.results(result)
    elif demisto.command() == 'irisk-get-scan-status':
        result = get_scan_status(demisto.args()['id'])
        demisto.results(result)
    elif demisto.command() == 'irisk-rescan-domain':
        result = rescan_domain(demisto.args().get('domain', DOMAIN))
        demisto.results(result)
    elif demisto.command() == 'irisk-get-domain-issues':
        result = get_domain_issues(demisto.args().get('domain', DOMAIN), demisto.args().get('severity'))
        demisto.results(result)
    elif demisto.command() == 'irisk-get-scan-results':
        domain = demisto.args().get('domain', DOMAIN)
        result = get_scan_results(domain, demisto.args()['component'])
        demisto.results(result)

# Log exceptions
except Exception as e:
    return_error(str(e))
