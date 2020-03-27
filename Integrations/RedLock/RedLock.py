<<<<<<< HEAD
import demistomock as demisto
from CommonServerPython import *
import requests
from datetime import datetime

=======
from datetime import datetime

import requests

from CommonServerPython import *

>>>>>>> upstream/master
# disable insecure warnings
requests.packages.urllib3.disable_warnings()

URL = demisto.getParam('url')
if URL[-1] != '/':
    URL += '/'

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

VERIFY = not demisto.params().get('unsecure', False)

# Standard headers
HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
TOKEN = None


def get_token():
    """
    Retrieve the token using the credentials
    """
<<<<<<< HEAD
    r = requests.post(URL + 'login', headers=HEADERS, verify=VERIFY, json={
=======
    response = requests.post(URL + 'login', headers=HEADERS, verify=VERIFY, json={
>>>>>>> upstream/master
        'customerName': demisto.getParam('customer') or '',
        'username': demisto.getParam('credentials')['identifier'],
        'password': demisto.getParam('credentials')['password']
    })
<<<<<<< HEAD
    if r.status_code != requests.codes.ok:
        return_error('Error authenticating to RedLock service [%d] - %s' % (r.status_code, r.text))
    TOKEN = r.json()['token']
=======
    if response.status_code != requests.codes.ok:
        raise Exception('Error authenticating to RedLock service [%d] - %s' % (response.status_code, response.text))
    TOKEN = response.json()['token']
>>>>>>> upstream/master
    HEADERS['x-redlock-auth'] = TOKEN


def req(method, path, data, param_data):
<<<<<<< HEAD
    if not TOKEN:
        get_token()
    r = requests.request(method, URL + path, json=data, params=param_data, headers=HEADERS, verify=VERIFY)
    if r.status_code != requests.codes.ok:
        text = r.text
        if r.headers.get('x-redlock-status'):
            try:
                status = json.loads(r.headers.get('x-redlock-status'))  # type: ignore
                for s in status:
                    text += '\n%s [%s]' % (s.get('i18nKey', ''), s.get('subject', ''))
            except Exception:
                pass
        return_error('Error in API call to RedLock service [%d] - %s' % (r.status_code, text))
    if not r.text:
        return {}
    return r.json()
=======
    """
    Generic request to Prisma Cloud (RedLock)
    """
    if not TOKEN:
        get_token()
    response = requests.request(method, URL + path, json=data, params=param_data, headers=HEADERS, verify=VERIFY)
    if response.status_code != requests.codes.ok:
        text = response.text
        if response.headers.get('x-redlock-status'):
            try:
                statuses = json.loads(response.headers.get('x-redlock-status'))  # type: ignore
                for status in statuses:
                    text += '\n%s [%s]' % (status.get('i18nKey', ''), status.get('subject', ''))
            except Exception:
                pass
        raise Exception('Error in API call to RedLock service [%d] - %s' % (response.status_code, text))
    if not response.text:
        return {}
    return response.json()
>>>>>>> upstream/master


def list_filters():
    """
    List the acceptable filters on alerts
    """
<<<<<<< HEAD
    r = req('GET', 'filter/alert/suggest', None, None)
    filters = [{
        'Name': k,
        'Options': ','.join(r.get(k).get('options')),
        'Static': r.get(k).get('staticFilter')
    } for k in r]
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': r,
=======
    response = req('GET', 'filter/alert/suggest', None, None)
    filters = [{
        'Name': filter_,
        'Options': ','.join(response.get(filter_).get('options')),
        'Static': response.get(filter_).get('staticFilter')
    } for filter_ in response]

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
>>>>>>> upstream/master
        'HumanReadable': tableToMarkdown('Filter options', filters, ['Name', 'Options', 'Static'])
    })


<<<<<<< HEAD
def convertDateToUnix(dstr):
    """
    Convert a given string with MM/DD/YYYY format to millis since epoch
    """
    d = datetime.strptime(dstr, '%m/%d/%Y')
    return int((d - datetime.utcfromtimestamp(0)).total_seconds() * 1000)


def convertUnixToDate(d):
    """
    Convert millise since epoch to date formatted MM/DD/YYYY HH:MI:SS
    """
    if d:
        dt = datetime.utcfromtimestamp(d / 1000)
        return dt.strftime('%m/%d/%Y %H:%M:%S')
    return 'N/A'


def convertUnixToDemisto(d):
    """
    Convert millise since epoch to date formatted MM/DD/YYYYTHH:MI:SS
    """
    if d:
        dt = datetime.utcfromtimestamp(d / 1000)
        return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    return ''


def handle_time_filter(payload, baseCase):
=======
def convert_date_to_unix(date_str):
    """
    Convert a given string with MM/DD/YYYY format to millis since epoch
    """
    date = datetime.strptime(date_str, '%m/%d/%Y')
    return int((date - datetime.utcfromtimestamp(0)).total_seconds() * 1000)


def convert_unix_to_date(timestamp):
    """
    Convert millise since epoch to date formatted MM/DD/YYYY HH:MI:SS
    """
    if timestamp:
        date_time = datetime.utcfromtimestamp(timestamp / 1000)
        return date_time.strftime('%m/%d/%Y %H:%M:%S')
    return 'N/A'


def convert_unix_to_demisto(timestamp):
    """
    Convert millise since epoch to date formatted MM/DD/YYYYTHH:MI:SS
    """
    if timestamp:
        date_time = datetime.utcfromtimestamp(timestamp / 1000)
        return date_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    return ''


def handle_time_filter(payload, base_case):
>>>>>>> upstream/master
    """
    Add the time filter to the payload
    """
    unit = demisto.getArg('time-range-unit')
    value = demisto.getArg('time-range-value')
<<<<<<< HEAD
    timeFrom = demisto.getArg('time-range-date-from')
    timeTo = demisto.getArg('time-range-date-to')
    relative = ('hour', 'day', 'week', 'month', 'year')
    toNow = relative[1:] + ('epoch', 'login')
    if unit:
        if timeFrom or timeTo:
=======
    time_from = demisto.getArg('time-range-date-from')
    time_to = demisto.getArg('time-range-date-to')
    relative = ('hour', 'day', 'week', 'month', 'year')
    to_now = relative[1:] + ('epoch', 'login')
    if unit:
        if time_from or time_to:
>>>>>>> upstream/master
            return_error('You cannot specify absolute times [time-range-date-from, time-range-date-to] '
                         + 'with relative times [time-range-unit, time-range-value]')
        if value:
            if unit not in relative:
                return_error('Time unit for relative time must be one of the following: ' + ','.join(relative))
            payload['timeRange'] = {'type': 'relative', 'value': {'amount': int(value), 'unit': unit}}
        else:
<<<<<<< HEAD
            if unit not in toNow:
                return_error('Time unit for to_now time must be one of the following: ' + ','.join(toNow))
            payload['timeRange'] = {'type': 'to_now', 'value': unit}
    else:
        if not timeFrom or not timeTo:
            payload['timeRange'] = baseCase
        else:
            payload['timeRange'] = {'type': 'absolute', 'value': {
                'startTime': convertDateToUnix(timeFrom), 'endTime': convertDateToUnix(timeTo)}}
=======
            if unit not in to_now:
                return_error('Time unit for to_now time must be one of the following: ' + ','.join(to_now))
            payload['timeRange'] = {'type': 'to_now', 'value': unit}
    else:
        if not time_from or not time_to:
            payload['timeRange'] = base_case
        else:
            payload['timeRange'] = {'type': 'absolute', 'value': {
                'startTime': convert_date_to_unix(time_from), 'endTime': convert_date_to_unix(time_to)}}
>>>>>>> upstream/master


def handle_filters(payload):
    """
    Add filters to the filter object based on received arguments
    """
<<<<<<< HEAD
    argsConversion = {
=======
    args_conversion = {
>>>>>>> upstream/master
        'alert-status': 'alert.status',
        'policy-name': 'policy.name',
        'policy-label': 'policy.label',
        'policy-compliance-standard': 'policy.complianceStandard',
        'cloud-account': 'cloud.account',
        'cloud-region': 'cloud.region',
        'alert-rule-name': 'alertRule.name',
        'resource-id': 'resource.id',
        'resource-name': 'resource.name',
        'resource-type': 'resource.type',
        'alert-id': 'alert.id',
        'cloud-type': 'cloud.type',
        'risk-grade': 'risk.grade',
        'policy-type': 'policy.type',
        'policy-severity': 'policy.severity'
    }
    payload['filters'] = []
<<<<<<< HEAD
    for k in demisto.args():
        if k in ('policy-name', 'policy-label', 'policy-compliance-standard', 'cloud-account', 'cloud-region',
                 'alert-rule-name', 'resource-id', 'resource-name', 'resource-type', 'alert-status', 'alert-id',
                 'cloud-type', 'risk-grade', 'policy-type', 'policy-severity') and demisto.getArg(k):
            payload['filters'].append({'name': argsConversion[k], 'operator': '=', 'value': demisto.getArg(k)})


def alert_to_readable(a):
=======
    for filter_ in demisto.args():
        if filter_ in ('policy-name', 'policy-label', 'policy-compliance-standard', 'cloud-account', 'cloud-region',
                       'alert-rule-name', 'resource-id', 'resource-name', 'resource-type', 'alert-status', 'alert-id',
                       'cloud-type', 'risk-grade', 'policy-type', 'policy-severity') and demisto.getArg(filter_):
            payload['filters'].append(
                {'name': args_conversion[filter_], 'operator': '=', 'value': demisto.getArg(filter_)})


def alert_to_readable(alert):
>>>>>>> upstream/master
    """
    Transform an alert to a nice readable object
    """
    return {
<<<<<<< HEAD
        'ID': a.get('id'),
        'Status': a.get('status'),
        'FirstSeen': convertUnixToDate(a.get('firstSeen')),
        'LastSeen': convertUnixToDate(a.get('lastSeen')),
        'AlertTime': convertUnixToDate(a.get('alertTime')),
        'PolicyName': demisto.get(a, 'policy.name'),
        'PolicyType': demisto.get(a, 'policy.policyType'),
        'PolicyDescription': demisto.get(a, 'policy.description'),
        'PolicySeverity': demisto.get(a, 'policy.severity'),
        'PolicyRecommendation': demisto.get(a, 'policy.recommendation'),
        'PolicyDeleted': demisto.get(a, 'policy.deleted'),
        'PolicyRemediable': demisto.get(a, 'policy.remediable'),
        'RiskRating': demisto.get(a, 'riskDetail.rating'),
        'ResourceName': demisto.get(a, 'resource.name'),
        'ResourceAccount': demisto.get(a, 'resource.account'),
        'ResourceType': demisto.get(a, 'resource.resourceType'),
        'ResourceCloudType': demisto.get(a, 'resource.cloudType')
    }


def alert_to_context(a):
=======
        'ID': alert.get('id'),
        'Status': alert.get('status'),
        'FirstSeen': convert_unix_to_date(alert.get('firstSeen')),
        'LastSeen': convert_unix_to_date(alert.get('lastSeen')),
        'AlertTime': convert_unix_to_date(alert.get('alertTime')),
        'PolicyName': demisto.get(alert, 'policy.name'),
        'PolicyType': demisto.get(alert, 'policy.policyType'),
        'PolicyDescription': demisto.get(alert, 'policy.description'),
        'PolicySeverity': demisto.get(alert, 'policy.severity'),
        'PolicyRecommendation': demisto.get(alert, 'policy.recommendation'),
        'PolicyDeleted': demisto.get(alert, 'policy.deleted'),
        'PolicyRemediable': demisto.get(alert, 'policy.remediable'),
        'RiskRating': demisto.get(alert, 'riskDetail.rating'),
        'ResourceName': demisto.get(alert, 'resource.name'),
        'ResourceAccount': demisto.get(alert, 'resource.account'),
        'ResourceType': demisto.get(alert, 'resource.resourceType'),
        'ResourceCloudType': demisto.get(alert, 'resource.cloudType')
    }


def alert_to_context(alert):
>>>>>>> upstream/master
    """
    Transform a single alert to context struct
    """
    return {
<<<<<<< HEAD
        'ID': a.get('id'),
        'Status': a.get('status'),
        'AlertTime': convertUnixToDate(a.get('alertTime')),
        'Policy': {
            'ID': demisto.get(a, 'policy.policyId'),
            'Name': demisto.get(a, 'policy.name'),
            'Type': demisto.get(a, 'policy.policyType'),
            'Severity': demisto.get(a, 'policy.severity'),
            'Remediable': demisto.get(a, 'policy.remediable')
        },
        'RiskDetail': {
            'Rating': demisto.get(a, 'riskDetail.rating'),
            'Score': demisto.get(a, 'riskDetail.riskScore.score')
        },
        'Resource': {
            'ID': demisto.get(a, 'resource.id'),
            'Name': demisto.get(a, 'resource.name'),
            'Account': demisto.get(a, 'resource.account'),
            'AccountID': demisto.get(a, 'resource.accountId')
=======
        'ID': alert.get('id'),
        'Status': alert.get('status'),
        'AlertTime': convert_unix_to_date(alert.get('alertTime')),
        'Policy': {
            'ID': demisto.get(alert, 'policy.policyId'),
            'Name': demisto.get(alert, 'policy.name'),
            'Type': demisto.get(alert, 'policy.policyType'),
            'Severity': demisto.get(alert, 'policy.severity'),
            'Remediable': demisto.get(alert, 'policy.remediable')
        },
        'RiskDetail': {
            'Rating': demisto.get(alert, 'riskDetail.rating'),
            'Score': demisto.get(alert, 'riskDetail.riskScore.score')
        },
        'Resource': {
            'ID': demisto.get(alert, 'resource.id'),
            'Name': demisto.get(alert, 'resource.name'),
            'Account': demisto.get(alert, 'resource.account'),
            'AccountID': demisto.get(alert, 'resource.accountId')
>>>>>>> upstream/master
        }
    }


def search_alerts():
    """
    Retrieves alerts by filter
    """
    payload = {}  # type: dict
    handle_time_filter(payload, {'type': 'relative', 'value': {'amount': 7, 'unit': 'day'}})
    handle_filters(payload)
<<<<<<< HEAD
    r = req('POST', 'alert', payload, {'detailed': 'true'})
    alerts = []
    context_path = 'Redlock.Alert(val.ID === obj.ID)'
    ec = {context_path: []}  # type: dict
    for k in r:
        alerts.append(alert_to_readable(k))
        ec[context_path].append(alert_to_context(k))
    ec['Redlock.Metadata.CountOfAlerts'] = len(r)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': r,
        'EntryContext': ec,
=======
    response = req('POST', 'alert', payload, {'detailed': 'true'})
    alerts = []
    context_path = 'Redlock.Alert(val.ID === obj.ID)'
    context = {context_path: []}  # type: dict
    for alert in response:
        alerts.append(alert_to_readable(alert))
        context[context_path].append(alert_to_context(alert))
    context['Redlock.Metadata.CountOfAlerts'] = len(response)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'EntryContext': context,
>>>>>>> upstream/master
        'HumanReadable': tableToMarkdown('Alerts', alerts, [
            'ID', 'Status', 'FirstSeen', 'LastSeen', 'AlertTime', 'PolicyName', 'PolicyType', 'PolicyDescription',
            'PolicySeverity', 'PolicyRecommendation', 'PolicyDeleted', 'PolicyRemediable', 'RiskRating', 'ResourceName',
            'ResourceAccount', 'ResourceType', 'ResourceCloudType'
        ])
    })


def get_alert_details():
    """
    Retrieve alert details by given ID
    """
<<<<<<< HEAD
    r = req('GET', 'alert/' + demisto.getArg('alert-id'), None, None)  # {'detailed': demisto.getArg('detailed')})
    alert = alert_to_readable(r)
    alert.update({
        'PolicyID': demisto.get(r, 'policy.policyID'),
        'PolicySystemDefault': demisto.get(r, 'policy.systemDefault'),
        'PolicyLabels': demisto.get(r, 'policy.labels'),
        'PolicyLastModifiedOn': demisto.get(r, 'policy.lastModifiedOn'),
        'PolicyLastModifiedBy': demisto.get(r, 'policy.lastModifiedBy'),
        'RiskScore': demisto.get(r, 'riskDetail.riskScore.score'),
        'ResourceRRN': demisto.get(r, 'resource.rrn'),
        'ResourceID': demisto.get(r, 'resource.id'),
        'ResourceAccountID': demisto.get(r, 'resource.accountId'),
        'ResourceRegionID': demisto.get(r, 'resource.regionId'),
        'ResourceApiName': demisto.get(r, 'resource.resourceApiName'),
        'ResourceUrl': demisto.get(r, 'resource.url'),
        'ResourceData': demisto.get(r, 'resource.data'),
        'ResourceAccessKeyAge': demisto.get(r, 'resource.additionalInfo.accessKeyAge'),
        'ResourceInactiveSinceTs': demisto.get(r, 'resource.additionalInfo.inactiveSinceTs')
    })

    ec = {'Redlock.Alert(val.ID === obj.ID)': alert_to_context(r)}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': r,
        'EntryContext': ec,
        'HumanReadable': tableToMarkdown('Alert', [alert], ['ID', 'Status', 'FirstSeen', 'LastSeen', 'AlertTime', 'PolicyID',
                                                            'PolicyName', 'PolicyType', 'PolicySystemDefault', 'PolicyLabels',
                                                            'PolicyDescription', 'PolicySeverity', 'PolicyRecommendation',
                                                            'PolicyDeleted', 'PolicyRemediable', 'PolicyLastModifiedOn',
                                                            'PolicyLastModifiedBy', 'RiskScore', 'RiskRating',
                                                            'ResourceName', 'ResourceRRN', 'ResourceID', 'ResourceAccount',
                                                            'ResourceAccountID', 'ResourceType',
                                                            'ResourceRegionID', 'ResourceApiName', 'ResourceUrl', 'ResourceData',
                                                            'ResourceAccessKeyAge', 'ResourceInactiveSinceTs', 'ResourceCloudType'
                                                            ])
=======
    response = req('GET', 'alert/' + demisto.getArg('alert-id'), None,
                   None)  # {'detailed': demisto.getArg('detailed')})
    alert = alert_to_readable(response)
    alert.update({
        'PolicyID': demisto.get(response, 'policy.policyID'),
        'PolicySystemDefault': demisto.get(response, 'policy.systemDefault'),
        'PolicyLabels': demisto.get(response, 'policy.labels'),
        'PolicyLastModifiedOn': demisto.get(response, 'policy.lastModifiedOn'),
        'PolicyLastModifiedBy': demisto.get(response, 'policy.lastModifiedBy'),
        'RiskScore': demisto.get(response, 'riskDetail.riskScore.score'),
        'ResourceRRN': demisto.get(response, 'resource.rrn'),
        'ResourceID': demisto.get(response, 'resource.id'),
        'ResourceAccountID': demisto.get(response, 'resource.accountId'),
        'ResourceRegionID': demisto.get(response, 'resource.regionId'),
        'ResourceApiName': demisto.get(response, 'resource.resourceApiName'),
        'ResourceUrl': demisto.get(response, 'resource.url'),
        'ResourceData': demisto.get(response, 'resource.data'),
        'ResourceAccessKeyAge': demisto.get(response, 'resource.additionalInfo.accessKeyAge'),
        'ResourceInactiveSinceTs': demisto.get(response, 'resource.additionalInfo.inactiveSinceTs')
    })

    context = {'Redlock.Alert(val.ID === obj.ID)': alert_to_context(response)}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'EntryContext': context,
        'HumanReadable': tableToMarkdown('Alert', [alert],
                                         ['ID', 'Status', 'FirstSeen', 'LastSeen', 'AlertTime', 'PolicyID',
                                          'PolicyName', 'PolicyType', 'PolicySystemDefault', 'PolicyLabels',
                                          'PolicyDescription', 'PolicySeverity', 'PolicyRecommendation',
                                          'PolicyDeleted', 'PolicyRemediable', 'PolicyLastModifiedOn',
                                          'PolicyLastModifiedBy', 'RiskScore', 'RiskRating',
                                          'ResourceName', 'ResourceRRN', 'ResourceID', 'ResourceAccount',
                                          'ResourceAccountID', 'ResourceType',
                                          'ResourceRegionID', 'ResourceApiName', 'ResourceUrl', 'ResourceData',
                                          'ResourceAccessKeyAge', 'ResourceInactiveSinceTs', 'ResourceCloudType'
                                          ])
>>>>>>> upstream/master
    })


def dismiss_alerts():
    """
    Dismiss the given list of alerts based on given filter
    """
    ids = argToList(demisto.getArg('alert-id'))
    policies = argToList(demisto.getArg('policy-id'))
    payload = {'alerts': ids, 'policies': policies, 'dismissalNote': demisto.getArg('dismissal-note'), 'filter': {}}
    demisto.args().pop('alert-id', None)
    handle_filters(payload['filter'])
    handle_time_filter(payload['filter'], {'type': 'to_now', 'value': 'epoch'})
    if not ids and not policies:
        return_error('You must specify either alert-id or policy-id for dismissing alerts')
<<<<<<< HEAD
    r = req('POST', 'alert/dismiss', payload, None)
    ec = {}
    if ids:
        ec['Redlock.DismissedAlert.ID'] = ids
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': r,
        'EntryContext': ec,
=======
    response = req('POST', 'alert/dismiss', payload, None)
    context = {}
    if ids:
        context['Redlock.DismissedAlert.ID'] = ids
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'EntryContext': context,
>>>>>>> upstream/master
        'HumanReadable': '### Alerts dismissed successfully. Dismissal Note: %s.' % demisto.getArg('dismissal-note')
    })


def reopen_alerts():
    """
    Reopen the given list of alerts based on given filter
    """
    ids = argToList(demisto.getArg('alert-id'))
    policies = argToList(demisto.getArg('policy-id'))
    payload = {'alerts': ids, 'policies': policies, 'filter': {}}
    demisto.args().pop('alert-id', None)
    handle_filters(payload['filter'])
    handle_time_filter(payload['filter'], {'type': 'to_now', 'value': 'epoch'})
    if not ids and not policies:
        return_error('You must specify either alert-id or policy-id for re-opening alerts')
<<<<<<< HEAD
    r = req('POST', 'alert/reopen', payload, None)
    ec = {}
    if ids:
        ec['Redlock.ReopenedAlert.ID'] = ids
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': r,
        'EntryContext': ec,
=======
    response = req('POST', 'alert/reopen', payload, None)
    context = {}
    if ids:
        context['Redlock.ReopenedAlert.ID'] = ids
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'EntryContext': context,
>>>>>>> upstream/master
        'HumanReadable': '### Alerts re-opened successfully.'
    })


def translate_severity(alert):
    """
    Translate alert severity to demisto
    Might take risk grade into account in the future
    """
<<<<<<< HEAD
    sev = demisto.get(alert, 'policy.severity')
    if sev == 'high':
        return 3
    elif sev == 'medium':
        return 2
    elif sev == 'low':
=======
    severity = demisto.get(alert, 'policy.severity')
    if severity == 'high':
        return 3
    if severity == 'medium':
        return 2
    if severity == 'low':
>>>>>>> upstream/master
        return 1
    return 0


def fetch_incidents():
    """
    Retrieve new incidents periodically based on pre-defined instance parameters
    """
    now = int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds() * 1000)
<<<<<<< HEAD
    lastRunObject = demisto.getLastRun()
    lastRun = lastRunObject and lastRunObject['time']
    if not lastRun:
        lastRun = now - 24 * 60 * 60 * 1000
    payload = {
        'timeRange': {
            'type': 'absolute',
            'value': {
                'startTime': lastRun,
                'endTime': now
            }
        }
    }
    payload['filters'] = [{'name': 'alert.status', 'operator': '=', 'value': 'open'}]  # type: ignore
=======
    last_run_object = demisto.getLastRun()
    last_run = last_run_object and last_run_object['time']
    if not last_run:
        last_run = now - 24 * 60 * 60 * 1000
    payload = {'timeRange': {
        'type': 'absolute',
        'value': {
            'startTime': last_run,
            'endTime': now
        }
    }, 'filters': [{'name': 'alert.status', 'operator': '=', 'value': 'open'}]}
>>>>>>> upstream/master
    if demisto.getParam('ruleName'):
        payload['filters'].append({'name': 'alertRule.name', 'operator': '=',  # type: ignore
                                   'value': demisto.getParam('ruleName')})
    if demisto.getParam('policySeverity'):
        payload['filters'].append({'name': 'policy.severity', 'operator': '=',  # type: ignore
                                   'value': demisto.getParam('policySeverity')})
<<<<<<< HEAD
    r = req('POST', 'alert', payload, {'detailed': 'true'})
    incidents = []
    for a in r:
        incidents.append({
            'name': a.get('policy.name', 'No policy') + ' - ' + a.get('id'),
            'occurred': convertUnixToDemisto(a.get('alertTime')),
            'severity': translate_severity(a),
            'rawJSON': json.dumps(a)
=======

    demisto.info("Executing Prisma Cloud (RedLock) fetch_incidents with payload: {}".format(payload))
    response = req('POST', 'alert', payload, {'detailed': 'true'})
    incidents = []
    for alert in response:
        incidents.append({
            'name': alert.get('policy.name', 'No policy') + ' - ' + alert.get('id'),
            'occurred': convert_unix_to_demisto(alert.get('alertTime')),
            'severity': translate_severity(alert),
            'rawJSON': json.dumps(alert)
>>>>>>> upstream/master
        })
    demisto.incidents(incidents)
    demisto.setLastRun({'time': now})


<<<<<<< HEAD
if demisto.command() == 'test-module':
    get_token()
    demisto.results('ok')
elif demisto.command() == 'redlock-search-alerts':
    search_alerts()
elif demisto.command() == 'redlock-list-alert-filters':
    list_filters()
elif demisto.command() == 'redlock-get-alert-details':
    get_alert_details()
elif demisto.command() == 'redlock-dismiss-alerts':
    dismiss_alerts()
elif demisto.command() == 'redlock-reopen-alerts':
    reopen_alerts()
elif demisto.command() == 'fetch-incidents':
    fetch_incidents()
else:
    return_error('Unrecognized command: ' + demisto.command())
=======
try:
    if demisto.command() == 'test-module':
        get_token()
        demisto.results('ok')
    elif demisto.command() == 'redlock-search-alerts':
        search_alerts()
    elif demisto.command() == 'redlock-list-alert-filters':
        list_filters()
    elif demisto.command() == 'redlock-get-alert-details':
        get_alert_details()
    elif demisto.command() == 'redlock-dismiss-alerts':
        dismiss_alerts()
    elif demisto.command() == 'redlock-reopen-alerts':
        reopen_alerts()
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
    else:
        raise Exception('Unrecognized command: ' + demisto.command())
except Exception as err:
    return_error(str(err))
>>>>>>> upstream/master
