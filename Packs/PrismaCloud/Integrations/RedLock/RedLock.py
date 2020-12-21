import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa F401 # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa F401 # pylint: disable=unused-wildcard-import
from datetime import datetime

import requests
import os

# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

URL = demisto.getParam('url')
if URL[-1] != '/':
    URL += '/'

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

VERIFY = not demisto.params().get('unsecure', False)

DEFAULT_LIMIT = 100

# Standard headers
HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
TOKEN = None


def get_token():
    """
    Retrieve the token using the credentials
    """
    response = requests.post(URL + 'login', headers=HEADERS, verify=VERIFY, json={
        'customerName': demisto.getParam('customer') or '',
        'username': demisto.getParam('credentials')['identifier'],
        'password': demisto.getParam('credentials')['password']
    })

    if response.status_code != requests.codes.ok:  # pylint: disable=no-member
        raise Exception('Error authenticating to RedLock service [%d] - %s' % (response.status_code, response.text))
    try:
        response_json = response.json()
        TOKEN = response_json.get('token')
        if not TOKEN:
            demisto.debug(json.dumps(response_json))
            message = 'Could not retrieve token from server: {}'.format(response_json.get("message"))
            if response_json.get('message') == 'login_needs_customer_name':
                available_customer_names = [name.get('customerName') for name in response_json.get('customerNames')]
                message = 'In order to login a customer name need to be configured. Available customer names: {}'.format(
                    {", ".join(available_customer_names)})
            raise Exception(message)
    except ValueError as exception:
        demisto.log(exception)
        raise Exception('Could not parse API response.')
    HEADERS['x-redlock-auth'] = TOKEN


def req(method, path, data, param_data):
    """
    Generic request to Prisma Cloud (RedLock)
    """
    if not TOKEN:
        get_token()
    response = requests.request(method, URL + path, json=data, params=param_data, headers=HEADERS, verify=VERIFY)
    if response.status_code != requests.codes.ok:  # pylint: disable=no-member
        text = response.text
        if response.headers.get('x-redlock-status'):
            try:
                statuses = json.loads(response.headers.get('x-redlock-status'))  # type: ignore
                for status in statuses:
                    text += '\n%s [%s]' % (status.get('i18nKey', ''), status.get('subject', ''))
                    # Handle case for no remediation details
                    if status['i18nKey'] == 'remediation_unavailable':
                        return False
                    if status['i18nKey'] == 'alert_no_longer_in_expected_state':
                        return False
            except Exception:
                pass
        raise Exception('Error in API call to RedLock service [%d] - %s' % (response.status_code, text))
    if not response.text:
        return {}
    return response.json()


def format_response(response):
    if response and isinstance(response, dict):
        response = {pascalToSpace(key).replace(" ", ""): format_response(value) for key, value in response.items()}
    elif response and isinstance(response, list):
        response = [format_response(item) for item in response]
    return response


def list_filters():
    """
    List the acceptable filters on alerts
    """
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
        'HumanReadable': tableToMarkdown('Filter options', filters, ['Name', 'Options', 'Static'])
    })


def convert_date_to_unix(date_str):
    """
    Convert a given string with MM/DD/YYYY format to millis since epoch
    """
    date = datetime.strptime(date_str, '%m/%d/%Y')
    return int((date - datetime.utcfromtimestamp(0)).total_seconds() * 1000)


def convert_unix_to_date(timestamp):
    """
    Convert milliseconds since epoch to date formatted MM/DD/YYYY HH:MI:SS
    """
    if timestamp:
        date_time = datetime.utcfromtimestamp(timestamp / 1000)
        return date_time.strftime('%m/%d/%Y %H:%M:%S')
    return 'N/A'


def convert_unix_to_demisto(timestamp):
    """
    Convert milliseconds since epoch to date formatted MM/DD/YYYYTHH:MI:SS
    """
    if timestamp:
        date_time = datetime.utcfromtimestamp(timestamp / 1000)
        return date_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    return ''


def handle_time_filter(payload, base_case):
    """
    Add the time filter to the payload
    """
    unit = demisto.getArg('time-range-unit')
    value = demisto.getArg('time-range-value')
    time_from = demisto.getArg('time-range-date-from')
    time_to = demisto.getArg('time-range-date-to')
    relative = ('hour', 'day', 'week', 'month', 'year')
    to_now = relative[1:] + ('epoch', 'login')
    if unit:
        if time_from or time_to:
            return_error('You cannot specify absolute times [time-range-date-from, time-range-date-to] '
                         + 'with relative times [time-range-unit, time-range-value]')
        if value:
            if unit not in relative:
                return_error('Time unit for relative time must be one of the following: ' + ','.join(relative))
            payload['timeRange'] = {'type': 'relative', 'value': {'amount': int(value), 'unit': unit}}
        else:
            if unit not in to_now:
                return_error('Time unit for to_now time must be one of the following: ' + ','.join(to_now))
            payload['timeRange'] = {'type': 'to_now', 'value': unit}
    else:
        if not time_from or not time_to:
            payload['timeRange'] = base_case
        else:
            payload['timeRange'] = {'type': 'absolute', 'value': {
                'startTime': convert_date_to_unix(time_from), 'endTime': convert_date_to_unix(time_to)}}


def handle_filters(payload):
    """
    Add filters to the filter object based on received arguments
    """
    args_conversion = {
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
    for filter_ in demisto.args():
        if filter_ in ('policy-name', 'policy-label', 'policy-compliance-standard', 'cloud-account', 'cloud-region',
                       'alert-rule-name', 'resource-id', 'resource-name', 'resource-type', 'alert-status', 'alert-id',
                       'cloud-type', 'risk-grade', 'policy-type', 'policy-severity') and demisto.getArg(filter_):
            payload['filters'].append(
                {'name': args_conversion[filter_], 'operator': '=', 'value': demisto.getArg(filter_)})


def alert_to_readable(alert):
    """
    Transform an alert to a nice readable object
    """
    return {
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
    """
    Transform a single alert to context struct
    """
    ec = {
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
        }
    }
    if alert.get('alertRules'):
        ec['AlertRules'] = [alert_rule.get('name') for alert_rule in alert.get('alertRules')]

    return ec


def search_alerts():
    """
    Retrieves alerts by filter
    """
    payload = {}  # type: dict
    handle_time_filter(payload, {'type': 'relative', 'value': {'amount': 7, 'unit': 'day'}})
    handle_filters(payload)
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
        'HumanReadable': tableToMarkdown('Alert', alert, removeNull=True)
    })


def dismiss_alerts():
    """
    Dismiss the given list of alerts based on given filter
    """
    ids = argToList(demisto.getArg('alert-id'))
    policies = argToList(demisto.getArg('policy-id'))
    payload = {'alerts': ids, 'policies': policies, 'dismissalNote': demisto.getArg('dismissal-note'), 'filter': {}}
    demisto.args().pop('alert-id', None)
    args = demisto.args()
    snooze_value = args.get('snooze-value', None)
    snooze_unit = args.get('snooze-unit', None)
    msg_notes = ['dismissed', 'Dismissal']

    if snooze_value and snooze_unit:
        payload['dismissalTimeRange'] = {
            'type': 'relative',
            'value': {
                'unit': snooze_unit,
                'amount': int(snooze_value)
            }
        }
        msg_notes = ['snoozed', 'Snooze']
    handle_filters(payload['filter'])
    handle_time_filter(payload['filter'], {'type': 'to_now', 'value': 'epoch'})
    if not ids and not policies:
        return_error('You must specify either alert-id or policy-id for dismissing alerts')
    response = req('POST', 'alert/dismiss', payload, None)
    if response is False:
        demisto.results("Alert not in expected state.")
    else:
        context = {}
        if ids:
            context['Redlock.DismissedAlert.ID'] = ids

            md = '### Alerts {} successfully. {} Note: {}.'.format(msg_notes[0], msg_notes[1], demisto.getArg('dismissal-note'))

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': response,
            'EntryContext': context,
            'HumanReadable': md
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
    response = req('POST', 'alert/reopen', payload, None)
    context = {}
    if ids:
        context['Redlock.ReopenedAlert.ID'] = ids
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'EntryContext': context,
        'HumanReadable': '### Alerts re-opened successfully.'
    })


def translate_severity(alert):
    """
    Translate alert severity to demisto
    Might take risk grade into account in the future
    """
    severity = demisto.get(alert, 'policy.severity')
    if severity == 'high':
        return 3
    if severity == 'medium':
        return 2
    if severity == 'low':
        return 1
    return 0


def get_rql_response():

    """"
    Retrieve any RQL
    """
    rql = demisto.getArg('rql').encode("utf-8")

    limit = demisto.args().get('limit', '1')
    rql += " limit search records to {}".format(limit)

    payload = {"query": rql, "filter": {}}

    handle_filters(payload['filter'])
    handle_time_filter(payload['filter'], {'type': 'to_now', 'value': 'epoch'})

    response = req('POST', 'search/config', payload, None)

    human_readable = []

    items = response["data"]["items"]

    for item in items:
        tmp_human_readable = {
            "ResourceName": item["name"],
            "Service": item["service"],
            "Account": item["accountName"],
            "Region": item["regionName"],
            "Deleted": item["deleted"]
        }
        human_readable.append(tmp_human_readable)

    contents = format_response(items)
    rql_data = {
        "Query": rql,
        "Response": contents
    }

    md = tableToMarkdown(name="RQL Output:", t=human_readable, headerTransform=pascalToSpace, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': rql_data,
        'EntryContext': {'Redlock.RQL(val.Query === obj.Query)': rql_data},
        'HumanReadable': md
    })


def get_remediation_details():
    """
    Retrieve remediation details for a given alert
    """
    alert_ids = argToList(demisto.getArg('alert-id'))
    payload = {'alerts': alert_ids, 'filter': {}}
    handle_filters(payload['filter'])
    handle_time_filter(payload['filter'], {'type': 'to_now', 'value': 'epoch'})

    md_data = []
    context = []
    response = req('POST', 'alert/remediation', payload, None)

    if response:
        for alert_id in alert_ids:
            details = {
                'ID': alert_id,
                'Remediation': {
                    'CLI': response['alertIdVsCliScript'][alert_id],
                    'Description': response['cliDescription']
                }
            }
            human_readable_details = {
                'ID': details['ID'],
                'RemediationCLI': details['Remediation']['CLI'],
                'RemediationDescription': details['Remediation']['Description']
            }
            context.append(details)
            md_data.append(human_readable_details)

        MD = tableToMarkdown("Remediation Details", md_data)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': response,
            'EntryContext': {'Redlock.Alert(val.ID == obj.ID)': context},
            'HumanReadable': MD
        })
    else:
        demisto.results('No Remediation Details Found')


def redlock_search_config():
    """
    Run query in config
    """
    query = demisto.args().get('query', None)
    limit = demisto.args().get('limit', None)
    if not limit:
        limit = DEFAULT_LIMIT
    else:
        limit = int(limit)

    if not query:
        return_error('You must specify a query to retrieve assets')
    payload = {
        'query': query,
        'limit': limit,
        'sort': [{"direction": "desc", "field": "insertTs"}],
        'withResourceJson': True
    }
    handle_time_filter(payload, {'type': 'to_now', 'value': 'epoch'})

    response = req('POST', 'search/config', payload, None)

    if (
        not response
        or 'data' not in response
        or not isinstance(response['data'], dict)
        or 'items' not in response['data']
        or not isinstance(response['data']['items'], list)
    ):
        demisto.results('No results found')
    else:
        items = response['data']['items']
        MD = tableToMarkdown("Configuration Details", items)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': items,
            'EntryContext': {'Redlock.Asset(val.id == obj.id)': items},
            'HumanReadable': MD
        })


def fetch_incidents():
    """
    Retrieve new incidents periodically based on pre-defined instance parameters
    """
    now = int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds() * 1000)
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
    if demisto.getParam('ruleName'):
        payload['filters'].append({'name': 'alertRule.name', 'operator': '=',  # type: ignore
                                   'value': demisto.getParam('ruleName')})
    if demisto.getParam('policySeverity'):
        payload['filters'].append({'name': 'policy.severity', 'operator': '=',  # type: ignore
                                   'value': demisto.getParam('policySeverity')})

    demisto.info("Executing Prisma Cloud (RedLock) fetch_incidents with payload: {}".format(payload))
    response = req('POST', 'alert', payload, {'detailed': 'true'})
    incidents = []
    for alert in response:
        incidents.append({
            'name': alert.get('policy.name', 'No policy') + ' - ' + alert.get('id'),
            'occurred': convert_unix_to_demisto(alert.get('alertTime')),
            'severity': translate_severity(alert),
            'rawJSON': json.dumps(alert)
        })
    demisto.incidents(incidents)
    demisto.setLastRun({'time': now})


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
    elif demisto.command() == 'redlock-get-remediation-details':
        get_remediation_details()
    elif demisto.command() == 'redlock-get-rql-response':
        get_rql_response()
    elif demisto.command() == 'redlock-search-config':
        redlock_search_config()
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
    else:
        raise Exception('Unrecognized command: ' + demisto.command())
except Exception as err:
    return_error(str(err))
