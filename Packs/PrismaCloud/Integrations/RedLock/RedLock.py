from CommonServerPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

URL = ''
VERIFY = False
DEFAULT_LIMIT = 100

# Standard headers
HEADERS = {'Content-Type': 'application/json', 'Accept': '*/*'}
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


def convert_date_to_unix(date_str, date_format="%m/%d/%Y"):
    """
    Convert the given string in the given format (by default - MM/DD/YYYY) to millis since epoch
    """
    date = datetime.strptime(date_str, date_format)
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

            md = '### Alerts {} successfully. {} Note: {}.'.format(msg_notes[0], msg_notes[1],
                                                                   demisto.getArg('dismissal-note'))

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


def get_rql_response(args):
    """"
    Retrieve any RQL
    """
    rql = args.get('rql')

    limit = str(args.get('limit', '1'))
    rql += " limit search records to {}".format(limit)

    payload = {"query": rql, "filter": {}}

    handle_filters(payload['filter'])
    handle_time_filter(payload['filter'], {'type': 'to_now', 'value': 'epoch'})

    response = req('POST', 'search/config', payload, None)

    human_readable = []

    attributes = response.get('data')
    items = attributes.get('items', [])

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
        response_data = response.get('data')
        items = response_data.get('items', [])
        md = tableToMarkdown("Configuration Details", items)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': items,
            'EntryContext': {'Redlock.Asset(val.id == obj.id)': items},
            'HumanReadable': md
        })


def redlock_list_scans():
    """
     Returns a list of IaC scans that meet the given conditions.

     See Also:
         https://prisma.pan.dev/api/cloud/cspm/iac-scan/#operation/getScans

    """
    args = demisto.args()
    group_by = args.get('group_by', 'scanId')
    page_size = args.get('page_size', 25)
    page_number = args.get('page_number', 1)
    sort = args.get('sort', None)
    filter_type = args.get('filter_type', 'relative')
    filter_time_amount = args.get('filter_time_amount', 1)
    to_now_time_unit = args.get('to_now_time_unit', 'login')
    relative_time_unit = args.get('relative_time_unit', 'day')
    filter_user = args.get('filter_user', None)
    filter_status = args.get('filter_status', None)
    filter_asset_type = args.get('filter_asset_type', None)
    filter_asset_name = args.get('filter_asset_name', None)
    filter_start_time = args.get('filter_start_time', None)
    filter_end_time = args.get('filter_end_time', None)

    list_filter = {
        'groupBy': group_by,
        'page[size]': page_size,
        'page[number]': page_number,
        'filter[timeType]': filter_type
    }

    if sort:
        list_filter['sort'] = sort

    if filter_type == 'relative':
        if relative_time_unit and filter_time_amount:
            list_filter['filter[timeUnit]'] = relative_time_unit
            list_filter['filter[timeAmount]'] = filter_time_amount
        else:
            return_error('You must specify a relative_time_unit and filter_time_amount with relative type filter')
    elif filter_type == 'to_now':
        if to_now_time_unit:
            list_filter['filter[timeUnit]'] = to_now_time_unit
        else:
            return_error('You must specify to_now_time_unit with to_now type filter')
    elif filter_type == 'absolute':
        if filter_start_time and filter_end_time:
            list_filter['filter[startTime]'] = convert_date_to_unix(filter_start_time, date_format="%m/%d/%Y %H:%M:%S")
            list_filter['filter[endTime]'] = convert_date_to_unix(filter_end_time, date_format="%m/%d/%Y %H:%M:%S")
        else:
            return_error('You must specify a filter_start_time and filter_end_time with absolute type filter')

    if filter_user:
        list_filter['filter[user]'] = filter_user

    if filter_status:
        list_filter['filter[status]'] = filter_status

    if filter_asset_type:
        list_filter['filter[assetType]'] = filter_asset_type

    if filter_asset_name:
        list_filter['filter[assetName]'] = filter_asset_name

    response = req('GET', 'iac/v2/scans', param_data=list_filter, data={})
    if (
            not response
            or 'data' not in response
            or not isinstance(response.get('data'), list)
    ):
        demisto.results('No results found')
    else:
        items = response.get('data', [])
        readable_output = []
        for item in items:
            id = item.get('id')
            attributes = item.get('attributes', {})
            readable_output.append({
                "ID": id,
                "Name": attributes.get('name', []),
                "Type": attributes.get('type', []),
                "Scan Time": attributes.get('scanTime'),
                "User": attributes.get('user', [])
            })
            # flatten the attributes section of the item - i.e removes 'attributes' key
            item.pop('attributes', None)
            for key, value in attributes.items():
                item[key] = value

        md = tableToMarkdown("Scans List:", readable_output)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': items,
            'EntryContext': {'Redlock.Scans(val.id == obj.id)': items},
            'HumanReadable': md
        })


def redlock_get_scan_status():
    """
    Returns the status of the asynchronous IaC scan job that has the specified scan ID.

    See Also:
        https://prisma.pan.dev/api/cloud/cspm/iac-scan/#operation/getAsyncScanStatus

    """
    scan_id = demisto.args().get('scan_id', None)

    response = req('GET', f'iac/v2/scans/{scan_id}/status', param_data={}, data={})
    if (
            not response
            or 'data' not in response
    ):
        demisto.results('No results found')
    else:
        result = response.get('data', {})
        id = result.get('id')
        status = result.get('attributes', {}).get('status')
        readable_output = {
            "ID": id,
            "Status": status
        }

        result = {
            'id': id,
            'status': status
        }

        md = tableToMarkdown("Scan Status:", readable_output)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'EntryContext': {'Redlock.Scans(val.id == obj.id)': result},
            'HumanReadable': md
        })


def redlock_get_scan_results():
    """
    Returns scan result details for the completed scan that has the specified scan ID.

    See Also:
        https://prisma.pan.dev/api/cloud/cspm/iac-scan/#operation/getScanResult
    """
    scan_id = demisto.args().get('scan_id', None)

    response = req('GET', f'iac/v2/scans/{scan_id}/results', param_data={}, data={})
    if (
            not response
            or 'data' not in response
            or not isinstance(response.get('data'), list)
    ):
        demisto.results('No results found')
    else:
        items = response.get('data', [])
        readable_output = []
        for item in items:
            id = item.get('id')
            attributes = item.get('attributes', {})
            readable_output.append({
                "ID": id,
                "Name": attributes.get('name'),
                "Policy ID": attributes.get('policyId'),
                "Description": attributes.get('desc'),
                "Severity": attributes.get('severity')
            })
        results = {
            "id": scan_id,
            "results": items
        }
        md = tableToMarkdown("Scan Results:", readable_output)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': results,
            'EntryContext': {'Redlock.Scans(val.id == obj.id)': results},
            'HumanReadable': md
        })


def fetch_incidents():
    """
    Retrieve new incidents periodically based on pre-defined instance parameters
    """
    now = int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds() * 1000)
    last_run = demisto.getLastRun().get('time')
    if not last_run:  # first time fetch
        last_run = parse_date_range(demisto.params().get('fetch_time', '3 days').strip(), to_timestamp=True)[0]

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
    if demisto.getParam('policyName'):
        payload['filters'].append({'name': 'policy.name', 'operator': '=',  # type: ignore
                                   'value': demisto.getParam('policyName')})
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

    return incidents, now


def main():
    global URL, VERIFY
    handle_proxy()
    params = demisto.params()
    URL = params.get('url')
    if URL[-1] != '/':
        URL += '/'
    VERIFY = not params.get('unsecure', False)
    try:
        command = demisto.command()
        if command == 'test-module':
            get_token()
            return_results('ok')
        elif command == 'redlock-search-alerts':
            search_alerts()
        elif command == 'redlock-list-alert-filters':
            list_filters()
        elif command == 'redlock-get-alert-details':
            get_alert_details()
        elif command == 'redlock-dismiss-alerts':
            dismiss_alerts()
        elif command == 'redlock-reopen-alerts':
            reopen_alerts()
        elif command == 'redlock-get-remediation-details':
            get_remediation_details()
        elif command == 'redlock-get-rql-response':
            get_rql_response(demisto.args())
        elif command == 'redlock-search-config':
            redlock_search_config()
        elif command == 'redlock-list-scans':
            redlock_list_scans()
        elif command == 'redlock-get-scan-status':
            redlock_get_scan_status()
        elif command == 'redlock-get-scan-results':
            redlock_get_scan_results()
        elif command == 'fetch-incidents':
            incidents, new_run = fetch_incidents()
            demisto.incidents(incidents)
            demisto.setLastRun({'time': new_run})
        else:
            raise Exception('Unrecognized command: ' + command)
    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
