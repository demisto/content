import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
from datetime import datetime
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

URL = demisto.getParam('URL')
if URL[-1] != '/':
    URL += '/'
QUERY = {'username': demisto.getParam('Username'), 'api_key': demisto.getParam('APIKey')}
FETCH_LIMIT = int(demisto.params().get('fetchLimit', 100))
USE_SSL = not demisto.params().get('insecure', False)


def req(method, path, query):
    """
    Send the request to JASK and return the JSON response
    """
    r = requests.request(method, URL + path, params=query, verify=USE_SSL)
    if r.status_code != requests.codes.ok:
        return_error('Error in API call to Jask service - %s' % r.text)
    if not r.text:
        return {}
    return r.json()


def to_readable(o, fields, translated):
    """
    Convert object properties to nice title readable
    """
    res = {}
    if o:
        for f in fields:
            if o.get(f):
                if translated.get(f):
                    res[translated.get(f)] = o.get(f)
                else:
                    res[f.title().replace('_', '')] = o.get(f)
    return res


def entity_to_readable(entity_json):
    """
    Convert entity response JSON to nicely formatted object
    """
    entity = to_readable(entity_json,
                         ['id', 'name', 'source', 'hostname', 'risk_score', 'is_whitelisted', 'groups', 'asset_type',
                          'firstSeen', 'lastSeen'],
                         {'asset_type': 'EntityType', 'firstSeen': 'FirstSeen', 'lastSeen': 'LastSeen'})
    entity['PrimaryEntityType'] = demisto.get(entity_json, 'current_entity.primary_asset_type')
    return entity


def signal_to_readable(signal_json):
    """
    Convert signal response JSON to nicely formatted object
    """
    signal = to_readable(
        signal_json, ['id', 'name', 'category', 'description', 'score', 'source_type', 'timestamp'], {})
    threat_indicators = demisto.get(signal_json, 'threat_indicators')
    if threat_indicators and isinstance(threat_indicators, dict):
        signal['ThreatIndicators'] = [{
            'IndicatorType': ti.get('indicator_type'),
            'Value': ti.get('value')
        } for ti in threat_indicators]
    return signal


def insight_to_readable(insight_json):
    """
    Convert insight response JSON to nicely formatted object
    """
    insight = to_readable(insight_json,
                          ['id', 'name', 'action', 'assigned_to', 'description', 'last_updated_by', 'last_updated',
                           'severity', 'workflow_status'], {})
    if insight_json.get('record_start_time'):
        insight['InsightTime'] = datetime.utcfromtimestamp(insight_json.get('record_start_time')).isoformat()
    if demisto.get(insight_json, 'ip') and demisto.get(insight_json['ip'], 'address'):
        insight['IpAddress'] = demisto.get(insight_json['ip'], 'address')
    return insight


def convert_string_date_to_unix(dstr):
    """
    Convert a given string with MM/DD/YYYY format to millis since epoch
    """
    d = datetime.strptime(dstr, '%m/%d/%Y')
    return int((d - datetime.utcfromtimestamp(0)).total_seconds() * 1000)


def get_insight_details():
    """
    Get insight details
    """
    alert_id = demisto.getArg('insight-id')
    resp_json = req('GET', 'alert/' + alert_id, QUERY)
    ec = insight_to_readable(resp_json)

    details_md = tableToMarkdown('Insight Details:', [ec],
                                 ['Id', 'Name', 'Action', 'AssignedTo', 'Description', 'IpAddress', 'LastUpdated',
                                  'LastUpdatedBy', 'Severity', 'InsightTime', 'WorkflowStatus'])

    entity_display = entity_to_readable(resp_json.get('asset_details'))
    entity_display.update({'IpAddress': demisto.get(resp_json['asset_details']['ip'], 'address')})
    ec['EntityDetails'] = entity_display
    entity_display['Id'] = resp_json.get('id')

    entity_markdown = tableToMarkdown('Insight\'s Main Entity Details:', [entity_display],
                                      ['Id', 'EntityType', 'Hostname', 'Groups', 'FirstSeen', 'LastSeen', 'IpAddress',
                                       'IsWhitelisted', 'RiskScore', 'Source'])

    related_assets_json = resp_json.get('related_assets') or []
    results_assets_list = []
    for rel_asset in related_assets_json:
        results_asset = to_readable(rel_asset, ['id', 'is_whitelisted', 'risk_score', 'source', 'asset_type'],
                                    {'asset_type': 'EntityType'})
        if rel_asset.get('asset_type') == 'hostname':
            results_asset['Name'] = rel_asset.get('hostname')
        elif rel_asset.get('asset_type') == 'username':
            results_asset['Name'] = rel_asset.get('username')

        if demisto.get(rel_asset, 'ip.address'):
            results_asset['IpAddress'] = demisto.get(rel_asset, 'ip.address')

        results_assets_list.append(results_asset)
    ec['RelatedEntityList'] = results_assets_list
    rel_assets_md = tableToMarkdown('Related Entities:', results_assets_list,
                                    ['Id', 'EntityType', 'IpAddress', 'Name', 'IsWhitelisted', 'RiskScore', 'Source'])

    signal_list_json = resp_json.get('signals') or []
    signal_list = []
    threat_intel = 0
    anomalies = 0
    patterns = 0
    for signal_item in signal_list_json:
        result_signal = signal_to_readable(signal_item)
        source_type = result_signal.get('SourceType', '')
        if source_type == 'threatintel':
            threat_intel += 1
        elif source_type == 'rule':
            patterns += 1
        elif source_type == 'anomaly':
            anomalies += 1
        signal_list.append(result_signal)
    ec['SignalList'] = signal_list
    signals_md = tableToMarkdown('Related Signals:', signal_list,
                                 ['Id', 'Name', 'Description', 'Category', 'SourceType'])
    ec['SignalListMetadata'] = {
        'Patterns': {
            'Count': patterns
        },
        'Anomalies': {
            'Count': anomalies
        },
        'ThreatIntel': {
            'Count': threat_intel
        }
    }
    final_ec = {'Jask.Insight(val.Id === obj.Id)': ec}
    signal_metadata_md = tableToMarkdown('Signal Metadata:', [
        {'Pattern Count': patterns, 'Anomaly Count': anomalies, 'Threat Intel Count': threat_intel}],
        ['Pattern Count', 'Anomaly Count', 'Threat Intel Count'])
    combined_md = details_md + '\n\n' + entity_markdown + '\n\n' + rel_assets_md +\
        '\n\n' + signals_md + '\n\n' + signal_metadata_md
    link = URL.replace('/api/', '/insight/') + alert_id
    md_link = "[" + link + "](" + link + ")"
    combined_md += '\n\n' + md_link
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': final_ec,
        'HumanReadable': combined_md,
        'Contents': resp_json,
        'ContentsFormat': formats['json']
    })


def get_insight_comments():
    """
    Get comments for insight
    """
    alert_id = demisto.getArg('insight-id')
    resp_json = req('GET', 'alert/%s/comments' % alert_id, QUERY)
    comments = [to_readable(comment, ['id', 'alert_id', 'author', 'body', 'last_updated', 'timestamp'],
                            {'alert_id': 'InsightId'}) for comment in resp_json['objects']]
    ec = {'Jask.Insight(val.Id == "%s").CommentList': comments}
    md = tableToMarkdown('Insight Comments:', comments,
                         ['Id', 'InsightId', 'Author', 'Body', 'LastUpdated', 'Timestamp'])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': ec,
        'HumanReadable': md,
        'Contents': resp_json,
        'ContentsFormat': formats['json']
    })


def get_signal_details():
    """
    Get signal details
    """
    alert_id = demisto.getArg('signal-id')
    resp_json = req('GET', 'signal/' + alert_id, QUERY)
    signal = signal_to_readable(resp_json)
    md = tableToMarkdown('Insight Signal Details:', [signal],
                         ['Id', 'Name', 'Category', 'Description', 'Score', 'SourceType', 'Timestamp'])

    flow = 0
    notice = 0
    http = 0
    if resp_json.get('extra_records'):
        for record in resp_json.get('extra_records'):
            if record.get('type') == 'http':
                http += 1
            elif record.get('type') == 'flow':
                flow += 1
            elif record.get('type') == 'notice':
                notice += 1
    record_types = [{'RecordType': 'flow', 'RecordCount': flow}, {'RecordType': 'notice', 'RecordCount': notice},
                    {'RecordType': 'http', 'RecordCount': http}]
    if signal.get('ThreatIndicators'):
        md = md + tableToMarkdown('Threat Indicators', signal.get('ThreatIndicators'), ['IndicatorType', 'Value'])
    md = md + tableToMarkdown('Record Metadata', {'Flow Count': flow, 'Notice Count': notice, 'Http Count': http},
                              ['Flow Count', 'Notice Count', 'Http Count'])
    signal['Metadata'] = record_types
    ec = {'Jask.Signal(val.Id === obj.Id)': signal}
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': ec,
        'HumanReadable': md,
        'Contents': resp_json,
        'ContentsFormat': formats['json']
    })


def get_entity_details():
    """
    Get entity details
    """
    entity_id = demisto.getArg('entity-id')
    resp_json = req('GET', 'asset/' + entity_id, QUERY)
    entity = entity_to_readable(resp_json)
    md = tableToMarkdown('Entity Details:', [entity],
                         ['Id', 'Name', 'FirstSeen', 'LastSeen', 'Source', 'EntityType', 'PrimaryEntityType',
                          'Hostname', 'RiskScore', 'IsWhitelisted', 'Groups'])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'Jask.Entity': entity},
        'HumanReadable': md,
        'Contents': resp_json,
        'ContentsFormat': formats['json']
    })


def get_related_entities():
    """
    Get related entities
    """
    entity_id = demisto.getArg('entity-id')
    resp_json = req('GET', 'asset/%s/related_assets' % entity_id, QUERY)
    entities = [
        to_readable(e,
                    ['id', 'name', 'email', 'source', 'username', 'hostname', 'active', 'admin', 'asset_type',
                     'created_ts', 'firstSeen', 'given_name', 'is_whitelisted', 'lastSeen', 'last_name', 'risk_score',
                     'groups'],
                    {
                        'asset_type': 'EntityType', 'created_ts': 'CreatedTimestamp', 'firstSeen': 'FirstSeen',
                        'lastSeen': 'LastSeen'
                    }) for e in resp_json['objects']
    ]

    ec = {'Jask.RelatedEntityList(val.Id === obj.Id)': entities}
    md = tableToMarkdown('Related Entities:', entities, ['Id', 'Name', 'EntityType', 'FirstSeen', 'LastSeen', 'Source',
                                                         'Hostname', 'Username', 'GivenName', 'Email', 'RiskScore',
                                                         'IsWhitelisted', 'Groups', 'CreatedTimestamp', 'Admin'])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': ec,
        'HumanReadable': md,
        'Contents': resp_json,
        'ContentsFormat': formats['json']
    })


def get_whitelisted_entities():
    """
    Get whitelisted entities
    """
    resp_json = req('GET', 'asset/whitelisted', QUERY)
    items = []
    for whitelisted_item in resp_json.get('objects'):
        w = to_readable(whitelisted_item, ['id', 'name'], {})
        w['ModelId'] = demisto.get(whitelisted_item, 'history.model_id')
        w['Timestamp'] = demisto.get(whitelisted_item, 'history.timestamp')
        w['UserName'] = demisto.get(whitelisted_item, 'history.username')
        items.append(w)
    ec = {
        'Jask.WhiteListed.EntityList(val.Id === obj.Id)': items,
        'Jask.WhiteListed.Metadata.TotalCount': len(items)
    }
    md = tableToMarkdown('Whitelisted:', items,
                         ['Id', 'Name', 'ModelId', 'Timestamp', 'UserName']) + '\n' + '### Count: ' + str(len(items))
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': ec,
        'HumanReadable': md,
        'Contents': resp_json,
        'ContentsFormat': formats['json']
    })


def convert_date_to_unix(d):
    """
    Convert a given date to seconds
    """
    return int((d - datetime.utcfromtimestamp(0)).total_seconds() * 1000)


def translate_last_seen(last):
    """
    Convert last-seen argument to querystring
    """
    if not last or last == 'All time':
        return ''
    if last == 'Last week':
        return 'timestamp:[%d TO *]' % (convert_date_to_unix(datetime.utcnow()) - 7 * 24 * 60 * 60 * 1000)
    if last == 'Last 48 hours':
        return 'timestamp:[%d TO *]' % (convert_date_to_unix(datetime.utcnow()) - 2 * 24 * 60 * 60 * 1000)
    if last == 'Last 24 hours':
        return 'timestamp:[%d TO *]' % (convert_date_to_unix(datetime.utcnow()) - 24 * 60 * 60 * 1000)


def _add_list_to_q(q, translate):
    """
    Add arguments in the translate dictionary to querystring
    """
    for v in translate:
        arg_list = argToList(demisto.getArg(translate[v]))
        if len(arg_list) == 1:
            q += ' AND ' + v + ':(%s)' % (arg_list[0])
        elif len(arg_list) > 1:
            q += ' AND ' + v + ':(%s)' % (' OR '.join(arg_list))
    return q


def _add_time_to_q(q):
    """
    Add the time filter to the query string
    Defaults to All time if no fields specified
    """
    last_seen = demisto.getArg('last-seen')
    time_from = demisto.getArg('time-from')
    time_to = demisto.getArg('time-to')
    if last_seen:
        if time_from or time_to:
            return_error('You cannot specify absolute times [time-to, time-from] with relative time [last-seen]')
        else:
            if translate_last_seen(last_seen) != '':
                q += ' AND ' + translate_last_seen(last_seen)
    elif time_from and time_to:
        q += ' AND timestamp:[%d TO %d]' % (
            convert_string_date_to_unix(time_from), convert_string_date_to_unix(time_to))
    elif time_from or time_to:
        return_error('You must specify both absolute times [time-to, time-from] or relative time [last-seen]')
    return q


def search_insights():
    """
    Search insights using available filters
    """
    q = _add_time_to_q('*')
    q = _add_list_to_q(q, {'workflow_status': 'status', 'rating': 'rating', 'group_assigned_to': 'assigned_team',
                           'assigned_to': 'assigned-user'})
    query = QUERY.copy()
    query['q'] = q
    query['offset'] = demisto.getArg('offset')
    query['limit'] = demisto.getArg('limit')
    query['sort_by'] = demisto.getArg('sort')
    resp_json = req('GET', 'search/alerts', query)
    insights = []
    for insight in resp_json['objects']:
        readable_insight = insight_to_readable(insight)
        readable_insight['IpAddress'] = demisto.get(insight, 'asset.ip')
        readable_insight['InsightTime'] = demisto.get(insight, 'timestamp')
        insights.append(readable_insight)
    ec = {'Jask.Insight(val.Id === obj.Id)': insights}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': resp_json,
        'EntryContext': ec,
        'HumanReadable': tableToMarkdown('Insights', insights,
                                         ['Id', 'Name', 'Action', 'AssignedTo', 'Description', 'IpAddress',
                                          'LastUpdated', 'LastUpdatedBy', 'Severity', 'InsightTime', 'WorkflowStatus'])
    })


def search_signals():
    """
    Search signals using available filters
    """
    q = _add_time_to_q('*')
    q = _add_list_to_q(q, {'source_type': 'source', 'category': 'category'})
    query = QUERY.copy()
    query['q'] = q
    query['offset'] = demisto.getArg('offset')
    query['limit'] = demisto.getArg('limit')
    query['sort_by'] = demisto.getArg('sort')
    resp_json = req('GET', 'search/signals', query)
    signals = [signal_to_readable(signal) for signal in resp_json['objects']]
    ec = {'Jask.Signal(val.Id === object.Id)': signals}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': resp_json,
        'EntryContext': ec,
        'HumanReadable': tableToMarkdown('Signals', signals,
                                         ['Id', 'Name', 'Category', 'Description', 'Score', 'SourceType', 'Timestamp',
                                          'ThreatIndicators'])
    })


def search_entities():
    """
    Search entities using the available filters
    """
    q = _add_time_to_q('*')
    q = _add_list_to_q(q, {'asset_type': 'entity-type'})
    query = QUERY.copy()
    query['q'] = q
    query['offset'] = demisto.getArg('offset')
    query['limit'] = demisto.getArg('limit')
    query['sort_by'] = demisto.getArg('sort')
    resp_json = req('GET', 'search/assets', query)
    entities = []
    for entity in resp_json['objects']:
        readable = entity_to_readable(entity)
        readable['IpAddress'] = entity.get('ip')
        entities.append(readable)
    ec = {'Jask.Entity(val.Id === obj.Id)': entities}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': resp_json,
        'EntryContext': ec,
        'HumanReadable': tableToMarkdown('Entities', entities, [
            'Id', 'Name', 'FirstSeen', 'LastSeen', 'Source', 'EntityType', 'PrimaryEntityType', 'Hostname', 'RiskScore',
            'IsWhitelisted', 'Groups', 'IpAddress'
        ])
    })


def translate_severity(severity):
    """
    Translate from Jask insight severity to Demisto severity
    """
    if severity <= 4:
        return severity
    return 4


def fetch_incidents():
    """
    Retrieve new incidents periodically based on pre-defined instance parameters
    """
    now = convert_date_to_unix(datetime.utcnow())
    last_run_object = demisto.getLastRun()
    if last_run_object and last_run_object.get('time'):
        last_run = last_run_object.get('time')
    else:
        last_run = now - 24 * 60 * 60 * 1000
    next_fetch = last_run
    q = '* AND timestamp:[%d TO *]' % last_run
    if demisto.getParam('fetchQuery'):
        q += ' AND ' + demisto.getParam('fetchQuery')
    else:
        q += ' AND workflow_status:(new OR inprogress)'
    query = QUERY.copy()
    query['q'] = q
    query['offset'] = 0
    query['limit'] = FETCH_LIMIT
    query['sort_by'] = 'timestamp:asc'
    resp_json = req('GET', 'search/alerts', query)
    incidents = []
    for a in resp_json['objects']:
        current_fetch = a.get('timestamp')
        if current_fetch:
            try:
                current_fetch = datetime.strptime(current_fetch, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                current_fetch = datetime.strptime(current_fetch, "%Y-%m-%dT%H:%M:%S.%f")
            current_fetch = convert_date_to_unix(current_fetch)
            if current_fetch > last_run:
                incidents.append({
                    'name': a.get('name', 'No name') + ' - ' + a.get('id'),
                    'occurred': a.get('timestamp') + 'Z',
                    'details': a.get('description'),
                    'severity': translate_severity(a.get('severity')),
                    'rawJSON': json.dumps(a)
                })
            if current_fetch > next_fetch:
                next_fetch = current_fetch

    demisto.incidents(incidents)
    demisto.setLastRun({'time': next_fetch})


def main():
    try:
        handle_proxy()
        if demisto.command() == 'test-module':
            req('GET', 'asset/whitelisted', QUERY)
            demisto.results('ok')
        elif demisto.command() == 'jask-get-insight-details':
            get_insight_details()
        elif demisto.command() == 'jask-get-insight-comments':
            get_insight_comments()
        elif demisto.command() == 'jask-get-signal-details':
            get_signal_details()
        elif demisto.command() == 'jask-get-entity-details':
            get_entity_details()
        elif demisto.command() == 'jask-get-related-entities':
            get_related_entities()
        elif demisto.command() == 'jask-get-whitelisted-entities':
            get_whitelisted_entities()
        elif demisto.command() == 'jask-search-insights':
            search_insights()
        elif demisto.command() == 'jask-search-entities':
            search_entities()
        elif demisto.command() == 'jask-search-signals':
            search_signals()
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()
        else:
            return_error('Unrecognized command: ' + demisto.command())
    except Exception as e:
        LOG(e)
        LOG.print_log(False)
        return_error(e.message)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
