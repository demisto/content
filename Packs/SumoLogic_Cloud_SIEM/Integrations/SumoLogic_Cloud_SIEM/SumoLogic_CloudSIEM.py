import json
from datetime import datetime

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401
from requests.auth import HTTPBasicAuth

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

URL = demisto.getParam('api_endpoint')
if URL[-1] != '/':
    URL += '/'
ACCESS_ID = demisto.getParam('access_id')
ACCESS_KEY = demisto.getParam('access_key')
FETCH_LIMIT_PARAM = int(demisto.params().get('fetchLimit', 20))
FETCH_LIMIT = 20 if FETCH_LIMIT_PARAM > 20 else FETCH_LIMIT_PARAM
USE_SSL = not demisto.params().get('insecure', False)
DEFAULT_HEADERS = {
    'Content-Type': 'application/json'
}


def req(method, path, query=None, data=None, headers=None):
    '''
    Send the request to Sumo Logic and return the JSON response
    '''
    if headers is None:
        headers = DEFAULT_HEADERS
    data = {} if data is None else data
    url = URL + path

    r = requests.request(method,
                         url,
                         params=query,
                         data=data,
                         headers=headers,
                         verify=USE_SSL,
                         auth=(ACCESS_ID, ACCESS_KEY)
                         )
    if r.status_code != requests.codes.ok:
        print('Error in API call to Sumo Logic service - {}'.format(r.text))
    if not r.text:
        return {}
    return r.json()


def get_insight_details():
    '''
    Get insight details
    '''
    insight_id = demisto.getArg('insight-id')
    resp_json = req('GET', 'sec/v1/insights/' + insight_id, {})
    insight = {(k[0].capitalize() + k[1:]): v for k, v in resp_json['data'].items()}
    details_md = tableToMarkdown('Insight Details:', [insight],
                                 ['Id', 'ReadableId', 'Name', 'Action', 'AssignedTo', 'Description', 'LastUpdated',
                                  'LastUpdatedBy', 'Severity', 'Closed', 'ClosedBy'])

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': insight,
        'HumanReadable': details_md,
        'Contents': resp_json['data'],
        'ContentsFormat': formats['json']
    })


def get_insight_comments():
    '''
    Get comments for insight
    '''
    insight_id = demisto.getArg('insight-id')
    resp_json = req('GET', 'sec/v1/insights/{}/comments'.format(insight_id), {})
    comments = [{'Id': c['id'], 'Body':c['body'], 'Author': c['author']['username'],
                 'Timestamp': c['timestamp'], 'InsightId': insight_id} for c in resp_json['data']['comments']]
    md = tableToMarkdown('Insight Comments:', comments,
                         ['Id', 'InsightId', 'Author', 'Body', 'LastUpdated', 'Timestamp'])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'SumoLogicSEC.Insight(val.Id == obj.Id).CommentList': comments},
        'HumanReadable': md,
        'Contents': resp_json['data'],
        'ContentsFormat': formats['json']
    })


def get_signal_details():
    '''
    Get signal details
    '''
    signal_id = demisto.getArg('signal-id')
    resp_json = req('GET', 'sec/v1/signals/' + signal_id, {})
    signal = resp_json['data']
    signal.pop('allRecords', None)  # don't need to display records from signal
    signal = {(k[0].capitalize() + k[1:]): v for k, v in signal.items()}
    md = tableToMarkdown('Signal Details:', [signal],
                         ['Id', 'Name', 'RuleId', 'Description', 'Severity', 'ContentType', 'Timestamp'])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'SumoLogicSEC.Signal(val.Id == obj.Id)': signal},
        'HumanReadable': md,
        'Contents': resp_json['data'],
        'ContentsFormat': formats['json']
    })


def get_entity_details():
    '''
    Get entity details
    '''
    entity_id = demisto.getArg('entity-id')
    resp_json = req('GET', 'sec/v1/entities/' + entity_id, {})
    entity = {(k[0].capitalize() + k[1:]): v for k, v in resp_json['data'].items()}
    if 'Os' in entity:
        entity['OperatingSystem'] = entity.pop('Os', None)
    else:
        entity['OperatingSystem'] = ''
    md = tableToMarkdown('Entity Details:', [entity],
                         ['Id', 'Name', 'FirstSeen', 'LastSeen',
                          'Hostname', 'ActivityScore', 'IsWhitelisted', 'OperatingSystem'])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'SumoLogicSEC.Entity': entity},
        'HumanReadable': md,
        'Contents': resp_json['data'],
        'ContentsFormat': formats['json']
    })


def convert_date_to_unix(d):
    '''
    Convert a given date to seconds
    '''
    return int((d - datetime.utcfromtimestamp(0)).total_seconds() * 1000)


def search_insights():
    '''
    Search insights using available filters

    The search query string is a custom DSL that is used to filter the results.

    Operators:
    - `exampleField:"bar"`: The value of the field is equal to "bar".
    - `exampleField:in("bar", "baz", "qux")`: The value of the field is equal to either "bar", "baz", or "qux".
    - `exampleTextField:contains("foo bar")`: The value of the field contains the phrase "foo bar".
    - `exampleNumField:>5`: The value of the field is greater than 5. There are similar `<`, `<=`, and `>=` operators.
    - `exampleNumField:5..10`: The value of the field is between 5 and 10 (inclusive).
    - `exampleDateField:>2019-02-01T05:00:00+00:00`: The value of the date field is after 5 a.m. UTC time on February 2,
        2019.
    - `exampleDateField:2019-02-01T05:00:00+00:00..2019-02-01T08:00:00+00:00`: The value of the date field is between 5 a.m.
        and 8 a.m. UTC time on February 2, 2019.

    Fields:
    - id
    - readableId
    - status
    - name
    - insightId
    - description
    - created
    - timestamp
    - closed
    - assignee
    - entity.ip
    - entity.hostname
    - entity.username
    - entity.type
    - enrichment
    - tag
    - severity
    - resolution
    - ruleId
    - records

    For example, the query `timestamp:>2021-03-18T12:00:00+00:00 severity:"HIGH` will return insights of high severity created after 12 PM UTC time on March 18th, 2021.
    '''
    query = {}
    query['q'] = demisto.getArg('query')
    query['offset'] = demisto.getArg('offset')
    query['limit'] = demisto.getArg('limit')
    resp_json = req('GET', 'sec/v1/insights', query)
    insights = []
    for insight in resp_json['data']['objects']:
        cap_insight = {(k[0].capitalize() + k[1:]): v for k, v in insight.items()}
        cap_insight['Entity'] = ''
        if 'entity' in insight:
            if 'name' in insight['entity']:
                cap_insight['Entity'] = insight['entity']['name']
        insights.append(cap_insight)
    ec = {'SumoLogicSEC.Insight(val.Id == obj.Id)': insights}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': resp_json,
        'EntryContext': ec,
        'HumanReadable': tableToMarkdown('Insights:', insights,
                                         ['Id', 'ReadableId', 'Name', 'Action', 'AssignedTo', 'Description', 'LastUpdated',
                                          'LastUpdatedBy', 'Severity', 'Closed', 'ClosedBy', 'Timestamp', 'Entity'])
    })


def search_signals():
    '''
    Search signals using available filters
    '''
    query = {}
    query['q'] = demisto.getArg('query')
    query['offset'] = demisto.getArg('offset')
    query['limit'] = demisto.getArg('limit')

    resp_json = req('GET', 'sec/v1/signals', query)
    signals = []
    for signal in resp_json['data']['objects']:
        cap_signal = {(k[0].capitalize() + k[1:]): v for k, v in signal.items()}
        cap_signal['Entity'] = ''
        if 'entity' in signal:
            if 'name' in signal['entity']:
                cap_signal['Entity'] = signal['entity']['name']
        signals.append(cap_signal)
    ec = {'SumoLogicSEC.Signal(val.Id == obj.Id)': signals}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': resp_json['data'],
        'EntryContext': ec,
        'HumanReadable': tableToMarkdown('Signals:', signals,
                                         ['Id', 'Name', 'RuleId', 'Description', 'Severity', 'Stage', 'Timestamp',
                                          'ContentType', 'Tags'])
    })


def search_entities():
    '''
    Search entities using the available filters
    '''
    query = {}
    query['q'] = demisto.getArg('query')
    query['offset'] = demisto.getArg('offset')
    query['limit'] = demisto.getArg('limit')

    resp_json = req('GET', 'sec/v1/entities', query)
    entities = []
    for entity in resp_json['data']['objects']:
        cap_entity = {(k[0].capitalize() + k[1:]): v for k, v in entity.items()}
        if 'Os' in entity:
            entity['OperatingSystem'] = entity.pop('Os', None)
        else:
            entity['OperatingSystem'] = ''
        entities.append(cap_entity)
    ec = {'SumoLogicSEC.Entity(val.Id == obj.Id)': entities}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': resp_json['data'],
        'EntryContext': ec,
        'HumanReadable': tableToMarkdown('Entities:', entities, ['Id', 'Name', 'FirstSeen', 'LastSeen',
                                                                'Hostname', 'ActivityScore', 'IsWhitelisted', 'OperatingSystem'])
    })


def translate_severity(severity):
    '''
    Translate from Sumo Logic CSE insight severity to Demisto severity
    '''
    _severities = {
        'LOW': 1,
        'MEDIUM': 2,
        'HIGH': 3
    }
    return _severities.get(severity, 4)


def fetch_incidents():
    '''
    Retrieve new incidents periodically based on pre-defined instance parameters
    '''
    DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

    last_run_object = demisto.getLastRun()
    if last_run_object and last_run_object.get('last_run_time'):
        last_run = convert_date_to_unix(datetime.strptime(last_run_object.get('last_run_time'), DATE_FORMAT))
    else:
        # How much time before the first fetch to retrieve incidents
        first_fetch_time = arg_to_datetime(
            arg=demisto.params().get('firstFetch', '1 day'),
            arg_name='First fetch time',
            required=True
        )
        first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
        # Using assert as a type guard (since first_fetch_time is always an int when required=True)
        assert isinstance(first_fetch_timestamp, int)
        last_run = first_fetch_timestamp  # first fetch is in ms

    next_fetch = last_run
    q = 'timestamp:>{}'.format(last_run)
    if demisto.getParam('fetchQuery'):
        q += ' ' + demisto.getParam('fetchQuery')
    else:
        q = q + ' status:in("new", "inprogress")'
    query = {}
    query['q'] = q
    query['offset'] = 0
    query['limit'] = FETCH_LIMIT
    resp_json = req('GET', 'sec/v1/insights', query)
    incidents = []
    for a in resp_json['data']['objects']:
        current_fetch = a.get('timestamp')
        if current_fetch:
            try:
                current_fetch = datetime.strptime(current_fetch, '%Y-%m-%dT%H:%M:%S')
            except ValueError:
                current_fetch = datetime.strptime(current_fetch, '%Y-%m-%dT%H:%M:%S.%f')
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
    demisto.setLastRun({
        'last_run_time': datetime.fromtimestamp(next_fetch / 1e3).strftime(DATE_FORMAT),
        'incidents': incidents
    })


def set_insight_status():
    '''
    Change status of insight

    Provide "reason" arg when closing an Insight with status=closed.
    '''
    insight_id = demisto.getArg('insight-id')
    reqbody = {}
    reqbody['status'] = demisto.getArg('status')
    if demisto.getArg('status') == 'closed':
        # resolution should only be specified when the status is set to "closed"
        reqbody['resolution'] = demisto.getArg('resolution').replace('_', ' ')
    json_data = json.dumps(reqbody)

    resp_json = req('PUT', 'sec/v1/insights/{}/status'.format(insight_id), None, json_data, DEFAULT_HEADERS)
    insight = {(k[0].capitalize() + k[1:]): v for k, v in resp_json['data'].items()}
    insight['Status'] = insight['Status']['displayName']
    details_md = tableToMarkdown('Insight Details:', [insight],
                                 ['Id', 'ReadableId', 'Name', 'Description', 'AssignedTo', 'Created', 'LastUpdated',
                                  'Status', 'Closed', 'ClosedBy', 'Resolution'])

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': insight,
        'HumanReadable': details_md,
        'Contents': resp_json['data'],
        'ContentsFormat': formats['json']
    })


def get_match_lists():
    '''
    Get match lists
    '''
    query = {}
    query['offset'] = demisto.getArg('offset')
    query['limit'] = demisto.getArg('limit')
    query['sort'] = demisto.getArg('sort')
    query['sortDir'] = demisto.getArg('sortDir')

    resp_json = req('GET', 'sec/v1/match-lists', query, None, DEFAULT_HEADERS)
    match_lists = []
    for match_list in resp_json['data']['objects']:
        cap_match_list = {(k[0].capitalize() + k[1:]): v for k, v in match_list.items()}
        match_lists.append(cap_match_list)
    match_lists_md = tableToMarkdown('Match lists:', match_lists,
                                     headers=['Id', 'Name', 'TargetColumn', 'DefaultTtl'])
    # Filtered out from readable output: 'Description', 'Created', 'CreatedBy', 'LastUpdated', 'LastUpdatedBy'

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': resp_json,
        'HumanReadable': match_lists_md,
        'Contents': resp_json['data'],
        'ContentsFormat': formats['json']
    })


def add_to_match_list():
    '''
    Add to match list
    '''
    match_list_id = demisto.getArg('match-list-id')
    item = {}
    item['active'] = demisto.getArg('active')
    item['description'] = demisto.getArg('description')
    item['expiration'] = demisto.getArg('expiration')
    item['value'] = demisto.getArg('value')
    json_data = json.dumps({"items": [item]})

    resp_json = req('POST', 'sec/v1/match-lists/{}/items'.format(match_list_id), None, json_data, DEFAULT_HEADERS)
    result = {'Result': 'Success' if resp_json['data'] else 'Failed', 'Server response': resp_json['data']}
    result_md = tableToMarkdown('Result:', [result], ['Result', 'Server response'])

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': result,
        'HumanReadable': result_md,
        'Contents': resp_json['data'],
        'ContentsFormat': formats['json']
    })


def search_threat_intel_indicators():
    '''
    Search Threat Intel Indicators

    The search query string in our custom DSL that is used to filter the results.

    Operators:
    - `exampleField:"bar"`: The value of the field is equal to "bar".
    - `exampleField:in("bar", "baz", "qux")`: The value of the field is equal to either "bar", "baz", or "qux".
    - `exampleTextField:contains("foo bar")`: The value of the field contains the phrase "foo bar".
    - `exampleNumField:>5`: The value of the field is greater than 5. There are similar `<`, `<=`, and `>=` operators.
    - `exampleNumField:5..10`: The value of the field is between 5 and 10 (inclusive).
    - `exampleDateField:>2019-02-01T05:00:00+00:00`: The value of the date field is after 5 a.m. UTC time on February 2,
        2019.
    - `exampleDateField:2019-02-01T05:00:00+00:00..2019-02-01T08:00:00+00:00`: The value of the date field is between 5 a.m.
        and 8 a.m. UTC time on February 2, 2019.

    Fields:
    - id
    - targetColumn
    - value
    - active
    - expirationDate
    - listName
    - description
    - created
    '''
    query = {}
    if demisto.getArg('query'):
        query['q'] = demisto.getArg('query')
    query['value'] = demisto.getArg('value')
    query['sourceIds'] = demisto.getArg('sourceIds').split(',')
    query['offset'] = demisto.getArg('offset')
    query['limit'] = demisto.getArg('limit')

    resp_json = req('GET', 'sec/v1/threat-intel-indicators', query)
    indicators = []
    for indicator in resp_json['data']['objects']:
        cap_indicator = {(k[0].capitalize() + k[1:]): v for k, v in indicator.items()}
        indicators.append(cap_indicator)
    ec = {'SumoLogicSEC.ThreatIntelIndicator(val.Id == obj.Id)': indicators}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': resp_json['data'],
        'EntryContext': ec,
        'HumanReadable': tableToMarkdown('Threat Intel Indicators:', indicators,
                                         ['Id', 'Value', 'Active', 'Expiration'])
        # Filtered out from readable output: Meta
    })


def get_threat_intel_sources():
    '''
    Get the list of Threat Intel Sources
    '''
    query = {}
    query['offset'] = demisto.getArg('offset')
    query['limit'] = demisto.getArg('limit')
    query['sort'] = demisto.getArg('sort')
    query['sortDir'] = demisto.getArg('sortDir')

    resp_json = req('GET', 'sec/v1/threat-intel-sources', query)
    threat_intel_sources = []
    for threat_intel_source in resp_json['data']['objects']:
        cap_threat_intel_source = {(k[0].capitalize() + k[1:]): v for k, v in threat_intel_source.items()}
        threat_intel_sources.append(cap_threat_intel_source)
    threat_intel_sources_md = tableToMarkdown('Threat intel sources:', threat_intel_sources,
                                              headers=['Id', 'Name', 'Description', 'SourceType'])
    # Filtered out from readable output: Created', 'CreatedBy', 'LastUpdated', 'LastUpdatedBy'

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': resp_json,
        'HumanReadable': threat_intel_sources_md,
        'Contents': resp_json['data'],
        'ContentsFormat': formats['json']
    })


def add_to_threat_intel_source():
    '''
    Add Indicator to a Threat Intel Source
    '''
    threat_intel_source_id = demisto.getArg('threat-intel-source-id')
    item = {}
    item['active'] = demisto.getArg('active')
    item['description'] = demisto.getArg('description')
    item['expiration'] = demisto.getArg('expiration')
    item['value'] = demisto.getArg('value')
    json_data = json.dumps({"indicators": [item]})

    resp_json = req('POST', 'sec/v1/threat-intel-sources/{}/items'.format(threat_intel_source_id),
                    None, json_data, DEFAULT_HEADERS)
    result = {'Result': 'Success' if resp_json['data'] else 'Failed', 'Server response': resp_json['data']}
    result_md = tableToMarkdown('Result:', [result], ['Result', 'Server response'])

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': result,
        'HumanReadable': result_md,
        'Contents': resp_json['data'],
        'ContentsFormat': formats['json']
    })


def main():
    try:
        handle_proxy()
        if demisto.command() == 'test-module':
            req('GET', 'sec/v1/insights', {})
            demisto.results('ok')
        elif demisto.command() == 'sumologic-sec-insight-get-details':
            get_insight_details()
        elif demisto.command() == 'sumologic-sec-insight-get-comments':
            get_insight_comments()
        elif demisto.command() == 'sumologic-sec-signal-get-details':
            get_signal_details()
        elif demisto.command() == 'sumologic-sec-entity-get-details':
            get_entity_details()
        elif demisto.command() == 'sumologic-sec-insight-search':
            search_insights()
        elif demisto.command() == 'sumologic-sec-entity-search':
            search_entities()
        elif demisto.command() == 'sumologic-sec-signal-search':
            search_signals()
        elif demisto.command() == 'sumologic-sec-insight-set-status':
            set_insight_status()
        elif demisto.command() == 'sumologic-sec-match-list-get':
            get_match_lists()
        elif demisto.command() == 'sumologic-sec-match-list-update':
            add_to_match_list()
        elif demisto.command() == 'sumologic-sec-threat-intel-search-indicators':
            search_threat_intel_indicators()
        elif demisto.command() == 'sumologic-sec-threat-intel-get-sources':
            get_threat_intel_sources()
        elif demisto.command() == 'sumologic-sec-threat-intel-update-source':
            add_to_threat_intel_source()
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()
        else:
            return_error('Unrecognized command: ' + demisto.command())
    except Exception as e:
        LOG(e)
        LOG.print_log(False)
        return_error(e)


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
