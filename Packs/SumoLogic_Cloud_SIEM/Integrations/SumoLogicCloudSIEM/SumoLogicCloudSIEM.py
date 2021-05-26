"""Integration for Sumo Logic Cloud SIEM

"""
from datetime import datetime
from typing import List, Any, Dict, Tuple, cast
from CommonServerPython import *  # noqa: F401

import traceback
import demistomock as demisto  # noqa: F401

''' CONSTANTS '''

MAX_INCIDENTS_TO_FETCH = 20
DEFAULT_HEADERS = {
    'Content-Type': 'application/json'
}
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    """

    def req(self, method, url_suffix, params=None, json_data=None, headers=None):
        '''
        Send the request to Sumo Logic and return the JSON response
        '''
        if headers is None:
            headers = DEFAULT_HEADERS
        json_data = {} if json_data is None else json_data
        r = self._http_request(
            headers=headers,
            method=method,
            params=params,
            json_data=json_data,
            url_suffix=url_suffix,
            resp_type='json'
        ).get('data')
        return r


''' HELPER FUNCTIONS '''


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


def add_to_query(q):
    if len(q) > 0:
        return '{} '.format(q)  # No need for 'AND' here
    else:
        return q


def arg_time_query_to_q(q, argval, timefield):
    '''
    Convert created argument to querystring
    '''
    if not argval or argval == 'All time':
        return q
    if argval == 'Last week':
        return add_to_query(q) + '{}:NOW-7D..NOW'.format(timefield)
    if argval == 'Last 48 hours':
        return add_to_query(q) + '{}:NOW-48h..NOW'.format(timefield)
    if argval == 'Last 24 hours':
        return add_to_query(q) + '{}:NOW-24h..NOW'.format(timefield)


def add_list_to_q(q, fields, args):
    '''
    Add arguments to querystring
    '''
    for arg_field in fields:
        arg_value = args.get(arg_field, None)
        if arg_value:
            if ',' in arg_value:
                quoted_values = ['"{}"'.format(v) for v in arg_value.split(',')]
                q = add_to_query(q) + '{}:in({})'.format(arg_field, ','.join(quoted_values))
            else:
                q = add_to_query(q) + '{}:"{}"'.format(arg_field, arg_value)
    return q


def insight_signal_to_readable(obj):
    '''
    Readable json output from insight/signal object
    '''
    if obj is None:
        return {}

    # Capitalize fields
    cap_obj = {(k[0].capitalize() + k[1:]): v for k, v in obj.items()}

    # Only show Entity name (Insights and Signals)
    cap_obj['Entity'] = ''
    if obj.get('entity'):
        if 'name' in obj['entity']:
            cap_obj['Entity'] = obj['entity']['name']

    # Only show status displayName (Insights only)
    if obj.get('status'):
        if 'displayName' in obj['status']:
            cap_obj['Status'] = obj['status']['displayName']

    # For Assignee show username (email)
    cap_obj['Assignee'] = ''
    if obj.get('assignee'):
        if 'username' in obj['assignee']:
            cap_obj['Assignee'] = obj['assignee']['username']

    # Remove some deprecated fields, replaced by "Assignee"
    cap_obj.pop('AssignedTo', None)
    cap_obj.pop('TeamAssignedTo', None)

    return cap_obj


def entity_to_readable(obj):
    '''
    Readable json output from entity object
    '''
    if obj is None:
        return {}

    # Capitalize fields
    cap_obj = {(k[0].capitalize() + k[1:]): v for k, v in obj.items()}

    # For Entities, show 'OperatingSystem'
    if 'Os' in cap_obj:
        cap_obj['OperatingSystem'] = cap_obj.pop('Os', None)
    else:
        cap_obj['OperatingSystem'] = None

    if len(cap_obj.get('Inventory', [])) > 0:
        invdata = cap_obj['Inventory'][0]
        if 'metadata' in invdata:
            if 'operatingSystem' in invdata['metadata']:
                cap_obj['OperatingSystem'] = invdata['metadata']['operatingSystem']
        cap_obj['InventoryData'] = True
    else:
        cap_obj['InventoryData'] = False

    cap_obj.pop('Inventory', None)  # don't need to display data from inventory
    cap_obj.pop('Ip', None)  # don't need to display Ip object

    return cap_obj


def get_update_result(resp_json):
    '''
    Readable json output from update
    '''
    return {'Result': 'Success' if resp_json is True else 'Failed', 'Server Response': resp_json}


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # test client and auth
        client.req('GET', 'sec/v1/insights', {})

        # test fetch_incidents command
        first_fetch_time = arg_to_datetime(
            arg=demisto.params().get('first_fetch', '1 day'),
            arg_name='First fetch time'
        )
        first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
        # Using assert as a type guard (since first_fetch_time is always an int when required=True)
        assert isinstance(first_fetch_timestamp, int)
        fetch_incidents(
            client=client,
            max_results=20,
            last_run={},  # getLastRun() gets the last run dict
            first_fetch_time=first_fetch_timestamp,
            fetch_query=''  # defaults to status:in("new", "inprogress")
        )
        message = 'ok'
    except DemistoException as e:
        if 'Unauthorized' in str(e):
            message = 'Authorization Error: make sure Access ID and Access Key are correctly set'
        else:
            raise e
    return message


def insight_get_details(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Get insight details
    '''
    insight_id = args.get('insight_id')
    if not insight_id:
        raise ValueError('insight_id not specified')

    resp_json = client.req('GET', 'sec/v1/insights/{}'.format(insight_id), {'exclude': 'signals.allRecords'})
    insight = insight_signal_to_readable(resp_json)
    readable_output = tableToMarkdown(
        'Insight Details:', [insight],
        ['Id', 'ReadableId', 'Name', 'Action', 'Status', 'Assignee', 'Description', 'LastUpdated', 'LastUpdatedBy', 'Severity',
         'Closed', 'ClosedBy', 'Timestamp', 'Entity', 'Resolution'], headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.Insight',
        outputs_key_field='Id',
        outputs=insight
    )


def insight_get_comments(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Get comments for insight
    '''
    insight_id = args.get('insight_id')
    resp_json = client.req('GET', 'sec/v1/insights/{}/comments'.format(insight_id))
    comments = [{'Id': c.get('id'), 'Body': c.get('body'), 'Author': c.get('author').get('username'),
                 'Timestamp': c.get('timestamp'), 'InsightId': insight_id} for c in resp_json.get('comments')]
    readable_output = tableToMarkdown('Insight Comments:', comments,
                                      ['Id', 'InsightId', 'Author', 'Body', 'LastUpdated', 'Timestamp'],
                                      headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.InsightComments',
        outputs_key_field='Id',
        outputs=comments
    )


def signal_get_details(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Get signal details
    '''
    signal_id = args.get('signal_id', None)
    if not signal_id:
        raise ValueError('signal_id not specified')

    signal = client.req('GET', 'sec/v1/signals/{}'.format(signal_id))
    signal.pop('allRecords', None)  # don't need to display records from signal
    signal = insight_signal_to_readable(signal)
    readable_output = tableToMarkdown(
        'Signal Details:', [signal],
        ['Id', 'Name', 'RuleId', 'Description', 'Severity', 'ContentType', 'Timestamp', 'Entity'], headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.Signal',
        outputs_key_field='Id',
        outputs=signal
    )


def entity_get_details(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Get entity details
    '''
    entity_id = args.get('entity_id', None)
    if not entity_id:
        raise ValueError('entity_id not specified')

    resp_json = client.req('GET', 'sec/v1/entities/{}'.format(entity_id), {'expand': 'inventory'})
    entity = entity_to_readable(resp_json)
    readable_output = tableToMarkdown(
        'Entity Details:', [entity],
        ['Id', 'Name', 'FirstSeen', 'LastSeen', 'ActivityScore', 'IsWhitelisted', 'OperatingSystem', 'InventoryData'],
        headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.Entity',
        outputs_key_field='Id',
        outputs=entity
    )


def insight_search(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    For example, the query `timestamp:>2021-03-18T12:00:00+00:00 severity:"HIGH` will return insights of high severity
    created after 12 PM UTC time on March 18th, 2021.
    '''
    query = {}
    q = args.get('query', '')
    q = arg_time_query_to_q(q, args.get('created'), 'created')
    q = add_list_to_q(q, ['status', 'assignee'], args)
    query['q'] = q
    query['offset'] = args.get('offset')
    query['limit'] = args.get('limit')
    query['exclude'] = 'signals.allRecords'

    resp_json = client.req('GET', 'sec/v1/insights', query)
    insights = []
    for insight in resp_json.get('objects'):
        insights.append(insight_signal_to_readable(insight))

    readable_output = tableToMarkdown(
        'Insights:', insights,
        ['Id', 'ReadableId', 'Name', 'Action', 'Status', 'Assignee', 'Description', 'LastUpdated', 'LastUpdatedBy', 'Severity',
         'Closed', 'ClosedBy', 'Timestamp', 'Entity', 'Resolution'], headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.InsightList',
        outputs_key_field='Id',
        outputs=insights
    )


def entity_search(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Search entities using the available filters
    '''
    query = {}
    q = args.get('query', '')
    q = add_list_to_q(q, ['ip', 'hostname', 'username', 'type', 'whitelisted', 'tag'], args)
    query['q'] = q
    query['offset'] = args.get('offset')
    query['limit'] = args.get('limit')
    query['sort_by'] = args.get('sort')
    query['expand'] = 'inventory'

    resp_json = client.req('GET', 'sec/v1/entities', query)
    entities = []
    for entity in resp_json.get('objects'):
        entities.append(entity_to_readable(entity))

    readable_output = tableToMarkdown(
        'Entities:', entities,
        ['Id', 'Name', 'FirstSeen', 'LastSeen', 'ActivityScore', 'IsWhitelisted', 'OperatingSystem', 'InventoryData'],
        headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.EntityList',
        outputs_key_field='Id',
        outputs=entities
    )


def signal_search(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Search signals using available filters
    '''
    query = {}
    q = args.get('query', '')
    q = arg_time_query_to_q(q, args.get('created'), 'created')
    q = add_list_to_q(q, ['category', 'contentType'], args)
    query['q'] = q
    query['offset'] = args.get('offset')
    query['limit'] = args.get('limit')

    resp_json = client.req('GET', 'sec/v1/signals', query)
    signals = []
    for signal in resp_json.get('objects'):
        signal.pop('allRecords', None)  # don't need to display records from signal
        signals.append(insight_signal_to_readable(signal))

    readable_output = tableToMarkdown(
        'Signals:', signals,
        ['Id', 'Name', 'Entity', 'RuleId', 'Description', 'Severity', 'Stage', 'Timestamp', 'ContentType', 'Tags'],
        headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.SignalList',
        outputs_key_field='Id',
        outputs=signals
    )


def insight_set_status(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Change status of insight

    Provide "reason" arg when closing an Insight with status=closed.
    '''
    insight_id = args.get('insight_id')
    reqbody = {}
    reqbody['status'] = args.get('status')
    if args.get('status') == 'closed' and args.get('resolution'):
        # resolution should only be specified when the status is set to "closed"
        reqbody['resolution'] = args['resolution']

    resp_json = client.req('PUT', 'sec/v1/insights/{}/status'.format(insight_id), None, reqbody)

    for s in resp_json.get('signals'):
        s.pop('allRecords', None)

    insight = insight_signal_to_readable(resp_json)

    readable_output = tableToMarkdown(
        'Insight Details:', [insight],
        ['Id', 'ReadableId', 'Name', 'Action', 'Status', 'Assignee', 'Description', 'LastUpdated', 'LastUpdatedBy', 'Severity',
         'Closed', 'ClosedBy', 'Timestamp', 'Entity', 'Resolution'], headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.Insight',
        outputs_key_field='Id',
        outputs=insight
    )


def match_list_get(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Get match lists
    '''
    query = {}
    query['offset'] = args.get('offset')
    query['limit'] = args.get('limit')
    query['sort'] = args.get('sort')
    query['sortDir'] = args.get('sortDir')

    resp_json = client.req('GET', 'sec/v1/match-lists', query)
    match_lists = []
    for match_list in resp_json.get('objects'):
        cap_match_list = {(k[0].capitalize() + k[1:]): v for k, v in match_list.items()}
        match_lists.append(cap_match_list)
    readable_output = tableToMarkdown(
        'Match lists:', match_lists, headers=['Id', 'Name', 'TargetColumn', 'DefaultTtl'],
        headerTransform=pascalToSpace)
    # Filtered out from readable output: 'Description', 'Created', 'CreatedBy', 'LastUpdated', 'LastUpdatedBy'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.MatchLists',
        outputs_key_field='Id',
        outputs=match_lists
    )


def match_list_update(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Add to match list
    '''
    match_list_id = args.get('match_list_id')
    item = {}
    item['active'] = args.get('active')
    item['description'] = args.get('description')
    item['expiration'] = args.get('expiration')
    item['value'] = args.get('value')

    resp_json = client.req('POST', 'sec/v1/match-lists/{}/items'.format(match_list_id), None, {'items': [item]})
    result = get_update_result(resp_json)
    readable_output = tableToMarkdown('Result:', [result], ['Result', 'Server Response'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.UpdateResult',
        outputs=result
    )


def threat_intel_search_indicators(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    if args.get('query'):
        query['q'] = args.get('query')
    query['value'] = args.get('value')
    if args.get('sourceIds'):
        query['sourceIds'] = args['sourceIds'].split(',')
    query['offset'] = args.get('offset')
    query['limit'] = args.get('limit')

    resp_json = client.req('GET', 'sec/v1/threat-intel-indicators', query)
    indicators = []
    for indicator in resp_json.get('objects'):
        cap_indicator = {(k[0].capitalize() + k[1:]): v for k, v in indicator.items()}
        indicators.append(cap_indicator)

    readable_output = tableToMarkdown('Threat Intel Indicators:', indicators, ['Id', 'Value', 'Active', 'Expiration'])
    # Filtered out from readable output: Meta

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.ThreatIntelIndicators',
        outputs_key_field='Id',
        outputs=indicators
    )


def threat_intel_get_sources(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Get the list of Threat Intel Sources
    '''
    query = {}
    query['offset'] = args.get('offset')
    query['limit'] = args.get('limit')
    query['sort'] = args.get('sort')
    query['sortDir'] = args.get('sortDir')

    resp_json = client.req('GET', 'sec/v1/threat-intel-sources', query)
    threat_intel_sources = []
    for threat_intel_source in resp_json.get('objects'):
        cap_threat_intel_source = {(k[0].capitalize() + k[1:]): v for k, v in threat_intel_source.items()}
        threat_intel_sources.append(cap_threat_intel_source)
    readable_output = tableToMarkdown('Threat intel sources:', threat_intel_sources,
                                      headers=['Id', 'Name', 'Description', 'SourceType'], headerTransform=pascalToSpace)
    # Filtered out from readable output: Created', 'CreatedBy', 'LastUpdated', 'LastUpdatedBy'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.ThreatIntelSources',
        outputs_key_field='Id',
        outputs=threat_intel_sources
    )


def threat_intel_update_source(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Add Indicator to a Threat Intel Source
    '''
    threat_intel_source_id = args.get('threat_intel_source_id')
    item = {}
    item['active'] = args.get('active')
    item['description'] = args.get('description')
    item['expiration'] = args.get('expiration')
    item['value'] = args.get('value')

    resp_json = client.req('POST', 'sec/v1/threat-intel-sources/{}/items'.format(threat_intel_source_id),
                           None, {'indicators': [item]})
    result = get_update_result(resp_json)
    readable_output = tableToMarkdown('Result:', [result], ['Result', 'Response'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SumoLogicSec.UpdateResult',
        outputs=result
    )


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int], first_fetch_time: Optional[int],
                    fetch_query: Optional[str]) -> Tuple[Dict[str, int], List[dict]]:
    '''
    Retrieve new incidents periodically based on pre-defined instance parameters
    '''

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)

    # track last_fetch_ids to handle insights with the same timestamp
    last_fetch_ids: List[str] = cast(List[str], last_run.get('last_fetch_ids', []))
    current_fetch_ids: List[str] = []

    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    q = 'timestamp:>={}'.format(latest_created_time)
    if fetch_query:
        q += ' ' + fetch_query
    else:
        q = q + ' status:in("new", "inprogress")'
    query = {}
    query['q'] = q
    query['offset'] = '0'
    query['limit'] = str(max_results)
    resp_json = client.req('GET', 'sec/v1/insights', query)
    incidents = []
    for a in resp_json.get('objects'):

        # If no created_time set is as epoch (0). We use time in ms so we must
        # convert it from the API response
        insight_timestamp = a.get('timestamp')
        insight_id = a.get('id')
        if insight_id and insight_timestamp and insight_id not in last_fetch_ids:
            try:
                incident_datetime = datetime.strptime(insight_timestamp, '%Y-%m-%dT%H:%M:%S')
            except ValueError:
                incident_datetime = datetime.strptime(insight_timestamp, '%Y-%m-%dT%H:%M:%S.%f')

            incident_created_time = int((incident_datetime - datetime.utcfromtimestamp(0)).total_seconds())
            incident_created_time_ms = incident_created_time * 1000

            # to prevent duplicates, we are only adding incidents with creation_time >= last fetched incident
            if last_fetch:
                if incident_created_time < last_fetch:
                    continue

            incidents.append({
                'name': a.get('name', 'No name') + ' - ' + insight_id,
                'occurred': timestamp_to_datestring(incident_created_time_ms),
                'details': a.get('description'),
                'severity': translate_severity(a.get('severity')),
                'rawJSON': json.dumps(a)
            })
            current_fetch_ids.append(insight_id)

            # Update last run and add incident if the incident is newer than last fetch
            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch and last_fetch_ids keys to be stored
    next_run = cast(
        Dict[str, Any],
        {
            'last_fetch': latest_created_time,
            'last_fetch_ids': current_fetch_ids if len(current_fetch_ids) > 0 else last_fetch_ids
        }
    )
    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    proxy = demisto.params().get('proxy', False)
    base_url = demisto.getParam('api_endpoint')
    access_id = demisto.getParam('access_id')
    access_key = demisto.getParam('access_key')
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get('first_fetch', '1 day'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

    fetch_query = demisto.params().get('fetch_query')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=DEFAULT_HEADERS,
            proxy=proxy,
            auth=(access_id, access_key),
            ok_codes=[200])

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'sumologic-sec-insight-get-details':
            return_results(insight_get_details(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-insight-get-comments':
            return_results(insight_get_comments(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-signal-get-details':
            return_results(signal_get_details(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-entity-get-details':
            return_results(entity_get_details(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-insight-search':
            return_results(insight_search(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-entity-search':
            return_results(entity_search(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-signal-search':
            return_results(signal_search(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-insight-set-status':
            return_results(insight_set_status(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-match-list-get':
            return_results(match_list_get(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-match-list-update':
            return_results(match_list_update(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-threat-intel-search-indicators':
            return_results(threat_intel_search_indicators(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-threat-intel-get-sources':
            return_results(threat_intel_get_sources(client, demisto.args()))
        elif demisto.command() == 'sumologic-sec-threat-intel-update-source':
            return_results(threat_intel_update_source(client, demisto.args()))

        elif demisto.command() == 'fetch-incidents':
            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                fetch_query=fetch_query
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
