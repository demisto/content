import json
import time
import copy
from unittest.mock import patch

from Devo_v2 import fetch_incidents, run_query_command, get_alerts_command,\
    multi_table_query_command, write_to_table_command, write_to_lookup_table_command,\
    check_credentials

MOCK_READER_ENDPOINT = "https://fake.devo.com/query"
MOCK_LINQ_LINK_BASE = "https://devo.com"
MOCK_READER_OAUTH_TOKEN = "123"
MOCK_WRITER_RELAY = 'eu.whatever.devo.com'
MOCK_LINQ_RETURN = 'from whatever.table'
MOCK_WRITER_CREDENTIALS = {
    "key": "fake",
    "crt": "fake",
    "chain": "fake"
}
MOCK_FETCH_INCIDENTS_FILTER = {
    "type": "OR",
    "filters": [
        {
            "key": "foo",
            "operator": "bar",
            "value": "baz"
        },
        {
            "key": "baz",
            "operator": "foo",
            "value": "bar"
        }
    ]
}
MOCK_HIGH_CPU_ALERT = {
    "eventdate": time.time() - 20,
    "alertHost": "backoffice",
    "domain": "dsteam",
    "priority": 5.0,
    "context": "CPU_Usage_Alert",
    "category": "my.context",
    "status": 4,
    "alertId": "6294258",
    "srcIp": None,
    "srcPort": None,
    "srcHost": None,
    "dstIp": None,
    "dstPort": None,
    "dstHost": None,
    "protocol": None,
    "username": None,
    "application": None,
    "engine": "CPU_Usage_Alert",
    "extraData": '{"cluster":"-","anomaly_score":"100","indices":'
    '"0%2","_message":"CPU+Usage+Anomaly","instance":"-","payload":'
    '"2019-09-20+08997","pred":"52.52","message":'
    '"097",'
    '"eventdate":"2019-09-20+08%3A52%3A14.096","timestamp":"2019-09-20+08%3A52%3A14"}'
}
MOCK_SIMULTANEOUS_LOGIN_ALERT = {
    "eventdate": time.time() - 45,
    "alertHost": "backoffice",
    "domain": "dsteam",
    "priority": 5.0,
    "context": "simultaneous_login",
    "category": "my.context",
    "status": 4,
    "alertId": "6306076",
    "srcIp": None,
    "srcPort": None,
    "srcHost": None,
    "dstIp": None,
    "dstPort": None,
    "dstHost": None,
    "protocol": None,
    "username": None,
    "application": None,
    "bar": None,
    "baz": None,
    "engine": "simultaneous_login",
    "extraData": '{"duration_seconds":"null","cluster":"-","prev_timestamp":"null","instance":'
    '"-","distance":"null","level":"info","city":"Natick","srcHost":"blahip","prev_city":"None","format":'
    '"output_aaa","prev_geolocation":"None","message":'
    '"0%2ENEW+RECORD'
    'test%40test.comNoneNone550.239.'
    '225.14NoneNoneNoneNone","eventdate":"2019-09-20+20%3A41%3A39.688","prev_srcHost":"None","duration":"None",'
    '"indices":"0%2C1C133","payload":'
    '"NEW+RECORDtest%40test.comNoneNoneNatic31.'
    '335.14NoneNoneNoneNone","state":"NEW+RECORD","category":"modelserverdev",'
    '"facility":"user","username":"test%40test.com","geolocation":"421%'
    'C2W","timestamp":"2019-09-20+20%3A41%3A37.395"}'
}
MOCK_QUERY_RESULTS = [MOCK_HIGH_CPU_ALERT, MOCK_SIMULTANEOUS_LOGIN_ALERT]
MOCK_LAST_RUN = {
    'from_time': time.time() - 60
}
MOCK_QUERY_ARGS = {
    'query': 'from whatever',
    'from': time.time() - 60,
    'to': time.time(),
    'writeToContext': 'true'
}
MOCK_ALERT_ARGS = {
    'filters': MOCK_FETCH_INCIDENTS_FILTER,
    'from': time.time() - 60,
    'to': time.time(),
    'writeToContext': 'true'
}
MOCK_MULTI_ARGS = {
    'tables': ['app', 'charlie', 'test'],
    'searchToken': 'searching',
    'from': time.time() - 60,
    'to': time.time(),
    'writeToContext': 'true'
}
MOCK_WRITER_ARGS = {
    'tableName': 'hello.world',
    'records': [{'foo': 'hello'}, {'foo': 'world'}, {'foo': 'demisto'}]
}
MOCK_LOOKUP_WRITER_ARGS = {
    'lookupTableName': 'hello.world.lookup',
    'headers': ['foo', 'bar', 'baz'],
    'records': [
        {'key': 'fookey', 'values': ['fookey', 'bar0', 'baz0']},
        {'key': 'keyfoo', 'values': ['keyfoo', 'bar1', 'baz1']},
        {'key': 'keykey', 'values': ['keykey', 'bar5', 'baz6']}
    ]
}
MOCK_KEYS = {
    'foo': 'bar',
    'baz': 'bug'
}


class MOCK_LOOKUP(object):
    def send_control(*args, **kw):
        pass

    def send_data_line(*args, **kw):
        pass


class MOCK_SOCKET(object):
    def shutdown(*args, **kw):
        pass


class MOCK_SENDER(object):
    socket = MOCK_SOCKET()

    def flush_buffer(*args, **kw):
        pass


@patch('Devo_v2.READER_ENDPOINT', MOCK_READER_ENDPOINT, create=True)
@patch('Devo_v2.READER_OAUTH_TOKEN', MOCK_READER_OAUTH_TOKEN, create=True)
@patch('Devo_v2.WRITER_RELAY', MOCK_WRITER_RELAY, create=True)
@patch('Devo_v2.WRITE_CREDENTIALS', MOCK_WRITER_CREDENTIALS, create=True)
@patch('Devo_v2.ds.Reader.query', MOCK_QUERY_RESULTS)
@patch('Devo_v2.ds.Writer.load', None)
def test_command():
    assert check_credentials


@patch('Devo_v2.READER_ENDPOINT', MOCK_READER_ENDPOINT, create=True)
@patch('Devo_v2.READER_OAUTH_TOKEN', MOCK_READER_OAUTH_TOKEN, create=True)
@patch('Devo_v2.FETCH_INCIDENTS_FILTER', MOCK_FETCH_INCIDENTS_FILTER, create=True)
@patch('Devo_v2.ds.Reader.query')
def test_first_fetch_incidents(mock_query_results):
    mock_query_results.return_value = copy.deepcopy(MOCK_QUERY_RESULTS)
    incidents = fetch_incidents()
    assert len(incidents) == 2
    assert json.loads(incidents[0]['rawJSON'])['devo.metadata.alert']['context'] == 'simultaneous_login'


@patch('Devo_v2.READER_ENDPOINT', MOCK_READER_ENDPOINT, create=True)
@patch('Devo_v2.READER_OAUTH_TOKEN', MOCK_READER_OAUTH_TOKEN, create=True)
@patch('Devo_v2.FETCH_INCIDENTS_FILTER', MOCK_FETCH_INCIDENTS_FILTER, create=True)
@patch('Devo_v2.demisto.getLastRun')
@patch('Devo_v2.ds.Reader.query')
def test_next_fetch(mock_query_results, mock_last_run):
    mock_query_results.return_value = copy.deepcopy(MOCK_QUERY_RESULTS)
    mock_last_run.return_value = MOCK_LAST_RUN
    incidents = fetch_incidents()
    assert len(incidents) == 2
    assert json.loads(incidents[1]['rawJSON'])['devo.metadata.alert']['context'] == 'CPU_Usage_Alert'


@patch('Devo_v2.READER_ENDPOINT', MOCK_READER_ENDPOINT, create=True)
@patch('Devo_v2.READER_OAUTH_TOKEN', MOCK_READER_OAUTH_TOKEN, create=True)
@patch('Devo_v2.demisto.args')
@patch('Devo_v2.ds.Reader.query')
def test_get_alerts(mock_query_results, mock_args_results):
    mock_query_results.return_value = copy.deepcopy(MOCK_QUERY_RESULTS)
    mock_args_results.return_value = MOCK_ALERT_ARGS
    results = get_alerts_command()
    assert len(results) == 2
    assert results[0]['Contents'][0]['engine'] == 'CPU_Usage_Alert'


@patch('Devo_v2.READER_ENDPOINT', MOCK_READER_ENDPOINT, create=True)
@patch('Devo_v2.READER_OAUTH_TOKEN', MOCK_READER_OAUTH_TOKEN, create=True)
@patch('Devo_v2.demisto.args')
@patch('Devo_v2.ds.Reader.query')
def test_run_query(mock_query_results, mock_args_results):
    mock_query_results.return_value = copy.deepcopy(MOCK_QUERY_RESULTS)
    mock_args_results.return_value = MOCK_QUERY_ARGS
    results = run_query_command()
    assert len(results) == 2
    assert results[0]['Contents'][0]['engine'] == 'CPU_Usage_Alert'


@patch('Devo_v2.READER_ENDPOINT', MOCK_READER_ENDPOINT, create=True)
@patch('Devo_v2.READER_OAUTH_TOKEN', MOCK_READER_OAUTH_TOKEN, create=True)
@patch('Devo_v2.concurrent.futures.wait')
@patch('Devo_v2.concurrent.futures.ThreadPoolExecutor.submit')
@patch('Devo_v2.demisto.args')
@patch('Devo_v2.ds.Reader.query')
@patch('Devo_v2.ds.Reader._get_types')
def test_multi_query(mock_query_types, mock_query_results, mock_args_results, mock_submit_results, mock_wait_results):
    mock_query_types.return_value = MOCK_KEYS
    mock_query_results.return_value = copy.deepcopy(MOCK_QUERY_RESULTS)
    mock_args_results.return_value = MOCK_MULTI_ARGS
    mock_submit_results.return_value = None
    mock_wait_results.return_value = (None, None)
    results = multi_table_query_command()
    assert results['HumanReadable'] == 'No results found'


@patch('Devo_v2.WRITER_RELAY', MOCK_WRITER_RELAY, create=True)
@patch('Devo_v2.WRITER_CREDENTIALS', MOCK_WRITER_CREDENTIALS, create=True)
@patch('Devo_v2.demisto.args')
@patch('Devo_v2.ds.Writer')
def test_write_devo(mock_load_results, mock_write_args):
    mock_load_results.return_value.load.return_value = MOCK_LINQ_RETURN
    mock_write_args.return_value = MOCK_WRITER_ARGS
    results = write_to_table_command()
    assert results[0]['EntryContext']['Devo.RecordsWritten'] == 3
    assert results[0]['EntryContext']['Devo.LinqQuery'] == 'from whatever.table'


@patch('Devo_v2.WRITER_RELAY', MOCK_WRITER_RELAY, create=True)
@patch('Devo_v2.WRITER_CREDENTIALS', MOCK_WRITER_CREDENTIALS, create=True)
@patch('Devo_v2.demisto.args')
@patch('Devo_v2.Sender')
@patch('Devo_v2.Lookup')
def test_write_lookup_devo(mock_lookup_writer_lookup, mock_lookup_writer_sender, mock_lookup_write_args):
    mock_lookup_write_args.return_value = MOCK_LOOKUP_WRITER_ARGS
    mock_lookup_writer_sender.return_value = MOCK_SENDER()
    mock_lookup_writer_lookup.return_value = MOCK_LOOKUP()
    results = write_to_lookup_table_command()
    assert results[0]['EntryContext']['Devo.RecordsWritten'] == 3
