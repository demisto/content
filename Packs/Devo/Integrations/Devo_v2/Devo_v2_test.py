import json
import time
import copy
from unittest.mock import MagicMock, patch

import pytest

from Devo_v2 import (
    alert_to_incident,
    fetch_incidents,
    run_query_command,
    get_alerts_command,
    multi_table_query_command,
    write_to_table_command,
    write_to_lookup_table_command,
    check_configuration,
    get_time_range,
)

MOCK_READER_ENDPOINT = "https://fake.devo.com/query"
MOCK_LINQ_LINK_BASE = "https://devo.com"
MOCK_READER_OAUTH_TOKEN = "123"
MOCK_WRITER_RELAY = "eu.whatever.devo.com"
MOCK_LINQ_RETURN = "from whatever.table"
MOCK_WRITER_CREDENTIALS = {"key": "fake", "crt": "fake", "chain": "fake"}
MOCK_FETCH_INCIDENTS_FILTER = {
    "type": "OR",
    "filters": [
        {"key": "foo", "operator": "->", "value": "baz"},
        {"key": "baz", "operator": "or", "value": "bar"},
    ],
}


MOCK_FETCH_INCIDENTS_LIMIT_INCORRECT = 1000

MOCK_FETCH_INCIDENTS_DEDUPE = {"cooldown": 120}
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
    '"eventdate":"2019-09-20+08%3A52%3A14.096","timestamp":"2019-09-20+08%3A52%3A14"}',
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
    "test%40test.comNoneNone550.239."
    '225.14NoneNoneNoneNone","eventdate":"2019-09-20+20%3A41%3A39.688","prev_srcHost":"None","duration":"None",'
    '"indices":"0%2C1C133","payload":'
    '"NEW+RECORDtest%40test.comNoneNoneNatic31.'
    '335.14NoneNoneNoneNone","state":"NEW+RECORD","category":"modelserverdev",'
    '"facility":"user","username":"test%40test.com","geolocation":"421%'
    'C2W","timestamp":"2019-09-20+20%3A41%3A37.395"}',
}
MOCK_QUERY_RESULTS = [MOCK_HIGH_CPU_ALERT, MOCK_SIMULTANEOUS_LOGIN_ALERT]
MOCK_LAST_RUN = {"from_time": time.time() - 60}
MOCK_QUERY_ARGS = {
    "query": "from whatever",
    "from": time.time() - 60,
    "to": time.time(),
    "writeToContext": "true",
}
MOCK_ALERT_ARGS = {
    "filters": MOCK_FETCH_INCIDENTS_FILTER,
    "from": time.time() - 60,
    "to": time.time(),
    "writeToContext": "true",
}
MOCK_MULTI_ARGS = {
    "tables": ["app", "charlie", "test"],
    "searchToken": "searching",
    "from": time.time() - 60,
    "to": time.time(),
    "writeToContext": "true",
}
MOCK_WRITER_ARGS = {
    "tableName": "whatever.table",
    "records": [{"foo": "hello"}, {"foo": "world"}, {"foo": "demisto"}],
}
MOCK_WRITE_TO_TABLE_RECORDS = {
    "tableName": "whatever.table",
    "records": ['{"foo": "hello"}', '{"foo": "world"}', '{"foo": "demisto"}'],
}
MOCK_LOOKUP_WRITER_ARGS = {
    "lookupTableName": "hello.world.lookup",
    "headers": ["foo", "bar", "baz"],
    "records": [
        {"key": "fookey", "values": ["fookey", "bar0", "baz0"]},
        {"key": "keyfoo", "values": ["keyfoo", "bar1", "baz1"]},
        {"key": "keykey", "values": ["keykey", "bar5", "baz6"]},
    ],
}
MOCK_KEYS = {"foo": "bar", "baz": "bug"}
OFFSET = 0
ITEMS_PER_PAGE = 10

ALERT_WITH_MISSING_DATA = {
    "user_prefixcontext": "sample.context.value",
    "user_prefixalertId": "alert123",
    "eventdate": 1646895689000,
    "user_prefixextraData": {
        "alertPriority": "HIGH",
        "alertName": "null",
        "alertDescription": "This is a sample alert",
    },
    "sample_key1": "sample_value1",
    "sample_key2": "sample_value2",
}

ALERT = {
    "user_prefixcontext": "sample.context.value",
    "user_prefixalertId": "alert123",
    "eventdate": 1646895689000,
    "user_prefixextraData": {
        "alertPriority": "HIGH",
        "alertName": "Sample Alert",
        "alertDescription": "This is a sample alert",
    },
    "sample_key1": "sample_value1",
    "sample_key2": "sample_value2",
}
USER_PREFIX = "user_prefix"
EXPECTED_LABELS_WITH_NULL = [
    {"type": "devo.metadata.alert.user_prefixcontext", "value": "sample.context.value"},
    {"type": "devo.metadata.alert.user_prefixalertId", "value": "alert123"},
    {"type": "devo.metadata.alert.eventdate", "value": "1646895689000"},
    {"type": "devo.metadata.alert.sample_key1", "value": "sample_value1"},
    {"type": "devo.metadata.alert.sample_key2", "value": "sample_value2"},
    {"type": "alertPriority", "value": "HIGH"},
    {"type": "alertName", "value": "null"},
    {"type": "alertDescription", "value": "This is a sample alert"},
]

EXPECTED_LABELS = [
    {"type": "devo.metadata.alert.user_prefixcontext", "value": "sample.context.value"},
    {"type": "devo.metadata.alert.user_prefixalertId", "value": "alert123"},
    {"type": "devo.metadata.alert.eventdate", "value": "1646895689000"},
    {"type": "devo.metadata.alert.sample_key1", "value": "sample_value1"},
    {"type": "devo.metadata.alert.sample_key2", "value": "sample_value2"},
    {"type": "alertPriority", "value": "HIGH"},
    {"type": "alertName", "value": "Sample Alert"},
    {"type": "alertDescription", "value": "This is a sample alert"},
]
LAST_RUN_DATA = {"from_time": 1691307869.0, "last_fetch_events": [{'123': 1691307869.0}]}

MOCK_EVENTS = [
    {
        "alertId": "123",
        "extraData": {"key1": "value1", "key2": "value2"},
        "eventdate": 1691307869000,
        "context": "value1",
    },
    {
        "alertId": "456",
        "extraData": {"key1": "value3", "key2": "value4"},
        "eventdate": 1691394269000,
        "context": "value2",
    },
    {
        "alertId": "789",
        "extraData": {"key1": "value3", "key2": "value4"},
        "eventdate": 1691480669000,
        "context": "value3",
    },
]

EXPECTED_LAST_RUN_DATA = {'from_time': 1691480669.0, 'last_fetch_events': [{'456': 1691394269.0}, {'789': 1691480669.0}]}


class MOCK_LOOKUP:
    def send_control(*args, **kw):
        pass

    def send_data_line(*args, **kw):
        pass


class MOCK_SOCKET:
    def shutdown(*args, **kw):
        pass


class MOCK_SENDER:
    socket = MOCK_SOCKET()

    def flush_buffer(*args, **kw):
        pass


class MOCK_READER:
    pass


def test_time_range():
    tolerance: float = 0.001
    time_from = time.time() - 60
    time_to = time.time()
    time_from_string = "2020-01-10T01:30:30"
    time_from_string_ts = 1578619830
    time_to_string = "2020-01-10T02:30:30"
    time_to_string_ts = 1578623430
    assert get_time_range(time_from, None)[0] == time_from
    assert get_time_range(time_from, time_to)[1] == time_to
    assert get_time_range(str(time_from), None)[0] == time_from
    assert get_time_range(str(time_from), str(time_to))[1] == time_to
    assert get_time_range("1 minute", None)[0] - time_from < abs(tolerance)
    assert get_time_range("2 minute", None)[0] <= time_from
    assert get_time_range(time_from_string, None)[0] - time_from_string_ts < abs(tolerance)
    assert get_time_range(time_from_string, time_to_string)[1] - time_to_string_ts < abs(tolerance)


@patch("Devo_v2.READER_ENDPOINT", MOCK_READER_ENDPOINT, create=True)
@patch("Devo_v2.READER_OAUTH_TOKEN", MOCK_READER_OAUTH_TOKEN, create=True)
@patch("Devo_v2.WRITER_RELAY", MOCK_WRITER_RELAY, create=True)
@patch("Devo_v2.WRITE_CREDENTIALS", MOCK_WRITER_CREDENTIALS, create=True)
@patch("Devo_v2.FETCH_INCIDENTS_FILTER", MOCK_FETCH_INCIDENTS_FILTER, create=True)
@patch("Devo_v2.FETCH_INCIDENTS_DEDUPE", MOCK_FETCH_INCIDENTS_DEDUPE, create=True)
@patch("Devo_v2.ds.Reader.query")
@patch("Devo_v2.Sender")
def test_command(mock_query_results, mock_write_args):
    mock_query_results.return_value = copy.deepcopy(MOCK_QUERY_RESULTS)
    mock_write_args.return_value = MOCK_WRITER_ARGS
    assert check_configuration()


@patch("Devo_v2.READER_ENDPOINT", MOCK_READER_ENDPOINT, create=True)
@patch("Devo_v2.READER_OAUTH_TOKEN", MOCK_READER_OAUTH_TOKEN, create=True)
@patch("Devo_v2.FETCH_INCIDENTS_FILTER", MOCK_FETCH_INCIDENTS_FILTER, create=True)
@patch("Devo_v2.ds.Reader.query")
def test_first_fetch_incidents(mock_query_results):
    mock_query_results.return_value = copy.deepcopy(MOCK_QUERY_RESULTS)
    incidents = fetch_incidents()
    assert len(incidents) == 2
    assert (
        json.loads(incidents[0]["rawJSON"])["devo.metadata.alert"]["context"]
        == "CPU_Usage_Alert"
    )


@patch("Devo_v2.READER_ENDPOINT", MOCK_READER_ENDPOINT, create=True)
@patch("Devo_v2.READER_OAUTH_TOKEN", MOCK_READER_OAUTH_TOKEN, create=True)
@patch("Devo_v2.FETCH_INCIDENTS_FILTER", MOCK_FETCH_INCIDENTS_FILTER, create=True)
@patch("Devo_v2.demisto.getLastRun")
@patch("Devo_v2.ds.Reader.query")
def test_next_fetch(mock_query_results, mock_last_run):
    mock_query_results.return_value = copy.deepcopy(MOCK_QUERY_RESULTS)
    mock_last_run.return_value = MOCK_LAST_RUN
    incidents = fetch_incidents()
    assert len(incidents) == 2
    assert (
        json.loads(incidents[1]["rawJSON"])["devo.metadata.alert"]["context"]
        == "simultaneous_login"
    )


@patch("Devo_v2.READER_ENDPOINT", MOCK_READER_ENDPOINT, create=True)
@patch("Devo_v2.READER_OAUTH_TOKEN", MOCK_READER_OAUTH_TOKEN, create=True)
@patch("Devo_v2.demisto.args")
@patch("Devo_v2.ds.Reader.query")
def test_get_alerts(mock_query_results, mock_args_results):
    mock_query_results.return_value = copy.deepcopy(MOCK_QUERY_RESULTS)
    mock_args_results.return_value = MOCK_ALERT_ARGS
    results = get_alerts_command(OFFSET, ITEMS_PER_PAGE)
    assert len(results) == 2
    assert results[0]["Contents"][0]["engine"] == "CPU_Usage_Alert"


@patch("Devo_v2.READER_ENDPOINT", MOCK_READER_ENDPOINT, create=True)
@patch("Devo_v2.READER_OAUTH_TOKEN", MOCK_READER_OAUTH_TOKEN, create=True)
@patch("Devo_v2.demisto.args")
@patch("Devo_v2.ds.Reader.query")
def test_run_query(mock_query_results, mock_args_results):
    mock_query_results.return_value = copy.deepcopy(MOCK_QUERY_RESULTS)
    mock_args_results.return_value = MOCK_QUERY_ARGS
    results = run_query_command(OFFSET, ITEMS_PER_PAGE)
    assert (results[1]["HumanReadable"]).find("Devo Direct Link") != -1
    assert len(results) == 2
    assert results[0]["Contents"][0]["engine"] == "CPU_Usage_Alert"


@patch("Devo_v2.READER_ENDPOINT", MOCK_READER_ENDPOINT, create=True)
@patch("Devo_v2.READER_OAUTH_TOKEN", MOCK_READER_OAUTH_TOKEN, create=True)
@patch("Devo_v2.concurrent.futures.wait")
@patch("Devo_v2.concurrent.futures.ThreadPoolExecutor.submit")
@patch("Devo_v2.demisto.args")
@patch("Devo_v2.ds.Reader.query")
@patch("Devo_v2.ds.Reader")
@patch("Devo_v2.get_types")
def test_multi_query(
    mock_query_types,
    mock_query_reader,
    mock_query_results,
    mock_args_results,
    mock_submit_results,
    mock_wait_results,
):
    mock_query_types.return_value = MOCK_KEYS
    mock_query_reader.return_value = MOCK_READER
    mock_query_results.return_value = copy.deepcopy(MOCK_QUERY_RESULTS)
    mock_args_results.return_value = MOCK_MULTI_ARGS
    mock_submit_results.return_value = None
    mock_wait_results.return_value = (None, None)
    results = multi_table_query_command(OFFSET, ITEMS_PER_PAGE)
    assert results["HumanReadable"] == "No results found"


@patch("Devo_v2.WRITER_RELAY", MOCK_WRITER_RELAY, create=True)
@patch("Devo_v2.WRITER_CREDENTIALS", MOCK_WRITER_CREDENTIALS, create=True)
@patch("Devo_v2.demisto.args")
@patch("Devo_v2.Sender")
def test_write_devo(mock_load_results, mock_write_args):
    mock_load_results.return_value.load.return_value = MOCK_LINQ_RETURN
    mock_write_args.return_value = MOCK_WRITE_TO_TABLE_RECORDS
    results = write_to_table_command()
    assert len(results[0]["EntryContext"]["Devo.RecordsWritten"]) == 3
    assert results[0]["EntryContext"]["Devo.LinqQuery"] == "from whatever.table"


@patch("Devo_v2.WRITER_RELAY", MOCK_WRITER_RELAY, create=True)
@patch("Devo_v2.WRITER_CREDENTIALS", MOCK_WRITER_CREDENTIALS, create=True)
@patch("Devo_v2.demisto.args")
@patch("Devo_v2.Sender")
@patch("Devo_v2.Lookup")
def test_write_lookup_devo(
    mock_lookup_writer_lookup, mock_lookup_writer_sender, mock_lookup_write_args
):
    mock_lookup_write_args.return_value = MOCK_LOOKUP_WRITER_ARGS
    mock_lookup_writer_sender.return_value = MOCK_SENDER()
    mock_lookup_writer_lookup.return_value = MOCK_LOOKUP()
    results = write_to_lookup_table_command()
    assert len(results[0]["EntryContext"]["Devo.RecordsWritten"]) == 3


@patch("Devo_v2.demisto_ISO", return_value="2022-03-15T15:01:23.456Z")
def test_alert_to_incident_all_data(mock_demisto_ISO):
    incident = alert_to_incident(ALERT, USER_PREFIX)
    assert incident["name"] == "Sample Alert"
    assert incident["severity"] == 3
    assert incident["details"] == "alert123"
    assert incident["description"] == "This is a sample alert"
    assert incident["occurred"] == "2022-03-15T15:01:23.456Z"
    assert incident["labels"] == EXPECTED_LABELS
    assert "devo.metadata.alert" in json.loads(incident["rawJSON"])
    assert "sample_key1" in json.loads(incident["rawJSON"])["devo.metadata.alert"]
    assert "sample_key2" in json.loads(incident["rawJSON"])["devo.metadata.alert"]
    assert "alertPriority" in json.loads(incident["rawJSON"])
    assert "alertName" in json.loads(incident["rawJSON"])
    assert "alertDescription" in json.loads(incident["rawJSON"])
    assert mock_demisto_ISO.called


@patch("Devo_v2.demisto_ISO", return_value="2022-03-15T15:01:23.456Z")
def test_alert_to_incident_missing_data(mock_demisto_ISO):
    incident = alert_to_incident(ALERT_WITH_MISSING_DATA, USER_PREFIX)
    assert incident["name"] == "value"
    assert incident["severity"] == 3
    assert incident["details"] == "alert123"
    assert incident["description"] == "This is a sample alert"
    assert incident["occurred"] == "2022-03-15T15:01:23.456Z"
    assert incident["labels"] == EXPECTED_LABELS_WITH_NULL
    assert "devo.metadata.alert" in json.loads(incident["rawJSON"])
    assert "sample_key1" in json.loads(incident["rawJSON"])["devo.metadata.alert"]
    assert "sample_key2" in json.loads(incident["rawJSON"])["devo.metadata.alert"]
    assert "alertPriority" in json.loads(incident["rawJSON"])
    assert "alertName" in json.loads(incident["rawJSON"])
    assert "alertDescription" in json.loads(incident["rawJSON"])
    assert mock_demisto_ISO.called


@patch("Devo_v2.demisto.getLastRun")
@patch("Devo_v2.ds.Reader")
@patch("Devo_v2.demisto.setLastRun")
@patch("Devo_v2.demisto.incidents")
def test_fetch_incidents(
    mock_incidents: MagicMock,
    mock_setLastRun: MagicMock,
    mock_Reader: MagicMock,
    mock_getLastRun: MagicMock,
):
    mock_getLastRun.return_value = LAST_RUN_DATA

    mock_Reader.return_value.query.return_value = MOCK_EVENTS
    # Call the function
    fetch_incidents()
    # Check that setLastRun was called with the expected argument

    mock_setLastRun.assert_called_once_with(EXPECTED_LAST_RUN_DATA)
    mock_incidents.assert_called_once()


@patch(
    "Devo_v2.FETCH_INCIDENTS_LIMIT", MOCK_FETCH_INCIDENTS_LIMIT_INCORRECT, create=True
)
def fetch_incidents_limit_out_of_range():
    with pytest.raises(ValueError) as e:
        fetch_incidents()
    assert (
        "Fetch incidents limit should be greater than or equal to 10 and smaller than or equal to 100"
        in str(e.value)
    )
