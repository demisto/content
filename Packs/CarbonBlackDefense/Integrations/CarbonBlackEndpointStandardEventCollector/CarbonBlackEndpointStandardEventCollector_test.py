import pytest
import json
from CarbonBlackEndpointStandardEventCollector import (
    Client,
    get_alerts_to_limit,
    get_audit_logs_to_limit,
    prepare_audit_logs_result,
    get_events,
    init_last_run,
    LAST_ALERT_IDS,
    LAST_AUDIT_TIME,
    MAX_AUDITS,
    MAX_FETCH_LOOP,
    timestamp_to_datestring,
)


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


@pytest.fixture
def cb_client():
    return Client(url="https://test.com", org_key="test", credentials={})


@pytest.fixture
def alerts():
    return util_load_json('test_data/alerts.json')


@pytest.fixture
def audit_logs():
    return util_load_json('test_data/audit_logs.json')


@pytest.fixture
def last_run():
    return init_last_run({})


def test_get_alerts_to_limit_empty(mocker, cb_client, last_run):
    """
    Given a CB client and last run
    When get_alerts_to_limit is called and empty response returned
    Then empty list is returned and last_run is returned unchanged
    """

    mocker.patch.object(cb_client, 'get_alerts', return_value=[])

    alerts, new_last_run = get_alerts_to_limit(cb_client, last_run)

    assert len(alerts) == 0
    assert new_last_run.get(LAST_AUDIT_TIME) is None
    assert new_last_run.get(LAST_ALERT_IDS) == []
    assert new_last_run == last_run


def test_prepare_audit_logs_result_remove_duplicates(cb_client, audit_logs):
    """
    Given: audit logs contain duplicate entries
    When: calling prepare_audit_logs_result
    Then: Filter out duplicate entries based on eventTime and return the filtered list
    """
    last_time = timestamp_to_datestring(audit_logs[2]['eventTime'])
    filtered_audit_logs = prepare_audit_logs_result(audit_logs, last_time)
    assert len(audit_logs) == len(filtered_audit_logs) + 2


def test_get_events(mocker, cb_client, last_run):
    """
    Given there are no events and no audits to fetch
    When get_events is called
    Then return no events and the last_run unchanged
    """

    mocker.patch.object(cb_client, 'get_alerts', return_value=[])
    mocker.patch.object(cb_client, 'get_audit_logs', return_value=[])

    events, new_last_run = get_events(cb_client, last_run, True)

    assert len(events) == 0
    assert new_last_run == last_run


def test_get_audit_logs_to_limit_max(mocker, cb_client, audit_logs):
    """
    Given there are 11 audit logs pages to fetch
    When  get_audit_logs_to_limit is called
    Then  10 pages are returned
    """
    mocker.patch.object(cb_client, 'get_audit_logs', return_value=[audit_logs] * (MAX_FETCH_LOOP + 1))
    audit_logs = get_audit_logs_to_limit(cb_client)
    assert len(audit_logs) < MAX_AUDITS
    assert cb_client.get_audit_logs.call_count == MAX_FETCH_LOOP
