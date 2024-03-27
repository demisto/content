import freezegun
import pytest
from CommonServerPython import *  # noqa: F401

from QualysEventCollector import get_activity_logs_events_command, \
    Client, fetch_events, get_activity_logs_events, fetch_assets, ASSETS_FETCH_FROM, ASSETS_DATE_FORMAT

ACTIVITY_LOGS_NEWEST_EVENT_DATETIME = 'activity_logs_newest_event_datetime'
ACTIVITY_LOGS_NEXT_PAGE = 'activity_logs_next_page'
ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN = 'activity_logs_since_datetime_prev_run'
HOST_DETECTIONS_NEWEST_EVENT_DATETIME = 'host_detections_newest_event_datetime'
HOST_DETECTIONS_NEXT_PAGE = 'host_detections_next_page'
HOST_DETECTIONS_SINCE_DATETIME_PREV_RUN = 'host_detections_since_datetime_prev_run'
HOST_LAST_FETCH = 'host_last_fetch'
BEGIN_RESPONSE_LOGS_CSV = "----BEGIN_RESPONSE_BODY_CSV"
END_RESPONSE_LOGS_CSV = "----END_RESPONSE_BODY_CSV"
FOOTER = """----BEGIN_RESPONSE_FOOTER_CSV
WARNING
"CODE","TEXT","URL"
"1980","17 record limit exceeded. Use URL to get next batch of results.","https://server_url/api/2.0/fo/activity_log/
?action=list&since_datetime=2022-12-21T03:42:05Z&truncation_limit=10&id_max=123456"
----END_RESPONSE_FOOTER_CSV"""


def test_get_activity_logs_events_command(requests_mock):
    """
    Given:
    - activity_logs_events_command

    When:
    - Want to list all existing activity logs

    Then:
    - Ensure Activity Logs Results in human-readable, and number of results reasonable.
    """
    base_url = 'https://server_url/'
    with open('test_data/activity_logs.csv') as f:
        logs = f.read()
    requests_mock.get(f'{base_url}api/2.0/fo/activity_log/'
                      f'?action=list&truncation_limit=0&since_datetime=2023-03-01T00%3A00%3A00Z', text=logs)
    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False,
                    username='demisto',
                    password='demisto',
                    )
    args = {'limit': 50, 'since_datetime': '1 March 2023'}
    first_fetch = '2022-03-21T03:42:05Z'
    activity_logs_events, results = get_activity_logs_events_command(client, args, first_fetch)
    assert 'Activity Logs' in results.readable_output
    assert len(activity_logs_events) == 17


@pytest.mark.parametrize('activity_log_last_run, logs_number, add_footer',
                         [(None, 17, True),
                          ("2023-05-24T09:55:35Z", 0, True),
                          ("2023-05-14T15:04:55Z", 7, True),
                          ("2023-01-01T08:06:44Z", 17, False)])
def test_fetch_logs_events_command(requests_mock, activity_log_last_run, logs_number, add_footer):
    """
    Given:
    - fetch events command (fetches logs)

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched
    - Ensure next page token saved
    - Ensure previous run saved
    - Ensure newest event time saved
    """
    first_fetch_str = '2022-12-21T03:42:05Z'
    base_url = 'https://server_url/'
    truncation_limit = logs_number
    with open('test_data/activity_logs.csv') as f:
        logs = f.read()
        new_logs = f'{BEGIN_RESPONSE_LOGS_CSV}'
        for row in logs.split('\n'):
            if activity_log_last_run and activity_log_last_run in row:
                new_logs += f'{row}\n'
                break
            new_logs += f'{row}\n'
        new_logs += f'{END_RESPONSE_LOGS_CSV}\n'
        if add_footer:
            new_logs += f'{FOOTER}\n'

    requests_mock.get(f'{base_url}api/2.0/fo/activity_log/'
                      f'?action=list&truncation_limit={truncation_limit}&'
                      f'since_datetime={activity_log_last_run if activity_log_last_run else first_fetch_str}',
                      text=new_logs)
    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False,
                    username='demisto',
                    password='demisto',
                    )
    last_run = {ACTIVITY_LOGS_NEWEST_EVENT_DATETIME: activity_log_last_run}

    logs_next_run, activity_logs_events = fetch_events(
        client=client,
        last_run=last_run,
        newest_event_field=ACTIVITY_LOGS_NEWEST_EVENT_DATETIME,
        next_page_field=ACTIVITY_LOGS_NEXT_PAGE,
        previous_run_time_field=ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN,
        fetch_function=get_activity_logs_events,
        first_fetch_time=first_fetch_str,
        max_fetch=truncation_limit,
    )
    assert len(activity_logs_events) == logs_number
    assert logs_next_run.get(ACTIVITY_LOGS_NEXT_PAGE) == ("123456" if add_footer else None)
    assert logs_next_run.get(ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN) == activity_log_last_run or first_fetch_str
    assert logs_next_run.get(ACTIVITY_LOGS_NEWEST_EVENT_DATETIME) == "2023-05-24T09:55:35Z"


def test_fetch_assets_command(requests_mock):
    """
    Given:
    - fetch_assets_command
    When:
    - Want to list all existing incidents
    Then:
    - Ensure List assets and vulnerabilities.
    """
    base_url = 'https://server_url/'
    with open('./test_data/host_list_detections_raw.xml') as f:
        assets = f.read()
    with open('./test_data/vulnerabilities_raw.xml') as f:
        vulnerabilities = f.read()
    requests_mock.get(f'{base_url}api/2.0/fo/asset/host/vm/detection/'
                      f'?action=list&truncation_limit=3&vm_scan_date_after={arg_to_datetime(ASSETS_FETCH_FROM).strftime(ASSETS_DATE_FORMAT)}', text=assets)

    requests_mock.post(f'{base_url}api/2.0/fo/knowledge_base/vuln/'
                       f'?action=list&last_modified_after={arg_to_datetime(ASSETS_FETCH_FROM).strftime(ASSETS_DATE_FORMAT)}', text=vulnerabilities)

    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False,
                    username='demisto',
                    password='demisto',
                    )
    assets, vulnerabilities = fetch_assets(client=client)

    assert len(assets) == 8
    assert len(vulnerabilities) == 2
