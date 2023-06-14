import freezegun
import pytest
from CommonServerPython import *  # noqa: F401

from QualysEventCollector import get_activity_logs_events_command, get_host_list_detections_events_command, \
    Client, fetch_events, get_host_list_detections_events, get_activity_logs_events, should_run_host_detections_fetch


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
    with open('./test_data/activity_logs.csv', 'r') as f:
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


def test_get_host_list_detections_events_command(requests_mock):
    """
    Given:
    - host_list_detections_events_command

    When:
    - Want to list all existing incidents
    Then:
    - Ensure List Host Detections Results in human-readable, and number of results reasonable.
    """
    base_url = 'https://server_url/'
    with open('./test_data/host_list_detections_raw.xml', 'r') as f:
        logs = f.read()
    requests_mock.get(f'{base_url}api/2.0/fo/asset/host/vm/detection/'
                      f'?action=list&truncation_limit=0&vm_scan_date_after=2023-03-01T00%3A00%3A00Z', text=logs)
    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False,
                    username='demisto',
                    password='demisto',
                    )
    args = {'limit': 50, 'vm_scan_date_after': '1 March 2023'}
    first_fetch = '2022-03-21T03:42:05Z'
    host_events, results = get_host_list_detections_events_command(client, args, first_fetch)
    assert 'Host List Detection' in results.readable_output
    assert len(host_events) == 8


@pytest.mark.parametrize('last_run, fetch_interval_param, expected_should_run', [
    ('2023-05-24T11:55:35Z', '12 hours', False),
    ('2023-05-23T11:55:35Z', '12 hours', True),
    ({}, '1 hour', True),
])
def test_should_run_host_detections_fetch(last_run, fetch_interval_param, expected_should_run):
    """
    Given:
    - should_run_host_detections_fetch command (fetches detections)

    When:
    - Running fetch-events command and need to decide whether to fetch host detections

    Then:
    - Ensure the expected result
    """
    datetime_now = datetime.strptime('2023-05-24 12:00:00', '%Y-%m-%d %H:%M:%S')
    fetch_interval = datetime_now - dateparser.parse(fetch_interval_param)
    last_run_dict = {'host_last_fetch': last_run}
    should_run = should_run_host_detections_fetch(last_run=last_run_dict,
                                                  host_detections_fetch_interval=fetch_interval,
                                                  datatime_now=datetime_now)
    assert should_run == expected_should_run


@pytest.mark.parametrize('activity_log_last_run, logs_number',
                         [(None, 17),
                          ("2023-05-24T09:55:35Z", 0),
                          ("2023-05-14T15:04:55Z", 7),
                          ("2023-01-01T08:06:44Z", 17)])
def test_fetch_logs_events_command(requests_mock, activity_log_last_run, logs_number):
    """
    Given:
    - fetch events command (fetches logs)

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched
    """
    first_fetch_str = '2022-12-21T03:42:05Z'
    base_url = 'https://server_url/'
    with open('./test_data/activity_logs.csv', 'r') as f:
        logs = f.read()
        new_logs = ''
        for row in logs.split('\n'):
            if activity_log_last_run and activity_log_last_run in row:
                new_logs += f'{row}\n'
                break
            else:
                new_logs += f'{row}\n'
    requests_mock.get(f'{base_url}api/2.0/fo/activity_log/'
                      f'?action=list&truncation_limit=0&'
                      f'since_datetime={activity_log_last_run if activity_log_last_run else first_fetch_str}',
                      text=new_logs)
    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False,
                    username='demisto',
                    password='demisto',
                    )
    last_run = {'activity_logs': activity_log_last_run, 'host_list_detection': ''}

    logs_next_run, activity_logs_events = fetch_events(
        client=client,
        last_run=last_run,
        last_run_field='activity_logs',
        fetch_function=get_activity_logs_events,
        first_fetch_time=first_fetch_str,
    )
    assert len(activity_logs_events) == logs_number
    assert logs_next_run.get('activity_logs') == "2023-05-24T09:55:35Z"


@freezegun.freeze_time('2023-05-16 16:00:00')
@pytest.mark.parametrize('host_last_run,detections_number',
                         [(None, 8),
                          ("2023-05-16T15:26:53Z", 4),
                          ("2023-05-14T15:04:55Z", 7)])
def test_fetch_detection_events_command(requests_mock, host_last_run, detections_number):
    """
    Given:
    - fetch events command (fetches detections)

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched
    """
    first_fetch_str = '2022-12-21T03:42:05Z'
    base_url = 'https://server_url/'
    with open('./test_data/host_list_detections_raw.xml', 'r') as f:
        hosts = f.read()
    requests_mock.get(f'{base_url}api/2.0/fo/asset/host/vm/detection/'
                      f'?action=list&truncation_limit=0'
                      f'&vm_scan_date_after={host_last_run if host_last_run else first_fetch_str}', text=hosts)
    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False,
                    username='demisto',
                    password='demisto',
                    )
    last_run = {'activity_logs': '', 'host_list_detection': host_last_run}
    host_next_run, host_list_detection_events = fetch_events(
        client=client,
        last_run=last_run,
        last_run_field='host_list_detection',
        fetch_function=get_host_list_detections_events,
        first_fetch_time=first_fetch_str,
    )

    assert len(host_list_detection_events) == detections_number
    assert host_next_run.get('host_list_detection') == '2023-05-16T15:26:01Z'
    assert host_next_run.get('host_last_fetch') == '2023-05-16T16:00:00Z'
