import pytest
import json
import Intel471WatcherAlerts as feed


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


GET_REPORT_TYPE_DATA = [
    (
        'https://titan.intel471.com/report/inforep/fd1636d9f5a66098bcea8ae341b0304d',  # input
        'INFO REPORT:\n'  # expected
    ),
    (
        'https://titan.intel471.com/report/fintel/3820588e7fab5f9e24cd582fe2a9f276',  # input
        'FINTEL:\n'  # expected
    ),
    (
        'https://titan.intel471.com/report/spotrep/3ff4ef482649a94e792f8476edc84381',  # input
        'SPOT REPORT:\n'  # expected
    )
]


@pytest.mark.parametrize('input,expected_results', GET_REPORT_TYPE_DATA)
def test_get_report_type(mocker, input, expected_results):
    """
    Given:
        - set of parameters from demisto.

    When:
        - create an instance and on every run.

    Then:
        - Returns a report type.

    """
    report_type: str = feed.get_report_type(input)
    assert report_type == expected_results


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Intel471WatcherAlerts import Client, fetch_incidents

    mock_response = util_load_json('test_data/search_alerts.json')
    requests_mock.get(
        'https://api.test.com/v1/alerts?showRead=true&displayWatchers=true&markAsRead=false&sort=earliest&count=1&'
        'from=1581944401',
        json=mock_response)

    client = Client(
        base_url='https://api.test.com/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    last_run = {
        'last_fetch': 1581944401  # Mon Feb 17 2020
    }

    latest_alert_uid, next_run, incidents = fetch_incidents(
        client=client,
        max_results=1,
        last_run=last_run,
        first_fetch_time=0,
        watcher_group_uids=None,
        severity='Medium',
        last_alert_uid=''
    )

    assert incidents == [
        {
            'name': 'INSTANT MESSAGE:\nPart 1 sell part2',
            'occurred': '2021-10-25T11:34:47.000Z',
            'rawJSON': json.dumps(mock_response['alerts'][0]),
            'type': 'Intel 471 Watcher Alert',
            'severity': 2,
            'CustomFields': {
                'titanurl': 'https://titan.intel471.com/ims_thread/45678901234567890123456789012345?message_uid'
                            '=34567890123456789012345678901234',
                'titanwatchergroup': 'Test Watcher Group 1',
                'titanwatcher': "Watcher on \"sell\""
            },
            'details': 'Source Object: INSTANT MESSAGE\nService: TestService\nChannel: TEST CHANNEL\nActor: \n\nPart 1 sell part2'
        }
    ]
