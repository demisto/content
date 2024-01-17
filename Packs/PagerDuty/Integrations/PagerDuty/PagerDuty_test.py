from CommonServerPython import *
import pytest
from pytest_mock import MockerFixture
from requests_mock import MockerCore


def load_mock_response(file_name: str) -> dict:
    """
    Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.

    Returns:
        str: Mock file content.

    """
    with open(f'test_data/{file_name}') as f:
        return json.loads(f.read())


def test_get_incidents(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - An incident with non-ascii character in its documentation

    When:
        - Running get incidents command

    Then:
        - Ensure command run without failing on UnicodeError
        - Verify the non-ascii character appears in the human readable output as expected
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'DefaultRequestor'
        }
    )
    from PagerDuty import get_incidents_command
    requests_mock.get(
        'https://api.pagerduty.com/incidents?include%5B%5D=assignees&statuses%5B%5D=triggered&statuses%5B%5D'
        '=acknowledged&include%5B%5D=first_trigger_log_entries&include%5B%5D=assignments&time_zone=UTC',
        json={
            'incidents': [{
                'first_trigger_log_entry': {
                    'channel': {
                        'details': {
                            'Documentation': '•'
                        }
                    }
                }
            }]
        }
    )
    res = get_incidents_command({})
    assert '| Documentation: • |' in res['HumanReadable']


def test_add_responders(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a responder request.

    When:
        - Running PagerDuty-add-responders command.

    Then:
        - Ensure command returns the correct output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            "incident_id": "PXP12GZ",
            "message": "Please help with issue - join bridge at +1(234)-567-8910",
            "user_requests": "P09TT3C,PAIXXX"
        }
    )
    requests_mock.post(
        'https://api.pagerduty.com/incidents/PXP12GZ/responder_requests',
        json=load_mock_response('responder_requests.json')['specific_users']
    )

    from PagerDuty import add_responders_to_incident
    res = add_responders_to_incident(**demisto.args())
    expected_users_requested = ','.join([x["ID"] for x in res.outputs])
    assert demisto.args()['incident_id'] == res.outputs[0]['IncidentID']
    assert demisto.args()['message'] == res.outputs[0]['Message']
    assert demisto.params()['DefaultRequestor'] == res.outputs[1]['RequesterID']
    assert demisto.args()['user_requests'] == expected_users_requested


def test_add_responders_default(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a responder request without specifying responders.

    When:
        - Running add_responders_to_incident function.

    Then:
        - Ensure the function returns the correct output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            "incident_id": "PXP12GZ",
            "message": "Please help with issue - join bridge at +1(234)-567-8910"
        }
    )
    requests_mock.post(
        'https://api.pagerduty.com/incidents/PXP12GZ/responder_requests',
        json=load_mock_response('responder_requests.json')['default_user']
    )

    from PagerDuty import add_responders_to_incident
    res = add_responders_to_incident(**demisto.args())
    expected_users_requested = ','.join([x["ID"] for x in res.outputs])
    assert demisto.args()['incident_id'] == res.outputs[0]['IncidentID']
    assert demisto.args()['message'] == res.outputs[0]['Message']
    assert demisto.params()['DefaultRequestor'] == res.outputs[0]['RequesterID']
    assert demisto.params()['DefaultRequestor'] == expected_users_requested


def test_play_response_play(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a responder request without specifying responders.

    When:
        - Running PagerDuty-run-response-play function.

    Then:
        - Ensure the function returns a valid status.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            "incident_id": "PXP12GZ",
            "from_email": "john.doe@example.com",
            "response_play_uuid": "response_play_id",
        }
    )
    requests_mock.post(
        'https://api.pagerduty.com/response_plays/response_play_id/run',
        json={"status": "ok"}
    )

    from PagerDuty import run_response_play
    res = run_response_play(**demisto.args())

    assert res.raw_response == {"status": "ok"}


def test_get_users_on_call(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a request to get user on-call by schedule ID.

    When:
        - Running get_on_call_users_command function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            "scheduleID": "PI7DH85",
        }
    )
    requests_mock.get(
        'https://api.pagerduty.com/schedules/PI7DH85/users',
        json=load_mock_response('schedules.json')
    )
    from PagerDuty import get_on_call_users_command
    res = get_on_call_users_command(**demisto.args())
    assert demisto.args()['scheduleID'] == res.outputs[0]['ScheduleID']


def test_get_users_on_call_now(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a reqest to get user oncall by schedule ID without specifying responders.

    When:
        - Running get_on_call_users_command function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            "schedule_ids": "PI7DH85,PA7DH85",
        }
    )
    requests_mock.get(
        'https://api.pagerduty.com/oncalls',
        json=load_mock_response('oncalls.json')
    )
    from PagerDuty import get_on_call_now_users_command
    res = get_on_call_now_users_command(**demisto.args())
    assert res.outputs[0]['ScheduleID'] in demisto.args()['schedule_ids']
    assert 'oncalls' in res.raw_response


def test_submit_event(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a reqest to submit request.

    When:
        - Running submit_event function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    source = 'test'
    summary = 'test'
    severity = 'test'
    action = 'test'

    requests_mock.post(
        'https://events.pagerduty.com/v2/enqueue',
        json={
            'status': 'status',
            'message': 'message',
            'dedup_key': 'dedup_key'
        }
    )
    from PagerDuty import submit_event_command
    res = submit_event_command(source, summary, severity, action)
    assert '### Trigger Event' in res['HumanReadable']


def test_get_all_schedules_command(mocker: MockerFixture, requests_mock: MockerCore) -> None:
    """
    Given:
        - a reqest to get all schedule

    When:
        - Running get_all_schedules function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )

    requests_mock.get(
        'https://api.pagerduty.com/schedules',
        json={
            'schedules': [{'id': 'id',
                           'name': 'name',
                           'time_zone': 'time_zone',
                           'escalation_policies': [{'id': 'id', 'summary': 'summary'}]}]

        }
    )
    from PagerDuty import get_all_schedules_command
    res = get_all_schedules_command()
    assert '### All Schedules' in res['HumanReadable']


def test_get_users_contact_methods_command(mocker: MockerFixture, requests_mock: MockerCore) -> None:
    """
    Given:
        - a reqest to get all schedule.

    When:
        - Running get_all_schedules function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )

    user_id = 'id'

    requests_mock.get(
        f'https://api.pagerduty.com/users/{user_id}/contact_methods',
        json={'contact_methods': [{'id': 'id', 'address': 'address', 'country_code': 'country_code'}]}
    )
    from PagerDuty import get_users_contact_methods_command
    res = get_users_contact_methods_command(user_id)
    assert '### Contact Methods' in res['HumanReadable']


def test_get_users_notification_command(mocker: MockerFixture, requests_mock: MockerCore) -> None:
    """
    Given:
        - a request to get users notifications.

    When:
        - Running get_users_notification_command function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )

    user_id = 'id'

    requests_mock.get(
        f'https://api.pagerduty.com/users/{user_id}/notification_rules',
        json={'notification_rules': [{'id': 'id', 'urgency': 'urgency', 'type': 'type'}]}
    )
    from PagerDuty import get_users_notification_command
    res = get_users_notification_command(user_id)
    assert '### User notification rules' in res['HumanReadable']


@pytest.mark.parametrize('severity, expected_result', [('high', 3), ('low', 1), ('other_severity', 0)])
def test_translate_severity(mocker: MockerFixture, severity: str, expected_result: int) -> None:
    """
    Given:
        - a severity.
    When:
        - Running translate_severity function.
    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    from PagerDuty import translate_severity
    res = translate_severity(severity)
    assert res == expected_result


def test_paginate_with_limit(mocker: MockerFixture):
    """This test verifies that the function correctly handles pagination when a limit is provided,
        making a single API request with the expected parameters and returning the correct results.
    Given:
        a test scenario where the `pagination_incidents` function is called with a specified limit,
    When:
        the function is invoked with a limit of 79,
    Then:
        it should make a single API request with the specified limit and offset 0,
        and the result should match the mocked API response.
    """
    from PagerDuty import pagination_incidents

    re = mocker.patch(
        "PagerDuty.http_request",
        side_effect=[
            {"incidents": list(range(79))}
        ],
    )

    result = pagination_incidents({"user_ids": "test_id"}, {"limit": 79}, "")

    assert result == list(range(79))
    assert re.call_count == 1
    assert re.call_args_list[0].args == ("GET", "", {"user_ids": "test_id", "limit": 79, "offset": 0})


def test_paginate_with_limit_is_more_than_INCIDENT_API_LIMIT(mocker: MockerFixture):
    """This test ensures that the function correctly handles pagination for large limits,
        making multiple API calls to retrieve all incidents.

    Given:
        a test scenario where the requested limit exceeds the max incidents per page (100),
    When:
        the `pagination_incidents` function is called with a limit of 179,
    Then:
        it should make two API calls:
        - First call with limit 100 and offset 0.
        - Second call with limit 79 (to fetch the remaining incidents) and offset 100.

    """
    from PagerDuty import pagination_incidents

    re = mocker.patch(
        "PagerDuty.http_request",
        side_effect=[
            {"incidents": list(range(100))},  # the response for the first call
            {"incidents": list(range(100, 179))},  # the response for the secund call
        ],
    )

    result = pagination_incidents({"user_ids": "test_id"}, {"limit": 179}, "")

    assert result == list(range(179))
    assert re.call_count == 2
    assert re.call_args_list[0].args == ("GET", "", {"user_ids": "test_id", "limit": 100, "offset": 0})  # first call
    assert re.call_args_list[1].args == ("GET", "", {"user_ids": "test_id", "limit": 79, "offset": 100})  # secund call


def test_paginate_with_page_size(mocker: MockerFixture):
    """This test verifies that the pagination functionality correctly handles the provided page size
        and page number, making a single API request with the expected parameters.
    Given:
        a test scenario where pagination is performed with a specified page size,
    When:
        the `pagination_incidents` function is called with a page size of 100 and page number 2,
    Then:
        it should make a single API request to fetch results from offset 100 to 199.
    """
    from PagerDuty import pagination_incidents

    re = mocker.patch(
        "PagerDuty.http_request", side_effect=[{"incidents": list(range(100, 200))}]
    )
    result = pagination_incidents({"user_ids": "test_id"}, {"page_size": 100, "page": 2}, "")
    assert result == list(range(100, 200))
    assert re.call_count == 1
    assert re.call_args_list[0].args == ('GET', '', {'user_ids': 'test_id', 'limit': 100, 'offset': 100})


def test_paginate_with_page_size_more_than_INCIDENT_API_LIMIT():
    """This test ensures that the function correctly handles the case where the provided page size exceeds the API limit,
    raising a DemistoException with the appropriate error message.
    Given:
        a test scenario where the `pagination_incidents` function is called with a page size greater than the API limit,
    When:
        the function is invoked with a page size of 200 and page number 2,
    Then:
        it should raise a DemistoException with the message "The max size for page is 100. Please provide a smaller page size."
    """
    from PagerDuty import pagination_incidents
    with pytest.raises(DemistoException, match="The max size for page is 100. Please provide a lower page size."):
        pagination_incidents({"user_ids": "test_id"}, {"page_size": 200, "page": 2}, "")


@pytest.mark.parametrize('add_content', [True, False])
def test_main_handles_httperror(requests_mock, mocker, add_content):
    """
        Given: params that causes http error.
        When: sending an HTTP request.
        Then: print the correct error message.
    """
    mocker.patch.object(demisto, 'params', return_value={'APIKey': 'test', 'ServiceKey': 'test', 'FetchInterval': '1'})

    from PagerDuty import main, SERVER_URL, ON_CALLS_USERS_SUFFIX

    class Response:
        def __init__(self, add_content):
            if add_content:
                self.content = 'Https error test'
    url = SERVER_URL + ON_CALLS_USERS_SUFFIX
    requests_mock.get(url, exc=requests.exceptions.HTTPError(response=Response(add_content)))

    mocker.patch.object(demisto, 'command', return_value='test-module')
    error_method = mocker.patch('PagerDuty.return_error')
    main()

    assert error_method.call_count == 1
    if add_content:
        assert error_method.call_args.args[0] == 'Error in API request Https error test'
    else:
        assert error_method.call_args.args[0] == 'Error in API request '
