import json
import pytest
import demistomock as demisto
from Gamma import Client, fetch_incidents, get_violation_list_command, get_violation_command, update_violation_command, main

MOCK_URL = "http://fake-api.net"

MOCK_VIOLATION = {
    "response": [
        {
            "app_name": "jira",
            "dashboard_url": "https://app.gamma.ai/dashboard/jira/monitor/violationId/2036",
            "file_labels_map": {},
            "text_labels": [],
            "user": {
                "active_directory_user_id": None,
                "atlassian_account_id": None,
                "email_address": None,
                "github_handle": None,
                "name": "Amane Suzuha",
                "slack_user_id": None
            },
            "violation_category": "mock_category",
            "violation_event_timestamp": 1605805555,
            "violation_id": 2036,
            "violation_status": "OPEN"
        }
    ]
}

MOCK_VIOLATION_2 = {
    "response": [
        {
            "app_name": "jira",
            "dashboard_url": "https://app.gamma.ai/dashboard/jira/monitor/violationId/5100",
            "file_labels_map": {},
            "text_labels": [],
            "user": {
                "active_directory_user_id": None,
                "atlassian_account_id": None,
                "email_address": None,
                "github_handle": None,
                "name": "Rintaro Okabe",
                "slack_user_id": None
            },
            "violation_category": "mock_category",
            "violation_event_timestamp": 1605804455,
            "violation_id": 5100,
            "violation_status": "OPEN"
        }
    ]
}

MOCK_VIOLATION_2_UPDATED = {
    "response": [
        {
            "app_name": "jira",
            "dashboard_url": "https://app.gamma.ai/dashboard/jira/monitor/violationId/5100",
            "file_labels_map": {},
            "text_labels": [],
            "user": {
                "active_directory_user_id": None,
                "atlassian_account_id": None,
                "email_address": None,
                "github_handle": None,
                "name": "Rintaro Okabe",
                "slack_user_id": None
            },
            "violation_category": "mock_category",
            "violation_event_timestamp": 1605804455,
            "violation_id": 5100,
            "violation_status": "RESOLVED"
        }
    ]
}

MOCK_ALL_VIOLATIONS = {
    'response': [
        MOCK_VIOLATION['response'][0],
        MOCK_VIOLATION_2['response'][0]
        ]
    }


def test_fetch_incidents(requests_mock):
    requests_mock.get(MOCK_URL+"/violation/list", json=MOCK_ALL_VIOLATIONS)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers={},
        proxy=False
    )

    last_run_violation = {}
    first_fetch_violation = "1"
    max_results = "10"

    # Test fetch
    next_run, incidents = fetch_incidents(client, last_run_violation, first_fetch_violation, max_results)
    assert next_run['starting_violation'] == 5100
    assert len(incidents) == 2

    # Test input validation
    first_fetch_violation = "0"
    with pytest.raises(ValueError):
        fetch_incidents(client, last_run_violation, first_fetch_violation, max_results)

    first_fetch_violation = "-1"
    with pytest.raises(ValueError):
        fetch_incidents(client, last_run_violation, first_fetch_violation, max_results)

    first_fetch_violation = "test"
    with pytest.raises(ValueError):
        fetch_incidents(client, last_run_violation, first_fetch_violation, max_results)

    first_fetch_violation = "1"
    max_results = "0"
    next_run, incidents = fetch_incidents(client, last_run_violation, first_fetch_violation, max_results)
    assert next_run['starting_violation'] == 5100
    assert len(incidents) == 2

    max_results = "-1"
    next_run, incidents = fetch_incidents(client, last_run_violation, first_fetch_violation, max_results)
    assert next_run['starting_violation'] == 5100
    assert len(incidents) == 2

    max_results = "test"
    with pytest.raises(ValueError):
        fetch_incidents(client, last_run_violation, first_fetch_violation, max_results)

    max_results = "200"
    next_run, incidents = fetch_incidents(client, last_run_violation, first_fetch_violation, max_results)
    assert next_run['starting_violation'] == 5100
    assert len(incidents) == 2

    # Test next fetch
    max_results = "10"
    next_run['starting_violation'] = 2036
    next_run, incidents = fetch_incidents(client, next_run, first_fetch_violation, max_results)
    assert next_run['starting_violation'] == 5100
    assert len(incidents) == 1
    assert json.loads(incidents[0]['rawJSON'])['violation_id'] == 5100

    next_run, incidents = fetch_incidents(client, next_run, first_fetch_violation, max_results)
    assert next_run['starting_violation'] == 5100
    assert len(incidents) == 0


def test_get_violation_command(requests_mock):
    requests_mock.get(MOCK_URL+"/violation/list", json=MOCK_VIOLATION)

    client = Client(
            base_url=MOCK_URL,
            verify=False,
            headers={},
            proxy=False
    )

    # Test correct get
    args = {"violation": "2036"}
    output = get_violation_command(client, args)
    assert output.raw_response['response'][0]['violation_id'] == 2036

    # Test wrong ID
    args = {"violation": "5100"}
    output = get_violation_command(client, args)
    assert output == "Violation with this ID does not exist."

    # Test input validation
    args = {"violation": "0"}
    with pytest.raises(ValueError):
        get_violation_command(client, args)

    args = {"violation": "-1"}
    with pytest.raises(ValueError):
        get_violation_command(client, args)

    args = {"violation": "test"}
    with pytest.raises(ValueError):
        get_violation_command(client, args)


def test_get_violation_list_command(requests_mock):
    requests_mock.get(MOCK_URL + "/violation/list", json=MOCK_ALL_VIOLATIONS)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers={},
        proxy=False
    )

    args = {"minimum_violation": "2036", "limit": "2"}
    output = get_violation_list_command(client, args)
    assert len(output.raw_response['response']) == 2

    # Test input validation for minimum_violation
    args = {"minimum_violation": "0", "limit": "2"}
    with pytest.raises(ValueError):
        get_violation_list_command(client, args)

    args = {"minimum_violation": "test", "limit": "2"}
    with pytest.raises(ValueError):
        get_violation_list_command(client, args)

    args = {"minimum_violation": "-1", "limit": "2"}
    with pytest.raises(ValueError):
        get_violation_list_command(client, args)

    # Test input validation for limit
    args = {"minimum_violation": "2035", "limit": "0"}
    with pytest.raises(ValueError):
        get_violation_list_command(client, args)

    args = {"minimum_violation": "2035", "limit": "-1"}
    with pytest.raises(ValueError):
        get_violation_list_command(client, args)

    args = {"minimum_violation": "2035", "limit": "test"}
    with pytest.raises(ValueError):
        get_violation_list_command(client, args)

    # Test wrong ID
    args = {"minimum_violation": "2035", "limit": "2"}
    output = get_violation_list_command(client, args)
    assert output.readable_output.startswith("Violation with the minimum_violation ID does not exist. Showing violations pulled from the next available ID")


def test_update_violation_command(requests_mock):
    test_violation = 5100
    requests_mock.put(MOCK_URL + f'/violation/{test_violation}', json=MOCK_VIOLATION_2)
    requests_mock.get(MOCK_URL + "/violation/list", json=MOCK_VIOLATION_2_UPDATED)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers={},
        proxy=False
    )

    # Test update
    args = {"violation": str(test_violation), "status": "resolved", "notes": "This has been updated!"}
    output = update_violation_command(client, args)
    assert output.raw_response['response'][0]['violation_status'] == 'RESOLVED'

    # Test input validation
    args = {"violation": "0", "status": "resolved", "notes": "This has been updated!"}
    with pytest.raises(ValueError):
        update_violation_command(client, args)

    args = {"violation": "-1", "status": "resolved", "notes": "This has been updated!"}
    with pytest.raises(ValueError):
        update_violation_command(client, args)

    args = {"violation": "test", "status": "resolved", "notes": "This has been updated!"}
    with pytest.raises(ValueError):
        update_violation_command(client, args)

    # Test wrong status
    args = {"violation": str(test_violation), "status": "closed", "notes": "This has been updated!"}
    with pytest.raises(ValueError):
        update_violation_command(client, args)


def test_main_get_list_and_fetch(requests_mock, mocker, capsys):
    mocker.patch.object(demisto, 'params', return_value={'api_key': 'thisisatestkey', 'url': MOCK_URL})

    # Test fetch
    requests_mock.get(MOCK_URL+"/api/discovery/v1/violation/list", json=MOCK_ALL_VIOLATIONS)
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    main()
    captured = capsys.readouterr()
    assert 'Gamma Violation 2036' in captured.out
    assert 'Gamma Violation 5100' in captured.out

    mocker.patch.object(demisto, 'args', return_value={'first_fetch_violation': "2036", 'max_results': "5"})
    main()
    captured = capsys.readouterr()
    assert 'Gamma Violation 2036' in captured.out
    assert 'Gamma Violation 5100' in captured.out

    # Test get violation list
    mocker.patch.object(demisto, 'command', return_value='gamma-get-violation-list')
    mocker.patch.object(demisto, 'args', return_value={'minimum_id': "2036", 'limit': "5"})
    main()
    captured = capsys.readouterr()
    assert '"violation_id": 5100' in captured.out
    assert '"violation_id": 2036' in captured.out


def test_main_get_single(requests_mock, mocker, capsys):
    mocker.patch.object(demisto, 'params', return_value={'api_key': 'thisisatestkey', 'url': MOCK_URL})

    # Test get violation
    requests_mock.get(MOCK_URL+"/api/discovery/v1/violation/list", json=MOCK_VIOLATION)
    mocker.patch.object(demisto, 'command', return_value='gamma-get-violation')
    mocker.patch.object(demisto, 'args', return_value={'violation': "2036"})
    main()
    captured = capsys.readouterr()
    assert '"violation_id": 2036' in captured.out


def test_main_update(requests_mock, mocker, capsys):
    mocker.patch.object(demisto, 'params', return_value={'api_key': 'thisisatestkey', 'url': MOCK_URL})
    test_violation = 2036

    # Test get violation
    requests_mock.put(MOCK_URL + f"/api/discovery/v1/violation/{test_violation}", json=MOCK_VIOLATION)
    requests_mock.get(MOCK_URL + "/api/discovery/v1/violation/list", json=MOCK_VIOLATION)
    mocker.patch.object(demisto, 'command', return_value='gamma-update-violation')
    mocker.patch.object(demisto, 'args', return_value={'violation': f"{test_violation}", 'status': 'resolved', 'notes': ''})
    main()
    captured = capsys.readouterr()
    assert '"violation_id": 2036' in captured.out


def test_main_fail(mocker, capsys):
    # Fail api
    mocker.patch.object(demisto, 'params', return_value={'url': MOCK_URL})
    with pytest.raises(KeyError):
        main()

    # Fail command
    mocker.patch.object(demisto, 'params', return_value={'api_key': 'thisisatestkey', 'url': MOCK_URL})
    mocker.patch.object(demisto, 'command', return_value='gamma-get-violation')
    with pytest.raises(BaseException):
        main()
