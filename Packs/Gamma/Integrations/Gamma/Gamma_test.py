import json
import pytest
import demistomock as demisto
from Gamma import Client, fetch_incidents, Command, main

MOCK_URL = "mock://fake-api.net"

MOCK_VIOLATION = {
    "response": [
        {
            "app_name": "jira",
            "dashboard_url": f"{MOCK_URL}/violationId/2036",
            "file_labels_map": {},
            "text_labels": [],
            "user": {
                "active_directory_user_id": None,
                "atlassian_account_id": None,
                "email_address": None,
                "github_handle": None,
                "name": "Amane Suzuha",
                "slack_user_id": None,
            },
            "violation_category": "mock_category",
            "violation_event_timestamp": 1605805555,
            "violation_id": 2036,
            "violation_status": "OPEN",
        }
    ]
}

MOCK_VIOLATION_2 = {
    "response": [
        {
            "app_name": "jira",
            "dashboard_url": f"{MOCK_URL}/violationId/5100",
            "file_labels_map": {},
            "text_labels": [],
            "user": {
                "active_directory_user_id": None,
                "atlassian_account_id": None,
                "email_address": None,
                "github_handle": None,
                "name": "Rintaro Okabe",
                "slack_user_id": None,
            },
            "violation_category": "mock_category",
            "violation_event_timestamp": 1605804455,
            "violation_id": 5100,
            "violation_status": "OPEN",
        }
    ]
}

MOCK_VIOLATION_2_UPDATED = {
    "response": [
        {
            "app_name": "jira",
            "dashboard_url": f"{MOCK_URL}/violationId/5100",
            "file_labels_map": {},
            "text_labels": [],
            "user": {
                "active_directory_user_id": None,
                "atlassian_account_id": None,
                "email_address": None,
                "github_handle": None,
                "name": "Rintaro Okabe",
                "slack_user_id": None,
            },
            "violation_category": "mock_category",
            "violation_event_timestamp": 1605804455,
            "violation_id": 5100,
            "violation_status": "RESOLVED",
        }
    ]
}

MOCK_ALL_VIOLATIONS = {"response": [MOCK_VIOLATION["response"][0], MOCK_VIOLATION_2["response"][0]]}


def mock_demisto(mocker, args_value=None, command_value=None):
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "params", return_value={"api_key": "thisisatestkey", "url": MOCK_URL})
    if not args_value:
        args_value = {"entryID": "entry_id", "parseAll": "yes", "codec": "utf-8"}
    if command_value:
        mocker.patch.object(demisto, "command", return_value=command_value)
    mocker.patch.object(demisto, "args", return_value=args_value)


def mock_client(mocker, demisto):
    mocker.patch.object(demisto, "params", return_value={"api_key": "thisisatestkey", "url": MOCK_URL})

    client = Client(demisto)

    return client


@pytest.mark.parametrize(
    "last_run_violation,first_fetch_violation,max_results,output_1,output_2",
    [
        ({}, "1", "10", "Gamma Violation 2036", 5100),
        ({}, "1", "0", "Gamma Violation 2036", 5100),
        ({}, "1", "-1", "Gamma Violation 2036", 5100),
        ({}, "1", "200", "Gamma Violation 2036", 5100),
    ],
)
def test_fetch_incidents(last_run_violation, first_fetch_violation, max_results, output_1, output_2, requests_mock, mocker):
    requests_mock.get(MOCK_URL + "/api/discovery/v1/violation/list", json=MOCK_ALL_VIOLATIONS)

    # Test fetch
    next_run, incidents = fetch_incidents(mock_client(mocker, demisto), last_run_violation, first_fetch_violation, max_results)
    mocker.patch.object(demisto, "incidents", incidents)
    assert output_1 == demisto.incidents[0]["name"]
    assert output_2 == next_run["starting_violation"]


@pytest.mark.parametrize(
    "next_run,first_fetch_violation,max_results,output_1,output_2",
    [({"starting_violation": 2036}, "1", "10", 1, 5100), ({"starting_violation": 5100}, "1", "10", 0, 5100)],
)
def test_fetch_incidents_next_fetch(next_run, first_fetch_violation, max_results, output_1, output_2, requests_mock, mocker):
    requests_mock.get(MOCK_URL + "/api/discovery/v1/violation/list", json=MOCK_ALL_VIOLATIONS)

    next_run, incidents = fetch_incidents(mock_client(mocker, demisto), next_run, first_fetch_violation, max_results)

    assert output_1 == len(incidents)
    assert output_2 == next_run["starting_violation"]


@pytest.mark.parametrize(
    "last_run_violation,first_fetch_violation,max_results,output",
    [
        ({}, "0", "10", "first_fetch_violation must be equal to 1 or higher"),
        ({}, "-1", "10", "first_fetch_violation must be equal to 1 or higher"),
        ({}, "test", "10", "first_fetch_violation and max_limit must be integers"),
        ({}, "1", "test", "first_fetch_violation and max_limit must be integers"),
    ],
)
def test_fetch_incidents_bad_input(last_run_violation, first_fetch_violation, max_results, output, mocker):
    with pytest.raises(ValueError) as err:
        fetch_incidents(mock_client(mocker, demisto), last_run_violation, first_fetch_violation, max_results)
    assert output == str(err.value)


def test_get_violation_command(requests_mock, mocker, capfd):
    requests_mock.get(MOCK_URL + "/api/discovery/v1/violation/list", json=MOCK_VIOLATION)

    args = {"violation": "2036"}
    mock_demisto(mocker, args, "gamma-get-violation")
    with capfd.disabled():
        main()
    content = demisto.results.call_args[0][0]["Contents"][0]["violation_id"]
    assert 2036 == content


@pytest.mark.parametrize(
    "demisto_args,output",
    [
        ({"violation": "0"}, "Violation must be greater than 0"),
        ({"violation": "-1"}, "Violation must be greater than 0"),
        ({"violation": "test"}, "invalid literal for int() with base 10: 'test'"),
    ],
)
def test_get_violation_command_bad_input(demisto_args, output, mocker):
    client = mock_client(mocker, demisto)
    with pytest.raises(ValueError) as err:
        Command.get_violation(client, demisto_args)
    assert output == str(err.value)


@pytest.mark.parametrize(
    "demisto_args,output",
    [
        ({"minimum_violation": "2036", "limit": "2"}, 2036),
        ({"minimum_violation": "2035", "limit": "2"}, 2036),
    ],
)
def test_get_violation_list_command(demisto_args, output, requests_mock, mocker, capfd):
    requests_mock.get(MOCK_URL + "/api/discovery/v1/violation/list", json=MOCK_ALL_VIOLATIONS)

    mock_demisto(mocker, demisto_args, "gamma-get-violation-list")
    with capfd.disabled():
        main()
    content = demisto.results.call_args[0][0]["Contents"][0]["violation_id"]
    assert output == content


@pytest.mark.parametrize(
    "demisto_args,output",
    [
        ({"minimum_violation": "0", "limit": "2"}, "minimum_violation must be greater than 0"),
        ({"minimum_violation": "test", "limit": "2"}, "invalid literal for int() with base 10: 'test'"),
        ({"minimum_violation": "-1", "limit": "2"}, "minimum_violation must be greater than 0"),
        ({"minimum_violation": "2035", "limit": "0"}, "limit must be between 1 and 100"),
        ({"minimum_violation": "2035", "limit": "-1"}, "limit must be between 1 and 100"),
        ({"minimum_violation": "2035", "limit": "test"}, "invalid literal for int() with base 10: 'test'"),
    ],
)
def test_get_violation_list_command_bad_input(demisto_args, output, mocker):
    client = mock_client(mocker, demisto)
    with pytest.raises(ValueError) as err:
        Command.get_violation_list(client, demisto_args)
    assert output == str(err.value)


@pytest.mark.parametrize(
    "demisto_args,demisto_command,output",
    [
        (
            {"violation": "5100", "status": "resolved", "notes": "This has been updated!"},
            "gamma-update-violation",
            "RESOLVED",
        ),
    ],
)
def test_update_violation_command(demisto_args, demisto_command, output, requests_mock, mocker, capfd):
    test_violation = 5100
    requests_mock.put(MOCK_URL + f"/api/discovery/v1/violation/{test_violation}", json=MOCK_VIOLATION_2)
    requests_mock.get(MOCK_URL + "/api/discovery/v1/violation/list", json=MOCK_VIOLATION_2_UPDATED)

    mock_demisto(mocker, demisto_args, demisto_command)
    with capfd.disabled():
        main()
    contents = demisto.results.call_args[0][0]["Contents"][0]["violation_status"]
    assert output == contents


@pytest.mark.parametrize(
    "demisto_args,output",
    [
        ({"violation": "0", "status": "resolved", "notes": "This has been updated!"}, "Violation must be greater than 0"),
        ({"violation": "-1", "status": "resolved", "notes": "This has been updated!"}, "Violation must be greater than 0"),
        (
            {"violation": "test", "status": "resolved", "notes": "This has been updated!"},
            "invalid literal for int() with base 10: 'test'",
        ),
        (
            {"violation": "5100", "status": "closed", "notes": "This has been updated!"},
            "Status must be one of the following: OPEN, RESOLVED, IGNORED",
        ),
    ],
)
def test_update_violation_command_bad_input(demisto_args, output, mocker):
    client = mock_client(mocker, demisto)
    with pytest.raises(ValueError) as err:
        Command.update_violation(client, demisto_args)
    assert output == str(err.value)


@pytest.mark.parametrize(
    "demisto_args,demisto_command,output_1,output_2",
    [
        ({}, "fetch-incidents", "Gamma Violation 2036", "Gamma Violation 5100"),
        (
            {"first_fetch_violation": "2036", "max_results": "5"},
            "fetch-incidents",
            "Gamma Violation 2036",
            "Gamma Violation 5100",
        ),
    ],
)
def test_main_fetch_incidents(demisto_args, demisto_command, output_1, output_2, requests_mock, mocker, capfd):
    # Test fetch
    requests_mock.get(MOCK_URL + "/api/discovery/v1/violation/list", json=MOCK_ALL_VIOLATIONS)
    mock_demisto(mocker, demisto_args, demisto_command)
    with capfd.disabled():
        main()
    contents = json.loads(demisto.results.call_args[0][0]["Contents"])
    assert output_1 == contents[0]["name"]
    assert output_2 == contents[1]["name"]


def test_main_get_violation_list(requests_mock, mocker, capfd):
    # Test fetch
    requests_mock.get(MOCK_URL + "/api/discovery/v1/violation/list", json=MOCK_ALL_VIOLATIONS)
    args = {"minimum_id": "2036", "limit": "5"}
    command = "gamma-get-violation-list"
    mock_demisto(mocker, args, command)
    with capfd.disabled():
        main()
    response = demisto.results.call_args[0][0]["Contents"]
    assert {2036, 5100} == {i["violation_id"] for i in response}


def test_main_get_bad_violation(mocker, requests_mock, capfd):
    requests_mock.get(MOCK_URL + "/api/discovery/v1/violation/list", json=MOCK_VIOLATION)

    # Test wrong ID
    command = "gamma-get-violation"
    args = {"violation": "5100"}
    mock_demisto(mocker, args, command)
    with pytest.raises(SystemExit):
        with capfd.disabled():
            main()
    assert (
        demisto.results.call_args[0][0]["Contents"] == "Failed to execute gamma-get-violation "
        "command.\nError:\nViolation with this "
        "ID does not exist."
    )


def test_main_get_violation(requests_mock, mocker, capfd):
    # Test get violation
    requests_mock.get(MOCK_URL + "/api/discovery/v1/violation/list", json=MOCK_VIOLATION)
    args = {"violation": "2036"}
    command = "gamma-get-violation"
    mock_demisto(mocker, args, command)
    with capfd.disabled():
        main()
    assert 2036 == demisto.results.call_args[0][0]["Contents"][0]["violation_id"]


def test_main_update(requests_mock, mocker, capfd):
    # Test get violation
    test_violation = 2036
    requests_mock.put(MOCK_URL + f"/api/discovery/v1/violation/{test_violation}", json=MOCK_VIOLATION)
    requests_mock.get(MOCK_URL + "/api/discovery/v1/violation/list", json=MOCK_VIOLATION)
    args = {"violation": f"{test_violation}", "status": "RESOLVED", "notes": ""}
    command = "gamma-update-violation"
    mock_demisto(mocker, args, command)
    with capfd.disabled():
        main()

    assert test_violation == demisto.results.call_args[0][0]["Contents"][0]["violation_id"]


def test_bad_command(mocker, capfd):
    test_violation = 2036
    args = {"violation": f"{test_violation}", "status": "resolved", "notes": ""}
    command = "gamma-violation-update"
    mock_demisto(mocker, args, command)
    with pytest.raises(SystemExit):
        with capfd.disabled():
            main()
    assert (
        demisto.results.call_args[0][0]["Contents"] == "Failed to execute "
        "gamma-violation-update "
        "command.\nError:\nCommand "
        '"gamma-violation-update" is not '
        "implemented."
    )
