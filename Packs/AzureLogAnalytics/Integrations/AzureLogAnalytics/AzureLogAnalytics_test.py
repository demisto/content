import pytest
import json
from pathlib import Path
from pytest_mock import MockerFixture
from requests_mock import MockerCore
from CommonServerPython import CommandResults, ScheduledCommand
from AzureLogAnalytics import (
    Client,
    execute_query_command,
    list_saved_searches_command,
    tags_arg_to_request_format,
    get_saved_search_by_id_command,
    create_or_update_saved_search_command,
    delete_saved_search_command,
    run_search_job_command,
    get_search_job_command,
    delete_search_job_command
)


def util_load_json(path: str) -> dict:
    return json.loads(Path(path).read_text())


MOCKED_SAVED_SEARCHES_OUTPUT = {
    "value": [
        {
            "id": "mocked_id/mocked_saved_search",
            "etag": "mocked_etag",
            "properties": {
                "displayName": "mocked saved search",
                "query": "mocked_query",
            },
        },
        {"id": "MORE_DUMMY_DATA"},
    ]
}
MOCKED_SAVED_SEARCH_OUTPUT = {
    "id": "test",
    "etag": "Mock",
    "properties": {
        "category": "test",
        "displayName": "new display name test",
        "query": "mock",
        "version": 2,
        "id": "test1234",
        "etag": "*",
        "type": None,
    },
}
MOCKED_EXECUTE_QUERY_OUTPUT = {
    "tables": [
        {
            "name": "Table 1",
            "columns": [
                {"name": "column1", "type": "string"},
                {"name": "column2", "type": "long"},
            ],
            "rows": [["test", 1], ["test", 2]],
        },
        {
            "name": "Table 2",
            "columns": [
                {"name": "column3", "type": "string"},
                {"name": "column4", "type": "int"},
            ],
            "rows": [["test", 3], ["test", 4]],
        },
    ]
}


CLIENT = Client(
    self_deployed=True,
    refresh_token="refresh_token",
    auth_and_token_url="auth_id",
    redirect_uri="redirect_uri",
    enc_key="enc_key",
    auth_code="auth_code",
    subscription_id="subscriptionID",
    resource_group_name="resourceGroupName",
    workspace_name="workspaceName",
    verify=False,
    proxy=False,
    certificate_thumbprint=None,
    private_key=None,
    client_credentials=False,
)


def test_execute_query_command(mocker: MockerFixture) -> None:
    """
    Given:
        - A LogAnalytics client object
    When:
        - Calling function execute_query_command
    Then:
        - Ensure the readable output's title is correct
        - Ensure the output's structure is as expected
    """

    args: dict = {"query": "dummy"}
    mocker.patch.object(
        CLIENT, "http_request", return_value=MOCKED_EXECUTE_QUERY_OUTPUT
    )

    command_result = execute_query_command(CLIENT, args=args)

    assert "Query Results" in command_result.readable_output
    assert len(command_result.outputs) == 2
    assert command_result.outputs[0]["TableName"] == "Table 1"
    assert command_result.outputs[1]["Data"][1]["column4"] == 4


def test_list_saved_searches_command(mocker: MockerFixture) -> None:
    """
    Given:
        - A LogAnalytics client object
        - Arguments of azure-log-analytics-list-saved-searches command, representing we want
          a single saved search from the first page of the list to be retrieved
    When:
        - Calling function list_saved_searches_command
    Then:
        - Ensure the readable output's title is correct
        - Ensure a single saved search is returned
        - Ensure the output's structure is as expected
    """
    args = {"limit": "1", "page": "0"}
    mocker.patch.object(
        CLIENT, "http_request", return_value=MOCKED_SAVED_SEARCHES_OUTPUT
    )

    command_result = list_saved_searches_command(CLIENT, args=args)

    assert "Saved searches" in command_result.readable_output
    assert len(command_result.outputs) == 1
    assert command_result.outputs[0]["id"] == "mocked_saved_search"
    assert command_result.outputs[0]["query"] == "mocked_query"
    assert command_result.outputs[0]["displayName"] == "mocked saved search"


def test_get_saved_search_by_id_command(mocker: MockerFixture) -> None:
    """
    Test function for get_saved_search_by_id_command.
    """
    mocker.patch.object(CLIENT, "http_request", return_value=MOCKED_SAVED_SEARCH_OUTPUT)

    command_result = get_saved_search_by_id_command(CLIENT, {"saved_search_id": "test"})
    assert command_result.outputs["id"] == "test"
    assert command_result.readable_output == (
        "### Saved search `test` properties\n"
        "|Etag|Id|Category|Display Name|Query|Version|\n"
        "|---|---|---|---|---|---|\n"
        "| Mock | test | test | new display name test | mock | 2 |\n"
    )


def test_create_or_update_saved_search_command(mocker: MockerFixture) -> None:
    args = {
        "saved_search_id": "test_saved_search_id",
        "display_name": "test_display_name",
        "category": "test_category",
        "query": "test_query",
    }
    mocker.patch.object(CLIENT, "http_request", return_value=MOCKED_SAVED_SEARCH_OUTPUT)
    result = create_or_update_saved_search_command(CLIENT, args)

    assert result.readable_output == (
        "### Saved search `test_saved_search_id` properties\n"
        "|Etag|Id|Category|Display Name|Query|Version|\n"
        "|---|---|---|---|---|---|\n"
        "| Mock | test | test | new display name test | mock | 2 |\n"
    )
    assert result.outputs["id"] == "test"


def test_delete_saved_search_command(mocker: MockerFixture) -> None:
    mocker.patch.object(CLIENT, "http_request", return_value=None)

    result = delete_saved_search_command(CLIENT, {"saved_search_id": "SAVED_SEARCH_ID"})

    assert result == "Successfully deleted the saved search SAVED_SEARCH_ID."


def test_tags_arg_to_request_format() -> None:
    """
    Given:
        - `tags` argument from azure-log-analytics-execute-query command
        - The argument has two tags (a name and a value for each tag)
    When:
        - Calling function tags_arg_to_request_format
    Then:
        - Ensure the argument is parsed correctly to a dict with two tags.
    """
    tags_arg = "name1=value1;name2=value2"
    parsed_tags = tags_arg_to_request_format(tags_arg)

    assert len(parsed_tags) == 2
    assert parsed_tags[0]["name"] == "name1"
    assert parsed_tags[1]["value"] == "value2"


@pytest.mark.parametrize("client_id", [("test_client_id"), (None)])
def test_test_module_command_with_managed_identities(
    mocker: MockerFixture, requests_mock: MockerCore, client_id: str | None
) -> None:
    """
    Scenario: run test module when managed identities client id provided.
    Given:
     - User has provided managed identities client oid.
    When:
     - test-module called.
    Then:
     - Ensure the output are as expected
    """
    from AzureLogAnalytics import main, MANAGED_IDENTITIES_TOKEN_URL
    import AzureLogAnalytics
    import demistomock as demisto

    mock_token = {"access_token": "test_token", "expires_in": "86400"}
    requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    params = {
        "managed_identities_client_id": {"password": client_id},
        "use_managed_identities": "True",
        "auth_type": "Azure Managed Identities",
        "subscription_id": {"password": "test"},
        "resource_group": "test_resource_group",
        "credentials_refresh_token": {"password": "test"},
        "subscriptionID": "subscriptionID",
        "resourceGroupName": "resourceGroupName",
        "workspaceName": "workspaceName",
        "client_credentials": True
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(AzureLogAnalytics, "return_results")
    mocker.patch.object(AzureLogAnalytics, "execute_query_command")

    main()

    assert "ok" in AzureLogAnalytics.return_results.call_args[0][0]


def test_generate_login_url(mocker: MockerFixture) -> None:
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function azure-log-analytics-generate-login-url
    Then:
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from AzureLogAnalytics import main
    import AzureLogAnalytics

    redirect_uri = "redirect_uri"
    tenant_id = "tenant_id"
    client_id = "client_id"
    mocked_params = {
        "redirect_uri": redirect_uri,
        "self_deployed": "True",
        "refresh_token": tenant_id,
        "credentials": {"identifier": client_id, "password": "client_secret"},
        "subscriptionID": "subscriptionID",
        "resourceGroupName": "resourceGroupName",
        "workspaceName": "workspaceName"
    }
    mocker.patch.object(demisto, "params", return_value=mocked_params)
    mocker.patch.object(
        demisto, "command", return_value="azure-log-analytics-generate-login-url"
    )
    mocker.patch.object(AzureLogAnalytics, "return_results")

    # call
    main()

    # assert
    expected_url = (
        f"[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?"
        "response_type=code&scope=offline_access%20https://api.loganalytics.io/Data.Read"
        "%20https://management.azure.com/user_impersonation"
        f"&client_id={client_id}&redirect_uri={redirect_uri})"
    )
    res = AzureLogAnalytics.return_results.call_args[0][0].readable_output
    assert expected_url in res


def test_run_search_job_command(mocker: MockerFixture) -> None:
    """
    Given:
    -----
        a mocked CLIENT and input arguments for a search job,
    When:
    ----
        the run_search_job_command function is called for the first run and the second run,
    Then:
    ----
        it should perform the required actions for each run and return the expected readable output.

    This test covers the run_search_job_command function, which is responsible for running search jobs.
    It tests two scenarios: the first run and the second run. The first run sends a 'PUT' request to
    create the search job, and the second run checks the job status with a 'GET' request and prepares
    arguments for the next run. It ensures that the function behaves as expected in both cases.
    """
    args = {"table_name": "test_SRCH", "query": "test", "limit": 50, "first_run": True}

    mocker.patch.object(
        ScheduledCommand,
        "raise_error_if_not_supported",
        return_value=None,
    )
    """ First run"""
    mocker.patch.object(CLIENT, "http_request", return_value=None)  # first_run, 'PUT'
    response: CommandResults = run_search_job_command(args, CLIENT)
    assert response.readable_output == (
        "The command was sent successfully. "
        "You can check the status of the command by running !azure-log-analytics-get-search-job command or wait."
    )

    """Secund run"""
    # 'GET' get status
    mocker.patch.object(
        CLIENT,
        "http_request",
        return_value={"properties": {"provisioningState": "Succeeded"}},
    )
    args_to_next_run = response.scheduled_command._args
    assert args_to_next_run == {
        "table_name": "test_SRCH",
        "query": "test",
        "limit": 50,
        "first_run": False,
        "hide_polling_output": True
    }
    response: CommandResults = run_search_job_command(args_to_next_run, CLIENT)
    assert response.readable_output == (
        f"The {args['table_name']} table created successfully."
        f" In order to get the table, run !azure-log-analytics-execute-query query={args['table_name']}"
    )


@pytest.mark.parametrize(
    "index",
    [
        pytest.param("case schema", id="searchResults key under schema key"),
        pytest.param("case properties", id="searchResults key under properties key")
    ]
)
def test_get_search_job_command(mocker: MockerFixture, index: str) -> None:
    """ The searchResults key could be under schema or properties key, this test checks both cases
    Given:
    ----
        a mocked CLIENT, a specific test data index, and an existing search job with the table name "test",
    When:
    ----
        the get_search_job_command function is called with the CLIENT and the search job parameters,
    Then:
    ----
        it should retrieve the search job information and return a readable output with the expected table.
    """
    mock_data = util_load_json("test_data/get_search_job.json")
    mocker.patch.object(CLIENT, "http_request", return_value=mock_data[index])
    response = get_search_job_command(CLIENT, {"table_name": "test"})
    assert response.readable_output == (
        "### Search Job\n"
        "|Create Date|Description|Name|Plan|Query|endSearchTime|provisioningState|startSearchTime|\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| 2023-10-26T21:49:25.6588002Z | This table was created using a Search Job with the following query: 'testLogs'. |"
        " test | Analytics | testLogs | 2023-10-25T00:00:00Z | Succeeded | 2023-10-23T00:00:00Z |\n"
    )


def test_delete_search_job_command(mocker: MockerFixture) -> None:
    """
    Given:
    -----
        a mocked CLIENT and a search job with the table name "test_SRCH" exists,
    When:
    ----
        the delete_search_job_command function is called with the CLIENT and the search job parameters,
    Then:
    ----
        it should delete the search job and return a readable output confirming the deletion.
    """
    mocker.patch.object(CLIENT, "http_request", return_value=None)
    response = delete_search_job_command(CLIENT, {"table_name": "test_SRCH"})
    assert response.readable_output == "Search job test_SRCH deleted successfully."
