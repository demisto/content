import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from AWSSystemManager import (
    add_tags_to_resource_command,
    cancel_automation_execution_command,
    cancel_command_command,
    convert_datetime_to_iso,
    format_document_version,
    format_parameters_arguments,
    get_association_command,
    get_automation_execution_command,
    get_command_status,
    get_document_command,
    list_associations_command,
    list_automation_executions_command,
    list_commands_command,
    list_documents_command,
    list_inventory_command,
    list_inventory_entry_command,
    list_tags_for_resource_command,
    list_versions_association_command,
    next_token_command_result,
    remove_tags_from_resource_command,
    run_automation_execution_command,
    run_command_command,
    update_if_value,
    validate_args,
)
from pytest_mock import MockerFixture

from CommonServerPython import CommandResults, DemistoException, ScheduledCommand


class MockClient:
    def __init__(self) -> None:
        pass

    def add_tags_to_resource(self, **kwargs) -> dict:
        pass

    def remove_tags_from_resource(self, **kwargs) -> dict:
        pass

    def get_inventory(self, **kwargs) -> dict:
        pass

    def list_inventory_entries(self, **kwargs) -> dict:
        pass

    def list_associations(self, **kwargs) -> dict:
        pass

    def describe_association(self, **kwargs) -> dict:
        pass

    def list_association_versions(self, **kwargs) -> dict:
        pass

    def list_documents(self, **kwargs) -> dict:
        pass

    def describe_document(self, **kwargs) -> dict:
        pass

    def get_automation_execution(self, **kwargs) -> dict:
        pass

    def describe_automation_executions(self, **kwargs) -> dict:
        pass

    def start_automation_execution(self, **kwargs) -> dict:
        pass

    def list_commands(self, **kwargs) -> dict:
        pass

    def stop_automation_execution(self, **kwargs) -> dict:
        pass

    def send_command(self, **kwargs) -> dict:
        pass

    def cancel_command(self, **kwargs) -> dict:
        pass

    def list_tags_for_resource(self, **kwargs) -> dict:
        pass


def util_load_json(path: str) -> dict:
    return json.loads(Path(path).read_text())


""" Tests For The Helper Functions """


@pytest.mark.parametrize(
    ("args", "kwargs", "input_to_output_keys", "expected_results"),
    [
        pytest.param(
            {"a": 1},
            {},
            {"a": "A"},
            {"A": 1},
            id="add args to empty  kwargs",
        ),
        pytest.param(
            {},
            {"b": 2},
            {},
            {"b": 2},
            id="keep kwargs the same, when no args",
        ),
        pytest.param(
            {"a": 1},
            {"b": 2},
            {"a": "A"},
            {"A": 1, "b": 2},
            id="add args to kwargs that already have values",
        ),
        pytest.param({}, {}, {}, {}, id="empty args and kwargs"),
    ],
)
def test_update_if_value(
    args: dict[str, str],
    kwargs: dict[str, str],
    input_to_output_keys: dict[str, str],
    expected_results: dict[str, str],
):
    """Given:
        - args - Input arguments
        - kwargs - Input keyword arguments
        - input_to_output_keys - Mapping of input to output keys
        - expected_results - Expected output after calling the function.

    When:
        - Calling update_if_value(args, kwargs, input_to_output_keys)

    Then:
        - The output should match expected_results
    """
    assert update_if_value(args, kwargs, input_to_output_keys) == expected_results


@pytest.mark.parametrize(
    ("value", "excepted_value"),
    [
        pytest.param(
            {"key1": "value1"},
            {"key1": ["value1"]},
            id="case playbook with one value",
        ),
        pytest.param(
            {"key1": "value1,value2"},
            {"key1": ["value1", "value2"]},
            id="case playbook with two values",
        ),
        pytest.param(
            {"key1": "value1,value2", "key2": "value1, value2"},
            {"key1": ["value1", "value2"], "key2": ["value1", "value2"]},
            id="case playbook with two keys",
        ),
        pytest.param(
            '"key1": ["value1"]',
            {"key1": ["value1"]},
            id="case war-room with one value",
        ),
        pytest.param(
            '{"key1": ["value1", "value2"]}',
            {"key1": ["value1", "value2"]},
            id="case war-room with one value and with brackets",
        ),
    ],
)
def test_format_parameters_arguments(
    value: str,
    excepted_value: dict[str, Any],
) -> None:
    """Given
        value (str): The input string to format.
        excepted_value (dict): The expected formatted output.
    When
        `format_parameters_arguments` is called with the parameters,
    Then
       The test cases cover:
        - Single key:value pair
        - Multiple values for a key
        - Multiple keys
        - Input from playbook vs warroom.
    """
    assert format_parameters_arguments(value) == excepted_value


@pytest.mark.parametrize(
    ("document_version", "expected_response"),
    [
        pytest.param("test_version", "test_version", id="Custom version"),
        pytest.param("default", "$DEFAULT", id="Default version"),
        pytest.param("latest", "$LATEST", id="Latest version"),
    ],
)
def test_format_document_version(document_version: str, expected_response: str) -> None:
    """Given
        a document version,
    When
        `format_document_version` is called with the document version,
    Then
        it should return the expected formatted response.
    """
    assert format_document_version(document_version) == expected_response


@pytest.mark.parametrize(
    ("args", "expected_error_message"),
    [
        pytest.param(
            {"instance_id": "test_id"},
            "Invalid instance id: test_id",
            id="Invalid instance id",
        ),
        pytest.param(
            {"association_id": "test_id"},
            "Invalid association id: test_id",
            id="Invalid association id",
        ),
        pytest.param(
            {"association_version": "test_version"},
            "Invalid association version: test_version",
            id="Invalid association version",
        ),
    ],
)
def test_validate_args(args: dict[str, str], expected_error_message: str) -> None:
    """Given
        specific arguments and their expected error messages,
    When
        the `validate_args` function is called with the arguments,
    Then
        it should raise a DemistoException with the expected error message.
    """
    with pytest.raises(DemistoException, match=expected_error_message):
        validate_args(args)


@pytest.mark.parametrize(
    ("next_token", "prefix"),
    [
        ("test_token", "test_prefix"),
    ],
)
def test_next_token_command_result(next_token: str, prefix: str) -> None:
    """Given:
        next_token (str): The next token value to be tested.
        prefix (str): The prefix to be used in the command result.

    When:
        - The next_token_command_result function is called with "test_token" as the next_token
          parameter and "test_prefix" as the prefix parameter.

    Then:
        The response's 'outputs' attribute (to_context()) is expected to be equal to the provided next_token value.
    """
    response = next_token_command_result(next_token, prefix)
    to_context = response.to_context()
    assert to_context["EntryContext"] == {
        f"AWS.SSM.{prefix}(val.NextToken)": {"NextToken": next_token},
    }


@pytest.mark.parametrize(
    ("data", "expected_response"),
    [
        pytest.param(
            {"Associations": [{"LastExecutionDate": "test"}]},
            {"Associations": [{"LastExecutionDate": "test"}]},
            id="dict with string value",
        ),
        pytest.param(
            {
                "Associations": [
                    {"LastExecutionDate": datetime(2023, 7, 25, 18, 51, 28, 607000)},
                ],
            },
            {"Associations": [{"LastExecutionDate": "2023-07-25T18:51:28.607000"}]},
            id="dict with key that contain datetime object",
        ),
        pytest.param(
            {
                "AssociationDescription": {
                    "LastExecutionDate": datetime(2023, 7, 25, 18, 51, 28, 607000),
                    "Date": datetime(2023, 7, 25, 18, 51, 28, 607000),
                },
            },
            {
                "AssociationDescription": {
                    "LastExecutionDate": "2023-07-25T18:51:28.607000",
                    "Date": "2023-07-25T18:51:28.607000",
                },
            },
            id="dict with multiply keys with datetime object",
        ),
    ],
)
def test_convert_datetime_to_iso(
    data: dict[str, Any],
    expected_response: dict[str, Any],
) -> None:
    """Given:
        data (dict): The input dictionary containing  datetime object.
        expected_response (dict): The expected output dictionary with datetime object formatted as strings.

    When:
        - The convert_datetime_to_iso function is called with the provided 'data' dictionary.

    Then:
        - The response from the function is expected to be equal to the 'expected_response'/
        (modify only the keys that contain datetime object.)
    """
    assert convert_datetime_to_iso(data) == expected_response


def test_convert_datetime_to_iso_raise_type_error() -> None:
    with pytest.raises(TypeError, match="Type <class 'function'> is not serializable."):
        convert_datetime_to_iso(
            {
                "Associations": [
                    {"LastExecutionDate": lambda x: ...},
                ],
            }
        )


def test_get_command_status(mocker: MockerFixture) -> None:
    """Given:
        a mocker with a patched `get_command_invocation` method that returns a command status of "Success",
    When:
        the `get_command_status` function is called with a test command_id and a MockClient,
    Then:
        it should return the expected command status, which is "Success".
    """
    mocker.patch.object(
        MockClient,
        "list_commands",
        return_value={"Commands": [{"Status": "Success"}]},
    )
    assert get_command_status("test_id", MockClient()) == "Success"


""" Test For The Command Functions """


def test_add_tags_to_resource_command(mocker: MockerFixture) -> None:
    """Given:
        mocker (MockerFixture): A mocker fixture for mocking external dependencies.

    When:
        - The add_tags_to_resource_command function is called with the provided arguments:
          - 'resource_type': "test_type"
          - 'resource_id': "test_id"
          - 'tag_key': "test_key"
          - 'tag_value': "test_value"

    Then:
        - The 'add_tags_to_resource' method of 'MockClient' is patched to return a
          successful response metadata with HTTP status code 200.
        - The 'readable_output' attribute of 'res' is expected to be
          "Tags added to resource test_id successfully."
    """
    args = {
        "resource_type": "Association",
        "resource_id": "test_id",
        "tag_key": "test_key",
        "tag_value": "test_value",
    }
    mocker.patch.object(
        MockClient,
        "add_tags_to_resource",
        return_value={"ResponseMetadata": {"HTTPStatusCode": 200}},
    )
    response = add_tags_to_resource_command(args, MockClient())
    assert response.readable_output == "Tags successfully added to resource test_id."


def test_list_tags_success(mocker: MockerFixture):
    """Given:
        - list_tags_for_resource_command function
        - Valid args including resource type and ID
        - Mock SSM client returns list of tags.

    When:
        - Calling list_tags_for_resource_command

    Then:
        - Ensure client called with expected args
        - CommandResults should contain outputs matching tags
        - Human readable output is formatted as expected
    """
    mocker.patch.object(
        MockClient,
        "list_tags_for_resource",
        return_value={
            "ResourceId": "i-1234abcd",
            "TagList": [
                {"Key": "Env", "Value": "Production"},
                {"Key": "Role", "Value": "WebServer"},
            ],
        },
    )

    args = {
        "resource_type": "Managed Instance",
        "resource_id": "i-1234abcd",
        "tag_key": "test",
        "tag_value": "test",
    }

    result = list_tags_for_resource_command(args, MockClient())

    MockClient.list_tags_for_resource.assert_called_with(
        ResourceType="ManagedInstance",
        ResourceId="i-1234abcd",
    )

    assert result.outputs == {
        "ResourceId": "i-1234abcd",
        "TagList": [
            {"Key": "Env", "Value": "Production"},
            {"Key": "Role", "Value": "WebServer"},
        ],
    }

    assert "Tags for i-1234abcd" in result.readable_output


def test_remove_tags_from_resource_command(mocker: MockerFixture) -> None:
    """Given:
        mocker (MockerFixture): A mocker fixture for mocking external dependencies.

    When:
        - The remove_tags_from_resource_command function is called with the provided arguments:
          - 'resource_type': "test_type"
          - 'resource_id': "test_id"
          - 'tag_key': "test_key"

    Then:
        - The 'add_tags_to_resource' method of 'MockClient' is patched to return a
          successful response metadata with HTTP status code 200.
        - The 'readable_output' attribute of 'res' is expected to be
          "Tag test_key removed from resource test_id successfully."
    """
    args = {
        "resource_type": "Association",
        "resource_id": "resource_id",
        "tag_key": "test_key",
    }
    mocker.patch.object(
        MockClient,
        "remove_tags_from_resource",
        return_value={"ResponseMetadata": {"HTTPStatusCode": 200}},
    )
    res = remove_tags_from_resource_command(args, MockClient())
    assert (
        res.readable_output
        == f"Tag {args['tag_key']} removed from resource {args['resource_id']} successfully."
    )


def test_list_inventory_command(mocker: MockerFixture) -> None:
    """Given:
    ----
        mocker (MockerFixture): A mocker fixture for mocking external dependencies.

    When:
    ----
        - The list_inventory_command function is called with the provided MockClient and
          an empty dictionary as arguments.

    Then:
    ----
        - The `get_inventory` method of `MockClient` is patched to return a mock inventory response.
        - The `outputs` attribute is expected to match the 'Entities'
          value from the mock response.
        - The `readable_output` attribute is expected to have a formatted
          table representation of the mock response's 'Entities'.

    Note:
    ----
        - The response is a list of CommandResults, where the first one is the get_inventory response.
        - The next response, which is the NextToken response,
            is tested in the `test_get_inventory_command_with_next_token_response` function.
    """
    mock_response: dict = util_load_json("test_data/get_inventory_response.json")
    mocker.patch.object(MockClient, "get_inventory", return_value=mock_response)
    res = list_inventory_command({"include_inactive_instance": False}, MockClient())

    assert res[0].outputs == mock_response["Entities"]
    assert res[0].readable_output == (
        "### AWS SSM Inventory\n"
        "|Agent version|Computer Name|IP address|Id|Instance Id|Platform Name|Platform Type|Resource Type|\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| agent_version | computer_name | ip_address | i-test_2 | i-test_2 | Ubuntu | Linux | resource_type |\n"
        "|  |  |  | i-test_3 | i-test_3 |  |  |  |\n"
        "| agent_version | computer_name | ip_address | i-test_4 | i-test_4 | Ubuntu | Linux | resource_type |\n"
        "| agent_version | computer_name | ip_address | i-test_5 | i-test_5 | Amazon Linux | Linux | resource_type |\n"
    )


def test_list_inventory_command_with_next_token_response(mocker: MockerFixture) -> None:
    """Given:
        mocker (MockerFixture): A mocker fixture for mocking external dependencies.
        check `next_token_command_result` function for more details.

    When:
        - The list_inventory_command function is called with the provided MockClient and
          an empty dictionary as arguments.
        - The mock response from 'get_inventory' is modified to include a "NextToken".

    Then:
        - The 'get_inventory' method of 'MockClient' is patched to return a mock inventory response
          with a "NextToken".
        - The 'outputs' attribute is expected to be the "NextToken" value
          from the mock response.

    Note: the `test_get_inventory_command` function test checking when the response is not return a Next Token value.
            the res[1] contains the inventory response.
    """
    mock_response: dict = util_load_json("test_data/get_inventory_response.json")
    mock_response["NextToken"] = "test_token"
    mocker.patch.object(MockClient, "get_inventory", return_value=mock_response)
    response: list[CommandResults] = list_inventory_command(
        {"include_inactive_instance": False},
        MockClient(),
    )

    to_context = response[0].to_context()
    assert to_context["EntryContext"] == {
        "AWS.SSM.InventoryNextToken(val.NextToken)": {"NextToken": "test_token"},
    }


def test_list_inventory_entry_command(mocker: MockerFixture) -> None:
    """Given:
        mocker (MockerFixture): A mocker fixture for mocking external dependencies.

    When:
        - The list_inventory_entry_command function is called with the provided MockClient
          and arguments:
          - 'instance_id': "i-0a00aaa000000000a"
          - 'type_name': "test_type_name"

    Then:
        - assert the list_inventory_entry_request call with the provided arguments,
            (MaxResults provide as a default value in the yml).
        - The 'outputs' attribute is expected to match the mock
          inventory entry response.
        - The 'readable_output' attribute is expected to have a formatted
          table representation of the mock inventory entry response.

    Note:
    ----
        - The response is a list of CommandResults, where the first one is the list inventory entry response.
        - The next response, which is the NextToken response,
            is tested in the `test_get_inventory_command_with_next_token_response` function.
    """
    mock_response: dict = util_load_json("test_data/get_inventory_entry_command.json")
    mock_list_inventory_entry_request = mocker.patch.object(
        MockClient,
        "list_inventory_entries",
        return_value=mock_response,
    )

    args = {
        "instance_id": "i-0a00aaa000000000a",
        "type_name": "File",
    }
    response = list_inventory_entry_command(args, MockClient())

    mock_list_inventory_entry_request.assert_called_with(
        InstanceId=args["instance_id"],
        TypeName="AWS:File",
        MaxResults=50,
    )

    assert response[0].outputs == mock_response
    assert response[0].readable_output == (
        "### AWS SSM Inventory Entry\n"
        "|AgentType|AgentVersion|ComputerName|InstanceId|InstanceStatus|IpAddress|PlatformName|PlatformType|PlatformVersion|"
        "ResourceType|\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "| agent_type | agent_version | computer_name | instance_id | Stopped | ip_address | Ubuntu | Linux | 20.04 |"
        " resource_type |\n"
        "| agent_type | agent_version | computer_name | instance_id | Stopped | ip_address | Ubuntu | Linux | 20.04 |"
        " resource_type |\n"
    )


def test_list_associations_command(mocker: MockerFixture) -> None:
    """Given:
        mocker (MockerFixture): A mocker fixture for mocking external dependencies.

    When:
        - The list_associations_command function is called with the provided MockClient
          and an empty dictionary as arguments.

    Then:
        - The 'list_associations' method of 'MockClient' is patched to return a mock association response.
        - The 'outputs' attribute is expected to match the mock
          association response.
        - The 'readable_output' attribute is expected to have a formatted
          table representation of the mock association response.

    Note:
    ----
        - The response is a list of CommandResults, where the first one is the list associations response.
        - The next response, which is the NextToken response,
            is tested in the `test_get_inventory_command_with_next_token_response` function.
    """
    mock_response: dict = util_load_json("test_data/list_associations.json")
    mocker.patch.object(MockClient, "list_associations", return_value=mock_response)
    response = list_associations_command({}, MockClient())
    assert response[0].outputs == mock_response["Associations"]
    assert response[0].readable_output == (
        "### AWS SSM Associations\n"
        "|Association id|Association version|Document name|Last execution date|Resource status count|Status|\n"
        "|---|---|---|---|---|---|\n"
        "| AssociationId_test | 1 | AWS-GatherSoftwareInventory | 2023-07-25 18:51:28.607000+03:00 |  | Pending |\n"
        "| AssociationId_test | 1 | AWSQuickSetup-CreateAndAttachIAMToInstance | 2023-08-13 14:49:38+03:00 | Failed: 1 | Failed |"
        "\n"
        "| AssociationId_test | 1 | AWS-GatherSoftwareInventory | 2023-07-25 18:54:37.936000+03:00 |  | Pending |\n"
    )


def test_get_association_command(mocker: MockerFixture) -> None:
    """Given:
        mocker (MockerFixture): A mocker fixture for mocking external dependencies.

    When:
        - The get_association_command function is called with the provided MockClient
          and arguments:
          - 'instance_id': "i-0a00aaa000000000a"
          - 'document_name': "test_name"

    Then:
        - The 'describe_association' method of 'MockClient' is patched to return a mock association description response.
        - The 'outputs' attribute of the response is expected to match the mock association description response.
        - The 'readable_output' attribute of the response is expected to have a formatted table representation
          of the mock association description response.

    Note:
    ----
        - The response is a list of CommandResults, where the first one is the association description response.
        - The next response, which is the NextToken response,
            is tested in the `test_get_inventory_command_with_next_token_response` function.
    """
    mock_response: dict = util_load_json("test_data/association_description.json")
    mocker.patch.object(MockClient, "describe_association", return_value=mock_response)
    response = get_association_command(
        {"instance_id": "i-0a00aaa000000000a", "document_name": "test_name"},
        MockClient(),
    )

    assert response.outputs == mock_response["AssociationDescription"]
    assert response.readable_output == (
        "### AWS SSM Association\n"
        "|Association id|Association name|Association version|Create date|Document name|Document version|Last execution date|"
        "Resource status count|Schedule expression|Status|\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "| association_id | test | 1 | 2023-07-18T13:50:27.691000+03:00 | AWS | $DEFAULT "
        "| 2023-07-25T18:51:28.607000+03:00 |  | rate(30 minutes) | Pending |\n"
    )


def test_list_versions_association_command(mocker: MockerFixture) -> None:
    """Given:
        - mocker (MockerFixture): A mocker fixture for mocking external dependencies.

    When:
        - The list_versions_association_command function is called with the provided MockClient
          and arguments:
          - 'association_id': "12345678-0000-0000-0000-000000000000"

    Then:
        - The 'list_association_versions' method of 'MockClient' is patched to return a mock association versions response.
        - The 'outputs' attribute of the response is expected to match the mock association versions response.
        - The 'readable_output' attribute of the response is expected to have a formatted table representation
          of the mock association versions response.

    Note:
    ----
        - The response is a list of CommandResults, where the first one is the list versions association response.
        - The next response, which is the NextToken response,
            is tested in the `test_get_inventory_command_with_next_token_response` function.
    """
    mock_response: dict = util_load_json(
        "test_data/list_association_versions_response.json",
    )
    mocker.patch.object(
        MockClient,
        "list_association_versions",
        return_value=mock_response,
    )
    response = list_versions_association_command(
        {"association_id": "12345678-0000-0000-0000-000000000000"},
        MockClient(),
    )

    assert response[0].outputs == mock_response["AssociationVersions"]
    assert response[0].readable_output == (
        "### Association Versions\n"
        "|Association id|Create date|Document version|MaxConcurrency|MaxErrors|Name|Output location|Parameters|Schedule "
        "expression|Targets|Version|\n"
        "|---|---|---|---|---|---|---|---|---|---|---|\n"
        "| association_id | 2023-02-14T13:48:24.511000+02:00 |  |  |  | AWSQuickSetup |  | **AutomationAssumeRole**:<br>\t"
        "***values***: arn<br>**IsPolicyAttachAllowed**:<br>\t***values***: false | rate(30 days) | **-**\t"
        "***Key***: ParameterValues<br>\t**Values**:<br>\t\t***values***: instance_id | 1 |\n"
    )


def test_list_documents_command(mocker: MockerFixture) -> None:
    """Given:
        - mocker (MockerFixture): A mocker fixture for mocking external dependencies.

    When:
        - The list_documents_command function is called with the provided MockClient and empty arguments.

    Then:
        - The 'list_documents' method of 'MockClient' is patched to return a mock list documents response.
        - The 'outputs' attribute of the response is expected to match the mock list documents response.
        - The 'readable_output' attribute of the response is expected to have a formatted table representation
          of the mock list documents response.

    Note:
    ----
        - The response is a list of CommandResults, where the first one is the list documents response.
        - The next response, which is the NextToken response,
            is tested in the `test_get_inventory_command_with_next_token_response` function.
    """
    mock_response: dict = util_load_json("test_data/list_documents_response.json")
    mocker.patch.object(MockClient, "list_documents", return_value=mock_response)
    response = list_documents_command({}, MockClient())

    assert response[0].outputs == mock_response["DocumentIdentifiers"]
    assert response[0].readable_output == (
        "### AWS SSM Documents\n"
        "|Name|Owner|Document version|Document type|Platform types|Created date|\n"
        "|---|---|---|---|---|---|\n"
        "| AWS-AS | Amazon | 1 | Automation | Windows,<br>Linux,<br>MacOS | 2018-02-15T05:03:20.597000+02:00 |\n"
        "| AWS-A | Amazon | 1 | Automation | Windows,<br>Linux,<br>MacOS | 2018-02-15T05:03:23.277000+02:00 |\n"
    )


def test_get_documents_command(mocker: MockerFixture) -> None:
    mock_response: dict = util_load_json("test_data/get_document_response.json")
    mocker.patch.object(MockClient, "describe_document", return_value=mock_response)
    response = get_document_command({"document_name": "test_name"}, MockClient())

    assert response.outputs == mock_response["Document"]
    assert response.readable_output == (
        "### AWS SSM Document\n"
        "|Created date|Description|Display Name|Document version|Name|Owner|Platform types|Status|\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| 2022-10-11T01:06:56.878000+03:00 | Change the test |  |  | AWS | Amazon | Windows,<br>Linux,<br>MacOS | Active |\n"
    )


def test_get_automation_execution_command(mocker: MockerFixture) -> None:
    """Given:
        a mocker with a patched `get_automation_execution` method that returns a mock response,
    When:
        the `get_automation_execution_command` function is called with a test execution_id and a MockClient,
    Then:
        it should return the expected CommandResults object with the specified outputs and readable_output.
    """
    mock_response: dict = util_load_json("test_data/get_automation_execution.json")
    mocker.patch.object(
        MockClient,
        "get_automation_execution",
        return_value=mock_response,
    )
    response = get_automation_execution_command(
        {"execution_id": "test_id"},
        MockClient(),
    )

    assert response.outputs == mock_response["AutomationExecution"]
    assert response.readable_output == (
        "### AWS SSM Automation Execution\n"
        "|Automation Execution Id|Document Name|Document Version|Start Time|End Time|Automation Execution Status|Mode|"
        "Executed By|\n|---|---|---|---|---|---|---|---|\n"
        "| AutomationExecutionId | AWS | 1 | 2023-08-29T19:00:50.101000+03:00 | 2023-08-29T19:00:51.618000+03:00 | Success |"
        " Auto | arn |\n"
    )


def test_list_automation_executions_command(mocker: MockerFixture) -> None:
    """Given:
        a mocker with a patched `describe_automation_executions` method that returns a mock response,
    When:
        the `list_automation_executions_command` function is called with an empty argument and a MockClient,
    Then:
        it should return the expected CommandResults object with the specified outputs and readable_output.
    """
    mock_response: dict = util_load_json("test_data/list_automation_executions.json")
    mocker.patch.object(
        MockClient,
        "describe_automation_executions",
        return_value=mock_response,
    )
    response = list_automation_executions_command({}, MockClient())

    assert response[0].outputs == mock_response["AutomationExecutionMetadataList"]
    assert response[0].readable_output == (
        "### AWS SSM Automation Executions\n"
        "|Automation Execution Id|Document Name|Document Version|Start Time|End Time|Automation Execution Status|Mode|"
        "Executed By|\n|---|---|---|---|---|---|---|---|\n"
        "|  |  | 1 | 2023-08-30T19:00:50.433000+03:00 | 2023-08-30T19:00:51.963000+03:00 | Success | Auto | arn |\n"
        "|  | AWS | 1 | 2023-08-30T19:00:50.141000+03:00 | 2023-08-30T19:00:51.807000+03:00 | Success | Auto | arn |\n"
    )


def test_list_commands_command(mocker: MockerFixture) -> None:
    """Given:
        a mocker with a patched `list_commands` method that returns a mock response,
    When:
        the `list_commands_command` function is called with an empty argument and a MockClient,
    Then:
        it should return the expected CommandResults object with the specified outputs and readable_output.
    """
    mock_response: dict = util_load_json("test_data/list_commands_response.json")
    mocker.patch.object(MockClient, "list_commands", return_value=mock_response)
    response = list_commands_command({}, MockClient())

    assert response[0].outputs == mock_response["Commands"]
    assert response[0].readable_output == (
        "### AWS SSM Commands\n"
        "|Command Id|Status|Requested date|Document name|Comment|Target Count|Error Count|Delivery Timed Out Count|"
        "Completed Count|\n|---|---|---|---|---|---|---|---|---|\n"
        "| CommandId | Success | 2023-08-31T13:34:00.596000+03:00 | AWS | test | 1 | 0 | 0 | 1 |\n"
        "| CommandId | Success | 2023-08-31T12:06:45.879000+03:00 | AWS- |  | 0 | 0 | 0 | 0 |\n"
    )


@pytest.mark.parametrize(
    ("status", "expected_message"),
    [
        pytest.param(
            "Success",
            "The automation status is Success, The automation completed successfully.",
            id="success",
        ),
        pytest.param(
            "Failed",
            "The automation status is Failed, The automation didn't complete successfully. This is a terminal state.",
            id="failed",
        ),
        pytest.param(
            "Cancelled",
            "The automation status is Cancelled, The automation was stopped by a requester before it completed.",
            id="cancelled",
        ),
        pytest.param(
            "TimedOut",
            "The automation status is TimedOut, A step or approval wasn't completed before the specified timeout period.",
            id="timed_out",
        ),
    ],
)
def test_run_automation_execution_command(
    mocker: MockerFixture,
    status: str,
    expected_message: str,
) -> None:
    args = {
        "document_name": "AWS",
        "parameters": json.dumps({"InstanceId": ["i-1234567890abcdef0"]}),
        "polling": True,
    }
    mocker.patch.object(
        ScheduledCommand,
        "raise_error_if_not_supported",
        return_value=None,
    )
    mocker.patch.object(
        MockClient,
        "get_automation_execution",
        return_value={"AutomationExecution": {"AutomationExecutionStatus": status}},
    )
    mocker.patch.object(
        MockClient,
        "start_automation_execution",
        return_value={"AutomationExecutionId": "test_id", "ResponseMetadata": "test"},
    )

    result: CommandResults = run_automation_execution_command(args, MockClient())

    assert result.readable_output == "Execution test_id is in progress"

    args_to_next_run = result.scheduled_command._args
    assert args_to_next_run == {
        "document_name": "AWS",
        "parameters": '{"InstanceId": ["i-1234567890abcdef0"]}',
        "polling": True,
        "execution_id": "test_id",
        "hide_polling_output": True,
    }
    result = run_automation_execution_command(args_to_next_run, MockClient())
    assert result.readable_output == expected_message


@pytest.mark.parametrize(
    ("status", "expected_message"),
    [
        pytest.param(
            "Success",
            "The automation status is Success,"
            " The cancel command failed. The automation completed successfully before the cancellation.",
            id="status is Success",
        ),
        pytest.param(
            "Failed",
            "The automation status is Failed, The cancel command failed. The automation failed before it completed.",
            id="status is Failed",
        ),
        pytest.param(
            "Cancelled",
            "The automation status is Cancelled,"
            " The cancel command completed successfully, The automation was stopped by a requester before it completed.",
            id="status is Cancelled",
        ),
        pytest.param(
            "TimedOut",
            "The automation status is TimedOut,"
            " The cancel command failed. The automation failed on timeout before the cancellation.",
            id="status is TimedOut",
        ),
    ],
)
def test_cancel_automation_execution_command(
    mocker: MockerFixture,
    status: str,
    expected_message: str,
) -> None:
    """Given:
        a mocker with a patched `cancel_automation_execution` method that returns a mock response,
    When:
        the `cancel_automation_execution_command` function is called with a test execution_id and a MockClient,
    Then:
        it should return the expected CommandResults object with the specified outputs and readable_output.
    """
    args = {
        "automation_execution_id": "test_id",
        "first_run": True,
        "include_polling": True,
    }
    mocker.patch.object(
        ScheduledCommand,
        "raise_error_if_not_supported",
        return_value=None,
    )
    mocker.patch.object(MockClient, "stop_automation_execution")
    mocker.patch.object(
        MockClient,
        "get_automation_execution",
        return_value={"AutomationExecution": {"AutomationExecutionStatus": status}},
    )
    response: CommandResults = cancel_automation_execution_command(args, MockClient())

    assert response.readable_output == "Cancellation command was sent successfully."

    args_to_next_run = response.scheduled_command._args
    assert args_to_next_run == {
        "automation_execution_id": "test_id",
        "first_run": False,
        "include_polling": True,
        "hide_polling_output": True,
    }
    response: CommandResults = cancel_automation_execution_command(
        args_to_next_run,
        MockClient(),
    )
    assert response.readable_output == expected_message


@pytest.mark.parametrize(
    ("status", "expected_message"),
    [
        pytest.param(
            "Failed",
            "The command status is Failed, The command wasn't successfully on the managed node.",
            id="status is Failed",
        ),
        pytest.param(
            "Cancelled",
            "The command status is Cancelled, The command was canceled before it was completed.",
            id="status is Cancelled",
        ),
        pytest.param(
            "Delivery Timed Out",
            "The command status is Delivery Timed Out,"
            " The command wasn't delivered to the managed node before the total timeout expired.",
            id="status is Delivery Timed Out",
        ),
    ],
)
def test_run_command_command(
    mocker: MockerFixture,
    status: str,
    expected_message: str,
) -> None:
    args = {
        "document_name": "AWS",
        "target_key": "Instance Ids",
        "target_values": "i-1234567890abcdef0,i-1234567890abcdef1",
        "polling": True,
    }
    mock_response: dict = util_load_json("test_data/run_command_response.json")
    mocker.patch.object(
        ScheduledCommand,
        "raise_error_if_not_supported",
        return_value=None,
    )
    mocker.patch.object(MockClient, "send_command", return_value=mock_response)
    mocker.patch.object(
        MockClient,
        "list_commands",
        return_value={"Commands": [{"Status": status}]},
    )

    result: CommandResults = run_command_command(args, MockClient())

    assert result.readable_output == "Command command_id_test was sent successfully."
    assert result.outputs == mock_response["Command"]

    args_to_next_run = result.scheduled_command._args
    assert args_to_next_run == {
        "document_name": "AWS",
        "target_key": "Instance Ids",
        "target_values": "i-1234567890abcdef0,i-1234567890abcdef1",
        "polling": True,
        "command_id": "command_id_test",
        "hide_polling_output": True,
    }

    result = run_command_command(args_to_next_run, MockClient())
    assert result.readable_output == expected_message


@pytest.mark.parametrize(
    ("status", "expected_message"),
    [
        pytest.param(
            "Failed",
            "The command status is Failed, The cancel command failed. The command failed before it completed. polling stops.",
            id="status is Failed",
        ),
        pytest.param(
            "Cancelled",
            "The command status is Cancelled, The cancel command completed successfully, "
            "The command was cancelled before it was completed. polling stops.",
            id="status is Cancelled",
        ),
        pytest.param(
            "Delivery Timed Out",
            "The command status is Delivery Timed Out, "
            "The command wasn't delivered to the managed node before the total timeout expired. polling stops.",
            id="status is Delivery Timed Out",
        ),
    ],
)
def test_cancel_command_command(
    mocker: MockerFixture,
    status: str,
    expected_message: str,
) -> None:
    """Given:
        a mocker with a patched `cancel_automation_execution` method that returns a mock response,
    When:
        the `cancel_automation_execution_command` function is called with a test execution_id and a MockClient,
    Then:
        it should return the expected CommandResults object with the specified outputs and readable_output.
    """
    args = {
        "command_id": "test_id",
        "first_run": True,
        "include_polling": True,
    }
    mocker.patch.object(
        ScheduledCommand,
        "raise_error_if_not_supported",
        return_value=None,
    )
    mocker.patch.object(MockClient, "cancel_command")
    mocker.patch.object(
        MockClient,
        "list_commands",
        return_value={"Commands": [{"Status": status}]},
    )
    response: CommandResults = cancel_command_command(args, MockClient())

    assert response.readable_output == "Cancellation command was sent successfully."

    args_to_next_run = response.scheduled_command._args
    assert args_to_next_run == {
        "command_id": "test_id",
        "first_run": False,
        "include_polling": True,
        "hide_polling_output": True,
    }
    response: CommandResults = cancel_command_command(args_to_next_run, MockClient())
    assert response.readable_output == expected_message
