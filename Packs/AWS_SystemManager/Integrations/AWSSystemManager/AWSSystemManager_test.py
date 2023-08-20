import json
import datetime
import pytest
from pytest_mock import MockerFixture
from AWSSystemManager import (
    add_tags_to_resource_command,
    get_inventory_command,
    list_inventory_entry_command,
    list_associations_command,
    convert_datetime_to_iso,
    next_token_command_result,
    validate_args,
    get_association_command,
    list_versions_association_command
)
from CommonServerPython import CommandResults, DemistoException


class MockClient:
    def __init__(self):
        pass

    def add_tags_to_resource(self, **kwargs):
        pass

    def get_inventory(self, **kwargs):
        pass

    def list_inventory_entries(self, **kwargs):
        pass

    def list_associations(self, **kwargs):
        pass

    def describe_association(self, **kwargs):
        pass

    def list_association_versions(self, **kwargs):
        pass


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


""" Tests For The Helper Functions """


@pytest.mark.parametrize(
    'args, expected_error_message',
    [
        ({'instance_id': 'test_id'}, 'Invalid instance id: test_id'),
        ({'document_name': '@_name'}, 'Invalid document name: @_name'),
        ({'association_id': 'test_id'}, 'Invalid association id: test_id'),
        ({'association_version': 'test_version'}, 'Invalid association version: test_version'),
    ]
)
def test_validate_args(args: dict[str, str], expected_error_message: str) -> None:
    with pytest.raises(DemistoException, match=expected_error_message):
        validate_args(args)


@pytest.mark.parametrize(
    'next_token, prefix',
    [
        ("test_token", "test_prefix")
    ]
)
def test_next_token_command_result(next_token: str, prefix: str) -> None:
    """
    Given:
        next_token (str): The next token value to be tested.
        prefix (str): The prefix to be used in the command result.

    When:
        - The next_token_command_result function is called with "test_token" as the next_token
          parameter and "test_prefix" as the prefix parameter.

    Then:
        - The response's 'outputs_prefix' attribute is expected to be equal to 'AWS.SSM.test_prefix'.
        - The response's 'outputs' attribute is expected to be equal to the provided next_token value.
        - The response's 'readable_output' attribute is expected to be formatted with the provided
          next_token value for rerunning the command.
    """
    response = next_token_command_result(next_token, prefix)
    assert response.outputs_prefix == f'AWS.SSM.{prefix}'
    assert response.outputs == next_token
    assert response.readable_output == f"For more results rerun the command with {next_token=}."


@pytest.mark.parametrize(
    "data, expected_response",
    [
        (
            {"Associations": [{"LastExecutionDate": "test"}]},
            {"Associations": [{"LastExecutionDate": "test"}]},
        ),
        (
            {"Associations": [{"LastExecutionDate": datetime.datetime(2023, 7, 25, 18, 51, 28, 607000)}]},
            {"Associations": [{"LastExecutionDate": "2023-07-25T18:51:28.607000"}]},
        ),
        (
            {
                "AssociationDescription":
                {
                    "LastExecutionDate": datetime.datetime(2023, 7, 25, 18, 51, 28, 607000),
                    'Date': datetime.datetime(2023, 7, 25, 18, 51, 28, 607000)
                }
            },
            {
                "AssociationDescription": {
                    "LastExecutionDate": "2023-07-25T18:51:28.607000", "Date": "2023-07-25T18:51:28.607000"
                }
            }
        )
    ]
)
def test_convert_datetime_to_iso(data: dict, expected_response: dict) -> None:
    """
    Given:
        data (dict): The input dictionary containing 'LastExecutionDate' values to be tested.
        expected_response (dict): The expected output dictionary with 'LastExecutionDate'
                                 values formatted as strings.

    When:
        - The convert_last_execution_date function is called with the provided 'data' dictionary.

    Then:
        - The response from the function is expected to be equal to the 'expected_response'
          dictionary, with 'LastExecutionDate' values formatted consistently.
    """
    response = convert_datetime_to_iso(data)
    assert response == expected_response


""" Test For The Command Functions """


def test_add_tags_to_resource_command(mocker: MockerFixture) -> None:
    """
    Given:
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
        "resource_type": "test_type",
        "resource_id": "test_id",
        "tag_key": "test_key",
        "tag_value": "test_value",
    }
    mocker.patch.object(
        MockClient,
        "add_tags_to_resource",
        return_value={"ResponseMetadata": {"HTTPStatusCode": 200}},
    )
    res = add_tags_to_resource_command(MockClient, args)
    assert res.readable_output == "Tags added to resource test_id successfully."


def test_get_inventory_command(mocker: MockerFixture) -> None:
    """
    Note: this test checking when the response is not return a Next Token value.
    the test_get_inventory_command_with_next_token_response function test checking the Next Token value.

    Args:
        mocker (MockerFixture): A mocker fixture for mocking external dependencies.

    When:
        - The get_inventory_command function is called with the provided MockClient and
          an empty dictionary as arguments.

    Then:
        - The 'get_inventory' method of 'MockClient' is patched to return a mock inventory response.
        - The 'outputs' attribute is expected to match the 'Entities'
          value from the mock response.
        - The 'readable_output' attribute is expected to have a formatted
          table representation of the mock response's 'Entities'.
    """
    mock_response: dict = util_load_json("test_data/get_inventory_response.json")
    mocker.patch.object(MockClient, "get_inventory", return_value=mock_response)
    res = get_inventory_command(MockClient, {})

    assert res[0].outputs == mock_response.pop("Entities")
    assert res[0].readable_output == (
        "### AWS SSM Inventory\n"
        "|Agent version|Computer Name|IP address|Id|Instance Id|Platform Name|Platform Type|Resource Type|\n"
        "|---|---|---|---|---|---|---|---|\n"
        "|  |  |  | i-test_1 |  |  |  |  |\n"
        "| agent_version | computer_name | ip_address | i-test_2 | i-test_2 | Ubuntu | Linux | resource_type |\n"
        "|  |  |  | i-test_3 | i-test_3 |  |  |  |\n"
        "| agent_version | computer_name | ip_address | i-test_4 | i-test_4 | Ubuntu | Linux | resource_type |\n"
        "| agent_version | computer_name | ip_address | i-test_5 | i-test_5 | Amazon Linux | Linux | resource_type |\n"
    )


def test_get_inventory_command_with_next_token_response(mocker: MockerFixture) -> None:
    """
    Note: the test_get_inventory_command function test checking when the response is not return a Next Token value.
    the res[1] contains the inventory response.

    Given:
        mocker (MockerFixture): A mocker fixture for mocking external dependencies.

    When:
        - The get_inventory_command function is called with the provided MockClient and
          an empty dictionary as arguments.
        - The mock response from 'get_inventory' is modified to include a "NextToken".

    Then:
        - The 'get_inventory' method of 'MockClient' is patched to return a mock inventory response
          with a "NextToken".
        - The 'outputs' attribute is expected to be the "NextToken" value
          from the mock response.
        - The 'readable_output' attribute is expected to contain a message
          indicating how to retrieve more results using the provided next_token.
    """
    mock_response: dict = util_load_json('test_data/get_inventory_response.json')
    mock_response["NextToken"] = "test_token"
    mocker.patch.object(MockClient, 'get_inventory', return_value=mock_response)
    res: list[CommandResults] = get_inventory_command(MockClient, {})
    assert res[0].outputs == "test_token"
    assert (
        res[0].readable_output
        == f"For more results rerun the command with next_token='{mock_response.pop('NextToken')}'."
    )


def test_list_inventory_entry_command(mocker: MockerFixture) -> None:
    """
    Given:
        mocker (MockerFixture): A mocker fixture for mocking external dependencies.

    When:
        - The list_inventory_entry_command function is called with the provided MockClient
          and arguments:
          - 'instance_id': "i-0a00aaa000000000a"
          - 'type_name': "test_type_name"

    Then:
        - assert the list_inventory_entry_request call with the provided arguments,
            (MaxResults provide as a default value in the yml).
        - The 'list_inventory_entries' method of 'MockClient' is patched to return a mock inventory
          entry response.
        - The 'outputs' attribute is expected to match the mock
          inventory entry response.
        - The 'readable_output' attribute is expected to have a formatted
          table representation of the mock inventory entry response.
    """
    mock_response: dict = util_load_json("test_data/get_inventory_entry_command.json")
    mock_list_inventory_entry_request = mocker.patch.object(MockClient, "list_inventory_entries", return_value=mock_response)

    args = {
        "instance_id": "i-0a00aaa000000000a",
        "type_name": "test_type_name",
    }
    response = list_inventory_entry_command(MockClient, args)

    mock_list_inventory_entry_request.assert_called_with(
        InstanceId=args["instance_id"],
        TypeName=args["type_name"],
        MaxResults=50,
    )
    assert response[0].outputs == mock_response
    assert response[0].readable_output == (
        "### AWS SSM Inventory\n"
        "|Agent version|Computer Name|IP address|Instance Id|Platform Name|Platform Type|Resource Type|\n"
        "|---|---|---|---|---|---|---|\n"
        "| agent_version | computer_name | ip_address | instance_id | Ubuntu | Linux | resource_type |\n"
        "| agent_version | computer_name | ip_address | instance_id | Ubuntu | Linux | resource_type |\n"
    )


def test_list_inventory_entry_command_raise_error() -> None:
    """
    When:
        - The list_inventory_entry_command function is called with the provided arguments:
          - 'instance_id': "bla-0a00aaa000000000a"
          - 'type_name': "test_type_name"
    the instance_id is not valid because is not match the regex of the instance id. {should begin with i-}

    Then:
        - The function call is expected to raise a DemistoException with a message that matches
          "Invalid instance id: bla-0a00aaa000000000a".
    """
    with pytest.raises(
        DemistoException, match="Invalid instance id: bla-0a00aaa000000000a"
    ):
        list_inventory_entry_command(
            MockClient,
            {
                "instance_id": "bla-0a00aaa000000000a",
                "type_name": "test_type_name",
            },
        )


def test_list_associations_command(mocker: MockerFixture) -> None:
    """
    Args:
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
    """
    mock_response: dict = util_load_json("test_data/list_associations.json")
    mocker.patch.object(MockClient, "list_associations", return_value=mock_response)
    response = list_associations_command(MockClient, {})
    assert response[0].outputs == mock_response
    assert response[0].readable_output == (
        '### AWS SSM Association\n'
        '|Association id|Association version|Document name|Last execution date|Resource status count|Status|\n'
        '|---|---|---|---|---|---|\n'
        '| AssociationId_test | 1 | AWS-GatherSoftwareInventory | 2023-07-25 18:51:28.607000+03:00 |  | Pending |\n'
        '| AssociationId_test | 1 | AWSQuickSetup-CreateAndAttachIAMToInstance | 2023-08-13 14:49:38+03:00 | Failed: 1 | Failed |'
        '\n'
        '| AssociationId_test | 1 | AWS-GatherSoftwareInventory | 2023-07-25 18:54:37.936000+03:00 |  | Pending |\n'
    )


def test_get_association_command(mocker: MockerFixture) -> None:
    mock_response: dict = util_load_json("test_data/association_description.json")
    mocker.patch.object(MockClient, "describe_association", return_value=mock_response)
    response = get_association_command(MockClient, {"instance_id": "i-0a00aaa000000000a", 'document_name': 'test_name'})
    mock_response.pop("ResponseMetadata")
    assert response.outputs == mock_response
    assert response.readable_output == (
        '### Association\n'
        '|Association id|Association name|Association version|Create date|Document name|Document version|Last execution date|'
        'Resource status count|Schedule expression|Status|\n'
        '|---|---|---|---|---|---|---|---|---|---|\n'
        '| association_id | Moishy | 1 | 2023-07-18T13:50:27.691000+03:00 | AWS | $DEFAULT '
        '| 2023-07-25T18:51:28.607000+03:00 |  | rate(30 minutes) | Pending |\n'
    )


def test_list_versions_association_command(mocker: MockerFixture) -> None:
    mock_response: dict = util_load_json("test_data/list_association_versions_response.json")
    mocker.patch.object(MockClient, "list_association_versions", return_value=mock_response)
    response = list_versions_association_command(MockClient, {"association_id": "12345678-0000-0000-0000-000000000000"})
    mock_response.pop("ResponseMetadata")
    assert response[0].outputs == mock_response
    assert response[0].readable_output == (
        "### Association Versions\n"
        "|Association id|Create date|Document version|MaxConcurrency|MaxErrors|Name|Output location|Parameters|Schedule "
        "expression|Targets|Version|\n"
        "|---|---|---|---|---|---|---|---|---|---|---|\n"
        "| association_id | 2023-02-14T13:48:24.511000+02:00 |  |  |  | AWSQuickSetup |  | **AutomationAssumeRole**:<br>\t"
        "***values***: arn<br>**IsPolicyAttachAllowed**:<br>\t***values***: false | rate(30 days) | **-**\t"
        "***Key***: ParameterValues<br>\t**Values**:<br>\t\t***values***: instance_id | 1 |\n"
    )
