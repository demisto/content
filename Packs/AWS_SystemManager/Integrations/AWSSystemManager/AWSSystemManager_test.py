import json
import datetime
# from boto3-
# from mypy_boto3_ssm.client import SSMClient, Exceptions as AWSExceptions
import pytest
from pytest_mock import MockerFixture
from AWSSystemManager import (
    add_tags_to_resource_command,
    get_inventory_command,
    list_inventory_entry_command,
    list_associations_command,
    convert_last_execution_date,
    next_token_command_result
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


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


""" Tests For The Helper Functions """


@pytest.mark.parametrize(
    'next_token, prefix',
    [
        ("test_token", "test_prefix")
    ]
)
def test_next_token_command_result(next_token: str, prefix: str):
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
        )
    ]
)
def test_convert_last_execution_date(data: dict, expected_response: dict):
    response = convert_last_execution_date(data)
    assert response == expected_response


""" Test For The Command Functions """


def test_add_tags_to_resource_command(mocker: MockerFixture) -> None:
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


def test_get_inventory_command_with_next_token_argument(mocker: MockerFixture):
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


def test_list_inventory_entry_command_raise_error():
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


def test_list_associations_command(mocker: MockerFixture):
    mock_response: dict = util_load_json("test_data/list_associations.json")
    mocker.patch.object(MockClient, "list_associations", return_value=mock_response)
    response = list_associations_command(MockClient, {})
    assert response[0].outputs == mock_response
