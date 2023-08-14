import json
# from mypy_boto3_ssm.client import SSMClient, Exceptions as AWSExceptions
import pytest
from pytest_mock import MockerFixture
from AWSSystemManager import (
    add_tags_to_resource_command,
    get_inventory_command,
    list_inventory_entry_command,
)
from CommonServerPython import DemistoException


class MockClient:
    def __init__(self):
        pass

    def add_tags_to_resource(self, **kwargs):
        pass

    def get_inventory(self, **kwargs):
        pass

    def list_inventory_entries(self, **kwargs):
        pass


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_add_tags_to_resource_command_success(mocker: MockerFixture) -> None:
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


@pytest.mark.parametrize(
    "args, mock_res_token, expected_len",
    [
        ({"limit": 1, "next_token": "test_token"}, {"NextToken": "test_token"}, 2),
        ({"limit": 1, "next_token": "test_token"}, {}, 1),
    ],
)
def test_get_inventory_command(
    mocker: MockerFixture, args: dict, mock_res_token: dict, expected_len: int
) -> None:
    mock_response: dict = util_load_json("test_data/get_inventory_response.json")
    mock_response.update(mock_res_token)
    mock_get_inventory = mocker.patch.object(
        MockClient, "get_inventory", return_value=mock_response
    )
    res = get_inventory_command(MockClient, args)

    readable_output = (
        "### AWS SSM Inventory\n"
        "|Id|Instance Id|Computer Name|Platform Type|Platform Name|Agent version|IP address|Resource Type|\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| i-test_1 |  |  |  |  |  |  |  |\n"
        "| i-test_2 | i-test_2 | computer_name | Linux | Ubuntu | agent_version | ip_address | resource_type |\n"
        "| i-test_3 | i-test_3 |  |  |  |  |  |  |\n"
        "| i-test_4 | i-test_4 | computer_name | Linux | Ubuntu | agent_version | ip_address | resource_type |\n"
        "| i-test_5 | i-test_5 | computer_name | Linux | Amazon Linux | agent_version | ip_address | resource_type |\n"
    )

    # if next_token is not provided, the first CommandResults in the result is the inventory
    inventory_index = 0 if len(res) == 1 else 1

    assert len(res) == expected_len
    assert res[inventory_index].outputs == mock_response.pop("Entities")
    assert res[inventory_index].readable_output == readable_output
    mock_get_inventory.assert_called_with(
        MaxResults=args["limit"], NextToken=args["next_token"]
    )

    if len(res) == 2:
        assert res[0].outputs == "test_token"
        assert (
            res[0].readable_output
            == f"For more results rerun the command with next_token='{mock_response.pop('NextToken')}'."
        )


@pytest.mark.parametrize(
    "args, mock_res_token, expected_len",
    [
        (
            {
                "instance_id": "i-0a00aaa000000000a",
                "type_name": "test_type_name",
                "next_token": "test_token",
            },
            {"NextToken": "test_token"},
            2,
        ),
        (
            {
                "instance_id": "i-0a00aaa000000000a",
                "type_name": "test_type_name",
                "next_token": "test_token",
            },
            {},
            1,
        ),
    ],
)
def test_list_inventory_entry_command(
    mocker: MockerFixture, args: dict, mock_res_token: dict, expected_len: int
) -> None:
    mock_response: dict = util_load_json(
        "test_data/get_inventory_entry_command.json"
    )
    mock_response.update(mock_res_token)
    mock_list_inventory_entry_request = mocker.patch.object(
        MockClient, "list_inventory_entries", return_value=mock_response
    )

    readable_output = (
        "### AWS SSM Inventory\n"
        "|Agent version|Computer Name|IP address|Instance Id|Platform Name|Platform Type|Resource Type|\n"
        "|---|---|---|---|---|---|---|\n"
        "| agent_version | computer_name | ip_address | instance_id | Ubuntu | Linux | resource_type |\n"
        "| agent_version | computer_name | ip_address | instance_id | Ubuntu | Linux | resource_type |\n"
    )
    response = list_inventory_entry_command(MockClient, args)
    entries_index = 0 if len(response) == 1 else 1

    # if next_token is not provided, the first CommandResults in the result is the entries
    assert (
        len(response) == expected_len
    )  # assert that the response contains list of CommandResults the inventory and the next_token if provided
    assert response[entries_index].outputs == mock_response
    assert response[entries_index].readable_output == readable_output
    mock_list_inventory_entry_request.assert_called_with(
        NextToken=args["next_token"],
        InstanceId=args["instance_id"],
        TypeName=args["type_name"],
        MaxResults=50,
    )
    if len(response) == 2:
        assert response[0].outputs == "test_token"
        assert (
            response[0].readable_output
            == f"For more results rerun the command with next_token='{mock_response.pop('NextToken')}'."
        )


def test_list_inventory_entry_command_raise_error():
    with pytest.raises(DemistoException, match="Invalid instance id: bla-0a00aaa000000000a"):
        list_inventory_entry_command(
            MockClient,
            {
                "instance_id": "bla-0a00aaa000000000a",
                "type_name": "test_type_name",
            },
        )
