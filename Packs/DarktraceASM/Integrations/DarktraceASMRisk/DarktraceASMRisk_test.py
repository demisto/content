import json
import pytest
from DarktraceASMRisk import (Client,
                              TagError,
                              CommentError,
                              MitigationError,
                              fetch_incidents,
                              get_asm_risk_command,
                              get_asm_asset_command,
                              mitigate_asm_risk_command,
                              post_asm_comment_command,
                              edit_asm_comment_command,
                              delete_asm_comment_command,
                              create_asm_tag_command,
                              assign_asm_tag_command,
                              unassign_asm_tag_command)

"""*****CONSTANTS****"""

command_dict = {"get_asm_risk": {"command": get_asm_risk_command,
                                 "args": {"risk_id": "Umlza1R5cGU6MTE5Nzc="},
                                 },
                "get_asm_asset": {"command": get_asm_asset_command,
                                  "args": {"asset_id": "QXBwbGljYXRpb25UeXBlOjI2NjI4"},
                                  },
                "mitigate_asm_risk": {"command": mitigate_asm_risk_command,
                                      "args": {"risk_id": "Umlza1R5cGU6MTE5Nzc="}
                                      },
                "post_asm_comment": {"command": post_asm_comment_command,
                                     "args": {"id": "Umlza1R5cGU6MTE5Nzc=",
                                              "comment": "API Test Comment"}
                                     },
                "edit_asm_comment": {"command": edit_asm_comment_command,
                                     "args": {"comment_id": "Q29tbWVudFR5cGU6OTg=",
                                              "comment": "API Test Comment Edited"}
                                     },
                "delete_asm_comment": {"command": delete_asm_comment_command,
                                       "args": {"comment_id": "Q29tbWVudFR5cGU6OTg="}
                                       },
                "create_asm_tag": {"command": create_asm_tag_command,
                                   "args": {"tag_name": "API TEST"}
                                   },
                "assign_asm_tag": {"command": assign_asm_tag_command,
                                   "args": {"asset_id": "QXBwbGljYXRpb25UeXBlOjI2NjI4",
                                            "tag_name": "API TEST"}
                                   },
                "unassign_asm_tag": {"command": unassign_asm_tag_command,
                                     "args": {"asset_id": "QXBwbGljYXRpb25UeXBlOjI2NjI4",
                                              "tag_name": "API TEST"}
                                     },
                }

"""*****HELPER FUNCTIONS****"""


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def func_template(requests_mock, command):
    """
    Tests a given Darktrace ASM command function for functions that return CommandResults types.
    Mainly for GET requests.

    Configures requests_mock instance to generate the appropriate
    API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    # GIVEN an integration is configured to Darktrace
    mock_api_response = util_load_json(f'test_data/{command}.json')
    requests_mock.post('https://mock.darktrace.com/graph/v1.0/api', json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        headers={"Authorization": "Token example_token"}
    )

    args = command_dict[command]['args']

    integration_response = command_dict[command]["command"](client, args)
    expected_response = util_load_json(f'test_data/formatted_{command}.json')

    prefix = command.split('_')[-1]

    # THEN the response should be returned and formatted
    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == f'Darktrace.{prefix}'


def func_template_post(requests_mock, command):
    """
    Tests a given Darktrace ASM command function for functions that return string types.
    Mainly for POST requests.

    Configures requests_mock instance to generate the appropriate
    API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    # GIVEN an integration is configured to Darktrace
    mock_api_response = util_load_json(f'test_data/{command}.json')
    requests_mock.post('https://mock.darktrace.com/graph/v1.0/api', json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        headers={"Authorization": "Token example_token"}
    )

    args = command_dict[command]['args']

    integration_response = command_dict[command]["command"](client, args)
    expected_response = util_load_json(f'test_data/formatted_{command}.json').get("readable_output")

    # THEN the response should be returned and formatted
    assert integration_response == expected_response


def func_template_error(requests_mock, command):
    """
    Tests a given Darktrace ASM command function to ensure it raises the correct errors.

    Configures requests_mock instance to generate the appropriate
    API response, loaded from a local JSON file. Verifies it raises the expected error.
    """

    # GIVEN an integration is configured to Darktrace
    mock_api_response = util_load_json(f'test_data/{command}_error.json')
    requests_mock.post('https://mock.darktrace.com/graph/v1.0/api', json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        headers={"Authorization": "Token example_token"}
    )

    args = command_dict[command]['args']

    if 'tag' in command:
        with pytest.raises(TagError):
            command_dict[command]["command"](client, args)
    elif 'comment' in command:
        with pytest.raises(CommentError):
            command_dict[command]["command"](client, args)
    elif 'mitigate' in command:
        with pytest.raises(MitigationError):
            command_dict[command]["command"](client, args)


"""*****TEST FUNCTIONS****"""


def test_fetch_incidents(requests_mock):
    """
    Given
            Integration pulls in incidents from ASM
    When
            Regular interval defined by user, default is one minute
    Then
            Incident info will be formatted for XSOAR UI and required info for next call will be returned
    """
    mock_api_response = util_load_json('test_data/fetch_incidents.json')
    requests_mock.post('https://mock.darktrace.com/graph/v1.0/api', json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        headers={"Authorization": "Token example_token"}
    )

    integration_response = fetch_incidents(client, last_run={}, first_fetch_time=0, max_alerts=50, min_severity=1, alert_types=[
                                           'gdpr', 'informational', 'misconfiguration', 'reported', 'ssl', 'vulnerable software'])
    expected_response = util_load_json('test_data/formatted_fetch_incidents.json')

    assert integration_response[0]['last_fetch'] == expected_response['last_fetch']
    assert integration_response[1] == expected_response['incidents']


def test_get_asm_risk(requests_mock):
    """
    Given
            You want to pull a risk from ASM
    When
            Calling the darktrace-asm-get-risk command with a specified risk id
    Then
            The context will be updated with information pertaining to that risk id
    """
    func_template(requests_mock, 'get_asm_risk')


def test_get_asm_asset(requests_mock):
    """
    Given
            You want to get an asset's information
    When
            Calling the darktrace-asm-get-asset command with a specified asset id
    Then
            The context will be updated with information pertaining to that asset id
    """
    func_template(requests_mock, 'get_asm_asset')


def test_mitigate_risk(requests_mock):
    """
    Given
            You want to mitigate a risk on Darktrace PREVENT /ASM
    When
            Calling the darktrace-asm-mitigate-risk command with a specified risk id
    Then
            The context will be updated to indicate a success or failure
    """
    func_template_post(requests_mock, 'mitigate_asm_risk')


def test_post_comment(requests_mock):
    """
    Given
            You want to post a comment on a risk or asset on Darktrace PREVENT /ASM
    When
            Calling the darktrace-asm-post-comment command with a specified risk id
    Then
            The context will be updated to indicate a success or failure
    """
    func_template_post(requests_mock, 'post_asm_comment')


def test_edit_comment(requests_mock):
    """
    Given
            You want to edit a comment on a risk or asset on Darktrace PREVENT /ASM
    When
            Calling the darktrace-asm-edit-comment command with a specified risk id (or asset id)
    Then
            The context will be updated to indicate a success or failure
    """
    func_template_post(requests_mock, 'edit_asm_comment')


def test_delete_comment(requests_mock):
    """
    Given
            You want to delete a comment on a risk or asset on Darktrace PREVENT /ASM
    When
            Calling the darktrace-asm-delete-comment command with a specified risk id (or asset id)
    Then
            The context will be updated to indicate a success or failure
    """
    func_template_post(requests_mock, 'delete_asm_comment')


def test_create_tag(requests_mock):
    """
    Given
            You want to create a tag on Darktrace PREVENT /ASM
    When
            Calling the darktrace-asm-create-tag command with a specified tag name
    Then
            The context will be updated to indicate a success or failure
    """
    func_template_post(requests_mock, 'create_asm_tag')


def test_assign_tag(requests_mock):
    """
    Given
            You want to assign a tag to an asset on Darktrace PREVENT /ASM
    When
            Calling the darktrace-asm-assign-tag command with a specified tag name and asset id
    Then
            The context will be updated to indicate a success or failure
    """
    func_template_post(requests_mock, 'assign_asm_tag')


def test_unassign_tag(requests_mock):
    """
    Given
            You want to unassign a tag to an asset on Darktrace PREVENT /ASM
    When
            Calling the darktrace-asm-unassign-tag command with a specified tag name and asset id
    Then
            The context will be updated to indicate a success or failure
    """
    func_template_post(requests_mock, 'unassign_asm_tag')


def test_assign_tag_error(requests_mock):
    """
    Given
            An error when assigning a Tag
    When
            Calling the darktrace-asm-assign-tag command with a specified tag name and asset id
    Then
            The proper error will be raised
    """
    func_template_error(requests_mock, 'assign_asm_tag')


def test_unassign_tag_error(requests_mock):
    """
    Given
            An error when unassigning a Tag
    When
            Calling the darktrace-asm-unassign-tag command with a specified tag name and asset id
    Then
            The proper error will be raised
    """
    func_template_error(requests_mock, 'unassign_asm_tag')


def test_create_tag_error(requests_mock):
    """
    Given
            An error when creating a Tag
    When
            Calling the darktrace-asm-create-tag command with a specified tag name
    Then
            The proper error will be raised
    """
    func_template_error(requests_mock, 'create_asm_tag')


def test_post_comment_error(requests_mock):
    """
    Given
            An error when posting a comment
    When
            Calling the darktrace-asm-post-comment command with a specified risk id
    Then
            The proper error will be raised
    """
    func_template_error(requests_mock, 'post_asm_comment')


def test_edit_comment_error(requests_mock):
    """
    Given
            An error when editing a comment
    When
            Calling the darktrace-asm-edit-comment command with a specified comment id and new comment text
    Then
            The proper error will be raised
    """
    func_template_error(requests_mock, 'edit_asm_comment')


def test_delete_comment_error(requests_mock):
    """
    Given
            An error when deleting a comment
    When
            Calling the darktrace-asm-delete-comment command with a specified comment id
    Then
            The proper error will be raised
    """
    func_template_error(requests_mock, 'delete_asm_comment')


def test_mitigate_risk_error(requests_mock):
    """
    Given
            An error when mitigating a risk
    When
            Calling the darktrace-asm-mitigate-risk command with a specified risk id
    Then
            The proper error will be raised
    """
    func_template_error(requests_mock, 'mitigate_asm_risk')
