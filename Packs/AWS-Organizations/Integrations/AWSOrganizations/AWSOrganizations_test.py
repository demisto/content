import pytest
from test_data.data import *  # noqa
from CommonServerPython import *  # noqa

# from mypy_boto3_organizations import *


class MockOrganizationsClient:  # (OrganizationsClient):
    def get_paginator(self, _):
        pass

    def describe_account(self, **kwargs):
        assert account_get.client_func_kwargs == kwargs
        return account_get.client_func_return

    def describe_organizational_unit(self, **kwargs):
        assert organization_unit_get.client_func_kwargs == kwargs
        return organization_unit_get.client_func_return

    def describe_organization(self):
        return organization_get.client_func_return

    def remove_account_from_organization(self, **kwargs):
        assert account_remove.client_func_kwargs == kwargs

    def move_account(self, **kwargs):
        assert account_move.client_func_kwargs == kwargs

    def create_account(self, **kwargs):
        assert account_create_initial_call.client_func_kwargs == kwargs
        return account_create_initial_call.client_func_return

    def describe_create_account_status(self, **kwargs):
        assert account_create_final_call.client_func_kwargs == kwargs
        return account_create_final_call.client_func_return

    def close_account(self, **kwargs):
        assert account_close.client_func_kwargs == kwargs

    def create_organizational_unit(self, **kwargs):
        assert organization_unit_create.client_func_kwargs == kwargs
        return organization_unit_create.client_func_return

    def delete_organizational_unit(self, **kwargs):
        assert organization_unit_delete.client_func_kwargs == kwargs

    def update_organizational_unit(self, **kwargs):
        assert organization_unit_rename.client_func_kwargs == kwargs

    def describe_policy(self, **kwargs):
        assert policy_get.client_func_kwargs == kwargs
        return policy_get.client_func_return

    def delete_policy(self, **kwargs):
        assert policy_delete.client_func_kwargs == kwargs
        return policy_delete.client_func_return

    def attach_policy(self, **kwargs):
        assert policy_attach.client_func_kwargs == kwargs

    def tag_resource(self, **kwargs):
        assert resource_tag_add.client_func_kwargs == kwargs


def get_mock_paginate(kwargs: dict, return_obj):
    def mock_paginate(
        paginator,
        key_to_pages,
        limit=None,
        page_size=None,
        next_token=None,
        **paginator_kwargs
    ):
        assert kwargs == paginator_kwargs
        return return_obj

    return mock_paginate


@pytest.mark.parametrize(
    "paginate_kwargs, expected_kwargs, real_key_to_pages, expected_output, message",
    [
        (
            {
                "key_to_pages": "Accounts",
                "limit": 10,
                "page_size": -1,
                "next_token": "token",
            },
            {
                "PaginationConfig": {
                    "MaxItems": 10,
                    "PageSize": 10,
                    "StartingToken": None,
                }
            },
            "Accounts",
            ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], "next_token"),
            "Test case: ignore page_size and next_token and when a limit is provided.",
        ),
        (
            {"key_to_pages": "Accounts", "page_size": 10, "next_token": "token"},
            {
                "PaginationConfig": {
                    "MaxItems": 10,
                    "PageSize": 10,
                    "StartingToken": "token",
                }
            },
            "Accounts",
            ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], "next_token"),
            "Test case: use page_size and next_token correctly.",
        ),
        (
            {
                "key_to_pages": "Accounts",
                "page_size": 13,
                "next_token": "token",
                "another_arg": "value",
            },
            {
                "PaginationConfig": {
                    "MaxItems": 13,
                    "PageSize": 13,
                    "StartingToken": "token",
                },
                "another_arg": "value",
            },
            "Accounts",
            ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], "next_token"),
            "Test case: check that the args are passed toi the paginator correctly.",
        ),
    ],
)
def test_paginate(
    paginate_kwargs, expected_kwargs, real_key_to_pages, expected_output, message
):
    """
    Given:
        Pagination args following the XSOAR pagination protocol.

    When:
        Calling the paginate function.

    Then:
        Use the client paginator to fetch all the results and return them with the next token.
    """
    from AWSOrganizations import paginate

    def mock_paginate(**kwargs):
        assert kwargs == expected_kwargs, message
        return (
            {"NextToken": "next_token", real_key_to_pages: list(range(nums, nums + 5))}
            for nums in range(0, 1000, 5)
        )

    output = paginate(type("Mock", (), {"paginate": mock_paginate}), **paginate_kwargs)

    assert output == expected_output, message


def test_build_tags_error():
    """
    Given:
        An invalid "tags" argument that is not in the format ""key1=value1,key2=value2"".

    When:
        Attempting to add tags to an AWS Organizations resource.

    Then:
        Raise an error that explains the correct format.
    """
    from AWSOrganizations import build_tags

    with pytest.raises(DemistoException, match='Tags must be provided in the format "key=value".'):
        build_tags('invalid_tag,key=value')


def test_root_list_command(mocker):
    from AWSOrganizations import root_list_command

    mocker.patch(
        "AWSOrganizations.paginate",
        side_effect=get_mock_paginate(
            root_list.client_func_kwargs,
            root_list.client_func_return
        ),
    )

    result = root_list_command(root_list.command_args, MockOrganizationsClient())

    assert list(result.outputs.values()) == root_list.context_outputs
    assert result.readable_output == root_list.readable_output


def test_children_list_command(mocker):
    from AWSOrganizations import children_list_command

    mocker.patch(
        "AWSOrganizations.paginate",
        side_effect=get_mock_paginate(
            children_list.client_func_kwargs,
            children_list.client_func_return
        ),
    )

    result = children_list_command(
        children_list.command_args, MockOrganizationsClient()
    )

    assert list(result.outputs.values()) == children_list.context_outputs
    assert result.readable_output == children_list.readable_output


def test_parent_list_command(mocker):
    from AWSOrganizations import parent_list_command

    mocker.patch(
        "AWSOrganizations.paginate",
        side_effect=get_mock_paginate(
            parent_list.client_func_kwargs,
            parent_list.client_func_return
        ),
    )

    result = parent_list_command(parent_list.command_args, MockOrganizationsClient())

    assert result.outputs == parent_list.context_outputs
    assert result.readable_output == parent_list.readable_output


def test_organization_unit_get():
    from AWSOrganizations import organization_unit_get_command

    result = organization_unit_get_command(
        organization_unit_get.command_args, MockOrganizationsClient()
    )

    assert result.outputs == organization_unit_get.context_outputs
    assert result.readable_output == organization_unit_get.readable_output


def test_account_list_command(mocker):
    from AWSOrganizations import account_list_command

    mocker.patch(
        "AWSOrganizations.paginate",
        side_effect=get_mock_paginate(
            account_list.client_func_kwargs, account_list.client_func_return
        ),
    )

    result = account_list_command(account_list.command_args, MockOrganizationsClient())

    assert list(result.outputs.values()) == account_list.context_outputs
    assert result.readable_output == account_list.readable_output


def test_account_get():
    from AWSOrganizations import account_list_command

    result = account_list_command(account_get.command_args, MockOrganizationsClient())

    assert result.outputs == account_get.context_outputs
    assert result.readable_output == account_get.readable_output


def test_organization_get():
    from AWSOrganizations import organization_get_command

    result = organization_get_command(MockOrganizationsClient())

    assert result.outputs == organization_get.context_outputs
    assert result.readable_output == organization_get.readable_output


def test_account_remove():
    from AWSOrganizations import account_remove_command

    result = account_remove_command(
        account_remove.command_args, MockOrganizationsClient()
    )

    assert result.readable_output == account_remove.readable_output


def test_account_move():
    from AWSOrganizations import account_move_command

    result = account_move_command(account_move.command_args, MockOrganizationsClient())

    assert result.readable_output == account_move.readable_output


def test_account_create_initial_call(mocker):
    from AWSOrganizations import account_create_command
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    mocker.patch.object(ScheduledCommand, '__init__', return_value=None)

    account_create_command(
        account_create_initial_call.command_args,
        MockOrganizationsClient()
    )

    assert account_create_initial_call.command_args['request_id'] == 'id'


def test_account_create_final_call(mocker):
    from AWSOrganizations import account_create_command
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    mocker.patch.object(ScheduledCommand, '__init__', return_value=None)

    result = account_create_command(
        account_create_final_call.command_args,
        MockOrganizationsClient()
    )

    assert result.outputs == account_create_final_call.context_outputs
    assert result.readable_output == account_create_final_call.readable_output


def test_account_close(mocker):
    from AWSOrganizations import account_close_command
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    mocker.patch.object(ScheduledCommand, '__init__', return_value=None)

    result: CommandResults = account_close_command(account_close.command_args, MockOrganizationsClient())

    assert result.outputs == account_close.context_outputs
    assert result.readable_output == account_close.readable_output


def test_organization_unit_create():
    from AWSOrganizations import organization_unit_create_command

    result = organization_unit_create_command(
        organization_unit_create.command_args, MockOrganizationsClient()
    )

    assert result.outputs == organization_unit_create.context_outputs
    assert result.readable_output == organization_unit_create.readable_output


def test_organization_unit_delete():
    from AWSOrganizations import organization_unit_delete_command

    result = organization_unit_delete_command(
        organization_unit_delete.command_args, MockOrganizationsClient()
    )

    assert result.outputs == organization_unit_delete.context_outputs
    assert result.readable_output == organization_unit_delete.readable_output


def test_organization_unit_rename():
    from AWSOrganizations import organization_unit_rename_command

    result = organization_unit_rename_command(
        organization_unit_rename.command_args, MockOrganizationsClient()
    )

    assert result.outputs == organization_unit_rename.context_outputs
    assert result.readable_output == organization_unit_rename.readable_output


def test_policy_list(mocker):
    from AWSOrganizations import policy_list_command

    mocker.patch(
        "AWSOrganizations.paginate",
        side_effect=get_mock_paginate(
            policy_list.client_func_kwargs,
            policy_list.client_func_return
        ),
    )

    result = policy_list_command(policy_list.command_args, MockOrganizationsClient())

    assert list(result.outputs.values()) == policy_list.context_outputs
    assert result.readable_output == policy_list.readable_output


def test_target_policy_list(mocker):
    from AWSOrganizations import target_policy_list_command

    mocker.patch(
        "AWSOrganizations.paginate",
        side_effect=get_mock_paginate(
            target_policy_list.client_func_kwargs,
            target_policy_list.client_func_return
        ),
    )

    result = target_policy_list_command(
        target_policy_list.command_args, MockOrganizationsClient()
    )

    assert list(result.outputs.values()) == target_policy_list.context_outputs
    assert result.readable_output == target_policy_list.readable_output


def test_policy_get():
    from AWSOrganizations import policy_get_command

    result = policy_get_command(policy_get.command_args, MockOrganizationsClient())

    assert result.outputs == policy_get.context_outputs
    assert result.readable_output == policy_get.readable_output


def test_policy_delete():
    from AWSOrganizations import policy_delete_command

    result = policy_delete_command(
        policy_delete.command_args, MockOrganizationsClient()
    )

    assert result.outputs == policy_delete.context_outputs
    assert result.readable_output == policy_delete.readable_output


def test_policy_attach():
    from AWSOrganizations import policy_attach_command

    result = policy_attach_command(
        policy_attach.command_args, MockOrganizationsClient()
    )

    assert result.outputs == policy_attach.context_outputs
    assert result.readable_output == policy_attach.readable_output


def test_policy_target_list(mocker):
    from AWSOrganizations import policy_target_list_command

    mocker.patch(
        "AWSOrganizations.paginate",
        side_effect=get_mock_paginate(
            policy_target_list.client_func_kwargs,
            policy_target_list.client_func_return
        ),
    )

    result = policy_target_list_command(
        policy_target_list.command_args, MockOrganizationsClient()
    )

    assert list(result.outputs.values()) == policy_target_list.context_outputs
    assert result.readable_output == policy_target_list.readable_output


def test_resource_tag_add():
    from AWSOrganizations import resource_tag_add_command

    result = resource_tag_add_command(
        resource_tag_add.command_args, MockOrganizationsClient()
    )

    assert result.outputs == resource_tag_add.context_outputs
    assert result.readable_output == resource_tag_add.readable_output


def test_resource_tag_list(mocker):
    from AWSOrganizations import resource_tag_list_command

    mocker.patch(
        "AWSOrganizations.paginate",
        side_effect=get_mock_paginate(
            resource_tag_list.client_func_kwargs,
            resource_tag_list.client_func_return
        ),
    )

    result = resource_tag_list_command(
        resource_tag_list.command_args, MockOrganizationsClient()
    )

    assert list(result.outputs.values()) == resource_tag_list.context_outputs
    assert result.readable_output == resource_tag_list.readable_output
