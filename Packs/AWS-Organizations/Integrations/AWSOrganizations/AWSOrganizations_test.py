import pytest
from test_data.data import *  # noqa

# from mypy_boto3_organizations import *


class MockOrganizationsClient:  # (OrganizationsClient):

    def get_paginator(self, _):
        return None

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


def get_mock_paginate(kwargs: dict, return_obj):
    def mock_paginate(paginator, key_to_pages, limit=None, page_size=None, next_token=None, **paginator_kwargs):
        assert kwargs == paginator_kwargs
        return return_obj
    return mock_paginate


@pytest.mark.parametrize(
    'paginate_kwargs, expected_kwargs, real_key_to_pages, expected_output, message',
    [
        (
            {'key_to_pages': 'Accounts', 'limit': 10, 'page_size': -1, 'next_token': 'token'},
            {'PaginationConfig': {'MaxItems': 10, 'PageSize': 10, 'StartingToken': None}},
            'Accounts',
            ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 'next_token'),
            'Test case: ignore page_size and next_token and when a limit is provided.',
        ),
        (
            {'key_to_pages': 'Accounts', 'page_size': 10, 'next_token': 'token'},
            {'PaginationConfig': {'MaxItems': 10, 'PageSize': 10, 'StartingToken': 'token'}},
            'Accounts',
            ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 'next_token'),
            'Test case: use page_size and next_token correctly.',
        ),
        (
            {'key_to_pages': 'Accounts', 'page_size': 13, 'next_token': 'token', 'another_arg': 'value'},
            {'PaginationConfig': {'MaxItems': 13, 'PageSize': 13, 'StartingToken': 'token'}, 'another_arg': 'value'},
            'Accounts',
            ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], 'next_token'),
            'Test case: check that the args are passed toi the paginator correctly.',
        )
    ]
)
def test_paginate(paginate_kwargs, expected_kwargs, real_key_to_pages, expected_output, message):
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
            {
                'NextToken': 'next_token',
                real_key_to_pages: list(range(nums, nums + 5))
            }
            for nums in range(0, 1000, 5)
        )

    output = paginate(
        type('Mock', (), {'paginate': mock_paginate}),
        **paginate_kwargs
    )

    assert output == expected_output, message


def test_root_list_command(mocker):

    from AWSOrganizations import root_list_command

    mocker.patch(
        'AWSOrganizations.paginate',
        side_effect=get_mock_paginate(
            root_list.client_func_kwargs,
            root_list.client_func_return
        )
    )

    result = root_list_command(root_list.command_args, MockOrganizationsClient())

    assert list(result.outputs.values()) == root_list.context_outputs
    assert result.readable_output == root_list.readable_output


def test_children_list_command(mocker):

    from AWSOrganizations import children_list_command

    mocker.patch(
        'AWSOrganizations.paginate',
        side_effect=get_mock_paginate(
            children_list.client_func_kwargs,
            children_list.client_func_return
        )
    )

    result = children_list_command(children_list.command_args, MockOrganizationsClient())

    assert list(result.outputs.values()) == children_list.context_outputs
    assert result.readable_output == children_list.readable_output


def test_parent_list_command(mocker):

    from AWSOrganizations import parent_list_command

    mocker.patch(
        'AWSOrganizations.paginate',
        side_effect=get_mock_paginate(
            parent_list.client_func_kwargs,
            parent_list.client_func_return
        )
    )

    result = parent_list_command(parent_list.command_args, MockOrganizationsClient())

    assert result.outputs == parent_list.context_outputs
    assert result.readable_output == parent_list.readable_output


def test_organization_unit_get():

    from AWSOrganizations import organization_unit_get_command

    result = organization_unit_get_command(organization_unit_get.command_args, MockOrganizationsClient())

    assert result.outputs == organization_unit_get.context_outputs
    assert result.readable_output == organization_unit_get.readable_output


def test_account_list_command(mocker):

    from AWSOrganizations import account_list_command

    mocker.patch(
        'AWSOrganizations.paginate',
        side_effect=get_mock_paginate(
            account_list.client_func_kwargs,
            account_list.client_func_return
        )
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

    result = account_remove_command(account_remove.command_args, MockOrganizationsClient())

    assert result.readable_output == account_remove.readable_output


def test_account_move():

    from AWSOrganizations import account_move_command

    result = account_move_command(account_move.command_args, MockOrganizationsClient())

    assert result.readable_output == account_move.readable_output


def test_account_create_initial_call():
    
    from AWSOrganizations import account_create_command

    result = account_create_command(MockOrganizationsClient())

    assert result.response.outputs == test_data.context_outputs
    assert result.response.readable_output == test_data.readable_output
