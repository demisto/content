import pytest
from test_data.data import *
from typing import TYPE_CHECKING

# The following imports are used only for type hints and autocomplete.
# They are not used at runtime, and are not in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_organizations import *
    # from botocore.paginate import Paginator


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


CLIENT = MockOrganizationsClient()


def get_mock_paginate(kwargs: dict, return_obj):
    def mock_paginate(paginator, key_to_pages, limit=None, page_size=None, next_token=None, **paginator_kwargs):
        assert kwargs == paginator_kwargs
        return return_obj
    return mock_paginate


def paginate(
    paginator: 'Paginator', key_to_pages: str, limit=None, page_size=None, next_token=None, **kwargs
) -> tuple[list, str | None]:

    max_items = arg_to_number(limit or page_size) or 50
    pagination_max = min(max_items, MAX_PAGINATION)

    iterator = paginator.paginate(
        **kwargs,
        PaginationConfig={
            'MaxItems': pagination_max,
            'PageSize': pagination_max,
            'StartingToken': next_token if not limit else None
        }
    )

    pages: list = []
    next_token = None

    for response in iterator:
        pages.extend(response.get(key_to_pages, []))
        next_token = response.get('NextToken')
        if len(pages) >= max_items:
            break

    del pages[max_items:]
    return pages, next_token


@pytest.mark.parametrize(
    'paginate_kwargs, expected_kwargs, real_key_to_pages',
    [
        (
            {'key_to_pages': 'Accounts', 'Limit': 10, 'page_size': -1, 'next_token': 'token'},
            {'PaginationConfig': {'MaxItems': 10, 'PageSize': 10, 'StartingToken': None}},
            'Accounts',
            ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 'next_token')
        ),
        (
            {'key_to_pages': 'Accounts', 'page_size': 10, 'next_token': 'token'},
            {'PaginationConfig': {'MaxItems': 10, 'PageSize': 10, 'StartingToken': 'token'}},
            'Accounts',
            ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 'next_token')
        ),
        (
            {'key_to_pages': 'Accounts', 'page_size': 13, 'next_token': 'token', 'another_arg': 'value'},
            {'PaginationConfig': {'MaxItems': 13, 'PageSize': 13, 'StartingToken': 'token'}, 'another_arg': 'value'},
            'Accounts',
            ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], 'next_token')
        )
    ]
)
def test_paginate(paginate_kwargs, expected_kwargs, real_key_to_pages, expected_output):
    
    from AWSOrganizations import paginate

    def mock_paginate(**kwargs):
        assert kwargs == expected_kwargs
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

    assert output == expected_output


def test_root_list_command(mocker):

    from AWSOrganizations import root_list_command

    mocker.patch(
        'AWSOrganizations.paginate',
        side_effect=get_mock_paginate(
            root_list.client_func_kwargs,
            root_list.client_func_return
        )
    )

    result = root_list_command(root_list.command_args, CLIENT)

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

    result = children_list_command(children_list.command_args, CLIENT)

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

    result = parent_list_command(parent_list.command_args, CLIENT)

    assert result.outputs == parent_list.context_outputs
    assert result.readable_output == parent_list.readable_output


def test_organization_unit_get():

    from AWSOrganizations import organization_unit_get_command

    result = organization_unit_get_command(organization_unit_get.command_args, CLIENT)

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

    result = account_list_command(account_list.command_args, CLIENT)

    assert list(result.outputs.values()) == account_list.context_outputs
    assert result.readable_output == account_list.readable_output


def test_account_get():

    from AWSOrganizations import account_list_command

    result = account_list_command(account_get.command_args, CLIENT)

    assert result.outputs == account_get.context_outputs
    assert result.readable_output == account_get.readable_output


def test_organization_get():

    from AWSOrganizations import organization_get_command

    result = organization_get_command(CLIENT)

    assert result.outputs == organization_get.context_outputs
    assert result.readable_output == organization_get.readable_output
