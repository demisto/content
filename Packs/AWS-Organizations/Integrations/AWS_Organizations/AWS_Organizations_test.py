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
        assert account_list.client_func_kwargs == kwargs
        return account_list.client_func_return

    def describe_organizational_unit(self, **kwargs):
        assert organization_unit_get.client_func_kwargs == kwargs
        return organization_unit_get.client_func_return

    def describe_organization(self):
        return organization_get.client_func_return


CLIENT = MockOrganizationsClient()


def get_mock_paginator(kwargs: dict, return_obj):
    def mock_paginator(paginator, key_to_pages, limit=None, page_size=None, next_token=None, **paginator_kwargs):
        assert kwargs == paginator_kwargs
        return return_obj
    return mock_paginator


def test_root_list_command(mocker):

    from AWS_Organizations import root_list_command

    mocker.patch(
        'AWS_Organizations.paginate',
        side_effect=get_mock_paginator(
            root_list.client_func_kwargs,
            root_list.client_func_return
        )
    )

    result = root_list_command(root_list.command_args, CLIENT)

    assert list(result.outputs.values()) == root_list.context_outputs
    assert result.readable_output == root_list.readable_output


def test_children_list_command(mocker):

    from AWS_Organizations import children_list_command

    mocker.patch(
        'AWS_Organizations.paginate',
        side_effect=get_mock_paginator(
            children_list.client_func_kwargs,
            children_list.client_func_return
        )
    )

    result = children_list_command(children_list.command_args, CLIENT)

    assert list(result.outputs.values()) == children_list.context_outputs
    assert result.readable_output == children_list.readable_output

# @pytest.mark.parametrize('args, expected', [
#     ({'limit': 10}, {'Accounts': [...], 'NextToken': 'xyz'}),  # example output
#     ({'next_token': 'abc'}, {'Accounts': [...]}),
#     ({}, {'Accounts': [...]})
# ])
# def test_account_list(args, expected):
#     client = OrganizationsClient() # mock client
#     result = account_list_command(args, client)

#     assert result.outputs == expected


def test_account_get():

    from AWS_Organizations import account_list_command

    result = account_list_command(account_list.command_args, CLIENT)

    assert result.outputs == account_list.context_outputs
    assert result.readable_output == account_list.readable_output


def test_organization_unit_get():

    from AWS_Organizations import organization_unit_get_command

    result = organization_unit_get_command(organization_unit_get.command_args, CLIENT)

    assert result.outputs == organization_unit_get.context_outputs
    assert result.readable_output == organization_unit_get.readable_output


def test_organization_get():

    from AWS_Organizations import organization_get_command

    result = organization_get_command(CLIENT)

    assert result.outputs == organization_get.context_outputs
    assert result.readable_output == organization_get.readable_output
