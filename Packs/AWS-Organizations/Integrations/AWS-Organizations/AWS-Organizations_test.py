import pytest
from AWSApiModule import *


@pytest.fixture() 
def mock_aws_client(mocker):

    mock = MagicMock()

    def mock_aws_session(self, service, region, role_arn, role_session_name, role_session_duration):
        return mock

    mocker.patch('AWS-Organizations.AWSClient.aws_session', side_effect=mock_aws_session)

    return mock


@pytest.mark.parametrize('args, expected', [
    ({'limit': 10}, {'Accounts': [...], 'NextToken': 'xyz'}),  # example output
    ({'next_token': 'abc'}, {'Accounts': [...]}),
    ({}, {'Accounts': [...]})
])
def test_account_list(args, expected):
    client = OrganizationsClient() # mock client
    result = account_list_command(args, client)

    assert result.outputs == expected


@pytest.mark.parametrize('account_id, expected', [
    ('1234', {'Id': '1234', 'Name': 'Test Account'}),
    ('5678', {'Id': '5678', 'Name': 'Another Account'})
])
def test_account_get(account_id, expected):
    client = OrganizationsClient() # mock client
    args = {'account_id': account_id}

    result = account_list_command(args, client)

    assert result.outputs == expected