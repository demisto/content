import demistomock as demisto
from CommonServerPython import *
from unittest.mock import MagicMock
import pytest


def test_internal_request(mocker):
    from AwsEC2SyncAccounts import internal_request

    mock_execute_command = mocker.patch.object(
        demisto, "executeCommand", return_value=[{'Contents': {'response': 'result'}}]
    )

    result = internal_request('POST', '/path/', {'body': 'data'})

    assert result == 'result'
    mock_execute_command.assert_called_with(
        'core-api-post', {'uri': '/path/', 'body': '{"body": "data"}'}
    )


def test_get_account_ids(mocker):
    from AwsEC2SyncAccounts import get_account_ids

    mock_execute_command = mocker.patch.object(demisto, "executeCommand")
    mock_execute_command.return_value = [
        {
            "EntryContext": {
                "AWS.Organizations.Account(val.Id && val.Id == obj.Id)": [
                    {"Id": "1234"},
                    {"Id": "5678"},
                ]
            },
            "HumanReadable": "human_readable"
        }
    ]

    account_ids = get_account_ids('instance_name', 2)

    assert account_ids == (["1234", "5678"], "human_readable")
    mock_execute_command.assert_called_with("aws-org-account-list", {'limit': 2, 'using': 'instance_name'})


def test_set_instance(mocker):
    import AwsEC2SyncAccounts

    internal_request: MagicMock = mocker.patch.object(
        AwsEC2SyncAccounts, "internal_request"
    )
    AwsEC2SyncAccounts.set_instance(
        {
            "data": [
                {
                    "name": "accounts_to_access",
                    "hasvalue": False,
                    "value": "",
                },
                {
                    "name": "sessionDuration"
                },
            ],
        },
        'accounts'
    )
    internal_request.assert_called_with(
        'put', '/settings/integration', {
            "data": [
                {
                    "name": "accounts_to_access",
                    "hasvalue": True,
                    "value": "accounts",
                },
                {
                    "name": "sessionDuration"
                },
            ],
        }
    )


def test_update_ec2_instance(mocker):
    import AwsEC2SyncAccounts

    internal_request: MagicMock = mocker.patch.object(
        AwsEC2SyncAccounts,
        "internal_request",
        side_effect=lambda *args: {
            ("post", "/settings/integration/search"): {
                "instances": [
                    {
                        "id": "2fa1071e-af66-4668-8f79-8c57a3e4851d",
                        "name": "AWS - EC2",
                        "configvalues": {
                            "accounts_to_access": "",
                            "sessionDuration": None,
                        },
                        "configtypes": {"accounts_to_access": 0, "sessionDuration": 0},
                        "data": [
                            {
                                "name": "accounts_to_access",
                                "hasvalue": False,
                                "value": "",
                            },
                            {
                                "name": "sessionDuration"
                            },
                        ],
                    },
                    {
                        "name": "wrong name",
                    },
                ]
            },
            ("put", "/settings/integration"): {
                "configvalues": {"accounts_to_access": "1234,5678"}
            },
        }.get(args[:2]),
    )

    result = AwsEC2SyncAccounts.update_ec2_instance(["1234", "5678"], "AWS - EC2")

    assert internal_request.mock_calls[0].args == ('post', '/settings/integration/search')
    assert internal_request.mock_calls[1].args == (
        'put',
        '/settings/integration',
        {
            "id": "2fa1071e-af66-4668-8f79-8c57a3e4851d",
            "name": "AWS - EC2",
            "configvalues": {
                "accounts_to_access": "",
                "sessionDuration": None,
            },
            "configtypes": {"accounts_to_access": 0, "sessionDuration": 0},
            "data": [
                {
                    "name": "accounts_to_access",
                    "hasvalue": True,
                    "value": "1234,5678",
                },
                {
                    "name": "sessionDuration"
                },
            ],
        }
    )
    assert result == "Successfully updated ***AWS - EC2*** with accounts:"


def test_remove_excluded_accounts():
    from AwsEC2SyncAccounts import remove_excluded_accounts

    accounts = ['1', '2', '3', '4', '5']

    accounts = remove_excluded_accounts(accounts, '1,2,3')

    assert set(accounts) == {'4', '5'}


def test_errors():
    import AwsEC2SyncAccounts as sync

    with pytest.raises(DemistoException, match='Unexpected error while configuring AWS - EC2 instance with accounts'):
        sync.get_instance = lambda _: 1 / 0
        sync.update_ec2_instance([], '')

    with pytest.raises(DemistoException, match="Unexpected output from 'aws-org-account-list':\nNone"):
        sync.demisto.executeCommand = lambda *_: {}['key']
        sync.get_account_ids('', 0)
