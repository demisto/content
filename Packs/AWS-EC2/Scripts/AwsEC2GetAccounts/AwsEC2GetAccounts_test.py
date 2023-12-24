import demistomock as demisto
from CommonServerPython import *
from unittest.mock import MagicMock


def test_get_account_ids(mocker):
    from AwsEC2GetAccounts import get_account_ids

    mock_execute_command = mocker.patch.object(demisto, "executeCommand")
    mock_execute_command.return_value = [
        {
            "EntryContext": {
                "AWS.Organizations.Account(val.Id && val.Id == obj.Id)": [
                    {"Id": "1234"},
                    {"Id": "5678"},
                ]
            }
        }
    ]

    account_ids = get_account_ids()

    assert account_ids == ["1234", "5678"]
    mock_execute_command.assert_called_with("aws-org-account-list", {})


def test_update_ec2_instance(mocker):
    import AwsEC2GetAccounts

    internal_request: MagicMock = mocker.patch.object(
        AwsEC2GetAccounts,
        "internal_request",
        side_effect=lambda *args: {
            ("POST", "/settings/integration/search"): {
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
            ("PUT", "/settings/integration"): {
                "configvalues": {"accounts_to_access": "1234,5678"}
            },
        }.get(args[:2]),
    )

    result = AwsEC2GetAccounts.update_ec2_instance(["1234", "5678"], "AWS - EC2")

    assert internal_request.mock_calls[0].args == ('POST', '/settings/integration/search')
    assert internal_request.mock_calls[1].args == ('PUT', '/settings/integration', {
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
    assert result == "Successfully updated 'AWS - EC2' with accounts: 1234,5678"
