from typing import Any
from datetime import datetime


class Data:
    command_args: dict[str, str]
    client_func_kwargs: dict[str, Any]
    client_func_return: Any
    context_outputs: dict | list
    readable_output: str


class root_list(Data):
    command_args: dict = {}
    client_func_kwargs: dict = {}
    client_func_return = [
        [
            {
                "Id": "id_1",
                "Arn": "arn_1",
                "Name": "name_1",
                "PolicyTypes": [
                    {
                        "Type": "type_1_1",
                        "Status": "status_1_1",
                    },
                    {
                        "Type": "type_1_2",
                        "Status": "status_1_2",
                    },
                ],
            },
            {
                "Id": "id_2",
                "Arn": "arn_2",
                "Name": "name_2",
                "PolicyTypes": [
                    {
                        "Type": "type_2_1",
                        "Status": "status_2_1",
                    },
                    {
                        "Type": "type_2_2",
                        "Status": "status_2_2",
                    },
                ],
            },
        ],
        "next_token",
    ]
    context_outputs = [
        [
            {
                "Id": "id_1",
                "Arn": "arn_1",
                "Name": "name_1",
                "PolicyTypes": [
                    {
                        "Type": "type_1_1",
                        "Status": "status_1_1",
                    },
                    {
                        "Type": "type_1_2",
                        "Status": "status_1_2",
                    },
                ],
            },
            {
                "Id": "id_2",
                "Arn": "arn_2",
                "Name": "name_2",
                "PolicyTypes": [
                    {
                        "Type": "type_2_1",
                        "Status": "status_2_1",
                    },
                    {
                        "Type": "type_2_2",
                        "Status": "status_2_2",
                    },
                ],
            },
        ],
        {"RootNextToken": "next_token"},
    ]
    readable_output = """### AWS Organizations Roots
|Arn|Id|Name|
|---|---|---|
| arn_1 | id_1 | name_1 |
| arn_2 | id_2 | name_2 |
"""


class account_list(Data):
    command_args = {"account_id": "account_id"}
    client_func_kwargs = {"AccountId": "account_id"}
    client_func_return = {
        "Account": {
            "Id": "id",
            "Arn": "arn",
            "Email": "email",
            "Name": "name",
            "Status": "status",
            "JoinedMethod": "joined_method",
            "JoinedTimestamp": datetime(
                year=2022, month=10, day=15, hour=12, minute=30, second=45
            ),
        },
        "ResponseMetadata": ...,
    }
    context_outputs = {
        "Id": "id",
        "Arn": "arn",
        "Email": "email",
        "Name": "name",
        "Status": "status",
        "JoinedMethod": "joined_method",
        "JoinedTimestamp": "2022-10-15 12:30:45",
    }
    readable_output = """### AWS Organization Accounts
|Id|Arn|Name|Email|JoinedMethod|JoinedTimestamp|Status|
|---|---|---|---|---|---|---|
| id | arn | name | email | joined_method | 2022-10-15 12:30:45 | status |
"""


class organization_unit_get(Data):
    command_args = {"organization_unit_id": "organization_unit_id"}
    client_func_kwargs = {"OrganizationalUnitId": "organization_unit_id"}
    client_func_return = {
        "OrganizationalUnit": {"Id": "id", "Arn": "arn", "Name": "name"},
        "ResponseMetadata": ...,
    }
    context_outputs = {"Id": "id", "Arn": "arn", "Name": "name"}
    readable_output = """### AWS Organizations Unit
|Arn|Id|Name|
|---|---|---|
| arn | id | name |
"""


class organization_get(Data):
    client_func_return = {
        "Organization": {
            "Id": "id",
            "Arn": "arn",
            "FeatureSet": "featureset",
            "MasterAccountArn": "masteraccountarn",
            "MasterAccountId": "masteraccountid",
            "MasterAccountEmail": "masteraccountemail",
            "AvailablePolicyTypes": "availablepolicytypes",
        },
        "ResponseMetadata": ...,
    }
    context_outputs = {
        "Id": "id",
        "Arn": "arn",
        "FeatureSet": "featureset",
        "MasterAccountArn": "masteraccountarn",
        "MasterAccountId": "masteraccountid",
        "MasterAccountEmail": "masteraccountemail",
        "AvailablePolicyTypes": "availablepolicytypes",
    }
    readable_output = """### AWS Organization
|Id|Arn|FeatureSet|MasterAccountArn|MasterAccountId|MasterAccountEmail|
|---|---|---|---|---|---|
| id | arn | featureset | masteraccountarn | masteraccountid | masteraccountemail |
"""
