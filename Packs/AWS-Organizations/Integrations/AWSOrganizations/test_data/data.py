from typing import Any
from datetime import datetime


class Data:
    command_args: dict[str, Any] = {}
    client_func_kwargs: dict[str, Any] = {}
    client_func_return: Any = None
    context_outputs: dict | list | None = None
    readable_output: str | None = None


class root_list(Data):
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
    readable_output = """### AWS Organization Roots
|Id|Arn|Name|
|---|---|---|
| id_1 | arn_1 | name_1 |
| id_2 | arn_2 | name_2 |
"""


class children_list(Data):
    command_args = {"child_type": "OrganizationalUnit", "parent_id": "parent_id"}
    client_func_kwargs = {"ChildType": "ORGANIZATIONAL_UNIT", "ParentId": "parent_id"}
    client_func_return = [
        [
            {
                "Id": "id_1",
                "Type": "type_1",
            },
            {
                "Id": "id_2",
                "Type": "type_2",
            },
        ],
        "next_token",
    ]
    context_outputs = [
        [
            {"Id": "id_1", "Type": "type_1", "ParentId": "parent_id"},
            {"Id": "id_2", "Type": "type_2", "ParentId": "parent_id"},
        ],
        {"ChildrenNextToken": "next_token"},
    ]
    readable_output = """### AWS Account *parent_id* Children
|Id|Type|
|---|---|
| id_1 | type_1 |
| id_2 | type_2 |
"""


class parent_list(Data):
    command_args = {"child_id": "child_id"}
    client_func_kwargs = {"ChildId": "child_id"}
    client_func_return = [
        [
            {
                "Id": "id",
                "Type": "type",
            }
        ],
        "next_token",
    ]
    context_outputs = [{"Id": "id", "Type": "type", "ChildId": "child_id"}]
    readable_output = """### AWS Account *child_id* Parent
|Id|Type|
|---|---|
| id | type |
"""


class account_list(Data):
    client_func_return = [
        [
            {
                "Id": "id_1",
                "Arn": "arn_1",
                "Email": "email_1",
                "Name": "name_1",
                "Status": "status_1",
                "JoinedMethod": "joined_method_1",
                "JoinedTimestamp": datetime(
                    year=2022, month=10, day=15, hour=12, minute=30, second=45
                ),
            },
            {
                "Id": "id_2",
                "Arn": "arn_2",
                "Email": "email_2",
                "Name": "name_2",
                "Status": "status_2",
                "JoinedMethod": "joined_method_2",
                "JoinedTimestamp": datetime(
                    year=2022, month=10, day=16, hour=12, minute=30, second=45
                ),
            },
        ],
        "next_token",
    ]
    context_outputs = [
        [
            {
                "Id": "id_1",
                "Arn": "arn_1",
                "Email": "email_1",
                "Name": "name_1",
                "Status": "status_1",
                "JoinedMethod": "joined_method_1",
                "JoinedTimestamp": "2022-10-15 12:30:45",
            },
            {
                "Id": "id_2",
                "Arn": "arn_2",
                "Email": "email_2",
                "Name": "name_2",
                "Status": "status_2",
                "JoinedMethod": "joined_method_2",
                "JoinedTimestamp": "2022-10-16 12:30:45",
            },
        ],
        {"AccountNextToken": "next_token"},
    ]
    readable_output = """### AWS Organization Accounts
|Id|Arn|Name|Email|JoinedMethod|JoinedTimestamp|Status|
|---|---|---|---|---|---|---|
| id_1 | arn_1 | name_1 | email_1 | joined_method_1 | 2022-10-15 12:30:45 | status_1 |
| id_2 | arn_2 | name_2 | email_2 | joined_method_2 | 2022-10-16 12:30:45 | status_2 |
"""


class account_get(Data):
    command_args = {"account_id": "account_id"}
    client_func_kwargs = {"AccountId": "account_id"}
    client_func_return = {
        "Account": {
            "Id": "id",
            "Arn": "arn",
            "Email": "email",
            "Name": "name",
            "Status": "SUSPENDED",
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
        "Status": "SUSPENDED",
        "JoinedMethod": "joined_method",
        "JoinedTimestamp": "2022-10-15 12:30:45",
    }
    readable_output = """### AWS Organization Accounts
|Id|Arn|Name|Email|JoinedMethod|JoinedTimestamp|Status|
|---|---|---|---|---|---|---|
| id | arn | name | email | joined_method | 2022-10-15 12:30:45 | SUSPENDED |
"""


class organization_unit_get(Data):
    command_args = {"organization_unit_id": "organization_unit_id"}
    client_func_kwargs = {"OrganizationalUnitId": "organization_unit_id"}
    client_func_return = {
        "OrganizationalUnit": {"Id": "id", "Arn": "arn", "Name": "name"},
        "ResponseMetadata": ...,
    }
    context_outputs = {"Id": "id", "Arn": "arn", "Name": "name"}
    readable_output = """### AWS Organization Unit
|Id|Arn|Name|
|---|---|---|
| id | arn | name |
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


class account_remove(Data):
    command_args = {"account_id": "account_id"}
    client_func_kwargs = {"AccountId": "account_id"}
    readable_output = 'AWS account *account_id* removed successfully.'


class account_move(Data):
    command_args = {
        "account_id": "account_id",
        "source_parent_id": "source_parent_id",
        "destination_parent_id": "destination_parent_id",
    }
    client_func_kwargs = {
        "AccountId": "account_id",
        "SourceParentId": "source_parent_id",
        "DestinationParentId": "destination_parent_id",
    }
    readable_output = 'AWS account *account_id* moved successfully.'


class account_create_initial_call(Data):
    command_args = {
        "account_name": "account_name",
        "email": "email",
        "iam_user_access_to_billing": "Allow",
        "role_name": "role_name",
        "tags": "key1=value1,key2=value2",
    }
    client_func_kwargs = {
        'Email': 'email',
        'AccountName': 'account_name',
        'RoleName': 'role_name',
        'IamUserAccessToBilling': 'ALLOW',
        'Tags': [
            {"Key": "key1", "Value": "value1"},
            {"Key": "key2", "Value": "value2"},
        ]
    }
    client_func_return = {
        'CreateAccountStatus': {
            'Id': 'id',
            'AccountName': 'account_name',
            'State': 'IN_PROGRESS',
            'RequestedTimestamp': datetime(2015, 1, 1),
            'CompletedTimestamp': datetime(2015, 1, 1),
            'AccountId': 'account_id',
            'GovCloudAccountId': 'gov_id',
            'FailureReason': 'none'
        }
    }


class account_create_final_call(Data):
    command_args = {"request_id": "request_id"}
    client_func_kwargs = {"CreateAccountRequestId": "request_id"}
    client_func_return = {
        'CreateAccountStatus': {
            'Id': 'id',
            'AccountName': 'account_name',
            'State': 'SUCCEEDED',
            'RequestedTimestamp': datetime(2015, 1, 1),
            'CompletedTimestamp': datetime(2015, 1, 1),
            'AccountId': 'account_id',
            'GovCloudAccountId': 'gov_id',
            'FailureReason': 'none'
        }
    }
    context_outputs = account_get.context_outputs
    readable_output = account_get.readable_output


class account_close(Data):
    command_args = {
        "account_id": "account_id",
        "is_closed": False
    }
    client_func_kwargs = {
        "AccountId": "account_id"
    }
    readable_output = 'AWS account *account_id* closed successfully.'


class organization_unit_create(Data):
    command_args = {
        "name": "name",
        "parent_id": "parent_id",
        "tags": "key1=value1,key2=value2",
    }
    client_func_kwargs = {
        "ParentId": "parent_id",
        "Name": "name",
        "Tags": [
            {"Key": "key1", "Value": "value1"},
            {"Key": "key2", "Value": "value2"},
        ],
    }
    client_func_return = {
        "OrganizationalUnit": {"Id": "id", "Arn": "arn", "Name": "name"}
    }
    context_outputs = {"Id": "id", "Arn": "arn", "Name": "name"}
    readable_output = """### AWS Organization Unit
|Id|Name|Arn|
|---|---|---|
| id | name | arn |
"""


class organization_unit_delete(Data):
    command_args = {"organizational_unit_id": "organizational_unit_id"}
    client_func_kwargs = {"OrganizationalUnitId": "organizational_unit_id"}
    readable_output = 'AWS organizational unit *organizational_unit_id* deleted successfully.'


class organization_unit_rename(Data):
    command_args = {"organizational_unit_id": "organizational_unit_id", "name": "name"}
    client_func_kwargs = {
        "OrganizationalUnitId": "organizational_unit_id",
        "Name": "name",
    }
    readable_output = 'AWS organization unit *organizational_unit_id* successfully renamed to *name*.'


class policy_list(Data):
    command_args = {"policy_type": "AI Services Opt Out Policy"}
    client_func_kwargs = {"Filter": "AISERVICES_OPT_OUT_POLICY"}
    client_func_return = (
        [
            {
                "Id": "id1",
                "Arn": "arn1",
                "Name": "name1",
                "Description": "desc1",
                "Type": "type1",
                "AwsManaged": True,
            },
            {
                "Id": "id2",
                "Arn": "arn2",
                "Name": "name2",
                "Description": "desc2",
                "Type": "type2",
                "AwsManaged": False,
            },
        ],
        "next_token",
    )
    context_outputs = [
        [
            {
                "Id": "id1",
                "Arn": "arn1",
                "Name": "name1",
                "Description": "desc1",
                "Type": "type1",
                "AwsManaged": True,
            },
            {
                "Id": "id2",
                "Arn": "arn2",
                "Name": "name2",
                "Description": "desc2",
                "Type": "type2",
                "AwsManaged": False,
            },
        ],
        {"PolicyNextToken": "next_token"},
    ]
    readable_output = """### AWS Organization Policies
|Id|Arn|Name|Description|Type|AwsManaged|
|---|---|---|---|---|---|
| id1 | arn1 | name1 | desc1 | type1 | true |
| id2 | arn2 | name2 | desc2 | type2 | false |
"""


class target_policy_list(Data):
    command_args = {"policy_type": "Service Control Policy", "target_id": "target_id"}
    client_func_kwargs = {"Filter": "SERVICE_CONTROL_POLICY", "TargetId": "target_id"}
    client_func_return = (
        [
            {
                "Id": "id1",
                "Arn": "arn1",
                "Name": "name1",
                "Description": "desc1",
                "Type": "type1",
                "AwsManaged": True,
            },
            {
                "Id": "id2",
                "Arn": "arn2",
                "Name": "name2",
                "Description": "desc2",
                "Type": "type2",
                "AwsManaged": False,
            },
        ],
        "next_token",
    )
    context_outputs = [
        [
            {
                "Id": "id1",
                "Arn": "arn1",
                "Name": "name1",
                "Description": "desc1",
                "Type": "type1",
                "AwsManaged": True,
                "TargetId": "target_id"
            },
            {
                "Id": "id2",
                "Arn": "arn2",
                "Name": "name2",
                "Description": "desc2",
                "Type": "type2",
                "AwsManaged": False,
                "TargetId": "target_id"
            },
        ],
        {"TargetPolicyNextToken": "next_token"},
    ]
    readable_output = """### AWS Organization *target_id* Policies
|Id|Arn|Name|Description|Type|AwsManaged|
|---|---|---|---|---|---|
| id1 | arn1 | name1 | desc1 | type1 | true |
| id2 | arn2 | name2 | desc2 | type2 | false |
"""


class policy_get(Data):
    command_args = {"policy_id": "policy_id"}
    client_func_kwargs = {"PolicyId": "policy_id"}
    client_func_return = {
        "Policy": {
            "PolicySummary": {
                "Id": "id",
                "Arn": "arn",
                "Name": "name",
                "Description": "desc",
                "Type": "type",
                "AwsManaged": True,
            },
            "Content": ...,
        }
    }
    context_outputs = {
        "Id": "id",
        "Arn": "arn",
        "Name": "name",
        "Description": "desc",
        "Type": "type",
        "AwsManaged": True,
    }
    readable_output = """### AWS Organization Policies
|Id|Arn|Name|Description|Type|AwsManaged|
|---|---|---|---|---|---|
| id | arn | name | desc | type | true |
"""


class policy_delete(Data):
    command_args = {"policy_id": "policy_id"}
    client_func_kwargs = {"PolicyId": "policy_id"}
    readable_output = 'AWS Organizations policy *policy_id* successfully deleted.'


class policy_attach(Data):
    command_args = {"policy_id": "policy_id", "target_id": "target_id"}
    client_func_kwargs = {"PolicyId": "policy_id", "TargetId": "target_id"}
    readable_output = 'AWS Organizations policy *policy_id* successfully attached.'


class policy_target_list(Data):
    command_args = {"policy_id": "policy_id"}
    client_func_kwargs = {"PolicyId": "policy_id"}
    client_func_return = (
        [
            {
                "TargetId": "target_id1",
                "Arn": "arn1",
                "Name": "name1",
                "Type": "type1",
            },
            {
                "TargetId": "target_id2",
                "Arn": "arn2",
                "Name": "name2",
                "Type": "type2",
            },
        ],
        "next_token",
    )
    context_outputs = [
        [
            {
                "TargetId": "target_id1",
                "Arn": "arn1",
                "Name": "name1",
                "Type": "type1",
                "PolicyId": "policy_id",
            },
            {
                "TargetId": "target_id2",
                "Arn": "arn2",
                "Name": "name2",
                "Type": "type2",
                "PolicyId": "policy_id",
            },
        ],
        {"PolicyTargetNextToken": "next_token"},
    ]
    readable_output = """### AWS Organization *policy_id* Targets
|TargetId|Arn|Name|Type|
|---|---|---|---|
| target_id1 | arn1 | name1 | type1 |
| target_id2 | arn2 | name2 | type2 |
"""


class resource_tag_add(Data):
    command_args = {"resource_id": "resource_id", "tags": "key1=value1,key2=value2"}
    client_func_kwargs = {
        "ResourceId": "resource_id",
        "Tags": [
            {"Key": "key1", "Value": "value1"},
            {"Key": "key2", "Value": "value2"},
        ],
    }
    readable_output = "AWS Organizations resource *resource_id* successfully tagged."


class resource_tag_list(Data):
    command_args = {"resource_id": "resource_id", "next_token": "next_token"}
    client_func_kwargs = {"ResourceId": "resource_id", "NextToken": "next_token"}
    client_func_return = {
        "Tags": [
            {"Key": "key1", "Value": "value1"},
            {"Key": "key2", "Value": "value2"},
        ],
        "NextToken": "next_token",
    }
    context_outputs = [
        [
            {"Key": "key1", "Value": "value1", "ResourceId": "resource_id"},
            {"Key": "key2", "Value": "value2", "ResourceId": "resource_id"},
        ],
        {"TagNextToken": "next_token"},
    ]
    readable_output = """### AWS Organization *resource_id* Tags
|Key|Value|
|---|---|
| key1 | value1 |
| key2 | value2 |
"""
