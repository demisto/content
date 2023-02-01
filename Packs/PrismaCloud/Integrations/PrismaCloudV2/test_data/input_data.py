from PrismaCloudV2 import TIME_FILTER_BASE_CASE, ERROR_NOT_ENOUGH_ARGS, ERROR_RELATIVE_TIME_UNIT, ERROR_TO_NOW_TIME_UNIT, ERROR_TOO_MANY_ARGS

alert = {
    "id": "P-11111",
    "status": "open",
    "reason": "RESOURCE_UPDATED",
    "firstSeen": 1557254018605,
    "lastSeen": 1668017403014,
    "alertTime": 1668017403014,
    "lastUpdated": 1669196436771,
    "policyId": "a11b2cc3-1111-2222-33aa-a1b23ccc4dd5",
    "saveSearchId": "search-id-1",
    "metadata": {
        "saveSearchId": "search-id-1"
    },
    "policy": {
        "policyId": "a11b2cc3-1111-2222-33aa-a1b23ccc4dd5",
        "name": "Policy name",
        "policyType": "config",
        "systemDefault": True,
        "description": "This policy identifies something.",
        "severity": "high",
        "recommendation": "Before making any changes, please check the impact on your applications/services.",
        "complianceMetadata": [
            {
                "standardName": "CIS v1.2.0 (AWS)",
                "standardDescription": "Center for Internet Security Standard version 1.2.0",
                "requirementId": "4",
                "requirementName": "Networking",
                "sectionId": "4.3",
                "sectionDescription": "Ensure something",
                "policyId": "a11b2cc3-1111-2222-33aa-a1b23ccc4dd5",
                "complianceId": "compliance-id-2",
                "sectionLabel": "4",
                "sectionViewOrder": 51,
                "requirementViewOrder": 4,
                "systemDefault": True,
                "customAssigned": False
            },
            {
                "standardName": "Cyber Security Network (CSN)",
                "standardDescription": "Cyber Security Network (CSN)",
                "requirementId": "CPM",
                "requirementName": "CPM",
                "sectionId": "CPM-AP1",
                "sectionDescription": "Operational assets",
                "policyId": "a11b2cc3-1111-2222-33aa-a1b23ccc4dd5",
                "complianceId": "compliance-id-4",
                "sectionLabel": "MIL-2",
                "sectionViewOrder": 63,
                "requirementViewOrder": 3,
                "systemDefault": True,
                "customAssigned": False
            }
        ],
        "labels": [
            "CIS"
        ],
        "lastModifiedOn": 1645161768985,
        "lastModifiedBy": "foo@test.com",
        "deleted": False,
        "remediable": False
    },
    "alertRules": [],
    "history": [
        {
            "modifiedBy": "Prisma Cloud",
            "modifiedOn": 1668017403014,
            "status": "resolved",
            "reason": "RESOURCE_UPDATED"
        },
        {
            "modifiedOn": 1598377179374,
            "status": "open",
            "reason": "NEW_ALERT"
        },
        {
            "modifiedBy": "Someone",
            "modifiedOn": 1580391961367,
            "status": "resolved",
            "reason": "RESOURCE_DELETED"
        },
        {
            "modifiedBy": "Someone",
            "modifiedOn": 1580390976108,
            "status": "open",
            "reason": "NEW_ALERT"
        }
    ],
    "resource": {
        "rrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
        "id": "ab-11a2b3n4m",
        "name": "default",
        "account": "FakeAccount",
        "accountId": "111111111111",
        "cloudAccountGroups": [
            "a account group",
            "ALLAccounts"
        ],
        "region": "AWS Virginia",
        "regionId": "us-east-1",
        "resourceType": "SECURITY_GROUP",
        "resourceApiName": "aws-ec2-security-groups",
        "cloudServiceName": "Amazon VPC",
        "url": "https://fake.amazon.com/vpc/home?region=us-east-1#securityGroups:filter=ab-11a2b3n4m",
        "data": {
            "tags": [],
            "vpcId": "vpc-1a2b",
            "region": "us-east-1",
            "groupId": "ab-11a2b3n4m",
            "ownerId": "222222222222",
            "isShared": False,
            "groupName": "default",
            "description": "default VPC security group",
            "ipPermissions": [
                {
                    "ipRanges": [
                        "0.0.0.0/0"
                    ],
                    "prefixListIds": [],
                    "userIdGroupPairs": [],
                    "ipProtocol": "-1",
                    "ipv4Ranges": [
                        {
                            "cidrIp": "0.0.0.0/0"
                        }
                    ],
                    "ipv6Ranges": []
                }
            ],
            "ipPermissionsEgress": []
        },
        "additionalInfo": {},
        "cloudType": "aws",
        "resourceTs": 1668017402217,
        "unifiedAssetId": "unified-asset-id-5",
        "resourceConfigJsonAvailable": True,
        "resourceDetailsAvailable": True
    },
    "alertAdditionalInfo": {
        "scannerVersion": "CS_2.0"
    }
}

''' HELPER FUNCTIONS TESTS ARGUMENTS '''

# test_handle_time_filter
# arguments: base_case, unit_value, amount_value, time_from, time_to, expected_output
only_unit_value = (None, 'week', None, None, None, {'type': 'to_now', 'value': 'week'})
unit_amount_and_unit_value = (None, 'day', 6, None, None, {'type': 'relative', 'value': {'amount': 6, 'unit': 'day'}})
only_time_to = (None, None, None, None, '1579039377301', {'type': 'absolute', 'value': {'endTime': 1579039377301}})
time_from_and_time_to = (None, None, None, '1579039277301', '1579039377301',
                         {'type': 'absolute', 'value': {'endTime': 1579039377301, 'startTime': 1579039277301}})
use_given_base_case = ({'type': 'to_now', 'value': 'month'}, None, None, None, None, {'type': 'to_now', 'value': 'month'})
use_default_base_case = (None, None, None, None, None, TIME_FILTER_BASE_CASE)

# test_handle_time_filter_error
# arguments: base_case, unit_value, amount_value, time_from, time_to, expected_error
only_amount_value = (None, None, 2, None, None, ERROR_NOT_ENOUGH_ARGS)
wrong_unit_value_relative = (None, 'second', 3, None, None, ERROR_RELATIVE_TIME_UNIT)
wrong_unit_value_to_now = (None, 'hour', None, None, None, ERROR_TO_NOW_TIME_UNIT)
only_time_from = (None, None, None, '01/23/2023', None, ERROR_NOT_ENOUGH_ARGS)
unit_amount_and_time_to = (None, 'day', None, '1579039377301', None, ERROR_TOO_MANY_ARGS)
unit_value_and_time_to = (None, None, 2, '1579039377301', None, ERROR_TOO_MANY_ARGS)

# test_handle_filters
with_filters = ('alert.status=open,alert.status=resolved, policy.remediable=true ',
                [{'name': 'alert.status', 'operator': '=', 'value': 'open'},
                 {'name': 'alert.status', 'operator': '=', 'value': 'resolved'},
                 {'name': 'policy.remediable', 'operator': '=', 'value': 'true'}])
empty_filters = ('', [])
