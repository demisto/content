import json

from PrismaCloudV2 import TIME_FILTER_BASE_CASE, ERROR_NOT_ENOUGH_ARGS, ERROR_RELATIVE_TIME_UNIT, ERROR_TO_NOW_TIME_UNIT, \
    ERROR_TOO_MANY_ARGS, FETCH_DEFAULT_TIME

full_alert = {
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
mirroring_fields = {"mirror_direction": None, "mirror_instance": ""}
full_alert_with_mirroring_fields = {**full_alert, **mirroring_fields}
full_incident = {'name': 'Policy name - P-11111',
                 'occurred': '2022-11-09T18:10:03Z',
                 'rawJSON': json.dumps(full_alert_with_mirroring_fields),
                 'severity': 3}

''' HELPER FUNCTIONS TESTS ARGUMENTS '''

# test_concatenate_url
# arguments: dict_input, url_field, expected_result
nested_url_field = ({'id': 'P-11111', 'policy': {}, 'resource': {'url': 'suffix'}},
                    'resource.url',
                    {'id': 'P-11111', 'policy': {}, 'resource': {'url': 'https://app.prismacloud.io/suffix'}})
outer_url_field = ({'id': 'P-11111', 'policy': {}, 'url': 'suffix'},
                   'url',
                   {'id': 'P-11111', 'policy': {}, 'url': 'https://app.prismacloud.io/suffix'})
suffix_with_beginning_char = ({'id': 'P-11111', 'policy': {}, 'url': '/suffix'},
                              'url',
                              {'id': 'P-11111', 'policy': {}, 'url': 'https://app.prismacloud.io/suffix'})
url_field_nonexistent = ({'id': 'P-11111', 'policy': {}, 'url': '/suffix'},
                         'policy.url',
                         {'id': 'P-11111', 'policy': {}, 'url': '/suffix'})

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

# test_calculate_fetch_time_range
# arguments: now, first_fetch, look_back, last_run_time, expected_fetch_time_range
start_at_first_fetch_default = (1676880716607, FETCH_DEFAULT_TIME, None, None, {'type': 'absolute',
                                                                                'value': {'endTime': 1676880716607,
                                                                                          'startTime': 1675767600000}})
start_at_first_fetch2 = (1676880716607, '1 hour', 20, None, {'type': 'absolute',
                                                             'value': {'endTime': 1676880716607,
                                                                       'startTime': 1676023200000}})
start_at_first_fetch = (1676880716607, '1 hour', None, None, {'type': 'absolute',
                                                              'value': {'endTime': 1676880716607,
                                                                        'startTime': 1676023200000}})
start_at_last_run_time_with_look_back = (1676880716607, '2 hours', 20, 1676023200000, {'type': 'absolute',
                                                                                       'value': {'endTime': 1676880716607,
                                                                                                 'startTime': 1676022000000}})
start_at_last_run_time = (1676880716607, '2 hours', 0, 1676023200000, {'type': 'absolute',
                                                                       'value': {'endTime': 1676880716607,
                                                                                 'startTime': 1676023200000}})

# incidents for test_filter_alerts and test_alert_to_incident_context and test_fetch_request
truncated_alert1 = {'id': 'P-111111', 'alertTime': 1000000110000, 'policy': {'name': 'Policy One', 'severity': 'medium'}}
incident2 = {'name': 'Policy Two - P-222222',
             'occurred': '2001-09-09T00:28:50Z',
             'rawJSON': '{"id": "P-222222", "alertTime": 999995330000, "policy": {"name": '
                        '"Policy Two", "severity": "high"}}',
             'severity': 3}
incident3 = {'name': 'Policy Tree - P-333333',
             'occurred': '2001-09-09T00:28:50Z',
             'rawJSON': '{"id": "P-333333", "alertTime": 999995330000, "policy": {"name": '
                        '"Policy Tree", "severity": "informational"}}',
             'severity': 0.5}
truncated_alert6 = {'id': 'P-666666', 'alertTime': 1000000120000, 'policy': {'name': 'Policy Six', 'severity': 'medium'}}
incident6 = {'name': 'Policy Six - P-666666',
             'occurred': '2001-09-09T01:48:40Z',
             'rawJSON': '{"id": "P-666666", "alertTime": 1000000120000, "policy": '
                        '{"name": "Policy Six", "severity": "medium"}, "mirror_direction": null, "mirror_instance": ""}',
             'severity': 2}
truncated_alert7 = {'id': 'P-777777', 'alertTime': 1000000130000, 'policy': {'name': 'Policy Seven', 'severity': 'low'}}
incident7 = {'name': 'Policy Seven - P-777777',
             'occurred': '2001-09-09T01:48:50Z',
             'rawJSON': '{"id": "P-777777", "alertTime": 1000000130000, "policy": '
                        '{"name": "Policy Seven", "severity": "low"}, "mirror_direction": null, "mirror_instance": ""}',
             'severity': 1}
truncated_alert_no_policy = {'id': 'P-888888', 'alertTime': 1000000130000}
incident_no_policy = {'name': 'No policy - P-888888',
                      'occurred': '2001-09-09T01:48:50Z',
                      'rawJSON': '{"id": "P-888888", "alertTime": 1000000130000, '
                                 '"mirror_direction": null, "mirror_instance": ""}',
                      'severity': 0}

# test_filter_alerts
# arguments: limit, expected_incidents, expected_updated_fetched_ids
low_limit_for_filter = (1, [incident6], {'N-111111': 1000000000000,
                                         'P-222222': 999996400000,
                                         'P-666666': 1000000120000})
exactly_limit_for_filter = (2, [incident6, incident7], {'N-111111': 1000000000000,
                                                        'P-222222': 999996400000,
                                                        'P-666666': 1000000120000,
                                                        'P-777777': 1000000130000})
high_limit_for_filter = (200, [incident6, incident7], {'N-111111': 1000000000000,
                                                       'P-222222': 999996400000,
                                                       'P-666666': 1000000120000,
                                                       'P-777777': 1000000130000})

# test_filter_alerts with updated alert time
# arguments: limit, expected_incidents, expected_updated_fetched_ids
low_limit_for_filter__updated_alert_time = (1, [incident6], {'N-111111': 1000000000001,
                                                             'P-222222': 999996400000,
                                                             'P-666666': 1000000120000})
exactly_limit_for_filter__updated_alert_time = (2, [incident6, incident7], {'N-111111': 1000000000001,
                                                                            'P-222222': 999996400000,
                                                                            'P-666666': 1000000120000,
                                                                            'P-777777': 1000000130000})
high_limit_for_filter__updated_alert_time = (200, [incident6, incident7], {'N-111111': 1000000000001,
                                                                           'P-222222': 999996400000,
                                                                           'P-666666': 1000000120000,
                                                                           'P-777777': 1000000130000})

# test_fetch_request
# arguments: limit, request_results, expected_incidents, expected_fetched_ids, expected_updated_last_run_time
low_limit_for_request = (1,
                         [{'items': [truncated_alert6], 'nextPageToken': 'token'},
                          {'items': [truncated_alert7], 'nextPageToken': 'token'},
                          {'items': []}],
                         [incident6],
                         {'P-111111': 1000000110000,
                          'P-222222': 999996400000,
                          'P-666666': 1000000120000},
                         1000000120000)
exactly_limit_for_request = (2,
                             [{'items': [truncated_alert6], 'nextPageToken': 'token'},
                              {'items': [truncated_alert7], 'nextPageToken': 'token'},
                              {'items': []}],
                             [incident6, incident7],
                             {'P-111111': 1000000110000,
                              'P-222222': 999996400000,
                              'P-666666': 1000000120000,
                              'P-777777': 1000000130000},
                             1000000130000)
more_than_limit_for_request = (2,
                               [{'items': [truncated_alert1, truncated_alert6], 'nextPageToken': 'token'},
                                {'items': [truncated_alert7, truncated_alert_no_policy], 'nextPageToken': 'token'},
                                {'items': []}],
                               [incident6, incident7],
                               {'P-111111': 1000000110000,
                                'P-222222': 999996400000,
                                'P-666666': 1000000120000,
                                'P-777777': 1000000130000},
                               1000000130000)
high_limit_for_request = (10,
                          [{'items': [truncated_alert6, truncated_alert7], 'nextPageToken': 'token'},
                           {'items': [truncated_alert_no_policy], 'nextPageToken': 'token'},
                           {'items': []}],
                          [incident6, incident7, incident_no_policy],
                          {'P-111111': 1000000110000,
                           'P-222222': 999996400000,
                           'P-666666': 1000000120000,
                           'P-777777': 1000000130000,
                           'P-888888': 1000000130000},
                          1000000130000)

# test_fetch_incidents
# arguments: last_run, params, incidents, fetched_ids, updated_last_run_time, expected_fetched_ids, expected_updated_last_run_time
fetch_first_run = ({},
                   {},
                   [incident6, incident7, incident_no_policy],
                   {'P-666666': 1000000120000, 'P-777777': 1000000130000, 'P-888888': 1000000130000},
                   1000000130000,
                   {'P-666666': 1000000120000, 'P-777777': 1000000130000, 'P-888888': 1000000130000},
                   1000000130000)
fetch_no_incidents = ({},
                      {'first_fetch': '1 day'},
                      [],
                      {},
                      1000000130000,
                      {},
                      1000000130000)
fetch_with_last_run = ({'time': 999990000000, 'fetched_ids': {}},
                       {'first_fetch': '1 hour'},
                       [incident2],
                       {'P-222222': 999995330000},
                       999995330000,
                       {'P-222222': 999995330000},
                       999996530000)
fetch_with_expiring_ids = ({'time': 999990000000, 'fetched_ids': {}},
                           {'first_fetch': '20 minutes', 'look_back': '5'},
                           [incident3],
                           {'P-333333': 999995330000},
                           999995330000,
                           {},
                           999998930000)

# mirroring_tests
alert_search_request_response = [{'id': 'P-1111111', 'status': 'resolved'},
                                 {'id': 'P-1111112', 'status': 'dismissed'},
                                 {'id': 'P-1111113', 'status': 'snoozed'}
                                 ]

alert_get_details_request_dismissed_alert_raw_response = {'id': 'test id', 'status': 'dismissed', 'reason': 'USER_DISMISSED',
                                                          'dismissalNote': 'test dismiss', 'policy': {'name': 'alert name'},
                                                          'alertTime': '2023-08-16T11:39:36Z', 'firstSeen': '2023-08-16T11:39:36Z'}

alert_get_details_request_snoozed_alert_raw_response = {'id': 'test id', 'status': 'snoozed', 'reason': 'USER_SNOOZED',
                                                        'dismissalNote': 'test snooze', 'policy': {'name': 'alert name'},
                                                        'alertTime': '2023-08-16T11:39:36Z', 'firstSeen': '2023-08-16T11:39:36Z'}

alert_get_details_request_resolved_alert_raw_response = {'id': 'test id', 'status': 'resolved', 'reason': 'RESOLVED',
                                                         'policy': {'name': 'alert name'},
                                                         'alertTime': '2023-08-16T11:39:36Z', 'firstSeen': '2023-08-16T11:39:36Z'}

alert_get_details_request_reopened_alert_raw_response = {'id': 'test id', 'status': 'open', 'reason': 'USER_REOPENED',
                                                         'policy': {'name': 'alert name'},
                                                         'alertTime': '2023-08-16T11:39:36Z', 'firstSeen': '2023-08-16T11:39:36Z'}

get_remote_alert_data_dismissed_alert_updated_object = {'status': 'dismissed', 'reason': 'USER_DISMISSED',
                                                        'dismissalNote': 'test dismiss', 'policy': {'name': 'alert name'}}

get_remote_alert_data_snoozed_alert_updated_object = {'status': 'snoozed', 'reason': 'USER_SNOOZED',
                                                      'dismissalNote': 'test snooze', 'policy': {'name': 'alert name'}}

get_remote_alert_data_resolved_alert_updated_object = {'status': 'resolved', 'reason': 'RESOLVED', 'dismissalNote': '',
                                                       'policy': {'name': 'alert name'}}

get_remote_alert_data_reopened_alert_updated_object = {'status': 'open', 'reason': 'USER_REOPENED', 'dismissalNote': '',
                                                       'policy': {'name': 'alert name'}}

dismissed_closed_xsoar_entry = {'dbotIncidentClose': True,
                                'rawCloseReason': 'dismissed',
                                'closeReason': 'Alert was dismissed on Prisma Cloud.',
                                'closeNotes': 'test dismiss'}

snoozed_closed_xsoar_entry = {'dbotIncidentClose': True,
                              'rawCloseReason': 'snoozed',
                              'closeReason': 'Alert was snoozed on Prisma Cloud.',
                              'closeNotes': 'test snooze'}

resolved_closed_xsoar_entry = {'dbotIncidentClose': True,
                               'rawCloseReason': 'resolved',
                               'closeReason': 'Alert was resolved on Prisma Cloud.',
                               'closeNotes': 'resolved'}

reopened_closed_xsoar_entry = {'dbotIncidentReopen': True}
