import pytest
from MicrosoftCloudAppSecurity import Client


@pytest.mark.parametrize(
    "arg, expected",
    [
        ("3256754321", 3256754321),
        ("2020-03-20T14:28:23.382748", 1584714503),
        (2323248648.123, 2323248648)
    ]
)
def test_arg_to_timestamp(arg, expected):
    from MicrosoftCloudAppSecurity import arg_to_timestamp
    res = arg_to_timestamp(arg)
    assert res == expected


expected_alerts = {'filters': {'entity.service': {'eq': 111}, 'entity.instance': {'eq': 111}, 'severity': {'eq': 0},
                   'resolutionStatus': {'eq': 0}, 'entity.entity': {'eq': {'id': '3fa9f28b-eb0e-463a-ba7b-8089fe9991e2',
                                                                           'saas': 11161, 'inst': 0}}},
                   'skip': 5, 'limit': 10}
request_data_alerts = {"service": "111", "instance": "111", "severity": "Low",
                       "username": '{"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}',
                       "resolution_status": "Open", "skip": "5", "limit": "10"}


expected_activities = {'filters': {'service': {'eq': 111}, 'instance': {'eq': 111}, 'ip.address': {'eq': '8.8.8.8'},
                       'ip.category': {'eq': 1}, 'activity.takenAction': {'eq': 'block'}, 'source': {'eq': 0}},
                       'skip': 5, 'limit': 10}
request_data_activities = {"service": "111", "instance": "111", "ip": "8.8.8.8", "ip_category": "Corporate",
                           'taken_action': 'block', 'source': 'Access_control', "skip": "5", "limit": "10"}


expected_files = {'filters': {'service': {'eq': 111}, 'instance': {'eq': 111}, 'fileType': {'eq': 0},
                  'quarantined': {'eq': True}, 'owner.entity':
                                 {'eq': {"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}},
                              'sharing': {'eq': 0}, 'extension': {'eq': 'png'}, }, 'skip': 5, 'limit': 10}
request_data_files = {"service": "111", "instance": "111", "file_type": "Other", "username":
                      '{"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}', "sharing": 'Private',
                      'extension': 'png', 'quarantined': 'True', "skip": "5", "limit": "10"}


expected_entities = {'filters': {'app': {'eq': 111}, 'instance': {'eq': 111}, 'type': {'eq': 'user'}, 'isExternal':
                     {'eq': True}, 'status': {'eq': 0}, 'userGroups': {'eq': '1234'}, 'isAdmin': {'eq': 'demisto'},
                     'entity': {'eq': {"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}}},
                     'skip': 5, 'limit': 10}
request_data_entities = {"service": "111", "instance": "111", "type": "user", "status": 'N/A', "username":
                         '{"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}', "group_id": '1234',
                         'is_admin': 'demisto', 'is_external': 'External', "skip": "5", "limit": "10"}


@pytest.mark.parametrize(
    "request_data_entities, url_suffix, expected",
    [
        (request_data_alerts, '/alerts/', expected_alerts),
        (request_data_activities, '/activities/', expected_activities),
        (request_data_files, '/files/', expected_files),
        (request_data_entities, '/entities/', expected_entities)
    ]
)
def test_args_or_params_to_filter(request_data_entities, url_suffix, expected):
    from MicrosoftCloudAppSecurity import args_or_params_to_filter
    res = args_or_params_to_filter(request_data_entities, url_suffix)
    assert res == expected


@pytest.mark.parametrize(
    "alert_ids, customer_filters, comment, expected",
    [
        ("5f06d71dba4,289d0602ba5ac", '', '', {'filters': {'id': {'eq': ['5f06d71dba4', '289d0602ba5ac']}}}),
        ("5f06d71dba4", '', 'Irrelevant', {"comment": "Irrelevant", 'filters': {'id': {'eq': ['5f06d71dba4']}}}),
        ("", '{"filters": {"id": {"eq": ["5f06d71dba4"]}}}', "", {'filters': {'id': {'eq': ['5f06d71dba4']}}})
    ]
)
def test_args_to_filter_for_dismiss_and_resolve_alerts(alert_ids, customer_filters, comment, expected):
    from MicrosoftCloudAppSecurity import args_to_filter_for_dismiss_and_resolve_alerts
    res = args_to_filter_for_dismiss_and_resolve_alerts(alert_ids, customer_filters, comment)
    assert res == expected


client_mocker = Client(base_url='https://demistodev.eu2.portal.cloudappsecurity.com/api/v1')


def test_list_alerts_command(requests_mock):
    from MicrosoftCloudAppSecurity import list_alerts_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/5f06d71dba4289d0602ba5ac',
                      json=ALERT_BY_ID_DATA)
    res = list_alerts_command(client_mocker, {'alert_id': '5f06d71dba4289d0602ba5ac'})
    assert res.outputs == ALERT_BY_ID_DATA_CONTEXT


def test_list_activities_command(requests_mock):
    from MicrosoftCloudAppSecurity import list_activities_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/activities/'
                      '97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7',
                      json=ACTIVITIES_BY_ID_DATA)
    res = list_activities_command(client_mocker, {'activity_id': '97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7'})
    assert res.outputs == ACTIVITIES_BY_ID_DATA_CONTEXT


def test_list_files_command(requests_mock):
    from MicrosoftCloudAppSecurity import list_files_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/files/5f077ebfc3b664209dae1f6b',
                      json=FILES_BY_ID_DATA)
    res = list_files_command(client_mocker, {'file_id': '5f077ebfc3b664209dae1f6b'})
    context = res.to_context().get('EntryContext')
    assert context.get('MicrosoftCloudAppSecurity.Files(val.file_id == obj.file_id)') == FILES_BY_ID_DATA


def test_list_users_accounts_command(requests_mock):
    from MicrosoftCloudAppSecurity import list_users_accounts_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/entities/',
                      json=ENTITIES_BY_USERNAME_DATA)
    res = list_users_accounts_command(client_mocker,
                                      {'username': '{ "id": "7e14f6a3-185d-49e3-85e8-40a33d90dc90",'
                                                   ' "saas": 11161, "inst": 0 }'})
    assert ENTITIES_BY_USERNAME_DATA_CONTEXT == res.outputs


ALERT_BY_ID_DATA_CONTEXT = {
    'URL': 'https://demistodev.portal.cloudappsecurity.com/#/alerts/5f06d71dba4289d0602ba5ac',
    '_id': '5f06d71dba4289d0602ba5ac',
    'account': [{'em': 'dev@demistodev.onmicrosoft.com',
                 'entityType': 2,
                'id': '2827c1e7-edb6-4529-b50d-25984e968637',
                 'inst': 0,
                 'label': 'demisto dev',
                 'pa': 'dev@demistodev.onmicrosoft.com',
                 'saas': 11161,
                 'type': 'account'}],
    'comment': 'null',
    'contextId': 'ebac1a16-81bf-449b-8d43-5732c3c1d999',
    'description': "File policy 'block png files' was matched by 'image (2).png'",
    'file': [{'id': 'd10230e2-52db-4ec8-815b-c5484524d078|501f6179-e6f9-457c-9892-1590dee07ede',
               'label': 'image (2).png',
               'type': 'file'}],
    'handledByUser': 'null',
    'idValue': 15728642,
    'isSystemAlert': False,
    'policy': {'id': '5f01dce13de79160fbec4150',
               'label': 'block png files',
               'policyType': 'FILE',
               'type': 'policyRule'},
    'policyRule': [{'id': '5f01dce13de79160fbec4150',
                    'label': 'block png files',
                    'policyType': 'FILE',
                    'type': 'policyRule'}],
    'resolveTime': '2020-07-12T07:48:40.975Z',
    'service': [{'id': 15600,
                'label': 'Microsoft OneDrive for Business',
                 'type': 'service'}],
    'severityValue': 0,
    'statusValue': 1,
    'stories': [0],
    'threatScore': 19,
    'timestamp': 1594283802753,
    'title': 'block png files',
    'user': [{'id': 'dev@demistodev.onmicrosoft.com',
              'label': 'dev@demistodev.onmicrosoft.com',
              'type': 'user'}]
}

ALERT_BY_ID_DATA = {
    "_id": "5f06d71dba4289d0602ba5ac",
    "timestamp": 1594283802753,
    "entities": [
        {
            "id": "5f01dce13de79160fbec4150",
            "label": "block png files",
            "policyType": "FILE",
            "type": "policyRule"
        },
        {
            "id": 15600,
            "label": "Microsoft OneDrive for Business",
            "type": "service"
        },
        {
            "id": "d10230e2-52db-4ec8-815b-c5484524d078|501f6179-e6f9-457c-9892-1590dee07ede",
            "label": "image (2).png",
            "type": "file"
        },
        {
            "em": "dev@demistodev.onmicrosoft.com",
            "entityType": 2,
            "id": "2827c1e7-edb6-4529-b50d-25984e968637",
            "inst": 0,
            "label": "demisto dev",
            "pa": "dev@demistodev.onmicrosoft.com",
            "saas": 11161,
            "type": "account"
        },
        {
            "id": "dev@demistodev.onmicrosoft.com",
            "label": "dev@demistodev.onmicrosoft.com",
            "type": "user"
        }
    ],
    "title": "block png files",
    "description": "File policy 'block png files' was matched by 'image (2).png'",
    "stories": [
        0
    ],
    "policy": {
        "id": "5f01dce13de79160fbec4150",
        "label": "block png files",
        "policyType": "FILE",
        "type": "policyRule"
    },
    "contextId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
    "threatScore": 19,
    "isSystemAlert": False,
    "idValue": 15728642,
    "statusValue": 1,
    "severityValue": 0,
    "handledByUser": 'null',
    "comment": 'null',
    "resolveTime": "2020-07-12T07:48:40.975Z",
    "URL": "https://demistodev.portal.cloudappsecurity.com/#/alerts/5f06d71dba4289d0602ba5ac"
}

ACTIVITIES_BY_ID_DATA_CONTEXT = {
    '_id': '97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7',
    'aadTenantId': 'ebac1a16-81bf-449b-8d43-5732c3c1d999',
    'appId': 15600,
    'appName': 'Microsoft OneDrive for Business',
    'classifications': [],
    'collected': {'o365': {'blobCreated': '2020-07-18T18:21:10.6170000Z',
                  'blobId': '20200718182019454009710$20200718182110617003525$audit_sharepoint$Audit_SharePoint$emea0029'
                           }},
    'confidenceLevel': 20,
    'created': 1595096586840,
    'createdRaw': 1595096586840,
    'description': 'FilePreviewed',
    'description_id': 'EVENT_DESCRIPTION_BASIC_EVENT',
    'description_metadata': {'colon': '',
                             'dash': '',
                             'operation_name': 'FilePreviewed',
                             'target_object': ''},
    'device': {'clientIP': '8.8.8.8',
               'countryCode': 'IL',
               'userAgent': 'OneDriveMpc-Transform_Thumbnail/1.0'},
    'entityData': [{'displayName': 'Avishai Brandeis',
                    'id': {'id': 'avishai@demistodev.onmicrosoft.com',
                           'inst': 0,
                           'saas': 11161},
                    'resolved': True},
                   {'displayName': 'Avishai Brandeis',
                    'id': {'id': '3fa9f28b-eb0e-463a-ba7b-8089fe9991e2',
                           'inst': 0,
                           'saas': 11161},
                    'resolved': True}],
    'eventRouting': {'auditing': True, 'lograbber': True, 'scubaUnpacker': False},
    'eventType': 233580,
    'eventTypeName': 'EVENT_CATEGORY_UNSPECIFIED',
    'eventTypeValue': 'EVENT_O365_ONEDRIVE_GENERIC',
    'genericEventType': 'ENUM_ACTIVITY_GENERIC_TYPE_BASIC',
    'instantiation': 1595096584556,
    'instantiationRaw': 1595096584556,
    'internals': {'otherIPs': ['8.8.8.8']},
    'location': {'anonymousProxy': False,
                 'category': 0,
                 'categoryValue': 'NONE',
                 'city': 'Tel Aviv',
                 'countryCode': 'IL',
                 'isSatelliteProvider': False,
                 'latitude': 32.0679,
                 'longitude': 34.7604,
                 'organizationSearchable': 'Cellcom Group',
                 'region': 'Tel Aviv',
                 'regionCode': 'TA'},
    'lograbberService': {'gediEvent': True, 'o365EventGrabber': True},
    'mainInfo': {'eventObjects': [{'id': 'cac4b654-5fcf-44f0-818e-479cf8ae42ac',
                 'name': 'https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/',
                                   'objType': 1,
                                   'role': 3,
                                   'serviceObjectType': 'OneDrive Site Collection',
                                   'tags': []},
                                  {'id': 'avishai@demistodev.onmicrosoft.com',
                                   'instanceId': 0,
                                   'link': -162371649,
                                   'name': 'Avishai Brandeis',
                                   'objType': 21,
                                   'resolved': True,
                                   'role': 4,
                                   'saasId': 11161,
                                   'tags': []},
                                  {'id': '3fa9f28b-eb0e-463a-ba7b-8089fe9991e2',
                                   'instanceId': 0,
                                   'link': -162371649,
                                   'name': 'Avishai Brandeis',
                                   'objType': 23,
                                   'resolved': True,
                                   'role': 4,
                                   'saasId': 11161,
                                   'tags': ['5f01dbbc68df27c17aa6ca81']}],
                 'prettyOperationName': 'FilePreviewed',
                 'rawOperationName': 'FilePreviewed',
                 'type': 'basic'},
    'rawDataJson': {'ApplicationId': '4345a7b9-9a63-4910-a426-35363201d503',
                    'ClientIP': '8.8.8.8',
                    'CorrelationId': '3055679f-0048-2000-2b2a-29e5b1098433',
                    'CreationTime': '2020-07-18T18:18:33.0000000Z',
                    'DoNotDistributeEvent': True,
                    'EventSource': 'SharePoint',
                    'Id': '97ee2049-893e-4c9d-a312-08d82b46faf7',
                    'ItemType': 'File',
                    'ListId': '0d2a8402-c671-43cd-b8ec-b49882d43e08',
                    'ListItemUniqueId': '141133f2-6710-4f65-9c3b-c840a8d71483',

                    'ObjectId':
                    'https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/Documents/iban '
                    'example.docx',
                    'Operation': 'FilePreviewed',
                    'OrganizationId': 'ebac1a16-81bf-449b-8d43-5732c3c1d999',
                    'RecordType': 6,
                    'Site': 'cac4b654-5fcf-44f0-818e-479cf8ae42ac',
                    'SiteUrl': 'https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/',
                    'SourceFileExtension': 'docx',
                    'SourceFileName': 'iban example.docx',
                    'SourceRelativeUrl': 'Documents',
                    'UserAgent': 'OneDriveMpc-Transform_Thumbnail/1.0',
                    'UserId': 'avishai@demistodev.onmicrosoft.com',
                    'UserKey': '11111',
                    'UserType': 0,
                    'Version': 1,
                    'WebId': '8a6420f5-3cde-4d37-911c-ce86af6d3910',
                    'Workload': 'OneDrive'},
    'resolvedActor': {'id': '3fa9f28b-eb0e-463a-ba7b-8089fe9991e2',
                        'instanceId': '0',
                        'name': 'Avishai Brandeis',
                        'objType': '23',
                        'resolved': True,
                        'role': '4',
                        'saasId': '11161',
                        'tags': ['5f01dbbc68df27c17aa6ca81']},
    'saasId': 15600,
    'severity': 'INFO',
    'source': 2,
    'srcAppId': 11161,
    'tenantId': 97134000,
    'timestamp': 1595096313000,
    'timestampRaw': 1595096313000,
    'uid': '97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7',
    'user': {'userName': 'avishai@demistodev.onmicrosoft.com',
             'userTags': ['5f01dbbc68df27c17aa6ca81']},
    'userAgent': {'browser': 'MICROSOFT_ONEDRIVE_FOR_BUSINESS',
                  'deviceType': 'OTHER',
                  'family': 'MICROSOFT_ONEDRIVE_FOR_BUSINESS',
                  'name': 'Microsoft OneDrive for Business',
                  'nativeBrowser': True,
                  'operatingSystem': {'family': 'Unknown', 'name': 'Unknown'},
                  'os': 'OTHER',
                  'tags': ['000000000000000000000000'],
                  'type': 'Application',
                  'typeName': 'Application'}
}

ACTIVITIES_BY_ID_DATA = {
    "_id": "97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7",
    "tenantId": 97134000,
    "aadTenantId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
    "appId": 15600,
    "saasId": 15600,
    "timestamp": 1595096313000,
    "timestampRaw": 1595096313000,
    "instantiation": 1595096584556,
    "instantiationRaw": 1595096584556,
    "created": 1595096586840,
    "createdRaw": 1595096586840,
    "eventType": 233580,
    "eventTypeValue": "EVENT_O365_ONEDRIVE_GENERIC",
    "eventRouting": {
        "scubaUnpacker": False,
        "lograbber": True,
        "auditing": True
    },
    "device": {
        "clientIP": "8.8.8.8",
        "userAgent": "OneDriveMpc-Transform_Thumbnail/1.0",
        "countryCode": "IL"
    },
    "location": {
        "countryCode": "IL",
        "city": "Tel Aviv",
        "regionCode": "TA",
        "region": "Tel Aviv",
        "longitude": 34.7604,
        "latitude": 32.0679,
        "organizationSearchable": "Cellcom Group",
        "anonymousProxy": False,
        "isSatelliteProvider": False,
        "category": 0,
        "categoryValue": "NONE"
    },
    "user": {
        "userName": "avishai@demistodev.onmicrosoft.com",
        "userTags": [
            "5f01dbbc68df27c17aa6ca81"
        ]
    },
    "userAgent": {
        "family": "MICROSOFT_ONEDRIVE_FOR_BUSINESS",
        "name": "Microsoft OneDrive for Business",
        "operatingSystem": {
            "name": "Unknown",
            "family": "Unknown"
        },
        "type": "Application",
        "typeName": "Application",
        "deviceType": "OTHER",
        "nativeBrowser": True,
        "tags": [
            "000000000000000000000000"
        ],
        "os": "OTHER",
        "browser": "MICROSOFT_ONEDRIVE_FOR_BUSINESS"
    },
    "internals": {
        "otherIPs": [
            "8.8.8.8"
        ]
    },
    "mainInfo": {
        "eventObjects": [
            {
                "objType": 1,
                "role": 3,
                "tags": [],
                "name": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/",
                "id": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
                "serviceObjectType": "OneDrive Site Collection"
            },
            {
                "objType": 21,
                "role": 4,
                "tags": [],
                "name": "Avishai Brandeis",
                "instanceId": 0,
                "resolved": True,
                "saasId": 11161,
                "id": "avishai@demistodev.onmicrosoft.com",
                "link": -162371649
            },
            {
                "objType": 23,
                "role": 4,
                "tags": [
                    "5f01dbbc68df27c17aa6ca81"
                ],
                "name": "Avishai Brandeis",
                "instanceId": 0,
                "resolved": True,
                "saasId": 11161,
                "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                "link": -162371649
            }
        ],
        "rawOperationName": "FilePreviewed",
        "prettyOperationName": "FilePreviewed",
        "type": "basic"
    },
    "confidenceLevel": 20,
    "source": 2,
    "lograbberService": {
        "o365EventGrabber": True,
        "gediEvent": True
    },
    "srcAppId": 11161,
    "collected": {
        "o365": {
            "blobCreated": "2020-07-18T18:21:10.6170000Z",
            "blobId": "20200718182019454009710$20200718182110617003525$audit_sharepoint$Audit_SharePoint$emea0029"
        }
    },
    "rawDataJson": {
        "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
        "CreationTime": "2020-07-18T18:18:33.0000000Z",
        "RecordType": 6,
        "Operation": "FilePreviewed",
        "UserType": 0,
        "Workload": "OneDrive",
        "ClientIP": "8.8.8.8",
        "UserKey": "11111",
        "Version": 1,
        "ObjectId": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com"
                    "/Documents/iban example.docx",
        "CorrelationId": "3055679f-0048-2000-2b2a-29e5b1098433",
        "UserId": "avishai@demistodev.onmicrosoft.com",
        "ListItemUniqueId": "141133f2-6710-4f65-9c3b-c840a8d71483",
        "EventSource": "SharePoint",
        "SourceFileExtension": "docx",
        "UserAgent": "OneDriveMpc-Transform_Thumbnail/1.0",
        "SourceRelativeUrl": "Documents",
        "ItemType": "File",
        "SourceFileName": "iban example.docx",
        "Id": "97ee2049-893e-4c9d-a312-08d82b46faf7",
        "ApplicationId": "4345a7b9-9a63-4910-a426-35363201d503",
        "ListId": "0d2a8402-c671-43cd-b8ec-b49882d43e08",
        "WebId": "8a6420f5-3cde-4d37-911c-ce86af6d3910",
        "SiteUrl": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/",
        "Site": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
        "DoNotDistributeEvent": True
    },
    "resolvedActor": {
        "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
        "saasId": "11161",
        "instanceId": "0",
        "tags": [
            "5f01dbbc68df27c17aa6ca81"
        ],
        "objType": "23",
        "name": "Avishai Brandeis",
        "role": "4",
        "resolved": True
    },
    "uid": "97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7",
    "appName": "Microsoft OneDrive for Business",
    "eventTypeName": "EVENT_CATEGORY_UNSPECIFIED",
    "classifications": [],
    "entityData": {
        "0": {
            "displayName": "Avishai Brandeis",
            "id": {
                "id": "avishai@demistodev.onmicrosoft.com",
                "saas": 11161,
                "inst": 0
            },
            "resolved": True
        },
        "1": None,
        "2": {
            "displayName": "Avishai Brandeis",
            "id": {
                "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                "saas": 11161,
                "inst": 0
            },
            "resolved": True
        }
    },
    "description_id": "EVENT_DESCRIPTION_BASIC_EVENT",
    "description_metadata": {
        "target_object": "",
        "operation_name": "FilePreviewed",
        "colon": "",
        "dash": ""
    },
    "description": "FilePreviewed",
    "genericEventType": "ENUM_ACTIVITY_GENERIC_TYPE_BASIC",
    "severity": "INFO"
}

FILES_BY_ID_DATA = {
    "_id": "5f077ebfc3b664209dae1f6b",
    "_tid": 97134000,
    "appId": 15600,
    "id": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|56aa5551-0c4c-42d7-93f1-57ccdca766aa",
    "saasId": 15600,
    "instId": 0,
    "fileSize": 149,
    "createdDate": 1594326579000,
    "modifiedDate": 1594326594000,
    "driveId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
    "scanVersion": 4,
    "parentId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b",
    "alternateLink": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com"
                     "/Documents/20200325_104025.jpg.txt",
    "isFolder": False,
    "fileType": [
        4,
        "TEXT"
    ],
    "name": "20200325_104025.jpg.txt",
    "isForeign": False,
    "noGovernance": False,
    "fileAccessLevel": [
        0,
        "PRIVATE"
    ],
    "ownerAddress": "avishai@demistodev.onmicrosoft.com",
    "externalShares": [],
    "emails": [
        "avishai@demistodev.onmicrosoft.com"
    ],
    "groupIds": [],
    "groups": [],
    "domains": [
        "demistodev.onmicrosoft.com"
    ],
    "mimeType": "text/plain",
    "parentIds": [
        "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
    ],
    "ownerExternal": False,
    "fileExtension": "txt",
    "lastNrtTimestamp": 1594326781863,
    "effectiveParents": [
        "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
        "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
    ],
    "collaborators": [],
    "sharepointItem": {
        "UniqueId": "111111111111111",
        "ServerRelativeUrl": "/personal/avishai_demistodev_onmicrosoft_com/Documents/20200325_104025.jpg.txt",
        "Name": "20200325_104025.jpg.txt",
        "Length": 149,
        "TimeLastModified": "2020-07-09T20:29:54Z",
        "TimeCreated": "2020-07-09T20:29:39Z",
        "Author": {
            "sourceBitmask": 0,
            "oneDriveEmail": "avishai@demistodev.onmicrosoft.com",
            "trueEmail": "avishai@demistodev.onmicrosoft.com",
            "externalUser": False,
            "LoginName": "i:0#.f|membership|avishai@demistodev.onmicrosoft.com",
            "name": "Avishai Brandeis",
            "idInSiteCollection": "4",
            "sipAddress": "avishai@demistodev.onmicrosoft.com",
            "Email": "avishai@demistodev.onmicrosoft.com",
            "Title": "Avishai Brandeis"
        },
        "LinkingUrl": "",
        "parentUniqueId": "8f83a489-34b7-4bb6-a331-260d1291ef6b",
        "roleAssignments": [],
        "hasUniqueRoleAssignments": False,
        "urlFromMetadata": None,
        "ModifiedBy": {
            "LoginName": "i:0#.f|membership|tmcassp_fa02d7a6fe55edb22020060112572594@demistodev.onmicrosoft.com",
            "Title": "Cloud App Security Service Account for SharePoint",
            "Email": ""
        },
        "scopeId": "D853886D-DDEE-4A5D-BCB9-B6F072BC1413",
        "isFolder": False,
        "encodedAbsUrl": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/Documents/"
                         "20200325_104025.jpg.txt"
    },
    "siteCollection": "/personal/avishai_demistodev_onmicrosoft_com",
    "sitePath": "/personal/avishai_demistodev_onmicrosoft_com",
    "filePath": "/personal/avishai_demistodev_onmicrosoft_com/Documents/20200325_104025.jpg.txt",
    "spDomain": "https://demistodev-my.sharepoint.com",
    "siteCollectionId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
    "ftype": 4,
    "facl": 0,
    "fstat": 0,
    "unseenScans": 0,
    "fileStatus": [
        0,
        "EXISTS"
    ],
    "name_l": "20200325_104025.jpg.txt",
    "snapshotLastModifiedDate": "2020-07-09T22:15:39.820Z",
    "ownerName": "Avishai Brandeis",
    "originalId": "5f077ebfc3b664209dae1f6b",
    "dlpScanResults": [],
    "fTags": [],
    "enriched": True,
    "display_collaborators": [],
    "appName": "Microsoft OneDrive for Business",
    "actions": [
        {
            "task_name": "QuarantineTask",
            "display_title": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_TITLE",
            "type": "file",
            "governance_type": None,
            "bulk_support": True,
            "has_icon": True,
            "display_description": {
                "template": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_DESCRIPTION",
                "parameters": {
                    "fileName": "20200325_104025.jpg.txt"
                }
            },
            "bulk_display_description": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_BULK_DISPLAY_DESCRIPTION",
            "preview_only": False,
            "display_alert_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_TEXT",
            "display_alert_success_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_SUCCESS_TEXT",
            "is_blocking": None,
            "confirm_button_style": "red",
            "optional_notify": None,
            "uiGovernanceCategory": 1,
            "alert_display_title": None,
            "confirmation_button_text": None,
            "confirmation_link": None
        },
        {
            "task_name": "RescanFileTask",
            "display_title": "TASKS_ADALIBPY_RESCAN_FILE_DISPLAY_TITLE",
            "type": "file",
            "governance_type": None,
            "bulk_support": True,
            "has_icon": True,
            "display_description": None,
            "bulk_display_description": None,
            "preview_only": False,
            "display_alert_text": None,
            "display_alert_success_text": None,
            "is_blocking": None,
            "confirm_button_style": "red",
            "optional_notify": None,
            "uiGovernanceCategory": 0,
            "alert_display_title": None,
            "confirmation_button_text": None,
            "confirmation_link": None
        },
        {
            "task_name": "TrashFileTask",
            "display_title": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_TITLE",
            "type": "file",
            "governance_type": None,
            "bulk_support": True,
            "has_icon": True,
            "display_description": {
                "template": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_DESCRIPTION",
                "parameters": {
                    "fileName": "20200325_104025.jpg.txt"
                }
            },
            "bulk_display_description": "TASKS_ADALIBPY_TRASH_FILE_BULK_DISPLAY_DESCRIPTION",
            "preview_only": False,
            "display_alert_text": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_ALERT_TEXT",
            "display_alert_success_text": "TASKS_ADALIBPY_TRASH_FILE_ALERT_SUCCESS_TEXT",
            "is_blocking": None,
            "confirm_button_style": "red",
            "optional_notify": None,
            "uiGovernanceCategory": 1,
            "alert_display_title": None,
            "confirmation_button_text": None,
            "confirmation_link": None
        }
    ],
    "fileTypeDisplay": "File"
}

ENTITIES_BY_USERNAME_DATA_CONTEXT = {
    '_id': '5f01dc3d229037823e3b9e92',
    'actions': [],
    'appData': {'appId': 11161,
                'instance': 0,
                'name': 'Office 365',
                'saas': 11161},
    'displayName': 'MS Graph Groups',
    'domain': None,
    'email': None,
    'id': '7e14f6a3-185d-49e3-85e8-40a33d90dc90',
    'idType': 17,
    'identifiers': [],
    'ii': '11161|0|7e14f6a3-185d-49e3-85e8-40a33d90dc90',
    'isAdmin': False,
    'isExternal': True,
    'isFake': False,
    'lastSeen': '2020-07-19T06:59:24Z',
    'organization': None,
    'role': None,
    'scoreTrends': None,
    'sctime': None,
    'sid': None,
    'status': 2,
    'subApps': [],
    'threatScore': None,
    'type': 1,
    'userGroups': [{'_id': '5e6fa9ade2367fc6340f487e',
                   'description': 'App-initiated',
                    'id': '0000003b0000000000000000',
                    'name': 'Application (Cloud App Security)',
                    'usersCount': 562},
                   {'_id': '5e6fa9ace2367fc6340f4864',
                   'description': 'Either a user who is not a member of any of '
                                  'the managed domains you configured in '
                                  'General settings or a third-party app',
                    'id': '000000200000000000000000',
                    'name': 'External users',
                    'usersCount': 106}],
    'username': '{"id": "7e14f6a3-185d-49e3-85e8-40a33d90dc90", "saas": 11161, '
                '"inst": 0}'
}

ENTITIES_BY_USERNAME_DATA = {
    "data": [
        {
            "type": 1,
            "status": 2,
            "displayName": "MS Graph Groups",
            "id": "7e14f6a3-185d-49e3-85e8-40a33d90dc90",
            "_id": "5f01dc3d229037823e3b9e92",
            "userGroups": [
                {
                    "_id": "5e6fa9ade2367fc6340f487e",
                    "id": "0000003b0000000000000000",
                    "name": "Application (Cloud App Security)",
                    "description": "App-initiated",
                    "usersCount": 562
                },
                {
                    "_id": "5e6fa9ace2367fc6340f4864",
                    "id": "000000200000000000000000",
                    "name": "External users",
                    "description": 'Either a user who is not a member of any of '
                                   'the managed domains you configured in '
                                   'General settings or a third-party app',
                    "usersCount": 106
                }
            ],
            "identifiers": [],
            "sid": None,
            "appData": {
                "appId": 11161,
                "name": "Office 365",
                "saas": 11161,
                "instance": 0
            },
            "isAdmin": False,
            "isExternal": True,
            "email": None,
            "role": None,
            "organization": None,
            "lastSeen": "2020-07-19T06:59:24Z",
            "domain": None,
            "scoreTrends": None,
            "subApps": [],
            "threatScore": None,
            "idType": 17,
            "isFake": False,
            "ii": "11161|0|7e14f6a3-185d-49e3-85e8-40a33d90dc90",
            "actions": [],
            "username": "{\"id\": \"7e14f6a3-185d-49e3-85e8-40a33d90dc90\", \"saas\": 11161, \"inst\": 0}",
            "sctime": None
        }
    ],
    "hasNext": False,
    "max": 100,
    "total": 1,
    "moreThanTotal": False
}

DISMISSED_BY_ID_DATA = {
    "dismissed": 1
}

RESOLVED_BY_ID_DATA = {
    "resolved": 1
}
