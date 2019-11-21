import pytest
import json
from PhishLabsIOC_DRP import Client

'''Globals - Helper functions'''
TEST_RAW_RESPONSE_TO_CONTEXT = [
    (
        [
            {
                "caseId": "daa1e25e",
                "title": "Test-title",
                "description": "Test-description",
                "caseNumber": 1378051,
                "createdBy": {
                    "id": "30c2e916",
                    "name": "soc",
                    "displayName": "SOC PhishLabs"
                },
                "brand": "",
                "caseType": "Other",
                "resolutionStatus": "Threat Offline",
                "caseStatus": "Closed",
                "dateCreated": "2019-11-12T08:46:01Z",
                "dateClosed": "2019-11-12T09:20:06Z",
                "dateModified": "2019-11-12T09:20:06Z",
                "customer": "PhishLabs",
                "attachments": [
                    {
                        "id": "dab753fa-0528-11ea-909b-0eb92493f786",
                        "type": "Email",
                        "description": "Source Email for case creation",
                        "dateAdded": "2019-11-12T08:46:01Z",
                        "fileName": "msg.z6AH.eml",
                        "fileURL": "https://caseapi.phishlabs.com/v1/data/attachment/dab753fa"
                    }
                ],
                "formReceiver": 'false',
                "brandAbuseFlag": 'false',
                "appDate": "0001-01-01T00:00:00Z",
                "primaryMarketplace": 'false'
            },
            {
                "caseId": "83294b8d",
                "title": "Test-title",
                "description": "Test-description",
                "caseNumber": 1377827,
                "createdBy": {
                    "id": "30c2e916-c72d-11e3-860e-002590387e36",
                    "name": "soc.phishlabs",
                    "displayName": "SOC PhishLabs"
                },
                "brand": "",
                "caseType": "Other",
                "resolutionStatus": "Threat Offline",
                "caseStatus": "Closed",
                "dateCreated": "2019-11-12T04:33:02Z",
                "dateClosed": "2019-11-12T04:53:24Z",
                "dateModified": "2019-11-12T04:53:24Z",
                "customer": "PhishLabs",
                "attachments": [
                    {
                        "id": "833ecee6-0505-11ea-9b11-0ad24386a0d6",
                        "type": "Email",
                        "description": "Source Email for case creation",
                        "dateAdded": "2019-11-12T04:33:02Z",
                        "fileName": "msg.K-AH.eml",
                        "fileURL": "https://caseapi.phishlabs.com/v1/data/attachment/833ecee6-0505-11ea-9b11-0ad24386a0d6"
                    }
                ],
                "formReceiver": 'false',
                "brandAbuseFlag": 'false',
                "appDate": "0001-01-01T00:00:00Z",
                "primaryMarketplace": 'false'
            }
        ],
        [
            {
                'CaseID': "daa1e25e",
                'Title': "Test-title",
                'Description': "Test-description",
                'CaseNumber': 1378051,
                'ResolutionStatus': "Threat Offline",
                'CreatedBy': {
                    'ID': "30c2e916",
                    'Name': "soc",
                    'DisplayName': "SOC PhishLabs"
                },
                'CaseType': "Other",
                'CaseStatus': "Closed",
                'DateCreated': "2019-11-12T08:46:01Z",
                'DateClosed': "2019-11-12T09:20:06Z",
                'DateModified': "2019-11-12T09:20:06Z",
                'Customer': "PhishLabs",
                'Attachments': [
                    {
                        'ID': "dab753fa-0528-11ea-909b-0eb92493f786",
                        'Type': "Email",
                        'Description': "Source Email for case creation",
                        'DateAdded': "2019-11-12T08:46:01Z",
                        'FileName': "msg.z6AH.eml",
                        'FileURL': "https://caseapi.phishlabs.com/v1/data/attachment/dab753fa"
                    }
                ]
            },
            {
                'CaseID': "83294b8d",
                'Title': "Test-title",
                'Description': "Test-description",
                'CaseNumber': 1377827,
                'ResolutionStatus': "Threat Offline",
                'CreatedBy': {
                    'ID': "30c2e916-c72d-11e3-860e-002590387e36",
                    'Name': "soc.phishlabs",
                    'DisplayName': "SOC PhishLabs"
                },
                'CaseType': "Other",
                'CaseStatus': "Closed",
                'DateCreated': "2019-11-12T04:33:02Z",
                'DateClosed': "2019-11-12T04:53:24Z",
                'DateModified': "2019-11-12T04:53:24Z",
                'Customer': "PhishLabs",
                'Attachments': [
                    {
                        'ID': "833ecee6-0505-11ea-9b11-0ad24386a0d6",
                        'Type': "Email",
                        'Description': "Source Email for case creation",
                        'DateAdded': "2019-11-12T04:33:02Z",
                        'FileName': "msg.K-AH.eml",
                        'FileURL': "https://caseapi.phishlabs.com/v1/data/attachment/833ecee6-0505-11ea-9b11-0ad24386a0d6"
                    }
                ]
            }
        ]
    )
]

'''Globals - Command functions'''
CLIENT = Client(base_url='https://caseapi.phishlabs.com/v1/data')
RAW_RESPONSE = {
    "header": {
        "id": "d2d9d54e-0c42-11ea-8f4c-0efb1918365c",
        "queryParams": {
            "format": "json",
            "maxRecords": 20
        },
        "requestDate": "2019-11-21T09:39:33.308765885Z",
        "returnResult": 20,
        "totalResult": 39570,
        "user": "api.ioc.demisto"
    },
    "data": [
        {
            "caseId": "1",
            "title": "Test title",
            "description": "Description Test",
            "caseNumber": 1,
            "createdBy": {
                "id": "1",
                "name": "soc.phishlabs",
                "displayName": "SOC PhishLabs"
            },
            "brand": "",
            "caseType": "Other",
            "resolutionStatus": "Threat Offline",
            "caseStatus": "Closed",
            "dateCreated": "2019-11-21T07:31:01Z",
            "dateClosed": "2019-11-21T08:15:25Z",
            "dateModified": "2019-11-21T08:15:25Z",
            "customer": "PhishLabs",
            "attachments": [
                {
                    "id": "1",
                    "type": "Email",
                    "description": "Source Email for case creation",
                    "dateAdded": "2019-11-21T07:31:01Z",
                    "fileName": "google.com",
                    "fileURL": "https://google.com"
                }
            ],
            "formReceiver": 'false',
            "brandAbuseFlag": 'false',
            "appDate": "0001-01-01T00:00:00Z",
            "primaryMarketplace": 'false'
        },
        {
            "caseId": "2",
            "title": "Test title",
            "description": "Description Test",
            "caseNumber": '2',
            "createdBy": {
                "id": "2",
                "name": "soc.phishlabs",
                "displayName": "SOC PhishLabs"
            },
            "brand": "",
            "caseType": "Other",
            "resolutionStatus": "Threat Offline",
            "caseStatus": "Closed",
            "dateCreated": "2019-11-21T04:59:01Z",
            "dateClosed": "2019-11-21T05:06:35Z",
            "dateModified": "2019-11-21T05:06:35Z",
            "customer": "PhishLabs",
            "attachments": [
                {
                    "id": "2",
                    "type": "Email",
                    "description": "Source Email for case creation",
                    "dateAdded": "2019-11-21T04:59:02Z",
                    "fileName": "google.com",
                    "fileURL": "https://google.com"
                }
            ],
            "formReceiver": 'false',
            "brandAbuseFlag": 'false',
            "appDate": "0001-01-01T00:00:00Z",
            "primaryMarketplace": 'false'
        }
    ]
}

INCIDENTS = [
    {
        'name': 'PhishLabs IOC - DRP: 1',
        'occurred': '2019-11-21T07:31:01Z',
        'rawJSON': json.dumps(RAW_RESPONSE.get('data', [])[0])
    },
    {
        'name': 'PhishLabs IOC - DRP: 2',
        'occurred': '2019-11-21T04:59:01Z',
        'rawJSON': json.dumps(RAW_RESPONSE.get('data', [])[1])
    }
]

INCIDENTS_LAST_RUN_TIME = {'latsRun': '2019-11-21T07:31:01Z'}


'''Function tests'''


class TestHelperFunctions:
    @pytest.mark.parametrize(argnames="input_raw, output_ec", argvalues=TEST_RAW_RESPONSE_TO_CONTEXT)
    def test_raw_response_to_context(self, input_raw, output_ec):
        from PhishLabsIOC_DRP import raw_response_to_context
        out_to_test = raw_response_to_context(cases=input_raw)
        assert output_ec == out_to_test


class TestCommandsFunctions(object):
    def test_fetch_incidents_command(self, requests_mock):
        from PhishLabsIOC_DRP import fetch_incidents_command
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases',
                          json=RAW_RESPONSE)
        incidents, new_last_run = fetch_incidents_command(client=CLIENT,
                                                          fetch_time="7 days",
                                                          max_records="20",
                                                          last_run="2018-10-24T14:13:20+00:00")
        assert INCIDENTS_LAST_RUN_TIME == new_last_run, "Last run value isn't correct"
        assert INCIDENTS == incidents, 'incidents parsing isn\'t correct'

    def test_fetch_incidents_no_last_run_command(self, requests_mock):
        from PhishLabsIOC_DRP import fetch_incidents_command
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases',
                          json=RAW_RESPONSE)
        incidents, new_last_run = fetch_incidents_command(client=CLIENT,
                                                          fetch_time="7 days",
                                                          max_records="20",
                                                          last_run="")
        assert INCIDENTS_LAST_RUN_TIME == new_last_run, "Last run value isn't correct"
        assert INCIDENTS == incidents, 'incidents parsing isn\'t correct'
