import pytest

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


'''Function tests'''


class TestHelperFunctions:
    @pytest.mark.parametrize(argnames="input_raw, output_ec", argvalues=TEST_RAW_RESPONSE_TO_CONTEXT)
    def test_raw_response_to_context(self, input_raw, output_ec):
        from PhishLabsIOC_DRP import raw_response_to_context
        out_to_test = raw_response_to_context(cases=input_raw)
        assert output_ec == out_to_test
