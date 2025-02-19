import copy
from datetime import datetime, UTC
import pytest
from CommonServerPython import DemistoException
import demistomock as demisto
from ArcherV2 import Client, extract_from_xml, generate_field_contents, get_errors_from_res, generate_field_value, \
    fetch_incidents, get_fetch_time, parser, OCCURRED_FORMAT, search_records_by_report_command, \
    search_records_soap_request, upload_and_associate_command, validate_xml_conditions, construct_generic_filter_condition, \
    FilterConditionTypes

BASE_URL = 'https://test.com/'

GET_TOKEN_SOAP = '<?xml version="1.0" encoding="utf-8"?>' + \
                 '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"' \
                 ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
                 ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body>' + \
                 '        <CreateUserSessionFromInstanceResponse xmlns="http://archer-tech.com/webservices/">' + \
                 '            <CreateUserSessionFromInstanceResult>TOKEN</CreateUserSessionFromInstanceResult>' + \
                 '        </CreateUserSessionFromInstanceResponse>' + \
                 '    </soap:Body>' + \
                 '</soap:Envelope>'

XML_FOR_TEST = '<?xml version="1.0" encoding="utf-8"?>' + \
               '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
               'xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
               '    <soap:Body>' + \
               '        <GetValueListForField xmlns="http://archer-tech.com/webservices/">' + \
               '            <fieldId>6969</fieldId>' + \
               '        </GetValueListForField>' + \
               '    </soap:Body>' + \
               '</soap:Envelope>'

GET_LEVEL_RES = [{"IsSuccessful": True, "RequestedObject": {"Id": 123}}]

FIELD_DEFINITION_RES = [
    {
        "IsSuccessful": True,
        "RequestedObject": {
            "Id": 1, "Type": 7, "Name": "External Links", "IsRequired": False
        }
    },
    {
        "IsSuccessful": True,
        "RequestedObject": {
            "Id": 2, "Type": 1, "Name": "Device Name", "IsRequired": True, "RelatedValuesListId": 8
        }
    }
]

GET_LEVELS_BY_APP = {
    'level': 123, 'mapping': {'1': {
        'Type': 7, 'Name': 'External Links', 'FieldId': "1", 'IsRequired': False, 'RelatedValuesListId': None},
        '2': {
            'Type': 1, 'Name': 'Device Name', 'FieldId': "2",
            'IsRequired': True, 'RelatedValuesListId': 8}
    }}

GET_FIElD_DEFINITION_RES = {
    "RequestedObject": {"RelatedValuesListId": 62, "Type": 4},
    "IsSuccessful": True,
    "ValidationMessages": []
}

VALUE_LIST_RES = {
    "RequestedObject": {
        "Children": [
            {"Data": {"Id": 471, "Name": "Low", "IsSelectable": True}},
            {"Data": {"Id": 472, "Name": "Medium", "IsSelectable": True}},
            {"Data": {"Id": 473, "Name": "High", "IsSelectable": True}}]},
    "IsSuccessful": True, "ValidationMessages": []
}

NESTED_VALUE_LIST_RES = {
    "Links": [],
    "RequestedObject": {
        "Children": [
            {
                "Data": {
                    "Id": 83998,
                    "Name": "Corporate (Reportable)",
                    "IsSelectable": False,
                },
                "Children": [
                    {
                        "Data": {
                            "Id": 88888,
                            "Name": "level 2",
                            "IsSelectable": False
                        },
                        "Depth": 1
                    }
                ],
                "Depth": 0
            },
            {
                "Data": {
                    "Id": 83999,
                    "Name": "Group & Other Non-Healthcare (Reportable)",
                    "IsSelectable": False,
                    "Generation": 0,
                },
                "Children": [
                    {
                        "Data": {
                            "Id": 84000,
                            "Name": "Group D&L, Run-off Businesses (Operating)",
                            "IsSelectable": False,
                        },
                        "Children": [],
                        "Depth": 1
                    }
                ],
                "Depth": 0
            },
            {
                "Data": {
                    "Id": 84001,
                    "Name": "Health Services (Reportable)",
                    "IsSelectable": False,
                },
                "Children": [
                    {
                        "Data": {
                            "Id": 84002,
                            "Name": "Pharmacy Operations (Operating)",
                            "IsSelectable": False,
                            "Generation": 1,
                        },
                        "Children": [
                            {
                                "Data": {
                                    "Id": 84003,
                                    "Name": "Cigna Home Delivery (Sub Segments)",
                                    "IsSelectable": False,
                                },
                                "Children": [],
                                "Depth": 2
                            },
                            {
                                "Data": {
                                    "Id": 84004,
                                    "Name": "ESI PBM (including Evicore) (Sub Segments)",
                                    "IsSelectable": False,
                                },
                                "Children": [],
                                "Depth": 2
                            }
                        ],
                        "Depth": 1
                    }
                ],
                "Depth": 0
            },
            {
                "Data": {
                    "Id": 84005,
                    "Name": "Integrated Medical (Reportable)",
                    "IsSelectable": False,
                },
                "Children": [
                    {
                        "Data": {
                            "Id": 84006,
                            "Name": "Commercial (Operating)",
                            "IsSelectable": False,
                        },
                        "Children": [
                            {
                                "Data": {
                                    "Id": 84007,
                                    "Name": "Behavioral (Sub Segments)",
                                    "IsSelectable": False,
                                },
                                "Children": [],
                                "Depth": 2
                            },
                        ],
                        "Depth": 1
                    },
                    {
                        "Data": {
                            "Id": 84012,
                            "Name": "Government (Operating)",
                            "IsSelectable": False,
                        },
                        "Children": [
                            {
                                "Data": {
                                    "Id": 84013,
                                    "Name": "CareAllies (Sub Segments)",
                                    "IsSelectable": False,
                                },
                                "Children": [],
                                "Depth": 2
                            },
                        ],
                        "Depth": 1
                    }
                ],
                "Depth": 0
            },
            {
                "Data": {
                    "Id": 107694,
                    "Name": "US Commercial",
                    "IsSelectable": False,
                },
                "Children": [],
                "Depth": 0
            },
        ]
    },
    "IsSuccessful": "true",
    "ValidationMessages": []
}

VALUE_LIST_RES_FOR_SOURCE = {
    "RequestedObject": {
        "Children": [
            {"Data": {"Id": 471, "Name": "ArcSight", "IsSelectable": True}},
            {"Data": {"Id": 472, "Name": "Medium", "IsSelectable": True}},
            {"Data": {"Id": 473, "Name": "High", "IsSelectable": True}}]},
    "IsSuccessful": True, "ValidationMessages": []
}

VALUE_LIST_FIELD_DATA = {
    "FieldId": 304, "ValuesList": [
        {"Id": 471, "Name": "Low", "IsSelectable": True, 'Parent': 'root', 'Depth': None},
        {"Id": 472, "Name": "Medium", "IsSelectable": True, 'Parent': 'root', 'Depth': None},
        {"Id": 473, "Name": "High", "IsSelectable": True, 'Parent': 'root', 'Depth': None}]}

RES_WITH_ERRORS = {
    'ValidationMessages': [
        {'ResourcedMessage': 'The Type field is a required field.'},
        {'ResourcedMessage': 'The Device Name field is a required field.'}]
}

GET_RECORD_RES_failed = {'ValidationMessages': [{'ResourcedMessage': 'No resource found.'}]}

GET_RECORD_RES_SUCCESS = \
    {
        "Links": [],
        "RequestedObject": {
            "Id": 1010,
            "LevelId": 123,
            "FieldContents": {
                "2": {
                    "Type": 1,
                    "Value": "The device name",
                    "FieldId": 2
                }
            }
        },
        "IsSuccessful": True,
        "ValidationMessages": []
    }

INCIDENT_RECORD = {
    "record": {
        "Id": "227602",
        "Status": "New",
        "Name": "Incident 01",
        "Date/Time Reported": "2018-03-26T10:03:32.243Z"
    },
    "raw": {
        "@contentId": "227602",
        "@levelId": "67",
        "@levelGuid": "b0c2d9a1-167c-4fee-ad91-4b4e7b098b4b",
        "@moduleId": "75",
        "@parentId": "0",
        "Field": [
            {
                "@id": "302",
                "@guid": "3ec0f462-4c17-4036-b0fa-2f04f3aba3d0",
                "@type": "4",
                "ListValues": {
                    "ListValue": {
                        "@id": "466",
                        "@displayName": "New",
                        "#text": "New"
                    }
                }
            },
            {
                "@id": "305",
                "@guid": "9c5e3de1-299b-430f-998a-185ad86e2e79",
                "@type": "3",
                "@xmlConvertedValue": "2018-03-26T10:03:32.243Z",
                "#text": "26/03/2018 06:03:32"
            }
        ]
    }
}

INCIDENT_RECORD_US_TZ = {
    "record": {
        "Id": "227603",
        "Title": "Test",
        "created date": "2/25/2021 8:45:55 AM"
    },
    "raw": {
        "@contentId": "227603",
        "@levelId": "67",
        "@levelGuid": "b0c2d9a1-167c-4fee-ad91-4b4e7b098b4b",
        "@moduleId": "75",
        "@parentId": "0",
        "Field": [
            {
                "@id": "35339",
                "@guid": "9c5e3de1-299b-430f-998a-185ad86e2e79",
                "@type": "1",
                "#text": "Test"
            },
            {
                "@id": "53075",
                "@guid": "9c5e3de1-299b-430f-998a-185ad86e2e80",
                "@type": "21",
                "@xmlConvertedValue": "2021-02-25T08:45:55.977Z",
                "#text": "2/25/2021 8:45:55 AM"
            }
        ]
    }
}

SEARCH_RECORDS_RES = \
    '<?xml version="1.0" encoding="utf-8"?>' + \
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"' \
    ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">' + \
    '    <soap:Body>' + \
    '        <ExecuteSearchResponse xmlns="http://archer-tech.com/webservices/">' + \
    '            <ExecuteSearchResult>' + \
    '&lt;?xml version="1.0" encoding="utf-16"?&gt;&lt;Records count="6"&gt;&lt;Metadata&gt;&lt;' \
    'FieldDefinitions&gt;&lt;FieldDefinition id="2" name="Device Name" alias="Name_Full" /&gt;&lt;' \
    '/FieldDefinitions&gt;&lt;/Metadata&gt;&lt;LevelCounts&gt;&lt;LevelCount id="37" count="6" /&gt;&lt;' \
    '/LevelCounts&gt;&lt;Record contentId="238756" levelId="37" moduleId="84" parentId="0"&gt;&lt;Field id="2" guid=' \
    '"9bc24614-2bc7-4849-a3a3-054729854ab4" type="1"&gt;DEVICE NAME&lt;/Field&gt;&lt;/Record&gt;&lt;/Records&gt;' + \
    '            </ExecuteSearchResult>' + \
    '        </ExecuteSearchResponse>' + \
    '    </soap:Body>' + \
    '</soap:Envelope>'

GET_RESPONSE_NOT_SUCCESSFUL_JSON = {"IsSuccessful": False, "RequestedObject": None,
                                    "ValidationMessages": [{"Reason": "Validation", "Severity": 3,
                                                            "MessageKey": "ValidationMessageTemplates"
                                                                          ":LoginNotValid",
                                                            "Description": "",
                                                            "Location": -1,
                                                            "ErroredValue": None,
                                                            "Validator": "ArcherApi."
                                                                         "Controllers.Security"
                                                                         "Controller, ArcherApi, "
                                                                         "Version=6.5.200.1045, "
                                                                         "Culture=neutral, "
                                                                         "PublicKeyToken=null",
                                                            "XmlData": None,
                                                            "ResourcedMessage": None}]}

GET_RESPONSE_SUCCESSFUL_JSON = {"IsSuccessful": True, "RequestedObject": {'SessionToken': 'session-id'}}

SEARCH_RECORDS_BY_REPORT_RES = \
    '<Records count="18">' + \
    '<Metadata>' + \
    '    <FieldDefinitions>' + \
    '       <FieldDefinition id="1580" name="Policy Name" alias="Policy_Name"/>' + \
    '        <FieldDefinition id="1583" name="Policy Statement"' + \
    '                         alias="Policy_Statement"/>' + \
    '    </FieldDefinitions>' + \
    '</Metadata>' + \
    '<LevelCounts>' + \
    '    <LevelCount id="3" count="18"/>' + \
    '</LevelCounts>' + \
    '<Record contentId="1720" levelId="3" moduleId="65" parentId="0">' + \
    '    <Field id="1580" type="1">00.0 Introduction</Field>' + \
    '    <Field id="1583" type="1">Information' + \
    '    </Field>' + \
    '</Record>' + \
    '</Records>'

MOCK_READABLE_SEARCH_RECORDS_BY_REPORT = "### Search records by report results\n|Id|Policy Name|Policy " \
                                         "Statement|\n|---|---|---|\n| 1720 | 00.0 Introduction | Information |\n"

MOCK_RESULTS_SEARCH_RECORDS_BY_REPORT = {
    'Records': {'@count': '18', 'Metadata': {'FieldDefinitions': {
        'FieldDefinition': [{'@id': '1580', '@name': 'Policy Name', '@alias': 'Policy_Name'},
                            {'@id': '1583', '@name': 'Policy Statement', '@alias': 'Policy_Statement'}]}},
                'LevelCounts': {'LevelCount': {'@id': '3', '@count': '18'}},
                'Record': {'@contentId': '1720', '@levelId': '3',
                           '@moduleId': '65',
                           '@parentId': '0',
                           'Field': [{'@id': '1580', '@type': '1',
                                      '#text': '00.0 Introduction'},
                                     {'@id': '1583', '@type': '1',
                                      '#text': "Information"}]}}
}

GET_LEVEL_RES_2 = [
    {
        "RequestedObject": {
            "Type": 1,
            "Id": 1580,
            "LevelId": 3,
            "Name": "Policy Name",
            "Alias": "Policy_Name"
        },
        "IsSuccessful": True
    },
    {
        "RequestedObject": {
            "Type": 1,
            "Id": 1583,
            "LevelId": 3,
            "Name": "Policy Statement",
            "Alias": "Policy_Statement"
        },
        "IsSuccessful": True
    }
]

RES_DEPTH_0 = {'FieldId': 304, 'ValuesList': [
    {'Id': 83998, 'Name': 'Corporate (Reportable)', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0},
    {'Id': 83999, 'Name': 'Group & Other Non-Healthcare (Reportable)', 'IsSelectable': False, 'Parent': 'root',
     'Depth': 0},
    {'Id': 84001, 'Name': 'Health Services (Reportable)', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0},
    {'Id': 84005, 'Name': 'Integrated Medical (Reportable)', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0},
    {'Id': 107694, 'Name': 'US Commercial', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0}]}

RES_DEPTH_1 = {'FieldId': 304, 'ValuesList': [
    {'Id': 83998, 'Name': 'Corporate (Reportable)', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0},
    {'Id': 88888, 'Name': 'level 2', 'IsSelectable': False, 'Parent': 'Corporate (Reportable)', 'Depth': 1},
    {'Id': 83999, 'Name': 'Group & Other Non-Healthcare (Reportable)', 'IsSelectable': False, 'Parent': 'root',
     'Depth': 0},
    {'Id': 84000, 'Name': 'Group D&L, Run-off Businesses (Operating)', 'IsSelectable': False,
     'Parent': 'Group & Other Non-Healthcare (Reportable)', 'Depth': 1},
    {'Id': 84001, 'Name': 'Health Services (Reportable)', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0},
    {'Id': 84002, 'Name': 'Pharmacy Operations (Operating)', 'IsSelectable': False,
     'Parent': 'Health Services (Reportable)', 'Depth': 1},
    {'Id': 84005, 'Name': 'Integrated Medical (Reportable)', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0},
    {'Id': 84006, 'Name': 'Commercial (Operating)', 'IsSelectable': False,
     'Parent': 'Integrated Medical (Reportable)', 'Depth': 1},
    {'Id': 84012, 'Name': 'Government (Operating)', 'IsSelectable': False,
     'Parent': 'Integrated Medical (Reportable)', 'Depth': 1},
    {'Id': 107694, 'Name': 'US Commercial', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0}]}

RES_DEPTH_2 = {'FieldId': 304, 'ValuesList': [
    {'Id': 83998, 'Name': 'Corporate (Reportable)', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0},
    {'Id': 88888, 'Name': 'level 2', 'IsSelectable': False, 'Parent': 'Corporate (Reportable)', 'Depth': 1},
    {'Id': 83999, 'Name': 'Group & Other Non-Healthcare (Reportable)', 'IsSelectable': False, 'Parent': 'root',
     'Depth': 0},
    {'Id': 84000, 'Name': 'Group D&L, Run-off Businesses (Operating)', 'IsSelectable': False,
     'Parent': 'Group & Other Non-Healthcare (Reportable)', 'Depth': 1},
    {'Id': 84001, 'Name': 'Health Services (Reportable)', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0},
    {'Id': 84002, 'Name': 'Pharmacy Operations (Operating)', 'IsSelectable': False,
     'Parent': 'Health Services (Reportable)', 'Depth': 1},
    {'Id': 84003, 'Name': 'Cigna Home Delivery (Sub Segments)', 'IsSelectable': False,
     'Parent': 'Pharmacy Operations (Operating)', 'Depth': 2},
    {'Id': 84004, 'Name': 'ESI PBM (including Evicore) (Sub Segments)', 'IsSelectable': False,
     'Parent': 'Pharmacy Operations (Operating)', 'Depth': 2},
    {'Id': 84005, 'Name': 'Integrated Medical (Reportable)', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0},
    {'Id': 84006, 'Name': 'Commercial (Operating)', 'IsSelectable': False,
     'Parent': 'Integrated Medical (Reportable)', 'Depth': 1},
    {'Id': 84007, 'Name': 'Behavioral (Sub Segments)', 'IsSelectable': False, 'Parent': 'Commercial (Operating)',
     'Depth': 2},
    {'Id': 84012, 'Name': 'Government (Operating)', 'IsSelectable': False,
     'Parent': 'Integrated Medical (Reportable)', 'Depth': 1},
    {'Id': 84013, 'Name': 'CareAllies (Sub Segments)', 'IsSelectable': False, 'Parent': 'Government (Operating)',
     'Depth': 2},
    {'Id': 107694, 'Name': 'US Commercial', 'IsSelectable': False, 'Parent': 'root', 'Depth': 0}]}


class TestArcherV2:
    def test_extract_from_xml(self):
        field_id = extract_from_xml(XML_FOR_TEST, 'Envelope.Body.GetValueListForField.fieldId')
        assert field_id == '6969'

    def test_get_level_by_app_id(self, requests_mock):
        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}, 'IsSuccessful': True})
        requests_mock.get(BASE_URL + 'api/core/system/level/module/1', json=GET_LEVEL_RES)
        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/level/123', json=FIELD_DEFINITION_RES)
        client = Client(BASE_URL, '', '', '', '', 400)
        levels = client.get_level_by_app_id('1')
        assert levels == GET_LEVELS_BY_APP

    @pytest.mark.parametrize('requested_object, is_successful',
                             [(GET_RESPONSE_NOT_SUCCESSFUL_JSON, False),
                              (GET_RESPONSE_SUCCESSFUL_JSON, True)])
    def test_update_session(self, mocker, requests_mock, requested_object, is_successful):
        requests_mock.post(BASE_URL + 'api/core/security/login', json=requested_object)
        mocker.patch.object(demisto, 'results')
        client = Client(BASE_URL, '', '', '', '', 400)
        if is_successful:
            client.create_session()
            assert demisto.results.call_count == 0
        else:
            with pytest.raises(SystemExit) as e:
                # in case login wasn't successful, return_error will exit with a reason (for example, LoginNotValid)
                # return_error reached
                client.create_session()
            assert e

    def test_update_session_fail_parsing(self, mocker):
        """
        Given:
            an exception raised from _http_request who failed to pares json object
        When:
            - initiating session
        Then:
            - Raise exception with message to check the provided url
        """
        mocker.patch.object(Client, '_http_request', side_effect=DemistoException("Failed to parse json object from "
                                                                                  "response: b\"<html><head><script>"
                                                                                  "window.top.location='/Default.aspx';"
                                                                                  "</script></head><body>"
                                                                                  "</body></html>"))
        client = Client(BASE_URL, '', '', '', '', 400)
        with pytest.raises(DemistoException) as e:
            client.create_session()
        assert "Check the given URL, it can be a redirect issue" in str(e.value)

    def test_generate_field_contents(self):
        """
        Given:
            a string of fields values with a \\ character
        When:
            - loading a json object from the string object
        Then:
            - return a valid json object
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        field = generate_field_contents(client, '{"Device Name":"Macbook\\Name\\\"Test"}', GET_LEVELS_BY_APP['mapping'],
                                        {"depth": 1})
        assert field == {'2': {'Type': 1, 'Value': 'Macbook\\Name\"Test', 'FieldId': '2'}}

    def test_get_errors_from_res(self):
        errors = get_errors_from_res(RES_WITH_ERRORS)
        assert errors == 'The Type field is a required field.\nThe Device Name field is a required field.'

    def test_get_record_failed(self, requests_mock):
        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}, 'IsSuccessful': True})
        requests_mock.get(BASE_URL + 'api/core/content/1010', json=GET_RECORD_RES_failed)
        client = Client(BASE_URL, '', '', '', '', 400)
        record, res, errors = client.get_record(75, 1010, {"depth": 1})
        assert errors == 'No resource found.'
        assert res
        assert record == {}

    def test_get_record_success(self, requests_mock):
        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}, 'IsSuccessful': True})
        requests_mock.get(BASE_URL + 'api/core/content/1010', json=GET_RECORD_RES_SUCCESS)
        requests_mock.get(BASE_URL + 'api/core/system/level/module/1', json=GET_LEVEL_RES)
        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/level/123', json=FIELD_DEFINITION_RES)
        client = Client(BASE_URL, '', '', '', '', 400)
        record, res, errors = client.get_record(1, 1010, {"depth": 1})
        assert errors is None
        assert res
        assert record == {'Device Name': 'The device name', 'Id': 1010}

    def test_record_to_incident(self):
        client = Client(BASE_URL, '', '', '', '', 400)
        record = copy.deepcopy(INCIDENT_RECORD)
        record['raw']['Field'][1]['@xmlConvertedValue'] = '2018-03-26T10:03:00Z'
        incident, incident_created_time = client.record_to_incident(record, 75, '305')
        assert incident_created_time == datetime(2018, 3, 26, 10, 3, tzinfo=UTC)
        assert incident['name'] == 'RSA Archer Incident: 227602'
        assert incident['occurred'] == '2018-03-26T10:03:00Z'

    def test_search_records(self, requests_mock):
        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}, 'IsSuccessful': True})
        requests_mock.post(BASE_URL + 'ws/general.asmx', text=GET_TOKEN_SOAP)

        requests_mock.get(BASE_URL + 'api/core/system/level/module/1', json=GET_LEVEL_RES)
        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/level/123', json=FIELD_DEFINITION_RES)
        requests_mock.post(BASE_URL + 'ws/search.asmx', text=SEARCH_RECORDS_RES)
        client = Client(BASE_URL, '', '', '', '', 400)
        records, raw_res = client.search_records(1, ['External Links', 'Device Name'])
        assert raw_res
        assert len(records) == 1
        assert records[0]['record']['Id'] == '238756'
        assert records[0]['record']['Device Name'] == 'DEVICE NAME'

    @pytest.mark.parametrize(
        'field_name, field_to_search_by_id, expected_condition',
        [
            pytest.param(
                # Inputs ↓
                'id_field_name',
                '',
                # Expected ↓
                '<TextFilterCondition>'
                '<Operator>Contains</Operator>'
                '<Field name="id_field_name">field_id</Field>'
                '<Value>1234</Value>'
                '</TextFilterCondition>',
                id='Generic text filter',
            ),
            pytest.param(
                # Inputs ↓
                'id_field_name',
                'id_field_name',
                # Expected ↓
                '<ContentFilterCondition>'
                '<Level>5678</Level>'
                '<Operator>Equals</Operator>'
                '<Values><Value>1234</Value></Values>'
                '</ContentFilterCondition>',
                id='Content filter by ID',
            )

        ]
    )
    def test_search_records_soap_request(
        self,
        field_name: str,
        field_to_search_by_id: str,
        expected_condition: str
    ):
        """
        Given:
            - Fields to search on records and id fields to search by ID.

        When:
            - Running search_records_soap_request to build the XML body.

        Then:
            - Ensure the correct condition is exist in the XML request body.
        """
        xml_request = search_records_soap_request('token', 'app_id', 'display_fields', 'field_id',
                                                  field_name, '1234', field_to_search_by_id=field_to_search_by_id,
                                                  level_id='5678')

        assert expected_condition in xml_request

    def test_get_field_value_list(self, requests_mock):
        cache = demisto.getIntegrationContext()
        cache['fieldValueList'] = {}
        demisto.setIntegrationContext(cache)

        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}, 'IsSuccessful': True})
        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/304', json=GET_FIElD_DEFINITION_RES)
        requests_mock.get(BASE_URL + 'api/core/system/valueslistvalue/valueslist/62', json=VALUE_LIST_RES)
        client = Client(BASE_URL, '', '', '', '', 400)
        field_data = client.get_field_value_list(304, 1)
        assert field_data == VALUE_LIST_FIELD_DATA

    @pytest.mark.parametrize('args, expected_response', [(0, RES_DEPTH_0), (1, RES_DEPTH_1), (2, RES_DEPTH_2)])
    def test_get_field_value_list_nested_response(self, requests_mock, args, expected_response):
        cache = demisto.getIntegrationContext()
        cache['fieldValueList'] = {}
        demisto.setIntegrationContext(cache)

        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}, 'IsSuccessful': True})
        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/304', json=GET_FIElD_DEFINITION_RES)
        requests_mock.get(BASE_URL + 'api/core/system/valueslistvalue/valueslist/62', json=NESTED_VALUE_LIST_RES)
        client = Client(BASE_URL, '', '', '', '', 400)
        field_data = client.get_field_value_list(304, args)
        assert field_data.get('FieldId') == expected_response.get('FieldId')
        for expected, result in zip(expected_response.get('ValuesList'), field_data.get('ValuesList')):
            assert expected == result

    def test_generate_field_value_text_input(self):
        client = Client(BASE_URL, '', '', '', '', 400)
        field_key, field_value = generate_field_value(client, "", {'Type': 1}, "Demisto", {"depth": 1})
        assert field_key == 'Value'
        assert field_value == 'Demisto'

    def test_generate_field_value_values_list_input(self, requests_mock):
        cache = demisto.getIntegrationContext()
        cache['fieldValueList'] = {}
        demisto.setIntegrationContext(cache)

        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}, 'IsSuccessful': True})
        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/304', json=GET_FIElD_DEFINITION_RES)
        requests_mock.get(BASE_URL + 'api/core/system/valueslistvalue/valueslist/62', json=VALUE_LIST_RES)

        client = Client(BASE_URL, '', '', '', '', 400)
        field_key, field_value = generate_field_value(client, "", {'Type': 4, 'FieldId': 304}, ["High"], 1)
        assert field_key == 'Value'
        assert field_value == {'ValuesListIds': [473]}

    def test_generate_field_external_link_input(self):
        client = Client(BASE_URL, '', '', '', '', 400)
        field_key, field_value = generate_field_value(client, "", {'Type': 7},
                                                      [{"value": "github", "link": "https://github.com"},
                                                       {"value": "google", "link": "https://google.com"}],
                                                      {"depth": 1})
        assert field_key == 'Value'
        assert field_value == [{"Name": "github", "URL": "https://github.com"},
                               {"Name": "google", "URL": "https://google.com"}]

    def test_generate_field_users_groups_input(self):
        """
        Given:
            Valid value from dictionary type under "fieldsToValues" argument

        When:
            - running archer-update-record

        Then:
            - assert fields are generated correctly

        """
        client = Client(BASE_URL, '', '', '', '', 400)
        field_key, field_value = generate_field_value(client, "", {'Type': 8}, {"users": [20], "groups": [30]},
                                                      {"depth": 1})
        assert field_key == 'Value'
        assert field_value == {"UserList": [{"ID": 20}], "GroupList": [{"ID": 30}]}

    def test_generate_field_values_list_with_other(self, requests_mock, mocker):
        """
            Given:
                list values with "OtherText" from dictionary type under "fieldsToValues" argument

            When:
                - running archer-update-record

            Then:
                - assert fields are generated correctly

        """
        mocker.patch.object(Client, 'get_field_value_list', return_value={'ValuesList': [{"Name": "NA", "Id": 222}]})

        client = Client(BASE_URL, '', '', '', '', 400)
        field_key, field_value = generate_field_value(client, "", {'Type': 4, 'FieldId': 1234},
                                                      {"ValuesList": ["NA"], "OtherText": "test"},
                                                      {"depth": 1})
        assert field_key == 'Value'
        assert field_value == {'ValuesListIds': [222], 'OtherText': 'test'}

    def test_generate_invalid_field_users_groups_input(self):
        """
        Given:
            Invalid value under "fieldsToValues" argument with type 8 (lists)

        When:
            - running archer-update-record

        Then:
            - Raise exception indicates that the value is not with the right format

        """
        client = Client(BASE_URL, '', '', '', '', 400)
        with pytest.raises(DemistoException) as e:
            generate_field_value(client, "test", {'Type': 8}, 'user1, user2', {"depth": 1})
        assert "The value of the field: test must be a dictionary type and include a list under \"users\" key or " \
               "\"groups\" key e.g: {\"Policy Owner\":{\"users\":[20],\"groups\":[30]}}" in str(e.value)

    @pytest.mark.parametrize('field_value, result', [
        ([1, 2], [{"ContentID": 1}, {"ContentID": 2}]),
        (1234, [{"ContentID": 1234}])
    ])
    def test_generate_field_cross_reference_input(self, field_value, result):
        client = Client(BASE_URL, '', '', '', '', 400)
        field_key, field_value = generate_field_value(client, "", {'Type': 9}, field_value, {"depth": 1})
        assert field_key == 'Value'
        assert field_value == result

    def test_generate_field_ip_address_input(self):
        client = Client(BASE_URL, '', '', '', '', 400)
        field_key, field_value = generate_field_value(client, "", {'Type': 19}, '127.0.0.1', {"depth": 1})
        assert field_key == 'IpAddressBytes'
        assert field_value == '127.0.0.1'

    def test_generate_field_value(self, requests_mock):
        """
        Given
        - generate_field_value on Values List type
        When
        - the source is not a list
        Then
        - ensure generate_field_value will handle it
        """
        cache = demisto.getIntegrationContext()
        cache['fieldValueList'] = {}
        demisto.setIntegrationContext(cache)

        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/16172', json=GET_FIElD_DEFINITION_RES)
        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}, 'IsSuccessful': 'yes'})
        requests_mock.get(BASE_URL + 'api/core/system/valueslistvalue/valueslist/62', json=VALUE_LIST_RES_FOR_SOURCE)

        client = Client(BASE_URL, '', '', '', '', 400)
        field_key, field_value = generate_field_value(client, "Source",
                                                      {'FieldId': '16172', 'IsRequired': False, 'Name':
                                                          'Source', 'RelatedValuesListId': 2092, 'Type': 4}, 'ArcSight', 1)
        assert field_key == 'Value'
        assert field_value == {'ValuesListIds': [471]}

    def test_record_to_incident_europe_time(self):
        """
        Given:
            record with european time (day first)

        When:
            fetching incidents

        Then:
            assert return dates are right

        """
        client = Client(BASE_URL, '', '', '', '', 400)
        incident = INCIDENT_RECORD.copy()
        incident['raw']['Field'][1]['@xmlConvertedValue'] = '2018-03-26T10:03:00Z'
        incident['record']['Date/Time Reported'] = "26/03/2018 10:03 AM"
        incident, incident_created_time = client.record_to_incident(INCIDENT_RECORD, 75, '305')
        assert incident_created_time == datetime(2018, 3, 26, 10, 3, tzinfo=UTC)
        assert incident['occurred'] == '2018-03-26T10:03:00Z'

    def test_record_to_incident_american_time(self):
        """
        Given:
            record with american time (month first)

        When:
            fetching incidents

        Then:
            assert return dates are right

        """
        client = Client(BASE_URL, '', '', '', '', 400)
        incident = INCIDENT_RECORD.copy()
        incident['record']['Date/Time Reported'] = '03/26/2018 10:03 AM'
        incident['raw']['Field'][1]['@xmlConvertedValue'] = '2018-03-26T10:03:00Z'
        incident, incident_created_time = client.record_to_incident(
            INCIDENT_RECORD, 75, '305'
        )
        assert incident_created_time == datetime(2018, 3, 26, 10, 3, tzinfo=UTC)
        assert incident['occurred'] == '2018-03-26T10:03:00Z'

    def test_fetch_time_change(self, mocker):
        """
        Given:
            incident with date/time reported
            european time (day first) - True or false

        When:
            Fetching incidents

        Then:
            Check that the new next fetch is greater than last_fetch
            Check the wanted next_fetch is true
            Assert occurred time
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        date_time_reported = '2018-04-03T10:03:00.000Z'
        params = {
            'applicationId': '75',
            'applicationDateField': 'Date/Time Reported'
        }
        record = copy.deepcopy(INCIDENT_RECORD)
        record['record']['Date/Time Reported'] = date_time_reported
        record['raw']['Field'][1]['@xmlConvertedValue'] = date_time_reported
        last_fetch = get_fetch_time(
            {'last_fetch': '2018-03-01T10:03:00Z'}, params.get('fetch_time', '3 days')
        )
        mocker.patch.object(client, 'search_records', return_value=([record], {}))
        incidents, next_fetch = fetch_incidents(client, params, last_fetch, '305')
        assert last_fetch < next_fetch
        assert next_fetch == datetime(2018, 4, 3, 10, 3, tzinfo=UTC)
        assert incidents[0]['occurred'] == date_time_reported

    def test_two_fetches(self, mocker):
        """
        Given:
            2 incident with date/time reported
            running two fetches.
        When:
            Fetching incidents

        Then:
            Check that the new next fetch is greater than last_fetch on both calls.
            Check the wanted next_fetch is equals to the date in the incident in both calls.
            Assert occurred time
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        params = {
            'applicationId': '75',
            'applicationDateField': 'Date/Time Reported'
        }
        record1, record2 = copy.deepcopy(INCIDENT_RECORD), copy.deepcopy(INCIDENT_RECORD)
        record1['record']['Date/Time Reported'] = '18/03/2020 10:30 AM'
        record2['record']['Date/Time Reported'] = '18/03/2020 03:30 PM'
        record1['raw']['Field'][1]['@xmlConvertedValue'] = '2020-03-18T10:30:00.000Z'
        record2['raw']['Field'][1]['@xmlConvertedValue'] = '2020-03-18T15:30:00.000Z'
        last_fetch = parser('2020-18-03T09:00:00Z')
        mocker.patch.object(
            client, 'search_records', side_effect=[
                ([record1], {}),
                ([record2], {})
            ]
        )
        incidents, next_fetch = fetch_incidents(client, params, last_fetch, '305')
        assert last_fetch < next_fetch
        assert next_fetch == datetime(2020, 3, 18, 10, 30, tzinfo=UTC)
        assert incidents[0]['occurred'] == '2020-03-18T10:30:00.000Z'
        incidents, next_fetch = fetch_incidents(client, params, next_fetch, '305')
        assert last_fetch < next_fetch
        assert next_fetch == datetime(2020, 3, 18, 15, 30, tzinfo=UTC)
        assert incidents[0]['occurred'] == '2020-03-18T15:30:00.000Z'

    def test_fetch_got_old_incident(self, mocker):
        """
        Given:
            last_fetch is newer than new incident

        When:
            Fetching incidents

        Then:
            Check that the next fetch is equals last fetch (no new incident)
            Check that no incidents brought back
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        date_time_reported = '2018-03-01T10:02:00.000Z'
        params = {
            'applicationId': '75',
            'applicationDateField': 'Date/Time Reported'
        }
        record = copy.deepcopy(INCIDENT_RECORD)
        record['record']['Date/Time Reported'] = date_time_reported
        record['raw']['Field'][1]['@xmlConvertedValue'] = date_time_reported
        last_fetch = get_fetch_time(
            {'last_fetch': '2018-03-01T10:03:00Z'}, params.get('fetch_time', '3 days')
        )
        mocker.patch.object(client, 'search_records', return_value=([record], {}))
        incidents, next_fetch = fetch_incidents(client, params, last_fetch, '305')
        assert last_fetch == next_fetch
        assert not incidents, 'Should not get new incidents.'

    def test_fetch_got_exact_same_time(self, mocker):
        """
        Given:
            last_fetch is in the exact same time as the incident

        When:
            Fetching incidents

        Then:
            Check that the next fetch is equals last fetch (no new incident)
            Check that no incidents brought back
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        date_time_reported = '2018-03-01T10:02:00.000Z'
        params = {
            'applicationId': '75',
            'applicationDateField': 'Date/Time Reported'
        }
        record = copy.deepcopy(INCIDENT_RECORD)
        record['record']['Date/Time Reported'] = date_time_reported
        record['raw']['Field'][1]['@xmlConvertedValue'] = date_time_reported
        last_fetch = get_fetch_time(
            {'last_fetch': date_time_reported}, params.get('fetch_time', '3 days')
        )
        mocker.patch.object(client, 'search_records', return_value=([record], {}))
        incidents, next_fetch = fetch_incidents(client, params, last_fetch, '305')
        assert last_fetch == next_fetch
        assert not incidents, 'Should not get new incidents.'

    @staticmethod
    def test_fetch_blacklisted_date_filter():
        """
        Given:
            fetch_xml parameter with a forbidden DateComparisonFilterCondition

        When:
            Fetching incidents

        Then:
            Check that a ValueError is raised with the appropriate error message
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        params = {
            'applicationId': '75',
            'applicationDateField': 'Date/Time Reported',
            'fetch_xml': (
                '<DateComparisonFilterCondition>'
                '<Operator>GreaterThan</Operator>'
                '<Field name="Last Updated">7195</Field>'
                '<Value>2023-06-04T13:08:43.433385Z</Value>'
                '<TimeZoneId>UTC Standard Time</TimeZoneId>'
                '<IsTimeIncluded>TRUE</IsTimeIncluded>'
                '</DateComparisonFilterCondition>'
            )
        }
        from_time = datetime(2024, 12, 11)
        expected_error_message = 'XML filter condition cannot contain the "DateComparisonFilterCondition" tag'
        with pytest.raises(ValueError, match=expected_error_message):
            fetch_incidents(client, params, from_time, '204')

    def test_same_record_returned_in_two_fetches(self, mocker):
        """
        Given:
            - Same record returned in 2 fetch queries
        When:
            - Fetching incidents (2 iterations)
        Then:
            Check that the new next fetch is greater than last_fetch on both calls.
            Check the wanted next_fetch is equals to the date in the incident in both calls.
            Assert occurred time
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        mocker.patch.object(
            client, 'search_records', side_effect=[
                ([INCIDENT_RECORD_US_TZ], {}),
                ([INCIDENT_RECORD_US_TZ], {})
            ]
        )
        params = {
            'applicationId': '75',
            'applicationDateField': 'created date'
        }
        field_time_id = '53075'
        first_fetch = parser('2021-02-24T08:45:55Z')
        incidents, first_next_fetch = fetch_incidents(client, params, first_fetch, field_time_id)
        assert first_fetch < first_next_fetch
        assert first_next_fetch == datetime(2021, 2, 25, 8, 45, 55, 977000, tzinfo=UTC)
        assert incidents[0]['occurred'] == '2021-02-25T08:45:55.977Z'
        # first_next_fetch_dt simulates the set to last_run done in fetch-incidents
        first_next_fetch_dt = parser(first_next_fetch.strftime(OCCURRED_FORMAT))
        incidents, second_next_fetch = fetch_incidents(client, params, first_next_fetch_dt, field_time_id)
        assert first_next_fetch == datetime(2021, 2, 25, 8, 45, 55, 977000, tzinfo=UTC)
        assert not incidents

    def test_search_records_by_report_command(self, mocker):
        """
            Given:
                - search_records_by_report_command command args
            When:
                - run search_records_by_report_command
            Then:
                - Verify response outputs
                - verify response readable output
        """

        mock_args = {'reportGuid': 'id'}
        client = Client(BASE_URL, '', '', '', '', 400)
        mocker.patch.object(client, 'do_soap_request',
                            return_value=[SEARCH_RECORDS_BY_REPORT_RES, SEARCH_RECORDS_BY_REPORT_RES])
        mocker.patch.object(client, 'do_rest_request', return_value=GET_LEVEL_RES_2)
        mocker.patch.object(demisto, 'results')
        search_records_by_report_command(client, mock_args)
        assert demisto.results.call_args_list[0][0][0]['HumanReadable'] == MOCK_READABLE_SEARCH_RECORDS_BY_REPORT
        assert demisto.results.call_args_list[0][0][0]['Contents'] == MOCK_RESULTS_SEARCH_RECORDS_BY_REPORT

    @pytest.mark.parametrize('integration_context, is_login_expected, http_call_attempt_results', [
        ({}, True, [{'status_code': 200, 'json': {'res': 'some_res'}}]),
        ({'session_id': 'test_session_id'}, False, [{'status_code': 200, 'json': {'res': 'some_res'}}]),
        ({'session_id': 'test_session_id'}, False, [{'status_code': 401}, {'status_code': 200, 'json': {'res': 'some_res'}}]),
        ({'session_id': 'test_session_id'}, True, [{'status_code': 401}, {
         'status_code': 401}, {'status_code': 200, 'json': {'res': 'some_res'}}]),
    ])
    def test_do_rest_request(self, mocker, requests_mock, integration_context, is_login_expected, http_call_attempt_results):
        """
        Test for the do_rest_request function.
        Given:
            Case 1: Empty integration context (no cached session_id).
            Case 2: Integration context with cached session_id.
            Case 3: Integration context with cached session_id.
            Case 4: Integration context with cached session_id.

        When:
            Case 1: rest API request succeed on first run with newly generated session_id.
            Case 2: rest API request succeed on first run with cached the session_id.
            Case 3: rest API request fails on first attempt and succeed on second run with the cached session_id.
            Case 4: rest API request fails on two first attempts with the cached session_id and succeed on third run
                after creating new session_id.

        Then:
            Case 1: Ensure new session_id was generated, and only one call to the search API was done (success).
            Case 2: Ensure no new session_id was generated, and only one call to the search API was done (success).
            Case 3: Ensure no new session_id was generated, and two calls to the search API were done (failure and
                success).
            Case 3: Ensure new session_id was generated, and three calls to the search API were done (failure, failure
                and success).
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        mocker.patch('ArcherV2.get_integration_context', return_value=integration_context)
        login_mocker = requests_mock.post(BASE_URL + 'api/core/security/login',
                                          json={'RequestedObject': {'SessionToken': 'session-id'}, 'IsSuccessful': True})
        rest_mocker = requests_mock.get(BASE_URL + 'test_requests', http_call_attempt_results)
        dummy_response = client.do_rest_request('GET', 'test_requests')
        if is_login_expected:
            assert login_mocker.called_once
        else:
            assert not login_mocker.called
        assert rest_mocker.call_count == len(http_call_attempt_results)
        assert dummy_response

    @pytest.mark.parametrize('integration_context, is_new_token_expected, http_call_attempt_results', [
        ({}, True, [{'status_code': 200, 'text': SEARCH_RECORDS_RES}]),
        ({'token': 'TOKEN'}, False, [{'status_code': 200, 'text': SEARCH_RECORDS_RES}]),
        ({'token': 'TOKEN'}, False, [{'status_code': 500}, {'status_code': 200, 'text': SEARCH_RECORDS_RES}]),
        ({'token': 'TOKEN'}, True, [{'status_code': 500}, {'status_code': 500},
         {'status_code': 200, 'text': SEARCH_RECORDS_RES}]),
    ])
    def test_do_soap_request(self, mocker, requests_mock, integration_context, is_new_token_expected, http_call_attempt_results):
        """
        Test for the do_soap_request function.
        (we use the archer-search-records template as test case, but it doesn't really matter)
        Given:
            Case 1: Empty integration context (no cached token).
            Case 2: Integration context with cached token.
            Case 3: Integration context with cached token.
            Case 4: Integration context with cached token.

        When:
            Case 1: Soap API request succeed on first run with newly generated the token.
            Case 2: Soap API request succeed on first run with cached the token.
            Case 3: Soap API request fails on first attempt and succeed on second run with the cached token.
            Case 4: Soap API request fails on two first attempts and succeed on third run after creating new token.

        Then:
            Case 1: Ensure new token was generated, and only one call to the search API was done (success).
            Case 2: Ensure no new token was generated, and only one call to the search API was done (success).
            Case 3: Ensure no new token was generated, and two calls to the search API were done (failure and success).
            Case 3: Ensure new token was generated, and three calls to the search API were done (failure, failure and
            success).
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        mocker.patch('ArcherV2.get_integration_context', return_value=integration_context)
        new_token_mocker = requests_mock.post(BASE_URL + 'ws/general.asmx', text=GET_TOKEN_SOAP)
        soap_mocker = requests_mock.post(BASE_URL + 'ws/search.asmx', http_call_attempt_results)

        search_commands_args = {'app_id': 1, 'display_fields': '<DisplayField name="External Links">1</DisplayField>'
                                                               '<DisplayField name="Device Name">2</DisplayField>',
                                'field_id': '', 'field_name': '', 'field_to_search_by_id': '', 'numeric_operator': '',
                                'date_operator': '', 'search_value': '', 'max_results': 10, 'sort_type': 'Ascending',
                                'level_id': 123}
        client.do_soap_request('archer-search-records', **search_commands_args)
        if is_new_token_expected:
            assert new_token_mocker.called_once
        else:
            assert not new_token_mocker.called
        assert soap_mocker.call_count == len(http_call_attempt_results)

    def test_validate_xml_conditions_valid(self):
        """
        Given:
            - A string that is meant to represents a valid XML document.
        When:
            - Calling validate_xml_conditions.
        Assert:
            - Ensure no exception is raised.
        """
        xml_conditions = (
            '<TextFilterCondition>'
            '<Operator>Equals</Operator>'
            '<Field name="Job">7</Field>'
            '<Value>Dev</Value>'
            '</TextFilterCondition>'
            '<NumericFilterCondition>'
            '<Operator>GreaterThan</Operator>'
            '<Field name="Age">8</Field>'
            '<Value>25</Value>'
            '</NumericFilterCondition>'
        )
        validate_xml_conditions(xml_conditions)  # if exception raised, test would fail

    @pytest.mark.parametrize(
        'xml_document, blacklisted_tags, expected_error_message',
        [
            pytest.param(
                # Inputs ↓
                '<ShowStatSummaries>false</ShowSummaries>',
                [],
                # Expected ↓
                'Invalid XML filter condition syntax',
                id='Mismatched tags',
            ),
            pytest.param(
                # Inputs ↓
                '<ModuleCriteria><Module name="appname">5</Module></ModuleCriteria>',
                ['ModuleCriteria'],
                # Expected ↓
                'XML filter condition cannot contain the "ModuleCriteria" tag',
                id='Blacklisted tag',
            ),
        ]
    )
    def test_validate_xml_conditions_raise_exception(
        self,
        xml_document: str,
        blacklisted_tags: list[str],
        expected_error_message: str,
    ):
        """
        Given:
            - A malformed XML document and one that contains a forbidden XML tag.
        When:
            - Calling validate_xml_conditions.
        Assert:
            - Ensure a ValueError is raised with the correct error message.
        """
        with pytest.raises(ValueError, match=expected_error_message):
            validate_xml_conditions(xml_document, blacklisted_tags)

    @pytest.mark.parametrize(
        'condition_type, operator, field_name, field_id, search_value, expected_xml_condition',
        [
            pytest.param(
                # Inputs ↓
                FilterConditionTypes.date,
                'GreaterThan',
                'Last Updated',
                '1234',
                '2024-12-11T11:11:24.433385Z',
                # Expected ↓
                '<DateComparisonFilterCondition>'
                '<Operator>GreaterThan</Operator>'
                '<Field name="Last Updated">1234</Field>'
                '<Value>2024-12-11T11:11:24.433385Z</Value>'
                '</DateComparisonFilterCondition>',
                id='Date greater than condition',
            ),
            pytest.param(
                # Inputs ↓
                FilterConditionTypes.text,
                'Contains',
                'Incident Priority',
                '456',
                'High',
                # Expected ↓
                '<TextFilterCondition>'
                '<Operator>Contains</Operator>'
                '<Field name="Incident Priority">456</Field>'
                '<Value>High</Value>'
                '</TextFilterCondition>',
                id='Text contains condition',
            ),
        ]
    )
    def test_construct_generic_filter_condition(
        self,
        condition_type: FilterConditionTypes,
        operator: str,
        field_name: str,
        field_id: str,
        search_value: str,
        expected_xml_condition: str
    ):
        """
        Given:
            - A filter condition with a comparison operator on a given field.
        When:
            - Calling construct_generic_filter_condition.
        Assert:
            - Ensure a valid condition XML element with the correct sub-elements.
        """
        xml_condition = construct_generic_filter_condition(
            condition_type=condition_type,
            operator=operator,
            field_name=field_name,
            field_id=field_id,
            search_value=search_value,
        )
        assert xml_condition == expected_xml_condition

    def test_upload_and_associate_command_record_has_attachments(self, mocker):
        """
        Given: A record with existing attachments and multiple files to upload
        When: The upload_and_associate_command is called
        Then: Files are uploaded, associated with the record, and existing attachments are preserved
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        mock_upload_file = mocker.patch("ArcherV2.upload_file_command", return_value='123')
        mock_update_record = mocker.patch("ArcherV2.update_record_command")
        mock_get_record = mocker.patch.object(client, "get_record", return_value=({'Attachments': ['456', '789']}, '', ''))
        args = {
            "applicationId": "app1",
            "contentId": "content1",
            "associatedField": "field1",
            "entryId": "entry1, entry2"
        }

        upload_and_associate_command(client, args)

        assert mock_upload_file.call_count == 2
        assert mock_upload_file.call_args_list[0] == mocker.call(client, {"entryId": "entry1"})
        assert mock_upload_file.call_args_list[1] == mocker.call(client, {"entryId": "entry2"})
        mock_update_record.assert_called_once_with(client, {
            "applicationId": "app1",
            "contentId": "content1",
            "associatedField": "field1",
            "entryId": "entry1, entry2",
            "fieldsToValues": '{"field1": ["123", "123", "456", "789"]}'
        })
        mock_get_record.assert_called_once_with("app1", "content1", 0)

    def test_upload_and_associate_command_single_file(self, mocker):
        """
        Given: A single file to upload and associate
        When: The upload_and_associate_command is called
        Then: The file is uploaded and associated with the record
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        mock_upload_file = mocker.patch("ArcherV2.upload_file_command", return_value='123')
        mock_update_record = mocker.patch("ArcherV2.update_record_command")
        mock_get_record = mocker.patch.object(client, "get_record", return_value=({'ID': '123'}, '', ''))
        args = {
            "applicationId": "app1",
            "contentId": "content1",
            "associatedField": "field1",
            "entryId": "entry1"
        }

        upload_and_associate_command(client, args)

        assert mock_upload_file.call_count == 1
        assert mock_upload_file.call_args_list[0] == mocker.call(client, {"entryId": "entry1"})
        mock_get_record.assert_called_once_with("app1", "content1", 0)
        mock_update_record.assert_called_once_with(client, {
            "applicationId": "app1",
            "contentId": "content1",
            "associatedField": "field1",
            "entryId": "entry1",
            "fieldsToValues": '{"field1": ["123"]}'
        })

    def test_upload_and_associate_command_record_has_no_attachments(self, mocker):
        """
        Given: A record without existing attachments and multiple files to upload
        When: The upload_and_associate_command is called
        Then: Files are uploaded and associated with the record
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        mock_upload_file = mocker.patch("ArcherV2.upload_file_command", return_value='123')
        mock_update_record = mocker.patch("ArcherV2.update_record_command")
        mock_get_record = mocker.patch.object(client, "get_record", return_value=({'ID': '123'}, '', ''))
        args = {
            "applicationId": "app1",
            "contentId": "content1",
            "associatedField": "field1",
            "entryId": "entry1, entry2"
        }

        upload_and_associate_command(client, args)

        assert mock_upload_file.call_count == 2
        assert mock_upload_file.call_args_list[0] == mocker.call(client, {"entryId": "entry1"})
        assert mock_upload_file.call_args_list[1] == mocker.call(client, {"entryId": "entry2"})
        mock_update_record.assert_called_once_with(client, {
            "applicationId": "app1",
            "contentId": "content1",
            "associatedField": "field1",
            "entryId": "entry1, entry2",
            "fieldsToValues": '{"field1": ["123", "123"]}'
        })
        mock_get_record.assert_called_once_with("app1", "content1", 0)

    def test_upload_and_associate_command_record_with_error(self, mocker):
        """
        Given: An error occurs during record retrieval
        When: The upload_and_associate_command is called
        Then: Files are uploaded, association is attempted, and an error is returned
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        mock_upload_file = mocker.patch("ArcherV2.upload_file_command", return_value='123')
        mock_update_record = mocker.patch("ArcherV2.update_record_command")
        mock_get_record = mocker.patch.object(client, "get_record", return_value=({'ID': '123'}, '', 'error'))
        mock_error = mocker.patch("ArcherV2.return_error")
        args = {
            "applicationId": "app1",
            "contentId": "content1",
            "associatedField": "field1",
            "entryId": "entry1, entry2"
        }

        upload_and_associate_command(client, args)

        assert mock_upload_file.call_count == 2
        assert mock_upload_file.call_args_list[0] == mocker.call(client, {"entryId": "entry1"})
        assert mock_upload_file.call_args_list[1] == mocker.call(client, {"entryId": "entry2"})
        mock_update_record.assert_called_once_with(client, {
            "applicationId": "app1",
            "contentId": "content1",
            "associatedField": "field1",
            "entryId": "entry1, entry2",
            "fieldsToValues": '{"field1": ["123", "123"]}'
        })
        mock_get_record.assert_called_once_with("app1", "content1", 0)
        mock_error.assert_called_once_with('error')

    def test_upload_and_associate_command_without_association(self, mocker):
        """
        Given: A file to upload without association to a record
        When: The upload_and_associate_command is called
        Then: The file is uploaded without being associated to any record
        """
        client = Client(BASE_URL, '', '', '', '', 400)
        mock_upload_file = mocker.patch("ArcherV2.upload_file_command", return_value='123')
        args = {"entryId": "entry1"}

        upload_and_associate_command(client, args)

        assert mock_upload_file.call_count == 1
        mock_upload_file.assert_called_once_with(client, {
            "entryId": "entry1",
        })

    def test_upload_and_associate_command_missing_args(self, mocker):
        """
        Given: Incomplete arguments for upload and associate command
        When: The upload_and_associate_command is called
        Then: An exception is raised indicating missing required arguments
        """
        client = Client(BASE_URL, '', '', '', '', 400)

        # Test error when only applicationId is provided
        args = {"applicationId": "app1", "entryId": "entry1"}
        with pytest.raises(DemistoException) as e:
            upload_and_associate_command(client, args)
        assert str(e.value) == 'Found arguments to associate an attachment to a record, but not all required arguments supplied'

        # Test error when only contentId is provided
        args = {"contentId": "content1", "entryId": "entry1"}
        with pytest.raises(DemistoException) as e:
            upload_and_associate_command(client, args)
        assert str(e.value) == 'Found arguments to associate an attachment to a record, but not all required arguments supplied'
