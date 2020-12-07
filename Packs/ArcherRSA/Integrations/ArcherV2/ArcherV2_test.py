import copy
from datetime import datetime, timezone

import pytest

import demistomock as demisto
from ArcherV2 import Client, extract_from_xml, generate_field_contents, get_errors_from_res, generate_field_value, \
    fetch_incidents, get_fetch_time, parser

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

GET_LEVELS_BY_APP = [
    {'level': 123, 'mapping': {'1': {
        'Type': 7, 'Name': 'External Links', 'FieldId': "1", 'IsRequired': False, 'RelatedValuesListId': None},
        '2': {
            'Type': 1, 'Name': 'Device Name', 'FieldId': "2",
            'IsRequired': True, 'RelatedValuesListId': 8}
    }}]

GET_FIElD_DEFINITION_RES = {
    "RequestedObject": {"RelatedValuesListId": 62},
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
        {"Id": 471, "Name": "Low", "IsSelectable": True},
        {"Id": 472, "Name": "Medium", "IsSelectable": True},
        {"Id": 473, "Name": "High", "IsSelectable": True}]}

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


class TestArcherV2:
    def test_extract_from_xml(self):
        field_id = extract_from_xml(XML_FOR_TEST, 'Envelope.Body.GetValueListForField.fieldId')
        assert field_id == '6969'

    def test_get_level_by_app_id(self, requests_mock):
        requests_mock.post(BASE_URL + 'api/core/security/login', json={'RequestedObject': {'SessionToken': 'session-id',
                                                                                           }, 'IsSuccessful': True})
        requests_mock.get(BASE_URL + 'api/core/system/level/module/1', json=GET_LEVEL_RES)
        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/level/123', json=FIELD_DEFINITION_RES)
        client = Client(BASE_URL, '', '', '', '')
        levels = client.get_level_by_app_id('1')
        assert levels == GET_LEVELS_BY_APP

    @pytest.mark.parametrize('requested_object, is_successful',
                             [(GET_RESPONSE_NOT_SUCCESSFUL_JSON, False),
                              (GET_RESPONSE_SUCCESSFUL_JSON, True)])
    def test_update_session(self, mocker, requests_mock, requested_object, is_successful):
        requests_mock.post(BASE_URL + 'api/core/security/login', json=requested_object)
        mocker.patch.object(demisto, 'results')
        client = Client(BASE_URL, '', '', '', '')
        if is_successful:
            client.update_session()
            assert demisto.results.call_count == 0
        else:
            with pytest.raises(SystemExit) as e:
                # in case login wasn't successful, return_error will exit with a reason (for example, LoginNotValid)
                # return_error reached
                client.update_session()
            assert e

    def test_generate_field_contents(self):
        client = Client(BASE_URL, '', '', '', '')
        field = generate_field_contents(client, '{"Device Name":"Macbook"}', GET_LEVELS_BY_APP[0]['mapping'])
        assert field == {'2': {'Type': 1, 'Value': 'Macbook', 'FieldId': '2'}}

    def test_get_errors_from_res(self):
        errors = get_errors_from_res(RES_WITH_ERRORS)
        assert errors == 'The Type field is a required field.\nThe Device Name field is a required field.'

    def test_get_record_failed(self, requests_mock):
        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}})
        requests_mock.get(BASE_URL + 'api/core/content/1010', json=GET_RECORD_RES_failed)
        client = Client(BASE_URL, '', '', '', '')
        record, res, errors = client.get_record(75, 1010)
        assert errors == 'No resource found.'
        assert res
        assert record == {}

    def test_get_record_success(self, requests_mock):
        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}})
        requests_mock.get(BASE_URL + 'api/core/content/1010', json=GET_RECORD_RES_SUCCESS)
        requests_mock.get(BASE_URL + 'api/core/system/level/module/1', json=GET_LEVEL_RES)
        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/level/123', json=FIELD_DEFINITION_RES)
        client = Client(BASE_URL, '', '', '', '')
        record, res, errors = client.get_record(1, 1010)
        assert errors is None
        assert res
        assert record == {'Device Name': 'The device name', 'Id': 1010}

    def test_record_to_incident(self):
        client = Client(BASE_URL, '', '', '', '')
        incident, incident_created_time = client.record_to_incident(INCIDENT_RECORD, 75, 'Date/Time Reported')
        assert incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ') == '2018-03-26T10:03:32Z'
        assert incident['name'] == 'RSA Archer Incident: 227602'
        assert incident['occurred'] == '2018-03-26T10:03:32Z'

    def test_search_records(self, requests_mock):
        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}})
        requests_mock.post(BASE_URL + 'ws/general.asmx', text=GET_TOKEN_SOAP)

        requests_mock.get(BASE_URL + 'api/core/system/level/module/1', json=GET_LEVEL_RES)
        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/level/123', json=FIELD_DEFINITION_RES)
        requests_mock.post(BASE_URL + 'ws/search.asmx', text=SEARCH_RECORDS_RES)
        client = Client(BASE_URL, '', '', '', '')
        records, raw_res = client.search_records(1, ['External Links', 'Device Name'])
        assert raw_res
        assert len(records) == 1
        assert records[0]['record']['Id'] == '238756'
        assert records[0]['record']['Device Name'] == 'DEVICE NAME'

    def test_get_field_value_list(self, requests_mock):
        cache = demisto.getIntegrationContext()
        cache['fieldValueList'] = {}
        demisto.setIntegrationContext(cache)

        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}})
        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/304', json=GET_FIElD_DEFINITION_RES)
        requests_mock.get(BASE_URL + 'api/core/system/valueslistvalue/valueslist/62', json=VALUE_LIST_RES)
        client = Client(BASE_URL, '', '', '', '')
        field_data = client.get_field_value_list(304)
        assert VALUE_LIST_FIELD_DATA == field_data

    def test_generate_field_value_text_input(self):
        client = Client(BASE_URL, '', '', '', '')
        field_key, field_value = generate_field_value(client, "", {'Type': 1}, "Demisto")
        assert field_key == 'Value'
        assert field_value == 'Demisto'

    def test_generate_field_value_values_list_input(self, requests_mock):
        cache = demisto.getIntegrationContext()
        cache['fieldValueList'] = {}
        demisto.setIntegrationContext(cache)

        requests_mock.post(BASE_URL + 'api/core/security/login',
                           json={'RequestedObject': {'SessionToken': 'session-id'}})
        requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/304', json=GET_FIElD_DEFINITION_RES)
        requests_mock.get(BASE_URL + 'api/core/system/valueslistvalue/valueslist/62', json=VALUE_LIST_RES)

        client = Client(BASE_URL, '', '', '', '')
        field_key, field_value = generate_field_value(client, "", {'Type': 4, 'FieldId': 304}, ["High"])
        assert field_key == 'Value'
        assert field_value == {'ValuesListIds': [473]}

    def test_generate_field_external_link_input(self):
        client = Client(BASE_URL, '', '', '', '')
        field_key, field_value = generate_field_value(client, "", {'Type': 7},
                                                      [{"value": "github", "link": "https://github.com"},
                                                       {"value": "google", "link": "https://google.com"}])
        assert field_key == 'Value'
        assert field_value == [{"Name": "github", "URL": "https://github.com"},
                               {"Name": "google", "URL": "https://google.com"}]

    def test_generate_field_users_groups_input(self):
        client = Client(BASE_URL, '', '', '', '')
        field_key, field_value = generate_field_value(client, "", {'Type': 8}, {"users": [20], "groups": [30]})
        assert field_key == 'Value'
        assert field_value == {"UserList": [{"ID": 20}], "GroupList": [{"ID": 30}]}

    @pytest.mark.parametrize('field_value, result', [
        ([1, 2], [{"ContentID": 1}, {"ContentID": 2}]),
        (1234, [{"ContentID": 1234}])
    ])
    def test_generate_field_cross_reference_input(self, field_value, result):
        client = Client(BASE_URL, '', '', '', '')
        field_key, field_value = generate_field_value(client, "", {'Type': 9}, field_value)
        assert field_key == 'Value'
        assert field_value == result

    def test_generate_field_ip_address_input(self):
        client = Client(BASE_URL, '', '', '', '')
        field_key, field_value = generate_field_value(client, "", {'Type': 19}, '127.0.0.1')
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

        client = Client(BASE_URL, '', '', '', '')
        field_key, field_value = generate_field_value(client, "Source",
                                                      {'FieldId': '16172', 'IsRequired': False, 'Name':
                                                          'Source', 'RelatedValuesListId': 2092, 'Type': 4}, 'ArcSight')
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
        client = Client(BASE_URL, '', '', '', '')
        incident = INCIDENT_RECORD.copy()
        incident['record']['Date/Time Reported'] = "26/03/2018 10:03 AM"
        incident, incident_created_time = client.record_to_incident(
            INCIDENT_RECORD, 75, 'Date/Time Reported', day_first=True
        )
        assert incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ') == '2018-03-26T10:03:00Z'
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
        client = Client(BASE_URL, '', '', '', '')
        incident = INCIDENT_RECORD.copy()
        incident['record']['Date/Time Reported'] = '03/26/2018 10:03 AM'
        incident, incident_created_time = client.record_to_incident(
            INCIDENT_RECORD, 75, 'Date/Time Reported', day_first=False
        )
        assert incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ') == '2018-03-26T10:03:00Z'
        assert incident['occurred'] == '2018-03-26T10:03:00Z'

    @pytest.mark.parametrize('date_time_reported, use_european_time, occurred', [
        ('2018-04-03T10:03:00.000Z', False, '2018-04-03T10:03:00Z'),
        ('2018-04-03T10:03:00.000Z', True, '2018-04-03T10:03:00Z'),
        ('03/04/2018 10:03 AM', True, '2018-04-03T10:03:00Z'),
        ('04/03/2018 10:03 AM', False, '2018-04-03T10:03:00Z')
    ])
    def test_fetch_time_change(
            self, mocker, date_time_reported: str, use_european_time: bool, occurred: str
    ):
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
        client = Client(BASE_URL, '', '', '', '')
        params = {
            'applicationId': '75',
            'applicationDateField': 'Date/Time Reported',
            'time_zone': 0,
            'useEuropeanTime': use_european_time
        }
        record = copy.deepcopy(INCIDENT_RECORD)
        record['record']['Date/Time Reported'] = date_time_reported
        last_fetch = get_fetch_time(
            {'last_fetch': '2018-03-01T10:03:00Z'}, params.get('fetch_time', '3 days'),
            0
        )
        mocker.patch.object(client, 'search_records', return_value=([record], {}))
        incidents, next_fetch = fetch_incidents(client, params, last_fetch)
        assert last_fetch < next_fetch
        assert next_fetch == datetime(2018, 4, 3, 10, 3, tzinfo=timezone.utc)
        assert incidents[0]['occurred'] == occurred

    @pytest.mark.parametrize('date_time_reported, use_european_time, occurred', [
        ('11/29/2018 10:03 AM', False, '2018-11-29T10:03:00Z'),
        ('29/11/2018 10:03 AM', True, '2018-11-29T10:03:00Z')
    ])
    def test_fetch_times_with_impossible_date(
            self, mocker, date_time_reported: str, use_european_time: bool, occurred: str
    ):
        """
        Given:
            incident with date/time reported. The day/months can't be misplaced (29-11, 11-29)
            european time (day first) - True or false

        When:
            Fetching incidents

        Then:
            Check that the new next fetch is greater than last_fetch
            Check the wanted next_fetch is true
            Assert occurred time
        """
        client = Client(BASE_URL, '', '', '', '')
        params = {
            'applicationId': '75',
            'applicationDateField': 'Date/Time Reported',
            'time_zone': 0,
            'useEuropeanTime': use_european_time
        }
        record = copy.deepcopy(INCIDENT_RECORD)
        record['record']['Date/Time Reported'] = date_time_reported
        last_fetch = get_fetch_time(
            {'last_fetch': '2018-03-01T10:03:00Z'}, params.get('fetch_time', '3 days'),
            0
        )
        mocker.patch.object(client, 'search_records', return_value=([record], {}))
        incidents, next_fetch = fetch_incidents(client, params, last_fetch)
        assert last_fetch < next_fetch
        assert next_fetch == datetime(2018, 11, 29, 10, 3, tzinfo=timezone.utc)
        assert incidents[0]['occurred'] == occurred

    def test_fetch_time_change_with_offset(self, mocker):
        """
        Given:
            offset of -120 (2 hours)

        When:
            Fetching incidents

        Then:
            Check that the new last fetch is equals to record reported time (no delta) and is after the last_fetch
            Assert occurred time
        """
        client = Client(BASE_URL, '', '', '', '')
        record = copy.deepcopy(INCIDENT_RECORD)
        record['record']['Date/Time Reported'] = '03/04/2018 10:03 AM'
        params = {
            'applicationId': '75',
            'applicationDateField': 'Date/Time Reported',
            'time_zone': -120,
            'useEuropeanTime': 'true'
        }
        last_fetch = get_fetch_time(
            {'last_fetch': '2018-03-24T10:03:00Z'}, params.get('fetch_time', '3 days'),
            0
        )
        mocker.patch.object(client, 'search_records', return_value=([record], {}))
        incidents, next_fetch = fetch_incidents(client, params, last_fetch)
        assert last_fetch < next_fetch
        assert next_fetch == datetime(2018, 4, 3, 10, 3, tzinfo=timezone.utc)
        assert incidents[0]['occurred'] == '2018-04-03T12:03:00Z'

    def test_two_fetches(self, mocker):
        """
        Given:
            2 incident with date/time reported
            european time (day first) - True
            running two fetches.
        When:
            Fetching incidents

        Then:
            Check that the new next fetch is greater than last_fetch on both calls.
            Check the wanted next_fetch is equals to the date in the incident in both calls.
            Assert occurred time
        """
        client = Client(BASE_URL, '', '', '', '')
        params = {
            'applicationId': '75',
            'applicationDateField': 'Date/Time Reported',
            'time_zone': 0,
            'useEuropeanTime': True
        }
        record1, record2 = copy.deepcopy(INCIDENT_RECORD), copy.deepcopy(INCIDENT_RECORD)
        record1['record']['Date/Time Reported'] = '18/03/2020 10:30 AM'
        record2['record']['Date/Time Reported'] = '18/03/2020 03:30 PM'
        last_fetch = parser('2020-18-03T09:00:00Z').replace(tzinfo=timezone.utc)
        mocker.patch.object(
            client, 'search_records', side_effect=[
                ([record1], {}),
                ([record2], {})
            ]
        )
        incidents, next_fetch = fetch_incidents(client, params, last_fetch)
        assert last_fetch < next_fetch
        assert next_fetch == datetime(2020, 3, 18, 10, 30, tzinfo=timezone.utc)
        assert incidents[0]['occurred'] == '2020-03-18T10:30:00Z'
        incidents, next_fetch = fetch_incidents(client, params, next_fetch)
        assert last_fetch < next_fetch
        assert next_fetch == datetime(2020, 3, 18, 15, 30, tzinfo=timezone.utc)
        assert incidents[0]['occurred'] == '2020-03-18T15:30:00Z'
