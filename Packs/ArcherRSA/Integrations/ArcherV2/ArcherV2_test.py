from ArcherV2 import Client, extract_from_xml, generate_field_contents, get_errors_from_res, generate_field_value
import demistomock as demisto

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
    {"IsSuccessful": True, "RequestedObject": {"Id": 1, "Type": 7, "Name": "External Links", "IsRequired": False}},
    {"IsSuccessful": True, "RequestedObject": {"Id": 2, "Type": 1, "Name": "Device Name", "IsRequired": True,
                                               "RelatedValuesListId": 8}}]

GET_LEVELS_BY_APP = [{'level': 123, 'mapping':
                     {'1': {'Type': 7, 'Name': 'External Links', 'FieldId': "1",
                            'IsRequired': False, 'RelatedValuesListId': None},
                      '2': {'Type': 1, 'Name': 'Device Name', 'FieldId': "2",
                            'IsRequired': True, 'RelatedValuesListId': 8}}}]

GET_FIElD_DEFINITION_RES = {"RequestedObject":
                            {"RelatedValuesListId": 62},
                            "IsSuccessful": True,
                            "ValidationMessages": []}

VALUE_LIST_RES = {"RequestedObject": {
    "Children": [
        {"Data": {"Id": 471, "Name": "Low", "IsSelectable": True}},
        {"Data": {"Id": 472, "Name": "Medium", "IsSelectable": True}},
        {"Data": {"Id": 473, "Name": "High", "IsSelectable": True}}]},
    "IsSuccessful": True, "ValidationMessages": []}

VALUE_LIST_FIELD_DATA = {
    "FieldId": 304, "ValuesList": [
        {"Id": 471, "Name": "Low", "IsSelectable": True},
        {"Id": 472, "Name": "Medium", "IsSelectable": True},
        {"Id": 473, "Name": "High", "IsSelectable": True}]}

RES_WITH_ERRORS = {'ValidationMessages': [
    {'ResourcedMessage': 'The Type field is a required field.'},
    {'ResourcedMessage': 'The Device Name field is a required field.'}]}

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


def test_extract_from_xml():
    field_id = extract_from_xml(XML_FOR_TEST, 'Envelope.Body.GetValueListForField.fieldId')
    assert field_id == '6969'


def test_get_level_by_app_id(requests_mock):
    requests_mock.post(BASE_URL + 'api/core/security/login',
                       json={'RequestedObject': {'SessionToken': 'session-id'}})

    requests_mock.get(BASE_URL + 'api/core/system/level/module/1', json=GET_LEVEL_RES)
    requests_mock.get(BASE_URL + 'api/core/system/fielddefinition/level/123', json=FIELD_DEFINITION_RES)
    client = Client(BASE_URL, '', '', '', '')

    levels = client.get_level_by_app_id('1')
    assert levels == GET_LEVELS_BY_APP


def test_generate_field_contents():
    client = Client(BASE_URL, '', '', '', '')
    field = generate_field_contents(client, '{"Device Name":"Macbook"}', GET_LEVELS_BY_APP[0]['mapping'])
    assert field == {'2': {'Type': 1, 'Value': 'Macbook', 'FieldId': '2'}}


def test_get_errors_from_res():
    errors = get_errors_from_res(RES_WITH_ERRORS)
    assert errors == 'The Type field is a required field.\nThe Device Name field is a required field.'


def test_get_record_failed(requests_mock):
    requests_mock.post(BASE_URL + 'api/core/security/login',
                       json={'RequestedObject': {'SessionToken': 'session-id'}})
    requests_mock.get(BASE_URL + 'api/core/content/1010', json=GET_RECORD_RES_failed)
    client = Client(BASE_URL, '', '', '', '')
    record, res, errors = client.get_record(75, 1010)
    assert errors == 'No resource found.'
    assert res
    assert record == {}


def test_get_record_success(requests_mock):
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


def test_record_to_incident():
    client = Client(BASE_URL, '', '', '', '')
    incident, incident_created_time = client.record_to_incident(INCIDENT_RECORD, 75, 'Date/Time Reported')
    assert incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ') == '2018-03-26T10:03:32Z'
    assert incident['name'] == 'RSA Archer Incident: 227602'
    assert incident['occurred'] == '2018-03-26T10:03:32Z'


def test_search_records(requests_mock):
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


def test_get_field_value_list(requests_mock):
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


def test_generate_field_value_text_input():
    client = Client(BASE_URL, '', '', '', '')
    field_key, field_value = generate_field_value(client, "", {'Type': 1}, "Demisto")
    assert field_key == 'Value'
    assert field_value == 'Demisto'


def test_generate_field_value_values_list_input(requests_mock):
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


def test_generate_field_external_link_input():
    client = Client(BASE_URL, '', '', '', '')
    field_key, field_value = generate_field_value(client, "", {'Type': 7},
                                                  [{"value": "github", "link": "https://github.com"},
                                                   {"value": "google", "link": "https://google.com"}])
    assert field_key == 'Value'
    assert field_value == [{"Name": "github", "URL": "https://github.com"},
                           {"Name": "google", "URL": "https://google.com"}]


def test_generate_field_users_groups_input():
    client = Client(BASE_URL, '', '', '', '')
    field_key, field_value = generate_field_value(client, "", {'Type': 8}, {"users": [20], "groups": [30]})
    assert field_key == 'Value'
    assert field_value == {"UserList": [{"ID": 20}], "GroupList": [{"ID": 30}]}


def test_generate_field_cross_reference_input():
    client = Client(BASE_URL, '', '', '', '')
    field_key, field_value = generate_field_value(client, "", {'Type': 9}, [1, 2])
    assert field_key == 'Value'
    assert field_value == [{"ContentID": 1}, {"ContentID": 2}]


def test_generate_field_ip_address_input():
    client = Client(BASE_URL, '', '', '', '')
    field_key, field_value = generate_field_value(client, "", {'Type': 19}, '127.0.0.1')
    assert field_key == 'IpAddressBytes'
    assert field_value == '127.0.0.1'
