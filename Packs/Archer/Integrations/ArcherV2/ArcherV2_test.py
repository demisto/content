from ArcherV2 import Client, extract_from_xml, generate_field_contents, get_errors_from_res, get_file

BASE_URL = 'https://test.com/'

XML_FOR_TEST= '<?xml version="1.0" encoding="utf-8"?>' + \
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
    {"IsSuccessful": True, "RequestedObject": {"Id": 2, "Type": 1, "Name": "Device Name", "IsRequired": True, "RelatedValuesListId": 8}}]

GET_LEVELS_BY_APP = [{'level': 123, 'mapping':
                     {'1': {'Type': 7, 'Name': 'External Links', 'IsRequired': False, 'RelatedValuesListId': None},
                      '2': {'Type': 1, 'Name': 'Device Name', 'IsRequired': True, 'RelatedValuesListId': 8}}}]

RES_WITH_ERRORS = {'ValidationMessages': [
    {'ResourcedMessage': 'The Type field is a required field.'},
    {'ResourcedMessage': 'The Device Name field is a required field.'}]}

def test_extract_from_xml():
    field_id = extract_from_xml(XML_FOR_TEST, 'Envelope.Body.GetValueListForField.fieldId')
    assert field_id == '6969'


def test_get_level_by_app_id(requests_mock):
    requests_mock.post(BASE_URL + 'rsaarcher/api/core/security/login',
                       json={'RequestedObject': {'SessionToken': 'session-id'}})

    requests_mock.get(BASE_URL + 'rsaarcher/api/core/system/level/module/1', json=GET_LEVEL_RES)
    requests_mock.get(BASE_URL + 'rsaarcher/api/core/system/fielddefinition/level/123', json=FIELD_DEFINITION_RES)
    client = Client(BASE_URL, '', '', '', '')

    levels = client.get_level_by_app_id('1')
    assert levels == GET_LEVELS_BY_APP


def test_generate_field_contents():
    field = generate_field_contents('{"Device Name":"Macbook"}', GET_LEVELS_BY_APP[0]['mapping'])
    assert field =={'2': {'Type': 1, 'Value': 'Macbook', 'FieldId': '2'}}


def test_get_errors_from_res():
    errors = get_errors_from_res(RES_WITH_ERRORS)
    assert errors == 'The Type field is a required field.\nThe Device Name field is a required field.'
