import pytest
import demistomock as demisto
import time


def test_filter_creator():
    from Lockpath_KeyLight_v2 import create_filter
    filt = create_filter('Starts With', 'Blue', '3881')
    check = {
        "FieldPath": [
            3881
        ],
        "FilterType": "3",
        "Value": "Blue"
    }

    assert filt == check

    with pytest.raises(ValueError, match='Filter Type is invalid.'):
        create_filter('>=', '5', '3881')


def test_update_field_integration_context(mocker, requests_mock):
    # adding new component to context
    from Lockpath_KeyLight_v2 import Client
    from Lockpath_KeyLight_v2 import INTEGRATION_CONTEXT_SIZE
    client = Client("http://example.com", False, False, headers={'Accept': 'application/json'})
    mocker.patch.object(demisto, 'setIntegrationContext')
    requests_mock.get('http://example.com/ComponentService/GetFieldList', json=[
        {
            "Id": 2260,
            "Name": "AuthenticationTypes",
            "SystemName": "AuthenticationTypes",
            "ShortName": "AuthenticationTypes",
            "ReadOnly": True,
            "Required": False,
            "FieldType": 5,
            "OneToMany": True,
            "MatrixRows": []
        },
        {
            "Id": 1501,
            "Name": "Auto-Apply Status",
            "SystemName": "AutoApplyStatus",
            "ShortName": "AutoApplyStatus",
            "ReadOnly": False,
            "Required": False,
            "FieldType": 5,
            "OneToMany": False,
            "MatrixRows": []
        },
        {
            "Id": 1511,
            "Name": "Configuration Findings",
            "SystemName": "ConfigFindings",
            "ShortName": "ConfigFindings",
            "ReadOnly": False,
            "Required": False,
            "FieldType": 5,
            "OneToMany": True,
            "MatrixRows": []
        }])
    for i in range(INTEGRATION_CONTEXT_SIZE):
        client.update_field_integration_context(str(i))

    # check the fields were saved corredctly
    assert demisto.getIntegrationContext().get('1').get('fields') == {'1501': 'Auto-Apply Status',
                                                                      '1511': 'Configuration Findings',
                                                                      '2260': 'AuthenticationTypes'}
    assert len(demisto.getIntegrationContext()) == INTEGRATION_CONTEXT_SIZE

    # Check update was done ok
    # lenght is still INTEGRATION_CONTEXT_SIZE
    time.sleep(1)
    client.update_field_integration_context(str(INTEGRATION_CONTEXT_SIZE + 1))
    assert len(demisto.getIntegrationContext()) == INTEGRATION_CONTEXT_SIZE
    # 0 was removed
    assert demisto.getIntegrationContext().get('0', 'Not found') == 'Not found'
    # INTEGRATION_CONTEXT_SIZE was added
    assert demisto.getIntegrationContext().get(str(INTEGRATION_CONTEXT_SIZE + 1), 'Not found') != 'Not found'


def test_field_output_to_hr_fields(mocker, requests_mock):
    from Lockpath_KeyLight_v2 import Client
    client = Client("http://example.com", False, False, headers={'Accept': 'application/json'})
    mocker.patch.object(demisto, 'setIntegrationContext')
    requests_mock.get('http://example.com/ComponentService/GetFieldList', json=[
        {
            "Id": 2260,
            "Name": "AuthenticationTypes",
            "SystemName": "AuthenticationTypes",
            "ShortName": "AuthenticationTypes",
            "ReadOnly": True,
            "Required": False,
            "FieldType": 5,
            "OneToMany": True,
            "MatrixRows": []
        }])
    assert client.field_output_to_hr_fields([{'Key': '2260', 'Value': 'check authentication'}],
                                            '1') == {'AuthenticationTypes': 'check authentication'}

    # Check if a new field gets update
    requests_mock.get('http://example.com/ComponentService/GetFieldList', json=[
        {
            "Id": 2260,
            "Name": "AuthenticationTypes",
            "SystemName": "AuthenticationTypes",
            "ShortName": "AuthenticationTypes",
            "ReadOnly": True,
            "Required": False,
            "FieldType": 5,
            "OneToMany": True,
            "MatrixRows": []
        },
        {
            "Id": 2261,
            "Name": "New Field",
            "SystemName": "New Field",
            "ShortName": "New Field",
            "ReadOnly": True,
            "Required": False,
            "FieldType": 5,
            "OneToMany": True,
            "MatrixRows": []
        }])
    assert client.field_output_to_hr_fields([{'Key': '2260', 'Value': 'check authentication'},
                                             {'Key': '2261', 'Value': 'check new field'}],
                                            '1') == {'AuthenticationTypes': 'check authentication',
                                                     'New Field': 'check new field'}


def test_string_to_key_value(mocker, requests_mock):
    from Lockpath_KeyLight_v2 import Client
    client = Client("https://example.com/'", False, False, headers={'Accept': 'application/json'})
    requests_mock.get('http://example.com/ComponentService/GetFieldList', json=[
        {
            "Id": 2260,
            "Name": "AuthenticationTypes",
            "SystemName": "AuthenticationTypes",
            "ShortName": "AuthenticationTypes",
            "ReadOnly": True,
            "Required": False,
            "FieldType": 5,
            "OneToMany": True,
            "MatrixRows": []
        }])
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'10359': {
        'fields': {'1': 'Audit Project', '2': 'Task ID', '3': 'Updated At'}}})

    json = [{"fieldName": "Task ID", "value": "Updated by Demisto Test Playbook", "isLookup": False},
            {"fieldName": "Audit Project", "value": 3, "isLookup": True}]
    field_value = client.string_to_FieldValues(json, '10359')
    assert field_value == [{'Key': '2', 'Value': 'Updated by Demisto Test Playbook'},
                           {'Key': '1', 'Value': {'Id': 3}}]
