from pytest import raises, skip
from CommonServerPython import *
from dateutil.parser import parse
from SymantecDLP import main, get_cache_path
import os
from unittest.mock import MagicMock


def test_get_incident_attributes():
    from SymantecDLP import get_incident_attributes
    attributes_input = {
        'Test': 'test',
        'severity': 'High',
        'custom_attribute_name': 'can',
        'custom_attribute_value': 'cav',
        'data_owner_name': 'don',
        'data_owner_email': 'doe',
        'note': 'note_msg',
        'note_time': '2018-08-06T18:30:50.833000+05:30'
    }
    attributes_output_one = {
        'severity': 'High',
        'note': {
            'dateAndTime': parse('2018-08-06T18:30:50.833000+05:30'),
            'note': 'note_msg'
        },
        'customAttribute': {
            'name': 'can',
            'value': 'cav'
        },
        'dataOwner': {
            'name': 'don',
            'email': 'doe'
        },
    }
    attributes_output_two = {
        'severity': 'High'
    }
    assert attributes_output_one == get_incident_attributes(attributes_input)
    del attributes_input['custom_attribute_name']
    with raises(DemistoException, match="If updating an incident's custom attribute,"
                                        " both custom_attribute_name and custom_attribute_value must be provided."):
        get_incident_attributes(attributes_input)
    del attributes_input['custom_attribute_value']
    del attributes_input['data_owner_email']
    with raises(DemistoException, match="If updating an incident's data owner,"
                                        " both data_owner_name and data_owner_email must be provided."):
        get_incident_attributes(attributes_input)
    del attributes_input['data_owner_name']
    del attributes_input['note_time']
    with raises(DemistoException, match="If adding an incident's note, both note and note_time must be provided."):
        get_incident_attributes(attributes_input)
    del attributes_input['note']
    assert attributes_output_two == get_incident_attributes(attributes_input)


def test_parse_component():
    from SymantecDLP import parse_component
    components_bytes_input = [
        {
            'componentId': 69065,
            'name': 'CCN.txt',
            'componentTypeId': 3,
            'componentType': 'ATTACHMENT_TEXT',
            'content': '4386280016300125',
            'componentLongId': 69065
        }
    ]
    components_regular_input = [
        {
            'componentId': 69065,
            'name': 'CCN.txt',
            'componentTypeId': 3,
            'componentType': 'ATTACHMENT_TEXT',
            'content': '4386280016300125',
            'componentLongId': 69065
        }
    ]
    components_bytes_output = [
        {
            'ID': 69065,
            'Name': 'CCN.txt',
            'TypeID': 3,
            'Type': 'ATTACHMENT_TEXT',
            'Content': '4386280016300125',
            'LongID': 69065
        }
    ]
    components_regular_output = [
        {
            'ID': 69065,
            'Name': 'CCN.txt',
            'TypeID': 3,
            'Type': 'ATTACHMENT_TEXT',
            'Content': '4386280016300125',
            'LongID': 69065
        }
    ]
    assert components_bytes_output == parse_component(components_bytes_input)
    assert components_regular_output == parse_component(components_regular_input)


def test_parse_custom_attribute():
    from SymantecDLP import parse_custom_attribute
    custom_attribute_group_list = [
        {
            'customAttribute': [
                {
                    'name': 'cn',
                    'value': None
                }
            ],
            'name': 'Default Attribute Group'
        },
        {
            'customAttribute': [
                {
                    'name': 'Resolution',
                    'value': None
                },
                {
                    'name': 'First Name',
                    'value': 'Admin'
                }
            ],
            'name': 'Predefined'
        }
    ]
    args_all = {'custom_attributes': 'all'}
    custom_attribute_all_list_output = [
        {'Name': 'cn'},
        {'Name': 'Resolution'},
        {'Name': 'First Name', 'Value': 'Admin'}
    ]
    assert custom_attribute_all_list_output == parse_custom_attribute(custom_attribute_group_list, args_all)
    args_none = {'custom_attributes': 'none'}
    assert [] == parse_custom_attribute(custom_attribute_group_list, args_none)
    args_custom = {'custom_attributes': 'specific attributes'}
    with raises(DemistoException, match='When choosing the custom value for custom_attributes argument -'
                                        ' the custom_data list must be filled with custom attribute names.'
                                        ' For example: custom_value=ca1,ca2,ca3'):
        parse_custom_attribute(custom_attribute_group_list, args_custom)
    args_custom['custom_data'] = 'cn, First Name, bbb'
    custom_attribute_custom_list_output = [
        {'Name': 'cn'},
        {'Name': 'First Name', 'Value': 'Admin'}
    ]
    assert custom_attribute_custom_list_output == parse_custom_attribute(custom_attribute_group_list, args_custom)
    args_custom['custom_data'] = 'aaa'
    assert [] == parse_custom_attribute(custom_attribute_group_list, args_custom)
    args_group = {'custom_attributes': 'custom attributes group name'}
    with raises(DemistoException, match='When choosing the group value for custom_attributes argument -'
                                        ' the custom_data list must be filled with group names.'
                                        ' For example: custom_value=g1,g2,g3'):
        parse_custom_attribute(custom_attribute_group_list, args_group)
    args_group['custom_data'] = 'Default Attribute Group, Predefined, uuu'
    custom_attribute_group_list_output = [
        {'Name': 'cn'},
        {'Name': 'Resolution'},
        {'Name': 'First Name', 'Value': 'Admin'}
    ]
    assert custom_attribute_group_list_output == parse_custom_attribute(custom_attribute_group_list, args_group)


def test_parse_violating_component():
    from SymantecDLP import parse_violating_component
    violating_component_list_input = [
        {
            'name': 'C:\\Users\\Administrator\\Desktop\\CCN.txt',
            'documentFormat': 'ascii',
            'violatingComponentType': {
                '_value_1': 'Attachment',
                'id': 3
            },
            'violationCount': 1,
            'violatingSegment': [
                {
                    'documentViolation': None,
                    'fileSizeViolation': None,
                    'text': [
                        {
                            '_value_1': '4386280016300125',
                            'type': 'Violation',
                            'ruleId': 12288,
                            'ruleName': 'CCN number'
                        },
                        {
                            '_value_1': '\n',
                            'type': 'NonViolation',
                            'ruleId': None,
                            'ruleName': None
                        }
                    ]
                }
            ],
            'violatingImageInformation': [],
            'id': 69248,
            'longId': 69248
        }
    ]
    violating_component_list_output = [
        {
            'Name': 'C:\\Users\\Administrator\\Desktop\\CCN.txt',
            'DocumentFormat': 'ascii',
            'Type': 'Attachment',
            'TypeID': 3,
            'ViolatingCount': 1,
            'ViolationSegment': [
                {
                    'Text': [
                        {
                            'Data': '4386280016300125',
                            'Type': 'Violation',
                            'RuleID': 12288,
                            'RuleName': 'CCN number'
                        },
                        {
                            'Data': '\n',
                            'Type': 'NonViolation'
                        }
                    ]
                }
            ]
        }
    ]
    assert violating_component_list_output == parse_violating_component(violating_component_list_input)


def test_get_data_owner():
    from SymantecDLP import get_data_owner
    input_empty_data_owner = {}
    input_diff_data_owner_type = []
    input_valid_data_owner = {
        'name': 'TestName',
        'email': 'TestEmail'
    }
    output_empty_data_owner = {}
    output_diff_data_owner = {}
    output_valid_data_owner = {
        'Name': 'TestName',
        'Email': 'TestEmail'
    }
    assert output_empty_data_owner == get_data_owner(input_empty_data_owner)
    assert output_diff_data_owner == get_data_owner(input_diff_data_owner_type)
    assert output_valid_data_owner == get_data_owner(input_valid_data_owner)


def test_get_cache_path():
    path = get_cache_path()
    assert path.endswith('cache.db')
    test_path = path + '.test'
    # make sure we are able to create a file in this path (test for non-root user in docker)
    f = open(test_path, mode='w')
    f.close()
    os.remove(test_path)


def test_get_cache_path_static():
    # make sure static cache is copied
    if not os.getenv('DOCKER_IMAGE', None):
        skip('Skipping test as DOCKER_IMAGE not set. This test is meant to run within docker: demisto/zeep:1.0.0.8897 and above')
    assert 'cache.db' in os.getenv('ZEEP_STATIC_CACHE_DB')
    path = get_cache_path()
    assert path.endswith('cache.db')
    assert os.path.isfile(path)
    f = open(path, mode='r+b')
    f.close()


def test_self_signed_insecure_ssl(mocker):
    # test that we fail on an error other than certificate when insecure is True
    os.environ['REQUESTS_CA_BUNDLE'] = '/etc/ssl/certs/ca-certificates.crt'
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'https://self-signed.badssl.com/',
        'insecure': True
    })
    mocker.patch.object(demisto, 'command', return_value='test-module')
    try:
        main()
    except Exception as ex:
        assert 'certificate' not in str(ex).lower(), f'got certificate error: {ex}'


def test_self_signed_secure_ssl(mocker):
    # test that we fail on a certificate error when insecure is False
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'https://self-signed.badssl.com/',
        'insecure': False
    })
    mocker.patch.object(demisto, 'command', return_value='test-module')
    try:
        main()
    except Exception as ex:
        assert 'certificate' in str(ex).lower()


def test_fetch_incidents(mocker):
    """
    Given:
        - 2 DLP incidents to fetch
        - Fetch limit set to 1

    When:
        - Fetching incidents

    Then:
        - Ensure last run is set as expected with the incident fetched
    """
    dlp_incident1 = {
        'incident': {
            'incidentCreationDate': 'date1'
        }
    }
    dlp_incident2 = {
        'incident': {
            'incidentCreationDate': 'date2'
        }
    }
    import SymantecDLP
    last_run = mocker.patch.object(demisto, 'setLastRun')
    client = MagicMock()
    mocker.patch('SymantecDLP.helpers.serialize_object', side_effect=[{'incidentId': [1, 2]}, dlp_incident1, dlp_incident2])
    mocker.patch.object(SymantecDLP, 'get_incident_binaries', return_value=(None, None, None, None,))
    SymantecDLP.fetch_incidents(
        client=client,
        fetch_time='3 days',
        fetch_limit=1,
        last_run={},
        saved_report_id=''
    )
    last_run = last_run.call_args[0][0]
    assert last_run == {'last_fetched_event_iso': 'date1', 'last_incident_id': 1}
