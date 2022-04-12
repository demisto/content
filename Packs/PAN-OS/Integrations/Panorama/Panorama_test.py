import json

import pytest

import demistomock as demisto
from lxml import etree
from unittest.mock import patch, MagicMock
from panos.device import Vsys
from panos.panorama import Panorama, DeviceGroup, Template
from panos.firewall import Firewall
from CommonServerPython import DemistoException

integration_params = {
    'port': '443',
    'vsys': 'vsys1',
    'server': 'https://1.1.1.1',
    'key': 'thisisabogusAPIKEY!',
}

mock_demisto_args = {
    'threat_id': "11111",
    'vulnerability_profile': "mock_vuln_profile"
}


@pytest.fixture(autouse=True)
def set_params(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)
    mocker.patch.object(demisto, 'args', return_value=mock_demisto_args)


@pytest.fixture
def patched_requests_mocker(requests_mock):
    """
    This function mocks various PANOS API responses so we can accurately test the instance
    """
    base_url = "{}:{}/api/".format(integration_params['server'], integration_params['port'])
    # Version information
    mock_version_xml = """
    <response status = "success">
        <result>
            <sw-version>9.0.6</sw-version>
            <multi-vsys>off</multi-vsys>
            <model>Panorama</model>
            <serial>FAKESERIALNUMBER</serial>
        </result>
    </response>
    """
    version_path = "{}{}{}".format(base_url, "?type=version&key=", integration_params['key'])
    requests_mock.get(version_path, text=mock_version_xml, status_code=200)
    mock_response_xml = """
    <response status="success" code="20">
    <msg>command succeeded</msg>
    </response>
    """
    requests_mock.post(base_url, text=mock_response_xml, status_code=200)
    return requests_mock


def test_panorama_get_os_version(patched_requests_mocker):
    from Panorama import get_pan_os_version
    import Panorama
    Panorama.URL = 'https://1.1.1.1:443/api/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    r = get_pan_os_version()
    assert r == '9.0.6'


def test_panorama_override_vulnerability(patched_requests_mocker):
    from Panorama import panorama_override_vulnerability
    import Panorama
    Panorama.URL = 'https://1.1.1.1:443/api/'
    r = panorama_override_vulnerability(mock_demisto_args['threat_id'], mock_demisto_args['vulnerability_profile'],
                                        'reset-both')
    assert r['response']['@status'] == 'success'


def test_add_argument_list():
    from Panorama import add_argument_list
    list_argument = ["foo", "bar"]

    response_with_member = add_argument_list(list_argument, "test", True)
    expected_with_member = '<test><member>foo</member><member>bar</member></test>'
    assert response_with_member == expected_with_member

    response_with_member_field_name = add_argument_list(list_argument, "member", True)
    expected_with_member_field_name = '<member>foo</member><member>bar</member>'
    assert response_with_member_field_name == expected_with_member_field_name


def test_add_argument():
    from Panorama import add_argument
    argument = "foo"

    response_with_member = add_argument(argument, "test", True)
    expected_with_member = '<test><member>foo</member></test>'
    assert response_with_member == expected_with_member

    response_without_member = add_argument(argument, "test", False)
    expected_without_member = '<test>foo</test>'
    assert response_without_member == expected_without_member


def test_add_argument_yes_no():
    from Panorama import add_argument_yes_no
    arg = 'No'
    field = 'test'
    option = True

    response_option_true = add_argument_yes_no(arg, field, option)
    expected_option_true = '<option><test>no</test></option>'
    assert response_option_true == expected_option_true

    option = False
    response_option_false = add_argument_yes_no(arg, field, option)
    expected_option_false = '<test>no</test>'
    assert response_option_false == expected_option_false


def test_add_argument_target():
    from Panorama import add_argument_target
    response = add_argument_target('foo', 'bar')
    expected = '<bar><devices><entry name=\"foo\"/></devices></bar>'
    assert response == expected


def test_prettify_addresses_arr():
    from Panorama import prettify_addresses_arr
    addresses_arr = [{'@name': 'my_name', 'fqdn': 'a.com'},
                     {'@name': 'my_name2', 'fqdn': 'b.com'},
                     {'@name': 'test', 'ip-netmask': '1.1.1.1', 'tag': None}]
    response = prettify_addresses_arr(addresses_arr)
    expected = [{'Name': 'my_name', 'FQDN': 'a.com'},
                {'Name': 'my_name2', 'FQDN': 'b.com'},
                {'Name': 'test', 'IP_Netmask': '1.1.1.1'}]
    assert response == expected


def test_prettify_address():
    from Panorama import prettify_address
    address = {'@name': 'my_name', 'ip-netmask': '1.1.1.1', 'description': 'lala'}
    response = prettify_address(address)
    expected = {'Name': 'my_name', 'IP_Netmask': '1.1.1.1', 'Description': 'lala'}
    assert response == expected


def test_prettify_address_tag_none():
    from Panorama import prettify_address
    address = {'@name': 'test', 'ip-netmask': '1.1.1.1', 'tag': None}
    response = prettify_address(address)
    expected = {'Name': 'test', 'IP_Netmask': '1.1.1.1'}
    assert response == expected


def test_prettify_address_group():
    from Panorama import prettify_address_group
    address_group_static = {'@name': 'foo', 'static': {'member': 'address object'}}
    response_static = prettify_address_group(address_group_static)
    expected_address_group_static = {'Name': 'foo', 'Type': 'static', 'Addresses': 'address object'}
    assert response_static == expected_address_group_static

    address_group_dynamic = {'@name': 'foo', 'dynamic': {'filter': '1.1.1.1 and 2.2.2.2'}}
    response_dynamic = prettify_address_group(address_group_dynamic)
    expected_address_group_dynamic = {'Name': 'foo', 'Type': 'dynamic', 'Match': '1.1.1.1 and 2.2.2.2'}
    assert response_dynamic == expected_address_group_dynamic

    address_group_dynamic_tag_none = {'@name': 'foo', 'dynamic': {'filter': '1.1.1.1 or 2.2.2.2'}, 'tag': None}
    response_dynamic_tag_none = prettify_address_group(address_group_dynamic_tag_none)
    expected_address_group_dynamic_tag_none = {'Name': 'foo', 'Type': 'dynamic', 'Match': '1.1.1.1 or 2.2.2.2'}
    assert response_dynamic_tag_none == expected_address_group_dynamic_tag_none


def test_prettify_service():
    from Panorama import prettify_service
    service = {'@name': 'service_name', 'description': 'foo', 'protocol': {'tcp': {'port': '443'}}}
    response = prettify_service(service)
    expected = {'Name': 'service_name', 'Description': 'foo', 'Protocol': 'tcp', 'DestinationPort': '443'}
    assert response == expected


def test_prettify_service_tag_none():
    from Panorama import prettify_service
    service = {'@name': 'service_name', 'description': 'foo', 'protocol': {'tcp': {'port': '443'}}, 'tag': None}
    response = prettify_service(service)
    expected = {'Name': 'service_name', 'Description': 'foo', 'Protocol': 'tcp', 'DestinationPort': '443'}
    assert response == expected


def test_prettify_service_group():
    from Panorama import prettify_service_group
    service_group = {'@name': 'sg', 'members': {'member': ['service1', 'service2']}}
    response = prettify_service_group(service_group)
    expected = {'Name': 'sg', 'Services': ['service1', 'service2']}
    assert response == expected


def test_prettify_service_group_tag_none():
    from Panorama import prettify_service_group
    service_group = {'@name': 'sg_group', 'members': {'member': ['service1', 'service2']}, 'tag': None}
    response = prettify_service_group(service_group)
    expected = {'Name': 'sg_group', 'Services': ['service1', 'service2']}
    assert response == expected


def test_prettify_custom_url_category():
    from Panorama import prettify_custom_url_category
    custom_url_category = {'@name': 'foo', 'list': {'member': ['a', 'b', 'c']}}
    response = prettify_custom_url_category(custom_url_category)
    expected = {'Name': 'foo', 'Sites': ['a', 'b', 'c']}
    assert response == expected


def test_panorama_create_custom_url_category_8_x(mocker):
    """
    Given:
     - an only > 9.x valid argument for custom url category creation

    When:
     - running the panorama_create_custom_url_category function
     - mocking the pan-os version to be 8.x

    Then:
     - a proper error is raised
    """
    from Panorama import panorama_create_custom_url_category
    mocker.patch('Panorama.get_pan_os_major_version', return_value=8)
    custom_url_category_name = 'name'
    description = 'test_desc'
    type_ = 'URL List'

    with pytest.raises(DemistoException,
                       match='The type and categories arguments are only relevant for PAN-OS 9.x versions.'):
        panorama_create_custom_url_category(custom_url_category_name, type_=type_, description=description)


def test_panorama_create_custom_url_category_9_x(mocker):
    """
    Given:
     - a non valid argument for custom url category creation

    When:
     - running the panorama_create_custom_url_category function
     - mocking the pan-os version to be 9.x

    Then:
     - a proper error is raised
    """
    from Panorama import panorama_create_custom_url_category
    mocker.patch('Panorama.get_pan_os_major_version', return_value=9)
    custom_url_category_name = 'name'
    type_ = 'URL List'
    categories = 'phishing'
    sites = 'a.com'
    description = 'test_desc'

    with pytest.raises(DemistoException,
                       match='The type argument is mandatory for PAN-OS 9.x versions.'):
        panorama_create_custom_url_category(custom_url_category_name, sites=sites, description=description)

    with pytest.raises(DemistoException,
                       match='Exactly one of the sites and categories arguments should be defined.'):
        panorama_create_custom_url_category(custom_url_category_name, type_=type_, sites=sites, categories=categories)

    with pytest.raises(DemistoException,
                       match='URL List type is only for sites, Category Match is only for categories.'):
        panorama_create_custom_url_category(custom_url_category_name, type_=type_, categories=categories)


def test_create_url_filter_params_8_x(mocker):
    """
    Given:
     - a valid argument for url filter creation

    When:
     - running the create_url_filter_params utility function
     - mocking the pan-os version to be 8.x

    Then:
     - a proper xml element is generated
    """
    from Panorama import create_url_filter_params
    mocker.patch('Panorama.get_pan_os_major_version', return_value=8)
    url_filter_name = 'name'
    action = 'alert'
    url_category_list = 'adult'
    description = 'test_desc'

    url_filter_params = create_url_filter_params(url_filter_name, action, url_category_list=url_category_list,
                                                 description=description)
    assert url_filter_params['element'].find('<action>block</action>') != -1  # if not -1, then it is found


def test_create_url_filter_params_9_x(mocker):
    """
    Given:
     - a valid argument for url filter creation

    When:
     - running the create_url_filter_params utility function
     - mocking the pan-os version to be 9.x

    Then:
     - a proper xml element is generated
    """
    from Panorama import create_url_filter_params
    mocker.patch('Panorama.get_pan_os_major_version', return_value=9)
    url_filter_name = 'name'
    action = 'alert'
    url_category_list = 'adult'
    description = 'test_desc'

    url_filter_params = create_url_filter_params(url_filter_name, action, url_category_list=url_category_list,
                                                 description=description)
    assert url_filter_params['element'].find('<action>block</action>') == -1  # if  -1, then it is not found


def test_edit_url_filter_non_valid_args_8_x(mocker):
    """
    Given:
     - a non valid argument for edit url filter

    When:
     - running the edit_url_filter function
     - mocking the pan-os version to be 8.x

    Then:
     - a proper error is raised
    """
    from Panorama import panorama_edit_url_filter
    url_filter_object = {
        "@name": "fw_test_pb_dont_delete",
        "action": "block",
        "allow": {
            "member": [
                "Demisto- block sites",
                "test3"
            ]
        },
        "allow-list": {
            "member": "www.thepill2.com"
        },
        "block": {
            "member": [
                "abortion",
                "abused-drugs"
            ]
        },
        "block-list": {
            "member": "www.thepill.com"
        },
        "credential-enforcement": {
            "allow": {
                "member": [
                    "Demisto- block sites",
                    "test3"
                ]
            },
            "block": {
                "member": [
                    "abortion",
                    "abused-drugs"
                ]
            },
            "log-severity": "medium",
        },
        "description": "gogo"
    }
    mocker.patch('Panorama.get_pan_os_major_version', return_value=8)
    mocker.patch('Panorama.panorama_get_url_filter', return_value=url_filter_object)
    url_filter_name = 'fw_test_pb_dont_delete'
    element_to_change = 'allow_categories'
    element_value = 'gambling'
    add_remove_element = 'remove'

    err_msg = 'Only the override_allow_list, override_block_list, description properties can be' \
              ' changed in PAN-OS 8.x or earlier versions.'
    with pytest.raises(DemistoException, match=err_msg):
        panorama_edit_url_filter(url_filter_name, element_to_change, element_value, add_remove_element)


def test_edit_url_filter_non_valid_args_9_x(mocker):
    """
    Given:
     - a non valid argument for edit url filter

    When:
     - running the edit_url_filter function
     - mocking the pan-os version to be 9.x

    Then:
     - a proper error is raised
    """
    from Panorama import panorama_edit_url_filter
    url_filter_object = {
        "@name": "fw_test_pb_dont_delete",
        "allow": {
            "member": "Test_pb_custom_url_DONT_DELETE"
        },
        "credential-enforcement": {
            "block": {
                "member": [
                    "gambling",
                    "abortion"
                ]
            },
            "log-severity": "medium",
        },
        "description": "wowo"
    }
    mocker.patch('Panorama.get_pan_os_major_version', return_value=9)
    mocker.patch('Panorama.panorama_get_url_filter', return_value=url_filter_object)
    url_filter_name = 'fw_test_pb_dont_delete'
    element_to_change = 'override_block_list'
    element_value = 'gambling'
    add_remove_element = 'remove'

    err_msg = 'Only the allow_categories, block_categories, description properties can be changed in PAN-OS 9.x or' \
              ' later versions.'
    with pytest.raises(DemistoException, match=err_msg):
        panorama_edit_url_filter(url_filter_name, element_to_change, element_value, add_remove_element)


def http_mock(url: str, method: str, body: dict = {}):
    return body


@pytest.mark.parametrize('category_name, items', [('category_name', ['www.good.com'],)])
def test_remove_from_custom_url_category(category_name, items, mocker):
    """
    Given:
     - a valid argument for edit custom url group

    When:
     - running the custom_url_category_remove_items function

    Then:
     - checks an assertion
    """
    import Panorama
    from Panorama import panorama_custom_url_category_remove_items

    return_results_mock = mocker.patch.object(Panorama, 'return_results')

    mocker.patch('Panorama.panorama_get_custom_url_category', return_value={'description': 'description',
                                                                            'list': {'member': "www.test.com"}
                                                                            })
    mocker.patch('Panorama.get_pan_os_major_version', return_value=9)
    mocker.patch('Panorama.http_request', side_effect=http_mock)

    panorama_custom_url_category_remove_items(category_name, items, "URL List")
    demisto_result_got = return_results_mock.call_args.args[0]['Contents']
    assert "www.test.com" in demisto_result_got['element']


def test_prettify_edl():
    from Panorama import prettify_edl
    edl = {'@name': 'edl_name', 'type': {'my_type': {'url': 'abc.com', 'description': 'my_desc'}}}
    response = prettify_edl(edl)
    expected = {'Name': 'edl_name', 'Type': 'my_type', 'URL': 'abc.com', 'Description': 'my_desc'}
    assert response == expected


def test_build_traffic_logs_query():
    """
    Given:
     - a valid arguments for traffic logs query generation

    When:
     - running the build_traffic_logs_query utility function

    Then:
     - a proper query is generated
        (addr.src in 192.168.1.222) and (app eq netbios-dg) and (action eq allow) and (port.dst eq 138)
    """
    from Panorama import build_traffic_logs_query
    source = '192.168.1.222'
    application = 'netbios-dg'
    action = 'allow'
    to_port = '138'
    response = build_traffic_logs_query(source, None, None, application, to_port, action)
    expected = '(addr.src in 192.168.1.222) and (app eq netbios-dg) and (port.dst eq 138) and (action eq allow)'
    assert response == expected


def test_prettify_traffic_logs():
    from Panorama import prettify_traffic_logs
    traffic_logs = [{'action': 'my_action1', 'category': 'my_category1', 'rule': 'my_rule1'},
                    {'action': 'my_action2', 'category': 'my_category2', 'rule': 'my_rule2'}]
    response = prettify_traffic_logs(traffic_logs)
    expected = [{'Action': 'my_action1', 'Category': 'my_category1', 'Rule': 'my_rule1'},
                {'Action': 'my_action2', 'Category': 'my_category2', 'Rule': 'my_rule2'}]
    assert response == expected


def test_build_logs_query():
    """
    Given:
     - a valid arguments for logs query generation

    When:
     - running the build_logs_query utility function

    Then:
     - a proper query is generated
        ((url contains 'demisto.com') or (url contains 'paloaltonetworks.com'))
    """
    from Panorama import build_logs_query

    urls_as_string = "demisto.com, paloaltonetworks.com"
    response = build_logs_query(None, None, None, None, None, None, None, None, None, urls_as_string, None)
    expected = "((url contains 'demisto.com') or (url contains 'paloaltonetworks.com'))"
    assert response == expected


def test_prettify_logs():
    from Panorama import prettify_logs
    traffic_logs = [{'action': 'my_action1', 'category': 'my_category1', 'rule': 'my_rule1', 'natdport': '100',
                     'bytes': '12'},
                    {'action': 'my_action2', 'category': 'my_category2', 'rule': 'my_rule2', 'natdport': '101',
                     'bytes_sent': '11'}]
    response = prettify_logs(traffic_logs)
    expected = [{'Action': 'my_action1', 'CategoryOrVerdict': 'my_category1', 'Rule': 'my_rule1',
                 'NATDestinationPort': '100', 'Bytes': '12'},
                {'Action': 'my_action2', 'CategoryOrVerdict': 'my_category2', 'Rule': 'my_rule2',
                 'NATDestinationPort': '101', 'BytesSent': '11'}]
    assert response == expected


prepare_security_rule_inputs = [
    ('top', 'test_rule_name'),
    ('bottom', 'test_rule_name'),
]


@pytest.mark.parametrize('where, dst', prepare_security_rule_inputs)
def test_prepare_security_rule_params(where, dst):
    """
    Given:
     - a non valid arguments for the prepare_security_rule_params function

    When:
     - running the prepare_security_rule_params utility function

    Then:
     - a proper exception is raised
    """
    from Panorama import prepare_security_rule_params
    err_msg = 'Please provide a dst rule only when the where argument is before or after.'
    with pytest.raises(DemistoException, match=err_msg):
        prepare_security_rule_params(api_action='set', action='drop', destination=['any'], source=['any'],
                                     rulename='test', where=where, dst=dst)


def test_build_policy_match_query():
    """
    Given:
     - a valid arguments for policy match query generation

    When:
     - running the build_policy_match_query utility function

    Then:
     - a proper xml is generated
    """
    from Panorama import build_policy_match_query
    source = '1.1.1.1'
    destination = '6.7.8.9'
    protocol = '1'
    application = 'gmail-base'
    response = build_policy_match_query(application, None, destination, None, None, None, protocol, source)
    expected = '<test><security-policy-match><source>1.1.1.1</source><destination>6.7.8.9</destination>' \
               '<protocol>1</protocol><application>gmail-base</application></security-policy-match></test>'
    assert response == expected


def test_panorama_register_ip_tag_command_wrongful_args(mocker):
    """
    Given:
     - a non valid arguments for the panorama_register_ip_tag_command function

    When:
     - running the panorama_register_ip_tag_command function

    Then:
     - a proper exception is raised
    """
    from Panorama import panorama_register_ip_tag_command
    args = {'IPs': '1.1.1.1', 'tag': 'test_tag', 'persistent': 'true', 'timeout': '5'}

    mocker.patch('Panorama.get_pan_os_major_version', return_value=9)
    with pytest.raises(DemistoException,
                       match='When the persistent argument is true, you can not use the timeout argument.'):
        panorama_register_ip_tag_command(args)

    args['persistent'] = 'false'
    mocker.patch('Panorama.get_pan_os_major_version', return_value=8)
    with pytest.raises(DemistoException,
                       match='The timeout argument is only applicable on 9.x PAN-OS versions or higher.'):
        panorama_register_ip_tag_command(args)


def test_prettify_matching_rule():
    from Panorama import prettify_matching_rule
    matching_rule = {'action': 'my_action1', '@name': 'very_important_rule', 'source': '6.7.8.9', 'destination': 'any'}
    response = prettify_matching_rule(matching_rule)
    expected = {'Action': 'my_action1', 'Name': 'very_important_rule', 'Source': '6.7.8.9', 'Destination': 'any'}
    assert response == expected


def test_prettify_static_route():
    from Panorama import prettify_static_route
    static_route = {'@name': 'name1', 'destination': '1.2.3.4', 'metric': '10', 'nexthop': {'fqdn': 'demisto.com'}}
    virtual_router = 'my_virtual_router'
    response = prettify_static_route(static_route, virtual_router)
    expected = {'Name': 'name1', 'Destination': '1.2.3.4', 'Metric': 10,
                'NextHop': 'demisto.com', 'VirtualRouter': 'my_virtual_router'}
    assert response == expected


def test_validate_search_time():
    from Panorama import validate_search_time
    assert validate_search_time('2019/12/26')
    assert validate_search_time('2019/12/26 00:00:00')
    with pytest.raises(Exception):
        assert validate_search_time('219/12/26 00:00:00')
        assert validate_search_time('219/10/35')


def test_show_user_id_interface_config_command():
    """
    Given:
     - missing template and template_stack arguments for the show_user_id_interface_config_command command

    When:
     - running the show_user_id_interface_config_request function

    Then:
     - a proper exception is raised
    """
    from Panorama import show_user_id_interface_config_command
    args = {}
    str_match = 'In order to show the User Interface configuration in your Panorama, ' \
                'supply either the template or the template_stack arguments.'
    with pytest.raises(DemistoException, match=str_match):
        show_user_id_interface_config_command(args)


def test_prettify_user_interface_config():
    from Panorama import prettify_user_interface_config
    raw_response = [{'@name': 'internal', 'network': {'layer3': {'member': 'ethernet1/2'},
                                                      'log-setting': 'ToLoggingService'},
                     'enable-user-identification': 'yes'},
                    {'@name': 'External', 'network': {'tap': {'member': 'ethernet1/1'},
                                                      'log-setting': 'ToLoggingService'}}]
    response = prettify_user_interface_config(raw_response)
    expected = [{'Name': 'ethernet1/2', 'Zone': 'internal', 'EnableUserIdentification': 'yes'},
                {'Name': 'ethernet1/1', 'Zone': 'External', 'EnableUserIdentification': 'no'}]
    assert response == expected


def test_list_configured_user_id_agents_command(mocker):
    """
    Given:
     - missing template and template_stack arguments for the list_configured_user_id_agents_command command

    When:
     - running the list_configured_user_id_agents_request function

    Then:
     - a proper exception is raised
    """
    from Panorama import list_configured_user_id_agents_command
    mocker.patch('Panorama.get_pan_os_major_version', return_value=9)
    args = {}
    str_match = 'In order to show the the User ID Agents in your Panorama, ' \
                'supply either the template or the template_stack arguments.'
    with pytest.raises(DemistoException, match=str_match):
        list_configured_user_id_agents_command(args)


def test_prettify_configured_user_id_agents__multi_result():
    from Panorama import prettify_configured_user_id_agents
    raw_response = [{'@name': 'testing2', 'serial-number': 'panorama2'},
                    {'@name': 'fullinfo', 'host-port': {'port': '67', 'ntlm-auth': 'yes',
                                                        'ldap-proxy': 'yes', 'collectorname': 'demisto',
                                                        'secret': 'secret', 'host': 'what'}, 'ip-user-mappings': 'yes'}]
    response = prettify_configured_user_id_agents(raw_response)
    expected = [{'Name': 'testing2', 'Host': None, 'Port': None, 'NtlmAuth': 'no', 'LdapProxy': 'no',
                 'CollectorName': None, 'Secret': None, 'EnableHipCollection': 'no', 'SerialNumber': 'panorama2',
                 'IpUserMapping': 'no', 'Disabled': 'no'},
                {'Name': 'fullinfo', 'Host': 'what', 'Port': '67', 'NtlmAuth': 'yes', 'LdapProxy': 'yes',
                 'CollectorName': 'demisto', 'Secret': 'secret', 'EnableHipCollection': 'no', 'SerialNumber': None,
                 'IpUserMapping': 'yes', 'Disabled': 'no'}]
    assert response == expected


def test_prettify_configured_user_id_agents__single_result():
    from Panorama import prettify_configured_user_id_agents
    raw_response = {'@name': 'fullinfo', 'host-port': {'port': '67', 'ntlm-auth': 'yes',
                                                       'ldap-proxy': 'yes', 'collectorname': 'demisto',
                                                       'secret': 'secret', 'host': 'what'}, 'ip-user-mappings': 'yes'}
    response = prettify_configured_user_id_agents(raw_response)
    expected = {'Name': 'fullinfo', 'Host': 'what', 'Port': '67', 'NtlmAuth': 'yes', 'LdapProxy': 'yes',
                'CollectorName': 'demisto', 'Secret': 'secret', 'EnableHipCollection': 'no', 'SerialNumber': None,
                'IpUserMapping': 'yes', 'Disabled': 'no'}
    assert response == expected


def test_prettify_rule():
    from Panorama import prettify_rule
    with open("test_data/rule.json") as f:
        rule = json.load(f)

    with open("test_data/prettify_rule.json") as f:
        expected_prettify_rule = json.load(f)

    prettify_rule = prettify_rule(rule)

    assert prettify_rule == expected_prettify_rule


class TestPcap:

    @staticmethod
    def test_list_pcaps_flow_with_no_existing_pcaps(mocker):
        """
        Given -
            a response which indicates there are no pcap files on the firewall.

        When -
            listing all the available pcap files.

        Then -
            make sure that a message which indicates there are no Pcaps is printed out.
        """
        from Panorama import panorama_list_pcaps_command
        no_pcaps_response = MockedResponse(
            text='<?xml version="1.0"?>\n<response status="success">\n  '
                 '<result>\n    <dir-listing/>\n  </result>\n</response>\n',
            status_code=200,
        )

        mocker.patch('Panorama.http_request', return_value=no_pcaps_response)
        results_mocker = mocker.patch.object(demisto, "results")
        panorama_list_pcaps_command({'pcapType': 'filter-pcap'})
        assert results_mocker.called
        assert results_mocker.call_args.args[0] == 'PAN-OS has no Pcaps of type: filter-pcap.'

    @staticmethod
    def test_get_specific_pcap_flow_which_does_not_exist(mocker):
        """
        Given -
           a response which indicates there are no pcap files on the firewall.

        When -
           trying to download a pcap file.

        Then -
           make sure that the error message from the api is actually returned.
        """
        from Panorama import panorama_get_pcap_command
        no_pcaps_response = MockedResponse(
            text='<?xml version="1.0"?>\n<response status="error">\n  <msg>\n    '
                 '<line>test.pcap not present</line>\n  </msg>\n</response>\n',
            status_code=200,
            headers={'Content-Type': 'application/xml'}
        )
        mocker.patch('Panorama.http_request', return_value=no_pcaps_response)
        with pytest.raises(Exception, match='line: test.pcap not present'):
            panorama_get_pcap_command({'pcapType': 'filter-pcap', 'from': 'test'})

    @staticmethod
    def test_get_filter_pcap_without_from_argument(mocker):
        """
        Given -
           a filter-pcap type without 'from' argument

        When -
           trying to download a filter pcap file.

        Then -
           make sure that the error message which states that the 'from' argument should be returned is presented.
        """
        from Panorama import panorama_get_pcap_command
        no_pcaps_response = MockedResponse(
            text='<?xml version="1.0"?>\n<response status="error">\n  <msg>\n    '
                 '<line>test.pcap not present</line>\n  </msg>\n</response>\n',
            status_code=200,
            headers={'Content-Type': 'application/xml'}
        )
        mocker.patch('Panorama.http_request', return_value=no_pcaps_response)
        with pytest.raises(Exception, match='cannot download filter-pcap without the from argument'):
            panorama_get_pcap_command({'pcapType': 'filter-pcap'})


class TestPanoramaEditRuleCommand:
    EDIT_SUCCESS_RESPONSE = {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}

    @staticmethod
    def test_sanity(mocker):
        import Panorama
        args = {
            'rulename': 'TestRule',
            'element_to_change': 'source',
            'element_value': '2.3.4.5,3.3.3.3',
            'behaviour': 'add',
        }
        commited_rule_item = {
            'response': {
                '@status': 'success',
                '@code': '19',
                'result': {
                    '@total-count': '1',
                    '@count': '1',
                    'source': {
                        'member': ['1.1.1.1', '3.3.3.3', '2.3.4.5'],
                    }
                }
            }
        }
        mocker.patch('Panorama.http_request', return_value=commited_rule_item)
        Panorama.panorama_edit_rule_command(args)

    @staticmethod
    def test_add_to_element_on_uncommited_rule(mocker):
        import Panorama
        args = {
            'rulename': 'TestRule',
            'element_to_change': 'source',
            'element_value': '2.3.4.5',
            'behaviour': 'add',
        }
        uncommited_rule_item = {
            'response': {
                '@status': 'success',
                '@code': '19',
                'result': {
                    '@total-count': '1',
                    '@count': '1',
                    'source': {
                        '@admin': 'admin',
                        '@dirtyId': '1616',
                        '@time': '2021/11/27 10:55:18',
                        'member': {
                            '@admin': 'admin',
                            '@dirtyId': '1616',
                            '@time': '2021/11/27 10:55:18',
                            '#text': '3.3.3.3',
                        }
                    }
                }
            }
        }
        mocker.patch('Panorama.http_request', return_value=uncommited_rule_item)

        with pytest.raises(DemistoException):
            Panorama.panorama_edit_rule_command(args)

    @staticmethod
    def test_edit_rule_to_disabled_flow(mocker):
        """
        Given -
            arguments to change a pre-rule to 'disabled'

        When -
            running panorama_edit_rule_command function.

        Then -
            make sure the entire command flow succeeds.
        """
        from Panorama import panorama_edit_rule_command
        args = {
            "rulename": "test",
            "element_to_change": "disabled",
            "element_value": "yes",
            "behaviour": "replace",
            "pre_post": "pre-rulebase"
        }
        mocker.patch("Panorama.http_request", return_value=TestPanoramaEditRuleCommand.EDIT_SUCCESS_RESPONSE)
        results_mocker = mocker.patch.object(demisto, "results")
        panorama_edit_rule_command(args)
        assert results_mocker.called

    @staticmethod
    def test_edit_rule_to_disabled_with_no_element_value(mocker):
        """
        Given -
            arguments to change a pre-rule to 'disabled' when the element value should be set to 'no'

        When -
            running panorama_edit_rule_command function.

        Then -
            make sure that the `params['element']` contains the 'no' element value.
        """
        from Panorama import panorama_edit_rule_command
        args = {
            "rulename": "test",
            "element_to_change": "disabled",
            "element_value": "no",
            "behaviour": "replace",
            "pre_post": "pre-rulebase"
        }
        http_req_mocker = mocker.patch(
            "Panorama.http_request", return_value=TestPanoramaEditRuleCommand.EDIT_SUCCESS_RESPONSE
        )
        panorama_edit_rule_command(args)
        assert http_req_mocker.call_args.kwargs.get('body').get('element') == '<disabled>no</disabled>'


class MockedResponse:
    def __init__(self, text, status_code, reason='', headers=None):
        self.status_code = status_code
        self.text = text
        self.reason = reason
        self.headers = headers


@pytest.mark.parametrize('args, expected_request_params, request_result, expected_demisto_result',
                         [pytest.param({'device-group': 'some_device', 'admin_name': 'some_admin_name'},
                                       {'action': 'partial',
                                        'cmd': '<commit><device-group><entry '
                                               'name="some_device"/></device-group><partial><admin>'
                                               '<member>some_admin_name</member></admin></partial></commit>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'Panorama.Commit(val.JobID == obj.JobID)': {'Description': None,
                                                                                    'JobID': '19420',
                                                                                    'Status': 'Pending'}},
                                       id='only admin changes commit'),
                          pytest.param({'device-group': 'some_device', 'force_commit': 'true'},
                                       {'cmd': '<commit><device-group><entry name="some_device"/></device-group><force>'
                                               '</force></commit>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'Panorama.Commit(val.JobID == obj.JobID)': {'Description': None,
                                                                                    'JobID': '19420',
                                                                                    'Status': 'Pending'}},
                                       id="force commit"),
                          pytest.param({'device-group': 'some_device', 'exclude_device_network_configuration': 'true'},
                                       {'action': 'partial',
                                        'cmd': '<commit><device-group><entry name="some_device"/></device-group>'
                                               '<partial><device-and-network>excluded</device-and-network></partial>'
                                               '</commit>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'Panorama.Commit(val.JobID == obj.JobID)': {'Description': None,
                                                                                    'JobID': '19420',
                                                                                    'Status': 'Pending'}},
                                       id="device and network excluded"),
                          pytest.param({'device-group': 'some_device', 'exclude_shared_objects': 'true'},
                                       {'action': 'partial',
                                        'cmd': '<commit><device-group><entry name="some_device"/></device-group>'
                                               '<partial><shared-object>excluded</shared-object></partial></commit>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'Panorama.Commit(val.JobID == obj.JobID)': {'Description': None,
                                                                                    'JobID': '19420',
                                                                                    'Status': 'Pending'}},
                                       id="exclude shared objects"),
                          pytest.param({'device-group': 'some_device'},
                                       {'cmd': '<commit><device-group><entry name="some_device"/></device-group>'
                                               '</commit>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'Panorama.Commit(val.JobID == obj.JobID)': {'Description': None,
                                                                                    'JobID': '19420',
                                                                                    'Status': 'Pending'}},
                                       id="no args")
                          ])
def test_panorama_commit_command(mocker, args, expected_request_params, request_result, expected_demisto_result):
    """
    Given:
        - command args
        - request result
    When:
        - Running panorama-commit command
    Then:
        - Assert the request url is as expected
        - Assert demisto results contain the relevant result information
    """
    import Panorama
    import requests
    from Panorama import panorama_commit_command

    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    return_results_mock = mocker.patch.object(Panorama, 'return_results')
    request_mock = mocker.patch.object(requests, 'request', return_value=request_result)
    panorama_commit_command(args)

    called_request_params = request_mock.call_args.kwargs['data']  # The body part of the request
    assert called_request_params == expected_request_params

    demisto_result_got = return_results_mock.call_args.args[0]['EntryContext']
    assert demisto_result_got == expected_demisto_result


@pytest.mark.parametrize('args, expected_request_params, request_result, expected_demisto_result',
                         [pytest.param({},
                                       {'action': 'all',
                                        'cmd': '<commit-all><shared-policy><device-group><entry name="some_device"/>'
                                               '</device-group></shared-policy></commit-all>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'Panorama.Push(val.JobID == obj.JobID)': {'DeviceGroup': 'some_device',
                                                                                  'JobID': '19420',
                                                                                  'Status': 'Pending'}},
                                       id='no args'),
                          pytest.param({'serial_number': '1337'},
                                       {'action': 'all',
                                        'cmd': '<commit-all><shared-policy><device-group><entry name="some_device">'
                                               '<devices><entry name="1337"/></devices></entry></device-group>'
                                               '</shared-policy></commit-all>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'Panorama.Push(val.JobID == obj.JobID)': {'DeviceGroup': 'some_device',
                                                                                  'JobID': '19420',
                                                                                  'Status': 'Pending'}},
                                       id='serial number'),
                          pytest.param({'include-template': 'false'},
                                       {'action': 'all',
                                        'cmd': '<commit-all><shared-policy><device-group><entry name="some_device"/>'
                                               '</device-group><include-template>no</include-template></shared-policy>'
                                               '</commit-all>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'Panorama.Push(val.JobID == obj.JobID)': {'DeviceGroup': 'some_device',
                                                                                  'JobID': '19420',
                                                                                  'Status': 'Pending'}},
                                       id='do not include template')
                          ])
def test_panorama_push_to_device_group_command(mocker, args, expected_request_params, request_result,
                                               expected_demisto_result):
    """
    Given:
        - command args
        - request result
    When:
        - Running panorama-push-to-device-group command
    Then:
        - Assert the request url is as expected
        - Assert demisto results contain the relevant result information
    """
    import Panorama
    import requests
    from Panorama import panorama_push_to_device_group_command

    return_results_mock = mocker.patch.object(Panorama, 'return_results')
    request_mock = mocker.patch.object(requests, 'request', return_value=request_result)
    Panorama.DEVICE_GROUP = 'some_device'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    panorama_push_to_device_group_command(args)

    called_request_params = request_mock.call_args.kwargs['data']  # The body part of the request
    assert called_request_params == expected_request_params

    demisto_result_got = return_results_mock.call_args.args[0]['EntryContext']
    assert demisto_result_got == expected_demisto_result


def test_get_url_category__url_length_gt_1278(mocker):
    """
    Given:
        - Error in response indicating the url to get category for is over the allowed length (1278 chars)

    When:
        - Run get_url_category command

    Then:
        - Validate a commandResult is returned with detailed readable output
    """

    # prepare
    import Panorama
    import requests
    from Panorama import panorama_get_url_category_command
    Panorama.DEVICE_GROUP = ''
    mocked_res_dict = {
        'response': {
            '@status': 'error',
            '@code': '20',
            'msg': {'line': 'test -> url Node can be at most 1278 characters, but current length: 1288'}
        }}
    mocked_res_obj = requests.Response()
    mocked_res_obj.status_code = 200
    mocked_res_obj._content = json.dumps(mocked_res_dict).encode('utf-8')
    mocker.patch.object(requests, 'request', return_value=mocked_res_obj)
    mocker.patch.object(Panorama, 'xml2json', return_value=mocked_res_obj._content)
    return_results_mock = mocker.patch.object(Panorama, 'return_results')

    # run
    panorama_get_url_category_command(url_cmd='url', url='test_url', additional_suspicious=[], additional_malicious=[])

    # validate
    assert 'URL Node can be at most 1278 characters.' == return_results_mock.call_args[0][0][1].readable_output


class TestDevices:

    def test_with_fw(self):
        import Panorama
        Panorama.VSYS = 'this is a FW instance'
        assert list(Panorama.devices()) == [(None, None)]

    def test_with_specific_target_and_vsys(self):
        import Panorama
        Panorama.VSYS = None  # this a Panorama instance
        assert list(Panorama.devices(targets=['target'], vsys_s=['vsys1', 'vsys2'])) == [('target', 'vsys1'),
                                                                                         ('target', 'vsys2')]

    def test_with_specific_target_only(self, requests_mock):
        import Panorama
        with open('test_data/devices_list.xml', 'r') as data_file:
            requests_mock.get(Panorama.URL, text=data_file.read())
        Panorama.VSYS = None  # this a Panorama instance
        assert list(Panorama.devices(targets=['target1'])) == [('target1', 'vsys1'), ('target1', 'vsys2')]

    def test_without_specify(self, requests_mock):
        import Panorama
        with open('test_data/devices_list.xml', 'r') as data_file:
            requests_mock.get(Panorama.URL, text=data_file.read())
        Panorama.VSYS = None  # this a Panorama instance
        assert list(Panorama.devices()) == [('target1', 'vsys1'), ('target1', 'vsys2'), ('target2', None)]


def load_xml_root_from_test_file(xml_file: str):
    """Given an XML file, loads it and returns the root element XML object."""
    return etree.parse(xml_file).getroot()


MOCK_PANORAMA_SERIAL = "111222334455"
MOCK_FIREWALL_1_SERIAL = "111111111111111"
MOCK_FIREWALL_2_SERIAL = "222222222222222"
MOCK_FIREWALL_3_SERIAL = "333333333333333"


def mock_software_object():
    """Mocks PanDevice.software"""

    class MockSoftwareObject:
        versions = {
            "9.1.0": {
                "version": "9.1.0",
                "filename": "Pan-9.1.0",
                "size": 150,
                "size_kb": 150000,
                "release_notes": "https://releasenotes.paloaltonetworks.com",
                "downloaded": True,
                "current": True,
                "latest": True,
                "uploaded": True
            }
        }

        def check(self):
            pass

        def download(self, *args, **kwargs):
            pass

    return MockSoftwareObject()


@pytest.fixture
def mock_firewall():
    mock_firewall = MagicMock(spec=Firewall)
    mock_firewall.serial = MOCK_FIREWALL_1_SERIAL
    mock_firewall.hostname = None
    mock_firewall.software = mock_software_object()
    return mock_firewall


@pytest.fixture
def mock_panorama():
    mock_panorama = MagicMock(spec=Panorama)
    mock_panorama.serial = MOCK_PANORAMA_SERIAL
    mock_panorama.hostname = None
    mock_panorama.software = mock_software_object()
    return mock_panorama


def mock_device_groups():
    mock_device_group = MagicMock(spec=DeviceGroup)
    mock_device_group.name = "test-dg"
    return [mock_device_group]


def mock_templates():
    mock_template = MagicMock(spec=Template)
    mock_template.name = "test-template"
    return [mock_template]


def mock_vsys():
    mock_vsys = MagicMock(spec=Vsys)
    mock_vsys.name = "vsys1"
    return [mock_vsys]


@pytest.fixture
def mock_topology(mock_panorama, mock_firewall):
    from Panorama import Topology
    topology = Topology()
    topology.panorama_objects = {
        MOCK_PANORAMA_SERIAL: mock_panorama,
    }
    topology.firewall_objects = {
        MOCK_FIREWALL_1_SERIAL: mock_firewall
    }
    topology.ha_active_devices = {
        MOCK_PANORAMA_SERIAL: mock_panorama,
        MOCK_FIREWALL_1_SERIAL: mock_firewall
    }
    topology.ha_pair_serials = {
        MOCK_FIREWALL_1_SERIAL: MOCK_FIREWALL_2_SERIAL,
    }
    return topology


class TestTopology:
    """Tests the Topology class and all of it's methods"""
    SHOW_HA_STATE_ENABLED_XML = "test_data/show_ha_state_enabled.xml"
    SHOW_HA_STATE_DISABLED_XML = "test_data/show_ha_state_disabled.xml"
    SHOW_DEVICES_ALL_XML = "test_data/panorama_show_devices_all.xml"

    @patch("Panorama.Topology.get_all_child_firewalls")
    @patch("Panorama.run_op_command")
    def test_add_firewall_device_object(self, patched_run_op_command, _, mock_firewall):
        """
        Given the XML output of show ha state and a firewall object, test it is correctly added to the topology.
        """
        from Panorama import Topology
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestTopology.SHOW_HA_STATE_DISABLED_XML)
        topology = Topology()
        topology.add_device_object(mock_firewall)

        assert MOCK_FIREWALL_1_SERIAL in topology.firewall_objects

    @patch("Panorama.Topology.get_all_child_firewalls")
    @patch("Panorama.run_op_command")
    def test_add_panorama_device_object(self, patched_run_op_command, _, mock_panorama):
        """
        Given the output of show_ha_state with no entries, assert that the Panorama device has been added to the topolog
        as a panorama type device.
        """
        from Panorama import Topology
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestTopology.SHOW_HA_STATE_DISABLED_XML)
        topology = Topology()
        topology.add_device_object(mock_panorama)

        assert MOCK_PANORAMA_SERIAL in topology.panorama_objects
        assert MOCK_PANORAMA_SERIAL in topology.ha_active_devices
        assert MOCK_PANORAMA_SERIAL not in topology.firewall_objects

    @patch("Panorama.run_op_command")
    def test_get_all_child_firewalls(self, patched_run_op_command, mock_panorama):
        """
        Given the output of show devices all, assert that all the devices are added correctly to the topology with the correct
        HA State information.
        """
        from Panorama import Topology
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestTopology.SHOW_DEVICES_ALL_XML)
        topology = Topology()

        topology.get_all_child_firewalls(mock_panorama)
        # 222... firewall should be Active, with 111... as it's peer
        assert MOCK_FIREWALL_2_SERIAL in topology.ha_active_devices
        assert topology.ha_active_devices.get(MOCK_FIREWALL_2_SERIAL) == MOCK_FIREWALL_1_SERIAL

        # 333... is standalone
        assert MOCK_FIREWALL_3_SERIAL in topology.ha_active_devices
        assert topology.ha_active_devices.get(MOCK_FIREWALL_3_SERIAL) == "STANDALONE"

    @patch("Panorama.run_op_command")
    def test_get_active_devices(self, patched_run_op_command, mock_panorama):
        """
        Given a topology with a mixture of active and passive devices, assert that active_devices() returns the correct lists
        of objects.
        """
        from Panorama import Topology
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestTopology.SHOW_DEVICES_ALL_XML)
        topology = Topology()
        topology.add_device_object(mock_panorama)

        result_list = list(topology.active_devices())
        # Should be 3; panorama, one active firewall in a pair, and one stanadlone firewall (from panorama_show_devices_all.xml)
        assert len(result_list) == 3

        # Same as above by try filtering by serial number
        result_list = list(topology.active_devices(filter_str=MOCK_FIREWALL_3_SERIAL))
        assert len(result_list) == 1

        # Now try just getting the "top level" devices - should only return Panorama
        result_list = list(topology.active_top_level_devices())
        assert len(result_list) == 1
        assert isinstance(result_list[0], Panorama)

    @patch("Panorama.Template.refreshall", return_value=mock_templates())
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=mock_device_groups())
    def test_get_containers(self, _, __, ___, mock_panorama):
        """
        Given a list of device groups, vsys and templates, and a device, assert that get_all_object_containers() correctly returns
        the specified containers.
        """
        from Panorama import Topology
        topology = Topology()
        topology.add_device_object(mock_panorama)
        result = topology.get_all_object_containers()

        # Because it's panorama, should be; [shared, device-group, template]
        assert len(result) == 3


class TestUtilityFunctions:
    """Tests all the utility fucntions like dataclass_to_dict, etc"""
    SHOW_JOBS_ALL_XML = "test_data/show_jobs_all.xml"

    def test_dataclass_from_dict(self, mock_panorama):
        """Given a dictionary and dataclass type, assert that it is correctly converted into the dataclass."""
        from Panorama import dataclass_from_dict, CommitStatus
        example_dict = {
            "job-id": "10",
            "commit-type": "whatever",
            "status": "OK",
            "device-type": "firewall"
        }

        mock_panorama.hostname = None
        result_dataclass: CommitStatus = dataclass_from_dict(mock_panorama, example_dict, CommitStatus)
        assert result_dataclass.job_id
        assert result_dataclass.commit_type
        assert result_dataclass.status
        assert result_dataclass.device_type
        # With no hostname, hostid should be the serial number of the device
        assert result_dataclass.hostid == MOCK_PANORAMA_SERIAL

        mock_panorama.hostname = "test"
        mock_panorama.serial = None
        result_dataclass: CommitStatus = dataclass_from_dict(mock_panorama, example_dict, CommitStatus)
        # With a hostname and no serial, hostid shold be the hostname
        assert result_dataclass.hostid == "test"

    def test_flatten_xml_to_dict(self):
        """Given an XML element, assert that it is converted into a flat dictionary."""
        from Panorama import flatten_xml_to_dict, ShowJobsAllResultData

        xml_element = load_xml_root_from_test_file(TestUtilityFunctions.SHOW_JOBS_ALL_XML)
        result_element = xml_element.find("./result/job")
        result = flatten_xml_to_dict(result_element, {}, ShowJobsAllResultData)
        assert "type" in result

    def test_resolve_host_id(self, mock_panorama):
        """Given a device object, test the hostid, the unique ID of the device from the perspective of the new commands,
        can always be resolved as either the hostname or serial number. Pan-os-python will populate only one of these, depending
        on how the device has been connected."""
        from Panorama import resolve_host_id
        mock_panorama.hostname = None
        result = resolve_host_id(mock_panorama)

        assert result == MOCK_PANORAMA_SERIAL

        mock_panorama.hostname = "test"
        mock_panorama.serial = None
        result = resolve_host_id(mock_panorama)

        assert result == "test"

    def test_resolve_container_name(self, mock_panorama):
        """Same as hostid but resolve it for a container, like a device group or template. This will always return the name
        attribute unless it's a device itself, which is the case for shared objects."""
        from Panorama import resolve_container_name
        # Test the "shared" container
        assert resolve_container_name(mock_panorama) == "shared"

        device_group = mock_device_groups()[0]
        assert resolve_container_name(device_group) == "test-dg"


class TestPanoramaCommand:
    """
    Test all the commands relevant to Panorama
    All of these commands use the real XML in test_data to ensure it is parsed and converted to dataclasses correctly.
    """

    SHOW_DEVICEGROUPS_XML = "test_data/show_device_groups.xml"
    SHOW_TEMPLATESTACK_XML = "test_data/show_template_stack.xml"

    @patch("Panorama.run_op_command")
    def test_get_device_groups(self, patched_run_op_command, mock_topology):
        """Given the output XML for show device groups, assert it is parsed into the dataclasses correctly."""
        from Panorama import PanoramaCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestPanoramaCommand.SHOW_DEVICEGROUPS_XML)

        result = PanoramaCommand.get_device_groups(mock_topology)
        assert len(result) == 2
        assert result[0].name
        assert result[0].hostid
        assert result[0].connected
        assert result[0].serial
        assert result[0].last_commit_all_state_sp

    @patch("Panorama.run_op_command")
    def test_get_template_stacks(self, patched_run_op_command, mock_topology):
        """Given the output XML for show template-stacks, assert it is parsed into the dataclasses correctly."""
        from Panorama import PanoramaCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestPanoramaCommand.SHOW_TEMPLATESTACK_XML)
        result = PanoramaCommand.get_template_stacks(mock_topology)
        assert len(result) == 2
        assert result[0].name
        assert result[0].hostid
        assert result[0].connected
        assert result[0].serial
        assert result[0].last_commit_all_state_tpl


class TestUniversalCommand:
    """Test all the commands relevant to both Panorama and Firewall devices"""
    SHOW_SYSTEM_INFO_XML = "test_data/show_system_info.xml"
    SHOW_JOB_XML = "test_data/show_jobs_all.xml"

    @patch("Panorama.run_op_command")
    def test_get_system_info(self, patched_run_op_command, mock_topology):
        """Given the output XML for show system info, assert it is parsed into the dataclasses correctly."""
        from Panorama import UniversalCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestUniversalCommand.SHOW_SYSTEM_INFO_XML)

        result = UniversalCommand.get_system_info(mock_topology)
        # Check all attributes of result data have values
        for result_dataclass in result.result_data:
            for value in result_dataclass.__dict__.values():
                assert value

        # Check all attributes of summary data have values
        for result_dataclass in result.summary_data:
            for value in result_dataclass.__dict__.values():
                assert value

    def test_get_available_software(self, mock_topology):
        """
        Test we can convert result from PanDevice.software.check() into the correct dataclasses
        This does not use patching, but instead the mock objects themselves from mock_topology
        """
        from Panorama import UniversalCommand

        result = UniversalCommand.get_available_software(mock_topology)
        # Check all attributes of summary data have values
        for result_dataclass in result.summary_data:
            for value in result_dataclass.__dict__.values():
                assert value

    @patch("Panorama.run_op_command")
    def test_get_jobs(self, patched_run_op_command, mock_topology):
        """Given the output XML for show jobs all assert it is parsed into the dataclasses correctly."""
        from Panorama import UniversalCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestUniversalCommand.SHOW_JOB_XML)

        result = UniversalCommand.show_jobs(mock_topology)
        # Check all attributes of result data have values
        for result_dataclass in result:
            for key, value in result_dataclass.__dict__.items():
                # Nullable Values
                if key not in ["description", "user"]:
                    assert value

    def test_download_software(self, mock_topology):
        """
        Test the download software function returns the correct data.
        The pan-os-python download software actually doesn't return any output itself unless it errors, so we just check our
        dataclass is set correctly within the function and retuned.
        """
        from Panorama import UniversalCommand

        result = UniversalCommand.download_software(mock_topology, "9.1.0")
        # Check all attributes of summary data have values
        for result_dataclass in result.summary_data:
            for value in result_dataclass.__dict__.values():
                assert value


class TestFirewallCommand:
    """Test all the commands relevant only to Firewall instances"""

    SHOW_ARP_XML = "test_data/show_arp_all.xml"
    SHOW_ROUTING_SUMMARY_XML = "test_data/show_routing_summary.xml"
    SHOW_ROUTING_ROUTE_XML = "test_data/show_routing_route.xml"
    SHOW_GLOBAL_COUNTERS_XML = "test_data/show_counter_global.xml"
    SHOW_BGP_PEERS_XML = "test_data/show_routing_protocol_bgp_peer.xml"
    SHOW_HA_STATE_XML = "test_data/show_ha_state_enabled.xml"

    @patch("Panorama.run_op_command")
    def test_get_arp_table(self, patched_run_op_command, mock_topology):
        """Given the output XML for show arp, assert it is parsed into the dataclasses correctly."""
        from Panorama import FirewallCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestFirewallCommand.SHOW_ARP_XML)
        result = FirewallCommand.get_arp_table(mock_topology)
        # Check all attributes of result data have values
        for result_dataclass in result.result_data:
            for value in result_dataclass.__dict__.values():
                assert value

        # Check all attributes of summary data have values
        for result_dataclass in result.summary_data:
            for value in result_dataclass.__dict__.values():
                assert value

    @patch("Panorama.run_op_command")
    def test_get_routing_summary(self, patched_run_op_command, mock_topology):
        """Given the output XML for show route summary, assert it is parsed into the dataclasses correctly."""
        from Panorama import FirewallCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestFirewallCommand.SHOW_ROUTING_SUMMARY_XML)
        result = FirewallCommand.get_routing_summary(mock_topology)
        # Check all attributes of result data have values
        for result_dataclass in result.result_data:
            for value in result_dataclass.__dict__.values():
                assert value

        # Check all attributes of summary data have values
        for result_dataclass in result.summary_data:
            for value in result_dataclass.__dict__.values():
                assert value

    @patch("Panorama.run_op_command")
    def test_get_routes(self, patched_run_op_command, mock_topology):
        """Given the output XML for show route, assert it is parsed into the dataclasses correctly."""
        from Panorama import FirewallCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestFirewallCommand.SHOW_ROUTING_ROUTE_XML)
        result = FirewallCommand.get_routes(mock_topology)
        # Check all attributes of result data have values
        for result_dataclass in result.result_data:
            for value in result_dataclass.__dict__.values():
                # Attribute may be int 0
                assert value is not None

        # Check all attributes of summary data have values
        for result_dataclass in result.summary_data:
            for value in result_dataclass.__dict__.values():
                assert value

    @patch("Panorama.run_op_command")
    def test_get_counters(self, patched_run_op_command, mock_topology):
        """Given the output XML for show counters, assert it is parsed into the dataclasses correctly."""
        from Panorama import FirewallCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestFirewallCommand.SHOW_GLOBAL_COUNTERS_XML)
        result = FirewallCommand.get_counter_global(mock_topology)
        # Check all attributes of result data have values
        for result_dataclass in result.result_data:
            for value in result_dataclass.__dict__.values():
                # Attribute may be int 0
                assert value is not None

        # Check all attributes of summary data have values
        for result_dataclass in result.summary_data:
            for value in result_dataclass.__dict__.values():
                assert value

    @patch("Panorama.run_op_command")
    def test_get_bgp_peers(self, patched_run_op_command, mock_topology):
        """
        Given the output XML for show routing protocol bgp peers,
        assert it is parsed into the dataclasses correctly.
        """
        from Panorama import FirewallCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestFirewallCommand.SHOW_BGP_PEERS_XML)
        result = FirewallCommand.get_bgp_peers(mock_topology)
        # Check all attributes of result data have values
        for result_dataclass in result.result_data:
            for value in result_dataclass.__dict__.values():
                # Attribute may be int 0
                assert value is not None

        # Check all attributes of summary data have values
        for result_dataclass in result.summary_data:
            for value in result_dataclass.__dict__.values():
                # Attribute may be int 0
                assert value is not None

    @patch("Panorama.run_op_command")
    def test_get_ha_status(self, patched_run_op_command, mock_topology):
        """Given the XML output for a HA firewall, ensure the dataclasses are parsed correctly"""
        from Panorama import FirewallCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestFirewallCommand.SHOW_HA_STATE_XML)
        result = FirewallCommand.get_ha_status(mock_topology)
        # Check all attributes of result data have values
        for result_dataclass in result:
            for value in result_dataclass.__dict__.values():
                # Attribute may be int 0
                assert value is not None
