import json
import io
import pytest

import demistomock as demisto
from lxml import etree
from unittest.mock import patch, MagicMock
from panos.device import Vsys
from panos.panorama import Panorama, DeviceGroup, Template
from panos.firewall import Firewall
from CommonServerPython import DemistoException, CommandResults
from panos.objects import LogForwardingProfile, LogForwardingProfileMatchList

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


def load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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
    @pytest.mark.parametrize(
        'api_response, expected_context, expected_markdown_table', [
            (
                '<?xml version="1.0"?>\n<response status="success">\n  <result>\n    <dir-listing>\n      '
                '<file>/pcap</file>\n      <file>/pcap_test</file>\n    </dir-listing>\n  </result>\n</response>\n',
                ['pcap', 'pcap_test'],
                '### List of Pcaps:\n|Pcap name|\n|---|\n| pcap |\n| pcap_test |\n'
            ),
            (
                '<?xml version="1.0"?>\n<response status="success">\n  <result>\n    <dir-listing>\n      '
                '<file>/pcap_test</file>\n    </dir-listing>\n  </result>\n</response>\n',
                ['pcap_test'],
                '### List of Pcaps:\n|Pcap name|\n|---|\n| pcap_test |\n'
            )
        ]
    )
    def test_list_pcaps_flow(mocker, api_response, expected_context, expected_markdown_table):
        """
        Given
            - a response which indicates there are two pcaps in the firewall.
            - a response which indicates there is only one pcap in the firewall.

        When -
            listing all the available pcap files.

        Then -
            make sure the response is parsed correctly.
        """
        from Panorama import panorama_list_pcaps_command
        pcaps_response = MockedResponse(text=api_response, status_code=200)
        mocker.patch('Panorama.http_request', return_value=pcaps_response)
        results_mocker = mocker.patch.object(demisto, "results")
        panorama_list_pcaps_command({'pcapType': 'filter-pcap'})
        called_args = results_mocker.call_args[0][0]
        assert list(*called_args['EntryContext'].values()) == expected_context
        assert called_args['HumanReadable'] == expected_markdown_table

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


@pytest.mark.parametrize('panorama_version', [8, 9])
def test_panorama_list_applications_command(mocker, panorama_version):
    """
    Given
       - http response of the list of applications.
       - panorama version 8 & 9.

    When
       - getting a list of all the applications in panorama 8/9.

    Then
       - a valid context output is returned.
    """
    from Panorama import panorama_list_applications_command
    mocker.patch('Panorama.http_request', return_value=load_json('test_data/list_applications_response.json'))
    mocker.patch('Panorama.get_pan_os_major_version', return_value=panorama_version)
    res = mocker.patch('demistomock.results')
    panorama_list_applications_command(predefined='false')
    assert res.call_args.args[0]['Contents'] == {
        '@name': 'test-playbook-app', '@loc': 'Lab-Devices', 'subcategory': 'infrastructure', 'category': 'networking',
        'technology': 'client-server', 'description': 'test-playbook-application-do-not-delete', 'risk': '1'
    }


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


class TestPanoramaCommitCommand:

    COMMIT_POLLING_ARGS = {
        'device-group': 'some_device',
        'admin_name': 'some_admin_name',
        'description': 'a simple commit',
        'polling': 'true'
    }

    EXPECTED_COMMIT_REQUEST_URL_PARAMS = {
        'action': 'partial',
        'cmd': '<commit><device-group><entry '
               'name="some_device"/></device-group><partial><admin>'
               '<member>some_admin_name</member></admin></partial></commit>',
        'key': 'APIKEY',
        'type': 'commit'
    }

    @staticmethod
    def create_mock_responses(job_commit_status_count):

        mocked_responses = [  # panorama commit api response mock
            MockedResponse(
                text='<response status="success" code="19"><result><msg>''<line>Commit job '
                     'enqueued with jobid 123</line></msg>''<job>123</job></result></response>',
                status_code=200,
            )
        ]

        mocked_responses += [  # add a mocked response indicating that the job is still in progress
            MockedResponse(
                text='<response status="success"><result><job><tenq>2022/07/16 07:50:04</tenq><tdeq>07:50:04<'
                     '/tdeq><id>123</id><user>app</user><type>Commit</type><status>ACT</status><queued>NO</queued>'
                     '<stoppable>no</stoppable><result>PEND</result><tfin>Still Active</tfin><description></'
                     'description><positionInQ>0</positionInQ><progress>69</progress><warnings></warnings>'
                     '<details></details></job></result></response>',
                status_code=200,
            ) for _ in range(job_commit_status_count)
        ]

        mocked_responses += [  # add a mocked response indicating that the job has finished.
            MockedResponse(
                text='<response status="success"><result><job><tenq>2022/07/16 07:26:05</tenq><tdeq>07:26:05</tdeq>'
                     '<id>7206</id><user>app</user><type>Commit</type><status>FIN</status><queued>NO</queued>'
                     '<stoppable>no</stoppable><result>OK</result><tfin>07:26:24</tfin><description></description>'
                     '<positionInQ>0</positionInQ><progress>100</progress><details><line>Configuration '
                     'committed successfully</line></details><warnings></warnings></job></result></response>',
                status_code=200,
            )
        ]

        return mocked_responses

    @pytest.mark.parametrize('args, expected_request_params, request_result, expected_demisto_result',
                             [pytest.param({'device-group': 'some_device', 'admin_name': 'some_admin_name',
                                            'description': 'a simple commit', 'polling': 'false'},
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
                                           {'Description': "a simple commit", 'JobID': '19420', 'Status': 'Pending'},
                                           id='only admin changes commit'),
                              pytest.param({'device-group': 'some_device', 'force_commit': 'true', 'polling': 'false'},
                                           {'cmd': '<commit><device-group><entry name="some_device"/>'
                                                   '</device-group><force>''</force></commit>',
                                            'key': 'thisisabogusAPIKEY!',
                                            'type': 'commit'},
                                           MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                               '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                               '<job>19420</job></result></response>', status_code=200,
                                                          reason=''),
                                           {'Description': '', 'JobID': '19420', 'Status': 'Pending'},
                                           id="force commit"),
                              pytest.param({'device-group': 'some_device',
                                            'exclude_device_network_configuration': 'true', 'polling': 'false'},
                                           {'action': 'partial',
                                            'cmd': '<commit><device-group><entry name="some_device"/></device-group>'
                                                   '<partial><device-and-network>excluded</'
                                                   'device-and-network></partial>''</commit>',
                                            'key': 'thisisabogusAPIKEY!',
                                            'type': 'commit'},
                                           MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                               '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                               '<job>19420</job></result></response>', status_code=200,
                                                          reason=''),
                                           {'Description': '', 'JobID': '19420', 'Status': 'Pending'},
                                           id="device and network excluded"),
                              pytest.param({'device-group': 'some_device',
                                            'exclude_shared_objects': 'true', 'polling': 'false'},
                                           {'action': 'partial',
                                            'cmd': '<commit><device-group><entry name="some_device"/></device-group>'
                                                   '<partial><shared-object>excluded'
                                                   '</shared-object></partial></commit>',
                                            'key': 'thisisabogusAPIKEY!',
                                            'type': 'commit'},
                                           MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                               '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                               '<job>19420</job></result></response>', status_code=200,
                                                          reason=''),
                                           {'Description': '', 'JobID': '19420', 'Status': 'Pending'},
                                           id="exclude shared objects"),
                              pytest.param({'device-group': 'some_device', 'polling': 'false'},
                                           {'cmd': '<commit><device-group><entry name="some_device"/></device-group>'
                                                   '</commit>',
                                            'key': 'thisisabogusAPIKEY!',
                                            'type': 'commit'},
                                           MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                               '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                               '<job>19420</job></result></response>', status_code=200,
                                                          reason=''),
                                           {'Description': '', 'JobID': '19420', 'Status': 'Pending'}, id="no args")
                              ])
    def test_panorama_commit_command_without_polling(
        self, mocker, args, expected_request_params, request_result, expected_demisto_result
    ):
        """
        Given:
            - commit command arguments and the expected api request without polling

        When:
            - Running panorama-commit command

        Then:
            - Assert the request url is as expected
            - Assert that panorama commit returns the correct context output
        """
        import Panorama
        import requests
        from Panorama import panorama_commit_command

        Panorama.API_KEY = 'thisisabogusAPIKEY!'
        request_mock = mocker.patch.object(requests, 'request', return_value=request_result)
        command_result = panorama_commit_command(args)

        called_request_params = request_mock.call_args.kwargs['data']  # The body part of the request
        assert called_request_params == expected_request_params  # check that the URL is sent as expected.
        assert command_result.outputs == expected_demisto_result  # check context is valid

    @pytest.mark.parametrize(
        'args, expected_commit_request_url_params, api_response_queue',
        [
            pytest.param(
                COMMIT_POLLING_ARGS,
                EXPECTED_COMMIT_REQUEST_URL_PARAMS,
                create_mock_responses(job_commit_status_count=1)
            ),
            pytest.param(
                COMMIT_POLLING_ARGS,
                EXPECTED_COMMIT_REQUEST_URL_PARAMS,
                create_mock_responses(job_commit_status_count=10)
            ),
            pytest.param(
                COMMIT_POLLING_ARGS,
                EXPECTED_COMMIT_REQUEST_URL_PARAMS,
                create_mock_responses(job_commit_status_count=5)
            ),
            pytest.param(
                COMMIT_POLLING_ARGS,
                EXPECTED_COMMIT_REQUEST_URL_PARAMS,
                create_mock_responses(job_commit_status_count=8)
            ),
            pytest.param(
                COMMIT_POLLING_ARGS,
                EXPECTED_COMMIT_REQUEST_URL_PARAMS,
                create_mock_responses(job_commit_status_count=13)
            ),
            pytest.param(
                COMMIT_POLLING_ARGS,
                EXPECTED_COMMIT_REQUEST_URL_PARAMS,
                create_mock_responses(job_commit_status_count=0)  # commit job finished instantly (very very rare case!)
            ),
        ]
    )
    def test_panorama_commit_command_with_polling(
        self, mocker, args, expected_commit_request_url_params, api_response_queue
    ):
        """
        Given:
            - pan-os-commit command arguments
            - expected structure of the URL to commit pan-os configuration
            - a queue for api responses of the following:
                1) first value in the queue is the panorama commit api response
                2) panorama job status api response which indicates job isn't done yet (different number each time)
                3) last value in the queue is the panorama job status that indicates it has finished and succeeded

        When:
            - running pan-os-commit with polling argument.

        Then:
            - make sure that the panorama_commit_command function querying for the commit job ID status until its done.
            - make sure that eventually after polling the panorama_commit_command, that it returns the expected output.
        """
        import Panorama
        import requests
        from Panorama import panorama_commit_command
        from CommonServerPython import ScheduledCommand

        Panorama.API_KEY = 'APIKEY'
        request_mock = mocker.patch.object(requests, 'request', side_effect=api_response_queue)
        mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

        command_result = panorama_commit_command(args)
        description = args.get('description')

        called_request_params = request_mock.call_args.kwargs['data']  # The body part of the request
        assert called_request_params == expected_commit_request_url_params  # check that the URL is sent as expected.
        assert command_result.readable_output == f'Waiting for commit "{description}" with job ID 123 to finish...'

        polling_args = {
            'commit_job_id': '123', 'description': description, 'hide_polling_output': True, 'polling': True
        }

        command_result = panorama_commit_command(polling_args)
        while command_result.scheduled_command:  # if scheduled_command is set, it means that command should still poll
            assert not command_result.readable_output  # make sure that indication of polling is printed only once
            assert not command_result.outputs  # make sure no context output is being returned to war-room during polling
            command_result = panorama_commit_command(polling_args)

        # last response of the command should be job status and the commit description
        assert command_result.outputs == {'JobID': '123', 'Description': description, 'Status': 'Success'}


class TestPanoramaPushToDeviceGroupCommand:

    @staticmethod
    def create_mock_responses(push_to_devices_job_status_count):
        mocked_responses = [  # panorama commit api response mock
            MockedResponse(
                text='<response status="success" code="19"><result><msg>''<line>Push job '
                     'enqueued with jobid 123</line></msg>''<job>123</job></result></response>',
                status_code=200,
            )
        ]

        mocked_responses += [  # add a mocked response indicating that the job is still in progress
            MockedResponse(
                text='<response status="success"><result><job><tenq>2022/07/16 07:50:04</tenq><tdeq>07:50:04<'
                     '/tdeq><id>123</id><user>app</user><type>CommitAll</type><status>ACT</status><queued>NO</queued>'
                     '<stoppable>no</stoppable><result>PEND</result><tfin>Still Active</tfin><description></'
                     'description><positionInQ>0</positionInQ><progress>69</progress><warnings></warnings>'
                     '<details></details></job></result></response>',
                status_code=200,
            ) for _ in range(push_to_devices_job_status_count)
        ]

        with open('test_data/push_to_device_success.xml', 'r') as data_file:
            mocked_responses += [
                MockedResponse(
                    text=data_file.read(),
                    status_code=200
                )
            ]

        return mocked_responses

    @pytest.mark.parametrize(
        'api_response_queue',
        [
            create_mock_responses(push_to_devices_job_status_count=1),
            create_mock_responses(push_to_devices_job_status_count=3),
            create_mock_responses(push_to_devices_job_status_count=5),
            create_mock_responses(push_to_devices_job_status_count=8),
            create_mock_responses(push_to_devices_job_status_count=10),

        ]
    )
    def test_panorama_push_to_devices_command_with_polling(self, mocker, api_response_queue):
        """
        Given:
            - pan-os-push-to-device-group command arguments
            - a queue for api responses of the following:
                1) first value in the queue is the panorama push to the device group api response
                2) panorama job status api response which indicates job isn't done yet (different number each time)
                3) last value in the queue is the panorama job status that indicates it has finished and succeeded

        When:
            - running pan-os-push-to-device-group with polling argument = True

        Then:
            - make sure that the panorama_push_to_device_group_command function querying for
              the push job ID status until its done.
            - make sure that eventually after polling the panorama_push_to_device_group_command,
              that it returns the expected output.
            - make sure readable output is printed out only once.
            - make sure context output is returned only when polling is finished.
        """
        import requests
        import Panorama
        from Panorama import panorama_push_to_device_group_command
        from CommonServerPython import ScheduledCommand
        Panorama.DEVICE_GROUP = 'device-group'

        args = {
            'description': 'a simple push',
            'polling': 'true'
        }

        Panorama.API_KEY = 'APIKEY'
        mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)
        mocker.patch.object(requests, 'request', side_effect=api_response_queue)

        command_result = panorama_push_to_device_group_command(args)
        description = args.get('description')

        assert command_result.readable_output == f'Waiting for Job-ID 123 to finish ' \
                                                 f'push changes to device-group {Panorama.DEVICE_GROUP}...'

        polling_args = {
            'push_job_id': '123', 'description': description, 'hide_polling_output': True, 'polling': True
        }

        command_result = panorama_push_to_device_group_command(polling_args)
        while command_result.scheduled_command:  # if scheduled_command is set, it means that command should still poll
            assert not command_result.readable_output  # make sure that indication of polling is printed only once
            assert not command_result.outputs  # make sure no context output is being returned to war-room during polling
            command_result = panorama_push_to_device_group_command(polling_args)

        assert command_result.outputs.get('JobID') == '123'
        assert command_result.outputs.get('Status') == 'Completed'
        assert command_result.outputs.get('Details')
        assert command_result.outputs.get('Warnings')
        assert command_result.outputs.get('Description') == 'a simple push'


@pytest.mark.parametrize('args, expected_request_params, request_result, expected_demisto_result',
                         [pytest.param({'polling': 'false'},
                                       {'action': 'all',
                                        'cmd': '<commit-all><shared-policy><device-group><entry name="some_device"/>'
                                               '</device-group></shared-policy></commit-all>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'DeviceGroup': 'some_device', 'JobID': '19420', 'Status': 'Pending'},
                                       id='no args'),
                          pytest.param({'serial_number': '1337', 'polling': 'false'},
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
                                       {'DeviceGroup': 'some_device', 'JobID': '19420', 'Status': 'Pending'},
                                       id='serial number'),
                          pytest.param({'include-template': 'false', 'polling': 'false'},
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
                                       {'DeviceGroup': 'some_device', 'JobID': '19420', 'Status': 'Pending'},
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

    request_mock = mocker.patch.object(requests, 'request', return_value=request_result)
    Panorama.DEVICE_GROUP = 'some_device'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    result = panorama_push_to_device_group_command(args)

    called_request_params = request_mock.call_args.kwargs['data']  # The body part of the request
    assert called_request_params == expected_request_params

    assert result.outputs == expected_demisto_result


@pytest.mark.parametrize('args, expected_request_params, request_result, expected_demisto_result',
                         [pytest.param({},
                                       {'action': 'all',
                                        'cmd': '<commit-all><template><name>some_template</name></template></commit-all>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'Panorama.Push(val.JobID == obj.JobID)': {'Template': 'some_template',
                                                                                  'JobID': '19420',
                                                                                  'Status': 'Pending'}},
                                       id='no args'),
                          pytest.param({"validate-only": "true"},
                                       {'action': 'all',
                                        'cmd': '<commit-all><template><name>some_template</name>'
                                               '<validate-only>yes</validate-only></template></commit-all>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'Panorama.Push(val.JobID == obj.JobID)': {'Template': 'some_template',
                                                                                  'JobID': '19420',
                                                                                  'Status': 'Pending'}},
                                       id='with validate'),
                          pytest.param({'serial_number': '1337'},
                                       {'action': 'all',
                                        'cmd': '<commit-all><template><name>some_template</name><device><member>1337</member>'
                                               '</device></template></commit-all>',
                                        'key': 'thisisabogusAPIKEY!',
                                        'type': 'commit'},
                                       MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                           '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                           '<job>19420</job></result></response>', status_code=200,
                                                      reason=''),
                                       {'Panorama.Push(val.JobID == obj.JobID)': {'Template': 'some_template',
                                                                                  'JobID': '19420',
                                                                                  'Status': 'Pending'}},
                                       id='with device'),
                          ])
def test_panorama_push_to_template_command(
        mocker, args, expected_request_params, request_result, expected_demisto_result
):
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
    from Panorama import panorama_push_to_template_command

    return_results_mock = mocker.patch.object(Panorama, 'return_results')
    request_mock = mocker.patch.object(requests, 'request', return_value=request_result)
    Panorama.TEMPLATE = 'some_template'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    panorama_push_to_template_command(args)

    called_request_params = request_mock.call_args.kwargs['data']  # The body part of the request
    assert called_request_params == expected_request_params

    demisto_result_got = return_results_mock.call_args.args[0]['EntryContext']
    assert demisto_result_got == expected_demisto_result


@pytest.mark.parametrize('args, expected_request_params, request_result, expected_demisto_result',
                         [
                             pytest.param(
                                 {
                                     "template-stack": "some_template_stack"
                                 },
                                 {
                                     'action': 'all',
                                     'cmd': '<commit-all><template-stack><name>some_template_stack'
                                            '</name></template-stack></commit-all>',
                                     'key': 'thisisabogusAPIKEY!',
                                     'type': 'commit'
                                 },
                                 MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                     '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                     '<job>19420</job></result></response>', status_code=200,
                                                reason=''),
                                 {
                                     'Panorama.Push(val.JobID == obj.JobID)':
                                         {
                                             'TemplateStack': 'some_template_stack',
                                             'JobID': '19420', 'Status': 'Pending'
                                         }
                                 },
                                 id='no args'
                             ),
                             pytest.param(
                                 {
                                     "validate-only": "true", "template-stack": "some_template_stack"
                                 },
                                 {
                                     'action': 'all',
                                     'cmd': '<commit-all><template-stack><name>some_template_stack</name>'
                                            '<validate-only>yes</validate-only></template-stack></commit-all>',
                                     'key': 'thisisabogusAPIKEY!',
                                     'type': 'commit'
                                 },
                                 MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                     '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                     '<job>19420</job></result></response>', status_code=200,
                                                reason=''),
                                 {
                                     'Panorama.Push(val.JobID == obj.JobID)': {
                                         'TemplateStack': 'some_template_stack', 'JobID': '19420', 'Status': 'Pending'
                                     }
                                 },
                                 id='with validate'),
                             pytest.param(
                                 {
                                     'serial_number': '1337',
                                     "template-stack": "some_template_stack"
                                 },
                                 {
                                     'action': 'all',
                                     'cmd': '<commit-all><template-stack><name>some_template_stack<'
                                            '/name><device><member>1337</member>'
                                            '</device></template-stack></commit-all>',
                                     'key': 'thisisabogusAPIKEY!',
                                     'type': 'commit'
                                 },
                                 MockedResponse(text='<response status="success" code="19"><result><msg>'
                                                     '<line>Commit job enqueued with jobid 19420</line></msg>'
                                                     '<job>19420</job></result></response>', status_code=200,
                                                reason=''),
                                 {
                                     'Panorama.Push(val.JobID == obj.JobID)':
                                         {
                                             'TemplateStack': 'some_template_stack',
                                             'JobID': '19420',
                                             'Status': 'Pending'
                                         }
                                 },
                                 id='with device'),
                         ])
def test_panorama_push_to_template_stack_command(
        mocker, args, expected_request_params, request_result, expected_demisto_result
):
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
    from Panorama import panorama_push_to_template_stack_command

    return_results_mock = mocker.patch.object(Panorama, 'return_results')
    request_mock = mocker.patch.object(requests, 'request', return_value=request_result)
    Panorama.TEMPLATE = 'some_template'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    panorama_push_to_template_stack_command(args)

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
    panorama_get_url_category_command(
        url_cmd='url', url='test_url', additional_suspicious=[],
        additional_malicious=[], reliability='B - Usually reliable'
    )

    # validate
    assert 'URL Node can be at most 1278 characters.' == return_results_mock.call_args[0][0][1].readable_output


def test_get_url_category_multiple_categories_for_url(mocker):
    """
    Given:
        - response indicating the url has multiple categories.

    When:
        - Run get_url_category command

    Then:
        - Validate a commandResult is returned with detailed readable output
        - Validate only a single DBot score is returned for the URL.
    """
    # prepare
    import Panorama
    import requests
    from Panorama import panorama_get_url_category_command
    Panorama.DEVICE_GROUP = ''
    mocked_res_dict = {
        'response': {
            '@cmd': 'status',
            '@status': 'success',
            'result': 'https://someURL.com not-resolved (Base db) expires in 5 seconds\n'
                      'https://someURL.com shareware-and-freeware online-storage-and-backup low-risk (Cloud db)'
        }
    }
    mocked_res_obj = requests.Response()
    mocked_res_obj.status_code = 200
    mocked_res_obj._content = json.dumps(mocked_res_dict).encode('utf-8')
    mocker.patch.object(requests, 'request', return_value=mocked_res_obj)
    mocker.patch.object(Panorama, 'xml2json', return_value=mocked_res_obj._content)
    return_results_mock = mocker.patch.object(Panorama, 'return_results')

    # run
    panorama_get_url_category_command(
        url_cmd='url', url='test_url', additional_suspicious=[],
        additional_malicious=[], reliability='B - Usually reliable'
    )

    # validate
    for i in range(3):
        assert return_results_mock.call_args[0][0][0].outputs[i].get('Category') in ['shareware-and-freeware',
                                                                                     'online-storage-and-backup',
                                                                                     'low-risk']

    # category with highest dbot-score
    assert return_results_mock.call_args[0][0][1].indicator.dbot_score.score == 1


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

        def install(self, *args, **kwargs):
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


def mock_address_objects():
    from Panorama import AddressObject
    mock_object_1 = MagicMock(spec=AddressObject)
    mock_object_1.name = "test-address-1"

    mock_object_2 = MagicMock(spec=AddressObject)
    mock_object_2.name = "test-address-2"
    return [mock_object_1, mock_object_2]


def mock_good_log_fowarding_profile():
    good_log_forwarding_profile = LogForwardingProfile()
    good_log_forwarding_profile.enhanced_logging = True
    return [good_log_forwarding_profile]


def mock_bad_log_fowarding_profile():
    bad_Log_forwarding_profile = LogForwardingProfile()
    bad_Log_forwarding_profile.enhanced_logging = False
    bad_Log_forwarding_profile.name = "test-bad"
    return [bad_Log_forwarding_profile]


def mock_good_log_forwarding_profile_match_list():
    return [
        LogForwardingProfileMatchList(
            log_type="traffic"
        ),
        LogForwardingProfileMatchList(
            log_type="threat"
        ),
    ]


def mock_good_vulnerability_profile():
    from Panorama import VulnerabilityProfile, VulnerabilityProfileRule
    vulnerability_profile = VulnerabilityProfile()
    vulnerability_profile.children = [
        VulnerabilityProfileRule(
            severity=["critical"],
            is_reset_both=True
        ),
        VulnerabilityProfileRule(
            severity=["high"],
            is_reset_both=True
        ),
        VulnerabilityProfileRule(
            severity=["medium"],
            is_alert=True
        ),
        VulnerabilityProfileRule(
            severity=["low"],
            is_alert=True
        ),
    ]

    return vulnerability_profile


def mock_bad_vulnerability_profile():
    from Panorama import VulnerabilityProfile, VulnerabilityProfileRule
    vulnerability_profile = VulnerabilityProfile()
    vulnerability_profile.children = [
        VulnerabilityProfileRule(
            severity=["critical"],
            is_reset_both=True
        ),
        VulnerabilityProfileRule(
            severity=["high"],
            is_reset_both=True
        ),
        VulnerabilityProfileRule(
            severity=["medium"],
            is_alert=True
        ),
    ]

    return vulnerability_profile


def mock_good_spyware_profile():
    from Panorama import AntiSpywareProfile, AntiSpywareProfileRule
    antispyware_profile = AntiSpywareProfile()
    antispyware_profile.children = [
        AntiSpywareProfileRule(
            severity=["critical"],
            is_reset_both=True
        ),
        AntiSpywareProfileRule(
            severity=["high"],
            is_reset_both=True
        ),
        AntiSpywareProfileRule(
            severity=["medium"],
            is_alert=True
        ),
        AntiSpywareProfileRule(
            severity=["low"],
            is_alert=True
        ),
    ]

    return antispyware_profile


def mock_bad_spyware_profile():
    from Panorama import AntiSpywareProfile, AntiSpywareProfileRule
    antispyware_profile = AntiSpywareProfile()
    antispyware_profile.children = [
        AntiSpywareProfileRule(
            severity=["critical"],
            is_reset_both=True
        ),
        AntiSpywareProfileRule(
            severity=["high"],
            is_reset_both=True
        ),
        AntiSpywareProfileRule(
            severity=["medium"],
            is_alert=True
        )
    ]

    return antispyware_profile


def mock_good_security_zones():
    from Panorama import Zone
    zone = Zone()
    zone.log_setting = "example-log-setting"
    return [
        Zone(log_setting="example"),
        Zone(log_setting="second_example")
    ]


def mock_bad_security_zones():
    from Panorama import Zone
    zone = Zone()
    zone.log_setting = "example-log-setting"
    return [
        Zone(name="test-bad"),
        Zone(log_setting="second_example")
    ]


def mock_good_security_rules():
    from Panorama import SecurityRule
    return [
        SecurityRule(
            group="spg",
            log_setting="example",
            log_end=True
        )
    ]


def mock_bad_security_rules():
    from Panorama import SecurityRule
    return [
        # Missing SPG
        SecurityRule(
            name="test-bad",
            log_setting="example",
            log_end=True
        ),
        # Missing log profile
        SecurityRule(
            name="test-bad-no-lfp",
            group="spg",
            log_end=True
        ),
        # Missing log at session end
        SecurityRule(
            name="test-bad-no-spg",
            group="spg",
            log_setting="example",
        )
    ]


def mock_good_url_filtering_profile():
    from Panorama import URLFilteringProfile, BestPractices
    url_filtering_profile = URLFilteringProfile()
    url_filtering_profile.block = BestPractices.URL_BLOCK_CATEGORIES
    return url_filtering_profile


def mock_bad_url_filtering_profile():
    from Panorama import URLFilteringProfile
    url_filtering_profile = URLFilteringProfile()
    url_filtering_profile.block = ["hacking"]
    return url_filtering_profile


def mock_issue_with_underscores():
    return {
        "container_name": "test-dg",
        "issue_code": "BP-V-1",
        "description": "Log forwarding profile is missing enhanced application logging",
        "name": "test-bad",
        "hostid": MOCK_FIREWALL_1_SERIAL
    }


def mock_enhanced_log_forwarding_issue_dict():
    return {
        "containername": "test-dg",
        "issuecode": "BP-V-1",
        "description": "Log forwarding profile is missing enhanced application logging",
        "name": "test-bad",
        "hostid": MOCK_FIREWALL_1_SERIAL
    }


def mock_security_zone_no_log_setting_issue_dict():
    return {
        "containername": "test-dg",
        "issuecode": "BP-V-7",
        "description": "Security zone has no log forwarding setting",
        "name": "test-bad",
        "hostid": MOCK_FIREWALL_1_SERIAL
    }


def mock_security_rule_log_settings_issue_dict():
    return {
        "containername": "test-dg",
        "issuecode": "BP-V-8",
        "description": "Security rule has no log setting",
        "name": "test-bad-no-lfp",
        "hostid": MOCK_FIREWALL_1_SERIAL
    }


def mock_security_rule_security_profile_group_issue_dict():
    return {
        "containername": "test-dg",
        "issuecode": "BP-V-10",
        "description": "Security rule has no security profile group",
        "name": "test-bad-no-spg",
        "hostid": MOCK_FIREWALL_1_SERIAL
    }


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


@pytest.fixture
def mock_single_device_topology(mock_panorama):
    from Panorama import Topology
    topology = Topology()
    topology.panorama_objects = {
        MOCK_PANORAMA_SERIAL: mock_panorama,
    }
    topology.ha_active_devices = {
        MOCK_PANORAMA_SERIAL: mock_panorama,
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

    def test_dataclass_to_command_results(self):
        """Given a list of dataclasses, check that this function correctly converts it to a commandResults object."""
        from Panorama import dataclasses_to_command_results, PanosObjectReference
        test_dataclass = PanosObjectReference(
            hostid=MOCK_FIREWALL_1_SERIAL,
            container_name="test",
            object_type="TestObject",
            name="test_name"
        )
        results = dataclasses_to_command_results(test_dataclass)
        # Check we get the right table headers when no additional arguments are given
        assert "container_name|hostid|name|object_type" in results.readable_output
        assert "### PAN-OS Object" in results.readable_output

        results = dataclasses_to_command_results(
            test_dataclass, override_table_name="Test Table",
            override_table_headers=["hostid", "name", "container_name"])
        # When we provide overrides, check they are rendered correctly in the readable output
        assert "hostid|name|container_name" in results.readable_output
        assert "### Test Table" in results.readable_output


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
    SHOW_COMMIT_JOB_XML = "test_data/show_commit_jobs_all.xml"

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

    def test_reboot(self, mock_topology):
        """
        Test the reboot function returns the corect data
        The pan-os-python reboot method actually doesn't return any output itself unless it errors, so we just check our
        dataclass is set correctly within the function and returned by this function.
        """
        from Panorama import UniversalCommand

        result = UniversalCommand.reboot(mock_topology, MOCK_PANORAMA_SERIAL)
        # Check all attributes of summary data have values
        for result_dataclass in result.summary_data:
            for value in result_dataclass.__dict__.values():
                assert value

        # We also want to check that if an empty string is passed, an error is returned
        with pytest.raises(
                DemistoException,
                match="filter_str  is not the exact ID of a host in this topology; use a more specific filter string."
        ):
            UniversalCommand.reboot(mock_topology, "")

        # Lets also check that if an invalid hostid is given, we also raise.
        with pytest.raises(
                DemistoException,
                match="filter_str badserialnumber is not the exact ID of "
                      "a host in this topology; use a more specific filter string."
        ):
            UniversalCommand.reboot(mock_topology, "badserialnumber")

    @patch("Panorama.run_op_command")
    def test_system_status(self, patched_run_op_command, mock_topology):
        """
        Given a topology object with a mixture of systems in it,
        assert that check_system_availability returns the correct status
        based on whether devices are connected or not.
        """
        from Panorama import UniversalCommand

        patched_run_op_command.return_value = load_xml_root_from_test_file(TestUniversalCommand.SHOW_SYSTEM_INFO_XML)
        # Check a normal, up device
        result = UniversalCommand.check_system_availability(mock_topology, MOCK_PANORAMA_SERIAL)
        assert result.up

        # Check a device that isn't in the topology
        result = UniversalCommand.check_system_availability(mock_topology, "fake")
        assert result
        assert not result.up


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

    @patch("Panorama.run_op_command")
    def test_update_ha_state(self, patched_run_op_command, mock_topology):
        """
        Test the HA Update command returns the correct data
        """
        from Panorama import FirewallCommand

        result_dataclass = FirewallCommand.change_status(mock_topology, MOCK_FIREWALL_1_SERIAL, "operational")
        # Check all attributes of summary data have values
        for value in result_dataclass.__dict__.values():
            assert value


@pytest.mark.parametrize('args, expected_request_params, request_result, expected_demisto_result',
                         [pytest.param({'anti_spyware_profile_name': 'fake_profile_name',
                                        'dns_signature_source': 'edl_name', 'action': 'allow'},
                                       {
                                           'action': 'set',
                                           'type': 'config',
                                           'xpath': "/config/devices/entry[@name='localhost.localdomain']"
                                                    "/device-group/entry[@name='fakeDeviceGroup']"
                                                    "/profiles/spyware/entry[@name='fake_profile_name']",
                                           'key': 'fakeAPIKEY!',
                                           'element': '<botnet-domains>'
                                                      '<lists>'
                                                      '<entry name="edl_name"><packet-capture>disable</packet-capture>'
                                                      '<action><allow/></action></entry>'
                                                      '</lists>'
                                                      '</botnet-domains>'},
                                       MockedResponse(text='<response status="success" code="20"><msg>'
                                                           'command succeeded</msg></response>', status_code=200,
                                                      reason=''),
                                       '**success**',
                                       ),
                          ])
def test_panorama_apply_dns_command(mocker, args, expected_request_params, request_result, expected_demisto_result):
    """
    Given:
        - command args
        - request result
    When:
        - Running panorama-apply-dns
    Then:
        - Assert the request url is as expected
        - Assert Command results contains the relevant result information
    """
    import Panorama
    import requests
    from Panorama import apply_dns_signature_policy_command

    Panorama.API_KEY = 'fakeAPIKEY!'
    Panorama.DEVICE_GROUP = 'fakeDeviceGroup'
    request_mock = mocker.patch.object(requests, 'request', return_value=request_result)
    command_result: CommandResults = apply_dns_signature_policy_command(args)

    called_request_params = request_mock.call_args.kwargs['params']  # The body part of the request
    assert called_request_params == expected_request_params
    assert command_result.readable_output == expected_demisto_result


class TestHygieneFunctions:
    @patch("Panorama.Template.refreshall", return_value=[])
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=mock_device_groups())
    def test_check_log_forwarding(self, _, __, ___, mock_topology):
        """
        Test the Hygiene Configuration lookups can validate the log forwarding settings of a device
        """
        from Panorama import HygieneLookups, LogForwardingProfile, LogForwardingProfileMatchList
        # First, test that a correctly configured LFP and match list don't return a failure
        LogForwardingProfile.refreshall = MagicMock(return_value=mock_good_log_fowarding_profile())
        LogForwardingProfileMatchList.refreshall = MagicMock(return_value=mock_good_log_forwarding_profile_match_list())
        result = HygieneLookups.check_log_forwarding_profiles(mock_topology)
        assert len(result.result_data) == 0

        # Trim the "threat" log type and cause a missing log type error
        LogForwardingProfileMatchList.refreshall = MagicMock(
            return_value=[mock_good_log_forwarding_profile_match_list()[0]]
        )
        result = HygieneLookups.check_log_forwarding_profiles(mock_topology)
        # Note; because we mock the topology with multiple devices,
        # it appears that the same LFP is missing in each Container.
        # This is expected.
        assert len(result.result_data) == 3
        assert result.result_data[0].description == "Log forwarding profile missing log type 'threat'."

    @patch("Panorama.Template.refreshall", return_value=[])
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=mock_device_groups())
    def test_check_vulnerability_profiles(self, _, __, ___, mock_topology):
        """
        Test the Hygiene Configuration lookups can validate the vulnerability profiles
        """
        from Panorama import HygieneLookups, VulnerabilityProfile, BestPractices
        # First, test that we can get the conforming threat profile, of which there should be one
        result = HygieneLookups.get_conforming_threat_profiles(
            [mock_good_vulnerability_profile(), mock_bad_vulnerability_profile()],
            minimum_block_severities=BestPractices.VULNERABILITY_BLOCK_SEVERITIES,
            minimum_alert_severities=BestPractices.VULNERABILITY_ALERT_THRESHOLD
        )
        assert len(result) == 1

        VulnerabilityProfile.refreshall = MagicMock(
            return_value=[mock_good_vulnerability_profile(), mock_bad_vulnerability_profile()]
        )

        result = HygieneLookups.check_vulnerability_profiles(mock_topology)
        # Should return no results, as at least one vulnerability profile matches.
        assert len(result.result_data) == 0

        VulnerabilityProfile.refreshall = MagicMock(
            return_value=[mock_bad_vulnerability_profile()]
        )

        result = HygieneLookups.check_vulnerability_profiles(mock_topology)
        # Should return one issue, as no Vulnerability profile matches.
        assert len(result.result_data) == 1

    @patch("Panorama.Template.refreshall", return_value=[])
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=mock_device_groups())
    def test_check_spyware_profiles(self, _, __, ___, mock_topology):
        """
        Test the Hygiene Configuration lookups can validate the
        Spyware profiles given combinations of good and bad profile
        objects.
        """
        from Panorama import HygieneLookups, AntiSpywareProfile
        AntiSpywareProfile.refreshall = MagicMock(
            return_value=[mock_good_spyware_profile(), mock_bad_spyware_profile()]
        )

        # Check when at least one good profile exists - should return no results
        result = HygieneLookups.check_spyware_profiles(mock_topology)
        assert not result.result_data

    @patch("Panorama.Template.refreshall", return_value=[])
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=mock_device_groups())
    def test_check_url_filtering_profiles(self, _, __, ___, mock_topology):
        """
        Test the Hygiene Configuration lookups can validate the
        URL filtering profiles given combinations of good and bad
        profiles.
        """
        from Panorama import HygieneLookups, URLFilteringProfile
        URLFilteringProfile.refreshall = MagicMock(
            return_value=[mock_good_url_filtering_profile()]
        )

        # Check when a good profile exists - should return no results
        result = HygieneLookups.check_url_filtering_profiles(mock_topology)
        assert not result.result_data

        # When there's only bad, should return a result
        URLFilteringProfile.refreshall = MagicMock(
            return_value=[mock_bad_url_filtering_profile()]
        )

        # Check when a good profile exists - should return no results
        result = HygieneLookups.check_url_filtering_profiles(mock_topology)
        assert result.result_data

    @patch("Panorama.Template.refreshall", return_value=mock_templates())
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=[])
    def test_check_security_zones(self, _, __, ___, mock_topology):
        """
        Test the Hygiene Configuration lookups can validate security zones given a comination of good and bad zones.
        """
        from Panorama import HygieneLookups, Zone
        Zone.refreshall = MagicMock(
            return_value=mock_good_security_zones()
        )

        result = HygieneLookups.check_security_zones(mock_topology)
        # Result data should be empty as there are only good zones
        assert not result.result_data

        Zone.refreshall = MagicMock(
            return_value=mock_bad_security_zones()
        )

        result = HygieneLookups.check_security_zones(mock_topology)
        # Result data should have one issue as there is a misconfigured security zone
        assert result.result_data
        assert "BP-V-7" in [x.issue_code for x in result.result_data]

    @patch("Panorama.Template.refreshall", return_value=[])
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=mock_device_groups())
    def test_check_security_rules(self, _, __, ___, mock_topology):
        """
        Test the Hygiene Configuration lookups can validate security zones given a comination of good and bad zones.
        """
        from Panorama import HygieneLookups, SecurityRule
        SecurityRule.refreshall = MagicMock(
            return_value=mock_good_security_rules()
        )

        result = HygieneLookups.check_security_rules(mock_topology)
        # Should not raise any issues
        assert not result.result_data

        SecurityRule.refreshall = MagicMock(
            return_value=mock_bad_security_rules()
        )

        result = HygieneLookups.check_security_rules(mock_topology)
        # Should raise issues for each issue type
        assert result.result_data
        assert "BP-V-8" in [x.issue_code for x in result.result_data]
        assert "BP-V-9" in [x.issue_code for x in result.result_data]
        assert "BP-V-10" in [x.issue_code for x in result.result_data]

    def test_hygiene_issue_dict_to_object(self):
        """
        Tests the function can convert a given dictionary of
        an issue, returned by a hygiene lookup, back into the relevent
        object. This is to allow the check commands to pass their results directly into the fix commands via XSOAR.
        """
        from Panorama import hygiene_issue_dict_to_object, ConfigurationHygieneIssue
        result = hygiene_issue_dict_to_object(mock_enhanced_log_forwarding_issue_dict())
        assert isinstance(result[0], ConfigurationHygieneIssue)
        assert len(result) == 1
        for value in result[0].__dict__.values():
            assert value

        # If the issue is passed directly from the other command make sure this function works also
        result = hygiene_issue_dict_to_object(mock_issue_with_underscores())
        assert isinstance(result[0], ConfigurationHygieneIssue)
        assert len(result) == 1
        for value in result[0].__dict__.values():
            assert value

    @patch("Panorama.Template.refreshall", return_value=[])
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=mock_device_groups())
    def test_fix_log_forwarding_profile_enhanced_logging(self, _, __, ___, mock_topology):
        """
        Tests wthe fix function for enabling enhanced application
        logging on log forwarding profiles, given an issue referring
        to a bad log forwarding profile.
        """
        from Panorama import hygiene_issue_dict_to_object, LogForwardingProfile, HygieneRemediation
        issues = hygiene_issue_dict_to_object(mock_enhanced_log_forwarding_issue_dict())

        LogForwardingProfile.refreshall = MagicMock(return_value=mock_bad_log_fowarding_profile())
        LogForwardingProfile.apply = MagicMock()

        result = HygieneRemediation.fix_log_forwarding_profile_enhanced_logging(mock_topology, issues)
        # Should be at least one result
        assert result
        for value in result[0].__dict__.values():
            assert value

    @patch("Panorama.Template.refreshall", return_value=[])
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=mock_device_groups())
    def test_fix_security_zone_no_log_setting(self, _, __, ___, mock_topology):
        """
        Tests wthe fix function for setting a log forwarding profile on security zones when none is currently set
        """
        from Panorama import hygiene_issue_dict_to_object, Zone, HygieneRemediation
        issues = hygiene_issue_dict_to_object(mock_security_zone_no_log_setting_issue_dict())

        Zone.refreshall = MagicMock(return_value=mock_bad_security_zones())
        Zone.apply = MagicMock()

        result = HygieneRemediation.fix_security_zone_no_log_setting(mock_topology, issues, "test")
        # Should be at least one result, as we provided an issue.
        assert result
        for value in result[0].__dict__.values():
            assert value

    @patch("Panorama.Template.refreshall", return_value=[])
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=mock_device_groups())
    def test_fix_security_rule_log_settings(self, _, __, ___, mock_topology):
        """
        Tests the function that adds a log forwarding profile to a security rule when one isn't present.
        """
        from Panorama import hygiene_issue_dict_to_object, SecurityRule, HygieneRemediation
        issues = hygiene_issue_dict_to_object(mock_security_rule_log_settings_issue_dict())

        SecurityRule.refreshall = MagicMock(return_value=mock_bad_security_rules())
        SecurityRule.apply = MagicMock()

        result = HygieneRemediation.fix_secuity_rule_log_settings(mock_topology, issues, "test")
        # Should be at least one result, as we provided an issue.
        assert result
        for value in result[0].__dict__.values():
            assert value

    @patch("Panorama.Template.refreshall", return_value=[])
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=mock_device_groups())
    def test_fix_security_rule_profile_settings(self, _, __, ___, mock_topology):
        """
        Tests the function that adds sets the security profile group when no SPG is currently provided
        """
        from Panorama import hygiene_issue_dict_to_object, SecurityRule, HygieneRemediation
        issues = hygiene_issue_dict_to_object(mock_security_rule_log_settings_issue_dict())

        SecurityRule.refreshall = MagicMock(return_value=mock_bad_security_rules())
        SecurityRule.apply = MagicMock()

        result = HygieneRemediation.fix_security_rule_security_profile_group(mock_topology, issues, "test")
        # Should be at least one result, as we provided an issue.
        assert result
        for value in result[0].__dict__.values():
            assert value


class TestObjectFunctions:
    @patch("Panorama.Template.refreshall", return_value=[])
    @patch("Panorama.Vsys.refreshall", return_value=[])
    @patch("Panorama.DeviceGroup.refreshall", return_value=mock_device_groups())
    def test_get_objects(self, _, __, ___, mock_single_device_topology):
        """
        Tests that we can get various object types and the filtering logic, by object type and name, works correctly.
        """
        from Panorama import ObjectGetter, AddressObject

        # Use side effects so that objects are only returned from one container
        AddressObject.refreshall = MagicMock(side_effect=[mock_address_objects(), []])

        # Test with no filter first
        result = ObjectGetter.get_object_reference(mock_single_device_topology, "AddressObject")
        assert "test-address-1" in [x.name for x in result]
        assert "test-address-2" in [x.name for x in result]

        # Same as above but with a filter on object name
        AddressObject.refreshall = MagicMock(side_effect=[mock_address_objects(), []])
        result = ObjectGetter.get_object_reference(
            mock_single_device_topology, "AddressObject", object_name="test-address-1"
        )
        assert "test-address-1" in [x.name for x in result]
        assert "test-address-2" not in [x.name for x in result]

        # Same as above but include a regex filter
        AddressObject.refreshall = MagicMock(side_effect=[mock_address_objects(), []])
        result = ObjectGetter.get_object_reference(
            mock_single_device_topology, "AddressObject", object_name="test-address-\d+", use_regex="true"
        )
        assert "test-address-1" in [x.name for x in result]
        assert "test-address-2" in [x.name for x in result]

        # Test broken regex
        AddressObject.refreshall = MagicMock(side_effect=[mock_address_objects(), []])
        with pytest.raises(DemistoException):
            result = ObjectGetter.get_object_reference(
                mock_single_device_topology, "AddressObject", object_name="test-address-(\d+", use_regex="true"
            )
            assert not result


@pytest.mark.parametrize('expected_request_params, target',
                         [pytest.param(
                             {
                                 'type': 'op',
                                 'cmd': '<show><system><info/></system></show>',
                                 'key': 'fakeAPIKEY!',
                                 'target': 'fake-target'
                             },
                             'fake-target',
                         ),
                             pytest.param(
                                 {
                                     'type': 'op',
                                     'cmd': '<show><system><info/></system></show>',
                                     'key': 'fakeAPIKEY!',
                                 },
                                 None,),
                         ])
def test_add_target_arg(mocker, expected_request_params, target):
    """
    Given:
        - a call to the function with or without the target args
    When:
        - panorama_show_device_version_command - (or any other function with the target arg)
    Then:
        - Assert that the target param was added or not to the https request
    """
    import Panorama
    from Panorama import panorama_show_device_version

    Panorama.API_KEY = 'fakeAPIKEY!'
    Panorama.DEVICE_GROUP = 'fakeDeviceGroup'
    request_mock = mocker.patch.object(Panorama, 'http_request',
                                       return_value={'response': {'result': {'system': 'fake_data'}}})

    panorama_show_device_version(target)
    called_request_params = request_mock.call_args.kwargs['params']
    assert called_request_params == expected_request_params


@pytest.mark.parametrize('rule , expected_result',
                         [pytest.param({
                             'target': {
                                 'devices': {
                                     'entry': [
                                         {
                                             '@name': 'fw1'
                                         },
                                         {
                                             '@name': 'fw2'
                                         }
                                     ]
                                 }
                             }
                         },
                             True
                         ),
                             pytest.param(
                                 {
                                     'target': {
                                         'devices': {
                                             'entry': {
                                                 '@name': 'fw1'
                                             }
                                         }
                                     }
                                 },
                                 True),
                             pytest.param(
                                 {
                                     'target': {
                                         'devices': {
                                             'entry': {
                                                 '@name': 'fw2'
                                             }
                                         }
                                     }
                                 },
                                 False),
                             pytest.param(
                                 {
                                     'target':
                                         {
                                             'devices':
                                                 {
                                                     'entry': [
                                                         {
                                                             '@name': 'fw1'
                                                         }
                                                     ]
                                                 }
                                         }
                                 },
                                 True),
                         ])
def test_target_filter(rule, expected_result):
    """
    Given:
        - a rule (dict) and a target (str) - 'fw1'
    When:
        - filtering rules by target
    Then:
        - return True if the rule contains the target and False otherwise
    """
    from Panorama import target_filter
    assert target_filter(rule, 'fw1') == expected_result


def test_check_latest_version_hr(mocker):
    """
    Given:
        - a response from panorma of latest version
    When:
        - calling the command - pan-os-check-latest-panos-software
    Then:
        - filter the 5 latest results and present in a markdown
    """
    from Panorama import panorama_check_latest_panos_software_command
    import requests
    with open('test_data/latest_versions.xml') as xml_file:
        text = xml_file.read()
    with open('test_data/5_latest_version.md') as md_file:
        markdown_assert = md_file.read()
    mr = MockedResponse(text=text,
                        status_code=200,
                        reason='')
    mocker.patch.object(requests, 'request', return_value=mr)
    command_res: CommandResults = panorama_check_latest_panos_software_command()

    assert markdown_assert == command_res.readable_output


def test_pan_os_get_running_config(mocker):
    """
    Given -
        A target serial number
    When -
        Returning the running config
    Then -
        File returned should be called 'running_config'
        The contents should be XML and not JSON
    """
    from Panorama import pan_os_get_running_config

    return_mock = """
    <response status='error' code='13'><msg><line>SOME_SERIAL_NUMBER not connected</line></msg></response>
    """
    mocker.patch("Panorama.http_request", return_value=return_mock)
    created_file = pan_os_get_running_config({"target": "SOME_SERIAL_NUMBER"})
    assert created_file['File'] == 'running_config'


def test_pan_os_get_merged_config(mocker):
    """
    Given -
        A target serial number
    When -
        Returning the merged config
    Then -
        File returned should be called 'merged_config'
        The contents should be XML and not JSON
    """
    from Panorama import pan_os_get_merged_config

    return_mock = """
    <response status='error' code='13'><msg><line>SOME_SERIAL_NUMBER not connected</line></msg></response>
    """
    mocker.patch("Panorama.http_request", return_value=return_mock)
    created_file = pan_os_get_merged_config({"target": "SOME_SERIAL_NUMBER"})
    assert created_file['File'] == 'merged_config'
