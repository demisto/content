import pytest

import demistomock as demisto
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

    err_msg = 'Only the override_allow_list, override_block_list, description properties can be'\
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


def test_panorama_security_policy_match_command_no_target():
    """
    Given:
     - a Panorama instance(mocked parameter) without the target argument

    When:
     - running the panorama-security-policy-match command

    Then:
     - Validate a proper error is raised
    """
    from Panorama import panorama_security_policy_match_command
    err_msg = "The 'panorama-security-policy-match' command is relevant for a Firewall instance " \
              "or for a Panorama instance, to be used with the target argument."
    with pytest.raises(DemistoException, match=err_msg):
        panorama_security_policy_match_command(demisto.args())


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
    str_match = 'In order to show the the configured user interfaces in your Panorama, ' \
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
    str_match = 'In order to show the the configured user interfaces in your Panorama, ' \
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
