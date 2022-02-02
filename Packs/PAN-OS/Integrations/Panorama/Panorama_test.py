import pytest
import os
from xml.etree.ElementTree import fromstring
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


@pytest.fixture()
def firewall_login():
    return {
        "username": os.getenv("T_USERNAME"),
        "password": os.getenv("T_PASSWORD"),
        "ip": os.getenv("T_FW_IP")
    }


@pytest.fixture()
def panorama_login():
    return {
        "username": os.getenv("T_USERNAME"),
        "password": os.getenv("T_PASSWORD"),
        "ip": os.getenv("T_PAN_IP")
    }


@pytest.fixture()
def test_arp_result_element():
    xml_str = """<response status="success">
        <result>
            <max>1500</max>
            <total>7</total>
            <timeout>1800</timeout>
            <dp>dp0</dp>
            <entries>
                <entry>
                    <status>  c  </status>
                    <ip>2.3.4.5</ip>
                    <mac>00:66:4b:da:ce:61</mac>
                    <ttl>1525</ttl>
                    <interface>ethernet1/1</interface>
                    <port>ethernet1/1</port>
                </entry>
            </entries>
        </result>
    </response>"""
    return fromstring(xml_str)


@pytest.fixture()
def test_bgp_result_element():
    xml_str = """<response status="success">
    <result>
        <entry peer="testlab-server" vr="default">
            <peer-group>testlab-peers</peer-group>
            <peer-router-id>3.3.3.3</peer-router-id>
            <remote-as>64511</remote-as>
            <status>Established</status>
            <status-duration>12459</status-duration>
            <password-set>no</password-set>
            <passive>no</passive>
            <multi-hop-ttl>1</multi-hop-ttl>
            <peer-address>3.3.3.3:179</peer-address>
            <local-address>10.10.0.1:39889</local-address>
            <reflector-client>not-client</reflector-client>
            <same-confederation>no</same-confederation>
            <aggregate-confed-as>yes</aggregate-confed-as>
            <peering-type>Unspecified</peering-type>
            <connect-retry-interval>1</connect-retry-interval>
            <open-delay>0</open-delay>
            <idle-hold>15</idle-hold>
            <prefix-limit>5000</prefix-limit>
            <holdtime>90</holdtime>
            <holdtime-config>90</holdtime-config>
            <keepalive>30</keepalive>
            <keepalive-config>30</keepalive-config>
            <msg-update-in>3</msg-update-in>
            <msg-update-out>1</msg-update-out>
            <msg-total-in>420</msg-total-in>
            <msg-total-out>482</msg-total-out>
            <last-update-age>8</last-update-age>
            <last-error></last-error>
            <status-flap-counts>1479</status-flap-counts>
            <established-counts>1</established-counts>
            <ORF-entry-received>0</ORF-entry-received>
            <nexthop-self>no</nexthop-self>
            <nexthop-thirdparty>yes</nexthop-thirdparty>
            <nexthop-peer>no</nexthop-peer>
            <prefix-counter>
                <entry afi-safi="bgpAfiIpv4-unicast">
                    <incoming-total>1</incoming-total>
                    <incoming-accepted>1</incoming-accepted>
                    <incoming-rejected>0</incoming-rejected>
                    <policy-rejected>0</policy-rejected>
                    <outgoing-total>0</outgoing-total>
                    <outgoing-advertised>0</outgoing-advertised>
                </entry>
            </prefix-counter>
        </entry>
    </result>
</response>"""
    return fromstring(xml_str)


@pytest.fixture()
def fake_device():
    class Device:
        hostname = "test_hostname"
        serial = "testserial"

    return Device()


@pytest.fixture()
def hygiene_issue_example_list():
    return [
        {
            "containername": "LAB",
            "description": "Log forwarding profile is missing enhanced application logging.",
            "hostid": "1.1.1.1",
            "issuecode": "BP-V-3",
            "name": "test_fwd_profile-1"
        },
        {
            "containername": "LAB",
            "description": "Log forwarding profile is missing enhanced application logging.",
            "hostid": "1.1.1.1",
            "issuecode": "BP-V-3",
            "name": "test_fwd_profile-1-1"
        }
    ]


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


def test_panoram_get_os_version(patched_requests_mocker):
    from Panorama import get_pan_os_version
    import Panorama
    Panorama.URL = 'https://1.1.1.1:443/api/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    r = get_pan_os_version()
    assert r == '9.0.6'


def test_panoram_override_vulnerability(patched_requests_mocker):
    from Panorama import panorama_override_vulnerability
    import Panorama
    Panorama.URL = 'https://1.1.1.1:443/api/'
    r = panorama_override_vulnerability(mock_demisto_args['threat_id'],
                                        mock_demisto_args['vulnerability_profile'],
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
                     {'@name': 'my_name2', 'fqdn': 'b.com'}]
    response = prettify_addresses_arr(addresses_arr)
    expected = [{'Name': 'my_name', 'FQDN': 'a.com'},
                {'Name': 'my_name2', 'FQDN': 'b.com'}]
    assert response == expected


def test_prettify_address():
    from Panorama import prettify_address
    address = {'@name': 'my_name', 'ip-netmask': '1.1.1.1', 'description': 'lala'}
    response = prettify_address(address)
    expected = {'Name': 'my_name', 'IP_Netmask': '1.1.1.1', 'Description': 'lala'}
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


def test_prettify_service():
    from Panorama import prettify_service
    service = {'@name': 'service_name', 'description': 'foo', 'protocol': {'tcp': {'port': '443'}}}
    response = prettify_service(service)
    expected = {'Name': 'service_name', 'Description': 'foo', 'Protocol': 'tcp', 'DestinationPort': '443'}
    assert response == expected


def test_prettify_service_group():
    from Panorama import prettify_service_group
    service_group = {'@name': 'sg', 'members': {'member': ['service1', 'service2']}}
    response = prettify_service_group(service_group)
    expected = {'Name': 'sg', 'Services': ['service1', 'service2']}
    assert response == expected


def test_prettify_custom_url_category():
    from Panorama import prettify_custom_url_category
    custom_url_category = {'@name': 'foo', 'list': {'member': ['a', 'b', 'c']}}
    response = prettify_custom_url_category(custom_url_category)
    expected = {'Name': 'foo', 'Sites': ['a', 'b', 'c']}
    assert response == expected


def test_prettify_edl():
    from Panorama import prettify_edl
    edl = {'@name': 'edl_name', 'type': {'my_type': {'url': 'abc.com', 'description': 'my_desc'}}}
    response = prettify_edl(edl)
    expected = {'Name': 'edl_name', 'Type': 'my_type', 'URL': 'abc.com', 'Description': 'my_desc'}
    assert response == expected


def test_build_traffic_logs_query():
    # (addr.src in 192.168.1.222) and (app eq netbios-dg) and (action eq allow) and (port.dst eq 138)
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


def test_prettify_logs():
    from Panorama import prettify_logs
    traffic_logs = [
        {'action': 'my_action1', 'category': 'my_category1', 'rule': 'my_rule1', 'natdport': '100',
         'bytes': '12'},
        {'action': 'my_action2', 'category': 'my_category2', 'rule': 'my_rule2', 'natdport': '101',
         'bytes_sent': '11'}]
    response = prettify_logs(traffic_logs)
    expected = [{'Action': 'my_action1', 'CategoryOrVerdict': 'my_category1', 'Rule': 'my_rule1',
                 'NATDestinationPort': '100', 'Bytes': '12'},
                {'Action': 'my_action2', 'CategoryOrVerdict': 'my_category2', 'Rule': 'my_rule2',
                 'NATDestinationPort': '101', 'BytesSent': '11'}]
    assert response == expected


def test_build_policy_match_query():
    from Panorama import build_policy_match_query
    source = '1.1.1.1'
    destination = '6.7.8.9'
    protocol = '1'
    application = 'gmail-base'
    response = build_policy_match_query(application, None, destination, None, None, None, protocol, source)
    expected = '<test><security-policy-match><source>1.1.1.1</source><destination>6.7.8.9</destination>' \
               '<protocol>1</protocol><application>gmail-base</application></security-policy-match></test>'
    assert response == expected


def test_prettify_matching_rule():
    from Panorama import prettify_matching_rule
    matching_rule = {'action': 'my_action1', '@name': 'very_important_rule', 'source': '6.7.8.9',
                     'destination': 'any'}
    response = prettify_matching_rule(matching_rule)
    expected = {'Action': 'my_action1', 'Name': 'very_important_rule', 'Source': '6.7.8.9',
                'Destination': 'any'}
    assert response == expected


def test_prettify_static_route():
    from Panorama import prettify_static_route
    static_route = {'@name': 'name1', 'destination': '1.2.3.4', 'metric': '10',
                    'nexthop': {'fqdn': 'demisto.com'}}
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


def test_prettify_configured_user_id_agents__multi_result():
    from Panorama import prettify_configured_user_id_agents
    raw_response = [{'@name': 'testing2', 'serial-number': 'panorama2'},
                    {'@name': 'fullinfo', 'host-port': {'port': '67', 'ntlm-auth': 'yes',
                                                        'ldap-proxy': 'yes', 'collectorname': 'demisto',
                                                        'secret': 'secret', 'host': 'what'},
                     'ip-user-mappings': 'yes'}]
    response = prettify_configured_user_id_agents(raw_response)
    expected = [{'Name': 'testing2', 'Host': None, 'Port': None, 'NtlmAuth': 'no', 'LdapProxy': 'no',
                 'CollectorName': None, 'Secret': None, 'EnableHipCollection': 'no',
                 'SerialNumber': 'panorama2',
                 'IpUserMapping': 'no', 'Disabled': 'no'},
                {'Name': 'fullinfo', 'Host': 'what', 'Port': '67', 'NtlmAuth': 'yes', 'LdapProxy': 'yes',
                 'CollectorName': 'demisto', 'Secret': 'secret', 'EnableHipCollection': 'no',
                 'SerialNumber': None,
                 'IpUserMapping': 'yes', 'Disabled': 'no'}]
    assert response == expected


def test_prettify_configured_user_id_agents__single_result():
    from Panorama import prettify_configured_user_id_agents
    raw_response = {'@name': 'fullinfo', 'host-port': {'port': '67', 'ntlm-auth': 'yes',
                                                       'ldap-proxy': 'yes', 'collectorname': 'demisto',
                                                       'secret': 'secret', 'host': 'what'},
                    'ip-user-mappings': 'yes'}
    response = prettify_configured_user_id_agents(raw_response)
    expected = {'Name': 'fullinfo', 'Host': 'what', 'Port': '67', 'NtlmAuth': 'yes', 'LdapProxy': 'yes',
                'CollectorName': 'demisto', 'Secret': 'secret', 'EnableHipCollection': 'no',
                'SerialNumber': None,
                'IpUserMapping': 'yes', 'Disabled': 'no'}
    assert response == expected


def test_get_issue_code():
    from Panorama import HygieneCheckRegister, ConfigurationHygieneCheck
    check_register = HygieneCheckRegister.get_hygiene_check_register(["BP-V-1"])
    assert check_register.get("BP-V-1")
    assert type(check_register.get("BP-V-1")) == ConfigurationHygieneCheck


def test_missing_issue_code():
    from Panorama import HygieneCheckRegister
    check_register = HygieneCheckRegister.get_hygiene_check_register(["BP-V-1"])
    with pytest.raises(DemistoException):
        assert check_register.get("BP-V-2")


def test_dataclass_from_element(test_arp_result_element, fake_device):
    from Panorama import ShowArpCommandResultData, dataclass_from_element

    entry = test_arp_result_element.findall("./result/entries/entry")
    result_object: ShowArpCommandResultData = dataclass_from_element(fake_device,
                                                                     ShowArpCommandResultData, entry[0])
    for field in [result_object.ip, result_object.ttl, result_object.mac, result_object.port]:
        assert field

    assert result_object.hostid == "testserial"
    assert result_object.ip == "2.3.4.5"


def test_dataclass_from_nested_element(test_bgp_result_element, fake_device):
    from Panorama import ShowRoutingProtocolBGPPeersResultData, dataclass_from_element

    entry = test_bgp_result_element.findall("./result/entry")
    result_object: ShowRoutingProtocolBGPPeersResultData = dataclass_from_element(fake_device,
                                                                                  ShowRoutingProtocolBGPPeersResultData,
                                                                                  entry[0])
    assert result_object.incoming_total == 1
    assert result_object.peer == "testlab-server"


def test_run_command():
    from Panorama import (DownloadSoftwareCommandResult, CommandRegister,
                          GenericSoftwareStatus, ShowJobsAllResultData)

    cr = CommandRegister()
    cr.command("test_run_command")

    # Test a normal return with summary data
    def f(topology):
        return DownloadSoftwareCommandResult(
            summary_data=[GenericSoftwareStatus(hostid='015351000071920', started=True)]
        )

    cr.run_command_result_command("test_run_command", f, {}, {})

    def f(topology):
        return ShowJobsAllResultData(
            hostid="111",
            status="FIN",
            description="",
            result="OK",
            progress="100",
            stoppable="NO",
            positionInQ="1",
            tenq="blah",
            tfin="blah",
            type="Dwnld",
            id="48",
            user=None
        )

    cr.run_command_result_command("test_run_command", f, {}, {})


def test_convert_hygiene_dataclass(hygiene_issue_example_list):
    from Panorama import hygiene_issue_dict_to_object
    assert len(hygiene_issue_dict_to_object(hygiene_issue_example_list)) == 2
