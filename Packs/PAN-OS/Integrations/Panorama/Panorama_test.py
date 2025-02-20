import json
from defusedxml import ElementTree
import pytest
import requests_mock
from pytest_mock import MockerFixture
from requests_mock.mocker import Mocker as RequestsMock
import panos.errors
import demistomock as demisto
from unittest.mock import patch, MagicMock
from panos.device import Vsys
from panos.panorama import Panorama, DeviceGroup, Template
from panos.firewall import Firewall
from CommonServerPython import DemistoException, CommandResults
from panos.objects import LogForwardingProfile, LogForwardingProfileMatchList
import dateparser

from test_data import fetch_incidents_input
from test_data import mock_rules
from freezegun import freeze_time
from typing import cast

integration_firewall_params = {
    'port': '443',
    'vsys': 'vsys1',
    'server': 'https://1.1.1.1',
    'key': 'thisisabogusAPIKEY!',
}

mock_demisto_args = {
    'threat_id': "11111",
    'vulnerability_profile': "mock_vuln_profile"
}

integration_panorama_params = {
    'port': '443',
    'device_group': 'Lab-Devices',
    'server': 'https://1.1.1.1',
    'key': 'thisisabogusAPIKEY!',
    'template': 'test'
}


def load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture(autouse=True)
def set_params(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_firewall_params)
    mocker.patch.object(demisto, 'args', return_value=mock_demisto_args)


@pytest.fixture
def patched_requests_mocker(requests_mock):
    """
    This function mocks various PANOS API responses so we can accurately test the instance
    """
    base_url = "{}:{}/api/".format(integration_firewall_params['server'], integration_firewall_params['port'])
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
    version_path = "{}{}{}".format(base_url, "?type=version&key=", integration_firewall_params['key'])
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


@pytest.mark.parametrize('disabled, rules_file, expected_results_file',
                         [
                             ('yes', 'test_data/filter_rules_sample.json',
                              'test_data/filter_rules_expected_result.json'),
                         ])
def test_filter_rules_by_status(disabled: str, rules_file: str, expected_results_file: str):
    from Panorama import filter_rules_by_status

    with open(rules_file) as f:
        rules = json.loads(f.read())

    with open(expected_results_file) as f:
        expected_result = json.loads(f.read())

    result = filter_rules_by_status(disabled, rules)
    assert result == expected_result


def test_get_address(mocker):
    """
    Given:
     - an address_name argument which does not exist

    When:
     - running the panorama_get_address function

    Then:
     - Ensure the return value is an empty dictionary
    """
    import Panorama
    from Panorama import panorama_get_address
    exception_msg = 'Object was not found, verify that the name is correct and that the instance was committed.'
    mocker.patch.object(Panorama, "http_request", side_effect=Exception(exception_msg))
    result = panorama_get_address("TEST")
    assert result == {}


def test_get_address_command(mocker):
    """
    Given:
     - an address_name argument which does not exist

    When:
     - running the panorama_get_address_command function

    Then:
     - Ensure the return value is None, without any errors, and return_results contains the correct informative message.
    """
    import Panorama
    from Panorama import panorama_get_address_command
    mocker.patch.object(Panorama, "panorama_get_address", return_value={})
    return_results_mock = mocker.patch.object(Panorama, 'return_results')
    result = panorama_get_address_command({'name': 'TEST'})
    assert not result
    assert return_results_mock.call_args[0][0] == 'Address name TEST was not found'


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


class TestQueryLogsCommand:

    @staticmethod
    def create_logs_query_queue(status_count, no_logs_found):

        response_queue = [
            MockedResponse(
                text='<response status="success" code="19"><result><msg><line>query '
                     'job enqueued with jobid 1</line></msg><job>1</job></result></response>',
                status_code=200
            )
        ]

        for _ in range(status_count):
            response_queue.append(
                MockedResponse(
                    text='<response status="success"><result><job><tenq>15:05:47</tenq><tdeq>15:05:47</tdeq><tlast>'
                         '01:00:00</tlast><status>ACT</status><id>1238</id></job><log><logs count="0" progress="20"/'
                         '></log></result></response>',
                    status_code=200
                )
            )

        if no_logs_found:
            # job has finished without finding any logs
            response_queue.append(
                MockedResponse(
                    text='<response status="success"><result><job><tenq>15:05:47</tenq><tdeq>15:05:47</tdeq><tlast>'
                         '15:06:52</tlast><status>FIN</status><id>1</id></job><log><logs count="0"'
                         ' progress="100"/></log></result></response>',
                    status_code=200
                )
            )

        else:

            with open('test_data/query_logs.xml') as f:
                # job has finished with finding logs
                response_queue.append(
                    MockedResponse(
                        text=f.read(),
                        status_code=200
                    )
                )

        return response_queue

    def test_query_logs_command_without_polling(self, mocker):
        """
        Given
        - an api response indicating a log query job has been created

        When
        - querying logs without polling

        Then
        - make sure polling is not triggered.
        - make sure context output indicates that the status of the job is 'Pending'
        """
        import Panorama
        import requests
        from Panorama import panorama_query_logs_command

        Panorama.API_KEY = 'thisisabogusAPIKEY!'
        mocker.patch.object(
            requests,
            'request',
            return_value=MockedResponse(
                text='<response status="success" code="19"><result><msg><line>query '
                     'job enqueued with jobid 1</line></msg><job>1</job></result></response>',
                status_code=200
            )
        )

        command_result = panorama_query_logs_command({'log-type': 'traffic', 'polling': 'false'})
        assert command_result.outputs == {
            'JobID': '1', 'Status': 'Pending', 'LogType': 'traffic', 'Message': 'query job enqueued with jobid 1'
        }
        assert not command_result.scheduled_command
        assert command_result.readable_output == '### Query Logs:\n|JobID|Status|\n|---|---|\n| 1 | Pending |\n'

    @pytest.mark.parametrize(
        'status_count, no_logs_found', [(1, False), (2, True), (3, False), (5, True), (8, False), (10, True)]
    )
    def test_query_logs_command_with_polling(self, mocker, status_count, no_logs_found):
        """
        Given
        - a queue of api responses
        - responses indicating query logs succeeded or not succeeded.
        - a status count which means how many times polling was done.

        When
        - querying logs with polling

        Then
        - make sure the readable output indicating polling is active is printed only once.
        - make sure context is returned only at the end of polling, and that the context is valid
          if there are logs available and if there aren't.
        """
        import Panorama
        import requests
        from Panorama import panorama_query_logs_command
        from CommonServerPython import ScheduledCommand

        Panorama.API_KEY = 'thisisabogusAPIKEY!'
        mocker.patch.object(
            requests,
            'request',
            side_effect=self.create_logs_query_queue(status_count=status_count, no_logs_found=no_logs_found)
        )
        mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

        command_result = panorama_query_logs_command({'log-type': 'traffic', 'polling': 'true'})
        assert command_result.readable_output == 'Fetching traffic logs for job ID 1...'
        assert not command_result.outputs  # no context should be returned until polling is done.

        polling_args = {
            'query_log_job_id': '1', 'hide_polling_output': True, 'polling': True, 'log-type': 'traffic'
        }

        command_result = panorama_query_logs_command(polling_args)
        while command_result.scheduled_command:  # if scheduled_command is set, it means that command should still poll
            assert not command_result.readable_output  # make sure that indication of polling is printed only once
            assert not command_result.outputs  # make sure no context output is being returned to war-room during polling
            command_result = panorama_query_logs_command(polling_args)

        if no_logs_found:
            assert command_result.outputs == {'JobID': '1', 'LogType': 'traffic', 'Logs': [], 'Status': 'Completed'}
        else:
            partial_expected_outputs = {'JobID': '1', 'LogType': 'traffic', 'Status': 'Completed'}
            assert partial_expected_outputs.items() <= command_result.outputs.items()
            assert 'Logs' in command_result.outputs
            assert command_result.outputs['Logs']  # make sure there are log outputs available.


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
    response = build_logs_query(None, None, None, None, None, None, None, None, None, urls_as_string, None, None)
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
    ('after', 'test_rule_name', ['user1'], '<source-user><member>user1</member></source-user>'),
    ('after', 'test_rule_name', ['user1,user2'], '<source-user><member>user1,user2</member></source-user>'),
]


@pytest.mark.parametrize('where, dst, source_user, expected_result', prepare_security_rule_inputs)
def test_prepare_security_rule_params(where, dst, source_user, expected_result):
    """
    Given:
     - valid arguments for the prepare_security_rule_params function

    When:
     - running the prepare_security_rule_params utility function

    Then:
     - a valid security rule dictionary is returned.
    """
    from Panorama import prepare_security_rule_params
    params = prepare_security_rule_params(api_action='set', action='drop', destination=['any'], source=['any'],
                                          rulename='test', where=where, dst=dst, source_user=source_user)
    assert expected_result in params.get('element', '')


prepare_security_rule_fail_inputs = [
    ('top', 'test_rule_name'),
    ('bottom', 'test_rule_name'),
]


@pytest.mark.parametrize('where, dst', prepare_security_rule_fail_inputs)
def test_prepare_security_rule_params_fail(where, dst):
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
    args = {'IPs': '1.1.1.1', 'tag': 'test_tag', 'persistent': 'false', 'timeout': '5'}

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
        expected_pretty_rule = json.load(f)

    pretty_rule = prettify_rule(rule)
    del pretty_rule['DeviceGroup']

    assert pretty_rule == expected_pretty_rule


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


class TestPanoramaListApplicationsCommand:

    @staticmethod
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

        mocker.patch(
            'Panorama.http_request', return_value=load_json('test_data/list_applications_response.json')
        )
        mocker.patch('Panorama.get_pan_os_major_version', return_value=panorama_version)

        res = mocker.patch('demistomock.results')
        panorama_list_applications_command({'predefined': 'false'})

        assert res.call_args.args[0]['Contents'] == {
            '@name': 'test-playbook-app', '@loc': 'Lab-Devices', 'subcategory': 'infrastructure',
            'category': 'networking',
            'technology': 'client-server', 'description': 'test-playbook-application-do-not-delete', 'risk': '1'
        }

    @staticmethod
    @pytest.mark.parametrize('panorama_version', [8, 9])
    def test_panorama_list_applications_command_main_flow(mocker, panorama_version):
        """
        Given
         - integrations parameters.
         - pan-os-list-applications command arguments including device_group

        When -
            running the pan-os-list-applications command through the main flow

        Then
         - make sure the context output is returned as expected.
         - make sure the device group gets overriden by the command arguments.
        """
        from Panorama import main

        mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
        mocker.patch.object(demisto, 'args', return_value={'predefined': 'false', 'device-group': 'new-device-group'})
        mocker.patch.object(demisto, 'command', return_value='pan-os-list-applications')

        request_mock = mocker.patch(
            'Panorama.http_request', return_value=load_json('test_data/list_applications_response.json')
        )
        mocker.patch('Panorama.get_pan_os_major_version', return_value=panorama_version)
        res = mocker.patch('demistomock.results')
        main()

        assert res.call_args.args[0]['Contents'] == {
            '@name': 'test-playbook-app', '@loc': 'Lab-Devices', 'subcategory': 'infrastructure',
            'category': 'networking',
            'technology': 'client-server', 'description': 'test-playbook-application-do-not-delete', 'risk': '1'
        }
        # make sure that device group is getting overriden by the device-group from command arguments.
        assert request_mock.call_args.kwargs['body'] == {
            'type': 'config', 'action': 'get',
            'key': 'thisisabogusAPIKEY!',
            'xpath': "/config/devices/entry/device-group/entry[@name='new-device-group']/application/entry"
        }


def test_get_security_profiles_command_main_flow(mocker):
    """
    Given
     - integrations parameters.
     - pan-os-get-security-profiles command arguments including device_group

    When -
        running the pan-os-get-security-profiles command through the main flow

    Then
     - make sure the context output is returned as expected.
     - make sure the device group gets overriden by the command arguments.
    """
    from Panorama import main

    mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
    mocker.patch.object(demisto, 'args', return_value={'device-group': 'new-device-group'})
    mocker.patch.object(demisto, 'command', return_value='pan-os-get-security-profiles')
    expected_security_profile_response = load_json('test_data/get_security_profiles_response.json')
    request_mock = mocker.patch(
        'Panorama.http_request', return_value=expected_security_profile_response
    )
    res = mocker.patch('demistomock.results')
    main()

    assert res.call_args.args[0]['Contents'] == expected_security_profile_response

    # make sure that device group is getting overriden by the device-group from command arguments.
    assert request_mock.call_args.kwargs['params'] == {
        'action': 'get', 'type': 'config',
        'xpath': "/config/devices/entry[@name='localhost.localdomain']"
                 "/device-group/entry[@name='new-device-group']/profiles",
        'key': 'thisisabogusAPIKEY!'
    }


def test_apply_security_profiles_command_main_flow(mocker):
    """
    Given
     - integrations parameters.
     - pan-os-apply-security-profile command arguments including device_group

    When -
        running the pan-os-apply-security-profile command through the main flow

    Then
     - make sure the context output is returned as expected.
     - make sure the device group gets overriden by the command arguments.
    """
    from Panorama import main

    mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'device-group': 'new-device-group',
            'profile_type': 'data-filtering',
            'profile_name': 'test-profile',
            'rule_name': 'rule-test',
            'pre_post': 'rule-test'
        }
    )
    mocker.patch.object(demisto, 'command', return_value='pan-os-apply-security-profile')
    request_mock = mocker.patch('Panorama.http_request')

    res = mocker.patch('demistomock.results')
    main()

    # make sure that device group is getting overriden by the device-group from command arguments.
    assert request_mock.call_args.kwargs['params'] == {
        'action': 'set', 'type': 'config',
        'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='new-device-group']"
                 "/rule-test/security/rules/entry[@name='rule-test']",
        'key': 'thisisabogusAPIKEY!', 'element': '<profile-setting><profiles><data-filtering>'
                                                 '<member>test-profile</member></data-filtering></profiles>'
                                                 '</profile-setting>'}
    assert res.call_args.args[0] == 'The profile data-filtering = test-profile has been applied to the rule rule-test'


def test_apply_security_profiles_command_when_one_already_exists(mocker):
    """
    Given
     - integrations parameters.
     - pan-os-apply-security-profile command arguments including device_group
     - same profile as already exists in the rule

    When -
        running the pan-os-apply-security-profile command through the main flow

    Then
     - Ensure the request is what's already in the API (the 'element' parameter contains all profiles in the XML)
    """
    from Panorama import main

    mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'device-group': 'new-device-group',
            'profile_type': 'spyware',
            'profile_name': 'strict',
            'rule_name': 'rule-test',
            'pre_post': 'rule-test'
        }
    )
    mocker.patch('Panorama.dict_safe_get', return_value={'virus': {'member': 'Tap'}, 'spyware': {'member': 'strict'}})
    mocker.patch.object(demisto, 'command', return_value='pan-os-apply-security-profile')
    request_mock = mocker.patch('Panorama.http_request')

    res = mocker.patch('demistomock.results')
    main()

    assert request_mock.call_args.kwargs['params'] == {
        'action': 'set', 'type': 'config',
        'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='new-device-group']"
                 "/rule-test/security/rules/entry[@name='rule-test']",
        'key': 'thisisabogusAPIKEY!',
        'element': '<profile-setting><profiles><spyware><member>strict</member></spyware>'
                   '<virus><member>Tap</member></virus></profiles></profile-setting>'}
    assert res.call_args.args[0] == 'The profile spyware = strict has been applied to the rule rule-test'


def test_remove_security_profiles_command(mocker):
    """
    Given
     - integrations parameters.
     - pan-os-remove-security-profile command arguments

    When -
        running the pan-os-remove-security-profile command through the main flow

    Then
     - Ensure the given profile type has been removed from the given rule
    """
    from Panorama import main

    mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'device-group': 'new-device-group',
            'profile_type': 'spyware',
            'rule_name': 'rule-test',
            'pre_post': 'rule-test'
        }
    )
    mocker.patch('Panorama.dict_safe_get', return_value={'virus': {'member': 'Tap'}, 'spyware': {'member': 'strict'}})
    mocker.patch.object(demisto, 'command', return_value='pan-os-remove-security-profile')
    request_mock = mocker.patch('Panorama.http_request')

    res = mocker.patch('demistomock.results')
    main()

    assert request_mock.call_args.kwargs['params'] == {
        'action': 'set', 'type': 'config',
        'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='new-device-group']"
                 "/rule-test/security/rules/entry[@name='rule-test']",
        'key': 'thisisabogusAPIKEY!',
        'element': '<profile-setting><profiles><virus><member>Tap</member></virus></profiles></profile-setting>'}
    assert res.call_args.args[0] == 'The profile spyware has been removed from the rule rule-test'


class TestPanoramaEditRuleCommand:
    EDIT_SUCCESS_RESPONSE = {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    EDIT_AUDIT_COMMENT_SUCCESS_RESPONSE = {
        'response': {'@status': 'success', 'result': 'Successfully added comment for xpath'}
    }

    @staticmethod
    @pytest.fixture()
    def reset_device_group():
        import Panorama
        Panorama.DEVICE_GROUP = ''

    @staticmethod
    def test_sanity(mocker, reset_device_group):
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
    def test_add_to_element_on_uncommited_rule(mocker, reset_device_group):
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
        Panorama.panorama_edit_rule_command(args)

    @staticmethod
    def test_edit_rule_to_disabled_flow(mocker, reset_device_group):
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

    @staticmethod
    def test_edit_rule_main_flow_disable_rule(mocker):
        """
        Given
         - panorama integrations parameters.
         - pan-os-edit-rule command arguments including device_group.
         - arguments to disable the rule

        When -
            running the pan-os-edit-rule command through the main flow

        Then
         - make sure the context output is returned as expected.
         - make sure the device group gets overriden by the command arguments.
        """
        from Panorama import main

        mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
        mocker.patch.object(
            demisto,
            'args',
            return_value={
                "rulename": "test",
                "element_to_change": "disabled",
                "element_value": "no",
                "behaviour": "replace",
                "pre_post": "pre-rulebase",
                "device-group": "new device group"
            }
        )
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-rule')
        request_mock = mocker.patch(
            'Panorama.http_request', return_value=TestPanoramaEditRuleCommand.EDIT_SUCCESS_RESPONSE
        )

        res = mocker.patch('demistomock.results')
        main()

        # make sure that device group is getting overriden by the device-group from command arguments.
        assert request_mock.call_args.kwargs['body'] == {
            'type': 'config', 'action': 'edit', 'key': 'thisisabogusAPIKEY!',
            'element': '<disabled>no</disabled>',
            'xpath': "/config/devices/entry/device-group/entry[@name='new device group']/pre-rulebase"
                     "/security/rules/entry[@name='test']/disabled"
        }
        assert res.call_args.args[0]['Contents'] == {
            'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}
        }

    @staticmethod
    def test_edit_rule_main_flow_update_audit_comment(mocker):
        """
        Given
         - panorama integrations parameters.
         - pan-os-edit-rule command arguments including device_group.
         - arguments to edit audit comment of a rule

        When -
            running the pan-os-edit-rule command through the main flow

        Then
         - make sure the context output is returned as expected.
         - make sure the device group gets overriden by the command arguments.
        """
        from Panorama import main

        mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
        mocker.patch.object(
            demisto,
            'args',
            return_value={
                "rulename": "test",
                "element_to_change": "audit-comment",
                "element_value": "some string",
                "behaviour": "replace",
                "pre_post": "pre-rulebase",
                "device-group": "new device group"
            }
        )
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-rule')
        request_mock = mocker.patch(
            'Panorama.http_request', return_value=TestPanoramaEditRuleCommand.EDIT_AUDIT_COMMENT_SUCCESS_RESPONSE
        )

        res = mocker.patch('demistomock.results')
        main()

        # make sure that device group is getting overriden by the device-group from command arguments.
        assert request_mock.call_args.kwargs['body'] == {
            'type': 'op',
            'cmd': "<set><audit-comment><xpath>/config/devices/entry[@name='localhost.localdomain']/device-group"
                   "/entry[@name='new device group']/pre-rulebase/security/rules/entry[@name='test']"
                   "</xpath><comment>some string</comment></audit-comment></set>",
            'key': 'thisisabogusAPIKEY!'
        }
        assert res.call_args.args[0]['Contents'] == TestPanoramaEditRuleCommand.EDIT_AUDIT_COMMENT_SUCCESS_RESPONSE

    @staticmethod
    def test_edit_rule_main_flow_remove_profile_setting_group(mocker):
        """
        Given
         - panorama integrations parameters.
         - pan-os-edit-rule command arguments including device_group.
         - arguments to remove a profile-setting group.
        When
         - running the pan-os-edit-rule command through the main flow.

        Then
         - make sure the API request body is correct.
         - make sure the message is correct for the user.
        """
        from Panorama import main

        mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
        mocker.patch.object(
            demisto,
            'args',
            return_value={
                "rulename": "test",
                "element_to_change": "profile-setting",
                "element_value": "some string",
                "behaviour": "remove",
                "pre_post": "pre-rulebase",
                "device-group": "new device group"
            }
        )
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-rule')
        request_mock = mocker.patch(
            'Panorama.http_request', return_value=TestPanoramaEditRuleCommand.EDIT_AUDIT_COMMENT_SUCCESS_RESPONSE
        )

        res = mocker.patch('demistomock.results')
        main()

        # Check: 'action' == set (not edit)
        assert request_mock.call_args.kwargs['body']['action'] == 'set'
        # Ensure 'element' wasn't sent with a group (since we removed the profile-setting group)
        assert request_mock.call_args.kwargs['body']['element'] == '<profile-setting><group/></profile-setting>'
        # Make sure the message is correct for the user
        assert res.call_args.args[0]['HumanReadable'] == 'Rule edited successfully.'


def test_panorama_edit_address_group_command_main_flow_edit_description(mocker):
    """
    Given
     - integrations parameters.
     - pan-os-edit-address-group command arguments including device_group and description to add.

    When -
        running the pan-os-edit-address-group command through the main flow

    Then
     - make sure the context output is returned as expected.
     - make sure the device group gets overriden by the command arguments.
    """
    from Panorama import main

    mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
    mocker.patch.object(
        demisto,
        'args',
        return_value={'name': 'test', 'description': 'test', 'match': '1.1.1.1', 'device-group': 'new device group'}
    )
    mocker.patch.object(demisto, 'command', return_value='pan-os-edit-address-group')
    request_mock = mocker.patch(
        'Panorama.http_request',
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )

    res = mocker.patch('demistomock.results')
    main()

    # make sure that device group is getting overriden by the device-group from command arguments.
    assert request_mock.call_args.kwargs['body'] == {
        'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!',
        'xpath': "/config/devices/entry/device-group/entry[@name='new device group']"
                 "/address-group/entry[@name='test']/description", 'element': '<description>test</description>'
    }
    assert res.call_args.args[0]['Contents'] == {
        'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}
    }
    assert res.call_args.args[0]['HumanReadable'] == 'Address Group test was edited successfully.'


def test_panorama_edit_address_group_command_remove_single_address(mocker):
    """
    Given
     - pan-os-edit-address-group command arguments including a single address to remove.

    When
     - running the pan-os-edit-address-group command through the main flow

    Then
     - make sure an exception is raised because address group must always have at least one address.
    """
    import Panorama

    Panorama.DEVICE_GROUP = integration_panorama_params['device_group']

    mocker.patch(
        'Panorama.http_request',
        return_value={
            'response': {
                '@status': 'success', 'result': {
                    'entry': {
                        '@name': 'test5',
                        'static': {'member': ['5.5.5.5']},
                        'description': 'dfdf'
                    }
                }
            }
        }
    )

    with pytest.raises(DemistoException) as exc_info:
        Panorama.panorama_edit_address_group_command(
            {'name': 'test', 'device-group': 'Shared', 'type': 'static', 'element_to_remove': '5.5.5.5'}
        )

    assert exc_info.type == DemistoException
    assert exc_info.value.message == "cannot remove ['5.5.5.5'] addresses from address group test, " \
                                     "address-group test must have at least one address in its configuration"


@pytest.mark.parametrize(
    'action, existing_url_categories_mock, category', [
        (
            'add',
            {'list': {'member': []}},
            'category1'
        ),
        (
            'remove',
            {'list': {'member': ['category2']}},
            'category2'
        )
    ]
)
def test_panorama_edit_custom_url_category_command_main_flow(mocker, action, existing_url_categories_mock, category):
    """
    Given
     - integrations parameters.
     - pan-os-edit-custom-url-category command arguments: categories, device-group and action.

    When -
        running the pan-os-edit-custom-url-category command through the main flow

    Then
     - make sure the context output is returned as expected.
     - make sure the device group gets overriden by the command arguments.
    """
    from Panorama import main

    mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
    mocker.patch.object(
        demisto,
        'args',
        return_value={'name': 'test', 'action': action, 'categories': ['category1'], 'device-group': 'new device group'}
    )
    mocker.patch.object(demisto, 'command', return_value='pan-os-edit-custom-url-category')
    request_mock = mocker.patch(
        'Panorama.http_request',
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )
    mocker.patch('Panorama.panorama_get_custom_url_category', return_value=existing_url_categories_mock)
    mocker.patch('Panorama.get_pan_os_major_version', return_value=9)

    res = mocker.patch('demistomock.results')
    main()

    expected_body_request = {
        'action': 'edit', 'type': 'config',
        'xpath': "/config/devices/entry/device-group/entry[@name='new device group']/profiles/custom-url-category"
                 "/entry[@name='test']",
        'element': f"<entry name='test'><list><member>{category}<"
                   f"/member></list><type>Category Match</type></entry>",
        'key': 'thisisabogusAPIKEY!'
    }

    # make sure that device group is getting overriden by the device-group from command arguments.
    assert request_mock.call_args.kwargs['body'] == expected_body_request
    assert res.call_args.args[0]['Contents'] == {
        'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}
    }


def test_panorama_edit_custom_url_category_command_main_flow_with_sites(mocker):
    """
    Given
     - integrations parameters.
     - pan-os-edit-custom-url-category command arguments: sites, device-group and action = 'add'.

    When -
        running the pan-os-edit-custom-url-category command through the main flow

    Then
     - make sure the context output is returned as expected.
     - make sure the sites are being HTML escaped correctly for the site.
     - make sure the device group gets overriden by the command arguments.
    """
    from Panorama import main

    existing_url_categories_mock = {'list': {'member': []}}
    expected_site = 'example.com/?a=b&amp;c=d'

    mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'name': 'test', 'action': 'add', 'sites': ['example.com/?a=b&c=d'], 'device-group': 'new device group'
        }
    )
    mocker.patch.object(demisto, 'command', return_value='pan-os-edit-custom-url-category')
    request_mock = mocker.patch(
        'Panorama.http_request',
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )
    mocker.patch('Panorama.panorama_get_custom_url_category', return_value=existing_url_categories_mock)
    mocker.patch('Panorama.get_pan_os_major_version', return_value=9)

    res = mocker.patch('demistomock.results')
    main()

    expected_body_request = {
        'action': 'edit',
        'element': '<entry '
                   f"name='test'><list><member>{expected_site}</member></list><type>URL "
                   'List</type></entry>',
        'key': 'thisisabogusAPIKEY!',
        'type': 'config',
        'xpath': "/config/devices/entry/device-group/entry[@name='new device "
                 "group']/profiles/custom-url-category/entry[@name='test']"
    }
    # make sure that device group is getting overriden by the device-group from command arguments.
    assert request_mock.call_args.kwargs['body'] == expected_body_request
    assert res.call_args.args[0]['Contents'] == {
        'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}
    }


def test_panorama_list_edls_command_main_flow(mocker):
    """
    Given
     - integrations parameters.
     - EDLs from panorama (including un-committed).

    When -
        running the pan-os-list-edls command through the main flow.

    Then
     - make sure the context output is returned as expected.
     - make sure the http request was sent as expected.
    """
    from Panorama import main

    mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'command', return_value='pan-os-list-edls')
    request_mock = mocker.patch(
        'Panorama.http_request',
        return_value=load_json('test_data/list-edls-including-un-committed-edl.json')
    )

    result = mocker.patch('demistomock.results')
    main()

    assert request_mock.call_args.kwargs['params'] == {
        'action': 'get', 'type': 'config',
        'xpath': "/config/devices/entry/device-group/entry[@name='Lab-Devices']/external-list/entry",
        'key': 'thisisabogusAPIKEY!'
    }

    assert list(result.call_args.args[0]['EntryContext'].values())[0] == [
        {
            'Name': 'test-1', 'Type': 'domain', 'URL': 'http://test.com',
            'Recurring': 'hourly', 'DeviceGroup': 'Lab-Devices'
        },
        {
            'Name': 'test-2', 'Type': 'ip', 'URL': 'http://test1.com',
            'Recurring': 'five-minute', 'DeviceGroup': 'Lab-Devices'
        }
    ]


def test_panorama_edit_edl_command_main_flow(mocker):
    """
    Given
     - integrations parameters.
     - pan-os-edit-edl command arguments including device_group

    When -
        running the pan-os-edit-edl command through the main flow

    Then
     - make sure the context output is returned as expected.
     - make sure the device group gets overriden by the command arguments.
    """
    from Panorama import main

    mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'name': 'test', 'element_to_change': 'description',
            'element_value': 'edl1', 'device-group': 'new device group'
        }
    )
    mocker.patch.object(demisto, 'command', return_value='pan-os-edit-edl')
    mocker.patch('Panorama.panorama_get_edl', return_value={'type': {'test': 'test'}})
    request_mock = mocker.patch(
        'Panorama.http_request',
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )

    res = mocker.patch('demistomock.results')
    main()

    # make sure that device group is getting overriden by the device-group from command arguments.
    assert request_mock.call_args.kwargs['body'] == {
        'action': 'edit',
        'type': 'config',
        'key': 'thisisabogusAPIKEY!',
        'xpath': "/config/devices/entry/device-group/entry[@name='new device group']/external-list/ent"
                 "ry[@name='test']/type/test/description",
        'element': '<description>edl1</description>'
    }
    assert res.call_args.args[0]['Contents'] == {
        'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}
    }


def test_panorama_edit_service_group_command_main_flow(mocker):
    """
    Given
     - integrations parameters.
     - pan-os-edit-service-group command arguments including device_group

    When -
        running the pan-os-edit-service-group command through the main flow

    Then
     - make sure the context output is returned as expected.
     - make sure the device group gets overriden by the command arguments.
    """
    from Panorama import main

    mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
    mocker.patch.object(
        demisto,
        'args',
        return_value={'name': 'test', 'tag': 'tag1', 'device-group': 'new device group'}
    )
    mocker.patch.object(demisto, 'command', return_value='pan-os-edit-service-group')
    request_mock = mocker.patch(
        'Panorama.http_request',
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )

    res = mocker.patch('demistomock.results')
    main()

    # make sure that device group is getting overriden by the device-group from command arguments.
    assert request_mock.call_args.kwargs['body'] == {
        'action': 'edit',
        'type': 'config',
        'xpath': "/config/devices/entry/device-group/entry[@name='new device group']/"
                 "service-group/entry[@name='test']/tag",
        'element': '<tag><member>tag1</member></tag>', 'key': 'thisisabogusAPIKEY!'
    }

    assert res.call_args.args[0]['Contents'] == {
        'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}
    }


def test_panorama_edit_url_filter_command_main_flow(mocker):
    """
    Given
     - integrations parameters.
     - pan-os-edit-url-filter command arguments including device_group

    When -
        running the pan-os-edit-url-filter command through the main flow

    Then
     - make sure the context output is returned as expected.
     - make sure the device group gets overriden by the command arguments.
    """
    from Panorama import main

    mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
    mocker.patch.object(
        demisto,
        'args',
        return_value={'name': 'test', 'element_to_change': 'description', 'device-group': 'new device group'}
    )
    mocker.patch.object(demisto, 'command', return_value='pan-os-edit-url-filter')
    request_mock = mocker.patch(
        'Panorama.http_request',
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )
    mocker.patch('Panorama.panorama_get_url_filter', return_value={})
    mocker.patch('Panorama.get_pan_os_major_version', return_value=9)

    res = mocker.patch('demistomock.results')
    main()

    # make sure that device group is getting overriden by the device-group from command arguments.
    assert request_mock.call_args.kwargs['body'] == {
        'action': 'edit',
        'type': 'config',
        'key': 'thisisabogusAPIKEY!',
        'xpath': "/config/devices/entry/device-group/entry[@name='new device group']"
                 "/profiles/url-filtering/entry[@name='test']/description",
        'element': '<description>None</description>'
    }

    assert res.call_args.args[0]['Contents'] == {
        'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}
    }


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
               'name="some_device"/></device-group><description>a simple commit</description><partial><admin>'
               '<member>some_admin_name</member></admin></partial></commit>',
        'key': 'APIKEY',
        'type': 'commit'
    }

    @staticmethod
    def create_mock_responses(job_commit_status_count):
        mocked_responses = [  # panorama commit api response mock
            MockedResponse(
                text='<response status="success" code="19"><result><msg><line>Commit job '
                     'enqueued with jobid 123</line></msg><job>123</job></result></response>',
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
                                                   'name="some_device"/></device-group><description>a simple commit</description>'
                                                   '<partial><admin>'
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
                                                   '</device-group><force></force></commit>',
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
                                                   'device-and-network></partial></commit>',
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
                text='<response status="success" code="19"><result><msg><line>Push job '
                     'enqueued with jobid 123</line></msg><job>123</job></result></response>',
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

        with open('test_data/push_to_device_success.xml') as data_file:
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
            - pan-os-push-to-device-group command arguments including device-group.
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
            - make sure the device-group from argument overrides the device-group from parameter in context.
        """
        import requests
        import Panorama
        from Panorama import panorama_push_to_device_group_command
        from CommonServerPython import ScheduledCommand

        args = {
            'description': 'a simple push',
            'polling': 'true',
            'device-group': 'device-group-from-command-arg'
        }

        # mimcs the piece of code which decides which device-group will be set into DEVICE_GROUP parameter.
        Panorama.DEVICE_GROUP = args.get('device-group') or 'device-group-from-integration-params'

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
        assert command_result.outputs.get('DeviceGroup') == 'device-group-from-command-arg'
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
    assert return_results_mock.call_args[0][0][1].readable_output == 'URL Node can be at most 1278 characters.'


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
        with open('test_data/devices_list.xml') as data_file:
            requests_mock.get(Panorama.URL, text=data_file.read())
        Panorama.VSYS = None  # this a Panorama instance
        assert list(Panorama.devices(targets=['target1'])) == [('target1', 'vsys1'), ('target1', 'vsys2')]

    def test_without_specify(self, requests_mock):
        import Panorama
        with open('test_data/devices_list.xml') as data_file:
            requests_mock.get(Panorama.URL, text=data_file.read())
        Panorama.VSYS = None  # this a Panorama instance
        assert list(Panorama.devices()) == [('target1', 'vsys1'), ('target1', 'vsys2'), ('target2', None)]


def load_xml_root_from_test_file(xml_file: str):
    """Given an XML file, loads it and returns the root element XML object."""
    return ElementTree.parse(xml_file).getroot()


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
        MOCK_PANORAMA_SERIAL: "1.1.1.1",
        MOCK_FIREWALL_1_SERIAL: MOCK_FIREWALL_2_SERIAL,
    }
    return topology


@pytest.fixture
def mock_firewall_topology(mock_firewall):
    from Panorama import Topology
    topology = Topology()
    topology.firewall_objects = {
        MOCK_FIREWALL_1_SERIAL: mock_firewall
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
    SHOW_HA_STATE_PANORAMA_ENABLED = "test_data/show_ha_state_panorama_enabled.xml"
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

    @patch("Panorama.Topology.get_all_child_firewalls")
    @patch("Panorama.run_op_command")
    def test_add_panorama_device_object_with_ha(self, patched_run_op_command, _, mock_panorama):
        """
        Given a Panorama where High availability is active, test that it is correctly added to the topology.
        """
        from Panorama import Topology
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestTopology.SHOW_HA_STATE_PANORAMA_ENABLED)
        topology = Topology()
        topology.add_device_object(mock_panorama)

        assert MOCK_PANORAMA_SERIAL in topology.panorama_objects
        assert MOCK_PANORAMA_SERIAL in topology.ha_active_devices
        assert MOCK_PANORAMA_SERIAL in topology.ha_pair_serials
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
        assert len(result) == 3
        assert result[0].name
        assert result[0].hostid
        assert result[0].connected
        assert result[0].serial
        assert result[0].last_commit_all_state_sp
        # Support for missing hostname
        assert not result[2].hostname

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

    @patch("Panorama.run_op_command")
    def test_get_template_stacks_without_hostname(self, patched_run_op_command, mock_topology):
        """Given the output XML for show template-stacks without hostname, assert it is parsed into the dataclasses correctly."""
        from Panorama import PanoramaCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file("test_data/show_template_stack_without_hostname.xml")
        result = PanoramaCommand.get_template_stacks(mock_topology)
        assert len(result) == 2
        assert result[0].name
        assert not result[0].hostname
        assert result[0].hostid
        assert result[0].connected
        assert result[0].serial
        assert result[0].last_commit_all_state_tpl


class TestUniversalCommand:
    """Test all the commands relevant to both Panorama and Firewall devices"""
    SHOW_SYSTEM_INFO_XML = "test_data/show_system_info.xml"
    SHOW_JOB_XML = "test_data/show_jobs_all.xml"
    SHOW_COMMIT_JOB_XML = "test_data/show_commit_jobs_all.xml"
    SHOW_JOB_WITH_FAILED_XML = "test_data/show_jobs_with_failed.xml"

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
                if key not in ["description", "user", "details", "warnings"]:
                    assert value

    @patch("Panorama.run_op_command")
    @patch("Panorama.demisto.debug")
    def test_get_jobs_with_failed(self, patched_debug, patched_run_op_command):
        """Given the output XML for show jobs with a failed job, assert it is skipped."""
        from Panorama import UniversalCommand, ShowJobsAllResultData, Panorama

        patched_run_op_command.return_value = load_xml_root_from_test_file(TestUniversalCommand.SHOW_JOB_WITH_FAILED_XML)
        MockTopology = type('MockTopology', (), {'all': lambda *x, **y: [Panorama(hostname='123')]})

        result = UniversalCommand.show_jobs(MockTopology())

        assert patched_debug.call_args_list[0].args[0] == (
            '\'ShowJobsAllResultData\' cannot be instantiated with element: '
            '{"job": {"type": "Failed-Job", "details": {"line": "job failed because of configd restart"}, "warnings": null}}'
            '\nerror=TypeError("ShowJobsAllResultData.__init__() missing 9 required positional arguments: '
            "'id', 'tfin', 'status', 'result', 'user', 'tenq', 'stoppable', 'positionInQ', and 'progress'\")")
        assert isinstance(result, ShowJobsAllResultData)
        assert result.__dict__ == {
            'description': 'description',
            'hostid': '123',
            'id': 7,
            'positionInQ': '0',
            'progress': '100',
            'result': 'OK',
            'status': 'FIN',
            'stoppable': 'no',
            'tenq': '2024/08/25 22:07:53',
            'tfin': '2024/08/25 22:09:00',
            'type': 'Job Type',
            'user': None,
            'warnings': None
        }

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
    SHOW_HA_PANORAMA_STATE_XML = "test_data/show_ha_state_panorama_enabled.xml"

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
    def test_get_ha_status_firewall(self, patched_run_op_command, mock_firewall_topology):
        """
        Given the XML output for a HA firewall which is enabled, ensure the data class is parsed correctly
        """
        from Panorama import FirewallCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(TestFirewallCommand.SHOW_HA_STATE_XML)
        result = FirewallCommand.get_ha_status(mock_firewall_topology)

        assert result.status != 'HA Not enabled.'
        assert result.active is not None
        assert result.hostid is not None
        assert result.peer is not None

    @patch("Panorama.run_op_command")
    def test_get_ha_status_panorama(self, patched_run_op_command, mock_topology):
        """Given the XML output for a HA firewall, ensure the dataclasses are parsed correctly"""
        from Panorama import FirewallCommand
        patched_run_op_command.return_value = load_xml_root_from_test_file(
            TestFirewallCommand.SHOW_HA_PANORAMA_STATE_XML)
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
                                                      '<sinkhole><ipv4-address>pan-sinkhole-default-ip</ipv4-address>'
                                                      '<ipv6-address>::1</ipv6-address></sinkhole>'
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


def test_panorama_apply_dns_command2(mocker):
    """
    Given:
        - command args with a singel firewall
    When:
        - Running panorama-apply-dns
    Then:
        - Assert the request parameters are as expected
    """
    import Panorama
    from Panorama import apply_dns_signature_policy_command

    Panorama.API_KEY = 'fakeAPIKEY!'
    Panorama.DEVICE_GROUP = 'fakeDeviceGroup'
    request_mock = mocker.patch.object(Panorama, 'http_request', return_value={})
    apply_dns_signature_policy_command({'anti_spyware_profile_name': 'fake_profile_name'})

    request_params = request_mock.call_args.kwargs['params']  # The body part of the request
    assert request_params.get(
        'xpath') == "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='fakeDeviceGroup']/profiles/spyware/entry[@name='fake_profile_name']"  # noqa


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
                                 None, ),
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
    created_file = pan_os_get_running_config({"target": "SOME_SERIAL_NUMBER", "filename": "running_config"})
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


class TestPanOSListTemplatesCommand:

    def test_pan_os_list_templates_main_flow(self, mocker):
        """
        Given:
         - Panorama instance configuration.

        When:
         - running the pan-os-list-templates through the main flow.

        Then:
         - make sure the context output is parsed correctly.
         - make sure the xpath and the request is correct.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request", return_value=load_json('test_data/list_templates_including_uncommitted.json')
        )
        mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
        mocker.patch.object(demisto, 'args', return_value={})
        mocker.patch.object(demisto, 'command', return_value='pan-os-list-templates')
        result = mocker.patch('demistomock.results')

        main()

        assert list(result.call_args.args[0]['EntryContext'].values())[0] == [
            {
                'Name': 'test-1', 'Description': None,
                'Variable': [
                    {'Name': None, 'Type': None, 'Value': None, 'Description': None},
                    {'Name': None, 'Type': None, 'Value': None, 'Description': None}
                ]
            },
            {
                'Name': 'test-2', 'Description': 'just a test description',
                'Variable': [
                    {
                        'Name': '$variable-1', 'Type': 'ip-netmask',
                        'Value': '1.1.1.1', 'Description': 'description for $variable-1'
                    }
                ]
            }
        ]

        assert mock_request.call_args.kwargs['params'] == {
            'type': 'config', 'action': 'get', 'key': 'thisisabogusAPIKEY!',
            'xpath': "/config/devices/entry[@name='localhost.localdomain']/template"
        }

    def test_pan_os_list_templates_main_flow_firewall_instance(self):
        """
        Given:
         - Firewall instance configuration.

        When:
         - running the pan_os_list_templates_command function.

        Then:
         - make sure an exception is raised because hte pan-os-list-templates can run only on Panorama instances.
        """
        from Panorama import pan_os_list_templates_command
        import Panorama

        Panorama.VSYS = 'vsys'  # VSYS are only firewall instances
        Panorama.DEVICE_GROUP = ''  # device-groups are only panorama instances.
        with pytest.raises(DemistoException):
            pan_os_list_templates_command({})


class TestPanOSListNatRulesCommand:

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {'pre_post': 'pre-rulebase', 'show_uncommitted': 'false'},
                integration_panorama_params,
                {
                    'type': 'config', 'action': 'show', 'key': 'thisisabogusAPIKEY!',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']"
                             "/device-group/entry[@name='Lab-Devices']/pre-rulebase/nat"
                }
            ),
            pytest.param(
                {'show_uncommitted': 'false'},
                integration_firewall_params,
                {
                    'action': 'show',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']"
                             "/vsys/entry[@name='vsys1']/rulebase/nat"
                }
            ),
            pytest.param(
                {'pre_post': 'pre-rulebase', 'show_uncommitted': 'true', 'name': 'test'},
                integration_panorama_params,
                {
                    'action': 'get',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/nat/rules/entry[@name='test']"
                }
            ),
            pytest.param(
                {'show_uncommitted': 'true', 'name': 'test'},
                integration_firewall_params,
                {
                    'action': 'get',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
                             "/rulebase/nat/rules/entry[@name='test']"
                }
            )
        ]
    )
    def test_pan_os_list_rules_command_main_flow(self, mocker, args, params, expected_url_params):
        """
        Given:
         - Panorama instance configuration.
         - Firewall instance configuration.
         - Panorama instance configuration to get a specific nat-rule.
         - Firewall instance configuration to get a specific nat-rule.

        When:
         - running the pan-os-list-nat-rules through the main flow.

        Then:
         - make sure the context output is parsed correctly.
         - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        expected_context = [
            {
                'Name': 'test', 'Tags': 'test tag', 'SourceZone': '1.1.1.1', 'DestinationZone': '1.1.1.1',
                'SourceAddress': 'any', 'DestinationAddress': 'any', 'DestinationInterface': None,
                'Service': 'any', 'Description': None, 'SourceTranslation': None, 'DynamicDestinationTranslation': None,
                'DestinationTranslation': None, 'Disabled': 'yes'
            },
            {
                'Name': 'test-2', 'Tags': None, 'SourceZone': '2.2.2.2', 'DestinationZone': '2.2.2.2',
                'SourceAddress': 'any', 'DestinationAddress': 'any', 'DestinationInterface': None,
                'Service': 'any', 'Description': None, 'SourceTranslation': None, 'DynamicDestinationTranslation': None,
                'DestinationTranslation': None, 'Disabled': 'no'
            }
        ]

        mock_request = mocker.patch(
            "Panorama.http_request", return_value=load_json('test_data/list-nat-rules-response.json')
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-list-nat-rules')
        result = mocker.patch('demistomock.results')

        main()

        assert list(result.call_args.args[0]['EntryContext'].values())[0] == expected_context
        assert mock_request.call_args.kwargs['params'] == expected_url_params


class TestCreatePanOSNatRuleCommand:
    CREATE_NAT_RULE = {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'rulename': 'test',
                    'description': 'test',
                    'pre_post': 'pre-rulebase',
                    'source_translation_type': 'static-ip',
                    'source_translated_address': '1.1.1.1',
                    'source_translated_address_type': 'translated-address',
                    'destination_translation_type': 'none'
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group"
                             "/entry[@name='Lab-Devices']/pre-rulebase/nat/rules/entry[@name='test']",
                    'element': '<source-translation><static-ip><translated-address>1.1.1.1<'
                               '/translated-address></static-ip></source-translation><description>test</description>',
                    'action': 'set', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'rulename': 'test',
                    'description': 'test',
                    'source_translation_type': 'static-ip',
                    'source_translated_address': '1.1.1.1',
                    'source_translated_address_type': 'translated-address',
                    'destination_translation_type': 'none'
                },
                integration_firewall_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/"
                             "entry[@name='vsys1']/rulebase/nat/rules/entry[@name='test']",
                    'element': '<source-translation><static-ip><translated-address>1.1.1.1<'
                               '/translated-address></static-ip></source-translation><description>test</description>',
                    'action': 'set', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'rulename': 'test',
                    'description': 'test',
                    'destination_zone': '1.1.1.1',
                    'source_zone': '2.2.2.2',
                    'pre_post': 'pre-rulebase',
                    'source_address': '1.1.1.1,2.2.2.2',
                    'source_translation_type': 'dynamic-ip',
                    'source_translated_address_type': 'translated-address',
                    'source_translated_address': '1.1.1.1,2.2.2.2',
                    'destination_translation_type': 'none',
                    'audit_comment': 'test comment',
                },
                integration_panorama_params,
                {
                    'action': 'set',
                    'element': '<source-translation><dynamic-ip><translated-address><member>1.1.1.1</member>'
                               '<member>2.2.2.2</member></translated-address></dynamic-ip></source-translation><to>'
                               '<member>1.1.1.1</member></to><from><member>2.2.2.2</member></from><source><member>'
                               '1.1.1.1</member><member>2.2.2.2</member></source><description>test</description>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/nat/rules/entry[@name='test']",
                    'audit-comment': 'test comment',
                }
            ),
            pytest.param(
                {
                    'rulename': 'test',
                    'description': 'test',
                    'destination_zone': '1.1.1.1',
                    'source_zone': '2.2.2.2',
                    'source_address': '1.1.1.1,2.2.2.2',
                    'source_translation_type': 'dynamic-ip',
                    'source_translated_address_type': 'translated-address',
                    'source_translated_address': '1.1.1.1,2.2.2.2',
                    'destination_translation_type': 'none',
                    'audit_comment': 'test comment',
                },
                integration_firewall_params,
                {
                    'action': 'set',
                    'element': '<source-translation><dynamic-ip><translated-address><member>1.1.1.1</member>'
                               '<member>2.2.2.2</member></translated-address></dynamic-ip></source-translation><to>'
                               '<member>1.1.1.1</member></to><from><member>2.2.2.2</member></from><source>'
                               '<member>1.1.1.1</member><member>2.2.2.2</'
                               'member></source><description>test</description>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/"
                             "entry[@name='vsys1']/rulebase/nat/rules/entry[@name='test']",
                    'audit-comment': 'test comment',
                }
            ),
        ]
    )
    def test_pan_os_create_nat_rule_command_main_flow(self, mocker, args, params, expected_url_params):
        """
        Given:
         - Panorama instance configuration with source_translation_type, source_translated_address
            and source_translated_address_type
         - Firewall instance configuration with source_translation_type, source_translated_address
            and source_translated_address_type
         - Panorama instance configuration with basic parameter configurations along with dynamic-ip
         - firewall instance configuration with basic parameter configurations along with dynamic-ip

        When:
         - running the pan-os-create-nat-rule through the main flow.

        Then:
         - make sure the xpath/element and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-create-nat-rule')

        main()
        assert mock_request.call_args.kwargs['params'] == expected_url_params


@pytest.mark.parametrize(
    'args, params, expected_url_params',
    [
        pytest.param(
            {
                'rulename': 'test',
                'pre_post': 'pre-rulebase'
            },
            integration_panorama_params,
            {
                'action': 'delete',
                'key': 'thisisabogusAPIKEY!',
                'type': 'config',
                'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                         "[@name='Lab-Devices']/pre-rulebase/nat/rules/entry[@name='test']"
            }
        ),
        pytest.param(
            {
                'rulename': 'test'
            },
            integration_firewall_params,
            {
                'action': 'delete',
                'key': 'thisisabogusAPIKEY!',
                'type': 'config',
                'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry"
                         "[@name='vsys1']/rulebase/nat/rules/entry[@name='test']"
            }
        )
    ]
)
def test_pan_os_delete_nat_rule_command_main_flow(mocker, args, params, expected_url_params):
    """
    Given:
     - Panorama instance configuration with a specific rulename.
     - Firewall instance configuration with a specific rulename.

    When:
     - running the pan-os-delete-nat-rule through the main flow.

    Then:
     - make sure the xpath/element and the request is correct for both panorama/firewall.
    """
    from Panorama import main

    mock_request = mocker.patch(
        "Panorama.http_request",
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'command', return_value='pan-os-delete-nat-rule')

    main()
    assert mock_request.call_args.kwargs['params'] == expected_url_params


class TestPanOSEditNatRule:

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'rulename': 'test',
                    'pre_post': 'pre-rulebase',
                    'element_to_change': 'source_translation_dynamic_ip',
                    'behavior': 'replace',
                    'element_value': '1.1.1.1,2.2.2.2'
                },
                integration_panorama_params,
                {
                    'action': 'edit',
                    'element': '<translated-address><member>1.1.1.1</member>'
                               '<member>2.2.2.2</member></translated-address>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry["
                             "@name='Lab-Devices']/pre-rulebase/nat/rules/entry[@name='test']/source-translation"
                             "/dynamic-ip/translated-address"
                }
            ),
            pytest.param(
                {
                    'rulename': 'test',
                    'element_to_change': 'source_zone',
                    'behavior': 'replace',
                    'element_value': '1.1.1.1'
                },
                integration_firewall_params,
                {
                    'action': 'edit',
                    'element': '<from><member>1.1.1.1</member></from>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
                             "/rulebase/nat/rules/entry[@name='test']/from"
                }
            ),
            pytest.param(
                {
                    'rulename': 'test',
                    'pre_post': 'pre-rulebase',
                    'element_to_change': 'destination_translation_dynamic_distribution_method',
                    'behavior': 'replace',
                    'element_value': 'Round Robin'
                },
                integration_panorama_params,
                {
                    'action': 'edit',
                    'element': '<distribution>Round Robin</distribution>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/nat/rules/entry[@name='test']/"
                             "dynamic-destination-translation/distribution"
                }
            ),
            pytest.param(
                {
                    'rulename': 'test',
                    'element_to_change': 'source_translation_static_ip',
                    'behavior': 'replace',
                    'element_value': '1.1.1.1'
                },
                integration_firewall_params,
                {
                    'action': 'edit',
                    'element': '<translated-address>1.1.1.1</translated-address>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/"
                             "nat/rules/entry[@name='test']/source-translation/static-ip/translated-address"
                }
            ),
        ]
    )
    def test_pan_os_nat_rule_replace_action_main_flow(self, mocker, args, params, expected_url_params):
        """
        Given
         - Panorama instance when replacing source_translation_dynamic_ip to a new value
         - Firewall instance when replacing source_zone to a new value.
         - Panorama instance when replacing destination_translation_dynamic_distribution_method to a new value.
         - Firewall instance when replacing source_translation_static_ip to a new value.

        When
         - running the pan-os-edit-nat-rule through the main flow.

        Then
         - make sure the xpath/element and the request is correct for both panorama/firewall.
        """
        from Panorama import main
        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-nat-rule')

        main()
        assert mock_request.call_args.kwargs['params'] == expected_url_params

    @pytest.mark.parametrize('nat_rule_object', ['destination_translation_ip', 'destination_interface', 'nat_type'])
    def test_pan_os_add_or_remove_un_listable_objects(self, nat_rule_object):
        """
        Given
         - un-listable nat-rules object.

        When
         - running the pan-os-edit-nat-rule command.

        Then
         - make sure an exception is raised.
        """
        from Panorama import pan_os_edit_nat_rule_command
        with pytest.raises(ValueError):
            pan_os_edit_nat_rule_command({'element_to_change': nat_rule_object, 'rulename': 'test', 'action': 'add'})

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'rulename': 'test',
                    'pre_post': 'pre-rulebase',
                    'element_to_change': 'source_zone',
                    'behavior': 'add',
                    'element_value': '2.2.2.2,3.3.3.3'
                },
                integration_panorama_params,
                {
                    'action': 'edit',
                    'element': '<from><member>2.2.2.2</member><member>3.3.3.3</member><member>1.1.1.1</member></from>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/nat/rules/entry[@name='test']/from"
                }
            ),
            pytest.param(
                {
                    'rulename': 'test',
                    'element_to_change': 'source_zone',
                    'behavior': 'add',
                    'element_value': '2.2.2.2,3.3.3.3'
                },
                integration_firewall_params,
                {
                    'action': 'edit',
                    'element': '<from><member>2.2.2.2/member><member>1.1.1.1/member></from>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
                             "/rulebase/nat/rules/entry[@name='test']/from"
                }
            )
        ]
    )
    def test_pan_os_nat_rule_add_action_main_flow(self, mocker, args, params, expected_url_params):
        """
        Given
         - Panorama instance when adding a new value to source_zone.
         - Firewall instance when adding a new value to source_zone.

        When
         - running the pan-os-edit-nat-rule through the main flow.

        Then
         - make sure the xpath/element and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={
                'response': {
                    '@status': 'success', '@code': '19', 'result': {
                        '@total-count': '1', '@count': '1', 'from': {'member': '1.1.1.1'}
                    }
                }
            }
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-nat-rule')

        main()
        assert mock_request.call_args.kwargs['params']['xpath'] == expected_url_params['xpath']
        assert '1.1.1.1' in mock_request.call_args.kwargs['params']['element']
        assert '2.2.2.2' in mock_request.call_args.kwargs['params']['element']
        assert '3.3.3.3' in mock_request.call_args.kwargs['params']['element']

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'rulename': 'test',
                    'pre_post': 'pre-rulebase',
                    'element_to_change': 'source_zone',
                    'behavior': 'remove',
                    'element_value': '2.2.2.2,3.3.3.3'
                },
                integration_panorama_params,
                {
                    'action': 'edit',
                    'element': '<from><member>1.1.1.1</member></from>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/nat/rules/entry[@name='test']/from"
                }
            ),
            pytest.param(
                {
                    'rulename': 'test',
                    'element_to_change': 'source_zone',
                    'behavior': 'remove',
                    'element_value': '2.2.2.2,3.3.3.3'
                },
                integration_firewall_params,
                {
                    'action': 'edit',
                    'element': '<from><member>1.1.1.1</member></from>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/"
                             "rulebase/nat/rules/entry[@name='test']/from"
                }
            )
        ]
    )
    def test_pan_os_nat_rule_remove_action_main_flow(self, mocker, args, params, expected_url_params):
        """
        Given
         - Panorama instance when removing a value from source_zone.
         - Firewall instance when removing a value from source_zone.

        When
         - running the pan-os-edit-nat-rule through the main flow.

        Then
         - make sure the xpath/element and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={
                'response': {
                    '@status': 'success', '@code': '19', 'result': {
                        '@total-count': '1', '@count': '1', 'from': {'member': ['1.1.1.1', '2.2.2.2', '3.3.3.3']}
                    }
                }
            }
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-nat-rule')

        main()
        assert mock_request.call_args.kwargs['params']['xpath'] == expected_url_params['xpath']
        assert mock_request.call_args.kwargs['params'] == expected_url_params

    @staticmethod
    def test_pan_os_edit_nat_rule_command_audit_comment_main_flow(mocker):
        """
        Given
         - panorama integrations parameters.
         - pan-os-edit-nat-rule command arguments including device_group.
         - arguments to edit audit comment of a rule

        When -
            running the pan-os-edit-nat-rule command through the main flow

        Then
         - make sure the context output is returned as expected.
         - make sure the device group gets overriden by the command arguments.
        """
        from Panorama import main

        mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
        mocker.patch.object(
            demisto,
            'args',
            return_value={
                "rulename": "test",
                "element_to_change": "audit-comment",
                "element_value": "some string",
                "pre_post": "pre-rulebase",
                "device-group": "new device group"
            }
        )
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-nat-rule')
        request_mock = mocker.patch(
            'Panorama.http_request', return_value=TestPanoramaEditRuleCommand.EDIT_AUDIT_COMMENT_SUCCESS_RESPONSE
        )

        res = mocker.patch('demistomock.results')
        main()

        assert request_mock.call_args.kwargs['params'] == {
            'type': 'op',
            'cmd': "<set><audit-comment><xpath>/config/devices/entry[@name='localhost.localdomain']/device-group"
                   "/entry[@name='new device group']/pre-rulebase/nat/rules/entry[@name='test']"
                   "</xpath><comment>some string</comment></audit-comment></set>",
            'key': 'thisisabogusAPIKEY!'
        }
        assert res.call_args.args[0]['Contents'] == TestPanoramaEditRuleCommand.EDIT_AUDIT_COMMENT_SUCCESS_RESPONSE


class TestPanOSListVirtualRouters:

    @pytest.mark.parametrize(
        'args, params, expected_url_params, mocked_response_path',
        [
            pytest.param(
                {'pre_post': 'pre-rulebase', 'show_uncommitted': 'false', 'virtual_router': 'test'},
                integration_panorama_params,
                {
                    'type': 'config', 'action': 'show', 'key': 'thisisabogusAPIKEY!',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='test']/"
                             "config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                             "[@name='test']"
                },
                'test_data/list-virtual-routers-response.json'
            ),
            pytest.param(
                {'show_uncommitted': 'false', 'virtual_router': 'test'},
                integration_firewall_params,
                {
                    'type': 'config', 'action': 'show', 'key': 'thisisabogusAPIKEY!',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router"
                             "/entry[@name='test']"
                },
                'test_data/list-virtual-routers-response.json'
            ),
            pytest.param(
                {'pre_post': 'pre-rulebase', 'show_uncommitted': 'true', 'virtual_router': 'test'},
                integration_panorama_params,
                {
                    'type': 'config', 'action': 'get', 'key': 'thisisabogusAPIKEY!',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='test']"
                             "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router"
                             "/entry[@name='test']"
                },
                'test_data/list-virtual-routers-response-un-commited-router.json'
            ),
            pytest.param(
                {'show_uncommitted': 'true', 'virtual_router': 'test'},
                integration_firewall_params,
                {
                    'type': 'config', 'action': 'get', 'key': 'thisisabogusAPIKEY!',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router"
                             "/entry[@name='test']"
                },
                'test_data/list-virtual-routers-response-un-commited-router.json'
            )
        ]
    )
    def test_pan_os_list_virtual_routers_command_main_flow(
        self, mocker, args, params, expected_url_params, mocked_response_path
    ):
        """
        Given:
         - Panorama instance configuration and name to retrieve a specific virtual router that was committed.
         - Firewall instance configuration and name to retrieve a specific virtual router that was committed.
         - Panorama instance configuration and name to retrieve a specific virtual router that was not committed.
         - Firewall instance configuration and name to retrieve a specific virtual router that was not committed.

        When:
         - running the pan-os-list-virtual-routers through the main flow.

        Then:
         - make sure the context output is parsed correctly for both un-committed and committed cases.
         - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request", return_value=load_json(mocked_response_path)
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-list-virtual-routers')
        result = mocker.patch('demistomock.results')

        main()

        assert list(result.call_args.args[0]['EntryContext'].values())[0] == [
            {
                'BGP': {'enable': 'no',
                        'routing-options': {'graceful-restart': {'enable': 'yes'}}},
                'ECMP': {'algorithm': {'ip-modulo': 'None'}},
                'Interface': None,
                'Multicast': None,
                'Name': 'test',
                'OSPF': {'enable': 'no'},
                'OSPFv3': {'enable': 'no'},
                'RIP': {'enable': 'no'},
                'RedistributionProfile': None,
                'StaticRoute': None
            }
        ]
        assert mock_request.call_args.kwargs['params'] == expected_url_params


class TestPanOSListRedistributionProfiles:

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {'virtual_router': 'virtual-router-1', 'template': 'test-override'},
                integration_panorama_params,
                {
                    'type': 'config', 'action': 'get', 'key': 'thisisabogusAPIKEY!',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/template/entry["
                             "@name='test-override']/config/devices/entry[@name='localhost.localdomain']/network"
                             "/virtual-router/entry[@name='virtual-router-1']/protocol/redist-profile"
                }
            ),
            pytest.param(
                {'virtual_router': 'virtual-router-1'},
                integration_firewall_params,
                {
                    'action': 'get',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/"
                             "entry[@name='virtual-router-1']/protocol/redist-profile"
                }
            )
        ]
    )
    def test_pan_os_list_redistribution_profiles_main_flow(
        self, mocker, args, params, expected_url_params
    ):
        """
        Given:
         - Panorama instance configuration and name to retrieve redistribution profiles that were not committed.
         - Firewall instance configuration and name to retrieve redistribution profiles that were not committed.

        When:
         - running the pan-os-list-redistribution-profiles through the main flow.

        Then:
         - make sure the context output is parsed correctly.
         - make sure the xpath and the request is correct for both panorama/firewall and that template gets overriden
             when using panorama instance.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request", return_value=load_json(
                'test_data/list-redistribution-profiles-un-committed-response.json'
            )
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-list-redistribution-profiles')
        result = mocker.patch('demistomock.results')

        main()

        assert list(result.call_args.args[0]['EntryContext'].values())[0] == [
            {
                'Name': 'test1', 'Priority': '1', 'Action': 'redist', 'FilterInterface': 'loopback',
                'FilterType': ['bgp', 'connect', 'ospf', 'rip', 'static'], 'FilterDestination': '1.1.1.1',
                'FilterNextHop': '2.2.2.2',
                'BGP': {'Community': ['local-as', 'no-export'], 'ExtendedCommunity': '0x4164ACFCE33404EA'},
                'OSPF': {
                    'PathType': ['ext-1', 'ext-2', 'inter-area', 'intra-area'],
                    'Area': ['1.1.1.1', '2.2.2.2'], 'Tag': '1'}
            },
            {
                'Name': 'test-2', 'Priority': '123', 'Action': 'no-redist', 'FilterInterface': None,
                'FilterType': None, 'FilterDestination': None, 'FilterNextHop': None, 'BGP': None, 'OSPF': None
            }
        ]

        assert mock_request.call_args.kwargs['params'] == expected_url_params


class TestPanOSCreateRedistributionProfile:

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'virtual_router': 'virtual-router', 'name': 'redistribution-profile', 'priority': '12',
                    'action': 'redist', 'filter_bgp_extended_community': '0x4164ACFCE33404EA',
                    'filter_source_type': 'bgp,ospf', 'filter_ospf_area': '1.1.1.1,2.2.2.2'
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='test']/"
                             "config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry["
                             "@name='virtual-router']/protocol/redist-profile/entry[@name='redistribution-profile']",
                    'element': '<priority>12</priority><action><redist/></action><filter><ospf><area><member>1.1.1.1<'
                               '/member><member>2.2.2.2</member></area></ospf><bgp><extended-community>'
                               '<member>0x4164ACFCE33404EA</member></extended-community></bgp><type><member>bgp'
                               '</member><member>ospf</member></type></filter>',
                    'action': 'set', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'virtual_router': 'virtual-router', 'name': 'redistribution-profile', 'interface': 'loopback',
                    'filter_ospf_tag': '1.1.1.1,2.2.2.2', 'filter_source_type': 'ospf,bgp',
                    'filter_ospf_path_type': 'ext-1,ext-2'
                },
                integration_firewall_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                             "[@name='virtual-router']/protocol/redist-profile/entry[@name='redistribution-profile']",
                    'element': '<filter><ospf><path-type><member>ext-1</member><member>ext-2</member></path-type><tag>'
                               '<member>1.1.1.1</member><member>2.2.2.2</member></tag></ospf><type><member>'
                               'ospf</member><member>bgp</member></type><interface><member>loopback</member>'
                               '</interface></filter>',
                    'action': 'set', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            )
        ]
    )
    def test_pan_os_create_redistribution_profile_command_main_flow(self, mocker, args, params, expected_url_params):
        """
        Given:
        - Panorama instance configuration and arguments to create a redistribution-profile.
        - Firewall instance configuration and arguments to create a redistribution-profile.

        When:
        - running the pan-os-create-redistribution-profile through the main flow.

        Then:
        - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-create-redistribution-profile')

        main()

        assert mock_request.call_args.kwargs['params'] == expected_url_params


class TestPanOSEditRedistributionProfile:

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'virtual_router': 'virtual-router', 'name': 'redistribution-profile',
                    'element_to_change': 'priority', 'element_value': '50', 'behavior': 'replace'
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='test']/"
                             "config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                             "[@name='virtual-router']/protocol/redist-profile/entry[@name='redistribution-profile']"
                             "/priority",
                    'element': '<priority>50</priority>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'virtual_router': 'virtual-router', 'name': 'redistribution-profile',
                    'element_to_change': 'filter_type', 'element_value': 'bgp,ospf', 'behavior': 'replace'
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='test']/config"
                             "/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                             "[@name='virtual-router']/protocol/redist-profile/entry[@name='redistribution-profile']"
                             "/filter/type", 'element': '<type><member>bgp</member><member>ospf</member></type>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }

            ),
            pytest.param(
                {
                    'virtual_router': 'virtual-router', 'name': 'redistribution-profile',
                    'element_to_change': 'filter_ospf_area', 'element_value': '1.1.1.1,2.2.2.2,3.3.3.3',
                    'behavior': 'replace'
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='test']/config"
                             "/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                             "[@name='virtual-router']/protocol/redist-profile/entry[@name='redistribution-profile']"
                             "/filter/ospf/area",
                    'element': '<area><member>1.1.1.1</member><member>2.2.2.2</member><member>3.3.3.3</member></area>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'virtual_router': 'virtual-router', 'name': 'redistribution-profile',
                    'element_to_change': 'filter_bgp_extended_community', 'element_value': '0x4164ACFCE33404EA',
                    'behavior': 'replace'
                },
                integration_firewall_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                             "[@name='virtual-router']/protocol/redist-profile/entry[@name='redistribution-profile']"
                             "/filter/bgp/community",
                    'element': '<extended-community><member>0x4164ACFCE33404EA</member></extended-community>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'virtual_router': 'virtual-router', 'name': 'redistribution-profile',
                    'element_to_change': 'filter_destination', 'element_value': '1.1.1.1,2.2.2.2',
                    'behavior': 'replace'
                },
                integration_firewall_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                             "[@name='virtual-router']/protocol/redist-profile/entry[@name='redistribution-profile']"
                             "/filter/destination",
                    'element': '<destination><member>1.1.1.1</member><member>2.2.2.2</member></destination>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            )
        ]
    )
    def test_pan_os_edit_redistribution_profile_command_replace_action_main_flow(
        self, mocker, args, params, expected_url_params
    ):
        """
        Tests several cases where behavior == 'replace'

        Given:
        - Panorama instance configuration and priority object of a redistribution-profile to edit.
        - Panorama instance configuration and filter_type object of a redistribution-profile to edit.
        - Panorama instance configuration and filter_ospf_area object of a redistribution-profile to edit.
        - Firewall instance configuration and filter_bgp_extended_community object of a redistribution-profile to edit.
        - Firewall instance configuration and filter_destination object of a redistribution-profile to edit.

        When:
        - running the pan-os-edit-redistribution-profile through the main flow.

        Then:
        - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-redistribution-profile')

        main()

        assert mock_request.call_args.kwargs['params'] == expected_url_params

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'virtual_router': 'virtual-router', 'name': 'redistribution-profile',
                    'element_to_change': 'filter_nexthop', 'element_value': '2.2.2.2,3.3.3.3', 'behavior': 'add'
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='test']"
                             "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router"
                             "/entry[@name='virtual-router']/protocol/redist-profile/entry"
                             "[@name='redistribution-profile']/filter/nexthop",
                    'element': '<nexthop><member>1.1.1.1</member><member>3.3.3.3</member'
                               '><member>2.2.2.2</member></nexthop>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'virtual_router': 'virtual-router', 'name': 'redistribution-profile',
                    'element_to_change': 'filter_nexthop', 'element_value': '2.2.2.2,3.3.3.3', 'behavior': 'add'
                },
                integration_firewall_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                             "[@name='virtual-router']/protocol/redist-profile/entry[@name='redistribution-profile']"
                             "/filter/nexthop",
                    'element': '<nexthop><member>1.1.1.1</member><member>2.2.2.2</'
                               'member><member>3.3.3.3</member></nexthop>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }

            )
        ]
    )
    def test_pan_os_edit_redistribution_profile_command_add_action_main_flow(
        self, mocker, args, params, expected_url_params
    ):
        """
        Tests cases where behavior == 'add'

        Given:
        - Panorama instance configuration and nexthop object of a redistribution-profile to add.
        - Firewall instance configuration and nexthop object of a redistribution-profile to add.

        When:
        - running the pan-os-edit-redistribution-profile through the main flow.

        Then:
        - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={
                'response': {
                    '@status': 'success', '@code': '19', 'result': {
                        '@total-count': '1', '@count': '1', 'nexthop': {'member': '1.1.1.1'}
                    }
                }
            }
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-redistribution-profile')

        main()
        assert mock_request.call_args.kwargs['params']['xpath'] == expected_url_params['xpath']
        assert '1.1.1.1' in mock_request.call_args.kwargs['params']['element']
        assert '2.2.2.2' in mock_request.call_args.kwargs['params']['element']
        assert '3.3.3.3' in mock_request.call_args.kwargs['params']['element']

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'virtual_router': 'virtual-router', 'name': 'redistribution-profile',
                    'element_to_change': 'filter_ospf_area', 'element_value': '1.1.1.1', 'behavior': 'remove'
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='test']"
                             "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                             "[@name='virtual-router']/protocol/redist-profile/entry"
                             "[@name='redistribution-profile']/filter/ospf/area",
                    'element': '<area />',
                    'action': 'edit',
                    'type': 'config',
                    'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'virtual_router': 'virtual-router', 'name': 'redistribution-profile',
                    'element_to_change': 'filter_ospf_area', 'element_value': '1.1.1.1', 'behavior': 'remove'
                },
                integration_firewall_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                             "[@name='virtual-router']/protocol/redist-profile/entry[@name='redistribution-profile']"
                             "/filter/ospf/area",
                    'element': '<area />',
                    'action': 'edit',
                    'type': 'config',
                    'key': 'thisisabogusAPIKEY!'
                }
            )
        ]
    )
    def test_pan_os_edit_redistribution_profile_command_remove_action_main_flow(
        self, mocker, args, params, expected_url_params
    ):
        """
        Tests cases where behavior == 'remove'

        Given:
        - Panorama instance configuration and area object of a redistribution-profile to remove.
        - Firewall instance configuration and area object of a redistribution-profile to remove.

        When:
        - running the pan-os-edit-redistribution-profile through the main flow.

        Then:
        - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={
                'response': {
                    '@status': 'success', '@code': '19', 'result': {
                        '@total-count': '1', '@count': '1', 'area': {'member': ['1.1.1.1']}
                    }
                }
            }
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-redistribution-profile')

        main()
        assert mock_request.call_args.kwargs['params'] == expected_url_params


@pytest.mark.parametrize(
    'args, params, expected_url_params',
    [
        pytest.param(
            {
                'virtual_router': 'virtual-router', 'name': 'redistribution-profile'
            },
            integration_panorama_params,
            {
                'xpath': "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='test']/c"
                         "onfig/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                         "[@name='virtual-router']/protocol/redist-profile/entry[@name='redistribution-profile']",
                'action': 'delete', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
            }
        ),
        pytest.param(
            {
                'virtual_router': 'virtual-router', 'name': 'redistribution-profile'
            },
            integration_firewall_params,
            {
                'xpath': "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry"
                         "[@name='virtual-router']/protocol/redist-profile/entry[@name='redistribution-profile']",
                'action': 'delete', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
            }
        )
    ]
)
def test_pan_os_delete_redistribution_profile_command_main_flow(mocker, args, params, expected_url_params):
    """
    Given:
    - Panorama instance configuration and arguments to delete a redistribution-profile.
    - Firewall instance configuration and arguments to delete a redistribution-profile.

    When:
    - running the pan-os-delete-redistribution-profile through the main flow.

    Then:
    - make sure the xpath and the request is correct for both panorama/firewall.
    """
    from Panorama import main

    mock_request = mocker.patch(
        "Panorama.http_request",
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'command', return_value='pan-os-delete-redistribution-profile')

    main()

    assert mock_request.call_args.kwargs['params'] == expected_url_params


class TestPanOSListPBFRulesCommand:

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {'pre_post': 'pre-rulebase', 'show_uncommitted': 'true'},
                integration_panorama_params,
                {
                    'type': 'config', 'action': 'get', 'key': 'thisisabogusAPIKEY!',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group"
                             "/entry[@name='Lab-Devices']/pre-rulebase/pbf"
                }
            ),
            pytest.param(
                {'show_uncommitted': 'true'},
                integration_firewall_params,
                {
                    'type': 'config', 'action': 'get', 'key': 'thisisabogusAPIKEY!',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry"
                             "[@name='vsys1']/rulebase/pbf"
                }
            )
        ]
    )
    def test_pan_os_list_pbf_command_un_committed_rules_main_flow(self, mocker, args, params, expected_url_params):
        """
        Given:
         - Panorama instance configuration and arguments to get all the un-committed PBF rules.
         - Firewall instance configuration and arguments to get all the un-committed PBF rules.

        When:
         - running the pan-os-list-pbf-rules through the main flow.

        Then:
         - make sure the context output is parsed correctly.
         - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        expected_context = [
            {
                'Name': 'test', 'Description': 'this is a test description', 'Tags': ['test tag', 'dag_test_tag'],
                'SourceZone': '1.1.1.1', 'SourceInterface': None, 'SourceAddress': '1.1.1.1', 'SourceUser': 'pre-logon',
                'DestinationAddress': '1.1.1.1',
                'Action': {
                    'forward': {
                        'nexthop': {'ip-address': '2.2.2.2'},
                        'monitor': {'profile': 'profile', 'disable-if-unreachable': 'no', 'ip-address': '1.1.1.1'},
                        'egress-interface': 'a2'
                    }
                },
                'EnforceSymmetricReturn': {'nexthop-address-list': {'entry': {'@name': '1.1.1.1'}}, 'enabled': 'yes'},
                'Target': {'negate': 'no'}, 'Application': '3pc', 'Service': 'application-default', 'Disabled': None
            },
            {
                'Name': 'test2', 'Description': None, 'Tags': None, 'SourceZone': ['1.1.1.1', '2.2.2.2'],
                'SourceInterface': None, 'SourceAddress': 'any', 'SourceUser': 'any', 'DestinationAddress': 'any',
                'Action': {'no-pbf': {}}, 'EnforceSymmetricReturn': {'enabled': 'no'}, 'Target': {'negate': 'no'},
                'Application': 'any', 'Service': 'any', 'Disabled': "yes"
            },
            {
                'Name': 'test3', 'Description': None, 'Tags': None, 'SourceZone': None, 'SourceInterface': 'a2',
                'SourceAddress': 'any', 'SourceUser': 'any', 'DestinationAddress': 'any',
                'Action': {'discard': {}}, 'EnforceSymmetricReturn': {'enabled': 'no'}, 'Target': {'negate': 'no'},
                'Application': 'any', 'Service': 'any', 'Disabled': "no"
            }
        ]

        mock_request = mocker.patch(
            "Panorama.http_request", return_value=load_json('test_data/list-pbf-rules-response-un-committed.json')
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-list-pbf-rules')
        result = mocker.patch('demistomock.results')

        main()

        assert list(result.call_args.args[0]['EntryContext'].values())[0] == expected_context
        assert mock_request.call_args.kwargs['params'] == expected_url_params

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {'pre_post': 'pre-rulebase', 'show_uncommitted': 'false', 'rulename': 'test'},
                integration_panorama_params,
                {
                    'type': 'config', 'action': 'show', 'key': 'thisisabogusAPIKEY!',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/pbf/rules/entry[@name='test']"
                }
            ),
            pytest.param(
                {'show_uncommitted': 'false', 'rulename': 'test'},
                integration_firewall_params,
                {
                    'type': 'config', 'action': 'show', 'key': 'thisisabogusAPIKEY!',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
                             "/rulebase/pbf/rules/entry[@name='test']"
                }
            )
        ]
    )
    def test_pan_os_list_pbf_command_committed_rules_main_flow(self, mocker, args, params, expected_url_params):
        """
        Given:
         - Panorama instance configuration and arguments to get a specific committed PBF rule.
         - Firewall instance configuration and arguments to get a specific committed PBF rule.

        When:
         - running the pan-os-list-pbf-rules through the main flow.

        Then:
         - make sure the context output is parsed correctly.
         - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main
        expected_context = [
            {
                'Name': 'test', 'Description': 'this is a test description', 'Tags': ['test tag', 'dag_test_tag'],
                'SourceZone': '1.1.1.1', 'SourceInterface': None, 'Disabled': None, 'SourceAddress': '1.1.1.1',
                'SourceUser': 'pre-logon', 'DestinationAddress': '1.1.1.1',
                'Action': {
                    'forward': {
                        'nexthop': {'ip-address': '2.2.2.2'},
                        'monitor': {'profile': 'profile', 'disable-if-unreachable': 'no', 'ip-address': '1.1.1.1'},
                        'egress-interface': 'a2'
                    }
                },
                'EnforceSymmetricReturn': {'nexthop-address-list': {'entry': {'@name': '1.1.1.1'}}, 'enabled': 'yes'},
                'Target': {'negate': 'no'}, 'Application': '3pc', 'Service': 'application-default'}
        ]

        mock_request = mocker.patch(
            "Panorama.http_request", return_value=load_json('test_data/list-pbf-rules-response-commited.json')
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-list-pbf-rules')
        result = mocker.patch('demistomock.results')

        main()

        assert list(result.call_args.args[0]['EntryContext'].values())[0] == expected_context
        assert mock_request.call_args.kwargs['params'] == expected_url_params


class TestCreatePBFRuleCommand:

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'rulename': 'test',
                    'description': 'test',
                    'pre_post': 'pre-rulebase',
                    'negate_source': 'yes',
                    'action': 'forward',
                    'egress_interface': 'egress-interface',
                    'nexthop': 'none',
                    'destination_address': 'any',
                    'enforce_symmetric_return': 'no',
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/pbf/rules/entry[@name='test']",
                    'element': '<action><forward><egress-interface>egress-interface</egress-interface></forward>'
                               '</action><enforce-symmetric-return><enabled>no</enabled></enforce-symmetric-return>'
                               '<destination><member>any</member></destination><description>test</description>'
                               '<negate-source>yes</negate-source>',
                    'action': 'set', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'rulename': 'test',
                    'description': 'test',
                    'action': 'no-pbf',
                    'source_zone': '1.1.1.1,2.2.2.2',
                    'enforce_symmetric_return': 'yes',
                    'nexthop_address_list': '1.1.1.1,2.2.2.2',
                    'nexthop': 'ip-address',
                    'nexthop_value': '1.1.1.1',
                },
                integration_firewall_params,
                {
                    'action': 'set',
                    'element': '<action><no-pbf/></action><enforce-symmetric-return><enabled>yes</enabled>'
                               '<nexthop-address-list><entry name="1.1.1.1"/><entry name="2.2.2.2"/>'
                               '</nexthop-address-list></enforce-symmetric-return><description>test'
                               '</description><from><zone><member>1.1.1.1'
                               '</member><member>2.2.2.2</member></zone></from>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
                             "/rulebase/pbf/rules/entry[@name='test']"
                }
            ),
            pytest.param(
                {
                    'rulename': 'test',
                    'description': 'test',
                    'action': 'discard',
                    'destination_address': '1.1.1.1,2.2.2.2',
                    'tags': 'tag1,tag2',
                    'nexthop_address_list': '1.1.1.1,2.2.2.2',
                    'nexthop': 'fqdn',
                    'nexthop_value': '1.1.1.1/24',
                    'pre_post': 'pre-rulebase',
                    'enforce_symmetric_return': 'yes',
                    'audit_comment': 'test comment',
                },
                integration_panorama_params,
                {
                    'action': 'set',
                    'element': '<action><discard/></action><enforce-symmetric-return><enabled>yes</'
                               'enabled><nexthop-address-list><entry '
                               'name="1.1.1.1"/><entry name="2.2.2.2"/></nexthop-address-list>'
                               '</enforce-symmetric-return><destination>'
                               '<member>1.1.1.1</member><member>2.2.2.2</member>'
                               '</destination><description>test</description>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/pbf/rules/entry[@name='test']",
                    'audit-comment': 'test comment',
                }
            ),
            pytest.param(
                {
                    'rulename': 'test',
                    'description': 'test',
                    'action': 'forward',
                    'egress_interface': 'egress-interface',
                    'source_zone': 'all access zone external',
                    'nexthop': 'none',
                    'enforce_symmetric_return': 'no',
                    'audit_comment': 'test comment',
                },
                integration_firewall_params,
                {
                    'action': 'set',
                    'element': '<action><forward><egress-interface>egress-interface</egress-interface></forward>'
                               '</action><enforce-symmetric-return><enabled>no</enabled></enforce-symmetric-return>'
                               '<description>test</description><from><zone>'
                               '<member>all access zone external</member></zone></from>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
                             "/rulebase/pbf/rules/entry[@name='test']",
                    'audit-comment': 'test comment',
                }
            ),
        ]
    )
    def test_pan_os_create_pbf_rule_command_main_flow(self, mocker, args, params, expected_url_params):
        """
        Given:
         - Panorama instance configuration with forward action and egress_interface arguments.
         - Firewall instance configuration with no-pbf action and ip-address as nexthop arguments.
         - Panorama instance configuration with discard action and fqdn as nexthop arguments.
         - firewall instance configuration with basic parameter configurations along with dynamic-ip

        When:
         - running the pan-os-create-pbf-rule through the main flow.

        Then:
         - make sure the xpath/element and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-create-pbf-rule')

        main()
        assert mock_request.call_args.kwargs['params'] == expected_url_params


class TestPanOSEditPBFRule:

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'rulename': 'test', 'element_to_change': 'action_forward_egress_interface',
                    'element_value': 'interface-1', 'pre_post': 'pre-rulebase', 'behavior': 'replace'
                },
                integration_panorama_params,
                {
                    'action': 'edit',
                    'element': '<egress-interface>interface-1</egress-interface>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/pbf/rules/entry[@name='test']/"
                             "action/forward/egress-interface"
                }
            ),
            pytest.param(
                {
                    'rulename': 'test', 'element_to_change': 'action_forward_no_pbf', 'pre_post': 'pre-rulebase',
                    'behavior': 'replace'
                },
                integration_panorama_params,
                {
                    'action': 'edit',
                    'element': '<action><no-pbf/></action>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/pbf/rules/entry[@name='test']/action"
                }
            ),
            pytest.param(
                {
                    'rulename': 'test', 'element_to_change': 'action_forward_discard', 'pre_post': 'pre-rulebase',
                    'behavior': 'replace'
                },
                integration_panorama_params,
                {
                    'action': 'edit',
                    'element': '<action><discard/></action>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/pbf/rules/entry[@name='test']/action"
                }
            ),
            pytest.param(
                {
                    'rulename': 'test', 'element_to_change': 'nexthop_address_list', 'element_value': '1.1.1.1,2.2.2.2',
                    'behavior': 'replace'
                },
                integration_firewall_params,
                {
                    'action': 'edit',
                    'element': '<nexthop-address-list><entry name="1.1.1.1"/><entry '
                               'name="2.2.2.2"/></nexthop-address-list>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/"
                             "entry[@name='vsys1']/rulebase/pbf/rules/entry[@name='test']"
                             "/enforce-symmetric-return/nexthop-address-list"
                }
            ),
            pytest.param(
                {
                    'rulename': 'test', 'element_to_change': 'source_zone', 'element_value': '1.1.1.1,2.2.2.2',
                    'behavior': 'replace'
                },
                integration_firewall_params,
                {
                    'action': 'edit',
                    'element': '<zone><member>1.1.1.1</member><member>2.2.2.2</member></zone>',
                    'key': 'thisisabogusAPIKEY!',
                    'type': 'config',
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry"
                             "[@name='vsys1']/rulebase/pbf/rules/entry[@name='test']/from/zone"
                }
            )
        ]
    )
    def test_pan_os_edit_pbf_rule_command_replace_operation_main_flow(self, mocker, args, params, expected_url_params):
        """
        Tests several cases when behavior == 'replace'

        Given:
        - Panorama instance configuration and egress-interface object of a pbf-rule to edit.
        - Panorama instance configuration and action='no-pbf' object of a pbf-rule to edit.
        - Panorama instance configuration and action='discard' object of a pbf-rule to edit.
        - Firewall instance configuration and nexthop_address_list object of a pbf-rule to edit.
        - Firewall instance configuration and source_zone object of a pbf-rule to edit.

        When:
        - running the pan-os-edit-pbf-rule through the main flow.

        Then:
        - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-pbf-rule')

        main()

        assert mock_request.call_args.kwargs['params'] == expected_url_params

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'rulename': 'test', 'element_to_change': 'nexthop_address_list', 'element_value': '2.2.2.2,3.3.3.3',
                    'behavior': 'add', 'pre_post': 'pre-rulebase'
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/pbf/rules/entry[@name='test']/enforce-symmetric-return"
                             "/nexthop-address-list",
                    'element': '<nexthop-address-list><entry name="1.1.1.1"/><entry name="2.2.2.2"/>'
                               '<entry name="3.3.3.3"/></nexthop-address-list>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'rulename': 'test', 'element_to_change': 'nexthop_address_list', 'element_value': '2.2.2.2,3.3.3.3',
                    'behavior': 'add'
                },
                integration_firewall_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
                             "/rulebase/pbf/rules/entry[@name='test']/enforce-symmetric-return/nexthop-address-list",
                    'element': '<nexthop-address-list><entry name="2.2.2.2"/><entry name="3.3.3.3"/>'
                               '<entry name="1.1.1.1"/></nexthop-address-list>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            )
        ]
    )
    def test_pan_os_edit_pbf_rule_command_add_action_main_flow(self, mocker, args, params, expected_url_params):
        """
        Tests cases where behavior == 'add'

        Given:
        - Panorama instance configuration and nexthop-address-list object of a pbf-rule to add.
        - Firewall instance configuration and nexthop-address-list object of a pbf-rule to add.

        When:
        - running the pan-os-edit-pbf-rule through the main flow.

        Then:
        - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={
                'response': {
                    '@status': 'success', '@code': '19', 'result': {
                        '@total-count': '1', '@count': '1', 'nexthop-address-list': {'member': '1.1.1.1'}
                    }
                }
            }
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-pbf-rule')

        main()
        assert mock_request.call_args.kwargs['params']['xpath'] == expected_url_params['xpath']
        assert '1.1.1.1' in mock_request.call_args.kwargs['params']['element']
        assert '2.2.2.2' in mock_request.call_args.kwargs['params']['element']
        assert '3.3.3.3' in mock_request.call_args.kwargs['params']['element']

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'rulename': 'test', 'element_to_change': 'application',
                    'element_value': 'application-1', 'behavior': 'remove', 'pre_post': 'pre-rulebase'
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                             "[@name='Lab-Devices']/pre-rulebase/pbf/rules/entry[@name='test']/application",
                    'element': '<application><member>application-2</member></application>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'rulename': 'test', 'element_to_change': 'application',
                    'element_value': 'application-1', 'behavior': 'remove'
                },
                integration_firewall_params,
                {
                    'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/"
                             "rulebase/pbf/rules/entry[@name='test']/application",
                    'element': '<application><member>application-2</member></application>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }

            )
        ]
    )
    def test_pan_os_edit_pbf_rule_command_remove_action_main_flow(self, mocker, args, params, expected_url_params):
        """
        Tests cases where behavior == 'remove'

        Given:
        - Panorama instance configuration and address object of a PBF-rule to remove.
        - Firewall instance configuration and address object of a PBF-rule to remove.

        When:
        - running the pan-os-edit-pbf-rule through the main flow.

        Then:
        - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        mock_request = mocker.patch(
            "Panorama.http_request",
            return_value={
                'response': {
                    '@status': 'success', '@code': '19', 'result': {
                        '@total-count': '1', '@count': '1', 'application': {
                            'member': ['application-1', 'application-2']
                        }
                    }
                }
            }
        )
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-pbf-rule')

        main()
        assert mock_request.call_args.kwargs['params'] == expected_url_params

    @staticmethod
    def test_pan_os_edit_pbf_rule_command_audit_comment_main_flow(mocker):
        """
        Given
         - panorama integrations parameters.
         - pan-os-edit-pbf-rule command arguments including device_group.
         - arguments to edit audit comment of a rule

        When -
            running the pan-os-edit-pbf-rule command through the main flow

        Then
         - make sure the context output is returned as expected.
         - make sure the device group gets overriden by the command arguments.
        """
        from Panorama import main

        mocker.patch.object(demisto, 'params', return_value=integration_panorama_params)
        mocker.patch.object(
            demisto,
            'args',
            return_value={
                "rulename": "test",
                "element_to_change": "audit-comment",
                "element_value": "some string",
                "pre_post": "pre-rulebase",
                "device-group": "new device group"
            }
        )
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-pbf-rule')
        request_mock = mocker.patch(
            'Panorama.http_request', return_value=TestPanoramaEditRuleCommand.EDIT_AUDIT_COMMENT_SUCCESS_RESPONSE
        )

        res = mocker.patch('demistomock.results')
        main()

        assert request_mock.call_args.kwargs['params'] == {
            'type': 'op',
            'cmd': "<set><audit-comment><xpath>/config/devices/entry[@name='localhost.localdomain']/device-group"
                   "/entry[@name='new device group']/pre-rulebase/pbf/rules/entry[@name='test']"
                   "</xpath><comment>some string</comment></audit-comment></set>",
            'key': 'thisisabogusAPIKEY!'
        }
        assert res.call_args.args[0]['Contents'] == TestPanoramaEditRuleCommand.EDIT_AUDIT_COMMENT_SUCCESS_RESPONSE


@pytest.mark.parametrize(
    'args, params, expected_url_params',
    [
        pytest.param(
            {
                'rulename': 'test',
                'pre_post': 'pre-rulebase'
            },
            integration_panorama_params,
            {
                'action': 'delete',
                'key': 'thisisabogusAPIKEY!',
                'type': 'config',
                'xpath': "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
                         "[@name='Lab-Devices']/pre-rulebase/pbf/rules/entry[@name='test']"
            }
        ),
        pytest.param(
            {
                'rulename': 'test'
            },
            integration_firewall_params,
            {
                'action': 'delete',
                'key': 'thisisabogusAPIKEY!',
                'type': 'config',
                'xpath': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry"
                         "[@name='vsys1']/rulebase/pbf/rules/entry[@name='test']"
            }
        )
    ]
)
def test_pan_os_delete_pbf_rule_command_main_flow(mocker, args, params, expected_url_params):
    """
    Given:
     - Panorama instance configuration with a specific rulename.
     - Firewall instance configuration with a specific rulename.

    When:
     - running the pan-os-delete-pbf-rule through the main flow.

    Then:
     - make sure the xpath/element and the request is correct for both panorama/firewall.
    """
    from Panorama import main

    mock_request = mocker.patch(
        "Panorama.http_request",
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'command', return_value='pan-os-delete-pbf-rule')

    main()
    assert mock_request.call_args.kwargs['params'] == expected_url_params


@pytest.mark.parametrize(
    'args, params, expected_url_params',
    [
        pytest.param(
            {
                'name': 'address', 'element_to_change': 'fqdn', 'element_value': '1.1.1.1'
            },
            integration_panorama_params,
            {
                'xpath': '/config/devices/entry/device-group/entry[@name=\'Lab-Devices\']/address'
                         '/entry[@name="address"]/fqdn',
                'element': '<fqdn>1.1.1.1</fqdn>', 'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
            }

        ),
        pytest.param(
            {
                'name': 'address', 'element_to_change': 'ip_range', 'element_value': '1.1.1.1-1.1.1.8'
            },
            integration_panorama_params,
            {
                'xpath': '/config/devices/entry/device-group/entry[@name=\'Lab-Devices\']'
                         '/address/entry[@name="address"]/ip-range',
                'element': '<ip-range>1.1.1.1-1.1.1.8</ip-range>',
                'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
            }

        ),
        pytest.param(
            {
                'name': 'address', 'element_to_change': 'tag', 'element_value': 'tag1,tag2'
            },
            integration_firewall_params,
            {
                'xpath': '/config/devices/entry/vsys/entry[@name=\'vsys1\']/address/entry[@name="address"]/tag',
                'element': '<tag><member>tag1</member><member>tag2</member></tag>',
                'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
            }

        )
    ]
)
def test_pan_os_edit_address_group_command_main_flow(mocker, args, params, expected_url_params):
    """
    Given:
    - Panorama instance configuration and fqdn object of an address to edit.
    - Panorama instance configuration and ip-range object of an address to edit.
    - Firewall instance configuration and tag object of an address to edit.

    When:
    - running the pan-os-edit-address through the main flow.

    Then:
    - make sure the xpath and the request is correct for both panorama/firewall.
    """
    from Panorama import main

    mock_request = mocker.patch(
        "Panorama.http_request",
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'command', return_value='pan-os-edit-address')

    main()

    assert mock_request.call_args.kwargs['params'] == expected_url_params


@pytest.mark.parametrize(
    'args, params, expected_url_params',
    [
        pytest.param(
            {
                'show_uncommitted': 'true'
            },
            integration_panorama_params,
            {
                'type': 'config', 'action': 'get', 'key': 'thisisabogusAPIKEY!',
                'xpath': "/config/devices/entry/device-group/entry[@name='Lab-Devices']/application-group"
            }
        ),
        pytest.param(
            {
                'show_uncommitted': 'true'
            },
            integration_firewall_params,
            {
                'type': 'config', 'action': 'get', 'key': 'thisisabogusAPIKEY!',
                'xpath': "/config/devices/entry/vsys/entry[@name='vsys1']/application-group"
            }
        )
    ]
)
def test_pan_os_list_application_groups_command_main_flow(mocker, args, params, expected_url_params):
    """
    Given:
     - Panorama instance configuration to retrieve all un-committed applications-groups.
     - Firewall instance configuration to retrieve all un-committed applications-groups.

    When:
     - running the pan-os-list-application-groups through the main flow.

    Then:
     - make sure the context output is parsed correctly for both un-committed and committed cases.
     - make sure the xpath and the request is correct for both panorama/firewall.
    """
    from Panorama import main

    mock_request = mocker.patch(
        "Panorama.http_request", return_value=load_json('test_data/list_application_groups_un_committed.json')
    )
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'command', return_value='pan-os-list-application-groups')
    result = mocker.patch('demistomock.results')

    main()

    assert list(result.call_args.args[0]['EntryContext'].values())[0] == [
        {'Applications': ['application-3'], 'Members': 1, 'Name': 'test'},
        {'Applications': ['application-1', 'application-2'], 'Members': 2, 'Name': 'test-2'}
    ]
    assert mock_request.call_args.kwargs['params'] == expected_url_params


@pytest.mark.parametrize(
    'args, params, expected_url_params',
    [
        pytest.param(
            {
                'name': 'test', 'applications': 'application1,application2', 'device-group': 'test-device-group'
            },
            integration_panorama_params,
            {
                'xpath': "/config/devices/entry/device-group/entry[@name='test-device-group']"
                         "/application-group/entry[@name='test']",
                'element': '<members><member>application1</member><member>application2</member></members>',
                'action': 'set', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
            }
        ),
        pytest.param(
            {
                'name': 'test', 'applications': 'application1,application2'
            },
            integration_firewall_params,
            {
                'xpath': "/config/devices/entry/vsys/entry[@name='vsys1']/application-group/entry[@name='test']",
                'element': '<members><member>application1</member><member>application2</member></members>',
                'action': 'set', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
            }
        )
    ]
)
def test_pan_os_create_application_group_command_main_flow(mocker, args, params, expected_url_params):
    """
    Given:
     - Panorama instance configuration and arguments to create an application group.
     - Firewall instance configuration and arguments to create an application group.

    When:
     - running the pan-os-create-application-group through the main flow.

    Then:
     - make sure the xpath and the request is correct for both panorama/firewall.
     - make sure the context is returned correctly.
    """
    from Panorama import main

    mock_request = mocker.patch(
        "Panorama.http_request",
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'command', return_value='pan-os-create-application-group')
    result = mocker.patch('demistomock.results')

    main()
    assert list(result.call_args.args[0]['EntryContext'].values())[0] == {
        'Name': 'test', 'Applications': ['application1', 'application2'], 'Members': 2
    }
    assert mock_request.call_args.kwargs['params'] == expected_url_params


class TestPanOSEditApplicationGroupCommand:

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'name': 'test', 'applications': 'application-2', 'action': 'add'
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry/device-group/entry[@name='Lab-Devices']"
                             "/application-group/entry[@name='test']/members",
                    'element': '<members><member>application-1</member><member>application-2</member></members>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'name': 'test', 'applications': 'application-2', 'action': 'add'
                },
                integration_firewall_params,
                {
                    'xpath': "/config/devices/entry/vsys/entry[@name='vsys1']/application-group/"
                             "entry[@name='test']/members",
                    'element': '<members><member>application-2</member><member>application-1</member></members>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            )
        ]
    )
    def test_pan_os_edit_application_group_main_flow_add_action(self, mocker, args, params, expected_url_params):
        """
        Tests cases where action == 'add'

        Given:
        - Panorama instance configuration and applications object of an application-group to add.
        - Firewall instance configuration and applications object of an application-group to add.

        When:
        - running the pan-os-edit-application-group through the main flow.

        Then:
        - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        responses = [
            {
                'response': {
                    '@status': 'success', '@code': '19', 'result': {
                        '@total-count': '1', '@count': '1', 'members': {'member': 'application-1'}
                    }
                }
            },
            {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}},
            {
                'response': {
                    '@status': 'success', '@code': '19',
                    'result': {
                        '@total-count': '1', '@count': '1', 'members': {
                            '@admin': 'admin', '@dirtyId': '809', '@time': '2022/09/14 04:12:11',
                            'member': [
                                {
                                    '@admin': 'admin', '@dirtyId': '809',
                                    '@time': '2022/09/14 04:12:11', '#text': 'application-1'
                                },
                                {
                                    '@admin': 'admin', '@dirtyId': '809',
                                    '@time': '2022/09/14 04:12:11', '#text': 'application-2'
                                }
                            ]
                        }
                    }
                }
            }
        ]

        mock_request = mocker.patch("Panorama.http_request", side_effect=responses)
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-application-group')

        main()
        assert mock_request.mock_calls[1].kwargs['params']['xpath'] == expected_url_params['xpath']
        assert 'application-1' in mock_request.mock_calls[1].kwargs['params']['element']
        assert 'application-2' in mock_request.mock_calls[1].kwargs['params']['element']

    @pytest.mark.parametrize(
        'args, params, expected_url_params',
        [
            pytest.param(
                {
                    'name': 'test', 'applications': 'application-2', 'action': 'remove'
                },
                integration_panorama_params,
                {
                    'xpath': "/config/devices/entry/device-group/entry[@name='Lab-Devices']/application-group/"
                             "entry[@name='test']/members",
                    'element': '<members><member>application-1</member></members>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }
            ),
            pytest.param(
                {
                    'name': 'test', 'applications': 'application-2', 'action': 'remove'
                },
                integration_firewall_params,
                {
                    'xpath': "/config/devices/entry/vsys/entry[@name='vsys1']/application-group/entry"
                             "[@name='test']/members",
                    'element': '<members><member>application-1</member></members>',
                    'action': 'edit', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
                }

            )
        ]
    )
    def test_pan_os_edit_application_group_main_flow_remove_action(self, mocker, args, params, expected_url_params):
        """
        Tests cases where action == 'remove'

        Given:
        - Panorama instance configuration and an application object of an application-group to remove.
        - Firewall instance configuration and an application object of an application-group to remove.

        When:
        - running the pan-os-edit-application-group through the main flow.

        Then:
        - make sure the xpath and the request is correct for both panorama/firewall.
        """
        from Panorama import main

        responses = [
            {
                'response': {
                    '@status': 'success', '@code': '19', 'result': {
                        '@total-count': '1', '@count': '1', 'members': {'member': ['application-1', 'application-2']}
                    }
                }
            },
            {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}},
            {
                'response': {
                    '@status': 'success', '@code': '19',
                    'result': {
                        '@total-count': '1', '@count': '1', 'members': {
                            '@admin': 'admin', '@dirtyId': '809', '@time': '2022/09/14 04:12:11',
                            'member': [
                                {
                                    '@admin': 'admin', '@dirtyId': '809',
                                    '@time': '2022/09/14 04:12:11', '#text': 'application-1'
                                }
                            ]
                        }
                    }
                }
            }
        ]

        mock_request = mocker.patch("Panorama.http_request", side_effect=responses)
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'args', return_value=args)
        mocker.patch.object(demisto, 'command', return_value='pan-os-edit-application-group')

        main()
        assert mock_request.mock_calls[1].kwargs['params'] == expected_url_params


@pytest.mark.parametrize(
    'args, params, expected_url_params',
    [
        pytest.param(
            {
                'name': 'test', 'applications': 'application-2', 'action': 'remove'
            },
            integration_panorama_params,
            {
                'xpath': "/config/devices/entry/device-group/entry[@name='Lab-Devices']/"
                         "application-group/entry[@name='test']",
                'action': 'delete', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
            }
        ),
        pytest.param(
            {
                'name': 'test', 'applications': 'application-2', 'action': 'remove'
            },
            integration_firewall_params,
            {
                'xpath': "/config/devices/entry/vsys/entry[@name='vsys1']/application-group/entry[@name='test']",
                'action': 'delete', 'type': 'config', 'key': 'thisisabogusAPIKEY!'
            }
        )
    ]
)
def test_pan_os_delete_application_group_command_main_flow(mocker, args, params, expected_url_params):
    """
    Given:
     - Panorama instance with a name of the application-group to delete.
     - Firewall instance with a name of the application-group to delete.

    When:
     - running the pan-os-delete-application-group through the main flow.

    Then:
     - make sure the xpath/element and the request is correct for both panorama/firewall.
    """
    from Panorama import main

    mock_request = mocker.patch(
        "Panorama.http_request",
        return_value={'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    )
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'command', return_value='pan-os-delete-application-group')

    main()
    assert mock_request.call_args.kwargs['params'] == expected_url_params


@pytest.mark.parametrize(
    'args, params, expected_url_params',
    [
        pytest.param(
            {
                'IPs': '2.2.2.2', 'tag': 'test'
            },
            integration_firewall_params,
            {'type': 'user-id',
             'cmd': '<uid-message><version>2.0</version><type>update</type><payload><register><entry ip="2.2.2.2" '
                    'persistent="1"><tag><member>test</member></tag></entry></register></payload></uid-message>',
             'key': 'thisisabogusAPIKEY!',
             'vsys': 'vsys1'}
        ),
        pytest.param(
            {
                'IPs': '2.2.2.2', 'tag': 'test'
            },
            integration_panorama_params,
            {'type': 'user-id',
             'cmd': '<uid-message><version>2.0</version><type>update</type><payload><register><entry ip="2.2.2.2" '
                    'persistent="1"><tag><member>test</member></tag></entry></register></payload></uid-message>',
             'key': 'thisisabogusAPIKEY!'}
        )
    ]
)
def test_pan_os_register_ip_tag_command_main_flow(mocker, args, params, expected_url_params):
    """
    Given:
     - Panorama instance with IP tag to register (without vsys).
     - Firewall instance with IP tag to register (with vsys).

    When:
     - running the pan-os-register-ip-tag through the main flow.

    Then:
     - make sure the params and the request is correct for both panorama/firewall.
    """
    from Panorama import main

    mock_request = mocker.patch(
        "Panorama.http_request",
        return_value={'response': {'@status': 'success', 'result': {'uid-response': {'version': '2.0',
                                                                                     'payload': {'register': None}}}}}
    )
    mocker.patch('Panorama.get_pan_os_major_version', return_value=9)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'command', return_value='pan-os-register-ip-tag')

    main()
    assert mock_request.call_args.kwargs['body'] == expected_url_params


@pytest.mark.parametrize(
    'args', [
        {'ip_netmask': '1', 'ip_range': '2', 'fqdn': '3', 'ip_wildcard': '4', 'name': 'test'},
        {'ip_netmask': '1', 'ip_range': '2', 'fqdn': '3', 'name': 'test'},
        {'ip_netmask': '1', 'ip_range': '2', 'name': 'test'},
        {'ip_netmask': '1', 'fqdn': '3', 'name': 'test'},
        {'ip_range': '2', 'fqdn': '3', 'name': 'test'},
        {'ip_range': '2', 'fqdn': '3', 'ip_wildcard': '4', 'name': 'test'},
    ]
)
def test_pan_os_create_address_main_flow_error(args):
    """
    Given:
     - more than one ip_netmask/ip_range/fqdn/ip_wildcard as command arguments

    When:
     - running the panorama_create_address_command function

    Then:
     - make sure an exception is raised saying only one of ip_netmask/ip_range/fqdn/ip_wildcard can
        be the command input.
    """
    from Panorama import panorama_create_address_command

    with pytest.raises(DemistoException):
        panorama_create_address_command(args)


@pytest.mark.parametrize(
    "device_group, vsys, response, args, error", [
        (
            "test",
            "",
            '<response status="success" code="19"> \
                <result total-count="0" count="0"> \
                </result> \
            </response>',
            {"name": "test", "tag": "not exist"},
            "Failed to create the address object since the tags `{'not exist'}` does not exist. "
            "You can use the `create_tag` argument to create the tag."
        ),
        (
            "",
            "vsys1",
            '<response status="success" code="19"> \
                <result total-count="1" count="1"> \
                    <tag admin="admin" dirtyId="3" time="2023/04/23 01:41:22"> \
                        <entry name="exist" admin="admin" dirtyId="3" time="2023/04/23 01:18:03"/> \
                    </tag> \
                </result> \
            </response>',
            {"name": "test", "tag": "exist, not exist", 'create_tag': 'Yes'},
            'Please specify exactly one of the following arguments: fqdn, ip_netmask, ip_range, ip_wildcard.'
        ),
    ]
)
def test_pan_os_create_address_with_not_exist_tag(mocker, device_group, vsys, response, args, error):
    """
    Given:
     - Tags that does not exist in the system as command arguments

    When:
     - Running the panorama_create_address_command function

    Then:
     - Make sure an exception is raised saying only tags that already exist in system can be the command input.
    """
    from Panorama import panorama_create_address_command
    mocker.patch('Panorama.DEVICE_GROUP', device_group)
    mocker.patch('Panorama.VSYS', vsys)
    mocker.patch('Panorama.URL', 'https://example.com')

    with requests_mock.Mocker() as m:
        m.get('https://example.com', text=response, status_code=200)
        m.post('https://example.com', text=response, status_code=200)

        with pytest.raises(DemistoException) as e:
            panorama_create_address_command(args)

        assert e.value.message == error


""" FETCH INCIDENTS """


class TestFetchIncidentsHelperFunctions:

    @pytest.mark.parametrize('query, last_fetch, expected_result',
                             fetch_incidents_input.test_add_time_filter_to_query_parameter_args)
    def test_add_time_filter_to_query_parameter(self, query, last_fetch, expected_result):
        """
        Given:
            - a query from parameters
        When:
            - every fetch incidents cycle starts
        Then:
            - add_time_filter_to_query_parameter function will append time_generated parameter to the original query to filleter
              according to the queries log type last fetch time.
        """
        from Panorama import add_time_filter_to_query_parameter
        assert add_time_filter_to_query_parameter(query, last_fetch, 'time_generated') == expected_result

    @pytest.mark.parametrize('params, expected_result', fetch_incidents_input.test_parse_queries_args)
    def test_log_types_queries_to_dict(self, params, expected_result):
        """
        Given:
        - valid parameters dictionary

        When:
        - test_log_types_queries_to_dict function is called

        Then:
        - assert that the returned queries_dict value is valid
        """
        from Panorama import log_types_queries_to_dict
        assert log_types_queries_to_dict(params) == expected_result

    def test_incident_entry_to_incident_context(self):
        """
        Given:
        - raw incident entry represented by a dictionary

        When:
        - incident_entry_to_incident_context function is called

        Then:
        - assert that the returned context formatted incident entry is valid
        """
        from Panorama import incident_entry_to_incident_context, DATE_FORMAT
        raw_entry = {'seqno': '1', 'time_generated': '2022/01/01 12:00', 'type': 'TYPE', 'device_name': 'dummy_device'}
        if occured := dateparser.parse('2022/01/01 12:00', settings={'TIMEZONE': 'UTC'}):
            context_entry = {
                'name': 'dummy_device 1',
                'occurred': occured.strftime(DATE_FORMAT),
                'rawJSON': json.dumps(raw_entry),
            }
        assert incident_entry_to_incident_context(raw_entry) == context_entry

    @pytest.mark.parametrize('last_fetch_dict, first_fetch, queries_dict, expected_result',
                             fetch_incidents_input.test_get_fetch_start_datetime_dict_args)
    @freeze_time("2022-01-02 11:00:00 UTC")
    def test_get_fetch_start_datetime_dict(self, last_fetch_dict, first_fetch, queries_dict, expected_result):
        """
        Given:
        - last fetch dictionary
        - first fetch parameter
        - queries dictionary from parameters

        When:
        - get_fetch_start_datetime_dict function is called

        Then:
        - assert that the updated dictionary with fetch start time per log_type is valid
        """
        from Panorama import get_fetch_start_datetime_dict
        result_dict = get_fetch_start_datetime_dict(last_fetch_dict, first_fetch, queries_dict)
        assert fetch_incidents_input.assert_datetime_objects(
            result_dict.get('X_log_type'), expected_result.get('X_log_type'))
        assert fetch_incidents_input.assert_datetime_objects(
            result_dict.get('Y_log_type'), expected_result.get('Y_log_type'))

    @pytest.mark.parametrize('incident_entries, expected_result',
                             fetch_incidents_input.test_parse_incident_entries_args)
    def test_get_parsed_incident_entries(self, incident_entries, expected_result):
        from Panorama import get_parsed_incident_entries, LastFetchTimes, LastIDs

        last_id_dict = LastIDs()
        last_fetch_dict = LastFetchTimes(Url='2022/01/01 12:00:00')

        res = get_parsed_incident_entries({'Url': incident_entries}, last_fetch_dict, last_id_dict)

        assert last_id_dict.get('Url') == expected_result[0]
        assert last_fetch_dict['Url'] == expected_result[1]  # type: ignore
        assert res == expected_result[2]

    @pytest.mark.parametrize('incident_entries_dict, last_fetch_dict, last_id_dict, expected_result',
                             fetch_incidents_input.get_parsed_incident_entries_args)
    def test_get_parsed_incident_entries_2(self, mocker, incident_entries_dict, last_fetch_dict, last_id_dict, expected_result):
        from Panorama import get_parsed_incident_entries

        assert get_parsed_incident_entries(incident_entries_dict, last_fetch_dict, last_id_dict) == expected_result

    @pytest.mark.parametrize('response, debug_msg, expected_result',
                             fetch_incidents_input.get_query_entries_by_id_request_args)
    def test_get_query_entries_by_id_request(self, mocker, response, debug_msg, expected_result):
        """
        Given:
            - A valid Panorama job id.

        When:
            1. The Panorama job has already finished.
            2. The Panorama job is still running (not finished).

        Then:
            1. Verify the command output is the returned response, and the debug message is called with 'FIN' status.
            2. Retry to query the job status in 1 second, and return empty dict if max retries exceeded.
         """
        from Panorama import get_query_entries_by_id_request
        mocker.patch('Panorama.http_request', return_value=response)
        assert get_query_entries_by_id_request('000', 1) == expected_result


class TestFetchIncidentsFlows:
    def test_first_fetch_with_no_incidents_flow(self, mocker):
        """
        Given:
        - first fetch cycle.

        When:
        - no incident returned from fetch request.

        Then:
        - no incidents should be returned.
        """

        from Panorama import fetch_incidents
        last_run = {}
        first_fetch = '24 hours'
        queries_dict = {'X_log_type': "(receive_time geq '2021/01/22 08:00:00)"}
        max_fetch = {'X_log_type': 10}

        mocker.patch('Panorama.get_query_entries', return_value={})

        new_last_run, incident_entries_list = fetch_incidents(
            last_run, first_fetch, queries_dict, max_fetch, 5)

        assert incident_entries_list == []
        assert new_last_run['last_fetch_dict'] == {'X_log_type': ''}
        assert new_last_run['last_id_dict'] == {}

    def test_first_fetch_with_one_incident_flow(self, mocker):
        """
        Given:
        - first fetch cycle.

        When:
        - using fetch incidents.
        - one incident returned from fetch request.

        Then:
        - The only incident should be returned.
        - X_log_type last fetch should be created.
        - X_log_type last id should be created.
        """
        from Panorama import fetch_incidents
        last_run = {}
        first_fetch = '24 hours'
        queries_dict = {'X_log_type': "(receive_time geq '2021/01/01 08:00:00)"}
        max_fetch = {'X_log_type': 10}

        raw_entries = {'seqno': '000000001', 'type': 'X_log_type', 'time_generated': '2022/1/1 12:00:00',
                       'device_name': 'device_for_test'}
        expected_parsed_incident_entries = {'name': 'device_for_test 000000001', 'occurred': '2022-01-01T12:00:00Z',
                                            'rawJSON': json.dumps(raw_entries)}
        fetch_start_datetime_dict = {'X_log_type': dateparser.parse('2022/1/1 11:00:00', settings={'TIMEZONE': 'UTC'})}

        mocker.patch('Panorama.get_query_entries', return_value=[raw_entries])
        mocker.patch('Panorama.get_fetch_start_datetime_dict', return_value=fetch_start_datetime_dict)

        new_last_run, incident_entries_dict = fetch_incidents(
            last_run, first_fetch, queries_dict, max_fetch, 5)

        assert incident_entries_dict[0] == expected_parsed_incident_entries
        assert new_last_run['last_fetch_dict'].get('X_log_type', '') == '2022-01-01 12:00:00'
        assert new_last_run['last_id_dict'].get('X_log_type', '') == {'device_for_test': '000000001'}

    def test_second_fetch_with_no_incidents_flow(self, mocker):
        """
        Given:
        - second fetch cycle.

        When:
        - using fetch incidents.
        - no new incidents are returned from the fetch request.

        Then:
        - no fetch incidents should be returned.
        - last_fetch_dict X_log_type value should not be updated.
        - last_id_dict X_log_type value should not be updated.
        """
        from Panorama import fetch_incidents
        last_run = {'last_fetch_dict': {'X_log_type': '2022-01-01T12:00:00'},
                    'last_id_dict': {'X_log_type': '000000001'}}
        first_fetch = '24 hours'
        queries_dict = {'X_log_type': "(receive_time geq '2021/01/01 08:00:00)"}
        max_fetch = {'X_log_type': 10}

        raw_entries = []
        expected_parsed_incident_entries = []

        fetch_start_datetime_dict = {'X_log_type': dateparser.parse('2022/1/1 12:00:00', settings={'TIMEZONE': 'UTC'})}

        mocker.patch('Panorama.get_query_entries', return_value=raw_entries)
        mocker.patch('Panorama.get_fetch_start_datetime_dict', return_value=fetch_start_datetime_dict)

        new_last_run, incident_entries_dict = fetch_incidents(
            last_run, first_fetch, queries_dict, max_fetch, 5)

        assert incident_entries_dict == expected_parsed_incident_entries
        assert new_last_run['last_fetch_dict'].get('X_log_type', '') == '2022-01-01T12:00:00'
        assert new_last_run['last_id_dict'].get('X_log_type', '') == '000000001'

    def test_second_fetch_with_two_incidents_with_same_log_type_flow(self, mocker):
        """
        Given:
        - second fetch cycle with.

        When:
        - using fetch incidents.
        - one incident with an existing log type is returned (X_log_type).
        - the incident has a time generated value that is greater than last fetch time.

        Then:
        - the fetched incident should be returned.
        - last_fetch_dict X_log_type value should be updated.
        - last_id_dict X_log_type value should be updated.
        """
        from Panorama import fetch_incidents
        last_run = {'last_fetch_dict': {'X_log_type': '2022-01-01 13:00:00'},
                    'last_id_dict': {'X_log_type': {'dummy_device': '000000001'}}}
        first_fetch = '24 hours'
        queries_dict = {'X_log_type': "(receive_time geq '2021/01/01 08:00:00)"}
        max_fetch = {'X_log_type': 10}

        raw_entries = [{'seqno': '000000002', 'type': 'X_log_type', 'time_generated': '2022/1/1 13:00:00',
                        'device_name': 'dummy_device'}]

        expected_parsed_incident_entries = [{'name': 'dummy_device 000000002', 'occurred': '2022-01-01T13:00:00Z',
                                             'rawJSON': json.dumps(raw_entries[0])}]
        fetch_start_datetime_dict = {'X_log_type': dateparser.parse('2022/1/1 12:00:00', settings={'TIMEZONE': 'UTC'})}

        mocker.patch('Panorama.get_query_entries', return_value=raw_entries)
        mocker.patch('Panorama.get_fetch_start_datetime_dict', return_value=fetch_start_datetime_dict)

        new_last_run, incident_entries_dict = fetch_incidents(
            last_run, first_fetch, queries_dict, max_fetch, 5)

        assert incident_entries_dict == expected_parsed_incident_entries
        assert new_last_run['last_fetch_dict'].get('X_log_type', '') == '2022-01-01 13:00:00'
        assert new_last_run['last_id_dict'].get('X_log_type', '') == {'dummy_device': '000000002'}

    def test_second_fetch_with_two_incidents_with_different_log_types_flow(self, mocker):
        """
        Given:
        - second fetch cycle.

        When:
        - using fetch incidents.
        - two incidents of two deferent log types (X_log_type, Y_log_type) are returned from the fetch time.
        - both incidents has the same generated time that is later than the last fetch run time.
        - one incident of X_log_type already have a last fetch run and last id, the second incident of type Y_log_Type don't.

        Then:
        - both incidents should be returned.
        - Y_log_type last fetch should be created.
        - Y_log_type last id is created.
        - X_log_type last fetch time will be updated.
        - X_log_type last id is updated.
        """
        from Panorama import fetch_incidents
        last_run = {'last_fetch_dict': {'X_log_type': '2022-01-01 12:00:00'},
                    'last_id_dict': {'X_log_type': {'dummy_device1': '000000001'}}}
        first_fetch = '24 hours'
        queries_dict = {'X_log_type': "(receive_time geq '2021/01/01 08:00:00)",
                        'Y_log_type': "(receive_time geq '2021/01/01 08:00:00)"}
        max_fetch = {'X_log_type': 10}

        raw_entries = [{'seqno': '000000002', 'type': 'X_log_type', 'time_generated': '2022-01-01 13:00:00',
                        'device_name': 'dummy_device1'},
                       {'seqno': '000000001', 'type': 'Y_log_type', 'time_generated': '2022-01-01 13:00:00',
                        'device_name': 'dummy_device2'}]

        fetch_incidents_request_result = {'X_log_type': [raw_entries[0]], 'Y_log_type': [raw_entries[1]]}

        expected_parsed_incident_entries = [{'name': 'dummy_device1 000000002', 'occurred': '2022-01-01T13:00:00Z',
                                             'rawJSON': json.dumps(raw_entries[0])},
                                            {'name': 'dummy_device2 000000001', 'occurred': '2022-01-01T13:00:00Z',
                                             'rawJSON': json.dumps(raw_entries[1])}]
        fetch_start_datetime_dict = {'X_log_type': dateparser.parse(
            '2022/1/1 11:00:00', settings={'TIMEZONE': 'UTC'}),
            'Y_log_type': dateparser.parse(
                '2022/1/1 11:00:00', settings={'TIMEZONE': 'UTC'})}

        mocker.patch('Panorama.fetch_incidents_request', return_value=fetch_incidents_request_result)
        mocker.patch('Panorama.get_fetch_start_datetime_dict', return_value=fetch_start_datetime_dict)

        new_last_run, incident_entries_dict = fetch_incidents(
            last_run, first_fetch, queries_dict, max_fetch, 5)

        assert incident_entries_dict == expected_parsed_incident_entries
        assert new_last_run['last_fetch_dict'].get('X_log_type', '') == '2022-01-01 13:00:00'
        assert new_last_run['last_id_dict'].get('X_log_type', '') == {'dummy_device1': '000000002'}
        assert new_last_run['last_fetch_dict'].get('Y_log_type', '') == '2022-01-01 13:00:00'
        assert new_last_run['last_id_dict'].get('Y_log_type', '') == {'dummy_device2': '000000001'}

    def test_second_fetch_with_two_incidents_with_different_log_types_and_different_last_fetch_flow(self, mocker):
        """
        Given:
        - second fetch cycle.

        When:
        - using fetch incidents.
        - two incidents of two deferent log types (X_log_type, Y_log_type) are returned from the fetch time.
        - both incidents has the same generated time that is later than the last fetch run time.
        - both incidents log types has a last fetch run and last id.

        Then:
        - both incidents should be returned.
        - Y_log_type last fetch should be created.
        - Y_log_type last id is created.
        - X_log_type last fetch time will be updated.
        - X_log_type last id is updated.
        """
        from Panorama import fetch_incidents
        last_run = {'last_fetch_dict': {'X_log_type': '2022-01-01 11:00:00', 'Y_log_type': '2022-01-01 13:00:00'},
                    'last_id_dict': {'X_log_type': {'dummy_device1': '000000001'}, 'Y_log_type': {'dummy_device2': '000000002'}}}
        first_fetch = '24 hours'
        queries_dict = {'X_log_type': "(receive_time geq '2021/01/01 08:00:00)",
                        'Y_log_type': "(receive_time geq '2021/01/01 08:00:00)"}
        max_fetch = {'X_log_type': 10}

        X_log_type_raw_entries = [{'seqno': '000000002', 'type': 'X_log_type', 'time_generated': '2022-01-01 13:00:00',
                                   'device_name': 'dummy_device1'}]
        Y_log_type_raw_entries = [{'seqno': '000000003', 'type': 'Y_log_type', 'time_generated': '2022-01-01 13:00:00',
                                   'device_name': 'dummy_device2'}]
        fetch_incidents_request_result = {'X_log_type': X_log_type_raw_entries, 'Y_log_type': Y_log_type_raw_entries}

        expected_parsed_incident_entries = [{'name': 'dummy_device1 000000002', 'occurred': '2022-01-01T13:00:00Z',
                                             'rawJSON': json.dumps(X_log_type_raw_entries[0])},
                                            {'name': 'dummy_device2 000000003', 'occurred': '2022-01-01T13:00:00Z',
                                             'rawJSON': json.dumps(Y_log_type_raw_entries[0])}]
        fetch_start_datetime_dict = {'X_log_type': dateparser.parse('2022/1/1 11:00:00', settings={'TIMEZONE': 'UTC'}),
                                     'Y_log_type': dateparser.parse('2022/1/1 11:00:00', settings={'TIMEZONE': 'UTC'})}

        mocker.patch('Panorama.fetch_incidents_request', return_value=fetch_incidents_request_result)
        mocker.patch('Panorama.get_fetch_start_datetime_dict', return_value=fetch_start_datetime_dict)

        new_last_run, incident_entries_dict = fetch_incidents(
            last_run, first_fetch, queries_dict, max_fetch, 5)

        assert incident_entries_dict == expected_parsed_incident_entries
        assert new_last_run['last_fetch_dict'].get('X_log_type', '') == '2022-01-01 13:00:00'
        assert new_last_run['last_id_dict'].get('X_log_type', '') == {'dummy_device1': '000000002'}
        assert new_last_run['last_fetch_dict'].get('Y_log_type', '') == '2022-01-01 13:00:00'
        assert new_last_run['last_id_dict'].get('Y_log_type', '') == {'dummy_device2': '000000003'}


def test_find_largest_id_per_device(mocker):
    """
    Given:
    - list of dictionaries representing raw entries, some contain seqno and some don't, some contain device_name and
    When:
        - find_largest_id_per_device is called.
    Then:
        - return a dictionary with the largest id per device and skip entries that don't contain seqno or device_name.
    """
    raw_entries = [{'device_name': 'dummy_device1', 'seqno': '000000001'},
                   {'device_name': 'dummy_device1', 'seqno': '000000002'},
                   {'device_name': 'dummy_device2', 'seqno': '000000001'},
                   {'device_name': 'dummy_device7'},
                   {'seqno': '000000008'}]
    from Panorama import find_largest_id_per_device
    res = find_largest_id_per_device(raw_entries)
    assert res == {'dummy_device1': '000000002', 'dummy_device2': '000000001'}


def test_filter_fetched_entries(mocker):
    """
    Given:
    - list of dictionares repesenting raw entries, some contain seqno and some don't,  some contain device_name and some don't.
    - dictionary with the largest id per device.
    When:
    - filter_fetched_entries is called.
    Then:
    - return a dictionary the entries that there id is larger then the id in the id_dict,
        without the entries that do not have seqno.
    """
    from Panorama import filter_fetched_entries
    raw_entries = {"log_type1": [{'device_name': 'dummy_device1'},
                                 {'device_name': 'dummy_device1', 'seqno': '000000002'},
                                 {'device_name': 'dummy_device2', 'seqno': '000000001'}],
                   "log_type2": [{'device_name': 'dummy_device3', 'seqno': '000000004'},
                                 {'seqno': '000000007'}]}
    id_dict = {"log_type1": {'dummy_device1': '000000003', 'dummy_device2': '000000000'}}
    res = filter_fetched_entries(raw_entries, id_dict)
    assert res == {'log_type1': [{'device_name': 'dummy_device2', 'seqno': '000000001'}],
                   'log_type2': [{'device_name': 'dummy_device3', 'seqno': '000000004'}]}


@pytest.mark.parametrize('name_match, name_contain, filters, expected_result',
                         mock_rules.get_mock_rules_and_application)
def test_build_xpath_filter(name_match, name_contain, filters, expected_result):
    from Panorama import build_xpath_filter
    mock_result = build_xpath_filter(name_match, name_contain, filters)
    assert mock_result == expected_result


@pytest.mark.parametrize('sample_file, expected_result_file',
                         [
                             ('test_data/prettify_edls_arr_sample.json',
                              'test_data/prettify_edls_arr_expected_result.json'),
                         ])
def test_prettify_edls_arr(sample_file, expected_result_file):
    """
    Given:
    - raw response from api represented by a dictionary

    When:
    - calling panorama_list_edls and there is only one edl in response

    Then:
    - assert that the returned value after prettify is correct
    """
    from Panorama import prettify_edls_arr

    with open(sample_file) as f:
        sample = json.loads(f.read())

    with open(expected_result_file) as f:
        expected_result = json.loads(f.read())

    mock_result = prettify_edls_arr(sample)
    assert mock_result == expected_result


def test_panorama_list_rules():
    import Panorama
    Panorama.URL = 'https://1.1.1.1:443/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    mock_version_xml = """
    <response status="success" code="19">
        <result total-count="1" count="1">
            <entry name="hehe 2">
                <to>
                    <member>any</member>
                </to>
                <from>
                    <member>any</member>
                </from>
                <source>
                    <member>any</member>
                </source>
                <destination>
                    <member>any</member>
                </destination>
                <source-user>
                    <member>any</member>
                </source-user>
                <category>
                    <member>any</member>
                </category>
                <application>
                    <member>dns</member>
                    <member>http</member>
                </application>
                <service>
                    <member>application-default</member>
                </service>
                <hip-profiles>
                    <member>any</member>
                </hip-profiles>
                <action>allow</action>
            </entry>
        </result>
    </response>
    """
    xpath = "/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules/entry"
    query = "(application/member eq 'dns')"

    with requests_mock.Mocker() as m:
        mock_request = m.get('https://1.1.1.1:443', text=mock_version_xml, status_code=200)
        rules = Panorama.panorama_list_rules(xpath, query=query)

    assert rules['application']['member'][0] == 'dns'
    assert mock_request.last_request.qs['xpath'][0] == \
        "/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[(application/member = 'dns')]"


def test_prettify_rules():
    """
    Given:
        - rule entry.
    When:
        - Running the prettify_rules method.
    Then:
        - Ensure no errors are raised.
    """
    from Panorama import prettify_rules
    test_rule = {
        '@name': 'test',
        '@uuid': '11111-111-111-11',
        'source': {'@loc': 'test',
                   'member': [{'@loc': 'test', '#text': 'text'},
                              'Failing String']}}
    prettier_rules = prettify_rules(test_rule)
    assert 'Failing String' in prettier_rules[0].get('Source')


@pytest.mark.parametrize('include_shared', ['No', 'Yes'])
def test_panorama_list_tags(mocker, include_shared):
    """
    Given:
        - The include_shared argument.
    When:
        - Running the pan_os_list_tag_command method.
    Then:
        - Ensure the returned tags list output and HR table is as expected.
    """
    import Panorama
    import requests
    Panorama.URL = 'https://1.1.1.1:443/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    Panorama.DEVICE_GROUP = ''
    tags_response_xml = """<response status="success" code="19"><result total-count="1" count="1">
        <tag admin="admin" dirtyId="6" time="2023/05/28 06:51:22">
            <entry name="tag1">
                <color>color13</color>
            </entry>
            <entry name="tag2">
                <color>color39</color>
            </entry>
            <entry name="tag3">
                <color>color39</color>
                <disable-override>no</disable-override>
                <comments>text text text</comments>
            </entry></tag></result></response>"""

    shared_tags_response_xml = """<response status="success" code="19"><result total-count="1" count="1">
        <tag admin="admin" dirtyId="6" time="2023/05/28 06:51:22">
            <entry name="sharedtag1">
                <color>color15</color>
            </entry>
            <entry name="sharedtag2">
                <color>color34</color>
            </entry></tag></result></response>"""

    tags_mock_response = MockedResponse(text=tags_response_xml, status_code=200)
    shared_tags_mock_response = MockedResponse(text=shared_tags_response_xml, status_code=200)

    mocker.patch.object(requests, 'request', side_effect=[tags_mock_response, shared_tags_mock_response])

    expected_outputs_tags_list = [{"name": "tag1", "color": "color13", "location": ""},
                                  {"name": "tag2", "color": "color39", "location": ""},
                                  {"name": "tag3", "color": "color39", "location": "",
                                   "disable-override": "no", "comments": "text text text"}]

    expected_hr_result = '### Tags:\n|Name|Color|Comment|Location|\n|---|---|---|---|\n| tag1 | color13' \
                         ' |  |  |\n| tag2 | color39 |  |  |\n| tag3 | color39 | text text text |  |\n'

    if include_shared == 'Yes':
        expected_outputs_tags_list.extend([
            {"name": "sharedtag1", "color": "color15", "location": "shared"},
            {"name": "sharedtag2", "color": "color34", "location": "shared"}
        ])
        expected_hr_result += '| sharedtag1 | color15 |  | shared |\n| sharedtag2 | color34 |  | shared |\n'

    command_results = Panorama.pan_os_list_tag_command({"include_shared_tags": include_shared})

    assert command_results.outputs == expected_outputs_tags_list
    assert command_results.readable_output == expected_hr_result


def test_pan_os_create_tag_command(mocker):
    """
    Given:
        - The tag name to create.
    When:
        - Running the pan_os_create_tag_command method.
    Then:
        - Ensure the returned response and readable outputs is as expected.
    """
    import Panorama
    import requests
    Panorama.URL = 'https://1.1.1.1:443/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    expected_text_response = '<response status="success" code="20"><msg>command succeeded</msg></response>'

    create_tag_mock_response = MockedResponse(text=expected_text_response, status_code=200)
    mocker.patch.object(requests, 'request', return_value=create_tag_mock_response)

    command_results = Panorama.pan_os_create_tag_command({"name": "testtag"})

    assert command_results.raw_response == {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    assert command_results.readable_output == 'The tag with name "testtag" was created successfully.'


@pytest.mark.parametrize('is_shared', [False, True])
def test_pan_os_edit_tag_command(mocker, is_shared):
    """
    Given:
        - The command arguments to edit the tag.
    When:
        1. The tag is not in a shared device group.
        2. The tag is in a shared device group.
        - Running the pan_os_edit_tag_command method.
    Then:
        - Ensure the request method call counts is according to if the tag is shared.
        - Ensure the returned response and readable outputs is as expected.
    """
    import Panorama
    import requests
    Panorama.URL = 'https://1.1.1.1:443/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    expected_first_text_response_if_shared = '<response status="error" code="12"><msg>' \
                                             '<line>Edit breaks config validity</line></msg></response>'
    expected_text_response = '<response status="success" code="20"><msg>command succeeded</msg></response>'
    expected_list_text_response = """<response status="success" code="19"><result total-count="1" count="1">
        <tag admin="admin" dirtyId="6" time="2023/05/28 06:51:22">
            <entry name="testtag">
                <color>color39</color>
                <disable-override>no</disable-override>
                <comments>text text text</comments>
            </entry></tag></result></response>"""
    expected_request_count = 4 if is_shared else 3

    edit_tag_mock_response = MockedResponse(text=expected_text_response, status_code=200)
    edit_tag_first_mock_response = MockedResponse(text=expected_first_text_response_if_shared, status_code=200)
    list_tag_mr = MockedResponse(text=expected_list_text_response, status_code=200)

    responses = [list_tag_mr, list_tag_mr, edit_tag_first_mock_response, edit_tag_mock_response] if is_shared else \
        [list_tag_mr, list_tag_mr, edit_tag_mock_response]
    request_mocker = mocker.patch.object(requests, 'request', side_effect=responses)

    command_results = Panorama.pan_os_edit_tag_command({"name": "testtag", "new_name": "newtesttag"})

    assert request_mocker.call_count == expected_request_count
    assert command_results.raw_response == {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    assert command_results.readable_output == 'The tag with name "testtag" was edited successfully.'


@pytest.mark.parametrize('is_shared', [False, True])
def test_pan_os_delete_tag_command(mocker, is_shared):
    """
    Given:
        - The tag name to delete.
    When:
        1. The tag is not in a shared device group.
        2. The tag is in a shared device group.
        - Running the pan_os_delete_tag_command method.
    Then:
        - Ensure the request method call counts is according to if the tag is shared.
        - Ensure the returned response and readable outputs is as expected.
    """
    import Panorama
    import requests
    Panorama.URL = 'https://1.1.1.1:443/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    Panorama.DEVICE_GROUP = 'somedevice'

    expected_first_text_response_if_shared = '<response status="success" code="7"><msg>Object doesn\'t exist</msg></response>'
    expected_second_text_response_if_shared = '<response status="success" code="19"><result total-count="2" count="2">' \
                                              '<entry name="somedevice"></entry></result></response>'
    expected_text_response = '<response status="success" code="20"><msg>command succeeded</msg></response>'
    expected_request_count = 3 if is_shared else 1

    delete_tag_mock_response = MockedResponse(text=expected_text_response, status_code=200)
    delete_tag_first_mock_response = MockedResponse(text=expected_first_text_response_if_shared, status_code=200)
    delete_tag_second_mock_response = MockedResponse(text=expected_second_text_response_if_shared, status_code=200)

    responses = [delete_tag_first_mock_response, delete_tag_second_mock_response,
                 delete_tag_mock_response] if is_shared else [delete_tag_mock_response]
    request_mocker = mocker.patch.object(requests, 'request', side_effect=responses)

    command_results = Panorama.pan_os_delete_tag_command({"name": "testtag", "new_name": "newtesttag"})

    assert request_mocker.call_count == expected_request_count
    assert command_results.raw_response == {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    assert command_results.readable_output == 'The tag with name "testtag" was deleted successfully.'


@pytest.mark.parametrize(
    "device_group, vsys, args, expected_response", [
        (
            "device_group",
            "",
            {"disable_override": True, "comment": ""},
            "<disable-override>yes</disable-override><comments></comments>"
        ),
        (
            "",
            "vsys1",
            {"disable_override": True, "comment": ""},
            "<comments></comments>"
        ),
    ]
)
def test_build_tag_element(mocker, device_group, vsys, args, expected_response):
    """
    Given:
     - given the disable_override argument that isn't supported with Firewall instances

    When:
     - Running the build_tag_element function

    Then:
     - Ensure that the expected response matches the actual response.
     (ignoring the disable_override argument when using Firewall instances)
    """
    from Panorama import build_tag_element
    mocker.patch('Panorama.DEVICE_GROUP', device_group)
    mocker.patch('Panorama.VSYS', vsys)
    response = build_tag_element(**args)
    assert response == expected_response


@pytest.mark.parametrize(
    ("element_to_change, context_element, element_value, current_objects_items, params_element, "
     "expected_exception, expected_warning, expected_warning_exit"),
    [
        ('tag', 'Tags', ['tag3'], ['tag3'], '<tag></tag>', False, False, False),  # Last tag
        ('tag', 'Tags', ['tag2'], ['tag3', 'tag2'], '<tag><member>tag3</member></tag>', False, False, False),  # Not last tag
        ('tag', 'Tags', ['nonexistent_tag'], ['tag1'], '', False, True, True),  # Non-existent tag > exit
        ('tag', 'Tags', ['nonexistent_tag', 'tag1'], ['tag1'], '<tag></tag>',
         False, True, False),  # Non-existent tag & existent > warning
        ('source', 'Source', ['source'], ['source'], '', True, False, False)  # raise exception
    ]
)
def test_panorama_edit_rule_items_remove(
        mocker, element_to_change, context_element, element_value, current_objects_items,
        params_element, expected_exception, expected_warning, expected_warning_exit):
    """
    Given:
     - element_to_change: The element to be changed in the rule.
     - element_value: The value(s) to be removed from the element.
     - current_objects_items: The current items present in the element.
     - params_element: The expected element value in the request body.
     - expected_exception: Flag indicating whether an exception is expected to be raised.
     - expected_warning: Flag indicating whether a warning is expected to be returned.
     - expected_warning_exit: Flag indicating whether the warning is expected to trigger an exit.

    When:
     - Running the panorama_edit_rule_items function to remove element from rule.

    Then:
     - Ensure that the expected response matches the actual response.
     - If expected_exception is True, assert that the correct exception is raised.
     - If expected_warning is True, assert that the correct warning message is returned.
     - If expected_warning_exit is True, assert that the warning triggers an exit.
     - If expected_warning_exit is False, assert the correct values in the request body, the success message,
       and the call to return_results.
    """
    from Panorama import panorama_edit_rule_items

    mocker.patch('Panorama.VSYS', 'vsys1')
    mocker.patch('Panorama.DEVICE_GROUP', '')
    mocker.patch('Panorama.panorama_get_current_element', return_value=current_objects_items)
    mock_return_warning = mocker.patch('Panorama.return_warning')
    request_mock = mocker.patch(
        'Panorama.http_request', return_value=TestPanoramaEditRuleCommand.EDIT_SUCCESS_RESPONSE
    )

    return_results_mock = mocker.patch('Panorama.return_results')

    if expected_exception:
        with pytest.raises(Exception, match=f'The object: {element_to_change} must have at least one item.'):
            panorama_edit_rule_items('rulename', element_to_change, element_value, 'remove')
    else:
        panorama_edit_rule_items('rulename', element_to_change, element_value, 'remove')

        if expected_warning:
            mock_return_warning.assert_called_once_with('The following tags do not exist: nonexistent_tag',
                                                        exit=expected_warning_exit)

        if not expected_warning_exit:
            assert request_mock.call_args.kwargs['body']['action'] == 'edit'
            assert request_mock.call_args.kwargs['body']['element'] == params_element
            assert return_results_mock.call_args[0][0]['HumanReadable'] == 'Rule edited successfully.'
            assert isinstance(return_results_mock.call_args[0][0]['EntryContext'][
                'Panorama.SecurityRule(val.Name == obj.Name)'][context_element], list)


def test_list_device_groups_names(mocker):
    from Panorama import list_device_groups_names

    mocker.patch('Panorama.get_device_groups_names', return_value=['Test-Device', 'Test-Device-2'])

    result = list_device_groups_names()

    assert result.outputs == ['Test-Device', 'Test-Device-2']
    assert result.readable_output == '### Device Group Names:\n|Group Name|\n|---|\n| Test-Device |\n| Test-Device-2 |\n'


def test_panorama_list_security_profile_group_command(mocker):
    """
    Given:
        - A Panorama instance with security profile groups.
    When:
        - Running the pan_os_list_security_profile_group_command.
    Then:
        - Ensure the returned security profile groups list output and HR table is as expected.
    """
    import Panorama
    import requests
    Panorama.URL = 'https://1.1.1.1:443/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    Panorama.DEVICE_GROUP = ''

    tags_response_xml = """<response status="success" code="19"><result total-count="2" count="2">
    <entry name="test1" loc="">
        <virus><member>default</member></virus><spyware><member>default</member></spyware>
        <vulnerability><member>default</member></vulnerability><url-filtering><member>default</member></url-filtering>
    </entry>
    <entry name="test2" loc="">
        <virus><member>default</member></virus><spyware><member>default</member></spyware>
        <vulnerability><member>default</member></vulnerability><url-filtering><member>default</member></url-filtering>
        <wildfire-analysis><member>test wildfire analysis</member></wildfire-analysis><file-blocking>
        <member>basic file blocking</member></file-blocking><data-filtering><member>test data filtering</member></data-filtering>
    </entry>
    </result></response>"""

    mock_response = MockedResponse(text=tags_response_xml, status_code=200)
    mocker.patch.object(requests, 'request', return_value=mock_response)

    expected_outputs_tags_list = [{'virus': 'default', 'spyware': 'default', 'vulnerability': 'default',
                                   'url-filtering': 'default', 'name': 'test1', 'location': ''},
                                  {'virus': 'default', 'spyware': 'default', 'vulnerability': 'default',
                                   'url-filtering': 'default', 'wildfire-analysis': 'test wildfire analysis',
                                   'file-blocking': 'basic file blocking', 'data-filtering': 'test data filtering',
                                   'name': 'test2', 'location': ''}]

    expected_hr_result = '### Security Profile Groups:\n|Name|Location|Antivirus Profile|Anti-Spyware Profile|Vulnerability ' \
                         'Protection Profile|URL Filtering Profile|File Blocking Profile|Data Filtering Profile|WildFire ' \
                         'Analysis Profile|\n|---|---|---|---|---|---|---|---|---|\n| test1 |  | default | default | default | ' \
                         'default |  |  |  |\n| test2 |  | default | default | default | default | basic file blocking | test '\
                         'data filtering | test wildfire analysis |\n'

    command_results = Panorama.pan_os_list_security_profile_groups_command({})

    assert command_results.outputs == expected_outputs_tags_list
    assert command_results.readable_output == expected_hr_result


def test_pan_os_create_security_profile_group_command(mocker):
    """
    Given:
        - The security profile groups name to create.
    When:
        - Running the pan_os_create_security_profile_group_command.
    Then:
        - Ensure the returned response and readable outputs is as expected.
    """
    import Panorama
    import requests
    Panorama.URL = 'https://1.1.1.1:443/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    expected_text_response = '<response status="success" code="20"><msg>command succeeded</msg></response>'

    mock_response = MockedResponse(text=expected_text_response, status_code=200)
    mocker.patch.object(requests, 'request', return_value=mock_response)

    command_results = Panorama.pan_os_create_security_profile_group_command({"group_name": "test_spg"})

    assert command_results.raw_response == {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    assert command_results.readable_output == 'Successfully created Security Profile Group: "test_spg"'


def test_pan_os_edit_security_profile_group_command(mocker):
    """
    Given:
        - The profile_to_change and the value arguments to edit in the security profile groups.
    When:
        - Running the pan_os_edit_security_profile_group_command.
    Then:
        - Ensure the returned response and readable outputs is as expected.
    """
    import Panorama
    import requests
    Panorama.URL = 'https://1.1.1.1:443/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    expected_text_response = '<response status="success" code="20"><msg>command succeeded</msg></response>'

    mock_response = MockedResponse(text=expected_text_response, status_code=200)
    mocker.patch.object(requests, 'request', return_value=mock_response)

    command_results = Panorama.pan_os_edit_security_profile_group_command({"group_name": "test_spg"})

    assert command_results.raw_response == {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    assert command_results.readable_output == 'Successfully edited Security Profile Group: "test_spg"'


def test_pan_os_delete_security_profile_group_command(mocker):
    """
    Given:
        - The security profile groups name to delete.
    When:
        - Running the pan_os_delete_security_profile_group_command.
    Then:
        - Ensure the returned response and readable outputs is as expected.
    """
    import Panorama
    import requests
    Panorama.URL = 'https://1.1.1.1:443/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    Panorama.DEVICE_GROUP = 'somedevice'

    expected_text_response = '<response status="success" code="20"><msg>command succeeded</msg></response>'

    mock_response = MockedResponse(text=expected_text_response, status_code=200)
    mocker.patch.object(requests, 'request', return_value=mock_response)

    command_results = Panorama.pan_os_delete_security_profile_group_command({"group_name": "test_spg"})
    assert command_results.raw_response == {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    assert command_results.readable_output == 'Successfully deleted Security Profile Group: "test_spg"'


@pytest.mark.parametrize(
    "profile_name, profile_type, device_group, action, threat_id, expected_xpath",
    [
        # test cases for device_group
        (
            'name',
            'vulnerability',
            'device_group',
            'set',
            '1000',
            (
                "/config/devices/entry[@name='localhost.localdomain']"
                "/device-group/entry[@name='device_group']"
                "/profiles/vulnerability/entry[@name='name']/threat-exception"
            )
        ),
        (
            'name',
            'spyware',
            'device_group',
            'set',
            '1000',
            (
                "/config/devices/entry[@name='localhost.localdomain']"
                "/device-group/entry[@name='device_group']"
                "/profiles/spyware/entry[@name='name']/threat-exception"
            )
        ),
        # test case for VSYS
        (
            'name',
            'vulnerability',
            None,
            'set',
            '1000',
            (
                "/config/devices/entry[@name='localhost.localdomain']"
                "/vsys/entry[@name='vsys']"
                "/profiles/vulnerability/entry[@name='name']/threat-exception"
            )
        ),
        (
            'name',
            'spyware',
            None,
            'set',
            '1000',
            (
                "/config/devices/entry[@name='localhost.localdomain']"
                "/vsys/entry[@name='vsys']"
                "/profiles/spyware/entry[@name='name']/threat-exception"
            )
        ),
        # test case for EDIT action type
        (
            'name',
            'spyware',
            'device_group',
            'edit',
            '1000',
            (
                "/config/devices/entry[@name='localhost.localdomain']"
                "/device-group/entry[@name='device_group']"
                "/profiles/spyware/entry[@name='name']/threat-exception"
                "/entry[@name='1000']"
            )
        ),
        (
            'name',
            'vulnerability',
            'device_group',
            'edit',
            '1000',
            (
                "/config/devices/entry[@name='localhost.localdomain']"
                "/device-group/entry[@name='device_group']"
                "/profiles/vulnerability/entry[@name='name']/threat-exception"
                "/entry[@name='1000']"
            )
        ),
        # test case for DELETE action type
        (
            'name',
            'vulnerability',
            'device_group',
            'delete',
            '1000',
            (
                "/config/devices/entry[@name='localhost.localdomain']"
                "/device-group/entry[@name='device_group']"
                "/profiles/vulnerability/entry[@name='name']/threat-exception"
                "/entry[@name='1000']"
            )
        ),
        (
            'name',
            'spyware',
            'device_group',
            'delete',
            '1000',
            (
                "/config/devices/entry[@name='localhost.localdomain']"
                "/device-group/entry[@name='device_group']"
                "/profiles/spyware/entry[@name='name']/threat-exception"
                "/entry[@name='1000']"
            )
        ),
        (
            'name',
            'spyware',
            None,
            'delete',
            '1000',
            (
                "/config/devices/entry[@name='localhost.localdomain']"
                "/vsys/entry[@name='vsys']"
                "/profiles/spyware/entry[@name='name']/threat-exception"
                "/entry[@name='1000']"
            )
        ),
    ]
)
def test_pan_os_xpath_creation_for_exception_crud(profile_name, profile_type, device_group, action, threat_id, expected_xpath):
    """
    Given:
        - A profile name, profile type, device group name, action, and threat ID.
    When:
        - Running build_xpath_for_profile_exception_commands function to generate the XPath.
    Then:
        - Ensure the returned XPath is correctly constructed for both Vulnerability Protection and Anti Spyware profiles.
    """
    import Panorama
    Panorama.VSYS = 'vsys'

    result = Panorama.build_xpath_for_profile_exception_commands(
        profile_name, profile_type, device_group, action, threat_id
    )
    assert result == expected_xpath


def test_pan_os_check_profile_type_by_given_profile_name(mocker):
    """
    Given:
        - A profile name that could exist in either 'Vulnerability Protection Profile' or 'Anti Spyware Profile'.
    When:
        - Checking the profile type by the given profile name.
    Then:
        - Ensure the correct profile type is returned or an appropriate exception is raised.
    """
    import Panorama

    mocker.patch('Panorama.get_all_profile_names_from_profile_type', side_effect=[
        ['profile_1', 'profile_2'],
        ['profile_3', 'profile_4'],
        [],
        ['profile_3'],
        ['profile_5'],
        ['profile_5'],
        [],
        []
    ])

    result = Panorama.check_profile_type_by_given_profile_name('profile_1', 'device_group')
    assert result == 'vulnerability'

    result = Panorama.check_profile_type_by_given_profile_name('profile_3', None)
    assert result == 'spyware'

    with pytest.raises(DemistoException, match="Profile name was found both in Vulnerability Protection Profiles "
                       "and in Anti Spyware Profiles. Please specify profile_type."):
        Panorama.check_profile_type_by_given_profile_name('profile_5', 'device_group')

    with pytest.raises(DemistoException, match="Profile name was not found in Vulnerability Protection Profiles "
                       "or in Anti Spyware Profiles."):
        Panorama.check_profile_type_by_given_profile_name('profile_6', 'device_group')


def test_pan_os_get_threat_id_from_predefined_threats(mocker):
    """
    Given:
        - A threat name that may match a threat name, ID, or CVE in the predefined threats list.
    When:
        - Searching for the threat ID using the provided threat name.
    Then:
        - Ensure the correct threat ID, name, and CVEs are returned, or an appropriate exception is raised.
    """
    import Panorama

    mock_predefined_threats = [
        {
            "@name": "10003",
            "threatname": "Test Threat 1",
            "cve": {"member": ["CVE-2023-1234"]}
        },
        {
            "@name": "10004",
            "threatname": "Test Threat 2",
            "cve": {"member": ["CVE-2023-5678"]}
        },
        {
            "@name": "10005",
            "threatname": "Test Threat 3",
            "cve": {"member": ["CVE-2023-9012"]}
        }
    ]

    mocker.patch.object(Panorama, 'get_predefined_threats_list', return_value=mock_predefined_threats)

    result = Panorama.get_threat_id_from_predefined_threats('Test Threat 1')
    assert result == ("10003", "Test Threat 1", ["CVE-2023-1234"])

    result = Panorama.get_threat_id_from_predefined_threats('10004')
    assert result == ("10004", "Test Threat 2", ["CVE-2023-5678"])

    result = Panorama.get_threat_id_from_predefined_threats('CVE-2023-9012')
    assert result == ("10005", "Test Threat 3", ["CVE-2023-9012"])

    with pytest.raises(DemistoException, match="Threat was not found."):
        Panorama.get_threat_id_from_predefined_threats('Nonexistent Threat')


def test_pan_os_add_profile_exception(mocker):
    """
    Given:
        - A profile name, profile type, threat name, and device group.
    When:
        - Running the `pan_os_add_profile_exception_command` to add an exception to a security profile.
    Then:
        - Ensure the returned response indicates the successful creation of the exception with the correct threat name and ID.
    """
    import Panorama

    mock_response = {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    mocker.patch.object(Panorama, 'http_request', return_value=mock_response)
    mocker.patch.object(Panorama, 'get_threat_id_from_predefined_threats', return_value=('1000', 'threatname', 'cve'))

    command_results = Panorama.pan_os_add_profile_exception_command(args={"profile_name": "test_spg",
                                                                          "threat_name": '1000',
                                                                          "profile_type": "Vulnerability Protection Profile",
                                                                          "device_group": 'device_group'})
    assert command_results.raw_response == {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    assert command_results.readable_output == (
        'Successfully created exception "threatname" with threat ID 1000 in the "test_spg" '
        'profile of type "vulnerability".'
    )


def test_pan_os_edit_profile_exception(mocker):
    """
    Given:
        - A profile name, profile type, threat name, and device group.
    When:
        - Running the `pan_os_edit_profile_exception_command` to edit an exception in a security profile.
    Then:
        - Ensure the returned response indicates the successful editing of the exception with the correct threat name and ID.
    """
    import Panorama
    Panorama.URL = 'https://1.1.1.1:443/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    Panorama.DEVICE_GROUP = 'device_group'

    mock_response = {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    mocker.patch.object(Panorama, 'http_request', return_value=mock_response)
    mocker.patch.object(Panorama, 'get_threat_id_from_predefined_threats', return_value=('1000', 'threatname', 'cve'))
    command_results = Panorama.pan_os_edit_profile_exception_command(args={"profile_name": "test_spg",
                                                                           "threat_name": '1000',
                                                                           "profile_type": "Vulnerability Protection Profile",
                                                                           "device_group": 'device_group'})
    assert command_results.raw_response == {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    assert command_results.readable_output == (
        'Successfully edited exception "threatname" with threat ID 1000 in the "test_spg" '
        'profile of type "vulnerability".'
    )


def test_pan_os_delete_profile_exception(mocker):
    """
    Given:
        - A profile name, profile type, threat name, and device group.
    When:
        - Running the `pan_os_delete_profile_exception_command` to delete an exception from a security profile.
    Then:
        - Ensure the returned response indicates the successful deletion of the exception with the correct threat name and ID.
    """
    import Panorama

    mock_response = {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    mocker.patch.object(Panorama, 'http_request', return_value=mock_response)
    mocker.patch.object(Panorama, 'get_threat_id_from_predefined_threats', return_value=('1000', 'threatname', 'cve'))

    command_results = Panorama.pan_os_delete_profile_exception_command(args={"profile_name": "test_spg",
                                                                             "threat_name": '1000',
                                                                             "profile_type": "Vulnerability Protection Profile",
                                                                             "device_group": 'device_group'})
    assert command_results.raw_response == {'response': {'@status': 'success', '@code': '20', 'msg': 'command succeeded'}}
    assert command_results.readable_output == (
        'Successfully deleted exception "threatname" with threat ID 1000 in the "test_spg" '
        'profile of type "vulnerability".'
    )


def test_pan_os_list_profile_exception(mocker):
    """
    Given:
        - A profile name and profile type.
    When:
        - Running the `pan_os_list_profile_exception_command` to list exceptions in a security profile.
    Then:
        - Ensure the returned response is of type `CommandResults` and the readable output lists the correct profile exceptions.
    """
    import Panorama
    Panorama.URL = 'https://1.1.1.1:443/'
    Panorama.API_KEY = 'thisisabogusAPIKEY!'
    Panorama.DEVICE_GROUP = 'device_group'
    mocker.patch.object(
        Panorama,
        'profile_exception_crud_requests',
        return_value=({'raw_response': {
            'response': {
                'result': {
                    'threat-exception': {
                        'entry': [
                            {
                                '@name': '10003',
                                'action': {'block': {}},
                                'exempt-ip': {'entry': {'@name': '192.168.1.1'}},
                                'packet-capture': 'yes',
                                '@admin': 'admin1',
                                '@dirtyId': 'dirty1',
                                '@time': '2024-08-14T12:00:00'
                            },
                            {
                                '@name': '10002',
                                'action': {'allow': {}},
                                'packet-capture': 'no',
                                '@admin': 'admin2',
                                '@dirtyId': 'dirty2',
                                '@time': '2024-08-14T12:00:00'
                            }
                        ]
                    }
                }
            },
        },
            'exception_id': 'id',
            'exception_name': 'name',
            'profile_type': 'vulnerability'})
    )

    mocker.patch.object(Panorama, 'get_threat_id_from_predefined_threats', return_value=('test', 'threatname', 'cve'))

    args = {"profile_name": "test_profile", "profile_type": "Vulnerability Protection Profile"}
    result = Panorama.pan_os_list_profile_exception_command(args)

    assert isinstance(result, CommandResults)

    expected_hr = [
        {
            "ID": "10003",
            "Name": 'threatname',
            "CVE": 'cve',
            "Action": "block",
            "Exempt IP": "192.168.1.1",
            "Packet Capture": "yes",
        },
        {
            "ID": "10002",
            "Name": 'threatname',
            "CVE": 'cve',
            "Action": "allow",
            "Exempt IP": "",
            "Packet Capture": "no",
        },
    ]

    expected_output = {
        'Name': 'test_profile',
        'Exception': [
            {
                'id': '10003',
                'name': 'threatname',
                'CVE': 'cve',
                'action': 'block',
                'packet-capture': 'yes',
                'exempt-ip': '192.168.1.1'
            },
            {
                'id': '10002',
                'name': 'threatname',
                'CVE': 'cve',
                'action': 'allow',
                'packet-capture': 'no',
            },
        ]
    }

    assert "Profile Exceptions" in result.readable_output

    for hr_entry in expected_hr:
        for _, value in hr_entry.items():
            assert value in result.readable_output

    assert result.outputs == expected_output
    assert result.outputs_prefix == 'Panorama.Vulnerability'
    assert result.outputs_key_field == 'Name'


def test_fetch_incidents_correlation(mocker: MockerFixture):
    '''
    Given:
        -
    When:
        -
    Then:
        -
    '''
    from Panorama import fetch_incidents, LastIDs, LastFetchTimes, LastRun, MaxFetch, QueryMap
    corr_logs = load_json('test_data/corr_logs.json')
    mock_get_query_entries = mocker.patch('Panorama.get_query_entries')

    last_fetch_dict = LastFetchTimes(Correlation='2024/04/08 07:22:54')
    last_id_dict = LastIDs(Correlation=0)
    max_fetch_dict = MaxFetch(Correlation=10)
    last_run = LastRun(
        last_fetch_dict=last_fetch_dict,
        last_id_dict=last_id_dict,
        max_fetch_dict=max_fetch_dict
    )

    # assert duplicates are removed:

    mock_get_query_entries.return_value = corr_logs[:5]
    _, entries = fetch_incidents(
        last_run, '2024/04/08 07:22:54', QueryMap(Correlation='query'), max_fetch_dict, 1
    )

    assert entries[0]["name"] == "Correlation 1"
    assert "CORRELATION" in entries[0]["rawJSON"]
    assert mock_get_query_entries.call_args_list[0].args == (
        "Correlation", "query and (match_time geq '2024/04/08 07:22:54')", 10, 1, 0
    )  # asserting that "match_time" is used instead of "time_generated".
    assert last_fetch_dict == LastFetchTimes(Correlation="2024-04-09 07:22:54")  # the max date
    assert last_id_dict == LastIDs(Correlation=4)
    assert max_fetch_dict == MaxFetch(Correlation=10)

    # test with dict from older versions

    last_id_dict['Correlation'] = cast(int, {})

    _, entries = fetch_incidents(
        last_run, '2024/04/08 07:22:54', QueryMap(Correlation='query'), max_fetch_dict, 1
    )
    assert entries[0]["name"] == "Correlation 1"


def test_fetch_incidents_offset(mocker: MockerFixture):
    '''
    Given: Panorama incidents.

    When: Using fetch-incidents command using offset to get the next incidents.

    Then: Assert the correct amount of incidents were fetched and the correct offset value was stored.

    '''
    from Panorama import fetch_incidents, LastIDs, LastFetchTimes, LastRun, MaxFetch, QueryMap, Offset
    corr_logs = load_json('test_data/corr_logs_time_dif.json')
    mock_get_query_entries = mocker.patch('Panorama.get_query_entries')

    last_fetch_dict = LastFetchTimes(Correlation='2024/04/08 07:22:54')
    last_id_dict = LastIDs()
    max_fetch_dict = MaxFetch(Correlation=5)
    offset_dict = Offset(Correlation=0)

    last_run = LastRun(
        last_fetch_dict=last_fetch_dict,
        last_id_dict=last_id_dict,
        max_fetch_dict=max_fetch_dict,
        offset_dict=offset_dict
    )

    # assert duplicates are removed:

    mock_get_query_entries.return_value = corr_logs[:5]
    new_last_run, entries = fetch_incidents(
        last_run, '2024/04/08 07:22:54', QueryMap(Correlation='query'), max_fetch_dict, 1
    )

    assert entries[0]["name"] == "Correlation 1"
    assert "CORRELATION" in entries[0]["rawJSON"]
    assert mock_get_query_entries.call_args_list[0].args == (
        "Correlation", "query and (match_time geq '2024/04/08 07:22:54')", 5, 1, 0
    )  # asserting that "match_time" is used instead of "time_generated".
    assert last_fetch_dict == LastFetchTimes(Correlation="2024-04-08 07:22:54")  # the max date
    assert last_id_dict == LastIDs(Correlation=5)
    assert max_fetch_dict == MaxFetch(Correlation=5)
    assert offset_dict == Offset(Correlation=5)

    mock_get_query_entries.return_value = corr_logs[5:]
    new_last_run, entries = fetch_incidents(
        new_last_run, '2024/04/08 07:22:54', QueryMap(Correlation='query'), max_fetch_dict, 1
    )

    assert entries[0]["name"] == "Correlation 6"
    assert "CORRELATION" in entries[0]["rawJSON"]
    assert mock_get_query_entries.call_args_list[1].args == (
        "Correlation", "query and (match_time geq '2024/04/08 07:22:54')", 5, 1, 5
    )  # asserting that "match_time" is used instead of "time_generated".
    assert last_fetch_dict == LastFetchTimes(Correlation="2024-04-08 07:22:55")  # the max date
    assert last_id_dict == LastIDs(Correlation=10)
    assert max_fetch_dict == MaxFetch(Correlation=5)
    assert offset_dict == Offset(Correlation=2)


def test_build_master_key_create_or_update_cmd():
    """
    Given:
        - Command arguments for updating Panorama / PAN-OS master key

    When:
        - Calling build_master_key_create_or_update_cmd.

    Assert:
        - Correct XML command string.
    """
    from Panorama import build_master_key_create_or_update_cmd

    # Set
    args = {
        'current_master_key': 'MyFakeMasterKey1',
        'new_master_key': 'MyFakeMasterKey2',
        'lifetime_in_hours': '2160',
        'reminder_in_hours': '1992',
    }
    # Arrange
    cmd = build_master_key_create_or_update_cmd(args, action='update')

    # Assert
    assert cmd == (
        '<request><master-key><lifetime>2160</lifetime><reminder>1992</reminder>'
        '<new-master-key>MyFakeMasterKey2</new-master-key>'
        '<current-master-key>MyFakeMasterKey1</current-master-key>'
        '<on-hsm>no</on-hsm></master-key></request>'
    )


def test_pan_os_create_master_key_command(requests_mock: RequestsMock):
    """
    Given:
        - Command arguments for creating Panorama / PAN-OS master key

    When:
        - Calling pan_os_create_master_key_command.

    Assert:
        - Correct human readable output and raw response.
    """
    from Panorama import pan_os_create_master_key_command, xml2json
    import Panorama

    # Set
    args = {'master_key': 'MyFakeMasterKey1', 'lifetime_in_hours': '2160', 'reminder_in_hours': '1992'}
    Panorama.URL = 'https://1.1.1.1:443/api/'

    xml_root = load_xml_root_from_test_file('test_data/create_master_key.xml')
    response_result = xml_root.find('result').text

    xml_response_text = ElementTree.tostring(xml_root, encoding='unicode')
    requests_mock.get(Panorama.URL, text=xml_response_text)

    # Arrange
    command_results: CommandResults = pan_os_create_master_key_command(args)

    # Assert
    assert command_results.readable_output == (
        f'{response_result}. \n\n⚠️ The current API key is no longer valid! (by design) '
        'Generate a new API key and update it in the integration instance configuration to keep using the integration.'
    )
    assert command_results.raw_response == json.loads(xml2json(xml_response_text))


def test_pan_os_get_master_key_details_command(mocker: MockerFixture, requests_mock: RequestsMock):
    """
    When:
        - Calling pan_os_get_master_key_command.

    Assert:
        - Correct human readable, context output, and raw response.
    """
    from Panorama import pan_os_get_master_key_details_command, xml2json
    import Panorama

    # Set
    Panorama.URL = 'https://1.1.1.1:443/api/'

    xml_root = load_xml_root_from_test_file('test_data/get_master_key.xml')
    xml_response_text = ElementTree.tostring(xml_root, encoding='unicode')
    requests_mock.get(Panorama.URL, text=xml_response_text)

    table_to_markdown = mocker.patch('Panorama.tableToMarkdown')

    # Arrange
    command_results: CommandResults = pan_os_get_master_key_details_command()
    table_name: str = table_to_markdown.call_args[0][0]
    table_data: dict = table_to_markdown.call_args[0][1]
    raw_response: dict = json.loads(xml2json(xml_response_text))

    # Assert
    assert table_name == 'Master Key Details'
    assert table_data == raw_response['response']['result']
    assert command_results.outputs == raw_response['response']['result']
    assert command_results.raw_response == raw_response


@patch("Panorama.run_op_command")
def test_show_jobs_id_not_found(patched_run_op_command):
    """
    Given:
        - A specific job_id (23)

    When:
        - running show_jobs function

    Then:
        - Ensure DemistoException is thrown with ann informative message (since the given ID does not exist in all devices)
    """
    from Panorama import UniversalCommand

    patched_run_op_command.side_effect = panos.errors.PanDeviceXapiError("job 23 not found")
    MockTopology = type('MockTopology', (), {'all': lambda *x, **y: [Panorama(hostname='123')]})

    with pytest.raises(DemistoException, match="The given ID 23 is not found in all devices of the topology."):
        UniversalCommand.show_jobs(topology=MockTopology(), id=23)
