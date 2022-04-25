import re

import Qualysv2
import pytest
import requests
from Qualysv2 import is_empty_result, format_and_validate_response, \
    parse_two_keys_dict, create_ip_list_dicts, build_args_dict, handle_general_result, \
    change_dict_keys, COMMANDS_ARGS_DATA, limit_ip_results, Client, build_host_list_detection_outputs, \
    COMMANDS_PARSE_AND_OUTPUT_DATA, validate_depended_args, Dict, validate_at_most_one_group, parse_raw_response, \
    get_simple_response_from_raw, validate_required_group

from CommonServerPython import DemistoException


class TestIsEmptyResult:
    def test_is_empty_xml_empty_input(self):
        """
        Given
            - A json parsed result from qualys
        When
            - result has no keys
        Then
            - return true since result is empty
        """
        reponse = {}
        res = is_empty_result(reponse)
        assert res

    def test_is_empty_xml_only_datetime(self):
        """
        Given
            - A json parsed result from qualys
        When
            - result has only datetime key
        Then
            - return true since result has no content
        """
        response = {'DATETIME': 'sometime'}
        res = is_empty_result(response)
        assert res

    def test_is_empty_xml_non_empty_result(self):
        """
        Given
            - A json parsed result from qualys
        When
            - result has some keys
        Then
            - return false since result has content
        """
        response = {'IP_SET': {'IP': ['1.1.1.1']},
                    'DATETIME': 'sometime'}
        res = is_empty_result(response)
        assert not res

    def test_is_empty_xml_none_result(self):
        """
        Given
            - A result from qualys
        When
            - result is None
        Then
            - return true
        """
        response = None
        assert is_empty_result(response)


class TestFormatAndValidateResponse:
    raw_xml_response_success = '''<?xml version="1.0" encoding="UTF-8" ?>
                           <!DOCTYPE SIMPLE_RETURN SYSTEM
                            "https://qualysapi.qg2.apps.qualys.com/api/2.0/simple_return.dtd">
                           <SIMPLE_RETURN><RESPONSE>
                           <DATETIME>2021-03-24T15:40:23Z</DATETIME>
                           <TEXT>IPs successfully added to Vulnerability Management</TEXT>
                           </RESPONSE></SIMPLE_RETURN>'''
    raw_xml_response_failue = '''<?xml version="1.0" encoding="UTF-8" ?>
                               <!DOCTYPE SIMPLE_RETURN SYSTEM
                               "https://qualysapi.qg2.apps.qualys.com/api/2.0/simple_return.dtd">
                               <SIMPLE_RETURN>
                               <RESPONSE><DATETIME>2021-03-24T16:35:44Z</DATETIME>
                               <CODE>1905</CODE><TEXT>IP(s) do not exist.</TEXT></RESPONSE></SIMPLE_RETURN>'''
    bad_format_raw_xml_response = '''<?xml version="1.0" encoding="UTF-8" ?>
                           <!DOCTYPE SIMPLE_RETURN SYSTEM
                           "https://qualysapi.qg2.apps.qualys.com/api/2.0/simple_return.dtd">
                           <SIMPLE_RETURN>
                           <RESPONSE><DATETIME>2021-03-24T16:35:44Z</DATETIME>
                           <CODE>1905</CODE><TEXT>IP(s) do not exist.</TEXT></RESPONSE>'''

    def test_format_and_validate_response_proper_response(self):
        """
        Given
            - raw xml response
        When
            - the response is valid
        Then
            - return the parsed response
        """
        raw_json_response = format_and_validate_response(self.raw_xml_response_success)
        assert raw_json_response.get('SIMPLE_RETURN').get('RESPONSE')
        assert not raw_json_response.get('CODE')

    def test_format_and_validate_response_error_response(self):
        """
        Given
            - raw xml response
        When
            - the response has an error code provided by qualys
        Then
            - raise a DemistoException
        """
        with pytest.raises(DemistoException):
            format_and_validate_response(self.raw_xml_response_failue)

    def test_format_and_validate_response_bad_format(self):
        """
        Given
            - raw xml response
        When
            - the xml format is incorrect
        Then
            - return empty dictionary
        """
        result = format_and_validate_response(self.bad_format_raw_xml_response)
        assert not result

    def test_format_and_validate_response_none(self):
        """
        Given
            - raw xml response
        When
            - the xml format is incorrect
        Then
            - return empty dictionary
        """
        raw_xml_response = None
        result = format_and_validate_response(raw_xml_response)
        assert not result

    def test_format_and_validate_response_json(self):
        """
        Given
            - raw json response
        When
            - the json response is formatted correctly
        Then
            - return the raw response
        """
        raw_json_response = '[{"ip": "1.1.1.1"},{"ip": "1.1.1.1"}]'
        result = format_and_validate_response(raw_json_response)
        assert len(result) == 2

    def test_format_and_validate_response_bad_json(self):
        """
        Given
            - raw json response
        When
            - the json response is formatted incorrectly
        Then
            - return empty result
        """
        raw_json_response = '[{"ip": "1.1.1.1",{"ip": "1.1.1.1"}]'
        result = format_and_validate_response(raw_json_response)
        assert not result

    PARSE_RAW_RESPONSE_INPUTS = [('[{"ip": "1.1.1.1"},{"ip": "1.1.1.1"}]', [{'ip': '1.1.1.1'}, {'ip': '1.1.1.1'}]),
                                 (raw_xml_response_success, {'SIMPLE_RETURN': {
                                     'RESPONSE': {'DATETIME': '2021-03-24T15:40:23Z',
                                                  'TEXT': 'IPs successfully added to Vulnerability Management'}}}),
                                 # Invalid case - should return empty dict
                                 ('[{"ip": "1.1.1.1"ip": "1.1.1.1"}]', {})]

    @pytest.mark.parametrize('response, expected', PARSE_RAW_RESPONSE_INPUTS)
    def test_parse_raw_response(self, response, expected):
        """
        Given
            - Response.
        When
            - Parsing the raw response.
        Then
            - Ensure expected object is returned from parsing.
        """
        assert parse_raw_response(response) == expected

    SIMPLE_FROM_RAW_INPUTS = [({'SIMPLE_RETURN': {'RESPONSE': {'DATETIME': '2021-03-24T15:40:23Z',
                                                               'TEXT': 'IPs successfully added to Vulnerability '
                                                                       'Management'}}},
                               {'DATETIME': '2021-03-24T15:40:23Z',
                                'TEXT': 'IPs successfully added to Vulnerability Management'})]

    @pytest.mark.parametrize('raw_response, expected', SIMPLE_FROM_RAW_INPUTS)
    def test_get_simple_response_from_raw(self, raw_response, expected):
        """
        Given
            - Parsed raw response.
        When
            - Getting simple response from parsed raw response.
        Then
            - Ensure expected object is returned from parsing.
        """
        assert get_simple_response_from_raw(raw_response) == expected


class TestHandleGeneralResult:
    def test_handle_general_result_path_exists(self, mocker):
        """
        Given
            - response in json format
            - path to a specific field
        When
            - the json object is well formed
            - the path is correct
        Then
            - return the path requested
        """
        json_obj = {'IP_LIST_OUTPUT': {'RESPONSE': {'DATETIME': 'sometime', 'IP_SET': {'IP': ['1.1.1.1']}}}}
        mocker.patch.object(Qualysv2, 'format_and_validate_response', return_value=json_obj)
        dummy_response = requests.Response()

        assert handle_general_result(dummy_response, 'qualys-ip-list') == {'DATETIME': 'sometime',
                                                                           'IP_SET': {'IP': ['1.1.1.1']}}

    def test_handle_general_result_doesnt_exist(self, mocker):
        """
        Given
            - response in json format and
            - a path to be returned from the object
        When
            - the json object is well formed
            - the path doesn't exist
        Then
            - raise DemistoException Exception
        """
        with pytest.raises(ValueError):
            json_obj = {'IP_LIST_OUTPUT': {'RESPONSE': {'DATETIME': 'sometime', 'IP_SET': {'IP': ['1.1.1.1']}}}}
            path = {'qualys-ip-list': {'json_path': ['IP_SET', 'WHAT']}}
            mocker.patch.object(Qualysv2, 'format_and_validate_response', return_value=json_obj)
            mocker.patch.object(Qualysv2, 'COMMANDS_PARSE_AND_OUTPUT_DATA', path)
            dummy_response = requests.Response()

            handle_general_result(dummy_response, 'qualys-ip-list')

    def test_handle_general_result_empty_json(self, mocker):
        """
        Given
            - response in json format
            - a path to be returned from the object
        When
            - the json object is empty formed
            - the path doesn't exist
        Then
            - raise DemistoException Exception
        """
        with pytest.raises(ValueError):
            json_obj = {}
            path = {'qualys-ip-list': {'json_path': ['IP_SET', 'WHAT']}}
            mocker.patch.object(Qualysv2, 'format_and_validate_response', return_value=json_obj)
            mocker.patch.object(Qualysv2, 'COMMANDS_PARSE_AND_OUTPUT_DATA', path)
            dummy_response = requests.Response()

            handle_general_result(dummy_response, 'qualys-ip-list')

    def test_handle_general_result_none_value(self, mocker):
        """
        Given
            - response in json format
            - a path to be returned from the object
        When
            - the json object is none formed
            - the path doesn't exist
        Then
            - raise DemistoException Exception
        """
        with pytest.raises(ValueError):
            json_obj = None
            path = {'qualys-ip-list': {'json_path': ['IP_SET', 'WHAT']}}
            mocker.patch.object(Qualysv2, 'format_and_validate_response', return_value=json_obj)
            mocker.patch.object(Qualysv2, 'COMMANDS_PARSE_AND_OUTPUT_DATA', path)
            dummy_response = requests.Response()

            handle_general_result(dummy_response, 'qualys-ip-list')

    def test_handle_general_result_empty_path(self, mocker):
        """
        Given
            - response in json format
            - a path to be returned from the object
        When
            - the json object is formed correctly
            - the path is empty
        Then
            - return the json object without any changes
        """
        json_obj = {'IP_LIST_OUTPUT': {'RESPONSE': {'DATETIME': 'sometime', 'IP_SET': {'IP': ['1.1.1.1']}}}}
        path = {'qualys-ip-list': {'json_path': []}}
        mocker.patch.object(Qualysv2, 'format_and_validate_response', return_value=json_obj)
        mocker.patch.object(Qualysv2, 'COMMANDS_PARSE_AND_OUTPUT_DATA', path)
        dummy_response = requests.Response()

        result = handle_general_result(dummy_response, 'qualys-ip-list')
        assert result == json_obj


class TestParseTwoKeysDict:
    def test_parse_two_keys_dict_unexpected_format(self):
        """
        Given
            - json object
        When
            - the json object has unexpected format
        Then
            - raise a KeyError Exception
        """
        with pytest.raises(KeyError):
            json_obj = {'not_key': ' ', 'not_val': ' '}
            parse_two_keys_dict(json_obj)

    def test_parse_two_keys_dict_expected_format(self):
        """
        Given
            - json object
        When
            - the json object has the expected format
        Then
            - return a new dictionary with correct key and value
        """
        json_obj = {'KEY': 'a key', 'VALUE': 'a value'}
        res = parse_two_keys_dict(json_obj)
        assert res['a key'] == 'a value'

    def test_parse_two_keys_dict_none_value(self):
        """
        Given
            - json object
        When
            - the json object is None
        Then
            - raise a TypeError Exception
        """
        with pytest.raises(TypeError):
            json_obj = None
            parse_two_keys_dict(json_obj)


class TestChangeDictKeys:
    def test_change_dict_keys_expected_format(self):
        """
        Given
            - dictionary to be changed
            - dictionary with new keys' names
        When
            - the dictionaries are well formatted
        Then
            -  return the dictionary with the new keys
        """
        new_names_dict = {'old_name_1': 'new_name_1',
                          'old_name_2': 'new_name_2'}
        dict_to_change = {'old_name_1': 'some_value_1',
                          'old_name_2': 'some_value_2'}
        changed_dict = change_dict_keys(new_names_dict, dict_to_change)
        assert changed_dict['new_name_1']
        assert changed_dict['new_name_2']
        assert 'old_name_1' not in changed_dict
        assert 'old_name_2' not in changed_dict

    def test_change_dict_keys_missing_key(self):
        """
        Given
            - dictionary to be changed
            - dictionary with new keys' names
        When
            - the output dictionary is missing a key to be changed
        Then
            - change only the keys that exist
        """
        new_names_dict = {'old_name_1': 'new_name_1',
                          'old_name_2': 'new_name_2'}
        dict_to_change = {'old_name_2': 'some_value_2'}
        changed_dict = change_dict_keys(new_names_dict, dict_to_change)
        assert changed_dict['new_name_2']
        assert 'new_name_1' not in changed_dict
        assert 'old_name_1' not in changed_dict
        assert 'old_name_2' not in changed_dict

    def test_change_dict_keys_output_is_none(self):
        """
        Given
            - dictionary to be changed
            - dictionary with new keys' names
        When
            - the output dictionary is None
        Then
            - raise a TypeError Exception
        """
        with pytest.raises(TypeError):
            new_names_dict = {'old_name_1': 'new_name_1',
                              'old_name_2': 'new_name_2'}
            dict_to_change = None
            changed_dict = change_dict_keys(new_names_dict, dict_to_change)
            assert changed_dict['new_name_1']
            assert changed_dict['new_name_2']
            assert 'old_name_1' not in changed_dict
            assert 'old_name_2' not in changed_dict


class TestCreateIPListDicts:
    def test_create_ip_list_dicts_expected_format(self):
        """
        Given
            - dictionary of ip list command result
        When
            - the dictionary has the expected format
        Then
            - create a list of dictionaries
        """
        ip_dict = {'Address': ['1.1.1.1', '1.2.3.4'],
                   'Range': ['1.1.1.3-1.1.2.1']}

        dicts = create_ip_list_dicts(ip_dict)

        assert len(dicts[0]) == 2
        assert len(dicts[1]) == 1

    def test_create_ip_list_dicts_expected_format_single_value(self):
        """
        Given
            - dictionary of ip list command result
        When
            - the dictionary has the expected format but only single value
        Then
            - create a list of dictionaries
        """
        ip_dict = {'Address': '1.1.1.1'}

        dicts = create_ip_list_dicts(ip_dict)

        assert len(dicts) == 1
        assert len(dicts[0]) == 1

    def test_create_ip_list_dicts_expected_format_single_value_is_dict(self):
        """
        Given
            - dictionary of ip list command result
        When
            - the dictionary has the expected format but only single value and
              is a dictionary of values
        Then
            - create a list of dictionaries
        """
        ip_dict = {'Address': {'key1': 'value1', 'key2': 'value2'}}

        dicts = create_ip_list_dicts(ip_dict)

        assert len(dicts) == 1
        assert len(dicts[0]) == 1

    def test_create_ip_list_dicts_bad_keys(self):
        """
        Given
            - dictionary of ip list command result
        When
            - the dictionary has wrong keys
        Then
            - raise DemistoException exception
        """
        with pytest.raises(DemistoException):
            ip_dict = {'bad_key_1': ['1.1.1.1', '1.2.3.4'],
                       'bad_key_2': ['1.1.1.3-1.1.2.1']}

            create_ip_list_dicts(ip_dict)

    def test_create_ip_list_dicts_one_good_key(self):
        """
        Given
            - dictionary of ip list command result
        When
            - the dictionary has one wrong key
        Then
            - change only one key
        """
        ip_dict = {'Address': ['1.1.1.1', '1.2.3.4'],
                   'bad_key_2': ['1.1.1.3-1.1.2.1']}

        dicts = create_ip_list_dicts(ip_dict)
        assert len(dicts) == 1
        assert len(dicts[0]) == 2

    def test_create_ip_list_dicts_none_json(self):
        """
        Given
            - dictionary of ip list command result
        When
            - the dictionary is None
        Then
            - raise TypeError Exception
        """
        with pytest.raises(TypeError):
            ip_dict = None

            create_ip_list_dicts(ip_dict)


class TestLimitIPResults:
    def test_limit_ip_results_high_limit(self):
        """
        Given
            - IPs data that contains both single IP's and ranges
            - Limit value
        When
            - the limit value is high enough so data will be taken from both lists
        Then
            - Change the lists so all addresses will show and part of the Ranges
        """
        data = {
            'Address': ['1.1.1.1', '1.2.3.4'],
            'Range': ['1.4.3.1-1.4.3.5', '1.4.3.6-1.4.3.9']
        }
        limit = 3

        data = limit_ip_results(data, limit)
        assert len(data['Address']) == 2
        assert len(data['Range']) == 1

    def test_limit_ip_results_low_limit(self):
        """
        Given
            - IPs data that contains both single IP's and ranges
            - Limit value
        When
            - Limit values is low
        Then
            - Data will be changed so only Address's list can be shown
        """
        data = {
            'Address': ['1.1.1.1', '1.2.3.4'],
            'Range': ['1.4.3.1-1.4.3.5', '1.4.3.6-1.4.3.9']
        }
        limit = 1

        limit_ip_results(data, limit)
        assert len(data['Address']) == 1
        assert len(data['Range']) == 0

    def test_limit_ip_results_only_range_entry(self):
        """
        Given
            - IPs data that contains only ranges
            - Limit value
        When
            - limit value will be applied only to ranges entry
        Then
            - data will have a Range list with up to 'limit' entries
        """
        data = {
            'Range': ['1.4.3.1-1.4.3.5', '1.4.3.6-1.4.3.9']
        }
        limit = 1

        limit_ip_results(data, limit)
        assert len(data['Range']) == 1

    def test_limit_ip_results_single_ip_and_range(self):
        """
        Given
            - arguments received by the user
            - command name to be run
        When
            - all arguments where provided and there are only API args
        Then
            - create a dictionary with all the arguments
        """
        data = {
            'Address': '1.1.1.1',
            'Range': '1.4.3.1-1.4.3.5'
        }
        limit = 1

        limit_ip_results(data, limit)
        assert data['Address'] == '1.1.1.1'
        assert len(data['Range']) == 0


class TestBuildArgsDict:
    def test_build_api_args_dict_all_args(self):
        """
        Given
            - arguments received by the user
            - command name to be run
        When
            - all arguments where provided and there are only API args
        Then
            - create a dictionary with all the arguments
        """
        args = {'ips': 'ip',
                'network_id': 'id',
                'tracking_method': 'method',
                'compliance_enabled': True}
        command_args_data = COMMANDS_ARGS_DATA['qualys-ip-list']

        build_args_dict(args, command_args_data, False)
        assert Qualysv2.args_values == args

    def test_build_api_args_dict_missing_args(self):
        """
        Given
            - arguments received by the user
            - command name to be run
        When
            - Some arguments were not provided and there are only API args
        Then
            - create a dictionary with the provided arguments values and
              None value for arguments that were not provided
        """
        args = {'ips': 'ip'}
        command_args_data = COMMANDS_ARGS_DATA['qualys-ip-list']

        build_args_dict(args, command_args_data, False)
        assert Qualysv2.args_values == args

    def test_build_api_args_dict_empty_date(self):
        """
        Given
            - arguments received by the user
            - command name to be run
        When
            - Some arguments were not provided and there are only API args
        Then
            - create a dictionary with the provided arguments values and
              None value for arguments that were not provided
        """
        args = {'published_before': ''}
        command_args_data = COMMANDS_ARGS_DATA['qualys-vulnerability-list']

        build_args_dict(args, command_args_data, False)
        assert Qualysv2.args_values == {}

    def test_build_inner_args_dict_all_args(self):
        """
        Given
            - arguments received by the user
            - command name to be run
        When
            - all arguments where provided and there are both API args and inner-use args
        Then
            - create a dictionary with all the arguments
        """
        args = {'id': 'id', 'file_format': 'xml'}
        command_args_data = COMMANDS_ARGS_DATA['qualys-report-fetch']

        build_args_dict(args, command_args_data, True)
        assert Qualysv2.inner_args_values == {'file_format': 'xml'}

    def test_build_args_dict_none_args(self):
        """
        Given
            - arguments received by the user
            - command name to be run
        When
            - No arguments were provided
        Then
            - create a dictionary with no arguments' values
        """
        args = None
        command_args_data = COMMANDS_ARGS_DATA['test-module']
        build_args_dict(args, command_args_data, False)
        assert Qualysv2.args_values == {}

    def test_build_args_dict_date_args(self):
        """
        Given:
        - Cortex XSOAR arguments.
        - Command arg names.

        When:
        - Parsing date parameters.

        Then:
        - Ensure date parameters values are updated accordingly.
        """
        args = {'published_before': '1640508554',
                'launched_after_datetime': '2021-12-26T08:49:29Z',
                'start_date': '2021-12-26T08:49:29Z'}
        expected_result = {'launched_after_datetime': '2021-12-26',
                           'published_before': '2021-12-26',
                           'start_date': '12/26/2021'}

        build_args_dict(args, {'args': ['published_before', 'launched_after_datetime', 'start_date']}, False)
        assert Qualysv2.args_values == expected_result

    def test_build_args_dict_default_added_depended_args(self):
        """
        Given:
        - Cortex XSOAR arguments.
        - Command arg names.

        When:
        - There are arguments who should be added depending on an arguments.

        Then:
        - Ensure arguments are added as expected.
        """
        args = {'arg_to_depend_on': '1'}
        expected_result = {'arg_to_depend_on': '1', 'dep1': 2, 'dep2': 3}
        build_args_dict(args, {'args': ['arg_to_depend_on'],
                               'default_added_depended_args': {'arg_to_depend_on': {'dep1': 2, 'dep2': 3}}}, False)
        assert Qualysv2.args_values == expected_result


def test_handle_general_result_missing_output_builder():
    """
    Given
        - raw xml result
        - command name
        - output builder function
    When
        - output builder is None
    Then
        - raise a TypeError exception, None is not callable, must be provided
    """
    with pytest.raises(TypeError):
        raw_xml_response = '<?xml version="1.0" encoding="UTF-8" ?>' \
                           '<!DOCTYPE SIMPLE_RETURN SYSTEM' \
                           ' "https://qualysapi.qg2.apps.qualys.com/api/2.0/simple_return.dtd">' \
                           '<SIMPLE_RETURN><RESPONSE>' \
                           '<DATETIME>2021-03-24T15:40:23Z</DATETIME>' \
                           '<TEXT>IPs successfully added to Vulnerability Management</TEXT>' \
                           '</RESPONSE></SIMPLE_RETURN>'
        command_name = 'qualys-ip-add'
        handle_general_result(result=raw_xml_response, command_name=command_name, output_builder=None)


class TestHostDetectionOutputBuilder:
    DETECTION_INPUTS = [({'HOST_LIST': {'HOST_ITEM': []}}, '### Host Detection List\n\n**No entries.**\n', []),
                        ({'HOST_LIST': {'HOST_ITEM': [{'ID': 'ID123', 'IP': '1.1.1.1', 'DNS_DATA': {'data': 'dns data'},
                                                       'DETECTION_LIST': {
                                                           'DETECTION': [
                                                               {'QID': '123', 'RESULTS': 'FOUND DETECTION'}]}}]}},
                         "### Host Detection List\n\n|DETECTIONS|DNS_DATA|ID|IP|\n|---|---|---|---|\n| {"
                         "'QID': '123', 'RESULTS': 'FOUND DETECTION'} | data: dns data | ID123 | "
                         "1.1.1.1 |\n", [{'DETECTION_LIST': {'DETECTION': [{'QID': '123',
                                                                            'RESULTS': 'FOUND DETECTION'}]},
                                          'DNS_DATA': {'data': 'dns data'},
                                          'ID': 'ID123',
                                          'IP': '1.1.1.1'}])
                        ]

    @pytest.mark.parametrize('result, readable, expected_outputs', DETECTION_INPUTS)
    def test_build_host_list_detection_outputs(self, result, readable, expected_outputs):
        """
        Given:
        - Result of Qualys service for host list detection.

        When:
        - Parsing result into outputs and readable output.

        Then:
        - Ensure resultes are parsed as expected.
        """
        Qualysv2.inner_args_values['limit'] = 1
        assert build_host_list_detection_outputs({'command_parse_and_output_data': COMMANDS_PARSE_AND_OUTPUT_DATA[
            'qualys-host-list-detection'], 'handled_result': result}) == (expected_outputs, readable)


class MockResponse:
    def __init__(self, text, status_code, json=None, reason=None):
        self.text = text
        self.json = json
        self.status_code = status_code
        self.reason = reason

    def json(self):
        if self.json:
            return self.json
        raise Exception('No JSON')


class TestClientClass:
    ERROR_HANDLER_INPUTS = [
        (MockResponse('''<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE SIMPLE_RETURN SYSTEM "https://qualysapi.qg2.apps.qualys.com/api/2.0/simple_return.dtd">
<SIMPLE_RETURN>
  <RESPONSE>
    <DATETIME>2021-12-21T08:59:39Z</DATETIME>
    <CODE>999</CODE>
    <TEXT>Internal error. Please contact customer support.</TEXT>
    <ITEM_LIST>
      <ITEM>
        <KEY>Incident Signature</KEY>
        <VALUE>8ecaf66401cf247f5a6d75afd56bf847</VALUE>
      </ITEM>
    </ITEM_LIST>
  </RESPONSE>
</SIMPLE_RETURN>''', 500),
         'Error in API call [500] - None\nError Code: 999\nError Message: Internal error. Please '
         'contact customer support.'),
        (MockResponse('Invalid XML', 500), 'Error in API call [500] - None\nInvalid XML')
    ]

    @pytest.mark.parametrize('response, error_message', ERROR_HANDLER_INPUTS)
    def test_error_handler(self, response, error_message):
        """
        Given:
        - Qualys error response

        When:
        - Parsing error to readable message

        Then:
        - Ensure readable message is as expected
        """
        client: Client = Client('test.com', 'testuser', 'testpassword', False, False, None)
        with pytest.raises(DemistoException, match=re.escape(error_message)):
            client.error_handler(response)


class TestInputValidations:
    DEPENDANT_ARGS = {'day_of_month': 'frequency_months', 'day_of_week': 'frequency_months',
                      'week_of_month': 'frequency_months', 'weekdays': 'frequency_weeks', }
    VALIDATE_DEPENDED_ARGS_INPUT = [({}, {}),
                                    ({'required_depended_args': DEPENDANT_ARGS}, {}),
                                    ({'required_depended_args': DEPENDANT_ARGS},
                                     {k: 3 for k, v in DEPENDANT_ARGS.items() if v == 'frequency_months'})]

    @pytest.mark.parametrize('command_data, args', VALIDATE_DEPENDED_ARGS_INPUT)
    def test_validate_depended_args_valid(self, command_data: Dict, args: Dict):
        """
        Given:
        - Command data.
        - Cortex XSOAR arguments.

        When:
        - Validating depended args are supplied as expected.

        Then:
        - Ensure no exception is thrown.
        """
        Qualysv2.args_values = args
        validate_depended_args(command_data)

    def test_validate_depended_args_invalid(self):
        """
        Given:
        - Command data.
        - Cortex XSOAR arguments.

        When:
        - Validating depended args are not supplied as expected.

        Then:
        - Ensure exception is thrown.
        """
        Qualysv2.args_values = {'frequency_months': 1}
        with pytest.raises(DemistoException,
                           match='Argument day_of_month is required when argument frequency_months is given.'):
            validate_depended_args({'required_depended_args': self.DEPENDANT_ARGS})

    EXACTLY_ONE_GROUP_ARGS = [['asset_group_ids', 'asset_groups', 'ip', ],
                              ['frequency_days', 'frequency_weeks', 'frequency_months', ],
                              ['scanners_in_ag', 'default_scanner', ], ]
    EXACTLY_ONE_ARGS_INPUT = [({}, {}),
                              ({'required_groups': EXACTLY_ONE_GROUP_ARGS},
                               {'asset_group_ids': 1, 'scanners_in_ag': 1, 'frequency_days': 1}),
                              ({'required_groups': EXACTLY_ONE_GROUP_ARGS},
                               {'asset_groups': 1, 'scanners_in_ag': 1, 'frequency_weeks': 1}),
                              ({'required_groups': EXACTLY_ONE_GROUP_ARGS},
                               {'ip': '1.1.1.1', 'default_scanner': 1, 'frequency_months': 1})
                              ]

    @pytest.mark.parametrize('command_data, args', EXACTLY_ONE_ARGS_INPUT)
    def test_validate_required_group_valid(self, command_data: Dict, args: Dict):
        """
        Given:
        - Command data.
        - Cortex XSOAR arguments.

        When:
        - Validating required groups are supplied as expected.

        Then:
        - Ensure no exception is thrown.
        """
        Qualysv2.args_values = args
        validate_required_group(command_data)

    EXACTLY_ONE_INVALID_INPUT = [({}), ({'ip': '1.1.1.1', 'asset_group_ids': 1, 'frequency_months': 1})]

    @pytest.mark.parametrize('args', EXACTLY_ONE_INVALID_INPUT)
    def test_validate_required_group_invalid(self, args):
        """
        Given:
        - Command data.
        - Cortex XSOAR arguments.

        When:
        - Validating required groups are not supplied as expected.

        Then:
        - Ensure exception is thrown.
        """
        Qualysv2.args_values = args
        err_msg = "Exactly one of the arguments ['asset_group_ids', 'asset_groups', 'ip'] must be provided."
        with pytest.raises(DemistoException, match=re.escape(err_msg)):
            validate_required_group({'required_groups': self.EXACTLY_ONE_GROUP_ARGS})

    AT_MOST_ONE_GROUP_ARGS = [['asset_group_ids', 'asset_groups', 'ip', ],
                              ['frequency_days', 'frequency_weeks', 'frequency_months', ],
                              ['scanners_in_ag', 'default_scanner', ], ]
    AT_MOST_ONE_ARGS_INPUT = [({}, {}),
                              ({'at_most_one_groups': AT_MOST_ONE_GROUP_ARGS}, {}),
                              ({'at_most_one_groups': AT_MOST_ONE_GROUP_ARGS},
                               {'asset_group_ids': 1, 'scanners_in_ag': 1, 'frequency_days': 1}),
                              ({'at_most_one_groups': AT_MOST_ONE_GROUP_ARGS},
                               {'asset_groups': 1, 'scanners_in_ag': 1, 'frequency_weeks': 1}),
                              ({'at_most_one_groups': AT_MOST_ONE_GROUP_ARGS},
                               {'ip': '1.1.1.1', 'default_scanner': 1, 'frequency_months': 1})
                              ]

    @pytest.mark.parametrize('command_data, args', AT_MOST_ONE_ARGS_INPUT)
    def test_validate_at_most_one_group_valid(self, command_data: Dict, args: Dict):
        """
        Given:
        - Command data.
        - Cortex XSOAR arguments.

        When:
        - Validating depended args are supplied as expected.

        Then:
        - Ensure no exception is thrown.
        """
        Qualysv2.args_values = args
        validate_at_most_one_group(command_data)

    def test_validate_at_most_one_group_invalid(self):
        """
        Given:
        - Command data.
        - Cortex XSOAR arguments.

        When:
        - Validating depended args are not supplied as expected.

        Then:
        - Ensure exception is thrown.
        """
        Qualysv2.args_values = {'scanners_in_ag': 1, 'default_scanner': 1}
        err_msg = "At most one of the following args can be given: ['scanners_in_ag', 'default_scanner']"
        with pytest.raises(DemistoException, match=re.escape(err_msg)):
            validate_at_most_one_group({'at_most_one_groups': self.AT_MOST_ONE_GROUP_ARGS})
