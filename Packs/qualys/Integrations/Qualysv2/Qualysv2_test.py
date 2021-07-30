import pytest
import Qualysv2
from Qualysv2 import is_empty_result, format_and_validate_response,\
    parse_two_keys_dict, create_ip_list_dicts, build_args_dict, handle_general_result,\
    change_dict_keys, COMMANDS_ARGS_DATA, limit_ip_results
from CommonServerPython import DemistoException
import requests


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
        raw_xml_response = '<?xml version="1.0" encoding="UTF-8" ?>'\
                           '<!DOCTYPE SIMPLE_RETURN SYSTEM' \
                           ' "https://qualysapi.qg2.apps.qualys.com/api/2.0/simple_return.dtd">' \
                           '<SIMPLE_RETURN><RESPONSE>' \
                           '<DATETIME>2021-03-24T15:40:23Z</DATETIME>' \
                           '<TEXT>IPs successfully added to Vulnerability Management</TEXT>' \
                           '</RESPONSE></SIMPLE_RETURN>'
        command_name = 'qualys-ip-add'
        handle_general_result(result=raw_xml_response, command_name=command_name, output_builder=None)
