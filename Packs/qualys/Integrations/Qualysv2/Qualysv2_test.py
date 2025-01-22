import re

import Qualysv2
import pytest
import requests
from Qualysv2 import (
    is_empty_result,
    format_and_validate_response,
    parse_two_keys_dict,
    create_ip_list_dicts,
    build_args_dict,
    handle_general_result,
    change_dict_keys,
    COMMANDS_ARGS_DATA,
    limit_ip_results,
    Client,
    build_host_list_detection_outputs,
    COMMANDS_PARSE_AND_OUTPUT_DATA,
    validate_depended_args,
    Dict,
    validate_at_most_one_group,
    parse_raw_response,
    get_simple_response_from_raw,
    validate_required_group,
    get_activity_logs_events_command,
    fetch_events, get_activity_logs_events, fetch_assets, fetch_vulnerabilities, ASSETS_FETCH_FROM, ASSETS_DATE_FORMAT,
    HOST_LIMIT,
    API_SUFFIX,
)

from CommonServerPython import *  # noqa: F401

ACTIVITY_LOGS_NEWEST_EVENT_DATETIME = 'activity_logs_newest_event_datetime'
ACTIVITY_LOGS_NEXT_PAGE = 'activity_logs_next_page'
ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN = 'activity_logs_since_datetime_prev_run'
HOST_DETECTIONS_NEWEST_EVENT_DATETIME = 'host_detections_newest_event_datetime'
HOST_DETECTIONS_NEXT_PAGE = 'host_detections_next_page'
HOST_DETECTIONS_SINCE_DATETIME_PREV_RUN = 'host_detections_since_datetime_prev_run'
HOST_LAST_FETCH = 'host_last_fetch'
BEGIN_RESPONSE_LOGS_CSV = "----BEGIN_RESPONSE_BODY_CSV"
END_RESPONSE_LOGS_CSV = "----END_RESPONSE_BODY_CSV"
FOOTER = """----BEGIN_RESPONSE_FOOTER_CSV
WARNING
"CODE","TEXT","URL"
"1980","17 record limit exceeded. Use URL to get next batch of results.","https://server_url/api/2.0/fo/activity_log/
?action=list&since_datetime=2022-12-21T03:42:05Z&truncation_limit=10&id_max=123456"
----END_RESPONSE_FOOTER_CSV"""


def test_get_activity_logs_events_command(requests_mock):
    """
    Given:
    - activity_logs_events_command

    When:
    - Want to list all existing activity logs

    Then:
    - Ensure Activity Logs Results in human-readable, and number of results reasonable.
    """
    base_url = 'https://server_url/'
    with open('test_data/activity_logs.csv') as f:
        logs = f.read()
    requests_mock.get(f'{base_url}api/2.0/fo/activity_log/'
                      f'?action=list&truncation_limit=0&since_datetime=2023-03-01T00%3A00%3A00Z', text=logs)
    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False,
                    username='demisto',
                    password='demisto',
                    )
    args = {'limit': 50, 'since_datetime': '1 March 2023'}
    first_fetch = '2022-03-21T03:42:05Z'
    activity_logs_events, results = get_activity_logs_events_command(client, args, first_fetch)
    assert 'Activity Logs' in results.readable_output
    assert len(activity_logs_events) == 17


@pytest.mark.parametrize('activity_log_last_run, logs_number, add_footer',
                         [(None, 17, True),
                          ("2023-05-24T09:55:35Z", 0, True),
                          ("2023-05-14T15:04:55Z", 7, True),
                          ("2023-01-01T08:06:44Z", 17, False)])
def test_fetch_logs_events_command(requests_mock, activity_log_last_run, logs_number, add_footer):
    """
    Given:
    - fetch events command (fetches logs)

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched
    - Ensure next page token saved
    - Ensure previous run saved
    - Ensure newest event time saved
    """
    first_fetch_str = '2022-12-21T03:42:05Z'
    base_url = 'https://server_url/'
    truncation_limit = logs_number
    with open('test_data/activity_logs.csv') as f:
        logs = f.read()
        new_logs = f'{BEGIN_RESPONSE_LOGS_CSV}'
        for row in logs.split('\n'):
            if activity_log_last_run and activity_log_last_run in row:
                new_logs += f'{row}\n'
                break
            new_logs += f'{row}\n'
        new_logs += f'{END_RESPONSE_LOGS_CSV}\n'
        if add_footer:
            new_logs += f'{FOOTER}\n'

    requests_mock.get(f'{base_url}api/2.0/fo/activity_log/'
                      f'?action=list&truncation_limit={truncation_limit}&'
                      f'since_datetime={activity_log_last_run if activity_log_last_run else first_fetch_str}',
                      text=new_logs)
    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False,
                    username='demisto',
                    password='demisto',
                    )
    last_run = {ACTIVITY_LOGS_NEWEST_EVENT_DATETIME: activity_log_last_run}

    logs_next_run, activity_logs_events = fetch_events(
        client=client,
        last_run=last_run,
        newest_event_field=ACTIVITY_LOGS_NEWEST_EVENT_DATETIME,
        next_page_field=ACTIVITY_LOGS_NEXT_PAGE,
        previous_run_time_field=ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN,
        fetch_function=get_activity_logs_events,
        first_fetch_time=first_fetch_str,
        max_fetch=truncation_limit,
    )
    assert len(activity_logs_events) == logs_number
    assert logs_next_run.get(ACTIVITY_LOGS_NEXT_PAGE) == ("123456" if add_footer else None)
    assert logs_next_run.get(ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN) == activity_log_last_run or first_fetch_str
    assert logs_next_run.get(ACTIVITY_LOGS_NEWEST_EVENT_DATETIME) == "2023-05-24T09:55:35Z"


def test_fetch_assets_command(requests_mock):
    """
    Given:
    - fetch_assets_command
    When:
    - Want to list all existing incidents
    Then:
    - Ensure List assets.
    """
    base_url = 'https://server_url/'
    with open('./test_data/host_list_detections_raw.xml') as f:
        assets = f.read()
    requests_mock.get(f'{base_url}api/2.0/fo/asset/host/vm/detection/'
                      f'?action=list&truncation_limit={HOST_LIMIT}&vm_scan_date_after='
                      f'{arg_to_datetime(ASSETS_FETCH_FROM).strftime(ASSETS_DATE_FORMAT)}', text=assets)

    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False,
                    username='demisto',
                    password='demisto',
                    )
    assets, last_run, amount_to_report, snapshot_id, set_new_limit = fetch_assets(client=client, assets_last_run={})
    assert len(assets) == 8
    assert amount_to_report == 8
    assert snapshot_id
    assert last_run['stage'] == 'vulnerabilities'


def test_fetch_assets_command_time_out(requests_mock, mocker):
    """
    Given:
    - fetch_assets_command
    When:
    - Want to list all existing incidents and got a timeout
    Then:
    - Ensure the limit was reduced.
    """
    base_url = 'https://server_url/'
    with open('./test_data/host_list_detections_raw.xml') as f:
        assets = f.read()
    requests_mock.get(f'{base_url}api/2.0/fo/asset/host/vm/detection/'
                      f'?action=list&truncation_limit={HOST_LIMIT}&vm_scan_date_after='
                      f'{arg_to_datetime(ASSETS_FETCH_FROM).strftime(ASSETS_DATE_FORMAT)}',
                      exc=requests.exceptions.ReadTimeout)

    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False,
                    username='demisto',
                    password='demisto',
                    )
    assets, new_last_run, amount_to_report, snapshot_id, set_new_limit = fetch_assets(client=client, assets_last_run={})
    assert not assets
    assert set_new_limit


def test_fetch_vulnerabilities_command(requests_mock):
    """
    Given:
    - fetch_vulnerabilities_command
    When:
    - Want to list all existing incidents
    Then:
    - Ensure List vulnerabilities.
    """
    base_url = 'https://server_url/'
    with open('./test_data/vulnerabilities_raw.xml') as f:
        vulnerabilities = f.read()

    requests_mock.post(f'{base_url}api/2.0/fo/knowledge_base/vuln/'
                       f'?action=list&last_modified_after={arg_to_datetime(ASSETS_FETCH_FROM).strftime(ASSETS_DATE_FORMAT)}',
                       text=vulnerabilities)

    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False,
                    username='demisto',
                    password='demisto',
                    )
    last_run = {'since_datetime': {arg_to_datetime(ASSETS_FETCH_FROM).strftime(ASSETS_DATE_FORMAT)}}
    vulnerabilities, last_run = fetch_vulnerabilities(client=client, last_run=last_run)
    assert len(vulnerabilities) == 2
    assert last_run['next_page'] == ''
    assert last_run['stage'] == 'assets'


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
        response = {"DATETIME": "sometime"}
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
        response = {"IP_SET": {"IP": ["1.1.1.1"]}, "DATETIME": "sometime"}
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
    raw_xml_response_success = """<?xml version="1.0" encoding="UTF-8" ?>
                           <!DOCTYPE SIMPLE_RETURN SYSTEM
                            "https://qualysapi.qg2.apps.qualys.com/api/2.0/simple_return.dtd">
                           <SIMPLE_RETURN><RESPONSE>
                           <DATETIME>2021-03-24T15:40:23Z</DATETIME>
                           <TEXT>IPs successfully added to Vulnerability Management</TEXT>
                           </RESPONSE></SIMPLE_RETURN>"""
    raw_xml_response_failue = """<?xml version="1.0" encoding="UTF-8" ?>
                               <!DOCTYPE SIMPLE_RETURN SYSTEM
                               "https://qualysapi.qg2.apps.qualys.com/api/2.0/simple_return.dtd">
                               <SIMPLE_RETURN>
                               <RESPONSE><DATETIME>2021-03-24T16:35:44Z</DATETIME>
                               <CODE>1905</CODE><TEXT>IP(s) do not exist.</TEXT></RESPONSE></SIMPLE_RETURN>"""
    bad_format_raw_xml_response = """<?xml version="1.0" encoding="UTF-8" ?>
                           <!DOCTYPE SIMPLE_RETURN SYSTEM
                           "https://qualysapi.qg2.apps.qualys.com/api/2.0/simple_return.dtd">
                           <SIMPLE_RETURN>
                           <RESPONSE><DATETIME>2021-03-24T16:35:44Z</DATETIME>
                           <CODE>1905</CODE><TEXT>IP(s) do not exist.</TEXT></RESPONSE>"""

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
        assert raw_json_response.get("SIMPLE_RETURN").get("RESPONSE")
        assert not raw_json_response.get("CODE")

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

    PARSE_RAW_RESPONSE_INPUTS = [
        ('[{"ip": "1.1.1.1"},{"ip": "1.1.1.1"}]', [{"ip": "1.1.1.1"}, {"ip": "1.1.1.1"}]),
        (
            raw_xml_response_success,
            {
                "SIMPLE_RETURN": {
                    "RESPONSE": {"DATETIME": "2021-03-24T15:40:23Z",
                                 "TEXT": "IPs successfully added to Vulnerability Management"}
                }
            },
        ),
        # Invalid case - should return empty dict
        ('[{"ip": "1.1.1.1"ip": "1.1.1.1"}]', {}),
    ]

    @pytest.mark.parametrize("response, expected", PARSE_RAW_RESPONSE_INPUTS)
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

    SIMPLE_FROM_RAW_INPUTS = [
        (
            {
                "SIMPLE_RETURN": {
                    "RESPONSE": {
                        "DATETIME": "2021-03-24T15:40:23Z",
                        "TEXT": "IPs successfully added to Vulnerability Management",
                    }
                }
            },
            {"DATETIME": "2021-03-24T15:40:23Z", "TEXT": "IPs successfully added to Vulnerability Management"},
        )
    ]

    @pytest.mark.parametrize("raw_response, expected", SIMPLE_FROM_RAW_INPUTS)
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
        json_obj = {"IP_LIST_OUTPUT": {"RESPONSE": {"DATETIME": "sometime", "IP_SET": {"IP": ["1.1.1.1"]}}}}
        mocker.patch.object(Qualysv2, "format_and_validate_response", return_value=json_obj)
        dummy_response = requests.Response()

        assert handle_general_result(dummy_response, "qualys-ip-list") == {"DATETIME": "sometime",
                                                                           "IP_SET": {"IP": ["1.1.1.1"]}}

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
            json_obj = {"IP_LIST_OUTPUT": {"RESPONSE": {"DATETIME": "sometime", "IP_SET": {"IP": ["1.1.1.1"]}}}}
            path = {"qualys-ip-list": {"json_path": ["IP_SET", "WHAT"]}}
            mocker.patch.object(Qualysv2, "format_and_validate_response", return_value=json_obj)
            mocker.patch.object(Qualysv2, "COMMANDS_PARSE_AND_OUTPUT_DATA", path)
            dummy_response = requests.Response()

            handle_general_result(dummy_response, "qualys-ip-list")

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
            path = {"qualys-ip-list": {"json_path": ["IP_SET", "WHAT"]}}
            mocker.patch.object(Qualysv2, "format_and_validate_response", return_value=json_obj)
            mocker.patch.object(Qualysv2, "COMMANDS_PARSE_AND_OUTPUT_DATA", path)
            dummy_response = requests.Response()

            handle_general_result(dummy_response, "qualys-ip-list")

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
            path = {"qualys-ip-list": {"json_path": ["IP_SET", "WHAT"]}}
            mocker.patch.object(Qualysv2, "format_and_validate_response", return_value=json_obj)
            mocker.patch.object(Qualysv2, "COMMANDS_PARSE_AND_OUTPUT_DATA", path)
            dummy_response = requests.Response()

            handle_general_result(dummy_response, "qualys-ip-list")

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
        json_obj = {"IP_LIST_OUTPUT": {"RESPONSE": {"DATETIME": "sometime", "IP_SET": {"IP": ["1.1.1.1"]}}}}
        path = {"qualys-ip-list": {"json_path": []}}
        mocker.patch.object(Qualysv2, "format_and_validate_response", return_value=json_obj)
        mocker.patch.object(Qualysv2, "COMMANDS_PARSE_AND_OUTPUT_DATA", path)
        dummy_response = requests.Response()

        result = handle_general_result(dummy_response, "qualys-ip-list")
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
            json_obj = {"not_key": " ", "not_val": " "}
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
        json_obj = {"KEY": "a key", "VALUE": "a value"}
        res = parse_two_keys_dict(json_obj)
        assert res["a key"] == "a value"

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
        new_names_dict = {"old_name_1": "new_name_1", "old_name_2": "new_name_2"}
        dict_to_change = {"old_name_1": "some_value_1", "old_name_2": "some_value_2"}
        changed_dict = change_dict_keys(new_names_dict, dict_to_change)
        assert changed_dict["new_name_1"]
        assert changed_dict["new_name_2"]
        assert "old_name_1" not in changed_dict
        assert "old_name_2" not in changed_dict

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
        new_names_dict = {"old_name_1": "new_name_1", "old_name_2": "new_name_2"}
        dict_to_change = {"old_name_2": "some_value_2"}
        changed_dict = change_dict_keys(new_names_dict, dict_to_change)
        assert changed_dict["new_name_2"]
        assert "new_name_1" not in changed_dict
        assert "old_name_1" not in changed_dict
        assert "old_name_2" not in changed_dict

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
            new_names_dict = {"old_name_1": "new_name_1", "old_name_2": "new_name_2"}
            dict_to_change = None
            changed_dict = change_dict_keys(new_names_dict, dict_to_change)
            assert changed_dict["new_name_1"]
            assert changed_dict["new_name_2"]
            assert "old_name_1" not in changed_dict
            assert "old_name_2" not in changed_dict


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
        ip_dict = {"Address": ["1.1.1.1", "1.2.3.4"], "Range": ["1.1.1.3-1.1.2.1"]}

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
        ip_dict = {"Address": "1.1.1.1"}

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
        ip_dict = {"Address": {"key1": "value1", "key2": "value2"}}

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
            ip_dict = {"bad_key_1": ["1.1.1.1", "1.2.3.4"], "bad_key_2": ["1.1.1.3-1.1.2.1"]}

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
        ip_dict = {"Address": ["1.1.1.1", "1.2.3.4"], "bad_key_2": ["1.1.1.3-1.1.2.1"]}

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
        data = {"Address": ["1.1.1.1", "1.2.3.4"], "Range": ["1.4.3.1-1.4.3.5", "1.4.3.6-1.4.3.9"]}
        limit = 3

        data = limit_ip_results(data, limit)
        assert len(data["Address"]) == 2
        assert len(data["Range"]) == 1

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
        data = {"Address": ["1.1.1.1", "1.2.3.4"], "Range": ["1.4.3.1-1.4.3.5", "1.4.3.6-1.4.3.9"]}
        limit = 1

        limit_ip_results(data, limit)
        assert len(data["Address"]) == 1
        assert len(data["Range"]) == 0

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
        data = {"Range": ["1.4.3.1-1.4.3.5", "1.4.3.6-1.4.3.9"]}
        limit = 1

        limit_ip_results(data, limit)
        assert len(data["Range"]) == 1

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
        data = {"Address": "1.1.1.1", "Range": "1.4.3.1-1.4.3.5"}
        limit = 1

        limit_ip_results(data, limit)
        assert data["Address"] == "1.1.1.1"
        assert len(data["Range"]) == 0


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
        args = {"ips": "ip", "network_id": "id", "tracking_method": "method", "compliance_enabled": True}
        command_args_data = COMMANDS_ARGS_DATA["qualys-ip-list"]

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
        args = {"ips": "ip"}
        command_args_data = COMMANDS_ARGS_DATA["qualys-ip-list"]

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
        args = {"published_before": ""}
        command_args_data = COMMANDS_ARGS_DATA["qualys-vulnerability-list"]

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
        args = {"id": "id", "file_format": "xml"}
        command_args_data = COMMANDS_ARGS_DATA["qualys-report-fetch"]

        build_args_dict(args, command_args_data, True)
        assert Qualysv2.inner_args_values == {"file_format": "xml"}

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
        command_args_data = COMMANDS_ARGS_DATA["test-module"]
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
        args = {
            "published_before": "1640508554",
            "launched_after_datetime": "2021-12-26T08:49:29Z",
            "start_date": "2021-12-26T08:49:29Z",
        }
        expected_result = {"launched_after_datetime": "2021-12-26", "published_before": "2021-12-26",
                           "start_date": "12/26/2021"}

        build_args_dict(args, {"args": ["published_before", "launched_after_datetime", "start_date"]}, False)
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
        args = {"arg_to_depend_on": "1"}
        expected_result = {"arg_to_depend_on": "1", "dep1": 2, "dep2": 3}
        build_args_dict(
            args,
            {"args": ["arg_to_depend_on"], "default_added_depended_args": {"arg_to_depend_on": {"dep1": 2, "dep2": 3}}},
            False,
        )
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
        raw_xml_response = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            "<!DOCTYPE SIMPLE_RETURN SYSTEM"
            ' "https://qualysapi.qg2.apps.qualys.com/api/2.0/simple_return.dtd">'
            "<SIMPLE_RETURN><RESPONSE>"
            "<DATETIME>2021-03-24T15:40:23Z</DATETIME>"
            "<TEXT>IPs successfully added to Vulnerability Management</TEXT>"
            "</RESPONSE></SIMPLE_RETURN>"
        )
        command_name = "qualys-ip-add"
        handle_general_result(result=raw_xml_response, command_name=command_name, output_builder=None)


class TestHostDetectionOutputBuilder:
    DETECTION_INPUTS = [
        ({"HOST_LIST": {"HOST_ITEM": []}}, "", []),
        (
            {
                "HOST_LIST": {
                    "HOST_ITEM": [
                        {
                            "ID": "ID123",
                            "IP": "1.1.1.1",
                            "DNS_DATA": {"data": "dns data"},
                            "DETECTION_LIST": {"DETECTION": [{"QID": "123", "RESULTS": "FOUND DETECTION"}]},
                        }
                    ]
                }
            },
            "### Host Detection List - 1.1.1.1\n"
            "\n"
            "|ID|IP|DNS_DATA|QID: 123|\n"
            "|---|---|---|---|\n"
            "| ID123 | 1.1.1.1 | data: dns data | FOUND DETECTION |\n",
            [
                {
                    "ID": "ID123",
                    "IP": "1.1.1.1",
                    "DNS_DATA": {"data": "dns data"},
                    "DETECTION_LIST": {"DETECTION": [{"QID": "123", "RESULTS": "FOUND DETECTION"}]},
                }
            ],
        ),
        (
            {
                "HOST_LIST": {
                    "HOST_ITEM": [
                        {
                            "ID": "ID123",
                            "IP": "1.1.1.1",
                            "DNS_DATA": {"data": "dns data"},
                            "DETECTION_LIST": {"DETECTION": {"QID": "123", "RESULTS": "FOUND DETECTION"}},
                        }
                    ]
                }
            },
            "### Host Detection List - 1.1.1.1\n"
            "\n"
            "|ID|IP|DNS_DATA|QID: 123|\n"
            "|---|---|---|---|\n"
            "| ID123 | 1.1.1.1 | data: dns data | FOUND DETECTION |\n",
            [
                {
                    "ID": "ID123",
                    "IP": "1.1.1.1",
                    "DNS_DATA": {"data": "dns data"},
                    "DETECTION_LIST": {"DETECTION": {"QID": "123", "RESULTS": "FOUND DETECTION"}},
                }
            ],
        ),
    ]

    @pytest.mark.parametrize("result, readable, expected_outputs", DETECTION_INPUTS)
    def test_build_host_list_detection_outputs(self, result, readable, expected_outputs):
        """
        Given:
        - Result of Qualys service for host list detection.

        When:
        - Parsing result into outputs and readable output.

        Then:
        - Ensure resultes are parsed as expected.
        """
        Qualysv2.inner_args_values["limit"] = 1
        assert build_host_list_detection_outputs(
            handled_result=result,
            command_parse_and_output_data=COMMANDS_PARSE_AND_OUTPUT_DATA["qualys-host-list-detection"]
        ) == (expected_outputs, readable)


class MockResponse:
    def __init__(self, text, status_code, json=None, reason=None):
        self.text = text
        self.json = json
        self.status_code = status_code
        self.reason = reason

    def json(self):
        if self.json:
            return self.json
        raise Exception("No JSON")


class TestClientClass:
    client: Client = Client("test.com", "testuser", "testpassword", False, False, {})
    ERROR_HANDLER_INPUTS = [
        (
            MockResponse(
                """<?xml version="1.0" encoding="UTF-8" ?>
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
</SIMPLE_RETURN>""",
                500,
            ),
            "Error in API call [500] - None\nError Code: 999\nError Message: Internal error. Please contact customer support.",
        ),
        (MockResponse("Invalid XML", 500), "Error in API call [500] - None\nInvalid XML"),
    ]

    @pytest.mark.parametrize("response, error_message", ERROR_HANDLER_INPUTS)
    def test_error_handler(self, response, error_message):
        """
        Given:
        - Qualys error response

        When:
        - Parsing error to readable message

        Then:
        - Ensure readable message is as expected
        """
        with pytest.raises(DemistoException, match=re.escape(error_message)):
            self.client.error_handler(response)

    def test_get_host_list_detections_events(self, mocker):
        """
        Given
            - A Qualys Client instance and a since_datetime value
        When
            - Calling Client.get_host_list_detections_events
        Assert
            - The correct http request is made
        """
        since_datetime = "2024-12-12"

        client_http_request = mocker.patch.object(self.client, "_http_request")
        self.client.get_host_list_detection(since_datetime=since_datetime, limit=HOST_LIMIT)
        http_request_kwargs = client_http_request.call_args.kwargs

        assert client_http_request.called_once
        assert http_request_kwargs["method"] == "GET"
        assert http_request_kwargs["url_suffix"] == urljoin(API_SUFFIX, "asset/host/vm/detection/?action=list")
        assert http_request_kwargs["params"] == {
            "truncation_limit": HOST_LIMIT,
            "vm_scan_date_after": since_datetime,
            "show_qds": 1,
            "show_qds_factors": 1
        }


class TestInputValidations:
    DEPENDANT_ARGS = {
        "day_of_month": "frequency_months",
        "day_of_week": "frequency_months",
        "week_of_month": "frequency_months",
        "weekdays": "frequency_weeks",
    }
    VALIDATE_DEPENDED_ARGS_INPUT = [
        ({}, {}),
        ({"required_depended_args": DEPENDANT_ARGS}, {}),
        ({"required_depended_args": DEPENDANT_ARGS},
         {k: 3 for k, v in DEPENDANT_ARGS.items() if v == "frequency_months"}),
    ]

    @pytest.mark.parametrize("command_data, args", VALIDATE_DEPENDED_ARGS_INPUT)
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
        Qualysv2.args_values = {"frequency_months": 1}
        with pytest.raises(DemistoException,
                           match="Argument day_of_month is required when argument frequency_months is given."):
            validate_depended_args({"required_depended_args": self.DEPENDANT_ARGS})

    EXACTLY_ONE_GROUP_ARGS = [
        [
            "asset_group_ids",
            "asset_groups",
            "ip",
        ],
        [
            "frequency_days",
            "frequency_weeks",
            "frequency_months",
        ],
        [
            "scanners_in_ag",
            "default_scanner",
        ],
    ]
    EXACTLY_ONE_ARGS_INPUT = [
        ({}, {}),
        ({"required_groups": EXACTLY_ONE_GROUP_ARGS}, {"asset_group_ids": 1, "scanners_in_ag": 1, "frequency_days": 1}),
        ({"required_groups": EXACTLY_ONE_GROUP_ARGS}, {"asset_groups": 1, "scanners_in_ag": 1, "frequency_weeks": 1}),
        ({"required_groups": EXACTLY_ONE_GROUP_ARGS}, {"ip": "1.1.1.1", "default_scanner": 1, "frequency_months": 1}),
    ]

    @pytest.mark.parametrize("command_data, args", EXACTLY_ONE_ARGS_INPUT)
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

    EXACTLY_ONE_INVALID_INPUT = [({}), ({"ip": "1.1.1.1", "asset_group_ids": 1, "frequency_months": 1})]

    @pytest.mark.parametrize("args", EXACTLY_ONE_INVALID_INPUT)
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
            validate_required_group({"required_groups": self.EXACTLY_ONE_GROUP_ARGS})

    AT_MOST_ONE_GROUP_ARGS = [
        [
            "asset_group_ids",
            "asset_groups",
            "ip",
        ],
        [
            "frequency_days",
            "frequency_weeks",
            "frequency_months",
        ],
        [
            "scanners_in_ag",
            "default_scanner",
        ],
    ]
    AT_MOST_ONE_ARGS_INPUT = [
        ({}, {}),
        ({"at_most_one_groups": AT_MOST_ONE_GROUP_ARGS}, {}),
        ({"at_most_one_groups": AT_MOST_ONE_GROUP_ARGS},
         {"asset_group_ids": 1, "scanners_in_ag": 1, "frequency_days": 1}),
        (
            {"at_most_one_groups": AT_MOST_ONE_GROUP_ARGS},
            {"asset_groups": 1, "scanners_in_ag": 1, "frequency_weeks": 1}),
        (
            {"at_most_one_groups": AT_MOST_ONE_GROUP_ARGS},
            {"ip": "1.1.1.1", "default_scanner": 1, "frequency_months": 1}),
    ]

    @pytest.mark.parametrize("command_data, args", AT_MOST_ONE_ARGS_INPUT)
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
        Qualysv2.args_values = {"scanners_in_ag": 1, "default_scanner": 1}
        err_msg = "At most one of the following args can be given: ['scanners_in_ag', 'default_scanner']"
        with pytest.raises(DemistoException, match=re.escape(err_msg)):
            validate_at_most_one_group({"at_most_one_groups": self.AT_MOST_ONE_GROUP_ARGS})


class TestAssetTags:
    case_valid_asset_tag_list_args = (
        "qualys-asset-tag-list",
        {"criteria": "name", "operator": "EQUALS", "search_data": "parent_tag"},
        b'<ServiceRequest><filters><Criteria field="name" operator="EQUALS">parent_tag</Criteria></filters></ServiceRequest>',
    )
    case_valid_asset_tag_create_command = (
        "qualys-asset-tag-create",
        {
            "name": "parent_tag",
            "rule_type": "NAME_CONTAINS",
            "rule_text": "NetworkManager",
            "child_name": "child_1,child_2,child_3",
            "criticality_score": "2",
        },
        b"<ServiceRequest><data><Tag><name>parent_tag</name><ruleType>NAME_CONTAINS</ruleType><ruleText>NetworkManager</ruleText>"
        + b"<criticalityScore>2</criticalityScore><children><set><TagSimple><name>child_1</name></TagSimple><TagSimple><name>"
        + b"child_2</name></TagSimple><TagSimple><name>child_3</name></TagSimple></set></children></Tag></data></ServiceRequest>",
    )
    case_valid_asset_tag_update_command = (
        "qualys-asset-tag-update",
        {
            "name": "parent_tag",
            "rule_type": "NAME_CONTAINS",
            "rule_text": "NetworkManager",
            "child_to_remove": "child_1,child_2,child_3",
            "criticality_score": "2",
        },
        b"<ServiceRequest><data><Tag><name>parent_tag</name><ruleType>NAME_CONTAINS</ruleType><ruleText>NetworkManager</ruleText>"
        + b"<criticalityScore>2</criticalityScore><children><remove><TagSimple><id>child_1</id></TagSimple><TagSimple><id>"
        + b"child_2</id></TagSimple><TagSimple><id>child_3</id></TagSimple>"
        + b"</remove></children></Tag></data></ServiceRequest>",
    )
    VALID_ASSET_TAG_COMMAND_ARGS = [
        case_valid_asset_tag_list_args,
        case_valid_asset_tag_create_command,
        case_valid_asset_tag_update_command,
    ]

    @pytest.mark.parametrize("command_name, args, xml_request_body", VALID_ASSET_TAG_COMMAND_ARGS)
    def test_generate_asset_tag_xml_request_body(self, command_name: str, args: Dict, xml_request_body: bytes):
        assert Qualysv2.generate_asset_tag_xml_request_body(args, command_name) == xml_request_body

    def test_handle_asset_tag_result(self):
        raw_response = (
            '<?xml version="1.0" encoding="UTF-8"?>\n<ServiceResponse xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            + ' xsi:noNamespaceSchemaLocation="https://qualysapi.qg2.apps.qualys.com/qps/xsd/2.0/am/tag.xsd">\n '
            + " <responseCode>SUCCESS</responseCode>\n  <count>1</count>\n  <hasMoreRecords>false</hasMoreRecords>\n "
            + " <data>\n    <Tag>\n      <id>71163393</id>\n      <name>parent_tag</name>\n      "
            + "<created>2022-11-24T12:38:13Z</created>\n      <modified>2022-11-24T13:09:35Z</modified>\n     "
            + " <ruleType>INSTALLED_SOFTWARE</ruleType>\n      <children>\n        <list>\n          <TagSimple>\n"
            + "            <id>71163395</id>\n            <name>child_1</name>\n          </TagSimple>\n          "
            + "<TagSimple>\n            <id>71163394</id>\n            <name>child_2</name>\n          </TagSimple>\n"
            + "          <TagSimple>\n            <id>71163396</id>\n            <name>child_3</name>\n          "
            + "</TagSimple>\n        </list>\n      </children>\n      <criticalityScore>3</criticalityScore>\n"
            + "    </Tag>\n  </data>\n</ServiceResponse>"
        )
        command_name = "qualys-asset-tag-list"
        expected_result = {
            "id": "71163393",
            "name": "parent_tag",
            "created": "2022-11-24T12:38:13Z",
            "modified": "2022-11-24T13:09:35Z",
            "ruleType": "INSTALLED_SOFTWARE",
            "children": {
                "list": {
                    "TagSimple": [
                        {"id": "71163395", "name": "child_1"},
                        {"id": "71163394", "name": "child_2"},
                        {"id": "71163396", "name": "child_3"},
                    ]
                }
            },
            "criticalityScore": "3",
        }
        assert Qualysv2.handle_asset_tag_result(raw_response, command_name) == expected_result

    def test_handle_asset_tag_result_fail(self, mocker):
        mocker.patch.object(
            Qualysv2,
            "format_and_validate_response",
            return_value={"ServiceResponse": {"responseErrorDetails": {"errorMessage": "response with error message"}}},
        )

        with pytest.raises(DemistoException):
            Qualysv2.handle_asset_tag_result(raw_response=requests.Response(), command_name="")

    def test_build_tag_asset_output(self):
        args = {
            "command_parse_and_output_data": {
                "table_name": "Tags identified by the specified filter",
                "json_path": ["ServiceResponse", "data", "Tag"],
                "table_headers": ["ID", "name", "criticalityScore", "ruleText", "ruleType", "Child Tags"],
            },
            "handled_result": {
                "id": "0",
                "name": "parent_tag",
                "created": "2022-11-24T12:38:13Z",
                "modified": "2022-11-24T13:09:35Z",
                "ruleType": "INSTALLED_SOFTWARE",
                "children": {
                    "list": {
                        "TagSimple": [
                            {"id": "1", "name": "child_1"},
                            {"id": "2", "name": "child_2"},
                            {"id": "3", "name": "child_3"},
                        ]
                    }
                },
                "criticalityScore": "3",
            },
        }
        handled_result = {
            "id": "0",
            "name": "parent_tag",
            "created": "2022-11-24T12:38:13Z",
            "modified": "2022-11-24T13:09:35Z",
            "ruleType": "INSTALLED_SOFTWARE",
            "criticalityScore": "3",
            "childTags": [
                {"id": "1", "name": "child_1"},
                {"id": "2", "name": "child_2"},
                {"id": "3", "name": "child_3"},
            ],
        }
        assert Qualysv2.build_tag_asset_output(**args)[0] == handled_result


def test_handle_asset_tag_request_parameters():
    """
    Given
        - id argument
        - the command supports sending an XML request body
    When
        - Am asset-tag command is run
    Then
        - add an id to the http request and generate a request body
    """
    Qualysv2.handle_asset_tag_request_parameters({'id': '1234'}, "qualys-asset-tag-list")


def test_input_validation():
    """
    Given
        - A command name
    When
        - Any command is run
    Then
        - the input_validation command will validate the command name exists
    """
    assert Qualysv2.input_validation("qualys-asset-tag-list") is None


def test_calculate_ip_original_amount():
    """
    Given
        - A Parsed output, a dictionary that might contain a list of single ips and a list of ranges of ips.
        IP addresses and ranges are represented by a list of items, unless there's only a single item,
        then it's a string.
    When
        - A command that returns a list of IP's is run.
    Then
        - An integer which is the amount of ip addresses and ranges will be returned
    """
    result = {'Address': 'address', 'Range': 'range'}
    assert Qualysv2.calculate_ip_original_amount(result) == 2


def test_create_ip_list_markdown_table():
    """
    Given
        - A dictionary of IP's
    When
        - Dictionary IP's is a part of the API result
    Then
        - create_ip_list_markdown_table will generate a markdown for the IP's
    """
    dicts_of_ranges_and_ips = [{'1': 1}, {'2': 2}]
    readable_output = '|1|\n|---|\n| 1 |\n\n|2|\n|---|\n| 2 |\n'
    assert Qualysv2.create_ip_list_markdown_table(dicts_of_ranges_and_ips) == readable_output


def test_create_single_host_list():
    """
    Given
        - ip_and_range_lists: A dictionary that can have either a single ip as a string or
        a list of single ips in the key 'Address' and/or a single range as a string or
        a list of range of ips in the key 'Range'
    When
        - build_ip_list_output is run
    Then
        - create_single_host_list function will generate a list that has both ips and ranges of ips
    """
    ip_and_range_lists = {'Address': 'address', 'Range': 'range'}
    assert Qualysv2.create_single_host_list(ip_and_range_lists) == ['address', 'range']


def test_build_ip_and_range_dicts():
    """
    Given
        - ips_and_ranges: A list that might contain both ips and ranges of ips
        Returns: A list that has one list which consists of single value dictionaries of ips
        and another list which consists of single values dictionaries of ranges
    When
        - build_ip_list_from_single_value or build_ip_list_output functions are run
    Then
        - build_ip_and_range_dicts will generate a list that has one list which consists of single value dictionaries of ips
             and another list which consists of single values dictionaries of ranges
    """
    assert Qualysv2.build_ip_and_range_dicts(['-', 'example']) == [[{'ip': 'example'}], [{'range': '-'}]]


truncate_test_cases = [
    # Case 1: Asset with ID and detection unique vuln ID, and exceeds size limit
    ({
        "ID": "12345",
        "DETECTION": {
            "UNIQUE_VULN_ID": "vuln1",
            "RESULTS": "A" * 2 * 10 ** 6  # Exceeds size limit
        }
    },
        True),

    # Case 2: Asset with no ID and detection unique vuln ID, and exceeds size limit
    ({
        "DETECTION": {
            "UNIQUE_VULN_ID": "vuln2",
            "RESULTS": "A" * 2 * 10 ** 6  # Exceeds size limit
        }
    },
        True),
    # Case 3: Asset with ID and no detection unique vuln ID, and does not exceed size limit
    ({
        "ID": "12345",
        "DETECTION": {
            "RESULTS": "A" * 100  # Does not exceed size limit
        }
    },
        False),
    # Case 4: Asset with no ID and no detection unique vuln ID, and does not exceed size limit
    ({
        "DETECTION": {
            "RESULTS": "A" * 100  # Does not exceed size limit
        }
    },
        False)
]


@pytest.mark.parametrize('asset, expected_truncated', truncate_test_cases)
def test_truncate_asset_size(mocker, asset, expected_truncated):
    """
    Given:
    - Case 1: Asset which exceeds size limit with ID and detection unique vuln ID.
    - Case 2: Asset which exceeds size limit with no ID and detection unique vuln ID.
    - Case 3: Asset which does not exceed size limit with ID and no detection unique vuln ID.
    - Case 4: Asset which does not exceed size limit with no ID and no detection unique vuln ID.

    When: calling truncate_asset_size with the given asset

    Then:
    - Case 1: ensure the isTruncated flag is set to true, that the size of the assets was truncated to 1000 and that
        debug logs were printed.
    - Case 2: ensure the isTruncated flag is set to true, that the size of the assets was truncated to 1000 and that
        debug logs were printed.
    - Case 3: ensure the isTruncated flag is set to false or does not exist and that debug logs were not printed.
    - Case 4: ensure the isTruncated flag is set to false or does not exist and that debug logs were not printed.

    """
    mock_debug = mocker.patch.object(demisto, 'debug')

    Qualysv2.truncate_asset_size(asset)

    if expected_truncated:
        assert asset.get('isTruncated', False) is True
        assert len(asset['DETECTION']['RESULTS']) == 10000
        assert mock_debug.call_count >= 2  # Expecting at least 2 debug messages
    else:
        assert asset.get('isTruncated', False) is False
        assert mock_debug.call_count == 0  # No debug messages if not truncated

    # Reset mock_debug for the next test case
    mock_debug.reset_mock()
