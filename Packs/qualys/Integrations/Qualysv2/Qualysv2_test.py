import io
import re
from unittest.mock import Mock, PropertyMock
from xml.etree import ElementTree
import Qualysv2
import pytest
import requests
from urllib3.exceptions import ProtocolError, ReadTimeoutError
from requests_mock import Mocker as RequestsMocker
from pytest_mock import MockerFixture
from freezegun import freeze_time
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
    publish_assets_and_vulnerabilities,
    set_assets_last_run_with_new_limit,
    fetch_events,
    get_activity_logs_events,
    get_detections_from_hosts,
    iter_detections_from_hosts,
    iter_batches,
    iter_host_list_detections,
    fetch_and_send_assets_streamed,
    handle_host_list_detection_result,
    handle_vulnerabilities_result,
    fetch_assets_and_vulnerabilities_by_date,
    fetch_assets_and_vulnerabilities_by_qids,
    fetch_and_send_assets_and_vulnerabilities_by_qids,
    fetch_vulnerabilities_of_new_qids,
    build_next_last_run,
    HOST_LIMIT,
    API_SUFFIX_DETECTION,
    API_SUFFIX_KNOWLEDGEBASE,
    VENDOR,
    DEFAULT_LAST_ASSETS_RUN,
)

from CommonServerPython import *  # noqa: F401

ACTIVITY_LOGS_NEWEST_EVENT_DATETIME = "activity_logs_newest_event_datetime"
ACTIVITY_LOGS_NEXT_PAGE = "activity_logs_next_page"
ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN = "activity_logs_since_datetime_prev_run"
HOST_DETECTIONS_NEWEST_EVENT_DATETIME = "host_detections_newest_event_datetime"
HOST_DETECTIONS_NEXT_PAGE = "host_detections_next_page"
HOST_DETECTIONS_SINCE_DATETIME_PREV_RUN = "host_detections_since_datetime_prev_run"
HOST_LAST_FETCH = "host_last_fetch"
BEGIN_RESPONSE_LOGS_CSV = "----BEGIN_RESPONSE_BODY_CSV"
END_RESPONSE_LOGS_CSV = "----END_RESPONSE_BODY_CSV"
FOOTER = """----BEGIN_RESPONSE_FOOTER_CSV
WARNING
"CODE","TEXT","URL"
"1980","17 record limit exceeded. Use URL to get next batch of results.","https://server_url/api/2.0/fo/activity_log/
?action=list&since_datetime=2022-12-21T03:42:05Z&truncation_limit=10&id_max=123456"
----END_RESPONSE_FOOTER_CSV"""

BASE_URL = "https://server_url.com/"
SNAPSHOT_ID = "1737885000"


@pytest.fixture
def client() -> Client:
    """Fixture to create a Qualys.Client instance."""
    return Client(base_url=BASE_URL, verify=False, headers={}, proxy=False, username="demisto", password="demisto")


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_activity_logs_events_command(requests_mock: RequestsMocker, client: Client):
    """
    Given:
    - activity_logs_events_command

    When:
    - Want to list all existing activity logs

    Then:
    - Ensure Activity Logs Results in human-readable, and number of results reasonable.
    """
    with open("test_data/activity_logs.csv") as f:
        logs = f.read()
    requests_mock.get(
        f"{BASE_URL}api/2.0/fo/activity_log/?action=list&truncation_limit=0&since_datetime=2023-03-01T00%3A00%3A00Z",
        text=logs,
    )
    args = {"limit": 50, "since_datetime": "1 March 2023"}
    first_fetch = "2022-03-21T03:42:05Z"
    activity_logs_events, results = get_activity_logs_events_command(client, args, first_fetch)
    assert "Activity Logs" in results.readable_output
    assert len(activity_logs_events) == 17


@pytest.mark.parametrize(
    "activity_log_last_run, logs_number, add_footer",
    [(None, 17, True), ("2023-05-24T09:55:35Z", 0, True), ("2023-05-14T15:04:55Z", 7, True), ("2023-01-01T08:06:44Z", 17, False)],
)
def test_fetch_logs_events_command(requests_mock, activity_log_last_run, logs_number, add_footer, client: Client):
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
    first_fetch_str = "2022-12-21T03:42:05Z"
    truncation_limit = logs_number
    with open("test_data/activity_logs.csv") as f:
        logs = f.read()
        new_logs = f"{BEGIN_RESPONSE_LOGS_CSV}"
        for row in logs.split("\n"):
            if activity_log_last_run and activity_log_last_run in row:
                new_logs += f"{row}\n"
                break
            new_logs += f"{row}\n"
        new_logs += f"{END_RESPONSE_LOGS_CSV}\n"
        if add_footer:
            new_logs += f"{FOOTER}\n"

    requests_mock.get(
        f"{BASE_URL}api/2.0/fo/activity_log/"
        f"?action=list&truncation_limit={truncation_limit}&"
        f"since_datetime={activity_log_last_run if activity_log_last_run else first_fetch_str}",
        text=new_logs,
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


def _streamed_response(xml_bytes: bytes) -> Mock:
    """Builds a fake streamed ``requests.Response`` whose ``.raw`` is a readable byte stream, mimicking ``stream=True``."""
    response = Mock(spec=requests.Response)
    response.raw = io.BytesIO(xml_bytes)
    return response


def test_handle_host_list_detection_result_none_response():
    """
    Given:
    - A None response (e.g. the request timed out in get_host_list_detection).
    When:
    - Calling handle_host_list_detection_result.
    Then:
    - Returns no hosts and an empty next URL, without raising.
    """
    hosts, next_url = handle_host_list_detection_result(None)
    assert hosts == []
    assert next_url == ""


def test_handle_host_list_detection_result_streams_hosts_and_pagination():
    """
    Given:
    - A streamed host list detection XML response with two HOST records and a WARNING/URL pagination block.
    When:
    - Calling handle_host_list_detection_result (single-pass streaming parse).
    Then:
    - Both hosts are extracted with their nested fields, and the next page URL is read from WARNING/URL.
    """
    xml_bytes = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b"<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>"
        b"<HOST><ID>1</ID><IP>1.1.1.1</IP></HOST>"
        b"<HOST><ID>2</ID><IP>2.2.2.2</IP></HOST>"
        b"</HOST_LIST>"
        b"<WARNING><CODE>1980</CODE><URL>https://qualys.example/api?id_min=3</URL></WARNING>"
        b"</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"
    )

    hosts, next_url = handle_host_list_detection_result(_streamed_response(xml_bytes))

    assert len(hosts) == 2
    assert hosts[0]["ID"] == "1"
    assert hosts[0]["IP"] == "1.1.1.1"
    assert hosts[1]["ID"] == "2"
    assert next_url == "https://qualys.example/api?id_min=3"


def test_handle_host_list_detection_result_no_pagination():
    """
    Given:
    - A streamed host list detection XML response with a single HOST and no WARNING block.
    When:
    - Calling handle_host_list_detection_result.
    Then:
    - The host is extracted and the next URL is empty.
    """
    xml_bytes = (
        b"<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>"
        b"<HOST><ID>7</ID></HOST>"
        b"</HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"
    )

    hosts, next_url = handle_host_list_detection_result(_streamed_response(xml_bytes))

    assert len(hosts) == 1
    assert hosts[0]["ID"] == "7"
    assert next_url == ""


def test_handle_host_list_detection_result_raises_on_error_envelope():
    """
    Given:
    - A streamed SIMPLE_RETURN error envelope response (as Qualys returns on API errors).
    When:
    - Calling handle_host_list_detection_result.
    Then:
    - A DemistoException is raised containing both the error TEXT and CODE.
    """
    xml_bytes = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b"<SIMPLE_RETURN><RESPONSE><CODE>1234</CODE><TEXT>bad request</TEXT></RESPONSE></SIMPLE_RETURN>"
    )

    with pytest.raises(DemistoException) as e:
        handle_host_list_detection_result(_streamed_response(xml_bytes))

    assert "1234" in str(e.value)
    assert "bad request" in str(e.value)


def test_get_detections_from_hosts_preserves_existing_last_vm_auth_scan_datetime():
    """
    Given:
    - A host that already contains the LAST_VM_AUTH_SCAN_DATETIME field.
    When:
    - Parsing detections from hosts via get_detections_from_hosts.
    Then:
    - Ensure the existing LAST_VM_AUTH_SCAN_DATETIME value is preserved.
    """
    hosts = [
        {
            "ID": "1",
            "IP": "1.1.1.1",
            "LAST_VM_SCANNED_DATE": "01-01-2020",
            "LAST_VM_AUTH_SCAN_DATETIME": "2020-01-01T00:00:00Z",
            "DETECTION_LIST": {"DETECTION": [{"QID": "123"}]},
        }
    ]

    assets, _ = get_detections_from_hosts(hosts)

    assert len(assets) == 1
    assert assets[0]["LAST_VM_AUTH_SCAN_DATETIME"] == "2020-01-01T00:00:00Z"


def test_get_detections_from_hosts_fans_out_multiple_detections():
    """
    Given:
    - A single host containing multiple detections in its DETECTION_LIST.
    When:
    - Parsing detections from hosts via get_detections_from_hosts.
    Then:
    - Ensure one asset is produced per detection, each carrying the host-level fields, with the specific
      DETECTION assigned and the DETECTION_LIST key removed.
    """
    hosts = [
        {
            "ID": "1",
            "IP": "1.1.1.1",
            "LAST_VM_SCANNED_DATE": "01-01-2020",
            "DETECTION_LIST": {"DETECTION": [{"QID": "123"}, {"QID": "456"}, {"QID": "789"}]},
        }
    ]

    assets, _ = get_detections_from_hosts(hosts)

    assert len(assets) == 3
    assert [asset["DETECTION"]["QID"] for asset in assets] == ["123", "456", "789"]
    for asset in assets:
        # Host-level fields are carried onto every asset...
        assert asset["ID"] == "1"
        assert asset["IP"] == "1.1.1.1"
        assert asset["LAST_VM_SCANNED_DATE"] == "01-01-2020"
        # ...and the original DETECTION_LIST container is not present on the flattened asset.
        assert "DETECTION_LIST" not in asset


def test_get_detections_from_hosts_assets_are_independent_copies():
    """
    Given:
    - A single host with multiple detections and a nested host-level field.
    When:
    - Parsing detections from hosts via get_detections_from_hosts and then mutating a nested host-level
      field on one resulting asset.
    Then:
    - Ensure sibling assets from the same host are not affected (each asset is an independent deep copy).
    """
    hosts = [
        {
            "ID": "1",
            "IP": "1.1.1.1",
            "CLOUD_TAGS": {"TAG": {"NAME": "env", "VALUE": "prod"}},
            "DETECTION_LIST": {"DETECTION": [{"QID": "123"}, {"QID": "456"}]},
        }
    ]

    assets, _ = get_detections_from_hosts(hosts)

    assert len(assets) == 2
    # Mutate a nested host-level field on the first asset only.
    assets[0]["CLOUD_TAGS"]["TAG"]["VALUE"] = "mutated"

    # The sibling asset must retain the original nested value (proves deep, independent copies).
    assert assets[1]["CLOUD_TAGS"]["TAG"]["VALUE"] == "prod"


def test_handle_vulnerabilities_result_none_response():
    """
    Given:
    - A None response (e.g. the vulnerabilities request failed/returned nothing).
    When:
    - Calling handle_vulnerabilities_result.
    Then:
    - Ensure an empty list is returned without raising.
    """
    assert handle_vulnerabilities_result(None) == []


def test_handle_vulnerabilities_result_streams_vulnerabilities():
    """
    Given:
    - A streamed vulnerabilities XML response body.
    When:
    - Calling handle_vulnerabilities_result (single-pass streaming parse).
    Then:
    - Ensure all VULN records are extracted and match the expected parsed vulnerabilities.
    """
    with open("./test_data/vulnerabilities_raw.xml", "rb") as f:
        xml_bytes = f.read()

    expected_vulnerabilities = util_load_json("./test_data/fetched_vulnerabilities.json")

    vulnerabilities = handle_vulnerabilities_result(_streamed_response(xml_bytes))

    assert vulnerabilities == expected_vulnerabilities


@pytest.mark.parametrize(
    "xml_bytes",
    [
        b"<VULN><QID>1</QID><TITLE>Example</TITLE></VULN>",
        b"<HOST><ID>1</ID><IP>1.1.1.1</IP><DETECTION_LIST>"
        b"<DETECTION><QID>10</QID></DETECTION><DETECTION><QID>20</QID></DETECTION>"
        b"</DETECTION_LIST></HOST>",
        b"<WARNING><CODE>1980</CODE><URL>https://qualys.example/api?id_min=3</URL></WARNING>",
    ],
)
def test_elem_to_internal_matches_xml2json_roundtrip(xml_bytes: bytes):
    """
    Given:
    - A parsed XML element (single VULN, a HOST with repeated DETECTION children, and a WARNING block).
    When:
    - Converting it with elem_to_internal (used directly by the streaming parsers).
    Then:
    - The result is identical to the previous json.loads(xml2json(ElementTree.tostring(element))) round-trip,
      proving the optimization preserves the exact dict structure (including repeated-element lists).
    """
    element = ElementTree.fromstring(xml_bytes)

    optimized = elem_to_internal(element)
    legacy = json.loads(xml2json(ElementTree.tostring(element)))

    assert optimized == legacy


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
                    "RESPONSE": {"DATETIME": "2021-03-24T15:40:23Z", "TEXT": "IPs successfully added to Vulnerability Management"}
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

        assert handle_general_result(dummy_response, "qualys-ip-list") == {"DATETIME": "sometime", "IP_SET": {"IP": ["1.1.1.1"]}}

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
        expected_result = {"launched_after_datetime": "2021-12-26", "published_before": "2021-12-26", "start_date": "12/26/2021"}

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
            handled_result=result, command_parse_and_output_data=COMMANDS_PARSE_AND_OUTPUT_DATA["qualys-host-list-detection"]
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
        (
            MockResponse(
                """<?xml version="1.0" encoding="UTF-8" ?>
<SIMPLE_RETURN>
  <RESPONSE>
    <CODE>1965</CODE>
    <TEXT>This API cannot be run again for another 40 seconds.</TEXT>
  </RESPONSE>
</SIMPLE_RETURN>""",
                409,
            ),
            "Rate limit reached - the Qualys API rate limit was exceeded.\nError in API call [409] - None\n"
            "Error Code: 1965\nError Message: This API cannot be run again for another 40 seconds.",
        ),
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

        assert client_http_request.call_count == 1
        assert http_request_kwargs["method"] == "GET"
        assert http_request_kwargs["url_suffix"] == urljoin(
            API_SUFFIX_DETECTION, "asset/host/vm/detection/?action=list&host_metadata=all&show_cloud_tags=1"
        )
        assert http_request_kwargs["params"] == {
            "truncation_limit": HOST_LIMIT,
            "vm_scan_date_after": since_datetime,
            "show_qds": 1,
            "show_qds_factors": 1,
        }

    @pytest.mark.parametrize(
        "since_datetime, detection_qids, expected_params",
        [
            pytest.param("2024-12-12", None, {"last_modified_after": "2024-12-12"}, id="Specified since datetime"),
            pytest.param(None, "A,B", {"ids": "A,B"}, id="Specified detection QIDs"),
        ],
    )
    def test_get_vulnerabilities(
        self,
        mocker: MockerFixture,
        since_datetime: str | None,
        detection_qids: str | None,
        expected_params: dict,
    ) -> None:
        """
        Given:
            - Either a since_datetime or detection_qids value.
        When:
            - Calling client.get_vulnerabilities.
        Assert:
            - Ensure correct request HTTP method, API endpoint, and params.
        """
        client_http_request = mocker.patch.object(self.client, "_http_request")
        self.client.get_vulnerabilities(since_datetime, detection_qids)

        http_request_kwargs = client_http_request.call_args.kwargs

        assert client_http_request.call_count == 1
        assert http_request_kwargs["method"] == "POST"
        assert http_request_kwargs["url_suffix"] == urljoin(API_SUFFIX_KNOWLEDGEBASE, "knowledge_base/vuln/?action=list")
        assert http_request_kwargs["params"] == expected_params

    @pytest.mark.parametrize(
        "exception",
        [
            pytest.param(requests.exceptions.ReadTimeout, id="ReadTimeout"),
            pytest.param(requests.exceptions.ChunkedEncodingError, id="ChunkedEncodingError"),
        ],
    )
    def test_get_vulnerabilities_timeout(self, mocker: MockerFixture, exception: type) -> None:
        """
        Given:
            - A ReadTimeout or ChunkedEncodingError raised by the HTTP request.
        When:
            - Calling client.get_vulnerabilities.
        Assert:
            - The exception is re-raised after logging.
        """
        mocker.patch.object(self.client, "_http_request", side_effect=exception())
        mocker.patch("Qualysv2.demisto.error")
        with pytest.raises(exception):
            self.client.get_vulnerabilities(since_datetime="2024-12-12")


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
        ({"required_depended_args": DEPENDANT_ARGS}, {k: 3 for k, v in DEPENDANT_ARGS.items() if v == "frequency_months"}),
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
        with pytest.raises(DemistoException, match="Argument day_of_month is required when argument frequency_months is given."):
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
        ({"at_most_one_groups": AT_MOST_ONE_GROUP_ARGS}, {"asset_group_ids": 1, "scanners_in_ag": 1, "frequency_days": 1}),
        ({"at_most_one_groups": AT_MOST_ONE_GROUP_ARGS}, {"asset_groups": 1, "scanners_in_ag": 1, "frequency_weeks": 1}),
        ({"at_most_one_groups": AT_MOST_ONE_GROUP_ARGS}, {"ip": "1.1.1.1", "default_scanner": 1, "frequency_months": 1}),
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
    Qualysv2.handle_asset_tag_request_parameters({"id": "1234"}, "qualys-asset-tag-list")


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
    result = {"Address": "address", "Range": "range"}
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
    dicts_of_ranges_and_ips = [{"1": 1}, {"2": 2}]
    readable_output = "|1|\n|---|\n| 1 |\n\n|2|\n|---|\n| 2 |\n"
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
    ip_and_range_lists = {"Address": "address", "Range": "range"}
    assert Qualysv2.create_single_host_list(ip_and_range_lists) == ["address", "range"]


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
    assert Qualysv2.build_ip_and_range_dicts(["-", "example"]) == [[{"ip": "example"}], [{"range": "-"}]]


truncate_test_cases = [
    # Case 1: Asset with ID and detection unique vuln ID, and exceeds size limit
    (
        {
            "ID": "12345",
            "DETECTION": {
                "UNIQUE_VULN_ID": "vuln1",
                "RESULTS": "A" * 2 * 10**6,  # Exceeds size limit
            },
        },
        True,
    ),
    # Case 2: Asset with no ID and detection unique vuln ID, and exceeds size limit
    (
        {
            "DETECTION": {
                "UNIQUE_VULN_ID": "vuln2",
                "RESULTS": "A" * 2 * 10**6,  # Exceeds size limit
            }
        },
        True,
    ),
    # Case 3: Asset with ID and no detection unique vuln ID, and does not exceed size limit
    (
        {
            "ID": "12345",
            "DETECTION": {
                "RESULTS": "A" * 100  # Does not exceed size limit
            },
        },
        False,
    ),
    # Case 4: Asset with no ID and no detection unique vuln ID, and does not exceed size limit
    (
        {
            "DETECTION": {
                "RESULTS": "A" * 100  # Does not exceed size limit
            }
        },
        False,
    ),
]


@pytest.mark.parametrize("asset, expected_truncated", truncate_test_cases)
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
    mock_debug = mocker.patch.object(demisto, "debug")

    Qualysv2.truncate_asset_size(asset)

    if expected_truncated:
        assert asset.get("isTruncated", False) is True
        assert len(asset["DETECTION"]["RESULTS"]) == 10000
        assert mock_debug.call_count >= 2  # Expecting at least 2 debug messages
    else:
        assert asset.get("isTruncated", False) is False
        assert mock_debug.call_count == 0  # No debug messages if not truncated

    # Reset mock_debug for the next test case
    mock_debug.reset_mock()


def test_set_assets_last_run_with_new_limit():
    """
    Given:
        - A last run dictionary with fetch stage, total assets count, and snapshot ID.

    When:
        - Calling set_assets_last_run_with_new_limit.

    Assert:
        - Ensure last_run is correctly updated with half 'limit', 'nextTrigger' 0, and 'type' 1.
    """
    last_run = {"stage": "assets", "total_assets": 10, "snapshot_id": SNAPSHOT_ID}
    updated_last_run = set_assets_last_run_with_new_limit(last_run, limit=HOST_LIMIT)

    assert updated_last_run == {
        **last_run,
        "nextTrigger": "0",
        "type": 1,  # assets
        "limit": HOST_LIMIT // 2,
    }


def _make_host(host_id: str, num_detections: int) -> dict:
    """Build a minimal host dict with `num_detections` detections, mirroring the Qualys host/detection shape."""
    detections = [
        {"QID": f"{host_id}-{i}", "FIRST_FOUND_DATETIME": f"2025-01-0{(i % 9) + 1}T00:00:00Z"} for i in range(num_detections)
    ]
    return {"ID": host_id, "IP": "1.1.1.1", "DETECTION_LIST": {"DETECTION": detections if detections else {}}}


@pytest.mark.parametrize(
    "items, expected_batches",
    [
        pytest.param([1, 2, 3, 4, 5], [[1, 2], [3, 4], [5]], id="partial-last-batch"),
        pytest.param([1, 2, 3, 4], [[1, 2], [3, 4]], id="exact-multiple-no-empty-batch"),
        pytest.param([], [], id="empty-input"),
    ],
)
def test_iter_batches(items: list, expected_batches: list):
    """
    Given:
        - An iterable of items and a batch size of 2.

    When:
        - Grouping it with iter_batches.

    Assert:
        - Batches hold at most 2 items, only the last batch can be shorter, and no empty batch is yielded.
    """
    assert list(iter_batches(iter(items), 2)) == expected_batches


def test_iter_detections_from_hosts_matches_get_detections_from_hosts():
    """
    Given:
        - A list of hosts, each with multiple detections.

    When:
        - Fanning out detections lazily via iter_detections_from_hosts vs eagerly via get_detections_from_hosts.

    Assert:
        - Both produce the exact same detection rows (same fan-out, deep copy, and truncation semantics).
    """
    hosts = [_make_host("h1", 3), _make_host("h2", 2)]

    streamed = list(iter_detections_from_hosts([dict(h) for h in hosts]))
    eager, _ = get_detections_from_hosts([dict(h) for h in hosts])

    assert streamed == eager
    assert len(streamed) == 5  # 3 + 2 detections
    # Each row carries its own DETECTION and the host-without-DETECTION_LIST fields.
    assert all("DETECTION" in row and "DETECTION_LIST" not in row for row in streamed)


def test_iter_host_list_detections_matches_handle_host_list_detection_result(mocker: MockerFixture):
    """
    Given:
        - A streamed host-list-detection response yielding two HOST elements and a next-page URL.

    When:
        - Consuming it via iter_host_list_detections (with a stream_state holder).

    Assert:
        - The yielded hosts and the captured next_url match handle_host_list_detection_result's output.
    """
    hosts = [{"HOST": _make_host("h1", 1)}, {"HOST": _make_host("h2", 1)}]
    stream_elements = [("HOST", f"elem{i}") for i in range(len(hosts))] + [("WARNING", "warn")]

    mocker.patch("Qualysv2.stream_xml_elements", return_value=iter(stream_elements))

    def fake_elem_to_internal(element):
        if element == "warn":
            return {"WARNING": {"URL": "https://qualys/next?id_min=42"}}
        return hosts[int(str(element).replace("elem", ""))]

    mocker.patch("Qualysv2.elem_to_internal", side_effect=fake_elem_to_internal)

    raw_response = Mock()
    stream_state: dict = {}
    yielded = list(iter_host_list_detections(raw_response, stream_state))

    assert yielded == [h["HOST"] for h in hosts]
    assert stream_state["next_url"] == "https://qualys/next?id_min=42"


@freeze_time("2025-01-01 00:00:00 UTC")
def test_fetch_and_send_assets_streamed_last_page_seals_snapshot(mocker: MockerFixture, client: Client):
    """
    Given:
        - A last page (no next page) of 5 hosts with 1 detection each, committed every 2 hosts.

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - Each commit sends items_count=1 (unsealed); only the final send seals with the cumulative total.
        - Every send uses the same snapshot_id, product "assets", and should_update_health_module=False.
        - The returned last run moves to the "vulnerabilities" stage, keeping since_datetime and snapshot_id.
    """
    last_run = {"stage": "assets", "total_assets": 10, "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}
    hosts = [_make_host(str(100 + i), 1) for i in range(5)]

    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.iter_host_list_detections", return_value=iter(hosts))
    mocker.patch("Qualysv2.get_next_page_from_url", return_value="")  # last page
    mock_send = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")
    mock_health = mocker.patch("Qualysv2.demisto.updateModuleHealth")
    mocker.patch("Qualysv2.demisto.setAssetsLastRun")
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 2)

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    assert set_new_limit is False
    # 5 hosts, 2 hosts per commit => 2 commits (items_count=1) + 1 sealing send (cumulative total).
    assert mock_send.call_count == 3
    sent_host_ids: list = []
    for call in mock_send.call_args_list:
        sent_host_ids.extend(row["ID"] for row in call.args[0])
        assert call.kwargs["product"] == "assets"
        assert call.kwargs["snapshot_id"] == SNAPSHOT_ID
        assert call.kwargs["should_update_health_module"] is False
    assert sent_host_ids == [host["ID"] for host in hosts]

    cumulative_total = 10 + 5
    assert mock_send.call_args_list[0].kwargs["items_count"] == "1"
    assert mock_send.call_args_list[1].kwargs["items_count"] == "1"
    assert mock_send.call_args_list[2].kwargs["items_count"] == str(cumulative_total)  # sealing send

    mock_health.assert_called_once_with({"assetsPulled": cumulative_total})
    assert new_last_run["stage"] == "vulnerabilities"
    assert new_last_run["next_page"] == ""
    assert new_last_run["total_assets"] == cumulative_total
    assert new_last_run["since_datetime"] == "2024-10-03"
    assert new_last_run["snapshot_id"] == SNAPSHOT_ID


@freeze_time("2025-01-01 00:00:00 UTC")
def test_fetch_and_send_assets_streamed_commits_last_run_after_each_hosts_batch(mocker: MockerFixture, client: Client):
    """
    Given:
        - A page of 4 hosts (IDs 100-103) with 2 detections each, committed every 2 hosts.

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - After each commit the last run is saved with next_page set to the last sent host ID + 1, the cumulative total
          of rows sent so far, the same snapshot ID, and the current limit (so a resumed request uses the same page size).
    """
    last_run = {"stage": "assets", "total_assets": 10, "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID, "limit": 50}
    hosts = [_make_host(str(100 + i), 2) for i in range(4)]

    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.iter_host_list_detections", return_value=iter(hosts))
    mocker.patch("Qualysv2.get_next_page_from_url", return_value="500")
    mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")
    mock_set_last_run = mocker.patch("Qualysv2.demisto.setAssetsLastRun")
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 2)

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    committed_runs = [call.args[0] for call in mock_set_last_run.call_args_list]
    assert [run["next_page"] for run in committed_runs] == ["102", "104"]
    assert [run["total_assets"] for run in committed_runs] == [14, 18]
    assert all(run["snapshot_id"] == SNAPSHOT_ID and run["stage"] == "assets" for run in committed_runs)
    assert all(run["limit"] == 50 for run in committed_runs)
    # The page completed, so the returned last run moves to the next page from the Qualys response.
    assert set_new_limit is False
    assert new_last_run["next_page"] == "500"
    assert new_last_run["total_assets"] == 18


@freeze_time("2025-01-01 00:00:00 UTC")
@pytest.mark.parametrize(
    "stream_error",
    [
        pytest.param(requests.exceptions.ChunkedEncodingError("Connection broken"), id="ChunkedEncodingError"),
        pytest.param(ProtocolError("Connection broken"), id="urllib3-ProtocolError"),
        pytest.param(ReadTimeoutError(None, None, "Connection broken"), id="urllib3-ReadTimeoutError"),  # type: ignore[arg-type]
        pytest.param(ElementTree.ParseError("Connection broken: no element found"), id="ParseError"),
    ],
)
def test_fetch_and_send_assets_streamed_error_after_commit_resumes_from_last_commit(
    mocker: MockerFixture, client: Client, stream_error: Exception
):
    """
    Given:
        - A page whose stream breaks after 3 hosts, committed every 2 hosts. The error is one of those raised while
          reading a streamed body: a requests error, a urllib3 error from a `raw` read, or a parse error from a
          cut-off XML body.

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - The error does not propagate, and the response is closed.
        - Only the committed hosts were sent (the uncommitted third host is not sent).
        - The last commit is returned without a limit reduction, so the next fetch resumes from the next host ID.
    """
    last_run = {"stage": "assets", "total_assets": 10, "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}
    hosts = [_make_host(str(100 + i), 1) for i in range(3)]

    def broken_stream(*_args, **_kwargs):
        yield from hosts
        raise stream_error

    raw_response = Mock()
    mocker.patch.object(client, "get_host_list_detection", return_value=(raw_response, False))
    mocker.patch("Qualysv2.iter_host_list_detections", side_effect=broken_stream)
    mock_send = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")
    mocker.patch("Qualysv2.demisto.setAssetsLastRun")
    mock_error = mocker.patch("Qualysv2.demisto.error")
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 2)

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    assert set_new_limit is False
    assert mock_send.call_count == 1
    assert [row["ID"] for row in mock_send.call_args.args[0]] == ["100", "101"]
    assert new_last_run["next_page"] == "102"
    assert new_last_run["total_assets"] == 12
    assert new_last_run["snapshot_id"] == SNAPSHOT_ID
    raw_response.close.assert_called_once()
    assert "Connection broken" in mock_error.call_args.args[0]


@freeze_time("2025-01-01 00:00:00 UTC")
def test_fetch_and_send_assets_streamed_send_failure_before_commit_reduces_limit(mocker: MockerFixture, client: Client):
    """
    Given:
        - A page where the first send to XSIAM fails, so nothing was committed in this run.

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - The error does not propagate, the last run is returned with the consecutive failures counter incremented,
          and set_new_limit=True so the caller retries the same page with a reduced limit.
    """
    last_run = {"stage": "assets", "total_assets": 10, "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}
    hosts = [_make_host(str(100 + i), 1) for i in range(2)]

    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.iter_host_list_detections", return_value=iter(hosts))
    mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam", side_effect=DemistoException("XSIAM unavailable"))
    mock_set_last_run = mocker.patch("Qualysv2.demisto.setAssetsLastRun")
    mock_error = mocker.patch("Qualysv2.demisto.error")
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 2)

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    assert set_new_limit is True
    assert new_last_run == {**last_run, "consecutive_failures": 1}
    mock_set_last_run.assert_not_called()
    mock_error.assert_called_once()


@freeze_time("2025-01-01 00:00:00 UTC")
def test_fetch_and_send_assets_streamed_last_page_divides_evenly_sends_closing_signal(mocker: MockerFixture, client: Client):
    """
    Given:
        - A last page of 4 hosts with 1 detection each, committed every 2 hosts (no remainder after the commits).

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - Both commits are sent unsealed, then a closing signal ([{}] with total + 1) seals the snapshot.
    """
    last_run = {"stage": "assets", "total_assets": 10, "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}
    hosts = [_make_host(str(100 + i), 1) for i in range(4)]

    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.iter_host_list_detections", return_value=iter(hosts))
    mocker.patch("Qualysv2.get_next_page_from_url", return_value="")  # last page
    mock_send = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")
    mocker.patch("Qualysv2.demisto.setAssetsLastRun")
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 2)

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    assert set_new_limit is False
    assert [call.kwargs["items_count"] for call in mock_send.call_args_list] == ["1", "1", str(14 + 1)]
    assert mock_send.call_args_list[-1].args[0] == [{}]
    assert new_last_run["stage"] == "vulnerabilities"
    assert new_last_run["total_assets"] == 14


@freeze_time("2025-01-01 00:00:00 UTC")
def test_fetch_and_send_assets_streamed_sealing_send_failure_keeps_last_commit(mocker: MockerFixture, client: Client):
    """
    Given:
        - A last page of 3 hosts committed every 2 hosts, where the final (sealing) send fails.

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - The error does not propagate; the last commit is returned (stage "assets", next host ID), so the next fetch
          resumes with the uncommitted host and seals the snapshot then.
    """
    last_run = {"stage": "assets", "total_assets": 10, "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}
    hosts = [_make_host(str(100 + i), 1) for i in range(3)]

    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.iter_host_list_detections", return_value=iter(hosts))
    mocker.patch("Qualysv2.get_next_page_from_url", return_value="")  # last page
    mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam", side_effect=[None, DemistoException("XSIAM unavailable")])
    mock_health = mocker.patch("Qualysv2.demisto.updateModuleHealth")
    mocker.patch("Qualysv2.demisto.setAssetsLastRun")
    mocker.patch("Qualysv2.demisto.error")
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 2)

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    assert set_new_limit is False
    assert new_last_run["stage"] == "assets"
    assert new_last_run["next_page"] == "102"
    assert new_last_run["total_assets"] == 12
    mock_health.assert_not_called()


def test_fetch_and_send_assets_streamed_api_error_without_commit_reduces_limit(mocker: MockerFixture, client: Client):
    """
    Given:
        - A response whose Qualys error envelope is only detected at the end of the stream (before any commit).

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - Nothing is sent, the error does not propagate, and set_new_limit=True with the failures counter incremented.
    """
    last_run = {"stage": "assets", "total_assets": 10, "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}

    def stream_with_api_error(*_args, **_kwargs):
        yield _make_host("100", 1)
        raise DemistoException("Qualys API error. Code: 999")

    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.iter_host_list_detections", side_effect=stream_with_api_error)
    mock_send = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")
    mock_error = mocker.patch("Qualysv2.demisto.error")
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 2)

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    assert set_new_limit is True
    assert new_last_run["consecutive_failures"] == 1
    mock_send.assert_not_called()
    assert "Code: 999" in mock_error.call_args.args[0]


def test_fetch_and_send_assets_streamed_raises_after_max_consecutive_failures(mocker: MockerFixture, client: Client):
    """
    Given:
        - A last run that already failed ASSETS_MAX_CONSECUTIVE_FAILURES - 1 times in a row without progress.

    When:
        - Calling fetch_and_send_assets_streamed and the send fails again before any commit.

    Assert:
        - The error is raised (so the fetch shows as failed) and the response is still closed.
    """
    last_run = {
        "stage": "assets",
        "total_assets": 10,
        "since_datetime": "2024-10-03",
        "snapshot_id": SNAPSHOT_ID,
        "consecutive_failures": Qualysv2.ASSETS_MAX_CONSECUTIVE_FAILURES - 1,
    }
    raw_response = Mock()
    mocker.patch.object(client, "get_host_list_detection", return_value=(raw_response, False))
    mocker.patch("Qualysv2.iter_host_list_detections", return_value=iter([_make_host("100", 1), _make_host("101", 1)]))
    mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam", side_effect=DemistoException("XSIAM unavailable"))
    mocker.patch("Qualysv2.demisto.error")
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 2)

    with pytest.raises(DemistoException, match="failed 5 times in a row"):
        fetch_and_send_assets_streamed(client, last_run)

    raw_response.close.assert_called_once()


@freeze_time("2025-01-01 00:00:00 UTC")
def test_fetch_and_send_assets_streamed_commit_resets_consecutive_failures(mocker: MockerFixture, client: Client):
    """
    Given:
        - A last run with previous consecutive failures, and a page that commits before failing.

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - The returned commit has no failures counter (progress resets it), and no limit reduction is requested.
    """
    last_run = {
        "stage": "assets",
        "total_assets": 10,
        "since_datetime": "2024-10-03",
        "snapshot_id": SNAPSHOT_ID,
        "consecutive_failures": 3,
    }

    def broken_stream(*_args, **_kwargs):
        yield from [_make_host("100", 1), _make_host("101", 1), _make_host("102", 1)]
        raise requests.exceptions.ChunkedEncodingError("Connection broken")

    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.iter_host_list_detections", side_effect=broken_stream)
    mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")
    mocker.patch("Qualysv2.demisto.setAssetsLastRun")
    mocker.patch("Qualysv2.demisto.error")
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 2)

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    assert set_new_limit is False
    assert "consecutive_failures" not in new_last_run
    assert new_last_run["next_page"] == "102"


def test_fetch_assets_and_vulnerabilities_by_date_halves_limit_and_keeps_failures_counter(mocker: MockerFixture, client: Client):
    """
    Given:
        - The "assets" stage where the streamed fetch failed before any commit and incremented the failures counter.

    When:
        - Calling fetch_assets_and_vulnerabilities_by_date (the orchestrator).

    Assert:
        - The saved last run has the halved limit and keeps the incremented failures counter.
    """
    last_run = {"stage": "assets", "total_assets": 10, "snapshot_id": SNAPSHOT_ID, "limit": HOST_LIMIT}
    failed_run = {**last_run, "consecutive_failures": 2}

    mocker.patch("Qualysv2.fetch_and_send_assets_streamed", return_value=(failed_run, True))
    mock_set_assets_last_run = mocker.patch("Qualysv2.demisto.setAssetsLastRun")

    fetch_assets_and_vulnerabilities_by_date(client, last_run)

    saved_last_run = mock_set_assets_last_run.call_args.args[0]
    assert saved_last_run["limit"] == HOST_LIMIT // 2
    assert saved_last_run["consecutive_failures"] == 2


def test_fetch_assets_and_vulnerabilities_by_date_saves_last_commit_after_mid_page_error(mocker: MockerFixture, client: Client):
    """
    Given:
        - The "assets" stage where the streamed fetch failed mid-page after a commit (set_new_limit=False).

    When:
        - Calling fetch_assets_and_vulnerabilities_by_date (the orchestrator).

    Assert:
        - The committed last run is saved as-is (no limit reduction), so the next fetch resumes from it.
    """
    last_run = {"stage": "assets", "total_assets": 10, "snapshot_id": SNAPSHOT_ID, "limit": HOST_LIMIT}
    committed_run = {**last_run, "next_page": "102", "total_assets": 12}

    mocker.patch("Qualysv2.fetch_and_send_assets_streamed", return_value=(committed_run, False))
    mock_set_assets_last_run = mocker.patch("Qualysv2.demisto.setAssetsLastRun")

    fetch_assets_and_vulnerabilities_by_date(client, last_run)

    mock_set_assets_last_run.assert_called_once_with(committed_run)


@freeze_time("2025-01-01 00:00:00 UTC")
def test_fetch_and_send_assets_streamed_not_last_page_keeps_unsealed(mocker: MockerFixture, client: Client):
    """
    Given:
        - A non-final page (next page exists) of assets streamed in a single remainder batch.

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - The batch is sent with items_count=1 (snapshot stays unsealed), module health is NOT updated,
          and the returned last run continues the "assets" stage with the next page.
    """
    last_run = {"stage": "assets", "total_assets": 10, "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}
    hosts = [_make_host(str(100 + i), 1) for i in range(3)]

    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.iter_host_list_detections", return_value=iter(hosts))
    mocker.patch("Qualysv2.get_next_page_from_url", return_value="42")  # has next page
    mock_send = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")
    mock_health = mocker.patch("Qualysv2.demisto.updateModuleHealth")
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 10)  # more than the 3 hosts, so no commit mid-page

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    assert set_new_limit is False
    assert mock_send.call_count == 1
    assert mock_send.call_args.kwargs["items_count"] == "1"  # unsealed, more pages coming
    mock_health.assert_not_called()
    assert new_last_run["stage"] == "assets"
    assert new_last_run["next_page"] == "42"
    assert new_last_run["total_assets"] == 13
    assert new_last_run["since_datetime"] == "2024-10-03"
    assert new_last_run["snapshot_id"] == SNAPSHOT_ID


@freeze_time("2025-01-01 00:00:00 UTC")
def test_fetch_and_send_assets_streamed_empty_last_page(mocker: MockerFixture, client: Client):
    """
    Given:
        - A final page that yields zero assets, with a nonzero cumulative total from previous pages.

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - A single sealing send closes the snapshot via close_snapshot_if_empty ([{}] with total+1).
    """
    last_total = 500
    last_run = {"stage": "assets", "total_assets": last_total, "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}

    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.iter_host_list_detections", return_value=iter([]))
    mocker.patch("Qualysv2.get_next_page_from_url", return_value="")  # last page
    mock_send = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    assert set_new_limit is False
    assert mock_send.call_count == 1
    assert mock_send.call_args.args[0] == [{}]  # empty list replaced to trigger snapshot close
    assert mock_send.call_args.kwargs["items_count"] == str(last_total + 1)  # +1 for the empty JSON row
    assert new_last_run["stage"] == "vulnerabilities"


@freeze_time("2025-01-01 00:00:00 UTC")
def test_fetch_and_send_assets_streamed_last_page_exact_multiple_sends_closing_signal(mocker: MockerFixture, client: Client):
    """
    Given:
        - A last page of 4 hosts with 1 detection each, committed every 2 hosts, so the remainder is empty.

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - Both batches are committed unsealed (items_count=1), the cursor moves after the last host.
        - The empty remainder still sends the closing signal ([{}] with the cumulative total + 1).
        - The stage moves to "vulnerabilities".
    """
    last_total = 10
    last_run = {"stage": "assets", "total_assets": last_total, "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}
    hosts = [_make_host(str(100 + i), 1) for i in range(4)]

    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.iter_host_list_detections", return_value=iter(hosts))
    mocker.patch("Qualysv2.get_next_page_from_url", return_value="")  # last page
    mock_send = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")
    mock_set_last_run = mocker.patch("Qualysv2.demisto.setAssetsLastRun")
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 2)

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    assert set_new_limit is False
    items_counts = [call.kwargs["items_count"] for call in mock_send.call_args_list]
    assert items_counts == ["1", "1", str(last_total + 4 + 1)]  # 2 commits, then the closing signal
    assert mock_send.call_args.args[0] == [{}]
    assert mock_set_last_run.call_args.args[0]["next_page"] == "104"  # last commit: after host 103
    assert new_last_run["stage"] == "vulnerabilities"
    assert new_last_run["total_assets"] == last_total + 4


def test_fetch_and_send_assets_streamed_set_new_limit(mocker: MockerFixture, client: Client):
    """
    Given:
        - A host-list-detection request that read-times out (set_new_limit=True).

    When:
        - Calling fetch_and_send_assets_streamed.

    Assert:
        - Nothing is sent to XSIAM and the function only signals the reduction (set_new_limit=True),
          returning the last run unchanged. The actual limit reduction is the caller's responsibility
          (fetch_assets_and_vulnerabilities_by_date), so it is computed in a single place.
    """
    last_run = {"stage": "assets", "total_assets": 10, "snapshot_id": SNAPSHOT_ID, "limit": HOST_LIMIT}

    mocker.patch.object(client, "get_host_list_detection", return_value=(None, True))
    mock_send = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")

    new_last_run, set_new_limit = fetch_and_send_assets_streamed(client, last_run)

    assert set_new_limit is True
    mock_send.assert_not_called()
    # The function signals the reduction but does not apply it; the limit is still unchanged here.
    assert new_last_run is last_run
    assert new_last_run["limit"] == HOST_LIMIT


def test_fetch_assets_and_vulnerabilities_by_date_assets_stage_set_new_limit(mocker: MockerFixture, client: Client):
    """
    Given:
        - The "assets" stage where the streamed assets fetch signals set_new_limit=True (e.g. read timeout).

    When:
        - Calling fetch_assets_and_vulnerabilities_by_date (the orchestrator).

    Assert:
        - The orchestrator is the single place that applies the limit reduction: it calls
          set_assets_last_run_with_new_limit exactly once and saves a last run with the halved limit.
          (fetch_and_send_assets_streamed only signals; it does not apply the reduction.)
    """
    last_run = {"stage": "assets", "total_assets": 10, "snapshot_id": SNAPSHOT_ID, "limit": HOST_LIMIT}

    # Streamed fetch signals a reduction and returns the last run unchanged.
    mocker.patch("Qualysv2.fetch_and_send_assets_streamed", return_value=(last_run, True))
    spy_set_new_limit = mocker.patch(
        "Qualysv2.set_assets_last_run_with_new_limit", wraps=Qualysv2.set_assets_last_run_with_new_limit
    )
    mock_set_assets_last_run = mocker.patch("Qualysv2.demisto.setAssetsLastRun")

    fetch_assets_and_vulnerabilities_by_date(client, last_run)

    # Reduction applied exactly once, by the orchestrator.
    assert spy_set_new_limit.call_count == 1
    saved_last_run = mock_set_assets_last_run.call_args[0][0]
    assert saved_last_run["limit"] == HOST_LIMIT // 2
    assert saved_last_run["nextTrigger"] == "0"


def test_fetch_assets_and_vulnerabilities_by_date_vulnerabilities_stage(mocker: MockerFixture, client: Client):
    """
    Given:
        - Qualys client and last run dictionary with fetch stage, total vulnerabilities count, and snapshot ID.

    When:
        - Calling fetch_assets_and_vulnerabilities_by_date with the "vulnerabilities" stage (streamed, batched send).

    Assert:
        - The vulnerabilities are streamed to XSIAM in bounded batches, all under ONE snapshot id, with only the
          final batch sealing the snapshot (cumulative total); the next assets run is reset to default (pulling done).
    """
    last_total_vulnerabilities = 153
    last_run = {"stage": "vulnerabilities", "total_vulnerabilities": last_total_vulnerabilities, "snapshot_id": SNAPSHOT_ID}

    # Build 5 records (from the 2 sample records) so batch size 2 produces multiple flushes (2 + 2 + 1).
    base_vulnerabilities = util_load_json("./test_data/fetched_vulnerabilities.json")
    expected_vulnerabilities = [dict(base_vulnerabilities[i % len(base_vulnerabilities)], _idx=i) for i in range(5)]

    # Streamed send: client returns a (mocked) streamed response, parsed one record at a time.
    mocker.patch.object(client, "get_vulnerabilities", return_value=Mock())
    mocker.patch("Qualysv2.iter_vulnerabilities_result", return_value=iter(expected_vulnerabilities))
    # Small batch size to exercise multi-batch flushing within a single fetch.
    mocker.patch("Qualysv2.VULNERABILITIES_SEND_BATCH_SIZE", 2)

    mock_send_assets_to_xsiam = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")
    mock_set_assets_last_run = mocker.patch("Qualysv2.demisto.setAssetsLastRun")

    fetch_assets_and_vulnerabilities_by_date(client, last_run)

    # Reconstruct everything sent across the batched calls.
    sent_vulnerabilities: list = []
    for call in mock_send_assets_to_xsiam.call_args_list:
        sent_vulnerabilities.extend(call.args[0])
        assert call.kwargs["vendor"] == VENDOR
        assert call.kwargs["product"] == "vulnerabilities"

    next_run = mock_set_assets_last_run.call_args[0][0]

    assert sent_vulnerabilities == expected_vulnerabilities
    # 5 records with batch size 2 => 3 flushes (2 + 2 + 1).
    assert mock_send_assets_to_xsiam.call_count == 3
    # All batches must share ONE snapshot id, and only the final batch seals the snapshot with the cumulative
    # total; the earlier batches stay unsealed (items_count=1).
    snapshot_ids = {call.kwargs["snapshot_id"] for call in mock_send_assets_to_xsiam.call_args_list}
    assert len(snapshot_ids) == 1
    items_counts = [call.kwargs["items_count"] for call in mock_send_assets_to_xsiam.call_args_list]
    assert items_counts == ["1", "1", str(len(expected_vulnerabilities))]

    assert next_run == DEFAULT_LAST_ASSETS_RUN  # pulling finished, next run stage should be assets


def test_fetch_and_send_vulnerabilities_streamed_exact_multiple_sends_closing_signal(mocker: MockerFixture, client: Client):
    """
    Given:
        - 4 vulnerabilities with a send batch size of 2, so the rows divide evenly and the remainder is empty.

    When:
        - Calling fetch_assets_and_vulnerabilities_by_date with the "vulnerabilities" stage.

    Assert:
        - Two unsealed sends (items_count=1) of 2 rows each, then a closing signal ([{}] with total + 1),
          all under one snapshot id.
    """
    last_run = {"stage": "vulnerabilities", "snapshot_id": SNAPSHOT_ID}
    vulnerabilities = [{"QID": str(i)} for i in range(4)]

    mocker.patch.object(client, "get_vulnerabilities", return_value=Mock())
    mocker.patch("Qualysv2.iter_vulnerabilities_result", return_value=iter(vulnerabilities))
    mocker.patch("Qualysv2.VULNERABILITIES_SEND_BATCH_SIZE", 2)
    mock_send = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")
    mocker.patch("Qualysv2.demisto.setAssetsLastRun")

    fetch_assets_and_vulnerabilities_by_date(client, last_run)

    sent_batches = [call.args[0] for call in mock_send.call_args_list]
    items_counts = [call.kwargs["items_count"] for call in mock_send.call_args_list]
    assert sent_batches == [vulnerabilities[:2], vulnerabilities[2:], [{}]]
    assert items_counts == ["1", "1", str(len(vulnerabilities) + 1)]
    assert len({call.kwargs["snapshot_id"] for call in mock_send.call_args_list}) == 1


def _asset_row(qid: str) -> dict:
    """Builds a minimal asset row (one detection per row), as produced by iter_detections_from_hosts."""
    return {"ID": "1", "DETECTION": {"QID": qid}}


def _vulnerabilities_of(assets: list[dict]) -> list[dict]:
    """Fake fetch_vulnerabilities_of_new_qids result: one vulnerability per asset row."""
    return [{"QID": asset["DETECTION"]["QID"]} for asset in assets]


def test_fetch_vulnerabilities_of_new_qids_fetches_only_new_qids(mocker: MockerFixture, client: Client):
    """
    Given:
        - Asset rows with QIDs A, B, A and a row without a QID, where B was already fetched in this run.

    When:
        - Calling fetch_vulnerabilities_of_new_qids.

    Assert:
        - The knowledge base is queried once, only for A.
        - The returned vulnerabilities are the parsed response, and A is marked as fetched.
    """
    mock_get_vulnerabilities = mocker.patch.object(client, "get_vulnerabilities", return_value=Mock())
    mocker.patch("Qualysv2.handle_vulnerabilities_result", return_value=[{"QID": "A"}])
    assets = [_asset_row("A"), _asset_row("B"), _asset_row("A"), {"ID": "2", "DETECTION": {}}]
    fetched_qids = {"B"}

    vulnerabilities = fetch_vulnerabilities_of_new_qids(client, assets, fetched_qids)

    mock_get_vulnerabilities.assert_called_once_with(detection_qids="A")
    assert vulnerabilities == [{"QID": "A"}]
    assert fetched_qids == {"A", "B"}


def test_fetch_vulnerabilities_of_new_qids_no_new_qids(mocker: MockerFixture, client: Client):
    """
    Given:
        - Asset rows whose QIDs were all already fetched in this run.

    When:
        - Calling fetch_vulnerabilities_of_new_qids.

    Assert:
        - The knowledge base is not queried and an empty list is returned.
    """
    mock_get_vulnerabilities = mocker.patch.object(client, "get_vulnerabilities")

    assert fetch_vulnerabilities_of_new_qids(client, [_asset_row("A")], {"A"}) == []
    mock_get_vulnerabilities.assert_not_called()


def test_fetch_vulnerabilities_of_new_qids_requests_in_chunks(mocker: MockerFixture, client: Client):
    """
    Given:
        - 3 new QIDs and a QIDs chunk size of 2.

    When:
        - Calling fetch_vulnerabilities_of_new_qids.

    Assert:
        - The knowledge base is queried twice and the results of both chunks are combined.
    """
    mocker.patch("Qualysv2.QIDS_BATCH_SIZE", 2)
    mock_get_vulnerabilities = mocker.patch.object(client, "get_vulnerabilities", return_value=Mock())
    mocker.patch("Qualysv2.handle_vulnerabilities_result", side_effect=[[{"QID": "1"}], [{"QID": "2"}]])
    fetched_qids: set = set()

    vulnerabilities = fetch_vulnerabilities_of_new_qids(client, [_asset_row("A"), _asset_row("B"), _asset_row("C")], fetched_qids)

    assert mock_get_vulnerabilities.call_count == 2
    assert vulnerabilities == [{"QID": "1"}, {"QID": "2"}]
    assert fetched_qids == {"A", "B", "C"}


def test_fetch_vulnerabilities_of_new_qids_failure_does_not_mark_qids(mocker: MockerFixture, client: Client):
    """
    Given:
        - A knowledge base request that fails.

    When:
        - Calling fetch_vulnerabilities_of_new_qids.

    Assert:
        - The error is raised and the QIDs are not marked as fetched, so a later batch can fetch them again.
    """
    mocker.patch.object(client, "get_vulnerabilities", side_effect=DemistoException("KB error"))
    fetched_qids: set = set()

    with pytest.raises(DemistoException, match="KB error"):
        fetch_vulnerabilities_of_new_qids(client, [_asset_row("A")], fetched_qids)

    assert fetched_qids == set()


@pytest.mark.parametrize(
    "optional_fields",
    [
        pytest.param({}, id="no-optional-fields"),
        pytest.param({"limit": 50}, id="limit"),
        pytest.param({"total_vulnerabilities": 7}, id="total-vulnerabilities"),
        pytest.param({"limit": 50, "total_vulnerabilities": 0}, id="both-including-zero"),
    ],
)
def test_build_next_last_run(optional_fields: dict):
    """
    Given:
        - The required last run fields and any combination of the optional limit / total_vulnerabilities.

    When:
        - Calling build_next_last_run.

    Assert:
        - The last run triggers the next fetch immediately and contains the optional fields only when given.
    """
    next_last_run = build_next_last_run("assets", "102", 14, "2024-10-03", SNAPSHOT_ID, **optional_fields)

    assert next_last_run == {
        "stage": "assets",
        "next_page": "102",
        "total_assets": 14,
        "since_datetime": "2024-10-03",
        "snapshot_id": SNAPSHOT_ID,
        "nextTrigger": "0",
        "type": 1,
        **optional_fields,
    }


def _mock_qids_page(mocker: MockerFixture, client: Client, hosts: list, next_page: str) -> tuple[Mock, Mock, Mock]:
    """Mocks one host list detection page for the QIDs flow, committing every 2 hosts.

    Returns:
        The mocks of publish_assets_and_vulnerabilities, demisto.setAssetsLastRun, and demisto.updateModuleHealth.
    """
    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.iter_host_list_detections", return_value=iter(hosts))
    mocker.patch("Qualysv2.get_next_page_from_url", return_value=next_page)
    mocker.patch(
        "Qualysv2.fetch_vulnerabilities_of_new_qids", side_effect=lambda _client, assets, _qids: _vulnerabilities_of(assets)
    )
    mocker.patch("Qualysv2.ASSETS_COMMIT_HOSTS_BATCH_SIZE", 2)
    return (
        mocker.patch("Qualysv2.publish_assets_and_vulnerabilities"),
        mocker.patch("Qualysv2.demisto.setAssetsLastRun"),
        mocker.patch("Qualysv2.demisto.updateModuleHealth"),
    )


def test_fetch_and_send_assets_and_vulnerabilities_by_qids_last_page(mocker: MockerFixture, client: Client):
    """
    Given:
        - A last page (no next page) of 5 hosts with 1 detection each, committed every 2 hosts.

    When:
        - Calling fetch_and_send_assets_and_vulnerabilities_by_qids.

    Assert:
        - Each full batch is sent unsealed with the running totals, and the remainder seals both snapshots.
        - After each full batch the last run is saved with the next host ID, both totals, and the current limit.
        - Module health reports the assets count only, and the last run is reset for the next cycle.
    """
    last_run = {
        "stage": "assets",
        "total_assets": 10,
        "total_vulnerabilities": 5,
        "since_datetime": "2024-10-03",
        "snapshot_id": SNAPSHOT_ID,
        "limit": 50,
    }
    hosts = [_make_host(str(100 + i), 1) for i in range(5)]
    mock_publish, mock_set_last_run, mock_health = _mock_qids_page(mocker, client, hosts, next_page="")

    new_last_run, set_new_limit = fetch_and_send_assets_and_vulnerabilities_by_qids(client, last_run)

    assert set_new_limit is False
    sends = [(call.args[2], call.args[3], call.kwargs["has_next_page"]) for call in mock_publish.call_args_list]
    assert sends == [(12, 7, True), (14, 9, True), (15, 10, False)]
    assert all(call.kwargs["snapshot_id"] == SNAPSHOT_ID for call in mock_publish.call_args_list)

    committed_runs = [call.args[0] for call in mock_set_last_run.call_args_list]
    assert [run["next_page"] for run in committed_runs] == ["102", "104"]
    assert [run["total_vulnerabilities"] for run in committed_runs] == [7, 9]
    assert all(run["limit"] == 50 and run["snapshot_id"] == SNAPSHOT_ID for run in committed_runs)

    mock_health.assert_called_once_with({"assetsPulled": 15})
    assert new_last_run == DEFAULT_LAST_ASSETS_RUN


def test_fetch_and_send_assets_and_vulnerabilities_by_qids_not_last_page(mocker: MockerFixture, client: Client):
    """
    Given:
        - A page of 3 hosts with a next page, committed every 2 hosts.

    When:
        - Calling fetch_and_send_assets_and_vulnerabilities_by_qids.

    Assert:
        - All sends keep the snapshots unsealed and module health is not updated.
        - The returned last run points to the next page and keeps the snapshot ID and both totals.
    """
    last_run = {"stage": "assets", "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}
    hosts = [_make_host(str(100 + i), 1) for i in range(3)]
    mock_publish, _, mock_health = _mock_qids_page(mocker, client, hosts, next_page="500")

    new_last_run, set_new_limit = fetch_and_send_assets_and_vulnerabilities_by_qids(client, last_run)

    assert set_new_limit is False
    assert all(call.kwargs["has_next_page"] is True for call in mock_publish.call_args_list)
    mock_health.assert_not_called()
    assert new_last_run == build_next_last_run("assets", "500", 3, "2024-10-03", SNAPSHOT_ID, total_vulnerabilities=3)


def test_fetch_and_send_assets_and_vulnerabilities_by_qids_request_needs_new_limit(mocker: MockerFixture, client: Client):
    """
    Given:
        - A host list detection request that timed out, with a limit above 1.

    When:
        - Calling fetch_and_send_assets_and_vulnerabilities_by_qids.

    Assert:
        - The original last run is returned with set_new_limit=True and nothing is sent.
    """
    last_run = {"stage": "assets", "snapshot_id": SNAPSHOT_ID}
    mocker.patch.object(client, "get_host_list_detection", return_value=(None, True))
    mock_publish = mocker.patch("Qualysv2.publish_assets_and_vulnerabilities")

    assert fetch_and_send_assets_and_vulnerabilities_by_qids(client, last_run) == (last_run, True)
    mock_publish.assert_not_called()


def test_fetch_and_send_assets_and_vulnerabilities_by_qids_error_after_commit(mocker: MockerFixture, client: Client):
    """
    Given:
        - A page whose stream breaks after the first batch of 2 hosts was committed.

    When:
        - Calling fetch_and_send_assets_and_vulnerabilities_by_qids.

    Assert:
        - The last commit is returned without reducing the limit, so the next run resumes after host 101.
    """
    last_run = {"stage": "assets", "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}

    def broken_stream(*_args):
        yield _make_host("100", 1)
        yield _make_host("101", 1)
        raise requests.exceptions.ChunkedEncodingError("Connection broken")

    _mock_qids_page(mocker, client, [], next_page="500")
    mocker.patch("Qualysv2.iter_host_list_detections", side_effect=broken_stream)

    new_last_run, set_new_limit = fetch_and_send_assets_and_vulnerabilities_by_qids(client, last_run)

    assert set_new_limit is False
    assert new_last_run["next_page"] == "102"
    assert new_last_run["total_assets"] == 2
    assert new_last_run["total_vulnerabilities"] == 2


def test_fetch_and_send_assets_and_vulnerabilities_by_qids_error_before_commit(mocker: MockerFixture, client: Client):
    """
    Given:
        - A knowledge base request that fails on the first batch, before anything was committed.

    When:
        - Calling fetch_and_send_assets_and_vulnerabilities_by_qids.

    Assert:
        - Nothing is sent, the failure is counted, and set_new_limit=True is returned.
    """
    last_run = {"stage": "assets", "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}
    mock_publish, _, _ = _mock_qids_page(mocker, client, [_make_host("100", 1)], next_page="")
    mocker.patch("Qualysv2.fetch_vulnerabilities_of_new_qids", side_effect=DemistoException("KB error"))

    new_last_run, set_new_limit = fetch_and_send_assets_and_vulnerabilities_by_qids(client, last_run)

    assert set_new_limit is True
    assert new_last_run == {**last_run, "consecutive_failures": 1}
    mock_publish.assert_not_called()


PAGE_FUNCTIONS = [
    pytest.param(fetch_and_send_assets_streamed, id="by_date"),
    pytest.param(fetch_and_send_assets_and_vulnerabilities_by_qids, id="by_qids"),
]


@pytest.mark.parametrize("page_function", PAGE_FUNCTIONS)
def test_page_host_list_concurrency_limit_counts_and_keeps_limit(mocker: MockerFixture, client: Client, page_function):
    """
    Given:
        - A host list request that still hits the concurrency limit (409/1960) after the in-run retries.

    When:
        - Calling either page function.

    Assert:
        - The failure is counted, the limit is kept (set_new_limit=False), the next run is scheduled immediately,
          and nothing is sent.
    """
    last_run = {"stage": "assets", "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID, "limit": 250}
    mocker.patch.object(client, "get_host_list_detection", side_effect=_make_concurrency_limit_exception())
    mock_send = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")
    mocker.patch("Qualysv2.demisto.error")

    new_last_run, set_new_limit = page_function(client, last_run)

    assert set_new_limit is False
    assert new_last_run["consecutive_failures"] == 1
    assert new_last_run["limit"] == 250
    assert new_last_run["nextTrigger"] == "0"
    assert new_last_run["type"] == Qualysv2.FETCH_COMMAND["assets"]
    mock_send.assert_not_called()


@pytest.mark.parametrize("page_function", PAGE_FUNCTIONS)
def test_page_host_list_concurrency_limit_raises_on_max_failures(mocker: MockerFixture, client: Client, page_function):
    """
    Given:
        - A last run that already failed ASSETS_MAX_CONSECUTIVE_FAILURES - 1 times, and a host list 409/1960 again.

    When:
        - Calling either page function.

    Assert:
        - The fetch raises so the failure is visible.
    """
    last_run = {
        "stage": "assets",
        "since_datetime": "2024-10-03",
        "snapshot_id": SNAPSHOT_ID,
        "consecutive_failures": Qualysv2.ASSETS_MAX_CONSECUTIVE_FAILURES - 1,
    }
    mocker.patch.object(client, "get_host_list_detection", side_effect=_make_concurrency_limit_exception())
    mocker.patch("Qualysv2.demisto.error")

    with pytest.raises(DemistoException, match="failed 5 times in a row"):
        page_function(client, last_run)


@pytest.mark.parametrize("page_function", PAGE_FUNCTIONS)
def test_page_host_list_other_error_is_raised(mocker: MockerFixture, client: Client, page_function):
    """
    Given:
        - A host list request that fails with an error other than a timeout or the concurrency limit.

    When:
        - Calling either page function.

    Assert:
        - The error propagates unchanged (same as before).
    """
    last_run = {"stage": "assets", "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID}
    mocker.patch.object(client, "get_host_list_detection", side_effect=DemistoException("Unauthorized"))

    with pytest.raises(DemistoException, match="Unauthorized"):
        page_function(client, last_run)


@pytest.mark.parametrize("page_function", PAGE_FUNCTIONS)
@pytest.mark.parametrize(
    "consecutive_failures, expected_failures",
    [pytest.param(None, 1, id="first_failure"), pytest.param(2, 3, id="counter_incremented")],
)
def test_page_timeout_at_limit_1_counts_failure(
    mocker: MockerFixture, client: Client, page_function, consecutive_failures, expected_failures
):
    """
    Given:
        - A host list request that times out while the limit is already 1.

    When:
        - Calling either page function.

    Assert:
        - The timeout counts toward consecutive_failures, the limit stays 1, and the next run is scheduled immediately.
    """
    last_run = {"stage": "assets", "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID, "limit": 1}
    if consecutive_failures is not None:
        last_run["consecutive_failures"] = consecutive_failures
    mocker.patch.object(client, "get_host_list_detection", return_value=(None, True))

    new_last_run, set_new_limit = page_function(client, last_run)

    assert set_new_limit is False
    assert new_last_run["consecutive_failures"] == expected_failures
    assert new_last_run["limit"] == 1
    assert new_last_run["nextTrigger"] == "0"


@pytest.mark.parametrize("page_function", PAGE_FUNCTIONS)
def test_page_timeout_at_limit_1_raises_on_max_failures(mocker: MockerFixture, client: Client, page_function):
    """
    Given:
        - A last run with limit 1 that already failed ASSETS_MAX_CONSECUTIVE_FAILURES - 1 times, and another timeout.

    When:
        - Calling either page function.

    Assert:
        - The fetch raises, so a timeout at limit 1 cannot loop forever.
    """
    last_run = {
        "stage": "assets",
        "since_datetime": "2024-10-03",
        "snapshot_id": SNAPSHOT_ID,
        "limit": 1,
        "consecutive_failures": Qualysv2.ASSETS_MAX_CONSECUTIVE_FAILURES - 1,
    }
    mocker.patch.object(client, "get_host_list_detection", return_value=(None, True))

    with pytest.raises(DemistoException, match="failed 5 times in a row"):
        page_function(client, last_run)


@pytest.mark.parametrize("page_function", PAGE_FUNCTIONS)
def test_page_timeout_above_limit_1_does_not_count(mocker: MockerFixture, client: Client, page_function):
    """
    Given:
        - A host list request that times out while the limit is above 1, after previous failures.

    When:
        - Calling either page function.

    Assert:
        - The last run is returned unchanged with set_new_limit=True (the caller halves the limit; nothing is counted).
    """
    last_run = {"stage": "assets", "snapshot_id": SNAPSHOT_ID, "limit": 2, "consecutive_failures": 4}
    mocker.patch.object(client, "get_host_list_detection", return_value=(None, True))

    assert page_function(client, last_run) == (last_run, True)


def test_by_qids_knowledge_base_concurrency_limit_before_commit_keeps_limit(mocker: MockerFixture, client: Client):
    """
    Given:
        - A knowledge base request that hits the concurrency limit (409/1960) on the first batch, before any commit.

    When:
        - Calling fetch_and_send_assets_and_vulnerabilities_by_qids.

    Assert:
        - Same behavior as a host list 409/1960: counted, limit kept, next run scheduled immediately, nothing sent.
    """
    last_run = {"stage": "assets", "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID, "limit": 250}
    mock_publish, _, _ = _mock_qids_page(mocker, client, [_make_host("100", 1)], next_page="")
    mocker.patch("Qualysv2.fetch_vulnerabilities_of_new_qids", side_effect=_make_concurrency_limit_exception())
    mocker.patch("Qualysv2.demisto.error")

    new_last_run, set_new_limit = fetch_and_send_assets_and_vulnerabilities_by_qids(client, last_run)

    assert set_new_limit is False
    assert new_last_run["consecutive_failures"] == 1
    assert new_last_run["limit"] == 250
    assert new_last_run["nextTrigger"] == "0"
    mock_publish.assert_not_called()


def test_by_qids_knowledge_base_concurrency_limit_after_commit_keeps_commit(mocker: MockerFixture, client: Client):
    """
    Given:
        - A page whose first batch of 2 hosts was committed, and the knowledge base request of the second batch
          hits the concurrency limit (409/1960).

    When:
        - Calling fetch_and_send_assets_and_vulnerabilities_by_qids.

    Assert:
        - The last commit is returned, without counting a failure or reducing the limit.
    """
    last_run = {"stage": "assets", "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID, "consecutive_failures": 3}
    hosts = [_make_host(str(100 + i), 1) for i in range(4)]
    _mock_qids_page(mocker, client, hosts, next_page="500")
    mocker.patch(
        "Qualysv2.fetch_vulnerabilities_of_new_qids",
        side_effect=[[{"QID": "1"}], _make_concurrency_limit_exception()],
    )
    mocker.patch("Qualysv2.demisto.error")

    new_last_run, set_new_limit = fetch_and_send_assets_and_vulnerabilities_by_qids(client, last_run)

    assert set_new_limit is False
    assert new_last_run["next_page"] == "102"
    assert "consecutive_failures" not in new_last_run


def test_fetch_assets_and_vulnerabilities_by_qids_concurrency_limit_saves_same_limit(mocker: MockerFixture, client: Client):
    """
    Given:
        - A host list request that still hits the concurrency limit (409/1960) after the in-run retries.

    When:
        - Calling fetch_assets_and_vulnerabilities_by_qids (the orchestrator).

    Assert:
        - The saved last run keeps the limit, counts the failure, and triggers the next run immediately.
    """
    last_run = {"stage": "assets", "since_datetime": "2024-10-03", "snapshot_id": SNAPSHOT_ID, "limit": 250}
    mocker.patch.object(client, "get_host_list_detection", side_effect=_make_concurrency_limit_exception())
    mocker.patch("Qualysv2.demisto.error")
    mock_set_assets_last_run = mocker.patch("Qualysv2.demisto.setAssetsLastRun")

    fetch_assets_and_vulnerabilities_by_qids(client, last_run)

    saved_last_run = mock_set_assets_last_run.call_args.args[0]
    assert saved_last_run["limit"] == 250
    assert saved_last_run["consecutive_failures"] == 1
    assert saved_last_run["nextTrigger"] == "0"


@pytest.mark.parametrize(
    "set_new_limit, expected_limit_calls",
    [
        pytest.param(False, 0, id="page-done"),
        pytest.param(True, 1, id="needs-new-limit"),
    ],
)
def test_fetch_assets_and_vulnerabilities_by_qids(
    mocker: MockerFixture, client: Client, set_new_limit: bool, expected_limit_calls: int
):
    """
    Given:
        - The result of fetching one assets page by QIDs.

    When:
        - Calling fetch_assets_and_vulnerabilities_by_qids.

    Assert:
        - The returned last run is saved, with the limit reduced only when set_new_limit is True.
    """
    page_last_run = {"stage": "assets", "limit": 100}
    mocker.patch("Qualysv2.fetch_and_send_assets_and_vulnerabilities_by_qids", return_value=(page_last_run, set_new_limit))
    mock_new_limit = mocker.patch("Qualysv2.set_assets_last_run_with_new_limit", return_value={"limit": 50})
    mock_set_last_run = mocker.patch("Qualysv2.demisto.setAssetsLastRun")

    fetch_assets_and_vulnerabilities_by_qids(client, {})

    assert mock_new_limit.call_count == expected_limit_calls
    expected_saved_run = {"limit": 50} if set_new_limit else page_last_run
    mock_set_last_run.assert_called_once_with(expected_saved_run)


@pytest.mark.parametrize(
    "has_assets_next_page, expected_assets_count_to_report, expected_vulns_count_to_report",
    [
        pytest.param(True, "1", "1", id="Has next page"),
        pytest.param(False, "10", "13", id="Specified detection QIDs"),
    ],
)
def test_publish_assets_and_vulnerabilities(
    mocker: MockerFixture,
    has_assets_next_page: bool,
    expected_assets_count_to_report: str,
    expected_vulns_count_to_report: str,
):
    """
    Given:
        - Lists of assets and vulnerabilities, along with their respective cumulative counts, and a snapshot ID.

    When:
        - Calling publish_assets_and_vulnerabilities.

    Assert:
        - Ensure correct sending of assets and vulnerabilities data to XSIAM with the correct vendor and product.
        - Ensure reported count is 1 if not done pulling (has next page). Otherwise, count should be the cumulative value.
    """
    expected_assets = util_load_json("./test_data/fetched_assets.json")
    expected_vulnerabilities = util_load_json("./test_data/fetched_vulnerabilities.json")
    cumulative_assets_count = 10
    cumulative_vulns_count = 13

    mock_send_assets_to_xsiam = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")

    publish_assets_and_vulnerabilities(
        assets=expected_assets,
        vulnerabilities=expected_vulnerabilities,
        cumulative_assets_count=cumulative_assets_count,
        cumulative_vulns_count=cumulative_vulns_count,
        has_next_page=has_assets_next_page,
        snapshot_id=SNAPSHOT_ID,
    )

    # First send_assets_to_xsiam call is to send assets, second to send vulnerabilities.
    # The data list is passed positionally (args[0]); the rest are keyword args.
    send_assets_call = mock_send_assets_to_xsiam.mock_calls[0]
    send_vulns_call = mock_send_assets_to_xsiam.mock_calls[1]

    assert send_assets_call.args[0] == expected_assets
    assert send_assets_call.kwargs["vendor"] == VENDOR
    assert send_assets_call.kwargs["product"] == "assets"
    assert send_assets_call.kwargs["snapshot_id"] == SNAPSHOT_ID
    assert send_assets_call.kwargs["items_count"] == expected_assets_count_to_report
    assert not send_assets_call.kwargs["should_update_health_module"]

    assert send_vulns_call.args[0] == expected_vulnerabilities
    assert send_vulns_call.kwargs["vendor"] == VENDOR
    assert send_vulns_call.kwargs["product"] == "vulnerabilities"
    assert send_vulns_call.kwargs["snapshot_id"] == SNAPSHOT_ID
    assert send_vulns_call.kwargs["items_count"] == expected_vulns_count_to_report
    assert not send_vulns_call.kwargs["should_update_health_module"]


def test_publish_assets_and_vulnerabilities_empty_last_page(mocker: MockerFixture):
    """
    Given:
        - Empty assets and vulnerabilities lists on the closing snapshot (has_next_page=False).
        - Cumulative counts of 500 assets and 200 vulnerabilities from previous pages.

    When:
        - Calling publish_assets_and_vulnerabilities with empty data and has_next_page=False.

    Then:
        - Ensure close_snapshot_if_empty replaces empty lists with [{}] and increments items_count by 1.
        - Ensure send_assets_to_xsiam is called with the [{}] closing payload and items_count=str(count + 1) for both.
    """
    cumulative_assets_count = 500
    cumulative_vulns_count = 200

    mock_send_assets_to_xsiam = mocker.patch("Qualysv2.send_assets_and_vulnerabilities_to_xsiam")

    publish_assets_and_vulnerabilities(
        assets=[],
        vulnerabilities=[],
        cumulative_assets_count=cumulative_assets_count,
        cumulative_vulns_count=cumulative_vulns_count,
        has_next_page=False,
        snapshot_id=SNAPSHOT_ID,
    )

    send_assets_call = mock_send_assets_to_xsiam.mock_calls[0]
    send_vulns_call = mock_send_assets_to_xsiam.mock_calls[1]

    # Assets: empty list replaced with [{}], items_count incremented by 1
    assert send_assets_call.args[0] == [{}]
    assert send_assets_call.kwargs["items_count"] == str(cumulative_assets_count + 1)
    assert send_assets_call.kwargs["snapshot_id"] == SNAPSHOT_ID

    # Vulnerabilities: empty list replaced with [{}], items_count incremented by 1
    assert send_vulns_call.args[0] == [{}]
    assert send_vulns_call.kwargs["items_count"] == str(cumulative_vulns_count + 1)
    assert send_vulns_call.kwargs["snapshot_id"] == SNAPSHOT_ID


@pytest.fixture
def mock_client():
    client = Mock()
    return client


def test_get_qid_for_cve_single_qid(mock_client):
    """
    Given:
        - A single CVE

    When:
        - When executing the get_qid_for_cve function

    Then:
        - Ensure the function returns CommandResults
        - Ensure the outputs contain the right value
        - Ensure the outputs_prefix
    """
    xml_response = b"""
    <RESPONSE>
        <VULN_LIST>
            <VULN>
                <QID>12345</QID>
            </VULN>
        </VULN_LIST>
    </RESPONSE>
    """

    mock_response = Mock()
    mock_response.content = xml_response
    mock_client.get_qid_for_cve.return_value = mock_response

    from Qualysv2 import get_qid_for_cve  # Replace 'your_module' with your filename (without .py)

    result = get_qid_for_cve(mock_client, "CVE-2024-0001")

    assert isinstance(result, CommandResults)
    assert result.outputs == ["12345"]
    assert result.outputs_prefix == "Qualys.QID"


def test_get_qid_for_cve_multiple_qids(mock_client):
    """
    Given:
        - A single CVE

    When:
        - When executing the get_qid_for_cve function

    Then:
        - Ensure the outputs contain the right values ( in this case there are 2 qids for the given CVE)
    """
    xml_response = b"""
    <RESPONSE>
        <VULN_LIST>
            <VULN><QID>12345</QID></VULN>
            <VULN><QID>67890</QID></VULN>
        </VULN_LIST>
    </RESPONSE>
    """

    mock_response = Mock()
    mock_response.content = xml_response
    mock_client.get_qid_for_cve.return_value = mock_response

    from Qualysv2 import get_qid_for_cve

    result = get_qid_for_cve(mock_client, "CVE-2024-9999")

    assert result.outputs == ["12345", "67890"]


def _make_rate_limit_exception(wait_seconds: str | None = "40") -> Qualysv2.DemistoException:
    """Build a DemistoException mimicking a Qualys 409 rate-limit response."""
    response = Mock()
    response.status_code = Qualysv2.RATE_LIMIT_STATUS_CODE
    response.headers = {Qualysv2.RATE_LIMIT_TO_WAIT_HEADER: wait_seconds} if wait_seconds is not None else {}
    return Qualysv2.DemistoException("rate limited", res=response)


class TestRateLimitRetry:
    def test_retry_then_success(self, mocker: MockerFixture, client: Client):
        """
        Given: a first 409 rate-limit response followed by a successful response.
        When:  _http_request_with_rate_limit_retry is called.
        Then:  it waits using the header value and returns the successful result.
        """
        sleep_mock = mocker.patch.object(Qualysv2.time, "sleep")
        http_mock = mocker.patch.object(client, "_http_request", side_effect=[_make_rate_limit_exception("40"), "ok"])

        result = client._http_request_with_rate_limit_retry(method="GET", url_suffix="x")

        assert result == "ok"
        assert http_mock.call_count == 2
        sleep_mock.assert_called_once_with(42)  # 40 + RATE_LIMIT_WAIT_BUFFER_SEC

    def test_retry_exhausted_raises(self, mocker: MockerFixture, client: Client):
        """
        Given: 409 rate-limit responses on both the initial call and the single retry.
        When:  _http_request_with_rate_limit_retry is called.
        Then:  the rate-limit DemistoException is raised after one retry.
        """
        mocker.patch.object(Qualysv2.time, "sleep")
        http_mock = mocker.patch.object(
            client, "_http_request", side_effect=[_make_rate_limit_exception("10"), _make_rate_limit_exception("10")]
        )

        with pytest.raises(Qualysv2.DemistoException):
            client._http_request_with_rate_limit_retry(method="GET", url_suffix="x")

        assert http_mock.call_count == 2

    def test_non_rate_limit_error_raised_immediately(self, mocker: MockerFixture, client: Client):
        """
        Given: a non-409 error on the first call.
        When:  _http_request_with_rate_limit_retry is called.
        Then:  the error is raised immediately without retrying or sleeping.
        """
        sleep_mock = mocker.patch.object(Qualysv2.time, "sleep")
        other_response = Mock()
        other_response.status_code = 500
        http_mock = mocker.patch.object(
            client, "_http_request", side_effect=Qualysv2.DemistoException("server error", res=other_response)
        )

        with pytest.raises(Qualysv2.DemistoException):
            client._http_request_with_rate_limit_retry(method="GET", url_suffix="x")

        assert http_mock.call_count == 1
        sleep_mock.assert_not_called()

    @pytest.mark.parametrize(
        "raw_wait, expected",
        [
            ("40", 42),  # header value + buffer
            ("100", Qualysv2.RATE_LIMIT_MAX_WAIT_SEC),  # capped
            (
                "not-a-number",
                Qualysv2.RATE_LIMIT_DEFAULT_WAIT_SEC + Qualysv2.RATE_LIMIT_WAIT_BUFFER_SEC,
            ),  # unparseable -> default
            (None, Qualysv2.RATE_LIMIT_DEFAULT_WAIT_SEC + Qualysv2.RATE_LIMIT_WAIT_BUFFER_SEC),  # missing header -> default
        ],
    )
    def test_get_rate_limit_wait_seconds(self, raw_wait, expected):
        """Validate parsing of X-RateLimit-ToWait-Sec into a bounded wait value."""
        response = Mock()
        response.headers = {Qualysv2.RATE_LIMIT_TO_WAIT_HEADER: raw_wait} if raw_wait is not None else {}
        assert Client._get_rate_limit_wait_seconds(response) == expected


CONCURRENCY_LIMIT_BODY = (
    '<?xml version="1.0" encoding="UTF-8" ?>'
    "<SIMPLE_RETURN><RESPONSE>"
    f"<CODE>{Qualysv2.CONCURRENCY_LIMIT_ERROR_CODE}</CODE>"
    "<TEXT>This API cannot be run again until 1 currently running instance has finished.</TEXT>"
    "<ITEM_LIST><ITEM><KEY>CALLS_TO_FINISH</KEY><VALUE>1</VALUE></ITEM></ITEM_LIST>"
    "</RESPONSE></SIMPLE_RETURN>"
)


def _make_concurrency_limit_exception() -> Qualysv2.DemistoException:
    """Build a DemistoException mimicking a Qualys 409 concurrency-limit (Error Code 1960) response."""
    response = Mock()
    response.status_code = Qualysv2.RATE_LIMIT_STATUS_CODE
    # Header is deliberately misleading (0) for 1960 - the fix must NOT rely on it.
    response.headers = {Qualysv2.RATE_LIMIT_TO_WAIT_HEADER: "0"}
    response.text = CONCURRENCY_LIMIT_BODY
    return Qualysv2.DemistoException("concurrency limited", res=response)


class TestConcurrencyLimitRetry:
    def test_host_list_1960_retries_then_succeeds(self, mocker: MockerFixture, client: Client):
        """
        Given: a first 409/1960 concurrency-limit response followed by a successful response.
        When:  get_host_list_detection is called.
        Then:  it backs off (fixed wait) and returns the successful response, with set_new_limit=False.
        """
        sleep_mock = mocker.patch.object(Qualysv2.time, "sleep")
        http_mock = mocker.patch.object(
            client, "_http_request", side_effect=[_make_concurrency_limit_exception(), "host-list-data"]
        )

        response, set_new_limit = client.get_host_list_detection(since_datetime="2024-12-12", limit=HOST_LIMIT)

        assert response == "host-list-data"
        assert set_new_limit is False
        assert http_mock.call_count == 2
        sleep_mock.assert_called_once_with(Qualysv2.CONCURRENCY_LIMIT_WAIT_SEC)

    def test_host_list_1960_exhausts_retries_raises(self, mocker: MockerFixture, client: Client):
        """
        Given: persistent 409/1960 concurrency-limit responses on every attempt.
        When:  get_host_list_detection is called.
        Then:  after the in-run retries the 1960 error is raised, so the page function counts it
               (same as a 1960 on the knowledge-base request) instead of halving the limit.
        """
        mocker.patch.object(Qualysv2.time, "sleep")
        http_mock = mocker.patch.object(
            client,
            "_http_request",
            side_effect=[_make_concurrency_limit_exception() for _ in range(Qualysv2.CONCURRENCY_LIMIT_MAX_RETRIES + 1)],
        )

        with pytest.raises(DemistoException, match="concurrency limited"):
            client.get_host_list_detection(since_datetime="2024-12-12", limit=HOST_LIMIT)

        assert http_mock.call_count == Qualysv2.CONCURRENCY_LIMIT_MAX_RETRIES + 1

    def test_host_list_non_1960_409_raises(self, mocker: MockerFixture, client: Client):
        """
        Given: a 409 response that is NOT the 1960 concurrency error (e.g. 1965 rate-limit).
        When:  get_host_list_detection is called.
        Then:  the error propagates (we must not swallow genuine rate-limit errors) and no retry occurs.
        """
        mocker.patch.object(Qualysv2.time, "sleep")
        other_response = Mock()
        other_response.status_code = Qualysv2.RATE_LIMIT_STATUS_CODE
        other_response.headers = {}
        other_response.text = (
            '<?xml version="1.0" encoding="UTF-8" ?><SIMPLE_RETURN><RESPONSE>'
            "<CODE>1965</CODE><TEXT>This API cannot be run again for another 40 seconds.</TEXT>"
            "</RESPONSE></SIMPLE_RETURN>"
        )
        http_mock = mocker.patch.object(
            client, "_http_request", side_effect=Qualysv2.DemistoException("rate limited", res=other_response)
        )

        with pytest.raises(Qualysv2.DemistoException):
            client.get_host_list_detection(since_datetime="2024-12-12", limit=HOST_LIMIT)

        assert http_mock.call_count == 1

    def test_is_concurrency_limit_error_detection(self):
        """Validate _is_concurrency_limit_error correctly identifies 1960 vs other responses."""
        # 409 + CODE 1960 -> True
        resp_1960 = Mock()
        resp_1960.status_code = Qualysv2.RATE_LIMIT_STATUS_CODE
        resp_1960.text = CONCURRENCY_LIMIT_BODY
        assert Client._is_concurrency_limit_error(resp_1960) is True

        # 409 + CODE 1965 -> False
        resp_1965 = Mock()
        resp_1965.status_code = Qualysv2.RATE_LIMIT_STATUS_CODE
        resp_1965.text = "<SIMPLE_RETURN><RESPONSE><CODE>1965</CODE><TEXT>x</TEXT></RESPONSE></SIMPLE_RETURN>"
        assert Client._is_concurrency_limit_error(resp_1965) is False

        # non-409 -> False
        resp_500 = Mock()
        resp_500.status_code = 500
        resp_500.text = CONCURRENCY_LIMIT_BODY
        assert Client._is_concurrency_limit_error(resp_500) is False

        # None response -> False
        assert Client._is_concurrency_limit_error(None) is False

        # 409 but response body access/parse fails (e.g. missing/broken text attribute) -> False (fail-safe)
        resp_no_text = Mock()
        resp_no_text.status_code = Qualysv2.RATE_LIMIT_STATUS_CODE
        type(resp_no_text).text = PropertyMock(side_effect=AttributeError("no text attribute"))
        assert Client._is_concurrency_limit_error(resp_no_text) is False


class TestGetHostListDetectionRequest:
    """Tests for Client.get_host_list_detection request building and error handling."""

    def test_sends_qid_and_next_page_params(self, mocker: MockerFixture, client: Client):
        """
        Given:  A QID and a next page (minimum host ID).
        When:   get_host_list_detection is called.
        Then:   The request includes the `qids` and `id_min` params, and set_new_limit is False.
        """
        response = Mock()
        mock_request = mocker.patch.object(client, "_request_with_concurrency_retry", return_value=response)

        result, set_new_limit = client.get_host_list_detection("2024-12-12", next_page="42", limit=10, qid="123")

        params = mock_request.call_args.args[2]
        assert params["qids"] == "123"
        assert params["id_min"] == "42"
        assert params["truncation_limit"] == 10
        assert (result, set_new_limit) == (response, False)

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(requests.exceptions.ReadTimeout("timed out"), id="ReadTimeout"),
            pytest.param(requests.exceptions.ChunkedEncodingError("broken"), id="ChunkedEncodingError"),
        ],
    )
    def test_timeout_returns_set_new_limit(self, mocker: MockerFixture, client: Client, error: Exception):
        """
        Given:  The request times out or the response ends prematurely.
        When:   get_host_list_detection is called.
        Then:   No response is returned and set_new_limit is True.
        """
        mocker.patch.object(client, "_request_with_concurrency_retry", side_effect=error)

        assert client.get_host_list_detection("2024-12-12") == (None, True)

    def test_other_api_error_is_raised(self, mocker: MockerFixture, client: Client):
        """
        Given:  The request fails with an API error that is not the concurrency limit.
        When:   get_host_list_detection is called.
        Then:   The error is raised.
        """
        mocker.patch.object(client, "_request_with_concurrency_retry", side_effect=DemistoException("Unauthorized"))

        with pytest.raises(DemistoException, match="Unauthorized"):
            client.get_host_list_detection("2024-12-12")


def test_get_host_list_detections_events_request_needs_new_limit(mocker: MockerFixture, client: Client):
    """
    Given:
        - A host list detection request that needs a reduced limit.

    When:
        - Calling get_host_list_detections_events.

    Assert:
        - No assets are returned, the next page is unchanged, and set_new_limit is True.
    """
    mocker.patch.object(client, "get_host_list_detection", return_value=(None, True))
    mock_handle = mocker.patch("Qualysv2.handle_host_list_detection_result")

    assert Qualysv2.get_host_list_detections_events(client, "2024-12-12", next_page="7") == ([], "7", True)
    mock_handle.assert_not_called()


def test_get_host_list_detections_events_returns_assets_and_next_page(mocker: MockerFixture, client: Client):
    """
    Given:
        - A host list detection response with 2 hosts (3 detections in total) and a next-page URL.

    When:
        - Calling get_host_list_detections_events.

    Assert:
        - One asset row is returned per detection, and the next page is taken from the URL's `id_min`.
    """
    hosts = [_make_host("1", 2), _make_host("2", 1)]
    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch("Qualysv2.handle_host_list_detection_result", return_value=(hosts, "https://qualys/next?id_min=42"))

    assets, next_page, set_new_limit = Qualysv2.get_host_list_detections_events(client, "2024-12-12")

    assert len(assets) == 3
    assert next_page == "42"
    assert set_new_limit is False


def test_get_host_list_detections_events_test_mode_skips_parsing(mocker: MockerFixture, client: Client):
    """
    Given:
        - A host list detection response with hosts, in test-module mode.

    When:
        - Calling get_host_list_detections_events with is_test=True.

    Assert:
        - The hosts are not parsed into asset rows.
    """
    mocker.patch.object(client, "get_host_list_detection", return_value=(Mock(), False))
    mocker.patch(
        "Qualysv2.handle_host_list_detection_result", return_value=([_make_host("1", 1)], "https://qualys/next?id_min=42")
    )
    mock_parse = mocker.patch("Qualysv2.get_detections_from_hosts")

    assets, next_page, set_new_limit = Qualysv2.get_host_list_detections_events(client, "2024-12-12", is_test=True)

    assert (assets, next_page, set_new_limit) == ([], "42", False)
    mock_parse.assert_not_called()


@pytest.mark.parametrize(
    "params, expect_events, expect_assets, expect_api_call",
    [
        pytest.param({}, False, False, True, id="no-fetch"),
        pytest.param({"isFetchEvents": True}, True, False, False, id="fetch-events"),
        pytest.param({"isFetchAssets": True}, False, True, False, id="fetch-assets"),
        pytest.param({"isFetchEvents": True, "isFetchAssets": True}, True, True, False, id="fetch-both"),
    ],
)
def test_test_module(
    mocker: MockerFixture, client: Client, params: dict, expect_events: bool, expect_assets: bool, expect_api_call: bool
):
    """
    Given:
        - Integration params with fetch events and/or fetch assets enabled, or neither.

    When:
        - Calling test_module.

    Assert:
        - Only the checks of the enabled fetch types run; with no fetch enabled, a basic API request is made.
        - "ok" is returned.
    """
    mock_fetch_events = mocker.patch("Qualysv2.fetch_events")
    mock_assets = mocker.patch("Qualysv2.get_host_list_detections_events")
    mock_api_call = mocker.patch.object(client, "command_http_request")

    assert Qualysv2.test_module(client, params, first_fetch_time="3 days") == "ok"

    assert mock_fetch_events.called is expect_events
    assert mock_assets.called is expect_assets
    assert mock_api_call.called is expect_api_call
    if expect_assets:
        assert mock_assets.call_args.kwargs["limit"] == 1
        assert mock_assets.call_args.kwargs["is_test"] is True


class TestQualysCommandFlowManager:
    """Tests for qualys_command_flow_manager dispatching."""

    COMMAND_NAME = "qualys-report-list"

    @pytest.fixture(autouse=True)
    def mock_request_building(self, mocker: MockerFixture):
        """Skip argument building and validation, which are covered by their own tests."""
        self.mock_build_args = mocker.patch("Qualysv2.build_args_dict")
        self.mock_validation = mocker.patch("Qualysv2.input_validation")

    def test_asset_tag_command(self, mocker: MockerFixture, client: Client):
        """
        Given:  An asset tag command.
        When:   qualys_command_flow_manager is called.
        Then:   The request body is built from the args, the tag API data is used, and the handler result is returned.
        """
        command_name = "qualys-asset-tag-create"
        mock_tag_params = mocker.patch("Qualysv2.handle_asset_tag_request_parameters")
        mocker.patch.object(client, "command_http_request", return_value="raw")
        handler = Mock(return_value="handled")

        result = Qualysv2.qualys_command_flow_manager(client, {"name": "tag"}, command_name, {"result_handler": handler})

        mock_tag_params.assert_called_once_with({"name": "tag"}, command_name)
        client.command_http_request.assert_called_once_with(Qualysv2.TAG_ASSET_COMMANDS_API_DATA[command_name])
        self.mock_validation.assert_not_called()
        handler.assert_called_once_with("raw", command_name)
        assert result == "handled"

    def test_command_without_output_builder(self, mocker: MockerFixture, client: Client):
        """
        Given:  A regular command without an output builder.
        When:   qualys_command_flow_manager is called.
        Then:   The args are built and validated, and the handler result is returned as is.
        """
        mocker.patch.object(client, "command_http_request", return_value="raw")
        handler = Mock(return_value="handled")

        result = Qualysv2.qualys_command_flow_manager(client, {}, self.COMMAND_NAME, {"result_handler": handler})

        assert self.mock_build_args.call_count == 2  # API args and inner args
        self.mock_validation.assert_called_once_with(self.COMMAND_NAME)
        assert result == "handled"

    def test_command_with_empty_result(self, mocker: MockerFixture, client: Client):
        """
        Given:  A command with an output builder whose handler returns an empty result.
        When:   qualys_command_flow_manager is called.
        Then:   "No items found" is returned and the output builder is not called.
        """
        mocker.patch.object(client, "command_http_request", return_value="raw")
        output_builder = Mock()
        methods = {"result_handler": Mock(return_value={}), "output_builder": output_builder}

        result = Qualysv2.qualys_command_flow_manager(client, {}, self.COMMAND_NAME, methods)

        assert isinstance(result, CommandResults)
        assert result.readable_output == "No items found"
        output_builder.assert_not_called()

    @pytest.mark.parametrize(
        "context_data, expected_outputs, expected_raw",
        [
            pytest.param({"context_prefix": "Qualys.Report", "context_key": "ID"}, [{"ID": "1"}], "raw", id="with-context"),
            pytest.param({"context_prefix": "", "context_key": ""}, None, None, id="no-context"),
        ],
    )
    def test_command_with_output_builder(
        self,
        mocker: MockerFixture,
        client: Client,
        context_data: dict,
        expected_outputs: list | None,
        expected_raw: str | None,
    ):
        """
        Given:  A command with an output builder and a non-empty result.
        When:   qualys_command_flow_manager is called.
        Then:   The built outputs are returned under the command's context prefix;
                commands without a context prefix return the readable output only.
        """
        mocker.patch.dict(Qualysv2.COMMANDS_CONTEXT_DATA, {self.COMMAND_NAME: context_data})
        mocker.patch.object(client, "command_http_request", return_value="raw")
        output_builder = Mock(return_value=([{"ID": "1"}], "### Reports"))
        methods = {"result_handler": Mock(return_value={"REPORT": [{"ID": "1"}]}), "output_builder": output_builder}

        result = Qualysv2.qualys_command_flow_manager(client, {}, self.COMMAND_NAME, methods)

        assert isinstance(result, CommandResults)
        assert result.outputs == expected_outputs
        assert result.raw_response == expected_raw
        assert result.readable_output == "### Reports"
        assert output_builder.call_args.kwargs["handled_result"] == {"REPORT": [{"ID": "1"}]}


class TestOutputBuilders:
    """Tests for the command output builders."""

    @pytest.fixture(autouse=True)
    def mock_command_args(self, mocker: MockerFixture):
        """Isolate the module-level command args, which some builders read (e.g. `limit`, `action`)."""
        self.args_values: dict = {}
        self.inner_args_values: dict = {}
        mocker.patch.object(Qualysv2, "args_values", self.args_values)
        mocker.patch.object(Qualysv2, "inner_args_values", self.inner_args_values)

    def test_build_one_value_parsed_output(self):
        """
        Given:  A response with a KEY/VALUE collection, a datetime, and a text.
        When:   build_one_value_parsed_output is called.
        Then:   The KEY/VALUE pair becomes a single field, alongside the datetime and text.
        """
        handled_result = {"ITEM": {"VAL": {"KEY": "scan", "VALUE": "1"}}, "DATETIME": "2025-01-01", "TEXT": "done"}
        parse_data = {"collection_name": "ITEM", "table_name": "Result"}

        output, readable = Qualysv2.build_one_value_parsed_output(
            handled_result=handled_result, command_parse_and_output_data=parse_data
        )

        assert output == {"scan": "1", "DATETIME": "2025-01-01", "TEXT": "done"}
        assert "Result" in readable

    def test_build_single_text_output(self):
        """
        Given:  A response with a text.
        When:   build_single_text_output is called.
        Then:   The response is the output and its text is the readable output.
        """
        handled_result = {"TEXT": "Scan launched"}

        assert Qualysv2.build_single_text_output(handled_result=handled_result) == (handled_result, "Scan launched")

    @pytest.mark.parametrize(
        "inner_args, expected_len, expect_limit_msg",
        [
            pytest.param({}, 3, False, id="no-limit"),
            pytest.param({"limit": "2"}, 2, True, id="limit-below-total"),
            pytest.param({"limit": "5"}, 3, False, id="limit-above-total"),
        ],
    )
    def test_build_unparsed_output(self, inner_args: dict, expected_len: int, expect_limit_msg: bool):
        """
        Given:  A list response of 3 items and an optional limit.
        When:   build_unparsed_output is called.
        Then:   The list is limited, and a "displaying X out of Y" message is shown only when items were cut.
        """
        self.inner_args_values.update(inner_args)

        output, readable = Qualysv2.build_unparsed_output(
            handled_result=[{"a": 1}, {"a": 2}, {"a": 3}], command_parse_and_output_data={"table_name": "Items"}
        )

        assert len(output) == expected_len
        assert ("out of 3 results" in readable) is expect_limit_msg

    def test_build_ip_list_output_with_limit(self):
        """
        Given:  An IP list response with a status, 2 addresses and 1 range, and a limit of 2.
        When:   build_ip_list_output is called.
        Then:   The keys are renamed, the results are limited to 2, and a limit message is shown.
        """
        self.inner_args_values["limit"] = "2"
        handled_result = {"STATUS": "ok", "IP_SET": {"IP": ["1.1.1.1", "1.1.1.2"], "IP_RANGE": "1.1.1.3-1.1.1.4"}}
        parse_data = {"collection_name": "IP_SET", "new_names_dict": {"IP": "Address", "IP_RANGE": "Range"}}

        output, readable = Qualysv2.build_ip_list_output(handled_result=handled_result, command_parse_and_output_data=parse_data)

        assert output == {"Address": ["1.1.1.1", "1.1.1.2"], "Range": []}
        assert "Currently displaying 2 out of 3 results." in readable

    def test_build_ip_list_output_status_only(self):
        """
        Given:  An IP list response with a status but no IP collection.
        When:   build_ip_list_output is called.
        Then:   The readable output shows the current status.
        """
        parse_data = {"collection_name": "IP_SET", "new_names_dict": {}}

        output, readable = Qualysv2.build_ip_list_output(
            handled_result={"STATUS": "Pending"}, command_parse_and_output_data=parse_data
        )

        assert output == {"STATUS": "Pending"}
        assert readable == "### Current Status: Pending\n"

    @pytest.mark.parametrize(
        "parse_data, handled_result",
        [
            pytest.param(
                {"collection_name": "ITEMS", "table_name": "Items"},
                {"ITEMS": {"ITEM": [{"ID": "1"}, {"ID": "2"}, {"ID": "3"}]}},
                id="collection",
            ),
            pytest.param(
                {"table_name": "Items", "table_headers": ["ID"]},
                {"ITEM": [{"ID": "1"}, {"ID": "2"}, {"ID": "3"}]},
                id="no-collection",
            ),
        ],
    )
    def test_build_multiple_values_parsed_output(self, parse_data: dict, handled_result: Any):
        """
        Given:  A list of 3 items (with or without a collection name) and a limit of 2.
        When:   build_multiple_values_parsed_output is called.
        Then:   The output is limited to 2 items and a limit message is shown.
        """
        self.inner_args_values["limit"] = "2"

        output, readable = Qualysv2.build_multiple_values_parsed_output(
            handled_result=handled_result, command_parse_and_output_data=parse_data
        )

        assert output == [{"ID": "1"}, {"ID": "2"}]
        assert "Currently displaying 2 out of 3 results." in readable

    def test_build_host_list_detection_outputs(self):
        """
        Given:  Two hosts, one with a single (non-list) detection and one without detections, and a limit of 1.
        When:   build_host_list_detection_outputs is called.
        Then:   Only the first host is returned, its readable table includes the detection QID, and a limit message is shown.
        """
        self.inner_args_values["limit"] = "1"
        hosts = [
            {
                "ID": "1",
                "IP": "1.1.1.1",
                "DNS_DATA": {"HOSTNAME": "h1", "DOMAIN": None},
                "DETECTION_LIST": {"DETECTION": {"QID": "100", "RESULTS": "found"}},
            },
            {"ID": "2", "IP": "1.1.1.2"},
        ]

        output, readable = Qualysv2.build_host_list_detection_outputs(
            handled_result={"HOST_LIST": {"HOST": hosts}}, command_parse_and_output_data={"collection_name": "HOST_LIST"}
        )

        assert output == [hosts[0]]
        assert "Host Detection List - 1.1.1.1" in readable
        assert "QID: 100" in readable
        assert "Currently displaying 1 out of 2 results." in readable

    def test_build_host_list_detection_outputs_single_host_without_collection(self):
        """
        Given:  A single host dict without a collection name.
        When:   build_host_list_detection_outputs is called.
        Then:   The host is wrapped in a list.
        """
        host = {"ID": "1", "IP": "1.1.1.1"}

        output, readable = Qualysv2.build_host_list_detection_outputs(
            handled_result={"HOST": host}, command_parse_and_output_data={}
        )

        assert output == [host]
        assert "Host Detection List - 1.1.1.1" in readable

    def test_build_changed_names_output(self):
        """
        Given:  A list of dicts and a mapping of new key names.
        When:   build_changed_names_output is called.
        Then:   The keys are renamed in every dict.
        """
        parse_data = {"new_names_dict": {"old": "new"}, "table_name": "Items"}

        output, readable = Qualysv2.build_changed_names_output(
            handled_result=[{"old": 1}, {"old": 2}], command_parse_and_output_data=parse_data
        )

        assert output == [{"new": 1}, {"new": 2}]
        assert "Items" in readable

    def test_build_multiple_text_options_output(self):
        """
        Given:  A command action and the output texts per action.
        When:   build_multiple_text_options_output is called.
        Then:   The text of the requested action is returned, with no outputs.
        """
        self.args_values["action"] = "pause"
        parse_data = {"output_texts": {"pause": "Paused", "resume": "Resumed"}}

        assert Qualysv2.build_multiple_text_options_output(command_parse_and_output_data=parse_data) == (None, "Paused")

    def test_build_text_value_pairs_parsed_output(self):
        """
        Given:  A list of @value / #text pairs.
        When:   build_text_value_pairs_parsed_output is called.
        Then:   A single dict is built from the pairs.
        """
        handled_result = [{"@value": "name", "#text": "scan"}, {"@value": "state", "#text": "done"}]

        output, readable = Qualysv2.build_text_value_pairs_parsed_output(
            handled_result=handled_result, command_parse_and_output_data={"table_name": "Pairs"}
        )

        assert output == {"name": "scan", "state": "done"}
        assert "Pairs" in readable

    @pytest.mark.parametrize(
        "value, expected_in_readable",
        [
            pytest.param("1.1.1.1,1.1.1.2-1.1.1.3", "1.1.1.2-1.1.1.3", id="with-ips"),
            pytest.param("", "No IPs were found", id="no-ips"),
        ],
    )
    def test_build_ip_list_from_single_value(self, value: str, expected_in_readable: str):
        """
        Given:  A response whose value is a comma-separated list of IPs and ranges, or empty.
        When:   build_ip_list_from_single_value is called.
        Then:   The IPs are listed in the readable output, or a "No IPs were found" message is shown.
        """
        handled_result = {"KEY": "Hosts", "VALUE": value}

        output, readable = Qualysv2.build_ip_list_from_single_value(handled_result=handled_result)

        assert output == handled_result
        assert expected_in_readable in readable

    def test_build_tag_asset_output_with_message(self):
        """
        Given:  Command output data with a fixed human readable message.
        When:   build_tag_asset_output is called.
        Then:   The message is returned as the readable output.
        """
        output, readable = Qualysv2.build_tag_asset_output(
            handled_result={"id": "1"}, command_parse_and_output_data={"human_readable_massage": "Tag deleted"}
        )

        assert (output, readable) == ({"id": "1"}, "Tag deleted")


class TestResultHandlers:
    """Tests for the report list and fetch file result handlers."""

    def test_handle_report_list_result_no_report_for_id(self, mocker: MockerFixture):
        """
        Given:  An empty report list result for a requested report ID.
        When:   handle_report_list_result is called.
        Then:   An error saying no report exists for the ID is raised.
        """
        mocker.patch("Qualysv2.handle_general_result", return_value={})
        mocker.patch.object(demisto, "args", return_value={"id": "42"})

        with pytest.raises(DemistoException, match="No report exist for the id 42"):
            Qualysv2.handle_report_list_result(Mock(), "qualys-report-list")

    def test_handle_report_list_result_returns_result(self, mocker: MockerFixture):
        """
        Given:  A non-empty report list result.
        When:   handle_report_list_result is called.
        Then:   The parsed result is returned.
        """
        mocker.patch("Qualysv2.handle_general_result", return_value={"REPORT": [{"ID": "1"}]})

        assert Qualysv2.handle_report_list_result(Mock(), "qualys-report-list") == {"REPORT": [{"ID": "1"}]}

    def test_handle_fetch_result(self, mocker: MockerFixture):
        """
        Given:  A fetch file command with a file ID and file format.
        When:   handle_fetch_result is called.
        Then:   A file entry is created with a name built from the command's prefix, the file ID and the format.
        """
        command_name = "qualys-fetch-file-test"
        mocker.patch.dict(Qualysv2.COMMANDS_PARSE_AND_OUTPUT_DATA, {command_name: {"file_id": "id", "file_prefix": "report"}})
        mocker.patch.object(Qualysv2, "args_values", {"id": "7"})
        mocker.patch.object(Qualysv2, "inner_args_values", {"file_format": "pdf"})
        mocker.patch("Qualysv2.format_and_validate_response")
        mock_file_result = mocker.patch("Qualysv2.fileResult", return_value={"File": "report_7.pdf"})

        assert Qualysv2.handle_fetch_result(b"data", command_name) == {"File": "report_7.pdf"}
        assert mock_file_result.call_args.args[0] == "report_7.pdf"


class TestClientRequests:
    """Tests for the remaining Client request helpers and error handling."""

    @pytest.mark.parametrize("status_code", [414, 520])
    def test_error_handler_long_request_hint(self, status_code: int):
        """
        Given:  A 414 / 520 error response with a Qualys XML body.
        When:   error_handler is called.
        Then:   The raised error includes the hint about shortening the IP list.
        """
        response = Mock(status_code=status_code, reason="Too long")
        response.text = (
            "<SIMPLE_RETURN><RESPONSE><DATETIME>2025-01-01</DATETIME>"
            "<TEXT>too long</TEXT><CODE>999</CODE></RESPONSE></SIMPLE_RETURN>"
        )

        with pytest.raises(DemistoException, match="less than 5000 characters"):
            Client.error_handler(response)

    def test_error_handler_json_body(self):
        """
        Given:  An error response whose body is JSON rather than Qualys XML.
        When:   error_handler is called.
        Then:   The raised error includes the JSON body.
        """
        response = Mock(status_code=400, reason="Bad Request", text="not xml")
        response.json.return_value = {"error": "bad"}

        with pytest.raises(DemistoException, match='"error": "bad"'):
            Client.error_handler(response)

    def test_command_http_request_sets_content_type(self, mocker: MockerFixture, client: Client):
        """
        Given:  Command API data with a Content-Type.
        When:   command_http_request is called.
        Then:   The Content-Type header is set and the request uses the command's method, route and body.
        """
        mock_request = mocker.patch.object(client, "_http_request", return_value="ok")
        api_data = {
            "call_method": "POST",
            "api_route": "route",
            "resp_type": "text",
            "Content-Type": "text/xml",
            "request_body": "<a/>",
        }

        assert client.command_http_request(api_data) == "ok"
        assert client._headers["Content-Type"] == "text/xml"
        assert mock_request.call_args.kwargs["method"] == "POST"
        assert mock_request.call_args.kwargs["data"] == "<a/>"

    def test_get_user_activity_logs_next_page(self, mocker: MockerFixture, client: Client):
        """
        Given:  A next page marker.
        When:   get_user_activity_logs is called.
        Then:   The request uses it as `id_max`.
        """
        mock_request = mocker.patch.object(client, "_http_request_with_rate_limit_retry", return_value=Mock(text="csv"))

        assert client.get_user_activity_logs("2025-01-01", max_fetch=10, next_page="99") == "csv"
        assert mock_request.call_args.kwargs["params"]["id_max"] == "99"

    def test_get_qid_for_cve(self, mocker: MockerFixture, client: Client):
        """
        Given:  A CVE and a cloud agent scan type.
        When:   Client.get_qid_for_cve is called.
        Then:   The knowledge base is queried with both params.
        """
        mock_request = mocker.patch.object(client, "_http_request", return_value="<xml/>")

        assert client.get_qid_for_cve("CVE-2024-1", cloud_agent_scan_type="agent") == "<xml/>"
        assert mock_request.call_args.kwargs["params"] == {"cve": "CVE-2024-1", "cloud_agent_scan_type": "agent"}

    def test_is_concurrency_limit_error_unparsable_body(self, mocker: MockerFixture):
        """
        Given:  A 409 response whose body cannot be parsed.
        When:   _is_concurrency_limit_error is called.
        Then:   False is returned.
        """
        mocker.patch("Qualysv2.parse_raw_response", side_effect=ValueError("bad body"))
        response = Mock(status_code=Qualysv2.RATE_LIMIT_STATUS_CODE, text="bad")

        assert Client._is_concurrency_limit_error(response) is False
