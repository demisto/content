import demistomock as demisto
import pytest
import json
import io
import datetime
import unittest
from unittest.mock import patch
from CommonServerPython import arg_to_datetime
from Flashpoint import Client, MESSAGES, MAX_PRODUCT, FILTER_DATE_VALUES, IS_FRESH_VALUES, MAX_PAGE_SIZE, \
    SORT_DATE_VALUES, SORT_ORDER_VALUES

API_KEY = demisto.getParam('api_key')

HREF_BASE_URL = 'http://123-fake-api.com/api/v4/indicators/attribute/'  # NOSONAR
TEST_SCAN_DOMAIN = 'fakedomain.com'
TEST_SCAN_IP = '0.0.0.0'
TEST_SCAN_FILENAME = 'fakefilename'
TEST_SCAN_URL = 'http://123-fake-api.com'  # NOSONAR
TEST_SCAN_FILE = 'test_scan_dummy_file'
TEST_SCAN_EMAIL = 'fakeemail@test.com'

TEST_SCAN_REPORT_KEYWORD = 'fakexyz'
TEST_SCAN_REPORT_ID = 'test_scan_id'
TEST_SCAN_EVENT_ID = 'test_scan_id'
TEST_SCAN_FORUM_ID = 'test_scan_forum_id'
TEST_SCAN_FORUM_ROOM_ID = 'test_scan_forum_room_id'
TEST_SCAN_FORUM_USER_ID = 'test_scan_forum_user_id'
TEST_SCAN_FORUM_POST_ID = 'test_scan_forum_post_id'
TEST_SITE_SEARCH_KEYWORD = 'test'
TEST_POST_SEARCH_KEYWORD = 'testing'

INVALID_DATE_MESSAGE = '"abc" is not a valid date'
START_DATE = '2021-07-18T12:02:45Z'


def util_load_json(path: str) -> dict:
    """Load a json to python dict."""
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


class MyTestCase(unittest.TestCase):
    client = Client(API_KEY, "url", False, None, True)

    @patch("Flashpoint.Client.http_request")
    def test_test_module(self, mocker):
        from Flashpoint import test_module
        test_module(client=self.client, params={})

    @patch("Flashpoint.Client.http_request")
    def test_max_fetch_limit_failure(self, mocker):
        """
        Tests max_fetch parameter failure scenario.
        """
        from Flashpoint import test_module
        with pytest.raises(ValueError) as error1:
            test_module(self.client, {"isFetch": True, "max_fetch": 0})
        assert str(error1.value) == MESSAGES["INVALID_MAX_FETCH"].format(0)

    @patch("Flashpoint.Client.http_request")
    def test_max_fetch_value_failure(self, mocker):
        """
        Tests max_fetch parameter failure scenario.
        """
        from Flashpoint import test_module
        with pytest.raises(ValueError) as error2:
            test_module(self.client, {"isFetch": True, "max_fetch": "a"})
        assert str(error2.value) == '"a" is not a valid number'

    @patch("Flashpoint.Client.http_request")
    def test_first_fetch_failure(self, mocker):
        """
        Tests first_fetch parameter failure scenario.
        """
        from Flashpoint import test_module
        with pytest.raises(ValueError) as error3:
            test_module(self.client, {"isFetch": True, "first_fetch": "abc"})
        assert str(error3.value) == INVALID_DATE_MESSAGE

    @patch("Flashpoint.Client.http_request")
    def test_domain(self, mocker):
        from Flashpoint import domain_lookup_command

        with open("./TestData/domain_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        command_result = domain_lookup_command(self.client, TEST_SCAN_DOMAIN)
        resp = command_result.to_context().get('Contents')
        result = self.get_result(resp)
        # ec = command_result.to_context().get('EntryContext')
        #
        # with open("./TestData/domain_ec.json", encoding='utf-8') as f:
        #     expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['name'] == TEST_SCAN_DOMAIN
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        # assert expected_ec == ec  # Testing CommandResult object, should not check that function

    @patch("Flashpoint.Client.http_request")
    def test_ip(self, mocker):
        from Flashpoint import ip_lookup_command

        with open("./TestData/ip_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        command_result = ip_lookup_command(self.client, TEST_SCAN_IP)
        resp = command_result.to_context().get('Contents')
        result = self.get_result(resp)
        # ec = command_result.to_context().get('EntryContext')
        #
        # with open("./TestData/ip_ec.json", encoding='utf-8') as f:
        #     expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['name'] == TEST_SCAN_IP
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        # assert expected_ec == ec  # Testing CommandResult object, should not check that function

    @patch("Flashpoint.Client.http_request")
    def test_filename(self, mocker):
        from Flashpoint import filename_lookup_command

        with open("./TestData/filename_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = filename_lookup_command(self.client, TEST_SCAN_FILENAME)
        result = self.get_result(resp)

        with open("./TestData/filename_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['name'] == TEST_SCAN_FILENAME
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_url(self, mocker):
        from Flashpoint import url_lookup_command

        with open("./TestData/url_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        command_result = url_lookup_command(self.client, TEST_SCAN_URL)
        resp = command_result.to_context().get('Contents')
        result = self.get_result(resp)
        # ec = command_result.to_context().get('EntryContext')
        #
        # with open("./TestData/url_ec.json", encoding='utf-8') as f:
        #     expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['name'] == TEST_SCAN_URL
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        # assert expected_ec == ec  # Testing CommandResult object, should not check that function

    @patch("Flashpoint.Client.http_request")
    def test_file(self, mocker):
        from Flashpoint import file_lookup_command

        with open("./TestData/file_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        command_result = file_lookup_command(self.client, TEST_SCAN_FILE)
        resp = command_result.to_context().get('Contents')
        result = self.get_result(resp)
        # ec = command_result.to_context().get('EntryContext')
        #
        # with open("./TestData/file_ec.json", encoding='utf-8') as f:
        #     expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['name'] == TEST_SCAN_FILE
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        # assert expected_ec == ec  # Testing CommandResult object, should not check that function

    @patch("Flashpoint.Client.http_request")
    def test_email(self, mocker):
        from Flashpoint import email_lookup_command

        with open("./TestData/email_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = email_lookup_command(self.client, TEST_SCAN_EMAIL)
        result = self.get_result(resp)

        with open("./TestData/email_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['name'] == TEST_SCAN_EMAIL
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_report_search_by_keyword(self, mocker):
        from Flashpoint import get_reports_command

        with open("./TestData/report_search_by_keyword_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = get_reports_command(self.client, TEST_SCAN_REPORT_KEYWORD)

        assert resp['data'][0]['title'] == TEST_SCAN_REPORT_KEYWORD
        assert expected == resp

    @patch("Flashpoint.Client.http_request")
    def test_report_search_by_id(self, mocker):
        from Flashpoint import get_report_by_id_command

        with open("./TestData/report_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = get_report_by_id_command(self.client, TEST_SCAN_REPORT_ID)

        with open("./TestData/report_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp['id'] == TEST_SCAN_REPORT_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_event_search_by_id(self, mocker):
        from Flashpoint import get_event_by_id_command

        with open("./TestData/event_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = get_event_by_id_command(self.client, TEST_SCAN_EVENT_ID)

        with open("./TestData/event_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp[0]['fpid'] == TEST_SCAN_EVENT_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_event_search_by_id_when_no_malware_description_found(self, mocker):
        from Flashpoint import get_event_by_id_command

        with open("./TestData/event_search_by_id_response_no_malware_description.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = get_event_by_id_command(self.client, TEST_SCAN_EVENT_ID)

        with open("./TestData/event_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)
            # Without malware_description in response should not be considered in EC
            expected_ec.get('Flashpoint.Event(val.EventId == obj.EventId)').pop('MalwareDescription')

        assert resp[0]['fpid'] == TEST_SCAN_EVENT_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_forum_search_by_id(self, mocker):
        from Flashpoint import get_forum_details_by_id_command

        with open("./TestData/forum_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = get_forum_details_by_id_command(self.client, TEST_SCAN_FORUM_ID)

        with open("./TestData/forum_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp['id'] == TEST_SCAN_FORUM_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_forum_room_search_by_id(self, mocker):
        from Flashpoint import get_room_details_by_id_command

        with open("./TestData/forum_room_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = get_room_details_by_id_command(self.client, TEST_SCAN_FORUM_ROOM_ID)

        with open("./TestData/forum_room_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp['id'] == TEST_SCAN_FORUM_ROOM_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_forum_user_search_by_id(self, mocker):
        from Flashpoint import get_user_details_by_id_command

        with open("./TestData/forum_user_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = get_user_details_by_id_command(self.client, TEST_SCAN_FORUM_USER_ID)

        with open("./TestData/forum_user_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp['id'] == TEST_SCAN_FORUM_USER_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_forum_post_search_by_id(self, mocker):
        from Flashpoint import get_post_details_by_id_command

        with open("./TestData/forum_post_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = get_post_details_by_id_command(self.client, TEST_SCAN_FORUM_POST_ID)

        with open("./TestData/forum_post_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp['id'] == TEST_SCAN_FORUM_POST_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_search_events(self, mocker):
        from Flashpoint import get_events_command

        with open("./TestData/events_search_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        limit = 5
        report_fpid = None
        attack_id = None
        time_period = None

        hr, ec, resp = get_events_command(self.client, limit, report_fpid, attack_id, time_period)

        assert expected == resp

    @patch("Flashpoint.Client.http_request")
    def test_forum_site_search(self, mocker):
        from Flashpoint import get_forum_sites_command

        with open("./TestData/forum_site_search_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected

        hr, ec, resp = get_forum_sites_command(self.client, TEST_SITE_SEARCH_KEYWORD)

        assert expected == resp

    @patch("Flashpoint.Client.http_request")
    def test_forum_post_search(self, mocker):
        from Flashpoint import get_forum_posts_command

        with open("./TestData/forum_post_search_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected

        hr, ec, resp = get_forum_posts_command(self.client, TEST_POST_SEARCH_KEYWORD)

        assert expected == resp

    def test_validate_alert_list_args_when_valid_args_are_provided(self):
        """ Test case scenario when the arguments provided are valid. """
        from Flashpoint import validate_alert_list_args

        args = {
            'size': '5',
            'since': '03/07/2021',
            'scroll_id': ''
        }

        fetch_args = {
            'size': 5,
            'since': '2021-03-07T00:00:00Z',
        }

        assert validate_alert_list_args(args) == fetch_args

    def test_validate_alert_list_args_when_size_is_invalid(self):
        """ Test case scenario when the argument named size is invalid. """
        from Flashpoint import validate_alert_list_args

        with pytest.raises(ValueError) as err:
            validate_alert_list_args({'size': '-1'})
        assert str(err.value) == MESSAGES['SIZE_ERROR'].format('-1')

        with pytest.raises(ValueError) as err:
            validate_alert_list_args({'size': '101'})
        assert str(err.value) == MESSAGES['SIZE_ERROR'].format('101')

    def test_validate_alert_list_args_when_since_is_invalid(self):
        """ Test case scenario when the argument named since is invalid. """
        from Flashpoint import validate_alert_list_args

        with pytest.raises(ValueError) as err:
            validate_alert_list_args({'since': 'abc'})
        assert str(err.value) == INVALID_DATE_MESSAGE

    def test_validate_alert_list_args_when_until_is_invalid(self):
        """ Test case scenario when the argument named until is invalid. """
        from Flashpoint import validate_alert_list_args

        with pytest.raises(ValueError) as err:
            validate_alert_list_args({'until': 'abc'})
        assert str(err.value) == INVALID_DATE_MESSAGE

    @patch("Flashpoint.Client.http_request")
    def test_alert_list_command_when_valid_response_is_returned(self, mocker):
        """ Test case scenario when valid response is returned. """
        from Flashpoint import flashpoint_alert_list_command

        response = util_load_json("TestData/alert_list_response.json")
        mocker.return_value = response

        context = util_load_json("TestData/alert_list.json")

        expected_hr = util_load_json("TestData/alert_hr.json")

        result = flashpoint_alert_list_command(self.client, {})

        assert result.raw_response == response
        assert result.outputs == context
        assert result.readable_output == expected_hr.get('Data')

    @patch("Flashpoint.Client.http_request")
    def test_alert_list_command_when_empty_response_is_returned(self, mocker):
        """ Test case scenario when empty response is returned. """
        from Flashpoint import flashpoint_alert_list_command

        mocker.return_value = {}

        result = flashpoint_alert_list_command(self.client, {})

        assert result.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('alerts')

    @patch("Flashpoint.Client.http_request")
    def test_alert_list_command_when_invalid_response_is_returned(self, mocker):
        """ Test case scenario when empty response is returned. """
        from Flashpoint import prepare_hr_for_alerts

        alerts = {
            "data": [
                {"source": {"created_at": {}, "last_observed": {"date-time": "dummy"}, "file": ""}}
            ]
        }
        with pytest.raises(ValueError) as er:
            prepare_hr_for_alerts(alerts.get("data"))

        assert str(er.value) == MESSAGES['MISSING_DATA'].format('Alerts')

    def test_validate_compromised_credentials_list_args_when_valid_args_are_provided(self):
        """ Test case scenario when the arguments provided are valid. """
        from Flashpoint import validate_compromised_credentials_list_args

        args = {
            'page_size': '50',
            'page_number': '2',
            'start_date': '06-01-2021',
            'end_date': '07-01-2021',
            'filter_date': 'created_at',
            'sort_date': 'created_at',
            'sort_order': 'desc',
            'is_fresh': 'true'
        }

        params = {
            'query': '+basetypes:(credential-sighting) +breach.created_at.date-time: [2021-06-01T00:00:00Z'
                     ' TO 2021-07-01T00:00:00Z] +is_fresh:true',
            'skip': 50,
            'limit': 50,
            'sort': 'breach.created_at.timestamp:desc'
        }

        assert validate_compromised_credentials_list_args(args) == params

    def test_validate_compromised_credentials_list_args_when_page_size_is_invalid(self):
        """ Test case scenario when the argument named page_size is invalid. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'page_size': '-1'})
        assert str(err.value) == MESSAGES['PAGE_SIZE_ERROR'].format('-1', MAX_PAGE_SIZE)

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'page_size': '1001'})
        assert str(err.value) == MESSAGES['PAGE_SIZE_ERROR'].format('1001', MAX_PAGE_SIZE)

    def test_validate_compromised_credentials_list_args_when_page_number_is_invalid(self):
        """ Test case scenario when the argument named page_number is invalid. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'page_number': '0'})
        assert str(err.value) == MESSAGES['PAGE_NUMBER_ERROR'].format('0')

    def test_validate_compromised_credentials_list_args_when_product_is_invalid(self):
        """ Test case scenario when the product of page_size and page_number is invalid. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'page_size': '1000', 'page_number': '20'})
        assert str(err.value) == MESSAGES['PRODUCT_ERROR'].format(MAX_PRODUCT, 20000)

    def test_validate_compromised_credentials_list_args_when_start_date_is_invalid(self):
        """ Test case scenario when the argument named start_date is invalid. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'start_date': 'abc'})
        assert str(err.value) == INVALID_DATE_MESSAGE

    def test_validate_compromised_credentials_list_args_when_end_date_is_invalid(self):
        """ Test case scenario when the argument named end_date is invalid. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'end_date': 'def days'})
        assert str(err.value) == '"def days" is not a valid date'

    def test_validate_compromised_credentials_list_args_when_start_date_is_not_provided(self):
        """ Test case scenario when the argument named end_date is provided but start_date is not provided. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'end_date': '3 days'})
        assert str(err.value) == MESSAGES['START_DATE_ERROR']

    def test_validate_compromised_credentials_list_args_when_filter_date_is_invalid(self):
        """ Test case scenario when the argument named filter_date is invalid. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'filter_date': 'indexed_at'})
        assert str(err.value) == MESSAGES['FILTER_DATE_ERROR'].format('indexed_at', FILTER_DATE_VALUES)

    def test_validate_compromised_credentials_list_args_when_dates_are_missing(self):
        """ Test case scenario when the argument named filter_date is provided but
        start_date and end_date is missing. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'filter_date': 'created_at'})
        assert str(err.value) == MESSAGES['MISSING_DATE_ERROR']

    def test_validate_compromised_credentials_list_args_when_filter_date_is_missing(self):
        """ Test case scenario when the argument named start_date and end_date are provided but
        filter_date is missing. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'start_date': '3 days'})
        assert str(err.value) == MESSAGES['MISSING_FILTER_DATE_ERROR']

    def test_validate_compromised_credentials_list_args_when_sort_date_is_invalid(self):
        """ Test case scenario when the argument named sort_date is invalid. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'sort_date': 'indexed_at'})
        assert str(err.value) == MESSAGES['SORT_DATE_ERROR'].format('indexed_at', SORT_DATE_VALUES)

    def test_validate_compromised_credentials_list_args_when_sort_order_is_invalid(self):
        """ Test case scenario when the argument named sort_order is invalid. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'sort_order': 'none'})
        assert str(err.value) == MESSAGES['SORT_ORDER_ERROR'].format('none', SORT_ORDER_VALUES)

    def test_validate_compromised_credentials_list_args_when_sort_date_is_missing(self):
        """ Test case scenario when the argument named sort_order is provided but
        sort_date is missing. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'sort_order': 'asc'})
        assert str(err.value) == MESSAGES['MISSING_SORT_DATE_ERROR']

    def test_validate_compromised_credentials_list_args_when_is_fresh_is_invalid(self):
        """ Test case scenario when the argument named is_fresh is invalid. """
        from Flashpoint import validate_compromised_credentials_list_args

        with pytest.raises(ValueError) as err:
            validate_compromised_credentials_list_args({'is_fresh': 'none'})
        assert str(err.value) == MESSAGES['IS_FRESH_ERROR'].format('none', IS_FRESH_VALUES)

    @patch("Flashpoint.Client.http_request")
    def test_compromised_credentials_list_command_when_valid_response_is_returned(self, mocker):
        """ Test case scenario when valid response is returned. """
        from Flashpoint import flashpoint_compromised_credentials_list_command

        response = util_load_json("TestData/compromised_credentials_list_response.json")
        mocker.return_value = response

        context = util_load_json("TestData/compromised_credentials_list.json")

        expected_hr = util_load_json("TestData/compromised_credentials_hr.json")

        result = flashpoint_compromised_credentials_list_command(self.client, {})

        assert result.outputs == context
        assert result.raw_response == response
        assert result.readable_output == expected_hr.get('Data')

    @patch("Flashpoint.Client.http_request")
    def test_compromised_credentials_list_command_when_empty_response_is_returned(self, mocker):
        """ Test case scenario when empty response is returned. """
        from Flashpoint import flashpoint_compromised_credentials_list_command

        mocker.return_value = {}

        result = flashpoint_compromised_credentials_list_command(self.client, {})

        assert result.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('compromised credentials')

    def test_prepare_args_for_alerts_when_valid_args_are_provided(self):
        """ Test case scenario when the arguments provided are valid. """
        from Flashpoint import prepare_args_for_fetch_alerts

        last_run = {
            'since': START_DATE,
            'scroll_id': 'dummy-scroll-id'
        }
        expected_args = {
            'size': 15,
            'since': START_DATE,
            'scroll_id': 'dummy-scroll-id'
        }

        args = prepare_args_for_fetch_alerts(max_fetch=15, start_time='2021-07-28T00:00:00Z', last_run=last_run)

        assert args == expected_args

    def test_prepare_args_for_alerts_when_max_fetch_is_invalid(self):
        """ Test case scenario when argument named max_fetch is invalid """
        from Flashpoint import prepare_args_for_fetch_alerts

        with pytest.raises(ValueError) as err:
            prepare_args_for_fetch_alerts(max_fetch=-1, start_time='', last_run={})
        assert str(err.value) == MESSAGES['INVALID_MAX_FETCH'].format(-1)

    def test_prepare_args_for_compromised_credentials_when_valid_args_are_provided(self):
        """ Test case scenario when the arguments provided are valid. """
        from Flashpoint import prepare_args_for_fetch_compromised_credentials

        end_date = arg_to_datetime('now')
        end_date = datetime.datetime.timestamp(end_date)
        expected_args = {
            'limit': 15,
            'query': '+basetypes:(credential-sighting) +header_.indexed_at: [1626609765'
                     ' TO {}] +is_fresh:true'.format(int(end_date)),
            'skip': 0,
            'sort': 'header_.indexed_at:asc'
        }

        args = prepare_args_for_fetch_compromised_credentials(max_fetch=15, start_time=START_DATE,
                                                              is_fresh=True, last_run={})

        assert args.get('limit') == expected_args.get('limit')
        assert args.get('skip') == expected_args.get('skip')
        assert args.get('sort') == expected_args.get('sort')

    def test_prepare_args_for_compromised_credentials_when_max_fetch_is_invalid(self):
        """ Test case scenario when argument named max_fetch is invalid """
        from Flashpoint import prepare_args_for_fetch_compromised_credentials

        with pytest.raises(ValueError) as err:
            prepare_args_for_fetch_compromised_credentials(max_fetch=0, start_time='', is_fresh=True, last_run={})
        assert str(err.value) == MESSAGES['INVALID_MAX_FETCH'].format(0)

    def test_validate_fetch_incidents_params_when_valid_params_are_provided(self):
        """ Test case scenario when the arguments provided are valid. """
        from Flashpoint import validate_fetch_incidents_params

        params = {
            'fetch_type': 'Alerts',
            'first_fetch': START_DATE,
            'max_fetch': '20',
            'is_fresh_compromised_credentials': False
        }
        fetch_params = {
            'size': 20,
            'since': START_DATE,
        }
        expected_params = {
            'fetch_type': 'Alerts',
            'start_time': START_DATE,
            'fetch_params': fetch_params
        }

        assert validate_fetch_incidents_params(params, {}) == expected_params

        del params['fetch_type']
        start_time = '2021-08-04T10:10:00Z'
        last_run = {
            'fetch_count': 1,
            'end_time': '2021-08-05T03:43:52Z',
            'start_time': start_time,
            'fetch_sum': 20
        }
        fetch_params = {
            'limit': 20,
            'query': '+basetypes:(credential-sighting) +header_.indexed_at: [1628071800'
                     ' TO 1628135032]',
            'skip': 20,
            'sort': 'header_.indexed_at:asc'
        }
        expected_params = {
            'fetch_type': 'Compromised Credentials',
            'start_time': start_time,
            'fetch_params': fetch_params
        }

        assert validate_fetch_incidents_params(params, last_run) == expected_params

    def test_validate_fetch_incidents_params_when_first_fetch_is_invalid(self):
        """ Test case scenario when argument named first_fetch is invalid """
        from Flashpoint import validate_fetch_incidents_params

        with pytest.raises(ValueError) as err:
            validate_fetch_incidents_params({"first_fetch": "abc"}, {})
        assert str(err.value) == INVALID_DATE_MESSAGE

        with pytest.raises(ValueError) as err:
            validate_fetch_incidents_params({"first_fetch": None}, {})
        assert str(err.value) == MESSAGES['INVALID_FIRST_FETCH']

    def test_validate_fetch_incidents_params_when_max_fetch_is_invalid(self):
        """ Test case scenario when argument named max_fetch is invalid """
        from Flashpoint import validate_fetch_incidents_params

        with pytest.raises(ValueError) as err:
            validate_fetch_incidents_params({"max_fetch": "abc"}, {})
        assert str(err.value) == '"abc" is not a valid number'

        with pytest.raises(ValueError) as err:
            validate_fetch_incidents_params({"max_fetch": ""}, {})
        assert str(err.value) == MESSAGES['INVALID_MAX_FETCH'].format('None')

    def test_remove_duplicate_records(self):
        """ Test case scenario when there are duplicate records. """
        from Flashpoint import remove_duplicate_records

        alerts = util_load_json("TestData/fetch_alert_list.json")
        next_run = {
            'alert_ids': [
                '3d376ab6-a1bd-4acc-84e6-2c385f51a3ea',
                '86dfde39-a9f5-4ab8-a8f9-1890146034a0',
                'ed707017-26c4-4551-b3a0-3856c54d699b'
            ]
        }

        expected_alerts = util_load_json("TestData/fetch_alert_list_after_removing_duplication.json")

        assert remove_duplicate_records(alerts, "Alerts", next_run) == expected_alerts

    def test_prepare_incidents_from_alerts_data_when_valid_response_is_returned(self):
        """ Test case scenario when the given data is valid. """
        from Flashpoint import prepare_incidents_from_alerts_data

        start_time = '2021-06-16T02:22:14Z'
        response = util_load_json('TestData/alert_list_response.json')
        expected_incidents = util_load_json('TestData/incidents_alerts.json')
        expected_next_run = {
            'alert_ids': ['2983ad0b-b03d-4202-bea7-65dd94697b5b', 'a31a9f81-988b-47c0-9739-1300e1855f6b'],
            'start_time': '2021-07-28T16:56:07Z',
            'scroll_id': 'f97c16ab5408f3bb7df60e58c5b24a57$1623810166.258678',
            'since': start_time,
            'size': '1',
            'until': '2021-06-16T02:45:00Z'
        }

        next_run, incidents = prepare_incidents_from_alerts_data(response, {}, start_time)

        assert next_run == expected_next_run
        assert incidents == expected_incidents

    def test_prepare_incidents_from_alerts_data_when_empty_response_is_returned(self):
        """ Test case scenario when empty response is returned. """
        from Flashpoint import prepare_incidents_from_alerts_data

        expected_next_run = {
            'scroll_id': None,
            'since': START_DATE
        }

        next_run, incidents = prepare_incidents_from_alerts_data({}, {}, START_DATE)

        assert next_run == expected_next_run
        assert incidents == []

    def test_prepare_incidents_from_compromised_credentials_data_when_valid_response_is_returned(self):
        """ Test case scenario when the given data is valid. """
        from Flashpoint import prepare_incidents_from_compromised_credentials_data

        response = util_load_json('TestData/compromised_credentials_list_response.json')
        next_run = {
            'fetch_count': 0,
            'fetch_sum': 100
        }

        expected_incidents = util_load_json('TestData/incidents_compromised_credentials.json')
        expected_next_run = {
            'total': 1302,
            'fetch_count': 1,
            'fetch_sum': 100,
            'start_time': START_DATE,
            'hit_ids': ['YOBETNFzX0Ohjiq0xi_2Eg'],
            'last_time': '2021-03-31T19:42:05Z',
            'last_timestamp': 1617219725
        }

        next_run, incidents = prepare_incidents_from_compromised_credentials_data(response, next_run, START_DATE)

        assert next_run == expected_next_run
        assert incidents == expected_incidents

        end_time = '2021-08-05T17:50:00Z'
        last_time = '2021-03-31T19:42:05Z'
        next_run = {
            'fetch_count': 2,
            'fetch_sum': 100,
            'start_time': START_DATE,
            'end_time': end_time
        }
        expected_next_run = {
            'total': None,
            'fetch_count': 0,
            'fetch_sum': 0,
            'start_time': last_time,
            'end_time': end_time,
            'hit_ids': ['YOBETNFzX0Ohjiq0xi_2Eg'],
            'last_time': last_time,
            'last_timestamp': 1617219725
        }
        response['hits']['total'] = 100
        next_run, _ = prepare_incidents_from_compromised_credentials_data(response, next_run, START_DATE)

        assert next_run == expected_next_run

    def test_prepare_incidents_from_compromised_credentials_data_when_empty_response_is_returned(self):
        """ Test case scenario when empty response is returned. """
        from Flashpoint import prepare_incidents_from_compromised_credentials_data

        next_run = {
            'fetch_sum': 100,
            'fetch_count': 0,
        }
        expected_next_run = {
            'fetch_sum': 0,
            'fetch_count': 0,
            'total': None
        }

        next_run, incidents = prepare_incidents_from_compromised_credentials_data({'hits': {'total': 0}}, next_run,
                                                                                  START_DATE)

        assert next_run == expected_next_run
        assert incidents == []

    def test_prepare_incidents_from_compromised_credentials_data_when_email_is_not_present(self):
        """ Test case scenario when email key is not present in the response. """
        from Flashpoint import prepare_incidents_from_compromised_credentials_data

        next_run = {
            'fetch_count': 0,
            'fetch_sum': 100
        }
        response = util_load_json("TestData/compromised_credentials_list_response.json")
        del response['hits']['hits'][0]['_source']['email']
        expected_incidents = util_load_json("TestData/incidents_compromised_credentials_when_email_not_present.json")

        _, incidents = prepare_incidents_from_compromised_credentials_data(response, next_run, START_DATE)

        assert incidents == expected_incidents

    def test_prepare_incidents_from_compromised_credentials_data_when_fpid_is_not_present(self):
        """ Test case scenario when email key is not present in the response. """
        from Flashpoint import prepare_incidents_from_compromised_credentials_data

        next_run = {
            'fetch_count': 0,
            'fetch_sum': 100
        }
        response = util_load_json("TestData/compromised_credentials_list_response.json")

        del response['hits']['hits'][0]['_source']['email']
        del response['hits']['hits'][0]['_source']['fpid']
        expected_incidents = util_load_json("TestData/incidents_compromised_credentials_when_fpid_not_present.json")

        _, incidents = prepare_incidents_from_compromised_credentials_data(response, next_run, START_DATE)

        assert incidents == expected_incidents

    def test_prepare_incidents_from_compromised_credentials_data_when_records_are_more_than_limit(self):
        """ Test case scenario when the records are more than 10k. """
        from Flashpoint import prepare_incidents_from_compromised_credentials_data

        response = util_load_json("TestData/compromised_credentials_list_response.json")

        total = 10001
        response['hits']['total'] = total

        with pytest.raises(ValueError) as err:
            prepare_incidents_from_compromised_credentials_data(response, {'fetch_count': 0}, START_DATE)
        assert str(err.value) == MESSAGES['TIME_RANGE_ERROR'].format(total)

    def test_prepare_incidents_from_compromised_credentials_data_when_duplicate_records_are_present(self):
        """ Test case scenario when the records are duplicate. """
        from Flashpoint import prepare_incidents_from_compromised_credentials_data

        end_time = '2021-08-16T12:50:00Z'
        last_time = '2021-08-13T12:07:37Z'
        hit_ids = ['sIgauE9_X_m-y4NG-YuFig', 'kpKTMfErVDeb_zc60b52rg', '8m1IiImZVLOjdSOa16WKug',
                   'BeGFUbnlVMaur1g2u242sg', 'e_xaqvFdUz6ssGVbbXG7WA', 'yvzOnxaMVTKljLaSOYdILQ',
                   'fhiwOzONUDmZNq1TP092Zg', 'I-lA13YAUTmvB_XR9s6DXA', 'f1k62JNjUgu__CmUWSKrcw',
                   'HOr1NJB-X4yxJjmBhF3j1Q', 'E-w8zTgAUoCIdm0BZzLcyA', 'm-QJuetCX-6dbbBPedwqew',
                   'ueX_g5ZMW824FG-DpWecZg', 'qY7WhCzSV0aX2l39CIvCKg', '4Ztk3NxdULiozsxk2YYa2w']

        next_run = {
            'total': None,
            'fetch_count': 0,
            'fetch_sum': 15,
            'start_time': last_time,
            'end_time': end_time,
            'hit_ids': hit_ids,
            'last_time': last_time,
            'last_timestamp': 1628856457
        }
        expected_next_run = {
            'total': 46,
            'fetch_count': 1,
            'fetch_sum': 15,
            'start_time': last_time,
            'end_time': end_time,
            'hit_ids': hit_ids,
            'last_time': last_time,
            'last_timestamp': 1628856457
        }

        response = util_load_json("TestData/compromised_credentials_duplicate_records.json")

        next_run, incidents = prepare_incidents_from_compromised_credentials_data(response, next_run, last_time)

        assert incidents == []
        assert next_run == expected_next_run

    @patch("Flashpoint.Client.http_request")
    def test_fetch_incidents_when_valid_response_is_returned(self, mocker):
        """ Test case scenario for successful execution of fetch_incident. """
        from Flashpoint import fetch_incidents

        response = util_load_json('TestData/compromised_credentials_list_response.json')
        mocker.return_value = response

        expected_incidents = util_load_json('TestData/incidents_compromised_credentials.json')
        params = {'max_fetch': '1', 'first_fetch': '1 year', 'fetch_type': ''}

        _, incidents = fetch_incidents(self.client, {}, params)

        assert incidents == expected_incidents

        response = util_load_json('TestData/alert_list_response.json')
        mocker.return_value = response

        expected_incidents = util_load_json('TestData/incidents_alerts.json')
        params = {'max_fetch': '1', 'first_fetch': '1 year', 'fetch_type': 'Alerts'}

        _, incidents = fetch_incidents(self.client, {}, params)

        assert incidents == expected_incidents

    def get_result(self, resp):
        resp = resp[0]
        type = resp['Attribute']['type']
        name = resp['Attribute']['value'][type]
        fpid = resp['Attribute']['fpid']
        href = resp['Attribute']['href']

        result = {
            'name': name,
            'type': type,
            'fpid': fpid,
            'href': href
        }
        return result


if __name__ == '__main__':
    unittest.main()
