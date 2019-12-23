import demistomock as demisto

import json
import unittest
from unittest.mock import patch
from Flashpoint import Client

API_KEY = demisto.getParam('api_key')

HREF_BASE_URL = 'http://123-fake-api.com/api/v4/indicators/attribute/'
TEST_SCAN_DOMAIN = 'fakedomain.com'
TEST_SCAN_IP = '0.0.0.0'
TEST_SCAN_FILENAME = 'fakefilename'
TEST_SCAN_URL = 'http://123-fake-api.com'
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


class MyTestCase(unittest.TestCase):
    client = Client(API_KEY, "url", False, None)

    @patch("Flashpoint.Client.http_request")
    def test_domain(self, mocker):
        from Flashpoint import domain_lookup_command

        with open("./TestData/domain_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = domain_lookup_command(self.client, TEST_SCAN_DOMAIN)
        result = self.get_result(resp)

        with open("./TestData/domain_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['name'] == TEST_SCAN_DOMAIN
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_ip(self, mocker):
        from Flashpoint import ip_lookup_command

        with open("./TestData/ip_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = ip_lookup_command(self.client, TEST_SCAN_IP)
        result = self.get_result(resp)

        with open("./TestData/ip_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['name'] == TEST_SCAN_IP
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

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
        hr, ec, resp = url_lookup_command(self.client, TEST_SCAN_URL)
        result = self.get_result(resp)

        with open("./TestData/url_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['name'] == TEST_SCAN_URL
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_file(self, mocker):
        from Flashpoint import file_lookup_command

        with open("./TestData/file_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        hr, ec, resp = file_lookup_command(self.client, TEST_SCAN_FILE)
        result = self.get_result(resp)

        with open("./TestData/file_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['name'] == TEST_SCAN_FILE
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

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
