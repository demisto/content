import unittest
import json
import demistomock as demisto
from mock import patch
from Flashpoint import Client

API_KEY = demisto.getParam('api_key')

HREF_BASE_URL = 'https://fp.tools/api/v4/indicators/attribute/'
TEST_SCAN_DOMAIN = 'subaat.com'
TEST_SCAN_IP = '210.122.7.129'
TEST_SCAN_FILENAME = '.locked'
TEST_SCAN_URL = 'http://www.welshantifa.org'
TEST_SCAN_FILE = 'ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5'
TEST_SCAN_EMAIL = 'qicifomuejijika@o2.pl'

TEST_SCAN_REPORT_KEYWORD = 'November 21 Collections Update'
TEST_SCAN_REPORT_ID = 'e-QdYuuwRwCntzRljzn9-A'
TEST_SCAN_EVENT_ID = 'Hu2SoTWJWteLrH9mR94JbQ'
TEST_SCAN_FORUM_ID = 'rJnT5ETuWcW9jTCnsobFZQ'
TEST_SCAN_FORUM_ROOM_ID = 'dBoQqur5XmGGYLxSrc8C9A'
TEST_SCAN_FORUM_USER_ID = 'P3au_EzEX4-uctmRfdUYeA'
TEST_SCAN_FORUM_POST_ID = 'PDo1xGiKXDebHGc8fZme6g'
TEST_SITE_SEARCH_KEYWORD = '0hack'
TEST_POST_SEARCH_KEYWORD = 'The Courtyard Café'


class MyTestCase(unittest.TestCase):
    client = Client(API_KEY)

    @patch("Flashpoint.Client.http_request")
    def test_domain(self, mocker):
        from Flashpoint import domain_lookup

        with open("./TestData/domain_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = domain_lookup(self.client, TEST_SCAN_DOMAIN)
        result = self.get_result(resp)

        with open("./TestData/domain_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['type'] == 'domain'
        assert result['name'] == TEST_SCAN_DOMAIN
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_ip(self, mocker):
        from Flashpoint import ip_lookup

        with open("./TestData/ip_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = ip_lookup(self.client, TEST_SCAN_IP)
        result = self.get_result(resp)

        with open("./TestData/ip_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['type'] == 'ip-dst'
        assert result['name'] == TEST_SCAN_IP
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_filename(self, mocker):
        from Flashpoint import filename_lookup

        with open("./TestData/filename_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = filename_lookup(self.client, TEST_SCAN_FILENAME)
        result = self.get_result(resp)

        with open("./TestData/filename_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['type'] == 'filename'
        assert result['name'] == TEST_SCAN_FILENAME
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_url(self, mocker):
        from Flashpoint import url_lookup

        with open("./TestData/url_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = url_lookup(self.client, TEST_SCAN_URL)
        result = self.get_result(resp)

        with open("./TestData/url_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['type'] == 'url'
        assert result['name'] == TEST_SCAN_URL
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_file(self, mocker):
        from Flashpoint import file_lookup

        with open("./TestData/file_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = file_lookup(self.client, TEST_SCAN_FILE)
        result = self.get_result(resp)

        with open("./TestData/file_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['type'] == 'sha256'
        assert result['name'] == TEST_SCAN_FILE
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_email(self, mocker):
        from Flashpoint import email_lookup

        with open("./TestData/email_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = email_lookup(self.client, TEST_SCAN_EMAIL)
        result = self.get_result(resp)

        with open("./TestData/email_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        fpid = result['fpid']
        assert result['type'] == 'email-dst'
        assert result['name'] == TEST_SCAN_EMAIL
        assert result['href'] == HREF_BASE_URL + fpid
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_report_search_by_keyword(self, mocker):
        from Flashpoint import get_reports

        with open("./TestData/report_search_by_keyword_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = get_reports(self.client, TEST_SCAN_REPORT_KEYWORD)

        assert resp['data'][0]['title'] == TEST_SCAN_REPORT_KEYWORD
        assert expected == resp

    @patch("Flashpoint.Client.http_request")
    def test_report_search_by_id(self, mocker):
        from Flashpoint import get_report_by_id

        with open("./TestData/report_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = get_report_by_id(self.client, TEST_SCAN_REPORT_ID)

        with open("./TestData/report_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp['id'] == TEST_SCAN_REPORT_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_event_search_by_id(self, mocker):
        from Flashpoint import get_event_by_id

        with open("./TestData/event_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = get_event_by_id(self.client, TEST_SCAN_EVENT_ID)

        with open("./TestData/event_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp[0]['fpid'] == TEST_SCAN_EVENT_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_forum_search_by_id(self, mocker):
        from Flashpoint import get_forum_details_by_id

        with open("./TestData/forum_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = get_forum_details_by_id(self.client, TEST_SCAN_FORUM_ID)

        with open("./TestData/forum_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp['id'] == TEST_SCAN_FORUM_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_forum_room_search_by_id(self, mocker):
        from Flashpoint import get_room_details_by_id

        with open("./TestData/forum_room_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = get_room_details_by_id(self.client, TEST_SCAN_FORUM_ROOM_ID)

        with open("./TestData/forum_room_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp['id'] == TEST_SCAN_FORUM_ROOM_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_forum_user_search_by_id(self, mocker):
        from Flashpoint import get_user_details_by_id

        with open("./TestData/forum_user_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = get_user_details_by_id(self.client, TEST_SCAN_FORUM_USER_ID)

        with open("./TestData/forum_user_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp['id'] == TEST_SCAN_FORUM_USER_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_forum_post_search_by_id(self, mocker):
        from Flashpoint import get_post_details_by_id

        with open("./TestData/forum_post_search_by_id_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        resp, hr, ec = get_post_details_by_id(self.client, TEST_SCAN_FORUM_POST_ID)

        with open("./TestData/forum_post_search_by_id_ec.json", encoding='utf-8') as f:
            expected_ec = json.load(f)

        assert resp['id'] == TEST_SCAN_FORUM_POST_ID
        assert expected == resp
        assert expected_ec == ec

    @patch("Flashpoint.Client.http_request")
    def test_search_events(self, mocker):
        from Flashpoint import get_events

        with open("./TestData/events_search_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected
        limit = 5
        report_fpid = None
        attack_id = None
        time_period = None

        resp, hr, ec = get_events(self.client, limit, report_fpid, attack_id, time_period)

        assert expected == resp

    @patch("Flashpoint.Client.http_request")
    def test_forum_site_search(self, mocker):
        from Flashpoint import get_forum_sites

        with open("./TestData/forum_site_search_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected

        resp, hr, ec = get_forum_sites(self.client, TEST_SITE_SEARCH_KEYWORD)

        assert expected == resp

    @patch("Flashpoint.Client.http_request")
    def test_forum_post_search(self, mocker):
        from Flashpoint import get_forum_posts

        with open("./TestData/forum_post_search_response.json", encoding='utf-8') as f:
            expected = json.load(f)

        mocker.return_value = expected

        resp, hr, ec = get_forum_posts(self.client, TEST_POST_SEARCH_KEYWORD)

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
