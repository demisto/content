import json
import unittest
import demistomock as demisto
from IronDefense import IronDefense, LOG_PREFIX
from unittest import TestCase
import mock
import requests
from typing import Dict
from http.client import HTTPException
requests.packages.urllib3.disable_warnings()


class IronDefenseTest(TestCase):

    COOKIE_KEY = 'some_cookie_key'

    # Create a mock logger so nothing gets written to stdout
    demisto_logger_patcher = mock.patch('IronDefense.DemistoLogger', autospec=True)
    MockDemistoLogger = demisto_logger_patcher.start()
    MockDemistoLogger.debug = lambda msg: None
    MockDemistoLogger.error = lambda msg: None

    session_patcher = mock.patch('requests.Session', autospec=True)
    MockSession = session_patcher.start()

    def setUp(self):
        self.host = 'dev.rva.ironnet.io'
        self.url_prefix = '/IronApi'
        self.port = 6942
        self.credentials = {
            'identifier': 'someusername',
            'password': 'somepassword'
        }

        logger = self.MockDemistoLogger(demisto, LOG_PREFIX)
        self.mock_session = self.MockSession()
        self.mock_session.headers = {}
        # initialize the IronDefense object
        self.class_under_test = IronDefense(demisto,
                                            self.mock_session,
                                            self.host,
                                            self.port,
                                            self.credentials,
                                            logger)

    def tearDown(self):
        demisto.setIntegrationContext({})

    def test_get_jwt(self):
        test_jwt = 'jwt token'
        test_context = {
            'JWT': test_jwt
        }
        self.assertEqual(test_jwt, self.class_under_test._get_jwt(test_context), 'Unexpected result')
        self.assertEqual(None, self.class_under_test._get_jwt(None), 'None context should return None')
        self.assertEqual(None, self.class_under_test._get_jwt({'bogus': 'context'}), 'Missing jwt in context should return None')

    def test_configure_session_auth(self):
        self.mock_session.headers = {}

        # test no jwt token
        self.class_under_test._configure_session_auth({})
        self.assertIsNone(self.mock_session.headers.get('authentication', None))

        # test loading jwt token
        test_jwt = 'jwt token'
        test_context = {
            'JWT': test_jwt
        }
        self.class_under_test._configure_session_auth(test_context)
        self.assertEqual('Bearer ' + test_jwt, self.mock_session.headers.get('Authorization'))

    @mock.patch('requests.Response', autospec=True)
    def test_http_request(self, MockResponse):
        MockResponse.return_value.headers = {}
        method = 'GET'
        uri = '/something'
        headers: Dict[str, str] = {}
        data = '{}'
        params: Dict[str, str] = {}
        files = None
        mock_jwt_value = 'jwt token'
        expected_uri = 'https://{}:{}{}{}'.format(self.host, self.port, self.url_prefix, uri)

        '''Test successful response'''
        mock_response = MockResponse()
        mock_response.status_code = 200
        self.mock_session.request.return_value = mock_response

        test_response = self.class_under_test._http_request(method, uri)
        self.mock_session.request.assert_called_with(method, expected_uri, headers=headers, data=data, params=params,
                                                     files=files, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)
        self.assertEqual(test_response, mock_response)

        '''Test incorrect creds'''
        mock_response = MockResponse()
        mock_response.status_code = 401
        self.mock_session.request.return_value = mock_response

        test_response = self.class_under_test._http_request(method, uri)
        self.mock_session.request.assert_called_with(method, expected_uri, headers=headers, data=data, params=params,
                                                     files=files, timeout=self.class_under_test.request_timeout,
                                                     auth=(
                                                         self.credentials['identifier'], self.credentials['password']),
                                                     verify=False)
        self.assertEqual(test_response, mock_response)

        '''Test expired jwt'''
        self.mock_session.request.reset_mock()

        # create a class to return a mock 401 response after the initial call then a 200 response after
        class RequestEffect:
            def __init__(self):
                pass

            calls = 0

            def side_effect(self, *args, **kwargs):
                self.calls += 1
                side_effect_response = MockResponse()
                if self.calls > 1:
                    side_effect_response.status_code = 200
                    side_effect_response.headers['auth-token'] = mock_jwt_value
                else:
                    side_effect_response.status_code = 401
                return side_effect_response

        self.mock_session.request.side_effect = RequestEffect().side_effect

        test_response = self.class_under_test._http_request(method, uri)

        self.mock_session.request.assert_has_calls([
            mock.call(method, expected_uri, headers=headers, data=data, params=params,
                      files=files, timeout=self.class_under_test.request_timeout,
                      auth=None, verify=False),
            mock.call(method, expected_uri, headers=headers, data=data, params=params, files=files,
                      timeout=self.class_under_test.request_timeout,
                      auth=(self.credentials['identifier'], self.credentials['password']), verify=False)
        ])
        # check to see if the jwt was stored
        self.assertDictEqual({'JWT': mock_jwt_value}, demisto.getIntegrationContext(), 'JWT value should be the same '
                                                                                       'as the stored value.')
        self.assertEqual(200, test_response.status_code, 'Unexpected status code')
        self.assertEqual(2, self.mock_session.request.call_count, '_http_request should have made 2 calls')

        '''Test 5xx response'''
        self.mock_session.request.reset_mock()
        self.mock_session.request.side_effect = None

        mock_response = MockResponse()
        mock_response.status_code = 500
        mock_response.json.return_value = {'msg': 'server error!'}
        self.mock_session.request.return_value = mock_response

        test_response = self.class_under_test._http_request(method, uri)
        self.mock_session.request.assert_called_with(method, expected_uri, headers=headers, data=data, params=params,
                                                     files=files, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)
        self.assertEqual(test_response, mock_response)

    @mock.patch('requests.Response', autospec=True)
    def test_test_module(self, MockResponse):
        MockResponse.return_value.headers = {}
        expected_uri = 'https://{}:{}{}{}'.format(self.host, self.port, self.url_prefix, '/Login')

        # test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers['auth-token'] = 'some jwt token'
        self.mock_session.request.return_value = mock_response
        result = self.class_under_test.test_module()
        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data='{}', params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=(self.credentials['identifier'], self.credentials[
                                                         'password']),
                                                     verify=False)
        self.assertEqual('ok', result, 'Result should be "ok"')

        # test failed response
        error_json = {
            'msg': 'Some error message'
        }
        error_msg = json.dumps(error_json)
        mock_response = MockResponse()
        mock_response.status_code = 500
        mock_response.text = error_msg
        mock_response.json.return_value = error_json
        mock_response.headers['auth-token'] = 'some jwt token'
        self.mock_session.request.return_value = mock_response
        result = self.class_under_test.test_module()
        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data='{}', params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=(self.credentials['identifier'], self.credentials[
                                                         'password']),
                                                     verify=False)
        self.assertNotEqual('ok', result, 'Result should have an error message')

    @mock.patch('requests.Response', autospec=True)
    def test_update_analyst_ratings(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = 'test_alert_id'
        severity = 'Malicious'
        expectation = 'Unexpected'
        comments = 'test comments'
        share_irondome = True

        expected_uri = 'https://{}:{}{}{}'.format(self.host, self.port, self.url_prefix, '/RateAlert')
        expected_body = json.dumps({
            'alert_id': alert_id,
            'analyst_severity': 'SEVERITY_MALICIOUS',
            'analyst_expectation': 'EXP_UNEXPECTED',
            'comment': comments,
            'share_comment_with_irondome': share_irondome
        })

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers['auth-token'] = 'some jwt token'
        self.mock_session.request.return_value = mock_response

        self.class_under_test.update_analyst_ratings(alert_id, severity=severity, expectation=expectation,
                                                     comments=comments, share_irondome=share_irondome)

        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data=expected_body, params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.headers['auth-token'] = 'some jwt token'
        mock_response.json.return_value = {
            'msg': 'Some error'
        }
        self.mock_session.request.return_value = mock_response

        self.assertRaises(HTTPException, self.class_under_test.update_analyst_ratings, alert_id, severity=severity,
                          expectation=expectation, comments=comments, share_irondome=share_irondome)

        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data=expected_body, params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)

    @mock.patch('requests.Response', autospec=True)
    def test_add_comment_to_alert(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = 'test_alert_id'
        comment = 'test comment'
        share_irondome = True

        expected_uri = 'https://{}:{}{}{}'.format(self.host, self.port, self.url_prefix, '/CommentOnAlert')
        expected_body = json.dumps({
            'alert_id': alert_id,
            'comment': comment,
            'share_comment_with_irondome': share_irondome
        })

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers['auth-token'] = 'some jwt token'
        self.mock_session.request.return_value = mock_response

        self.class_under_test.add_comment_to_alert(alert_id, comment=comment, share_irondome=share_irondome)

        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data=expected_body, params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.headers['auth-token'] = 'some jwt token'
        mock_response.json.return_value = {
            'msg': 'Some error'
        }
        self.mock_session.request.return_value = mock_response

        self.assertRaises(HTTPException, self.class_under_test.add_comment_to_alert, alert_id, comment=comment,
                          share_irondome=share_irondome)

        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data=expected_body, params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)

    @mock.patch('requests.Response', autospec=True)
    def test_set_alert_status(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = 'test_alert_id'
        status = 'Closed'
        comments = 'test comments'
        share_irondome = True

        expected_uri = 'https://{}:{}{}{}'.format(self.host, self.port, self.url_prefix, '/SetAlertStatus')
        expected_body = json.dumps({
            'alert_id': alert_id,
            'status': 'STATUS_CLOSED',
            'comment': comments,
            'share_comment_with_irondome': share_irondome
        })

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers['auth-token'] = 'some jwt token'
        self.mock_session.request.return_value = mock_response

        self.class_under_test.set_alert_status(alert_id, status=status, comments=comments, share_irondome=share_irondome)

        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data=expected_body, params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.headers['auth-token'] = 'some jwt token'
        mock_response.json.return_value = {
            'msg': 'Some error'
        }
        self.mock_session.request.return_value = mock_response

        self.assertRaises(HTTPException, self.class_under_test.set_alert_status, alert_id, status=status,
                          comments=comments, share_irondome=share_irondome)

        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data=expected_body, params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)

    @mock.patch('requests.Response', autospec=True)
    def test_report_observed_bad_activity(self, MockResponse):
        MockResponse.return_value.headers = {}

        name = 'test_name'
        description = 'asdf'
        ip = '1.1.1.1'
        domain = 'bad.com'
        activity_start_time = '2019-01-01T00:00:00Z'
        activity_end_time = '2019-02-01T00:00:00Z'

        expected_uri = 'https://{}:{}{}{}'.format(self.host, self.port, self.url_prefix, '/ReportObservedBadActivity')
        expected_body = json.dumps({
            'name': name,
            'description': description,
            'ip': ip,
            'domain': domain,
            'activity_start_time': activity_start_time,
            'activity_end_time': activity_end_time,
        })

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.ok = True
        mock_response.headers['auth-token'] = 'some jwt token'
        self.mock_session.request.return_value = mock_response

        self.class_under_test.report_observed_bad_activity(name, description=description, ip=ip, domain=domain,
                                                           activity_start_time=activity_start_time,
                                                           activity_end_time=activity_end_time)

        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data=expected_body, params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.ok = False
        mock_response.headers['auth-token'] = 'some jwt token'
        mock_response.json.return_value = {
            'msg': 'Some error'
        }
        self.mock_session.request.return_value = mock_response

        self.assertRaises(HTTPException, self.class_under_test.report_observed_bad_activity, name,
                          description=description, ip=ip, domain=domain, activity_start_time=activity_start_time,
                          activity_end_time=activity_end_time)

        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data=expected_body, params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)

    @mock.patch('requests.Response', autospec=True)
    def test_get_error_msg_from_response(self, MockResponse):
        expected_error_msg = 'Some error message'
        mock_response = MockResponse()
        error_json = {
            'msg': expected_error_msg
        }

        mock_response.json.return_value = error_json
        error_msg = self.class_under_test._get_error_msg_from_response(mock_response)
        self.assertEqual(expected_error_msg, error_msg, 'Error message was not properly extracted')

        mock_response.json.return_value = {}
        mock_response.text = expected_error_msg
        error_msg = self.class_under_test._get_error_msg_from_response(mock_response)
        self.assertEqual(expected_error_msg, error_msg, 'Error message was not properly extracted')


if __name__ == '__main__':
    unittest.main()
