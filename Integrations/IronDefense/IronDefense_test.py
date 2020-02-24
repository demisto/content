# type: ignore
import json
import unittest
import demistomock as demisto
import IronDefense as irondefense_module
from IronDefense import IronDefense, LOG_PREFIX
from unittest import TestCase, mock
from unittest.mock import Mock
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
        self.assertEqual(None, self.class_under_test._get_jwt({'bogus': 'context'}),
                         'Missing jwt in context should return None')

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

        self.class_under_test.set_alert_status(alert_id, status=status, comments=comments,
                                               share_irondome=share_irondome)

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
    def test_get_event(self, MockResponse):
        MockResponse.return_value.headers = {}

        event_id = 'test_event_id'

        expected_uri = 'https://{}:{}{}{}'.format(self.host, self.port, self.url_prefix, '/GetEvent')
        expected_body = json.dumps({
            'event_id': event_id,
        })

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers['auth-token'] = 'some jwt token'
        self.mock_session.request.return_value = mock_response

        self.class_under_test.get_event(event_id)

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
        self.assertRaises(HTTPException, self.class_under_test.get_event, event_id)

        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data=expected_body, params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)

    @mock.patch('requests.Response', autospec=True)
    def test_get_events(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = 'test_alert_id'

        expected_uri = 'https://{}:{}{}{}'.format(self.host, self.port, self.url_prefix, '/GetEvents')
        expected_body = json.dumps({
            "alert_id": "test_alert_id",
            "constraint": {
                "limit": 10,
                "offset": 1
            }
        })

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers['auth-token'] = 'some jwt token'
        self.mock_session.request.return_value = mock_response

        self.class_under_test.get_events(alert_id=alert_id, limit=10, offset=1)

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
        self.assertRaises(HTTPException, self.class_under_test.get_events, alert_id, limit=10, offset=1)

        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data=expected_body, params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)

    @mock.patch('requests.Response', autospec=True)
    def test_get_alerts(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = ['test_alert_id']
        category = ['test_category']
        sub_category = ['test_category']
        status = ['test_status']
        analyst_severity = ['test_analyst_severity']
        analyst_expectation = ['test_analyst_expectation']
        severity = {
            'lower_bound': 0,
            'upper_bound': 2
        }
        created = {
            'start': '2019-01-01T00:00:00Z',
            'end': '2020-01-01T00:00:00Z'
        }
        updated = {
            'start': '2019-02-01T00:00:00Z',
            'end': '2020-02-01T00:00:00Z'
        }
        first_event_created = {
            'start': '2019-02-01T00:00:00Z',
            'end': '2020-02-01T00:00:00Z'
        }
        last_event_created = {
            'start': '2019-02-01T00:00:00Z',
            'end': '2020-02-01T00:00:00Z'
        }
        first_event_start_time = {
            'start': '2019-02-01T00:00:00Z',
            'end': '2020-02-01T00:00:00Z'
        }
        last_event_end_time = {
            'start': '2019-02-01T00:00:00Z',
            'end': '2020-02-01T00:00:00Z'
        }
        analytic_version = ['1']
        constraint = {
            'limit': 10,
            'offset': 0
        }
        sort = [{
            'field': 'ASF_UPDATED',
            'direction': 'SD_ASCENDING'
        }]

        expected_uri = 'https://{}:{}{}{}'.format(self.host, self.port, self.url_prefix, '/GetAlerts')
        expected_body = json.dumps({
            'alert_id': alert_id,
            'category': category,
            'sub_category': sub_category,
            'status': status,
            'analyst_severity': analyst_severity,
            'analyst_expectation': analyst_expectation,
            'analytic_version': analytic_version,
            'sort': sort,
            'severity': severity,
            'created': created,
            'updated': updated,
            'first_event_created': first_event_created,
            'last_event_created': last_event_created,
            'first_event_start_time': first_event_start_time,
            'last_event_end_time': last_event_end_time,
            'constraint': constraint
        })

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.ok = True
        mock_response.headers['auth-token'] = 'some jwt token'
        self.mock_session.request.return_value = mock_response

        self.class_under_test.get_alerts(alert_id=alert_id[0], category=category[0], sub_category=sub_category[0],
                                         status=status[0],
                                         analyst_severity=analyst_severity[0],
                                         analyst_expectation=analyst_expectation[0], min_severity=severity['lower_bound'],
                                         max_severity=severity['upper_bound'], min_created=created['start'],
                                         max_created=created['end'],
                                         min_updated=updated['start'], max_updated=updated['end'],
                                         min_first_event_created=first_event_created['start'],
                                         max_first_event_created=first_event_created['end'],
                                         min_last_event_created=last_event_created['start'],
                                         max_last_event_created=last_event_created['end'],
                                         min_first_event_start_time=first_event_start_time['start'],
                                         max_first_event_start_time=first_event_start_time['end'],
                                         min_last_event_end_time=last_event_end_time['start'],
                                         max_last_event_end_time=last_event_end_time['end'],
                                         analytic_version=analytic_version[0],
                                         limit=constraint['limit'], offset=constraint['offset'], sort=sort)

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

        self.assertRaises(HTTPException, self.class_under_test.get_alerts, alert_id=alert_id[0], category=category[0],
                          sub_category=sub_category[0], status=status[0],
                          analyst_severity=analyst_severity[0],
                          analyst_expectation=analyst_expectation[0], min_severity=severity['lower_bound'],
                          max_severity=severity['upper_bound'], min_created=created['start'],
                          max_created=created['end'],
                          min_updated=updated['start'], max_updated=updated['end'],
                          min_first_event_created=first_event_created['start'],
                          max_first_event_created=first_event_created['end'],
                          min_last_event_created=last_event_created['start'],
                          max_last_event_created=last_event_created['end'],
                          min_first_event_start_time=first_event_start_time['start'],
                          max_first_event_start_time=first_event_start_time['end'],
                          min_last_event_end_time=last_event_end_time['start'],
                          max_last_event_end_time=last_event_end_time['end'], analytic_version=analytic_version[0],
                          limit=constraint['limit'], offset=constraint['offset'], sort=sort)

        self.mock_session.request.assert_called_with('POST', expected_uri, headers={}, data=expected_body, params={},
                                                     files=None, timeout=self.class_under_test.request_timeout,
                                                     auth=None, verify=False)

    @mock.patch('requests.Response', autospec=True)
    def test_get_alert_irondome_information(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = 'test_alert_id'

        expected_uri = 'https://{}:{}{}{}'.format(self.host, self.port, self.url_prefix, '/GetAlertIronDomeInformation')
        expected_body = json.dumps({
            'alert_id': alert_id,
        })

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers['auth-token'] = 'some jwt token'
        self.mock_session.request.return_value = mock_response

        self.class_under_test.get_alert_irondome_information(alert_id)

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

        self.assertRaises(HTTPException, self.class_under_test.get_alert_irondome_information, alert_id)

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

    @mock.patch('IronDefense.demisto')
    def test_test_module_command(self, mock_demisto):

        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = 'result'
        irondefense_module.IRON_DEFENSE.test_module.return_value = expected_result

        irondefense_module.test_module_command()
        irondefense_module.IRON_DEFENSE.test_module.assert_called_once()
        mock_demisto.results.assert_called_once_with(expected_result)

    @mock.patch('IronDefense.demisto')
    def test_update_analyst_ratings_command(self, mock_demisto):

        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = 'result'
        irondefense_module.IRON_DEFENSE.update_analyst_ratings.return_value = expected_result

        expected_alert_id = 'aaa-bbb-ccc'
        expected_comment = 'comment'
        expected_severity = 'some severity'
        expected_expectation = 'some expectation'

        def getArg_side_effect(arg):
            if arg == 'alert_id':
                return expected_alert_id
            if arg == 'comments':
                return expected_comment
            if arg == 'share_comment_with_irondome':
                return 'true'
            if arg == 'severity':
                return expected_severity
            if arg == 'expectation':
                return expected_expectation

        mock_demisto.getArg.side_effect = getArg_side_effect

        irondefense_module.update_analyst_ratings_command()
        irondefense_module.IRON_DEFENSE.update_analyst_ratings.assert_called_once_with(expected_alert_id,
                                                                                       severity=expected_severity,
                                                                                       expectation=expected_expectation,
                                                                                       comments=expected_comment,
                                                                                       share_irondome=True)
        mock_demisto.results.assert_called_once_with(expected_result)

    @mock.patch('IronDefense.demisto')
    def test_add_comment_to_alert_command(self, mock_demisto):

        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = 'result'
        irondefense_module.IRON_DEFENSE.add_comment_to_alert.return_value = expected_result

        expected_alert_id = 'aaa-bbb-ccc'
        expected_comment = 'comment'

        def getArg_side_effect(arg):
            if arg == 'alert_id':
                return expected_alert_id
            if arg == 'comment':
                return expected_comment
            if arg == 'share_comment_with_irondome':
                return 'true'

        mock_demisto.getArg.side_effect = getArg_side_effect

        irondefense_module.add_comment_to_alert_command()
        irondefense_module.IRON_DEFENSE.add_comment_to_alert.assert_called_once_with(expected_alert_id,
                                                                                     comment=expected_comment,
                                                                                     share_irondome=True)
        mock_demisto.results.assert_called_once_with(expected_result)

    @mock.patch('IronDefense.demisto')
    def test_set_alert_status_command(self, mock_demisto):

        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = 'result'
        irondefense_module.IRON_DEFENSE.set_alert_status.return_value = expected_result

        expected_alert_id = 'aaa-bbb-ccc'
        expected_comment = 'comment'
        expected_status = 'some status'

        def getArg_side_effect(arg):
            if arg == 'alert_id':
                return expected_alert_id
            if arg == 'comments':
                return expected_comment
            if arg == 'share_comment_with_irondome':
                return 'true'
            if arg == 'status':
                return expected_status

        mock_demisto.getArg.side_effect = getArg_side_effect

        irondefense_module.set_alert_status_command()
        irondefense_module.IRON_DEFENSE.set_alert_status.assert_called_once_with(expected_alert_id,
                                                                                 comments=expected_comment,
                                                                                 share_irondome=True,
                                                                                 status=expected_status)
        mock_demisto.results.assert_called_once_with(expected_result)

    @mock.patch('IronDefense.demisto')
    def test_report_observed_bad_activity_command(self, mock_demisto):

        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = 'result'
        irondefense_module.IRON_DEFENSE.report_observed_bad_activity.return_value = expected_result

        expected_name = 'some name'
        expected_description = 'some description'
        expected_ip = '1.1.1.1'
        expected_domain = 'bad.com'
        expected_activity_start_time = 'pickles'
        expected_activity_end_time = 'more pickles'

        def getArg_side_effect(arg):
            if arg == 'name':
                return expected_name
            if arg == 'description':
                return expected_description
            if arg == 'ip':
                return expected_ip
            if arg == 'domain':
                return expected_domain
            if arg == 'activity_start_time':
                return expected_activity_start_time
            if arg == 'activity_end_time':
                return expected_activity_end_time

        mock_demisto.getArg.side_effect = getArg_side_effect

        irondefense_module.report_observed_bad_activity_command()
        irondefense_module.IRON_DEFENSE.report_observed_bad_activity\
            .assert_called_once_with(expected_name,
                                     description=expected_description,
                                     ip=expected_ip,
                                     domain=expected_domain,
                                     activity_start_time=expected_activity_start_time,
                                     activity_end_time=expected_activity_end_time)
        mock_demisto.results.assert_called_once_with(expected_result)

    @mock.patch('IronDefense.demisto')
    def test_get_event_command(self, mock_demisto):

        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = 'result'
        irondefense_module.IRON_DEFENSE.get_event.return_value = expected_result

        expected_event_id = 'aaa-bbb-ccc'

        def getArg_side_effect(arg):
            if arg == 'event_id':
                return expected_event_id

        mock_demisto.getArg.side_effect = getArg_side_effect

        irondefense_module.get_event_command()
        irondefense_module.IRON_DEFENSE.get_event.assert_called_once_with(expected_event_id)
        mock_demisto.results.assert_called_once_with(expected_result)

    @mock.patch('IronDefense.demisto')
    def test_get_alerts_command(self, mock_demisto):

        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = 'result'
        irondefense_module.IRON_DEFENSE.get_alerts.return_value = expected_result

        expected_alert_id = 'aaa-bbb-ccc'
        expected_category = 'some_cat'
        expected_subcategory = 'some_cat'
        expected_status = 'some_status'
        expected_analyst_severity = 'some_analyst_severity'
        expected_analyst_expectation = 'some_analyst_expectation'
        expected_min_severity = 0
        expected_max_severity = 1000
        expected_min_created = 'date1'
        expected_max_created = 'date2'
        expected_min_updated = 'date3'
        expected_max_updated = 'date3'
        expected_min_first_event_created = 'date4'
        expected_max_first_event_created = 'date5'
        expected_min_last_event_created = 'date6'
        expected_max_last_event_created = 'date7'
        expected_min_first_event_start_time = 'date8'
        expected_max_first_event_start_time = 'date9'
        expected_min_last_event_end_time = 'date10'
        expected_max_last_event_end_time = 'date11'
        expected_analytic_version = 10
        expected_limit = 42
        expected_offset = 100
        expected_sort = 'some sort'

        def getArg_side_effect(arg):
            if arg == 'alert_id':
                return expected_alert_id
            if arg == 'category':
                return expected_category
            if arg == 'sub_category':
                return expected_subcategory
            if arg == 'status':
                return expected_status
            if arg == 'analyst_severity':
                return expected_analyst_severity
            if arg == 'analyst_expectation':
                return expected_analyst_expectation
            if arg == 'min_severity':
                return expected_min_severity
            if arg == 'max_severity':
                return expected_max_severity
            if arg == 'min_created':
                return expected_min_created
            if arg == 'max_created':
                return expected_max_created
            if arg == 'min_updated':
                return expected_min_updated
            if arg == 'max_updated':
                return expected_max_updated
            if arg == 'min_first_event_created':
                return expected_min_first_event_created
            if arg == 'max_first_event_created':
                return expected_max_first_event_created
            if arg == 'min_last_event_created':
                return expected_min_last_event_created
            if arg == 'max_last_event_created':
                return expected_max_last_event_created
            if arg == 'min_first_event_start_time':
                return expected_min_first_event_start_time
            if arg == 'max_first_event_start_time':
                return expected_max_first_event_start_time
            if arg == 'min_last_event_end_time':
                return expected_min_last_event_end_time
            if arg == 'max_last_event_end_time':
                return expected_max_last_event_end_time
            if arg == 'analytic_version':
                return expected_analytic_version
            if arg == 'limit':
                return expected_limit
            if arg == 'offset':
                return expected_offset
            if arg == 'sort':
                return expected_sort

        mock_demisto.getArg.side_effect = getArg_side_effect

        irondefense_module.get_alerts_command()
        irondefense_module.IRON_DEFENSE.get_alerts.assert_called_once_with(alert_id=expected_alert_id,
                                                                           category=expected_category,
                                                                           sub_category=expected_subcategory,
                                                                           status=expected_status,
                                                                           analyst_severity=expected_analyst_severity,
                                                                           analyst_expectation=expected_analyst_expectation,
                                                                           min_severity=expected_min_severity,
                                                                           max_severity=expected_max_severity,
                                                                           min_created=expected_min_created,
                                                                           max_created=expected_max_created,
                                                                           min_updated=expected_min_updated,
                                                                           max_updated=expected_max_updated,
                                                                           min_first_event_created=expected_min_first_event_created,
                                                                           max_first_event_created=expected_max_first_event_created,
                                                                           min_last_event_created=expected_min_last_event_created,
                                                                           max_last_event_created=expected_max_last_event_created,
                                                                           min_first_event_start_time=expected_min_first_event_start_time,
                                                                           max_first_event_start_time=expected_max_first_event_start_time,
                                                                           min_last_event_end_time=expected_min_last_event_end_time,
                                                                           max_last_event_end_time=expected_max_last_event_end_time,
                                                                           analytic_version=expected_analytic_version,
                                                                           limit=expected_limit,
                                                                           offset=expected_offset,
                                                                           sort=expected_sort)
        mock_demisto.results.assert_called_once_with(expected_result)


if __name__ == '__main__':
    unittest.main()
