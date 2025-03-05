import json
import unittest
import demistomock as demisto
import IronDefense as irondefense_module
from IronDefense import IronDefense, LOG_PREFIX
from unittest import TestCase, mock
from unittest.mock import Mock, call
import requests
from http.client import HTTPException

requests.packages.urllib3.disable_warnings()


class IronDefenseTest(TestCase):
    COOKIE_KEY = "some_cookie_key"

    # Create a mock logger so nothing gets written to stdout
    demisto_logger_patcher = mock.patch("IronDefense.XsoarLogger", autospec=True)
    MockXsoarLogger = demisto_logger_patcher.start()
    MockXsoarLogger.debug = lambda msg: None
    MockXsoarLogger.error = lambda msg: None

    session_patcher = mock.patch("requests.Session", autospec=True)
    MockSession = session_patcher.start()

    def setUp(self):
        self.host = "dev.rva.ironnet.io"
        self.url_prefix = "/IronApi"
        self.port = 6942
        self.credentials = {"identifier": "someusername", "password": "somepassword"}

        logger = self.MockXsoarLogger(demisto, LOG_PREFIX)
        self.mock_session = self.MockSession()
        self.mock_session.headers = {}
        # initialize the IronDefense object
        self.class_under_test = IronDefense(demisto, self.mock_session, self.host, self.port, self.credentials, logger)

    def tearDown(self):
        demisto.setIntegrationContext({})

    def test_get_jwt(self):
        test_jwt = "jwt token"
        test_context = {"JWT": test_jwt}
        assert test_jwt == self.class_under_test._get_jwt(test_context), "Unexpected result"
        assert None is self.class_under_test._get_jwt(None), "None context should return None"
        assert None is self.class_under_test._get_jwt({"bogus": "context"}), "Missing jwt in context should return None"

    def test_configure_session_auth(self):
        self.mock_session.headers = {}

        # test no jwt token
        self.class_under_test._configure_session_auth({})
        assert self.mock_session.headers.get("authentication", None) is None

        # test loading jwt token
        test_jwt = "jwt token"
        test_context = {"JWT": test_jwt}
        self.class_under_test._configure_session_auth(test_context)
        assert "Bearer " + test_jwt == self.mock_session.headers.get("Authorization")

    @mock.patch("requests.Response", autospec=True)
    def test_http_request(self, MockResponse):
        MockResponse.return_value.headers = {}
        method = "GET"
        uri = "/something"
        headers: dict[str, str] = {}
        data = "{}"
        params: dict[str, str] = {}
        files = None
        mock_jwt_value = "jwt token"
        expected_uri = f"https://{self.host}:{self.port}{self.url_prefix}{uri}"

        """Test successful response"""
        mock_response = MockResponse()
        mock_response.status_code = 200
        self.mock_session.request.return_value = mock_response

        test_response = self.class_under_test._http_request(method, uri)
        self.mock_session.request.assert_called_with(
            method,
            expected_uri,
            headers=headers,
            data=data,
            params=params,
            files=files,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )
        assert test_response == mock_response

        """Test incorrect creds"""
        mock_response = MockResponse()
        mock_response.status_code = 401
        self.mock_session.request.return_value = mock_response

        test_response = self.class_under_test._http_request(method, uri)
        self.mock_session.request.assert_called_with(
            method,
            expected_uri,
            headers=headers,
            data=data,
            params=params,
            files=files,
            timeout=self.class_under_test.request_timeout,
            auth=(self.credentials["identifier"], self.credentials["password"]),
            verify=False,
        )
        assert test_response == mock_response

        """Test expired jwt"""
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
                    side_effect_response.headers["auth-token"] = mock_jwt_value
                else:
                    side_effect_response.status_code = 401
                return side_effect_response

        self.mock_session.request.side_effect = RequestEffect().side_effect

        test_response = self.class_under_test._http_request(method, uri)

        self.mock_session.request.assert_has_calls(
            [
                mock.call(
                    method,
                    expected_uri,
                    headers=headers,
                    data=data,
                    params=params,
                    files=files,
                    timeout=self.class_under_test.request_timeout,
                    auth=None,
                    verify=False,
                ),
                mock.call(
                    method,
                    expected_uri,
                    headers=headers,
                    data=data,
                    params=params,
                    files=files,
                    timeout=self.class_under_test.request_timeout,
                    auth=(self.credentials["identifier"], self.credentials["password"]),
                    verify=False,
                ),
            ]
        )
        # check to see if the jwt was stored
        assert {"JWT": mock_jwt_value} == demisto.getIntegrationContext()
        assert test_response.status_code == 200, "Unexpected status code"
        assert self.mock_session.request.call_count == 2, "_http_request should have made 2 calls"

        """Test 5xx response"""
        self.mock_session.request.reset_mock()
        self.mock_session.request.side_effect = None

        mock_response = MockResponse()
        mock_response.status_code = 500
        mock_response.json.return_value = {"msg": "server error!"}
        self.mock_session.request.return_value = mock_response

        test_response = self.class_under_test._http_request(method, uri)
        self.mock_session.request.assert_called_with(
            method,
            expected_uri,
            headers=headers,
            data=data,
            params=params,
            files=files,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )
        assert test_response == mock_response

    @mock.patch("requests.Response", autospec=True)
    def test_test_module(self, MockResponse):
        MockResponse.return_value.headers = {}
        expected_uri = "https://{}:{}{}{}".format(self.host, self.port, self.url_prefix, "/Login")

        # test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response
        result = self.class_under_test.test_module()
        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data="{}",
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=(self.credentials["identifier"], self.credentials["password"]),
            verify=False,
        )
        assert result == "ok", 'Result should be "ok"'

        # test failed response
        error_json = {"msg": "Some error message"}
        error_msg = json.dumps(error_json)
        mock_response = MockResponse()
        mock_response.status_code = 500
        mock_response.text = error_msg
        mock_response.json.return_value = error_json
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response
        result = self.class_under_test.test_module()
        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data="{}",
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=(self.credentials["identifier"], self.credentials["password"]),
            verify=False,
        )
        assert result != "ok", "Result should have an error message"

    @mock.patch("requests.Response", autospec=True)
    def test_update_analyst_ratings(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = "test_alert_id"
        severity = "Malicious"
        expectation = "Unexpected"
        comments = "test comments"
        share_irondome = True

        expected_uri = "https://{}:{}{}{}".format(self.host, self.port, self.url_prefix, "/RateAlert")
        expected_body = json.dumps(
            {
                "alert_id": alert_id,
                "analyst_severity": "SEVERITY_MALICIOUS",
                "analyst_expectation": "EXP_UNEXPECTED",
                "comment": comments,
                "share_comment_with_irondome": share_irondome,
            }
        )

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        self.class_under_test.update_analyst_ratings(
            alert_id, severity=severity, expectation=expectation, comments=comments, share_irondome=share_irondome
        )

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.headers["auth-token"] = "some jwt token"
        mock_response.json.return_value = {"msg": "Some error"}
        self.mock_session.request.return_value = mock_response

        self.assertRaises(
            HTTPException,
            self.class_under_test.update_analyst_ratings,
            alert_id,
            severity=severity,
            expectation=expectation,
            comments=comments,
            share_irondome=share_irondome,
        )

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

    @mock.patch("requests.Response", autospec=True)
    def test_add_comment_to_alert(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = "test_alert_id"
        comment = "test comment"
        share_irondome = True

        expected_uri = "https://{}:{}{}{}".format(self.host, self.port, self.url_prefix, "/CommentOnAlert")
        expected_body = json.dumps({"alert_id": alert_id, "comment": comment, "share_comment_with_irondome": share_irondome})

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        self.class_under_test.add_comment_to_alert(alert_id, comment=comment, share_irondome=share_irondome)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.headers["auth-token"] = "some jwt token"
        mock_response.json.return_value = {"msg": "Some error"}
        self.mock_session.request.return_value = mock_response

        self.assertRaises(
            HTTPException, self.class_under_test.add_comment_to_alert, alert_id, comment=comment, share_irondome=share_irondome
        )

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

    @mock.patch("requests.Response", autospec=True)
    def test_set_alert_status(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = "test_alert_id"
        status = "Closed"
        comments = "test comments"
        share_irondome = True

        expected_uri = "https://{}:{}{}{}".format(self.host, self.port, self.url_prefix, "/SetAlertStatus")
        expected_body = json.dumps(
            {"alert_id": alert_id, "status": "STATUS_CLOSED", "comment": comments, "share_comment_with_irondome": share_irondome}
        )

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        self.class_under_test.set_alert_status(alert_id, status=status, comments=comments, share_irondome=share_irondome)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.headers["auth-token"] = "some jwt token"
        mock_response.json.return_value = {"msg": "Some error"}
        self.mock_session.request.return_value = mock_response

        self.assertRaises(
            HTTPException,
            self.class_under_test.set_alert_status,
            alert_id,
            status=status,
            comments=comments,
            share_irondome=share_irondome,
        )

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

    @mock.patch("requests.Response", autospec=True)
    def test_report_observed_bad_activity(self, MockResponse):
        MockResponse.return_value.headers = {}

        name = "test_name"
        description = "asdf"
        ip = "1.1.1.1"
        domain = "bad.com"
        activity_start_time = "2019-01-01T00:00:00Z"
        activity_end_time = "2019-02-01T00:00:00Z"

        expected_uri = "https://{}:{}{}{}".format(self.host, self.port, self.url_prefix, "/ReportObservedBadActivity")
        expected_body = json.dumps(
            {
                "name": name,
                "description": description,
                "ip": ip,
                "domain": domain,
                "activity_start_time": activity_start_time,
                "activity_end_time": activity_end_time,
            }
        )

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.ok = True
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        self.class_under_test.report_observed_bad_activity(
            name,
            description=description,
            ip=ip,
            domain=domain,
            activity_start_time=activity_start_time,
            activity_end_time=activity_end_time,
        )

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.ok = False
        mock_response.headers["auth-token"] = "some jwt token"
        mock_response.json.return_value = {"msg": "Some error"}
        self.mock_session.request.return_value = mock_response

        self.assertRaises(
            HTTPException,
            self.class_under_test.report_observed_bad_activity,
            name,
            description=description,
            ip=ip,
            domain=domain,
            activity_start_time=activity_start_time,
            activity_end_time=activity_end_time,
        )

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

    @mock.patch("requests.Response", autospec=True)
    def test_get_event(self, MockResponse):
        MockResponse.return_value.headers = {}

        event_id = "test_event_id"

        expected_uri = "https://{}:{}{}{}".format(self.host, self.port, self.url_prefix, "/GetEvent")
        expected_body = json.dumps(
            {
                "event_id": event_id,
            }
        )

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        self.class_under_test.get_event(event_id)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.headers["auth-token"] = "some jwt token"
        mock_response.json.return_value = {"msg": "Some error"}
        self.mock_session.request.return_value = mock_response
        self.assertRaises(HTTPException, self.class_under_test.get_event, event_id)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

    @mock.patch("requests.Response", autospec=True)
    def test_get_events(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = "test_alert_id"

        expected_uri = "https://{}:{}{}{}".format(self.host, self.port, self.url_prefix, "/GetEvents")
        expected_body = json.dumps({"alert_id": "test_alert_id", "constraint": {"limit": 10, "offset": 1}})

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        self.class_under_test.get_events(alert_id=alert_id, limit=10, offset=1)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.headers["auth-token"] = "some jwt token"
        mock_response.json.return_value = {"msg": "Some error"}
        self.mock_session.request.return_value = mock_response
        self.assertRaises(HTTPException, self.class_under_test.get_events, alert_id, limit=10, offset=1)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

    @mock.patch("requests.Response", autospec=True)
    def test_get_alerts(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = ["test_alert_id"]
        category = ["TEST_CATEGORY"]
        sub_category = ["TEST_CATEGORY"]
        status = ["TEST_STATUS"]
        analyst_severity = ["TEST_ANALYST_SEVERITY"]
        analyst_expectation = ["TEST_ANALYST_EXPECTATION"]
        severity = {"lower_bound": 0, "upper_bound": 2}
        created = {"start": "2019-01-01T00:00:00Z", "end": "2020-01-01T00:00:00Z"}
        updated = {"start": "2019-02-01T00:00:00Z", "end": "2020-02-01T00:00:00Z"}
        first_event_created = {"start": "2019-02-01T00:00:00Z", "end": "2020-02-01T00:00:00Z"}
        last_event_created = {"start": "2019-02-01T00:00:00Z", "end": "2020-02-01T00:00:00Z"}
        first_event_start_time = {"start": "2019-02-01T00:00:00Z", "end": "2020-02-01T00:00:00Z"}
        last_event_end_time = {"start": "2019-02-01T00:00:00Z", "end": "2020-02-01T00:00:00Z"}
        analytic_version = ["1"]
        constraint = {"limit": 10, "offset": 0}
        sort = [{"field": "ASF_UPDATED", "direction": "SD_ASCENDING"}]

        expected_uri = "https://{}:{}{}{}".format(self.host, self.port, self.url_prefix, "/GetAlerts")
        expected_body = json.dumps(
            {
                "alert_id": alert_id,
                "category": category,
                "sub_category": sub_category,
                "status": ["STATUS_" + status[0]],
                "analyst_severity": ["SEVERITY_" + analyst_severity[0]],
                "analyst_expectation": ["EXP_" + analyst_expectation[0]],
                "analytic_version": analytic_version,
                "sort": sort,
                "severity": severity,
                "created": created,
                "updated": updated,
                "first_event_created": first_event_created,
                "last_event_created": last_event_created,
                "first_event_start_time": first_event_start_time,
                "last_event_end_time": last_event_end_time,
                "constraint": constraint,
            }
        )

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.ok = True
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        self.class_under_test.get_alerts(
            alert_id=alert_id[0],
            category=category[0],
            sub_category=sub_category[0],
            status=status[0],
            analyst_severity=analyst_severity[0],
            analyst_expectation=analyst_expectation[0],
            min_severity=severity["lower_bound"],
            max_severity=severity["upper_bound"],
            min_created=created["start"],
            max_created=created["end"],
            min_updated=updated["start"],
            max_updated=updated["end"],
            min_first_event_created=first_event_created["start"],
            max_first_event_created=first_event_created["end"],
            min_last_event_created=last_event_created["start"],
            max_last_event_created=last_event_created["end"],
            min_first_event_start_time=first_event_start_time["start"],
            max_first_event_start_time=first_event_start_time["end"],
            min_last_event_end_time=last_event_end_time["start"],
            max_last_event_end_time=last_event_end_time["end"],
            analytic_version=analytic_version[0],
            limit=constraint["limit"],
            offset=constraint["offset"],
            sort=sort,
        )

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.ok = False
        mock_response.headers["auth-token"] = "some jwt token"
        mock_response.json.return_value = {"msg": "Some error"}
        self.mock_session.request.return_value = mock_response

        self.assertRaises(
            HTTPException,
            self.class_under_test.get_alerts,
            alert_id=alert_id[0],
            category=category[0],
            sub_category=sub_category[0],
            status=status[0],
            analyst_severity=analyst_severity[0],
            analyst_expectation=analyst_expectation[0],
            min_severity=severity["lower_bound"],
            max_severity=severity["upper_bound"],
            min_created=created["start"],
            max_created=created["end"],
            min_updated=updated["start"],
            max_updated=updated["end"],
            min_first_event_created=first_event_created["start"],
            max_first_event_created=first_event_created["end"],
            min_last_event_created=last_event_created["start"],
            max_last_event_created=last_event_created["end"],
            min_first_event_start_time=first_event_start_time["start"],
            max_first_event_start_time=first_event_start_time["end"],
            min_last_event_end_time=last_event_end_time["start"],
            max_last_event_end_time=last_event_end_time["end"],
            analytic_version=analytic_version[0],
            limit=constraint["limit"],
            offset=constraint["offset"],
            sort=sort,
        )

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

    # Mock Json Data for fetch_alert_incidents tests
    def mock_fetch_alert_incidents_data(self):
        data = {
            "alert_notifications": [
                {
                    "alert_action": "ANA_ALERT_CREATED",
                    "alert": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC1",
                        "severity": 700,
                    },
                },
                {
                    "alert_action": "ANA_ALERT_CREATED",
                    "alert": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC1",
                        "severity": 400,
                    },
                },
                {
                    "alert_action": "ANA_A1",
                    "alert": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC1",
                        "severity": 700,
                    },
                },
                {
                    "alert_action": "ANA_A2",
                    "alert": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC1",
                        "severity": 700,
                    },
                },
                {
                    "alert_action": "ANA_A3",
                    "alert": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC1",
                        "severity": 700,
                    },
                },
                {
                    "alert_action": "ANA_ALERT_CREATED",
                    "alert": {
                        "category": "C2",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC2",
                        "severity": 600,
                    },
                },
                {
                    "alert_action": "ANA_ALERT_CREATED",
                    "alert": {
                        "category": "XC1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC2",
                        "severity": 600,
                    },
                },
                {
                    "alert_action": "ANA_ALERT_CREATED",
                    "alert": {
                        "category": "XC2",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC2",
                        "severity": 600,
                    },
                },
                {
                    "alert_action": "ANA_ALERT_CREATED",
                    "alert": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "XSC1",
                        "severity": 600,
                    },
                },
                {
                    "alert_action": "ANA_ALERT_CREATED",
                    "alert": {
                        "category": "C2",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "XSC2",
                        "severity": 600,
                    },
                },
            ]
        }
        return data

    # Test successful/unsuccessful responses for fetch_alert_incidents()
    @mock.patch("requests.Response", autospec=True)
    def test_fetch_alert_incidents(self, MockResponse):
        MockResponse.return_value.headers = {}

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_fetch_alert_incidents_data()
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        alert_limit = 50

        expected_uri = "https://{}:{}{}{}".format(self.host, self.port, self.url_prefix, "/GetAlertNotifications")
        expected_body = json.dumps(
            {
                "limit": alert_limit,
            }
        )

        # Run test
        self.class_under_test.fetch_alert_incidents(alert_limit=alert_limit)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.headers["auth-token"] = "some jwt token"
        mock_response.json.return_value = {"msg": "Some error"}
        self.mock_session.request.return_value = mock_response

        # Run test
        self.assertRaises(Exception, self.class_under_test.fetch_alert_incidents, alert_limit)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

    # Test filtering from inputs on Alert Notifications
    @mock.patch("requests.Response", autospec=True)
    def test_fetch_alert_incidents_filtering(self, MockResponse):
        MockResponse.return_value.headers = {}

        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_fetch_alert_incidents_data()
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        # Input params for filtering
        excluded_categories = ["xc1", "xc2"]
        excluded_subcats = "xsc1,xsc2"
        severity_threshold = 500
        included_alert_actions = ["Alert Created", "A1", "A2"]
        alert_limit = 50

        # Define expectations
        expected_resp_data = [
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 700,'
            + ' "type": "alert"}',
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 700,'
            + ' "type": "alert"}',
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 700,'
            + ' "type": "alert"}',
            '{"category": "C2", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC2", "severity": 600,'
            + ' "type": "alert"}',
        ]

        # Run test
        init_result = self.class_under_test.fetch_alert_incidents(
            alert_categories=excluded_categories,
            alert_subcategories=excluded_subcats,
            alert_severity_lower=severity_threshold,
            alert_severity_upper=None,
            alert_limit=alert_limit,
            alert_actions=included_alert_actions,
        )

        result = [init_result[0]["rawJSON"], init_result[1]["rawJSON"], init_result[2]["rawJSON"], init_result[3]["rawJSON"]]

        assert expected_resp_data == result

    # Test default filtering on Alert Notifications
    @mock.patch("requests.Response", autospec=True)
    def test_fetch_alert_incidents_action_default(self, MockResponse):
        MockResponse.return_value.headers = {}

        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_fetch_alert_incidents_data()
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        # Input params for filtering
        excluded_categories = None
        excluded_subcats = None
        severity_threshold = None
        included_alert_actions = None
        alert_limit = 50

        # Define Expectations
        expected_resp_data = [
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 700,'
            + ' "type": "alert"}',
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 400,'
            + ' "type": "alert"}',
            '{"category": "C2", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC2", "severity": 600,'
            + ' "type": "alert"}',
            '{"category": "XC1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC2", "severity": 600,'
            + ' "type": "alert"}',
            '{"category": "XC2", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC2", "severity": 600,'
            + ' "type": "alert"}',
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "XSC1", "severity": 600,'
            + ' "type": "alert"}',
            '{"category": "C2", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "XSC2", "severity": 600,'
            + ' "type": "alert"}',
        ]

        # Run test
        init_result = self.class_under_test.fetch_alert_incidents(
            alert_categories=excluded_categories,
            alert_subcategories=excluded_subcats,
            alert_severity_lower=severity_threshold,
            alert_severity_upper=None,
            alert_limit=alert_limit,
            alert_actions=included_alert_actions,
        )

        result = [
            init_result[0]["rawJSON"],
            init_result[1]["rawJSON"],
            init_result[2]["rawJSON"],
            init_result[3]["rawJSON"],
            init_result[4]["rawJSON"],
            init_result[5]["rawJSON"],
            init_result[6]["rawJSON"],
        ]

        assert expected_resp_data == result

    # Mock Json Data for fetch_event_incidents()
    def mock_fetch_event_incidents_data(self):
        data = {
            "event_notifications": [
                {
                    "event_action": "ENA_EVENT_CREATED",
                    "event": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC1",
                        "severity": 700,
                    },
                },
                {
                    "event_action": "ENA_EVENT_CREATED",
                    "event": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC1",
                        "severity": 400,
                    },
                },
                {
                    "event_action": "ENA_A1",
                    "event": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC1",
                        "severity": 700,
                    },
                },
                {
                    "event_action": "ENA_A2",
                    "event": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC1",
                        "severity": 700,
                    },
                },
                {
                    "event_action": "ENA_A3",
                    "event": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC1",
                        "severity": 700,
                    },
                },
                {
                    "event_action": "ENA_EVENT_CREATED",
                    "event": {
                        "category": "C2",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC2",
                        "severity": 600,
                    },
                },
                {
                    "event_action": "ENA_EVENT_CREATED",
                    "event": {
                        "category": "XC1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC2",
                        "severity": 600,
                    },
                },
                {
                    "event_action": "ENA_EVENT_CREATED",
                    "event": {
                        "category": "XC2",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "SC2",
                        "severity": 600,
                    },
                },
                {
                    "event_action": "ENA_EVENT_CREATED",
                    "event": {
                        "category": "C1",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "XSC1",
                        "severity": 600,
                    },
                },
                {
                    "event_action": "ENA_EVENT_CREATED",
                    "event": {
                        "category": "C2",
                        "updated": "2020-04-09T04:29:10.471378Z",
                        "sub_category": "XSC2",
                        "severity": 600,
                    },
                },
            ]
        }
        return data

    # Test successful/unsuccessful responses for fetch_event_incidents()
    @mock.patch("requests.Response", autospec=True)
    def test_fetch_event_incidents(self, MockResponse):
        MockResponse.return_value.headers = {}

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_fetch_event_incidents_data()
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        event_limit = 50

        expected_uri = "https://{}:{}{}{}".format(self.host, self.port, self.url_prefix, "/GetEventNotifications")
        expected_body = json.dumps(
            {
                "limit": event_limit,
            }
        )

        # Run test
        self.class_under_test.fetch_event_incidents(event_limit=event_limit)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.headers["auth-token"] = "some jwt token"
        mock_response.json.return_value = {"msg": "Some error"}
        self.mock_session.request.return_value = mock_response

        # Run test
        self.assertRaises(Exception, self.class_under_test.fetch_event_incidents, event_limit)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

    # Test filtering from inputs on Event Notifications
    @mock.patch("requests.Response", autospec=True)
    def test_fetch_event_incidents_filtering(self, MockResponse):
        MockResponse.return_value.headers = {}

        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_fetch_event_incidents_data()
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        # Input params for filtering
        excluded_categories = ["xc1", "xc2"]
        excluded_subcats = "xsc1,xsc2"
        severity_threshold = 500
        included_event_actions = ["Event Created", "A1", "A2"]
        event_limit = 50

        # Define expectations
        expected_resp_data = [
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 700,'
            + ' "type": "event"}',
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 700,'
            + ' "type": "event"}',
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 700,'
            + ' "type": "event"}',
            '{"category": "C2", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC2", "severity": 600,'
            + ' "type": "event"}',
        ]

        # Run test
        init_result = self.class_under_test.fetch_event_incidents(
            event_categories=excluded_categories,
            event_subcategories=excluded_subcats,
            event_severity_lower=severity_threshold,
            event_severity_upper=None,
            event_limit=event_limit,
            event_actions=included_event_actions,
        )

        result = [init_result[0]["rawJSON"], init_result[1]["rawJSON"], init_result[2]["rawJSON"], init_result[3]["rawJSON"]]

        assert expected_resp_data == result

    # Test default filtering on Event Notifications
    @mock.patch("requests.Response", autospec=True)
    def test_fetch_event_incidents_action_default(self, MockResponse):
        MockResponse.return_value.headers = {}

        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_fetch_event_incidents_data()
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        # Input params for filtering
        excluded_categories = None
        excluded_subcats = None
        severity_threshold = None
        included_event_actions = None
        event_limit = 50

        # Define Expectations
        expected_resp_data = [
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 700,'
            + ' "type": "event"}',
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 400,'
            + ' "type": "event"}',
            '{"category": "C2", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC2", "severity": 600,'
            + ' "type": "event"}',
            '{"category": "XC1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC2", "severity": 600,'
            + ' "type": "event"}',
            '{"category": "XC2", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC2", "severity": 600,'
            + ' "type": "event"}',
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "XSC1", "severity": 600,'
            + ' "type": "event"}',
            '{"category": "C2", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "XSC2", "severity": 600,'
            + ' "type": "event"}',
        ]

        # Run test
        init_result = self.class_under_test.fetch_event_incidents(
            event_categories=excluded_categories,
            event_subcategories=excluded_subcats,
            event_severity_lower=severity_threshold,
            event_severity_upper=None,
            event_limit=event_limit,
            event_actions=included_event_actions,
        )

        result = [
            init_result[0]["rawJSON"],
            init_result[1]["rawJSON"],
            init_result[2]["rawJSON"],
            init_result[3]["rawJSON"],
            init_result[4]["rawJSON"],
            init_result[5]["rawJSON"],
            init_result[6]["rawJSON"],
        ]

        assert expected_resp_data == result

    @mock.patch("requests.Response", autospec=True)
    def test_get_alert_irondome_information(self, MockResponse):
        MockResponse.return_value.headers = {}

        alert_id = "test_alert_id"

        expected_uri = "https://{}:{}{}{}".format(self.host, self.port, self.url_prefix, "/GetAlertIronDomeInformation")
        expected_body = json.dumps(
            {
                "alert_id": alert_id,
            }
        )

        # Test successful response
        mock_response = MockResponse()
        mock_response.status_code = 200
        mock_response.headers["auth-token"] = "some jwt token"
        self.mock_session.request.return_value = mock_response

        self.class_under_test.get_alert_irondome_information(alert_id)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

        # Test failed response
        mock_response = MockResponse()
        mock_response.status_code = 403
        mock_response.headers["auth-token"] = "some jwt token"
        mock_response.json.return_value = {"msg": "Some error"}
        self.mock_session.request.return_value = mock_response

        self.assertRaises(HTTPException, self.class_under_test.get_alert_irondome_information, alert_id)

        self.mock_session.request.assert_called_with(
            "POST",
            expected_uri,
            headers={},
            data=expected_body,
            params={},
            files=None,
            timeout=self.class_under_test.request_timeout,
            auth=None,
            verify=False,
        )

    @mock.patch("requests.Response", autospec=True)
    def test_get_error_msg_from_response(self, MockResponse):
        expected_error_msg = "Some error message"
        mock_response = MockResponse()
        error_json = {"msg": expected_error_msg}

        mock_response.json.return_value = error_json
        error_msg = self.class_under_test._get_error_msg_from_response(mock_response)
        assert expected_error_msg == error_msg, "Error message was not properly extracted"

        mock_response.json.return_value = {}
        mock_response.text = expected_error_msg
        error_msg = self.class_under_test._get_error_msg_from_response(mock_response)
        assert expected_error_msg == error_msg, "Error message was not properly extracted"

    @mock.patch("IronDefense.demisto")
    def test_test_module_command(self, mock_demisto):
        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = "result"
        irondefense_module.IRON_DEFENSE.test_module.return_value = expected_result

        irondefense_module.test_module_command()
        irondefense_module.IRON_DEFENSE.test_module.assert_called_once()
        mock_demisto.results.assert_called_once_with(expected_result)

    @mock.patch("IronDefense.demisto")
    def test_update_analyst_ratings_command(self, mock_demisto):
        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = "result"
        irondefense_module.IRON_DEFENSE.update_analyst_ratings.return_value = expected_result

        expected_alert_id = "aaa-bbb-ccc"
        expected_comment = "comment"
        expected_severity = "some severity"
        expected_expectation = "some expectation"

        def getArg_side_effect(arg):
            if arg == "alert_id":
                return expected_alert_id
            if arg == "comments":
                return expected_comment
            if arg == "share_comment_with_irondome":
                return "true"
            if arg == "severity":
                return expected_severity
            if arg == "expectation":
                return expected_expectation
            return None

        mock_demisto.getArg.side_effect = getArg_side_effect

        irondefense_module.update_analyst_ratings_command()
        irondefense_module.IRON_DEFENSE.update_analyst_ratings.assert_called_once_with(
            expected_alert_id,
            severity=expected_severity,
            expectation=expected_expectation,
            comments=expected_comment,
            share_irondome=True,
        )
        mock_demisto.results.assert_called_once_with(expected_result)

    @mock.patch("IronDefense.demisto")
    def test_add_comment_to_alert_command(self, mock_demisto):
        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = "result"
        irondefense_module.IRON_DEFENSE.add_comment_to_alert.return_value = expected_result

        expected_alert_id = "aaa-bbb-ccc"
        expected_comment = "comment"

        def getArg_side_effect(arg):
            if arg == "alert_id":
                return expected_alert_id
            if arg == "comment":
                return expected_comment
            if arg == "share_comment_with_irondome":
                return "true"
            return None

        mock_demisto.getArg.side_effect = getArg_side_effect

        irondefense_module.add_comment_to_alert_command()
        irondefense_module.IRON_DEFENSE.add_comment_to_alert.assert_called_once_with(
            expected_alert_id, comment=expected_comment, share_irondome=True
        )
        mock_demisto.results.assert_called_once_with(expected_result)

    @mock.patch("IronDefense.demisto")
    def test_set_alert_status_command(self, mock_demisto):
        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = "result"
        irondefense_module.IRON_DEFENSE.set_alert_status.return_value = expected_result

        expected_alert_id = "aaa-bbb-ccc"
        expected_comment = "comment"
        expected_status = "some status"

        def getArg_side_effect(arg):
            if arg == "alert_id":
                return expected_alert_id
            if arg == "comments":
                return expected_comment
            if arg == "share_comment_with_irondome":
                return "true"
            if arg == "status":
                return expected_status
            return None

        mock_demisto.getArg.side_effect = getArg_side_effect

        irondefense_module.set_alert_status_command()
        irondefense_module.IRON_DEFENSE.set_alert_status.assert_called_once_with(
            expected_alert_id, comments=expected_comment, share_irondome=True, status=expected_status
        )
        mock_demisto.results.assert_called_once_with(expected_result)

    @mock.patch("IronDefense.demisto")
    def test_report_observed_bad_activity_command(self, mock_demisto):
        irondefense_module.IRON_DEFENSE = Mock()
        expected_result = "result"
        irondefense_module.IRON_DEFENSE.report_observed_bad_activity.return_value = expected_result

        expected_name = "some name"
        expected_description = "some description"
        expected_ip = "1.1.1.1"
        expected_domain = "bad.com"
        expected_activity_start_time = "pickles"
        expected_activity_end_time = "more pickles"

        def getArg_side_effect(arg):
            if arg == "name":
                return expected_name
            if arg == "description":
                return expected_description
            if arg == "ip":
                return expected_ip
            if arg == "domain":
                return expected_domain
            if arg == "activity_start_time":
                return expected_activity_start_time
            if arg == "activity_end_time":
                return expected_activity_end_time
            return None

        mock_demisto.getArg.side_effect = getArg_side_effect

        irondefense_module.report_observed_bad_activity_command()
        irondefense_module.IRON_DEFENSE.report_observed_bad_activity.assert_called_once_with(
            expected_name,
            description=expected_description,
            ip=expected_ip,
            domain=expected_domain,
            activity_start_time=expected_activity_start_time,
            activity_end_time=expected_activity_end_time,
        )
        mock_demisto.results.assert_called_once_with(expected_result)

    @mock.patch("IronDefense.demisto")
    def test_fetch_incidents_command(self, mock_demisto):
        irondefense_module.IRON_DEFENSE = Mock()
        irondefense_module.LOGGER = self.MockXsoarLogger(demisto, LOG_PREFIX)
        expected_result = [
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 700}',
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 700}',
            '{"category": "C1", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC1", "severity": 700}',
            '{"category": "C2", "updated": "2020-04-09T04:29:10.471378Z", "sub_category": "SC2", "severity": 600}',
        ]
        irondefense_module.IRON_DEFENSE.fetch_alert_incidents.return_value = expected_result

        # Notification related params
        irondefense_module.PARAMS = {
            "domeCategories": None,
            "domeLimit": 500,
            "enableDomeNotifications": False,
            "alertCategories": None,
            "alertSubCategories": None,
            "alertSeverityLower": None,
            "alertSeverityUpper": None,
            "alertLimit": 500,
            "alertActions": None,
            "enableAlertNotifications": True,
            "eventCategories": None,
            "eventSubCategories": None,
            "eventSeverityLower": None,
            "eventSeverityUpper": None,
            "eventLimit": 500,
            "eventActions": None,
            "enableEventNotifications": False,
        }

        expected_alert_categories = irondefense_module.PARAMS.get("alertCategories", None)
        expected_alert_subcategories = irondefense_module.PARAMS.get("alertSubCategories", None)
        expected_alert_severity_lower = irondefense_module.PARAMS.get("alertSeverityLower", None)
        expected_alert_severity_upper = irondefense_module.PARAMS.get("alertSeverityUpper", None)
        expected_alert_limit = int(irondefense_module.PARAMS.get("alertLimit", 500))
        expected_alert_actions = irondefense_module.PARAMS.get("alertActions", None)

        irondefense_module.fetch_incidents_command()
        irondefense_module.IRON_DEFENSE.fetch_alert_incidents.assert_called_once_with(
            expected_alert_categories,
            expected_alert_subcategories,
            expected_alert_severity_lower,
            expected_alert_severity_upper,
            expected_alert_limit,
            expected_alert_actions,
        )
        mock_demisto.incidents.assert_called_once_with(expected_result)

    @mock.patch("IronDefense.demisto")
    def test_get_event_command(self, mock_demisto):
        # Expectations
        expected_event = {
            "id": "abc",
            "category": "cat",
            "sub_category": "subcat",
        }

        with open("./test-data/event-context-table.json") as event_context_table_file:
            json_data = event_context_table_file.read()
            enterprise_ips_table = json.loads(json_data)

        with open("./test-data/event-context-key-value-table.json") as event_context_table_file:
            json_data = event_context_table_file.read()
            summary_table = json.loads(json_data)

        expected_context = [summary_table, enterprise_ips_table]
        expected_enterprise_ips = [
            {
                "ip": "1.1.1.1",
                "classification": "CLASSIFICATION_ENTERPRISE",
            },
            {
                "ip": "2.2.2.2",
                "classification": "CLASSIFICATION_ENTERPRISE_2",
            },
        ]
        expected_summary_table = {
            "session_size": "1069918",
            "threshold_entity_time": "2020-04-11T09:00:00.000Z",
            "producer_to_consumer_ratio": "1.977250634801539",
            "threshold_size": "1020401",
        }
        expected_return_outputs_calls = [
            call(
                readable_output="### IronDefense Event: cat - subcat\n"
                "link\n"
                "|category|id|sub_category|\n"
                "|---|---|---|\n"
                "| cat | abc | subcat |\n",
                outputs={
                    "IronDefense.Event(val.id == obj.id)": expected_event,
                },
                raw_response=expected_event,
            ),
            call(
                readable_output="### Event Context: enterprise_ips\n"
                "|ip|classification|\n"
                "|---|---|\n"
                "| 1.1.1.1 | CLASSIFICATION_ENTERPRISE |\n"
                "| 2.2.2.2 | CLASSIFICATION_ENTERPRISE_2 |\n",
                outputs={
                    "IronDefense.Event.Context(val.name == obj.name)": enterprise_ips_table,
                },
                raw_response=enterprise_ips_table,
            ),
            call(
                readable_output="### Event Context: summary\n"
                "|producer_to_consumer_ratio|session_size|threshold_entity_time|threshold_size|\n"
                "|---|---|---|---|\n"
                "| 1.977250634801539 | 1069918 | 2020-04-11T09:00:00.000Z | 1020401 |\n",
                outputs={
                    "IronDefense.Event.Context(val.name == obj.name)": summary_table,
                },
                raw_response=summary_table,
            ),
        ]
        expected_event_id = "aaa-bbb-ccc"

        # Set up mocks
        irondefense_module.IRON_DEFENSE = Mock()
        get_event_result = {
            "event": expected_event,
            "context": expected_context,
        }
        irondefense_module.IRON_DEFENSE.get_event.return_value = get_event_result
        irondefense_module.IRON_DEFENSE.create_markdown_link.return_value = "link"

        def getArg_side_effect(arg):
            if arg == "event_id":
                return expected_event_id
            return None

        def event_context_table_contains_multi_columns_side_effect(table):
            return table.get("name") == "enterprise_ips"

        mock_demisto.getArg.side_effect = getArg_side_effect
        irondefense_module.IRON_DEFENSE.event_context_table_contains_multi_columns.side_effect = (
            event_context_table_contains_multi_columns_side_effect
        )
        irondefense_module.IRON_DEFENSE.event_context_table_to_dict_list.return_value = expected_enterprise_ips
        irondefense_module.IRON_DEFENSE.event_context_table_to_dict.return_value = expected_summary_table
        irondefense_module.return_outputs = Mock()

        # Execute
        irondefense_module.get_event_command()

        # Assert
        irondefense_module.IRON_DEFENSE.get_event.assert_called_once_with(expected_event_id)
        irondefense_module.return_outputs.assert_has_calls(expected_return_outputs_calls, any_order=True)

    @mock.patch("IronDefense.return_outputs")
    @mock.patch("IronDefense.demisto")
    def test_get_events_command(self, demisto_mock, return_outputs_mock):
        # Expectations
        expected_alert_id = "abc"
        expected_limit = 42
        expected_offset = 4242
        expected_total = 5000
        expected_event_1 = {"id": "123", "category": "cat1", "sub_category": "subcat1"}
        expected_event_2 = {"id": "456", "category": "cat2", "sub_category": "subcat2"}
        expected_calls = [
            call(
                readable_output="### IronDefense Event 4243/5000\n"
                "link\n"
                "|category|id|sub_category|\n"
                "|---|---|---|\n"
                "| cat1 | 123 | subcat1 |\n",
                outputs={
                    "IronDefense.Event(val.id == obj.id)": expected_event_1,
                },
                raw_response=expected_event_1,
            ),
            call(
                readable_output="### IronDefense Event 4244/5000\n"
                "link\n"
                "|category|id|sub_category|\n"
                "|---|---|---|\n"
                "| cat2 | 456 | subcat2 |\n",
                outputs={
                    "IronDefense.Event(val.id == obj.id)": expected_event_2,
                },
                raw_response=expected_event_2,
            ),
        ]

        # Setup mocks
        def getArg_side_effect(arg_name):
            if arg_name == "alert_id":
                return expected_alert_id
            elif arg_name == "limit":
                return expected_limit
            elif arg_name == "offset":
                return expected_offset
            else:
                return None

        demisto_mock.getArg.side_effect = getArg_side_effect
        irondefense_module.IRON_DEFENSE = Mock()
        irondefense_module.IRON_DEFENSE.get_events.return_value = {
            "events": [expected_event_1, expected_event_2],
            "constraint": {"total": expected_total, "offset": expected_offset, "limit": expected_limit},
        }
        irondefense_module.IRON_DEFENSE.create_markdown_link.return_value = "link"

        # Execute test
        irondefense_module.get_events_command()

        # Assert results
        irondefense_module.IRON_DEFENSE.get_events.assert_called_with(
            alert_id=expected_alert_id, limit=expected_limit, offset=expected_offset
        )
        return_outputs_mock.assert_has_calls(expected_calls, any_order=True)

    @mock.patch("IronDefense.return_outputs")
    @mock.patch("IronDefense.demisto")
    def test_get_alerts_command(self, demisto_mock, return_outputs_mock):
        # Expectations
        expected_alert_id = "a"
        expected_category = "b"
        expected_sub_category = "c"
        expected_status = "d"
        expected_analyst_severity = "x"
        expected_analyst_expectation = "e"
        expected_min_severity = "f"
        expected_max_severity = "g"
        expected_min_created = "h"
        expected_max_created = "i"
        expected_min_updated = "j"
        expected_max_updated = "k"
        expected_min_first_event_created = "l"
        expected_max_first_event_created = "m"
        expected_min_last_event_created = "n"
        expected_max_last_event_created = "o"
        expected_min_first_event_start_time = "p"
        expected_max_first_event_start_time = "q"
        expected_min_last_event_end_time = "r"
        expected_max_last_event_end_time = "s"
        expected_analytic_version = "t"
        expected_limit = "u"
        expected_offset = "v"
        expected_sort = "w"

        expected_alert_1 = {"id": "123", "category": "cat1", "sub_category": "subcat1"}
        expected_alert_2 = {"id": "456", "category": "cat2", "sub_category": "subcat2"}
        expected_constraint = {
            "limit": 4242,
            "offset": 10,
            "total": 42,
        }
        expected_calls = [
            call(
                readable_output="### IronDefense Alert 11/42: cat1 - subcat1\n"
                "link\n"
                "|category|id|sub_category|\n"
                "|---|---|---|\n"
                "| cat1 | 123 | subcat1 |\n",
                outputs={
                    "IronDefense.Alert(val.id == obj.id)": expected_alert_1,
                },
                raw_response=expected_alert_1,
            ),
            call(
                readable_output="### IronDefense Alert 12/42: cat2 - subcat2\n"
                "link\n"
                "|category|id|sub_category|\n"
                "|---|---|---|\n"
                "| cat2 | 456 | subcat2 |\n",
                outputs={
                    "IronDefense.Alert(val.id == obj.id)": expected_alert_2,
                },
                raw_response=expected_alert_2,
            ),
            call(
                readable_output="### Query Constraints\n|limit|offset|total|\n|---|---|---|\n| 4242 | 10 | 42 |\n",
                outputs={
                    "IronDefense.Query.GetAlerts": expected_constraint,
                },
                raw_response=expected_constraint,
            ),
        ]

        # Setup mocks
        def getArg_side_effect(arg_name):
            arg_dict = {
                "alert_id": expected_alert_id,
                "category": expected_category,
                "sub_category": expected_sub_category,
                "status": expected_status,
                "analyst_severity": expected_analyst_severity,
                "analyst_expectation": expected_analyst_expectation,
                "min_severity": expected_min_severity,
                "max_severity": expected_max_severity,
                "min_created": expected_min_created,
                "max_created": expected_max_created,
                "min_updated": expected_min_updated,
                "max_updated": expected_max_updated,
                "min_first_event_created": expected_min_first_event_created,
                "max_first_event_created": expected_max_first_event_created,
                "min_last_event_created": expected_min_last_event_created,
                "max_last_event_created": expected_max_last_event_created,
                "min_first_event_start_time": expected_min_first_event_start_time,
                "max_first_event_start_time": expected_max_first_event_start_time,
                "min_last_event_end_time": expected_min_last_event_end_time,
                "max_last_event_end_time": expected_max_last_event_end_time,
                "analytic_version": expected_analytic_version,
                "limit": expected_limit,
                "offset": expected_offset,
                "sort": expected_sort,
            }
            return arg_dict[arg_name]

        demisto_mock.getArg.side_effect = getArg_side_effect
        irondefense_module.IRON_DEFENSE = Mock()
        irondefense_module.IRON_DEFENSE.get_alerts.return_value = {
            "alerts": [expected_alert_1, expected_alert_2],
            "constraint": expected_constraint,
        }
        irondefense_module.IRON_DEFENSE.create_markdown_link.return_value = "link"

        # Execute test
        irondefense_module.get_alerts_command()

        # Assert results
        irondefense_module.IRON_DEFENSE.get_alerts.assert_called_with(
            alert_id=expected_alert_id,
            category=expected_category,
            sub_category=expected_sub_category,
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
            min_first_event_start_time=(expected_min_first_event_start_time),
            max_first_event_start_time=(expected_max_first_event_start_time),
            min_last_event_end_time=expected_min_last_event_end_time,
            max_last_event_end_time=expected_max_last_event_end_time,
            analytic_version=expected_analytic_version,
            limit=expected_limit,
            offset=expected_offset,
            sort=expected_sort,
        )
        return_outputs_mock.assert_has_calls(expected_calls, any_order=True)

    @mock.patch("IronDefense.return_outputs")
    @mock.patch("IronDefense.demisto")
    def test_get_alert_irondome_information_command(self, demisto_mock, return_outputs_mock):
        # load test data
        with open("./test-data/get_alert_irondome_information_resp.json") as test_data:
            json_data = test_data.read()
            mock_resp = json.loads(json_data)

        # Expectations
        expected_alert_id = "abc"

        expected_correlations_output = {
            "IronDome.Correlations(val.alert_id = obj.alert.id)": {
                "alert_id": expected_alert_id,
                "correlation": mock_resp.get("correlations")[0],
            }
        }
        expected_correlations_raw = mock_resp.get("correlations")[0]
        expected_ip_correlations_readable_output = (
            '### IronDome IP Correlations in "redskins"\n'
            "|ip|enterprise_correlations|community_correlations|\n"
            "|---|---|---|\n"
            "| 1.1.1.1 | 1 | 2 |\n"
        )

        expected_domain_correlations_readable_output = (
            '### IronDome Domain Correlations in "redskins"\n'
            "|domain|enterprise_correlations|community_correlations|\n"
            "|---|---|---|\n"
            "| bad.com | 3 | 4 |\n"
        )

        expected_behavior_correlations_readable_output = (
            '### IronDome Behavior Correlations in "redskins"\n'
            "|behavior|enterprise_correlations|community_correlations|\n"
            "|---|---|---|\n"
            "| true | 5 | 6 |\n"
        )

        expected_correlation_participation_output = {
            "IronDome.CorrelationParticipation(val.alert_id = obj.alert.id)": {
                "alert_id": expected_alert_id,
                "correlation_participation": mock_resp.get("correlation_participation")[0],
            }
        }
        expected_correlation_participation_readable_output = (
            "### IronDome Correlation Participation in "
            '"redskins"\n|malicious'
            "_count|suspicious_count|benign_count|whitelisted_count"
            "|comments_count|activity_count|resource_owner|"
            "first_seen|last_seen|\n|---|---|---|---|---|---|---|---"
            "|---|\n| 7 | 8 | 9 | 10 | 11 | 12 | false | "
            "2020-01-08T10:40:00.000Z | 2020-02-07T19:22:56.000Z |\n"
        )
        expected_correlation_participation_raw = mock_resp.get("correlation_participation")[0]

        expected_community_comments_output = {
            "IronDome.CommunityComments(val.alert_id = obj.alert.id)": {
                "alert_id": expected_alert_id,
                "community_comments": mock_resp.get("community_comments"),
            }
        }
        expected_community_comments_readable_output = (
            "### IronDome Community "
            "Comments\n|created|comment|dome_tags|enterprise|"
            "self|\n|---|---|---|---|---|\n| 2020-04-15T18:57:16.000Z | "
            "BrandonTest2 - Share irondome | demo,<br>brandon_test,<br>"
            "BrandonNEWTEST,<br>Energy,<br>redskins | true | true |\n"
        )
        expected_community_comments_raw = mock_resp.get("community_comments")

        expected_cognitive_system_score_output = {
            "IronDome.CognitiveSystemScore(val.alert_id = obj.alert.id)": {
                "alert_id": expected_alert_id,
                "cognitive_system_score": mock_resp.get("cognitive_system_score"),
            }
        }
        expected_cognitive_system_score_readable_output = (
            f'### Cognitive System Score: ' f'{mock_resp.get("cognitive_system_score")}'
        )
        expected_cognitive_system_score_raw = mock_resp.get("cognitive_system_score")

        expected_dome_notifications_output = {
            "IronDome.Notification(val.alert_id = obj.alert.id)": {
                "alert_id": expected_alert_id,
                "dome_notification": mock_resp.get("dome_notifications")[0],
            }
        }
        expected_dome_notifications_readable_output = (
            "### IronDome Notification: "
            "DNC_JOINED_HIGH_RISK\n|alert_ids|category|created|"
            "dome_tags|id|\n|---|---|---|---|---|\n| "
            "04f94226-60f7-4f1b-9569-15d7ddc01b7a | DNC_JOINED_HIGH_RISK "
            "| 2020-04-15T09:27:20.000Z | redskins | 576225 |\n"
        )
        expected_dome_notifications_raw = mock_resp.get("dome_notifications")[0]
        expected_results = "link"
        expected_calls = [
            call(
                readable_output=expected_ip_correlations_readable_output,
                outputs=expected_correlations_output,
                raw_response=expected_correlations_raw,
            ),
            call(
                readable_output=expected_domain_correlations_readable_output,
                outputs=expected_correlations_output,
                raw_response=expected_correlations_raw,
            ),
            call(
                readable_output=expected_behavior_correlations_readable_output,
                outputs=expected_correlations_output,
                raw_response=expected_correlations_raw,
            ),
            call(
                readable_output=expected_correlation_participation_readable_output,
                outputs=expected_correlation_participation_output,
                raw_response=expected_correlation_participation_raw,
            ),
            call(
                readable_output=expected_community_comments_readable_output,
                outputs=expected_community_comments_output,
                raw_response=expected_community_comments_raw,
            ),
            call(
                readable_output=expected_cognitive_system_score_readable_output,
                outputs=expected_cognitive_system_score_output,
                raw_response=expected_cognitive_system_score_raw,
            ),
            call(
                readable_output=expected_dome_notifications_readable_output,
                outputs=expected_dome_notifications_output,
                raw_response=expected_dome_notifications_raw,
            ),
            call(readable_output=expected_results, outputs={}),
        ]

        # Set up mocks
        def getArg_side_effect(arg_name):
            arg_dict = {
                "alert_id": expected_alert_id,
            }
            return arg_dict[arg_name]

        demisto_mock.getArg.side_effect = getArg_side_effect
        irondefense_module.IRON_DEFENSE = Mock()
        irondefense_module.IRON_DEFENSE.get_alert_irondome_information.return_value = mock_resp
        irondefense_module.IRON_DEFENSE.create_dome_markdown_link.return_value = "link"

        # Execute test
        irondefense_module.get_alert_irondome_information_command()

        # Assert results
        irondefense_module.IRON_DEFENSE.get_alert_irondome_information.assert_called_with(expected_alert_id)
        return_outputs_mock.assert_has_calls(expected_calls, any_order=True)
        irondefense_module.IRON_DEFENSE.create_dome_markdown_link.assert_called_with(
            "Open IronDome information in " "IronVue", expected_alert_id
        )

    @mock.patch("IronDefense.return_outputs")
    @mock.patch("IronDefense.demisto")
    def test_get_alert_irondome_information_command_empty_resp(self, demisto_mock, return_outputs_mock):
        # Expectations
        expected_alert_id = "abc"
        expected_results = f"No correlations found for alert ID: {expected_alert_id}"

        # Setup mocks
        def getArg_side_effect(arg_name):
            arg_dict = {
                "alert_id": expected_alert_id,
            }
            return arg_dict[arg_name]

        demisto_mock.getArg.side_effect = getArg_side_effect
        irondefense_module.IRON_DEFENSE = Mock()
        irondefense_module.IRON_DEFENSE.get_alert_irondome_information.return_value = {
            "correlations": [],
            "correlation_participation": [],
            "community_comments": [],
            "dome_notifications": [],
            "cognitive_system_score": 0,
        }

        # Execute test
        irondefense_module.get_alert_irondome_information_command()

        # Assert results
        irondefense_module.IRON_DEFENSE.get_alert_irondome_information.assert_called_with(expected_alert_id)
        demisto_mock.results.assert_called_with(expected_results)
        return_outputs_mock.assert_not_called()

    def test_event_context_table_to_dict_list(self):
        # Expectations
        expected_dict_table_list = [
            {
                "ip": "1.1.1.1",
                "classification": "CLASSIFICATION_ENTERPRISE",
            },
            {
                "ip": "2.2.2.2",
                "classification": "CLASSIFICATION_ENTERPRISE_2",
            },
        ]

        # Execute test
        with open("./test-data/event-context-table.json") as event_context_table_file:
            json_data = event_context_table_file.read()
            event_context_table = json.loads(json_data)
            actual_dict_table_list = self.class_under_test.event_context_table_to_dict_list(event_context_table)

        # Assert results
        assert expected_dict_table_list == actual_dict_table_list

    def test_event_context_to_dict(self):
        # Expectations
        expected_dict_table = {
            "session_size": "1069918",
            "threshold_entity_time": "2020-04-11T09:00:00.000Z",
            "producer_to_consumer_ratio": "1.977250634801539",
            "threshold_size": "1020401",
        }

        # Execute test
        with open("./test-data/event-context-key-value-table.json") as event_context_table_file:
            json_data = event_context_table_file.read()
            event_context_table = json.loads(json_data)
            actual_dict_table = self.class_under_test.event_context_table_to_dict(event_context_table)

        # Assert results
        assert expected_dict_table == actual_dict_table

    def test_event_context_table_contains_multi_columns(self):
        # Execute test
        with open("./test-data/event-context-table.json") as event_context_table_file:
            json_data = event_context_table_file.read()
            event_context_table = json.loads(json_data)
            result = self.class_under_test.event_context_table_contains_multi_columns(event_context_table)
            assert result

        with open("./test-data/event-context-key-value-table.json") as event_context_table_file:
            json_data = event_context_table_file.read()
            event_context_table = json.loads(json_data)
            result = self.class_under_test.event_context_table_contains_multi_columns(event_context_table)
            assert not result

    def test_create_markdown_link(self):
        # Expectations
        link_text = "asdf"
        url = "https://asdf.com"
        expected_markdown_link = "[asdf](https://asdf.com)"

        # Execute test
        actual_markdown_link = self.class_under_test.create_markdown_link(link_text, url)

        # Assert
        assert expected_markdown_link == actual_markdown_link

    def test_create_dome_markdown_link(self):
        # Expectations
        link_text = "asdf"
        alert_id = "abc"
        expected_markdown_link = f"[asdf](https://{self.host}/alerts/irondome?filter=alertId%3D%3" f"D{alert_id})"

        # Execute test
        actual_markdown_link = self.class_under_test.create_dome_markdown_link(link_text, alert_id)

        # Assert
        assert expected_markdown_link == actual_markdown_link


if __name__ == "__main__":
    unittest.main()
