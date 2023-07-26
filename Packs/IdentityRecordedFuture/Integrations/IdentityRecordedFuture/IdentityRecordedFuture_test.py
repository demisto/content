import io
import os
import unittest
import json
from pathlib import Path
from unittest.mock import patch, Mock
from IdentityRecordedFuture import Actions, Client, main
from CommonServerPython import CommandResults, DemistoException

import vcr as vcrpy

CASSETTES = Path(__file__).parent / "test_data"
DATETIME_STR_VALUE = "2021-12-08T12:10:21.837Z"


def filter_out_whoami(response):
    body = response["body"]["string"]
    try:
        body.decode("utf-8")
        json_blob = json.loads(body)
        json_blob.pop("api_key", None)
        response["body"]["string"] = json.dumps(json_blob).encode("utf-8")
    except UnicodeDecodeError:
        pass  # It's not a json string
    return response


vcr = vcrpy.VCR(
    serializer="yaml",
    cassette_library_dir=str(CASSETTES),
    record_mode="once",
    filter_headers=[("X-RFToken", "XXXXXX")],
    before_record_response=filter_out_whoami,
)


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def create_client() -> Client:
    base_url = "https://api.recordedfuture.com/gw/xsoar/"
    verify_ssl = True
    token = os.environ.get("RF_TOKEN")
    headers = {
        "X-RFToken": token,
        "X-RF-User-Agent": "Cortex_XSOAR/2.0 Cortex_XSOAR_unittest_0.1",
    }

    return Client(base_url=base_url, verify=verify_ssl, headers=headers, proxy=None)


class RFClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = create_client()

    @patch("IdentityRecordedFuture.BaseClient._http_request")
    def test_client_whoami(self, mock_http_request: Mock) -> None:
        """Test whoami()."""
        response = {1: 1}
        mock_http_request.return_value = response
        result = self.client.whoami()
        self.assertEqual(response, result)
        mock_http_request.assert_called_once_with(
            method="get", url_suffix="info/whoami", timeout=60
        )

    @patch("IdentityRecordedFuture.Client._call")
    def test_identity_search(self, mock_call: Mock) -> None:
        """Test identity_search()."""
        self.client.identity_search()
        mock_call.assert_called_once_with(url_suffix="/v2/identity/credentials/search")

    @patch("IdentityRecordedFuture.Client._call")
    def test_identity_lookup(self, mock_call: Mock) -> None:
        """Test identity_lookup()."""
        self.client.identity_lookup()
        mock_call.assert_called_once_with(url_suffix="/v2/identity/credentials/lookup")

    @patch("IdentityRecordedFuture.Client._call")
    def test_password_lookup(self, mock_call: Mock) -> None:
        """Test password_lookup()."""
        self.client.password_lookup()
        mock_call.assert_called_once_with(url_suffix="/v2/identity/password/lookup")

    @patch("IdentityRecordedFuture.demisto")
    @patch("IdentityRecordedFuture.BaseClient._http_request")
    def test_call(self, mock_http_request: Mock, mocked_demisto: Mock):
        """Test _call()."""

        STATUS_TO_RETRY = [500, 501, 502, 503, 504]

        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}
        mock_demisto_params = {"someparam": "some param value"}

        mocked_demisto.args.return_value = mock_command_args
        mocked_demisto.params.return_value = mock_demisto_params
        http_response = {"some": "http response"}
        mock_http_request.return_value = http_response

        mock_url_suffix = "mock_url_suffix"

        result = self.client._call(url_suffix=mock_url_suffix)

        json_data = {
            "demisto_args": mock_command_args,
            "demisto_params": mock_demisto_params,
        }

        mock_http_request.assert_called_once_with(
            method="post",
            url_suffix=mock_url_suffix,
            json_data=json_data,
            timeout=90,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
        )
        self.assertEqual(result, http_response)

    @patch("IdentityRecordedFuture.return_error")
    @patch("IdentityRecordedFuture.BaseClient._http_request")
    def test_call_return_error(self, mock_http_request: Mock, return_error_mock: Mock):
        """Test _call() when error message was returned."""

        mock_url_suffix = "mock_url_suffix"
        error_message_res = {"message": "error"}
        mock_error_response = Mock()
        mock_error_response.json.return_value = error_message_res
        mock_http_request.side_effect = DemistoException(message="", res=mock_error_response)
        self.client._call(url_suffix=mock_url_suffix)
        return_error_mock.assert_called_once_with(**error_message_res)

    @patch("IdentityRecordedFuture.BaseClient._http_request")
    def test_call_return_error_not_json(self, mock_http_request: Mock):
        """Test _call() when error message was returned and it is not json serializable."""

        mock_url_suffix = "mock_url_suffix"
        mock_error_response = Mock()
        mock_error_response.json.side_effect = json.JSONDecodeError("some not json error", "some", 3)
        mock_http_request.side_effect = DemistoException(message="", res=mock_error_response)
        with self.assertRaises(DemistoException):
            self.client._call(url_suffix=mock_url_suffix)

    @patch("IdentityRecordedFuture.CommandResults")
    @patch("IdentityRecordedFuture.BaseClient._http_request")
    def test_call_return_http_404_error(
        self, mock_http_request: Mock, command_results_mock: Mock
    ):
        """Test _call() when error message was returned."""

        mock_url_suffix = "mock_url_suffix"
        mock_http_request.side_effect = DemistoException("There is HTTP 404 error")
        self.client._call(url_suffix=mock_url_suffix)
        command_results_mock.assert_called_once_with(
            outputs_prefix="",
            outputs=dict(),
            raw_response=dict(),
            readable_output="No results found.",
            outputs_key_field="",
        )

    @patch("IdentityRecordedFuture.BaseClient._http_request")
    def test_call_return_http_error(self, mock_http_request: Mock):
        """Test _call() when error message was returned."""

        mock_url_suffix = "mock_url_suffix"
        mock_http_request.side_effect = DemistoException("Some error from the Server")
        with self.assertRaises(DemistoException):
            self.client._call(url_suffix=mock_url_suffix)


class RFActioncTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = Mock()
        self.action = Actions(self.client)
        return super().setUp()

    @patch("IdentityRecordedFuture.Actions._process_result_actions")
    def test_identity_search(self, process_result_mock: Mock) -> None:
        """Test search identities code."""
        some_random_data = "data"
        self.client.identity_search.return_value = some_random_data
        process_result_mock.return_value = some_random_data
        action_result = self.action.identity_search_command()
        self.assertEqual(some_random_data, action_result)
        self.client.identity_search.assert_called_once()
        process_result_mock.assert_called_once_with(response=some_random_data)

    @patch("IdentityRecordedFuture.Actions._process_result_actions")
    def test_identity_lookup(self, process_result_mock: Mock) -> None:
        """Test lookup identities code."""
        some_random_data = "data"
        self.client.identity_lookup.return_value = some_random_data
        process_result_mock.return_value = some_random_data
        action_result = self.action.identity_lookup_command()
        self.assertEqual(some_random_data, action_result)
        self.client.identity_lookup.assert_called_once()
        process_result_mock.assert_called_once_with(response=some_random_data)

    @patch("IdentityRecordedFuture.Actions._process_result_actions")
    def test_password_lookup(self, process_result_mock: Mock) -> None:
        """Test password lookup code."""
        some_random_data = "data"
        self.client.password_lookup.return_value = some_random_data
        process_result_mock.return_value = some_random_data
        action_result = self.action.password_lookup_command()
        self.assertEqual(some_random_data, action_result)
        self.client.password_lookup.assert_called_once()
        process_result_mock.assert_called_once_with(response=some_random_data)

    def test_process_result_actions_404_error(self) -> None:
        """Test result processing function with the case when we received 404 error."""
        response = CommandResults()
        result = self.action._process_result_actions(response)
        self.assertEqual(response, result)

    def test_process_result_actions_wrong_type(self) -> None:
        """Test result processing function with the case when we received string data."""
        response = "Some bad response from API"
        result = self.action._process_result_actions(response)
        self.assertIsNone(result)

    def test_process_result_actions_no_key_value(self) -> None:
        """Test result processing function with the case when we received date without action_result key."""
        response = {}
        result = self.action._process_result_actions(response)
        self.assertIsNone(result)

    def test_process_result_actions(self) -> None:
        """Test result processing function with the case when we received good data."""
        response = {"action_result": {"readable_output": "data"}}
        result = self.action._process_result_actions(response)
        self.assertIsInstance(result, CommandResults)


class MainTest(unittest.TestCase):

    @patch("IdentityRecordedFuture.demisto")
    @patch("IdentityRecordedFuture.Client")
    @patch("IdentityRecordedFuture.Actions")
    def test_main_general(self, actions_mock: Mock, client_mock: Mock, mocked_demisto: Mock,):
        """Test main function is it runs correctly and calling general things"""
        main()
        client_mock.assert_called_once()
        mocked_demisto.params.assert_called_once_with()
        mocked_demisto.command.assert_called_once_with()
        actions_mock.assert_called_once_with(client_mock.return_value)
