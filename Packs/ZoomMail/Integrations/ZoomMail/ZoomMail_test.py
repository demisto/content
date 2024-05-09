import base64
import unittest
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any
from unittest.mock import patch, MagicMock
import json

from CommonServerPython import CommandResults, DemistoException
from ZoomMail import (
    ZoomMailClient,
    the_testing_module,
    fetch_incidents,
    get_email_thread_command,
    trash_email_command,
    list_emails_command,
    get_email_attachment_command,
    get_mailbox_profile_command,
    list_users_command,
    process_attachments,
    create_email_message,
    attach_files_to_email,
    attach_file,
    main,
)


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


class TestZoomMailClient(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://api.zoom.us/v2"
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.account_id = "test_account_id"
        self.default_email = "test@testingzmail.com"
        self.client = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            self.default_email,
        )

    @patch("ZoomMail.BaseClient._http_request")
    def test_obtain_access_token_success(self, mock_http_request):
        # Setup mock response
        mock_response = {
            "access_token": "test_token",
        }
        mock_http_request.return_value = mock_response

        # Execute function
        result = self.client.obtain_access_token()

        # Verify results
        assert result["success"]
        assert result["token"] == "test_token"
        assert self.client.access_token is not None
        assert self.client.token_time is not None

    @patch("ZoomMail.BaseClient._http_request")
    def test_obtain_access_token_failure(self, mock_http_request):
        # Setup mock response
        mock_http_request.return_value = {}

        # Execute function
        result = self.client.obtain_access_token()

        # Verify results
        assert not result["success"]
        assert "error" in result


class TestZoomMailClientGetEmailThread(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://api.zoom.us/v2"
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.account_id = "test_account_id"
        self.default_email = "testing@zmail.com"
        self.client = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            self.default_email,
        )
        self.email = "user@example.com"
        self.thread_id = "12345"
        self.format = "full"
        self.metadata_headers = "From,To"
        self.maxResults = "50"
        self.pageToken = ""

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_thread_success(self, mock_http_request):
        # Prepare mock response
        mock_thread_response = load_test_data(
            "test_data/thread/thread_list_response.json"
        )

        mock_http_request.return_value = mock_thread_response

        # Call the function
        response = self.client.get_email_thread(
            self.email,
            self.thread_id,
            self.format,
            self.metadata_headers,
            self.maxResults,
            self.pageToken,
        )

        # Assertions to verify the expected outcomes
        assert response["id"] == self.thread_id
        assert isinstance(response["messages"], list)
        assert len(response["messages"]) == 4
        assert response["messages"][0]["id"] == "MYSTERY_GUID"

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_thread_failure(self, mock_http_request):
        # Setup to simulate an API failure
        mock_http_request.side_effect = Exception("API Request Failed")

        # Call the function and handle exceptions
        with self.assertRaises(Exception) as context:
            self.client.get_email_thread(
                self.email,
                self.thread_id,
                self.format,
                self.metadata_headers,
                self.maxResults,
                self.pageToken,
            )

        # Verify that the exception message is correct
        assert "API Request Failed" in str(context.exception)

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_thread_invalid_input(self, mock_http_request):
        # Assuming the API returns a different type of error for invalid inputs
        mock_http_request.return_value = {"error": "Invalid thread ID"}

        # Call the function with an invalid thread ID
        response = self.client.get_email_thread(
            self.email,
            "invalid_thread_id",
            self.format,
            self.metadata_headers,
            self.maxResults,
            self.pageToken,
        )

        # Check if the error is handled as expected
        assert "error" in response
        assert response["error"] == "Invalid thread ID"

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_thread_with_no_email_provided_uses_default(
        self, mock_http_request
    ):
        """Test that the default email is used when no email is provided."""
        # Prepare mock response
        mock_response = {"id": self.thread_id, "messages": []}
        mock_http_request.return_value = mock_response

        # Call the function with email set to None
        response = self.client.get_email_thread(
            None,  # No email provided
            self.thread_id,
            self.format,
            self.metadata_headers,
            self.maxResults,
            self.pageToken,
        )

        # Assertions to verify the default email is used
        mock_http_request.assert_called_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{self.default_email}/threads/{self.thread_id}",
            params={
                "format": self.format,
                "metadata_headers": self.metadata_headers,
                "maxResults": self.maxResults,
                "pageToken": self.pageToken,
            },
        )
        assert response == mock_response, "The response should match the mock response."


class TestZoomMailClientTrashEmail(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://api.example.com"
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.account_id = "test_account_id"
        self.default_email = "default@example.com"
        self.client = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            self.default_email,
        )
        self.message_id = "123456789"

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_trash_email_with_email_provided(self, mock_http_request):
        """Test trashing an email with a specific email address provided."""
        email = "user@example.com"
        expected_url_suffix = (
            f"/emails/mailboxes/{email}/messages/{self.message_id}/trash"
        )
        mock_http_request.return_value = {"success": True}

        # Call the function
        response = self.client.trash_email(email, self.message_id)

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="POST", url_suffix=expected_url_suffix
        )
        # Assert response matches the mock
        assert response == {"success": True}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_trash_email_with_no_email_provided_uses_default(self, mock_http_request):
        """Test trashing an email with no email address provided uses default email."""
        expected_url_suffix = (
            f"/emails/mailboxes/{self.default_email}/messages/{self.message_id}/trash"
        )
        mock_http_request.return_value = {"success": True}

        # Call the function without providing an email
        response = self.client.trash_email(None, self.message_id)

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="POST", url_suffix=expected_url_suffix
        )
        # Assert response matches the mock
        assert response == {"success": True}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_trash_email_raises_error_if_no_default_email_set(self, mock_http_request):
        """Test that trashing an email raises an error if no email is provided and no default is set."""
        client_without_default = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            None,  # No default email set
        )

        # Expecting ValueError when no default email is set and none is provided
        with self.assertRaises(ValueError) as context:
            client_without_default.trash_email(None, self.message_id)

        assert str(context.exception) == "No email address provided and no default set."


class TestZoomMailClientListEmails(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://api.example.com"
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.account_id = "test_account_id"
        self.default_email = "default@example.com"
        self.client = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            self.default_email,
        )

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_list_emails_with_all_parameters(self, mock_http_request):
        """Test listing emails with all parameters provided."""
        email = "user@example.com"
        expected_params = {
            "maxResults": "100",
            "pageToken": "token123",
            "q": "subject:hello",
            "includeSpamTrash": "true",
        }
        mock_http_request.return_value = {"messages": []}

        # Call the function
        response = self.client.list_emails(
            email=email,
            max_results="100",
            page_token="token123",
            label_ids="INBOX,SENT",
            query="subject:hello",
            include_spam_trash=True,
        )

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{email}/messages",
            params=expected_params,
        )
        # Assert response matches the mock
        assert response == {"messages": []}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_list_emails_uses_default_email_when_none_provided(self, mock_http_request):
        """Test listing emails uses default email when none is provided."""
        expected_params = {
            "maxResults": "50",
            "pageToken": "",
            "q": "",
            "includeSpamTrash": "false",
        }
        mock_http_request.return_value = {"messages": []}

        # Call the function without providing an email
        response = self.client.list_emails(email=None)

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{self.default_email}/messages",
            params=expected_params,
        )
        # Assert response matches the mock
        assert response == {"messages": []}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_list_emails_raises_error_if_no_default_email_set(self, mock_http_request):
        """Test that listing emails raises an error if no email is provided and no default is set."""
        client_without_default = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            None,  # No default email set
        )

        # Expecting ValueError when no default email is set and none is provided
        with self.assertRaises(ValueError) as context:
            client_without_default.list_emails(email=None)

        assert str(context.exception) == "No email address provided and no default set."


class TestZoomMailClientGetEmailAttachment(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://api.example.com"
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.account_id = "test_account_id"
        self.default_email = "default@example.com"
        self.client = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            self.default_email,
        )

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_attachment_success(self, mock_http_request):
        """Test successful retrieval of an email attachment."""
        email = "user@example.com"
        message_id = "12345"
        attachment_id = "67890"
        mock_http_request.return_value = {"data": "base64data", "more_info": "details"}

        # Call the function
        response = self.client.get_email_attachment(email, message_id, attachment_id)

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{email}/messages/{message_id}/attachments/{attachment_id}",
        )
        # Assert response matches the mock
        assert response == {"data": "base64data", "more_info": "details"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_attachment_uses_default_email_when_none_provided(
        self, mock_http_request
    ):
        """Test using default email when none is provided."""
        message_id = "12345"
        attachment_id = "67890"
        mock_http_request.return_value = {"data": "base64data"}

        # Call the function without providing an email
        response = self.client.get_email_attachment(None, message_id, attachment_id)

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{self.default_email}/messages/{message_id}/attachments/{attachment_id}",
        )
        # Assert response matches the mock
        assert response == {"data": "base64data"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_attachment_raises_error_if_no_default_email_set(
        self, mock_http_request
    ):
        """Test that method raises an error if no email is provided and no default is set."""
        client_without_default = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            None,  # No default email set
        )
        message_id = "12345"
        attachment_id = "67890"

        # Expecting ValueError when no default email is set and none is provided
        with self.assertRaises(ValueError) as context:
            client_without_default.get_email_attachment(None, message_id, attachment_id)

        assert str(context.exception) == "No email address provided and no default set."


class TestZoomMailClientGetEmailMessage(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://api.example.com"
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.account_id = "test_account_id"
        self.default_email = "default@example.com"
        self.client = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            self.default_email,
        )

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_message_success(self, mock_http_request):
        """Test successful retrieval of an email message."""
        email = "user@example.com"
        message_id = "12345"
        msg_format = "full"
        metadata_headers = "From,To"
        mock_http_request.return_value = {"id": message_id, "subject": "Test Email"}

        # Call the function
        response = self.client.get_email_message(
            email, message_id, msg_format, metadata_headers
        )

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{email}/messages/{message_id}",
            params={"format": msg_format, "metadata_headers": metadata_headers},
        )
        # Assert response matches the mock
        assert response == {"id": message_id, "subject": "Test Email"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_message_uses_default_email_when_none_provided(
        self, mock_http_request
    ):
        """Test using default email when none is provided."""
        message_id = "12345"
        mock_http_request.return_value = {"id": message_id}

        # Call the function without providing an email
        response = self.client.get_email_message(None, message_id, "full", "")

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{self.default_email}/messages/{message_id}",
            params={"format": "full", "metadata_headers": ""},
        )
        # Assert response matches the mock
        assert response == {"id": message_id}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_message_raises_error_if_no_default_email_set(
        self, mock_http_request
    ):
        """Test that method raises an error if no email is provided and no default is set."""
        client_without_default = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            None,  # No default email set
        )
        message_id = "12345"

        # Expecting ValueError when no default email is set and none is provided
        with self.assertRaises(ValueError) as context:
            client_without_default.get_email_message(None, message_id, "full", "")

        assert str(context.exception) == "No email address provided and no default set."


class TestZoomMailClientSendEmail(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://api.example.com"
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.account_id = "test_account_id"
        self.default_email = "default@example.com"
        self.client = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            self.default_email,
        )

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_send_email_success(self, mock_http_request):
        """Test successful sending of an email."""
        email = "user@example.com"
        raw_message = "encoded_message"
        mock_http_request.return_value = {"status": "sent", "id": "123"}

        # Call the function
        response = self.client.send_email(email, raw_message)

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="POST",
            url_suffix=f"/emails/mailboxes/{email}/messages/send",
            json_data={"raw": raw_message},
        )
        # Assert response contains the expected keys
        assert response == {"status": "sent", "id": "123"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_send_email_uses_default_email_when_none_provided(self, mock_http_request):
        """Test using default email when none is provided."""
        raw_message = "encoded_message"
        mock_http_request.return_value = {"status": "sent"}

        # Call the function without providing an email
        response = self.client.send_email(None, raw_message)

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="POST",
            url_suffix=f"/emails/mailboxes/{self.default_email}/messages/send",
            json_data={"raw": raw_message},
        )
        # Assert response matches the mock
        assert response == {"status": "sent"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_send_email_raises_error_if_no_default_email_set(self, mock_http_request):
        """Test that method raises an error if no email is provided and no default is set."""
        client_without_default = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            None,  # No default email set
        )
        raw_message = "encoded_message"

        # Expecting ValueError when no default email is set and none is provided
        with self.assertRaises(ValueError) as context:
            client_without_default.send_email(None, raw_message)

        assert str(context.exception) == "No email address provided and no default set."


class TestZoomMailClientGetMailboxProfile(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://api.example.com"
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.account_id = "test_account_id"
        self.default_email = "default@example.com"
        self.client = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            self.default_email,
        )

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_mailbox_profile_success(self, mock_http_request):
        """Test successful retrieval of mailbox profile."""
        email = "user@example.com"
        mock_http_request.return_value = {"email": email, "status": "active"}

        # Call the function
        response = self.client.get_mailbox_profile(email)

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="GET", url_suffix=f"/emails/mailboxes/{email}/profile"
        )
        # Assert response contains the expected keys
        assert response == {"email": email, "status": "active"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_mailbox_profile_uses_default_email_when_none_provided(
        self, mock_http_request
    ):
        """Test using default email when none is provided."""
        mock_http_request.return_value = {
            "email": self.default_email,
            "status": "active",
        }

        # Call the function without providing an email
        response = self.client.get_mailbox_profile(None)

        # Assert correct HTTP request call
        mock_http_request.assert_called_once_with(
            method="GET", url_suffix=f"/emails/mailboxes/{self.default_email}/profile"
        )
        # Assert response matches the mock
        assert response == {"email": self.default_email, "status": "active"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_mailbox_profile_raises_error_if_no_default_email_set(
        self, mock_http_request
    ):
        """Test that method raises an error if no email is provided and no default is set."""
        client_without_default = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            None,  # No default email set
        )

        # Expecting ValueError when no default email is set and none is provided
        with self.assertRaises(ValueError) as context:
            client_without_default.get_mailbox_profile(None)

        assert str(context.exception) == "No email address provided and no default set."


class TestZoomMailClientListUsers(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://api.example.com"
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.account_id = "test_account_id"
        self.default_email = "default@example.com"
        self.client = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            self.default_email,
        )

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_list_users_basic(self, mock_http_request):
        """Test listing users without pagination."""
        mock_http_request.return_value = {"users": [], "total": 0}

        # Call the function
        response = self.client.list_users()

        # Assert correct HTTP request call
        expected_params = {
            "status": "active",
            "page_size": 30,
            "role_id": "",
            "page_number": "1",
            "include_fields": "",
            "next_page_token": "",
            "license": "",
        }
        mock_http_request.assert_called_once_with(
            method="GET", url_suffix="/users", params=expected_params
        )
        # Assert response is as expected
        assert response == {"users": [], "total": 0}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_list_users_with_pagination(self, mock_http_request):
        """Test listing users with pagination token."""
        mock_http_request.return_value = {"users": [], "total": 0}

        # Call the function with a next_page_token
        response = self.client.list_users(next_page_token="abc123")

        # Assert correct HTTP request call with pagination
        mock_http_request.assert_called_once_with(
            method="GET", url_suffix="/users", params={"next_page_token": "abc123"}
        )
        # Assert response is as expected
        assert response == {"users": [], "total": 0}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_list_users_with_advanced_filters(self, mock_http_request):
        """Test listing users with additional filter options."""
        mock_http_request.return_value = {"users": [], "total": 0}
        advanced_filters = {
            "status": "inactive",
            "page_size": 50,
            "role_id": "admin",
            "page_number": "2",
            "include_fields": "email",
            "zoom_license": "pro",
        }

        # Call the function with additional filters
        response = self.client.list_users(**advanced_filters)

        # Check that the HTTP request is called with the modified parameters
        expected_params = advanced_filters.copy()
        expected_params["license"] = expected_params.pop("zoom_license")
        expected_params["next_page_token"] = ""
        mock_http_request.assert_called_once_with(
            method="GET", url_suffix="/users", params=expected_params
        )

        # Assert the response is correct
        assert response == {"users": [], "total": 0}


class TestTheTestingModule(unittest.TestCase):
    def setUp(self):
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.params = {
            "url": "https://api.example.com",
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
        }

    @patch("ZoomMail.validate_params")
    @patch("ZoomMail.ZoomMailClient.obtain_access_token")
    def test_the_testing_module_success(
        self, mock_obtain_access_token, mock_validate_params
    ):
        """Test successful API authentication."""
        mock_validate_params.return_value = []
        mock_obtain_access_token.return_value = {"success": True}

        # Execute the function
        result = the_testing_module(self.client, self.params)

        # Verify results
        assert result == "ok"
        mock_obtain_access_token.assert_called_once()

    @patch("ZoomMail.validate_params")
    @patch("ZoomMail.ZoomMailClient.obtain_access_token")
    def test_the_testing_module_failed_authentication(
        self, mock_obtain_access_token, mock_validate_params
    ):
        """Test failed authentication due to API error."""
        mock_validate_params.return_value = []
        mock_obtain_access_token.return_value = {
            "success": False,
            "error": "Invalid credentials",
        }

        # Execute the function
        result = the_testing_module(self.client, self.params)

        # Verify results
        expected_error = "Errors were found while testing:\nInvalid credentials"
        assert result == expected_error

    @patch("ZoomMail.validate_params")
    @patch("ZoomMail.ZoomMailClient.obtain_access_token")
    def test_the_testing_module_invalid_params(
        self, mock_obtain_access_token, mock_validate_params
    ):
        """Test response when there are validation errors in the parameters."""
        mock_validate_params.return_value = ["URL parameter is missing."]
        mock_obtain_access_token.return_value = {"success": True}

        # Execute the function
        result = the_testing_module(self.client, self.params)

        expected_error = "Errors were found while testing:\nURL parameter is missing."
        assert result == expected_error


class TestFetchIncidents(unittest.TestCase):
    def setUp(self):
        # Set up a ZoomMailClient instance with dummy parameters
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        # Common attributes for use in tests
        self.params = {
            "default_mailbox": "default@example.com",
            "first_fetch": "3 days",
            "max_fetch": "50",
        }

    @patch("ZoomMail.demisto.getLastRun")
    @patch("ZoomMail.demisto.setLastRun")
    @patch("ZoomMail.demisto.incidents")
    def test_no_emails_fetched(
        self, mock_get_last_run, mock_set_last_run, mock_incidents
    ):
        # Setup the mock responses and behaviors
        mock_get_last_run.return_value = {}

        mock_thread_response = load_test_data(
            "test_data/fetch/fetch_list_response_empty.json"
        )

        self.client.list_emails = MagicMock(return_value=mock_thread_response)

        # Execute the function
        fetch_incidents(self.client, self.params)

        mock_set_last_run.assert_called_once()

        # Ensure no incidents are created
        mock_incidents.assert_called_once()

    @patch("ZoomMail.demisto.getLastRun")
    @patch("ZoomMail.demisto.setLastRun")
    @patch("ZoomMail.demisto.incidents")
    def test_emails_fetched(self, mock_incidents, mock_set_last_run, mock_get_last_run):
        # Prepare mock data and response
        mock_get_last_run.return_value = {
            "last_fetch_info": {"internalDate": 1622440000, "ids": []},
            "next_page_token": "",
        }
        mock_list_response = load_test_data("test_data/fetch/fetch_list_response.json")
        self.client.list_emails = MagicMock(return_value=mock_list_response)
        mock_get_email_message_response_1 = load_test_data(
            "test_data/fetch/fetch_email_1.json"
        )
        mock_get_email_message_response_2 = load_test_data(
            "test_data/fetch/fetch_email_2.json"
        )
        mock_get_email_message_response_3 = load_test_data(
            "test_data/fetch/fetch_email_3.json"
        )
        self.client.get_email_message = MagicMock(
            side_effect=[
                mock_get_email_message_response_1,
                mock_get_email_message_response_2,
                mock_get_email_message_response_3,
            ]
        )

        # Execute the function
        fetch_incidents(self.client, self.params)

        # Check if incidents are created and handled properly
        incidents = mock_incidents.call_args[0][0]
        assert len(incidents) == 2
        assert incidents[0]["name"] == "Zoom Encrypted Email"

    @patch("ZoomMail.demisto.getLastRun")
    @patch("ZoomMail.demisto.setLastRun")
    @patch("ZoomMail.demisto.incidents")
    def test_handle_pagination(
        self, mock_incidents, mock_set_last_run, mock_get_last_run
    ):
        # Setup for pagination testing
        mock_get_last_run.return_value = {
            "last_fetch_info": {"internalDate": 1622440000, "ids": []},
            "next_page_token": "",
        }
        self.client.list_emails = MagicMock(
            side_effect=[
                {
                    "messages": [{"id": "123", "threadId": "123"}],
                    "nextPageToken": "abc123",
                },
                {"messages": [{"id": "124", "threadId": "124"}]},
            ]
        )

        mock_get_email_message_response_1 = load_test_data(
            "test_data/fetch/fetch_email_2.json"
        )
        mock_get_email_message_response_2 = load_test_data(
            "test_data/fetch/fetch_email_3.json"
        )
        self.client.get_email_message = MagicMock(
            side_effect=[
                mock_get_email_message_response_1,
                mock_get_email_message_response_2,
            ]
        )

        # Execute the function
        fetch_incidents(self.client, self.params)

        # Verify if nextPageToken is handled correctly
        calls = mock_set_last_run.call_args_list
        expected_call = {
            "last_fetch_info": {"internalDate": 1714987137.321, "ids": ["123"]},
            "next_page_token": "abc123",
        }
        # Check that setLastRun was called correctly
        assert len(calls) == 1
        assert (
            calls[0][0][0] == expected_call
        )  # Accessing the first argument of the first call


class TestGetEmailThreadCommand(unittest.TestCase):
    def setUp(self):
        """Prepare environment for tests, creating a mock client."""
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.args: dict[str, str] = {
            "email": "user@example.com",
            "thread_id": "1001",
            "format": "full",
            "metadata_headers": "Subject,Date",
            "max_results": "10",
            "page_token": "abc123",
        }

    @patch("ZoomMail.ZoomMailClient.get_email_thread")
    def test_successful_email_thread_retrieval(self, mock_get_email_thread):
        """Test successful retrieval of an email thread."""
        # Assuming load_test_data correctly loads and returns the desired JSON structure
        test_data = load_test_data("test_data/thread/thread_list_response.json")
        mock_get_email_thread.return_value = test_data

        # Set up command arguments
        self.args = {
            "email": "user@example.com",
            "thread_id": "12345",  # Ensure this matches what's in your mock data if necessary
            "format": "full",
            "metadata_headers": "",
            "max_results": "50",
            "page_token": "",
        }

        # Execute command
        result = get_email_thread_command(self.client, self.args)

        # Verify results
        assert isinstance(result, CommandResults)
        assert "Email Thread 12345" in result.readable_output
        assert "MYSTERY_GUID" in result.readable_output

    @patch("ZoomMail.ZoomMailClient.get_email_thread")
    def test_empty_email_thread(self, mock_get_email_thread):
        """Test the retrieval of an empty email thread."""
        test_data = load_test_data("test_data/thread/thread_list_response_empty.json")
        mock_get_email_thread.return_value = test_data

        # Execute command
        result = get_email_thread_command(self.client, self.args)

        # Verify results
        assert "has no messages" in result.readable_output

    @patch("ZoomMail.ZoomMailClient.get_email_thread")
    def test_email_thread_pagination_handling(self, mock_get_email_thread):
        """Test proper handling of pagination tokens."""
        mock_get_email_thread.return_value = {
            "messages": [{"id": "msg1"}, {"id": "msg2"}],
            "nextPageToken": "def456",
        }

        # Execute command
        result = get_email_thread_command(self.client, self.args)

        # Verify page token use and output correctness
        mock_get_email_thread.assert_called_with(
            "user@example.com", "1001", "full", "Subject,Date", "10", "abc123"
        )
        assert "msg2" in result.readable_output

    def test_missing_email_argument(self):
        """Test response when required email argument is missing."""
        self.args.pop("email")
        with self.assertRaises(ValueError) as context:
            get_email_thread_command(self.client, self.args)

        assert "Both 'email' and 'thread_id' arguments are required" in str(
            context.exception
        )

    def test_missing_thread_id_argument(self):
        """Test response when required thread_id argument is missing."""
        self.args.pop("thread_id")
        with self.assertRaises(ValueError) as context:
            get_email_thread_command(self.client, self.args)

        assert "Both 'email' and 'thread_id' arguments are required" in str(
            context.exception
        )


class TestTrashEmailCommand(unittest.TestCase):
    def setUp(self):
        """Prepare environment for tests, creating a mock client."""
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.args: dict[str, str] = {
            "email": "user@example.com",
            "message_id": "msg123",
        }

    @patch("ZoomMail.ZoomMailClient.trash_email")
    def test_successful_email_trashing(self, mock_trash_email):
        """Test successful trashing of an email."""
        # Mock API response
        mock_trash_email.return_value = {"success": True, "id": "msg123"}

        # Execute command
        result = trash_email_command(self.client, self.args)

        # Verify results
        assert isinstance(result, CommandResults)
        assert "was moved to TRASH" in result.readable_output

    def test_missing_email_argument(self):
        """Test response when required email argument is missing."""
        self.args.pop("email")
        with self.assertRaises(ValueError) as context:
            trash_email_command(self.client, self.args)

        assert "Both 'email' and 'message_id' arguments are required" in str(
            context.exception
        )

    def test_missing_message_id_argument(self):
        """Test response when required message_id argument is missing."""
        self.args.pop("message_id")
        with self.assertRaises(ValueError) as context:
            trash_email_command(self.client, self.args)

        assert "Both 'email' and 'message_id' arguments are required" in str(
            context.exception
        )


class TestListEmailsCommand(unittest.TestCase):
    def setUp(self):
        """Prepare environment for tests, creating a mock client."""
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.args: dict[str, str] = {
            "email": "user@example.com",
            "max_results": "100",
            "page_token": "",
            "label_ids": "INBOX,UNREAD",
            "query": "subject:urgent",
            "include_spam_trash": "false",
        }

    @patch("ZoomMail.ZoomMailClient.list_emails")
    def test_successful_email_listing(self, mock_list_emails):
        """Test successful listing of emails."""
        # Mock API response
        mock_list_emails.return_value = {
            "messages": [
                {"id": "msg1", "threadId": "thread1"},
                {"id": "msg2", "threadId": "thread2"},
            ]
        }

        # Execute command
        result = list_emails_command(self.client, self.args)

        # Verify results
        assert isinstance(result, CommandResults)
        assert "msg1" in result.readable_output
        assert "thread1" in result.readable_output

    @patch("ZoomMail.ZoomMailClient.list_emails")
    def test_no_emails_found(self, mock_list_emails):
        """Test the scenario where no emails are found."""
        mock_list_emails.return_value = {}

        # Execute command
        result = list_emails_command(self.client, self.args)

        # Verify results
        assert "No messages found" in result.readable_output

    def test_missing_email_argument(self):
        """Test response when the required 'email' argument is missing."""
        del self.args["email"]  # Remove the email from args to simulate the error

        with self.assertRaises(ValueError) as context:
            list_emails_command(self.client, self.args)

        assert "The 'email' argument is required" in str(context.exception)

    @patch("ZoomMail.ZoomMailClient.list_emails")
    def test_optional_parameters_handling(self, mock_list_emails):
        """Test proper handling of optional parameters."""
        self.args["include_spam_trash"] = (
            "true"  # Adjust for boolean handling in function
        )

        mock_list_emails.return_value = {}

        list_emails_command(self.client, self.args)

        # Check if the mock was called
        assert mock_list_emails.called, "The list_emails function was not called."

        # Check the arguments with which the mock was called
        called_with_kwargs = mock_list_emails.call_args[0]

        # Additional asserts to check argument passing
        assert called_with_kwargs[0] == self.args["email"]
        assert called_with_kwargs[1] == self.args["max_results"]
        assert called_with_kwargs[2] == self.args["page_token"]
        assert called_with_kwargs[3] == self.args["label_ids"]
        assert called_with_kwargs[4] == self.args["query"]
        assert called_with_kwargs[5] is True


class TestGetEmailAttachmentCommand(unittest.TestCase):
    def setUp(self):
        """Prepare environment for tests, creating a mock client."""
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.args: dict[str, Any] = {
            "email": "user@example.com",
            "message_id": "1001",
            "attachment_id": "2001",
        }

    @patch("ZoomMail.ZoomMailClient.get_email_attachment")
    @patch("ZoomMail.fileResult")
    def test_successful_attachment_retrieval(
        self, mock_file_result, mock_get_email_attachment
    ):
        """Test successful retrieval of an email attachment."""
        # Mock API response and file result function
        mock_get_email_attachment.return_value = {
            "data": "SGVsbG8sIHdvcmxkIQ==",  # base64 for "Hello, world!"
            "attachmentId": "2001",
        }
        mock_file_result.return_value = {
            "Type": "File",
            "FileID": "2001",
            "File": "attachment.txt",
        }

        # Execute command
        result = get_email_attachment_command(self.client, self.args)

        # Verify results
        assert isinstance(result, CommandResults)
        assert "retrieved successfully" in result.readable_output
        assert result.outputs["attachmentId"] == "2001"

    @patch("ZoomMail.ZoomMailClient.get_email_attachment")
    def test_no_attachment_found(self, mock_get_email_attachment):
        """Test the scenario where no attachment is found."""
        mock_get_email_attachment.return_value = {}

        # Execute command
        result = get_email_attachment_command(self.client, self.args)

        # Verify results
        assert "No data found" in result.readable_output

    def test_missing_required_arguments(self):
        """Test response when required arguments are missing."""
        # Missing message_id
        with self.assertRaises(ValueError) as context:
            missing_args = self.args.copy()
            del missing_args["message_id"]
            get_email_attachment_command(self.client, missing_args)
        assert "The 'message_id', and 'attachment_id' arguments are required" in str(
            context.exception
        )

        # Missing attachment_id
        with self.assertRaises(ValueError) as context:
            missing_args = self.args.copy()
            del missing_args["attachment_id"]
            get_email_attachment_command(self.client, missing_args)
        assert "The 'message_id', and 'attachment_id' arguments are required" in str(
            context.exception
        )


class TestGetMailboxProfileCommand(unittest.TestCase):
    def setUp(self):
        """Prepare environment for tests, creating a mock client."""
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.args = {"email": "user@example.com"}

    @patch("ZoomMail.ZoomMailClient.get_mailbox_profile")
    def test_successful_mailbox_profile_retrieval(self, mock_get_mailbox_profile):
        """Test successful retrieval of a mailbox profile."""
        # Mock API response
        mock_get_mailbox_profile.return_value = {
            "emailAddress": "user@example.com",
            "groupEmails": ["group1@example.com", "group2@example.com"],
            "createTime": 1588300800,  # Example timestamp
            "status": "active",
            "mboxSize": 2048,
            "messagesTotal": 100,
            "threadsTotal": 10,
            "encryptionEnabled": True,
            "labelEncryptionEnabled": False,
            "historyId": "12345",
        }

        # Execute command
        result = get_mailbox_profile_command(self.client, self.args)

        # Verify results
        assert isinstance(result, CommandResults)
        assert "Mailbox Profile for user@example.com" in result.readable_output
        assert "active" in result.readable_output
        assert "2048 bytes" in result.readable_output

    def test_missing_email_argument(self):
        """Test response when the 'email' argument is missing."""
        with self.assertRaises(ValueError) as context:
            missing_args = {}
            get_mailbox_profile_command(self.client, missing_args)

        assert "The 'email' argument is required" in str(context.exception)


class TestListUsersCommand(unittest.TestCase):
    def setUp(self):
        """Prepare environment for tests, creating a mock client."""
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.args = {
            "status": "active",
            "limit": "50",
            "role_id": "admin",
            "page_number": "1",
            "include_fields": "email,status",
            "next_page_token": "",
            "license": "pro",
        }

    @patch("ZoomMail.ZoomMailClient.list_users")
    def test_successful_user_listing(self, mock_list_users):
        """Test successful listing of users."""
        # Mock API response
        mock_list_users.return_value = {
            "users": [
                {
                    "email": "user1@example.com",
                    "first_name": "John",
                    "last_name": "Doe",
                    "type": "admin",
                    "status": "active",
                },
                {
                    "email": "user2@example.com",
                    "first_name": "Jane",
                    "last_name": "Smith",
                    "type": "member",
                    "status": "inactive",
                },
            ]
        }

        # Execute command
        result = list_users_command(self.client, self.args)

        # Verify results
        assert isinstance(result, CommandResults)
        assert "user1@example.com" in result.readable_output
        assert "John" in result.readable_output

    @patch("ZoomMail.ZoomMailClient.list_users")
    def test_no_users_found(self, mock_list_users):
        """Test the scenario where no users are found."""
        mock_list_users.return_value = {"users": []}

        # Execute command
        result = list_users_command(self.client, self.args)

        # Verify results
        assert "No entries" in result.readable_output

    @patch("ZoomMail.ZoomMailClient.list_users")
    def test_user_listing_with_pagination(self, mock_list_users):
        """Test user listing with pagination."""
        mock_list_users.return_value = {
            "users": [
                {
                    "email": "user3@example.com",
                    "first_name": "Alice",
                    "last_name": "Johnson",
                    "type": "admin",
                    "status": "active",
                }
            ],
            "nextPageToken": "abc123",
        }
        self.args["next_page_token"] = "abc123"

        # Execute command
        result = list_users_command(self.client, self.args)

        # Ensure pagination token is used correctly
        mock_list_users.assert_called_with(
            "active", 50, "admin", "1", "email,status", "", "pro"
        )
        assert "Alice" in result.readable_output


class TestProcessAttachments(unittest.TestCase):
    def setUp(self):
        """Prepare test environment."""
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.email = "test@example.com"
        self.message = {
            "id": "123",
            "attachments": [
                {"ID": "attach1", "Name": "file1.pdf"},
                {"ID": "attach2", "Name": "file2.pdf"},
            ],
        }

    @patch("ZoomMail.demisto.error")
    @patch("ZoomMail.ZoomMailClient.get_email_attachment")
    def test_process_attachments_failure(
        self, mock_get_email_attachment, mock_demisto_error
    ):
        """Test handling errors while processing attachments."""
        # Setup the client mock to raise an exception on attachment retrieval
        mock_get_email_attachment.side_effect = Exception(
            "Failed to retrieve attachment"
        )

        # Execute the function
        result = process_attachments(self.message, self.client, self.email)

        # Check that no attachments are returned
        assert len(result) == 0

        # Ensure error handling function is called
        mock_demisto_error.assert_called()

    @patch("ZoomMail.demisto.error")
    @patch("ZoomMail.ZoomMailClient.get_email_attachment")
    def test_process_attachments_success(
        self, mock_get_email_attachment, mock_demisto_error
    ):
        """Test successful processing of email attachments."""
        # Setup the client mock to return mock attachment data
        encoded_data = base64.urlsafe_b64encode(b"Test file content").decode("ascii")
        mock_get_email_attachment.return_value = {"data": encoded_data}

        # Execute the function
        result = process_attachments(self.message, self.client, self.email)

        # Check that attachments are processed correctly
        assert len(result) == 2
        assert result[0]["name"] == "file1.pdf"
        assert result[1]["name"] == "file2.pdf"

        # Ensure error handling function is not called
        mock_demisto_error.assert_not_called()


class TestCreateEmailMessage(unittest.TestCase):
    def setUp(self):
        self.from_email = "from@example.com"
        self.to_email = "to@example.com"
        self.subject = "Test Subject"
        self.body_text = "This is a plain text body."
        self.html_text = "<p>This is an HTML body.</p>"
        self.attachment_ids = ["attach1", "attach2"]

    @patch("ZoomMail.attach_files_to_email")
    def test_create_plain_text_email(self, mock_attach_files):
        """Test creating a plain text email without HTML or attachments."""
        email = create_email_message(
            self.from_email, self.to_email, self.subject, self.body_text, None, []
        )
        assert isinstance(email, MIMEMultipart)
        assert mock_attach_files.called
        assert email["From"] == self.from_email
        assert email["To"] == self.to_email
        assert email["Subject"] == self.subject
        assert len(email.get_payload()), 1
        assert isinstance(email.get_payload()[0], MIMEText)
        assert email.get_payload()[0].get_payload() == self.body_text

    @patch("ZoomMail.attach_files_to_email")
    def test_create_html_email(self, mock_attach_files):
        """Test creating an email with HTML content."""
        email = create_email_message(
            self.from_email, self.to_email, self.subject, None, self.html_text, []
        )
        assert isinstance(email, MIMEMultipart)
        assert mock_attach_files.called
        assert len(email.get_payload()) == 1
        assert isinstance(email.get_payload()[0], MIMEText)
        assert email.get_payload()[0].get_payload() == self.html_text

    @patch("ZoomMail.attach_files_to_email")
    def test_create_email_with_attachments(self, mock_attach_files):
        """Test creating an email with attachments."""
        email = create_email_message(
            self.from_email,
            self.to_email,
            self.subject,
            self.body_text,
            self.html_text,
            self.attachment_ids,
        )
        assert isinstance(email, MIMEMultipart)
        assert mock_attach_files.called
        assert mock_attach_files.call_args[0][1] == self.attachment_ids

    @patch("ZoomMail.attach_files_to_email")
    def test_create_email_all_elements(self, mock_attach_files):
        """Test creating an email with text, HTML, and attachments."""
        email = create_email_message(
            self.from_email,
            self.to_email,
            self.subject,
            self.body_text,
            self.html_text,
            self.attachment_ids,
        )
        assert isinstance(email, MIMEMultipart)
        assert mock_attach_files.called
        assert len(email.get_payload()) == 2  # Expecting two MIMEText parts (plain and html)
        assert any(part.get_content_type() == "text/plain" for part in email.get_payload())
        assert any(part.get_content_type() == "text/html" for part in email.get_payload())


class TestAttachFilesToEmail(unittest.TestCase):
    def setUp(self):
        self.message = MIMEMultipart()
        self.attachment_ids = ["123", "456", "789"]

    @patch("ZoomMail.demisto.getFilePath")
    @patch("ZoomMail.attach_file")
    def test_attach_files_success(self, mock_attach_file, mock_get_file_path):
        """Test attaching files successfully."""
        # Mock getFilePath to return dummy file paths
        mock_get_file_path.side_effect = [
            {"path": "/path/to/file1", "name": "file1.txt"},
            {"path": "/path/to/file2", "name": "file2.txt"},
            {"path": "/path/to/file3", "name": "file3.txt"},
        ]

        # Call the function under test
        attach_files_to_email(self.message, self.attachment_ids)

        # Assert attach_file was called correctly
        assert mock_attach_file.call_count == 3
        mock_attach_file.assert_any_call(self.message, "/path/to/file1", "file1.txt")
        mock_attach_file.assert_any_call(self.message, "/path/to/file2", "file2.txt")
        mock_attach_file.assert_any_call(self.message, "/path/to/file3", "file3.txt")

    @patch("ZoomMail.demisto.getFilePath")
    @patch("ZoomMail.attach_file")
    def test_attach_files_no_files_found(self, mock_attach_file, mock_get_file_path):
        """Test scenario where no files are found."""
        # Mock getFilePath to return None indicating no file was found
        mock_get_file_path.return_value = None

        # Call the function under test
        attach_files_to_email(self.message, self.attachment_ids)

        # Assert attach_file was not called
        mock_attach_file.assert_not_called()

    @patch("ZoomMail.demisto.getFilePath")
    @patch("ZoomMail.attach_file")
    def test_attach_files_partial_files_found(
        self, mock_attach_file, mock_get_file_path
    ):
        """Test attaching files when some files are not found."""
        # Mock getFilePath to return None for some files
        mock_get_file_path.side_effect = [
            {"path": "/path/to/file1", "name": "file1.txt"},
            None,
            {"path": "/path/to/file3", "name": "file3.txt"},
        ]

        # Call the function under test
        attach_files_to_email(self.message, self.attachment_ids)

        # Assert attach_file was called correctly
        assert mock_attach_file.call_count == 2
        mock_attach_file.assert_any_call(self.message, "/path/to/file1", "file1.txt")
        mock_attach_file.assert_any_call(self.message, "/path/to/file3", "file3.txt")


class TestAttachFile(unittest.TestCase):
    def setUp(self):
        self.message = MIMEMultipart()

    @patch(
        "builtins.open", new_callable=unittest.mock.mock_open, read_data="file content"
    )
    @patch("ZoomMail.MIMEBase")
    @patch("ZoomMail.encoders.encode_base64")
    def test_attach_file(self, mock_encode_base64, mock_mime_base, mock_open):
        """Test attaching a single file to the email."""
        # Configure the MIMEBase mock
        mock_part = MagicMock(spec=MIMEBase)
        mock_mime_base.return_value = mock_part

        # Call the function under test
        attach_file(self.message, "/fake/path/to/file.txt", "file.txt")

        # Assert file was opened correctly
        mock_open.assert_called_once_with("/fake/path/to/file.txt", "rb")

        # Check MIMEBase was initialized correctly
        mock_mime_base.assert_called_once_with("application", "octet-stream")

        # Ensure the file content was read and encoded
        mock_part.set_payload.assert_called_once_with("file content")
        mock_encode_base64.assert_called_once_with(mock_part)

        # Verify correct headers were added to the part
        mock_part.add_header.assert_called_once_with(
            "Content-Disposition", "attachment", filename="file.txt"
        )

        # Check the part was attached to the message
        assert len(self.message.get_payload()) == 1


class TestMainFunction(unittest.TestCase):
    @patch("ZoomMail.demisto")
    def test_command_routing(self, mock_demisto):
        """Test if commands are routed to the correct function."""
        # Setup mocks for demisto functions and client methods
        mock_demisto.params.return_value = {
            "url": "https://api.example.com",
            "credentials": {"identifier": "id", "password": "pass"},
            "account_id": "12345",
            "insecure": False,
            "proxy": False,
            "default_email": "default@example.com",
        }
        mock_demisto.args.return_value = {}
        mock_demisto.command.return_value = "test-module"

        # Prepare a realistic return value for the command function being tested
        mock_command_function = MagicMock(return_value="ok")

        # Patch the specific function within the COMMAND_FUNCTIONS dict
        with patch("ZoomMail.the_testing_module", mock_command_function):
            main()

            # Ensure the mock was called (i.e., routing works correctly)
            mock_command_function.assert_called_once()

            # Check that the return value is correct
            assert mock_command_function.return_value == "ok"

    @patch("ZoomMail.demisto")
    def test_handle_not_implemented_command(self, mock_demisto):
        """Test the handling of not implemented commands."""
        mock_demisto.command.return_value = "non-existent-command"
        with self.assertRaises(NotImplementedError):
            main()

    @patch("ZoomMail.demisto")
    def test_error_handling(self, mock_demisto):
        """Test if exceptions are handled correctly."""
        mock_demisto.command.return_value = "test-module"
        mock_demisto.params.return_value = {}
        mock_demisto.args.return_value = {}

        # Simulate an exception in the command function
        with patch(
            "ZoomMail.the_testing_module", side_effect=DemistoException("Error")
        ), patch("ZoomMail.return_error") as mock_return_error:
            main()
            mock_return_error.assert_called_once()


if __name__ == "__main__":
    unittest.main()
