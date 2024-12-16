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
    main, safe_bytes_to_string, decode_base64, correct_base64_errors,
)


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


class TestZoomMailClient(unittest.TestCase):
    def setUp(self):
        """Prepare environment for testing."""
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
        """
        Tests the successful retrieval of an access token from the API.

        Given:
          - Mock response simulates a successful API call returning an access token.
        When:
          - Client requests an access token.
        Then:
          - Client should receive a valid token and update internal states appropriately.
        """
        mock_http_request.return_value = {"access_token": "test_token"}
        result = self.client.obtain_access_token()
        assert result["success"]
        assert result["token"] == "test_token"
        assert self.client.access_token == "test_token"
        assert self.client.token_time is not None

    @patch("ZoomMail.BaseClient._http_request")
    def test_obtain_access_token_failure(self, mock_http_request):
        """
        Tests the failure to retrieve an access token from the API.

        Given:
          - Mock response simulates an API failure with empty response.
        When:
          - Client attempts to obtain an access token.
        Then:
          - The response should indicate failure and contain an appropriate error message.
        """
        mock_http_request.return_value = {}
        result = self.client.obtain_access_token()
        assert not result["success"]
        assert "error" in result


class TestZoomMailClientGetEmailThread(unittest.TestCase):
    """
    Unit tests for the ZoomMailClient's method get_email_thread to ensure it handles different scenarios correctly.
    """

    def setUp(self):
        """
        Prepare environment for each test.
        """
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
        """
        Tests successful retrieval of an email thread.

        Given:
          - A valid response from the API for an email thread retrieval.
        When:
          - Requesting the email thread using valid parameters.
        Then:
          - Should return the correct thread details.
        """
        mock_thread_response = load_test_data("test_data/thread/thread_list_response.json")
        mock_http_request.return_value = mock_thread_response
        response = self.client.get_email_thread(
            self.email, self.thread_id, self.format, self.metadata_headers, self.maxResults, self.pageToken
        )
        assert response["id"] == self.thread_id
        assert isinstance(response["messages"], list)
        assert len(response["messages"]) == 4

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_thread_failure(self, mock_http_request):
        """
        Tests the client's response to a failed API request.

        Given:
          - An API error occurs during the request.
        When:
          - Retrieving an email thread.
        Then:
          - Should raise an Exception and provide a relevant error message.
        """
        mock_http_request.side_effect = Exception("API Request Failed")
        with self.assertRaises(Exception) as context:
            self.client.get_email_thread(
                self.email, self.thread_id, self.format, self.metadata_headers, self.maxResults, self.pageToken
            )
        assert "API Request Failed" in str(context.exception)

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_thread_invalid_input(self, mock_http_request):
        """
        Tests handling of invalid thread IDs.

        Given:
          - The API returns an error response for invalid input.
        When:
          - An invalid thread ID is used to retrieve an email thread.
        Then:
          - Should receive an error response indicating the invalid input.
        """
        mock_http_request.return_value = {"error": "Invalid thread ID"}
        response = self.client.get_email_thread(
            self.email, "invalid_thread_id", self.format, self.metadata_headers, self.maxResults, self.pageToken
        )
        assert "error" in response
        assert response["error"] == "Invalid thread ID"

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_thread_with_no_email_provided_uses_default(self, mock_http_request):
        """
        Tests the use of default email when none is provided.

        Given:
          - An API call is made without specifying the email address.
        When:
          - The email parameter is None, expecting the system to use the default email address.
        Then:
          - Should use the default email address and execute the API call successfully.
        """
        mock_response = {"id": self.thread_id, "messages": []}
        mock_http_request.return_value = mock_response
        response = self.client.get_email_thread(
            None, self.thread_id, self.format, self.metadata_headers, self.maxResults, self.pageToken
        )
        mock_http_request.assert_called_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{self.default_email}/threads/{self.thread_id}",
            params={"format": self.format, "metadata_headers": self.metadata_headers,
                    "maxResults": self.maxResults, "pageToken": self.pageToken},
        )
        assert response == mock_response


class TestZoomMailClientTrashEmail(unittest.TestCase):
    """
    Tests for the ZoomMailClient's trash_email method to ensure it correctly handles email trashing under various scenarios.
    """

    def setUp(self):
        """
        Set up common variables for tests.
        """
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
        """
        Test that trashing an email successfully sends a request to the server when an email address is provided.

        Given:
          - An email address and message ID to trash.
        When:
          - The trash_email method is called with the email address.
        Then:
          - A POST request should be made to the correct API endpoint.
          - The server should return a success response.
        """
        email = "user@example.com"
        expected_url_suffix = f"/emails/mailboxes/{email}/messages/{self.message_id}/trash"
        mock_http_request.return_value = {"success": True}

        response = self.client.trash_email(email, self.message_id)

        mock_http_request.assert_called_once_with(method="POST", url_suffix=expected_url_suffix)
        assert response == {"success": True}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_trash_email_with_no_email_provided_uses_default(self, mock_http_request):
        """
        Test that trashing an email uses the default email when none is provided.

        Given:
          - A message ID to trash and no email address provided.
        When:
          - The trash_email method is called without an email address.
        Then:
          - A POST request should be made using the default email to the correct API endpoint.
          - The server should return a success response.
        """
        expected_url_suffix = f"/emails/mailboxes/{self.default_email}/messages/{self.message_id}/trash"
        mock_http_request.return_value = {"success": True}

        response = self.client.trash_email(None, self.message_id)

        mock_http_request.assert_called_once_with(method="POST", url_suffix=expected_url_suffix)
        assert response == {"success": True}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_trash_email_raises_error_if_no_default_email_set(self, mock_http_request):
        """
        Test that trashing an email raises an error if no email is provided and no default email is set.

        Given:
          - A message ID to trash and no email address or default email set.
        When:
          - The trash_email method is called without an email and without a default email.
        Then:
          - The method should raise a ValueError due to missing email information.
        """
        client_without_default = ZoomMailClient(
            self.base_url, self.client_id, self.client_secret, self.account_id, None  # No default email set
        )

        with self.assertRaises(ValueError) as context:
            client_without_default.trash_email(None, self.message_id)

        assert str(context.exception) == "No email address provided and no default set."


class TestZoomMailClientListEmails(unittest.TestCase):
    """
    Tests for the ZoomMailClient's list_emails method to ensure it handles email listing under various scenarios correctly.
    """

    def setUp(self):
        """
        Set up common test components and dependencies.
        """
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
        """
        Test listing emails successfully with all filtering parameters provided.

        Given:
          - A complete set of filtering parameters for listing emails.
        When:
          - The list_emails method is invoked with these parameters.
        Then:
          - A GET request should be made to the API with the correct parameters.
          - The API should return a list of emails.
        """
        email = "user@example.com"
        expected_params = {
            "maxResults": "100",
            "pageToken": "token123",
            "q": "subject:hello",
            "includeSpamTrash": "true",
        }
        mock_http_request.return_value = {"messages": []}

        response = self.client.list_emails(
            email=email,
            max_results="100",
            page_token="token123",
            label_ids="INBOX,SENT",
            query="subject:hello",
            include_spam_trash=True,
        )

        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{email}/messages",
            params=expected_params,
        )
        assert response == {"messages": []}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_list_emails_uses_default_email_when_none_provided(self, mock_http_request):
        """
        Test that the default email address is used for listing emails when no specific email is provided.

        Given:
          - No specific email address is provided for listing emails.
        When:
          - The list_emails method is called without an email address.
        Then:
          - The API should use the default email address for the request.
          - A GET request should retrieve the emails from the mailbox associated with the default email.
        """
        expected_params = {
            "maxResults": "50",
            "pageToken": "",
            "q": "",
            "includeSpamTrash": "false",
        }
        mock_http_request.return_value = {"messages": []}

        response = self.client.list_emails(email=None)

        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{self.default_email}/messages",
            params=expected_params,
        )
        assert response == {"messages": []}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_list_emails_raises_error_if_no_default_email_set(self, mock_http_request):
        """
        Test that an error is raised when attempting to list emails without providing an email and no default is set.

        Given:
          - No default email is set and no email address is provided.
        When:
          - The list_emails method is called without an email address.
        Then:
          - The method should raise a ValueError indicating that no email address was provided and no default is set.
        """
        client_without_default = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            None,  # No default email set
        )

        with self.assertRaises(ValueError) as context:
            client_without_default.list_emails(email=None)

        assert str(context.exception) == "No email address provided and no default set."


class TestZoomMailClientGetEmailAttachment(unittest.TestCase):
    """
    Tests for the ZoomMailClient's get_email_attachment method to ensure it handles attachment retrieval correctly.
    """

    def setUp(self):
        """
        Set up common test components and dependencies.
        """
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
        """
        Test successful retrieval of an email attachment.

        Given:
          - All parameters including email, message ID, and attachment ID are provided.
        When:
          - The get_email_attachment method is called with these parameters.
        Then:
          - A GET request should be made correctly and the expected attachment data should be returned.
        """
        email = "user@example.com"
        message_id = "12345"
        attachment_id = "67890"
        mock_http_request.return_value = {"data": "base64data", "more_info": "details"}

        response = self.client.get_email_attachment(email, message_id, attachment_id)

        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{email}/messages/{message_id}/attachments/{attachment_id}",
        )
        assert response == {"data": "base64data", "more_info": "details"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_attachment_uses_default_email_when_none_provided(self, mock_http_request):
        """
        Test the default email address is used for retrieving an email attachment when no specific email is provided.

        Given:
          - Message ID and attachment ID are provided, but no email address is provided.
        When:
          - The get_email_attachment method is called without an email address.
        Then:
          - The API should use the default email address for the request and successfully return the attachment data.
        """
        message_id = "12345"
        attachment_id = "67890"
        mock_http_request.return_value = {"data": "base64data"}

        response = self.client.get_email_attachment(None, message_id, attachment_id)

        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{self.default_email}/messages/{message_id}/attachments/{attachment_id}",
        )
        assert response == {"data": "base64data"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_attachment_raises_error_if_no_default_email_set(self, mock_http_request):
        """
        Test that an error is raised when attempting to retrieve an email attachment without providing an email and no default is
         set.

        Given:
          - No default email is set and no email address is provided.
        When:
          - The get_email_attachment method is called without an email address.
        Then:
          - The method should raise a ValueError indicating that no email address was provided and no default is set.
        """
        client_without_default = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            None,  # No default email set
        )
        message_id = "12345"
        attachment_id = "67890"

        with self.assertRaises(ValueError) as context:
            client_without_default.get_email_attachment(None, message_id, attachment_id)

        assert str(context.exception) == "No email address provided and no default set."


class TestZoomMailClientGetEmailMessage(unittest.TestCase):
    """
    Tests for the ZoomMailClient's get_email_message method to ensure it properly retrieves email messages.
    """

    def setUp(self):
        """
        Set up common test components and dependencies.
        """
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
        """
        Test successful retrieval of an email message.

        Given:
          - An email address, message ID, message format, and metadata headers are provided.
        When:
          - The get_email_message method is called with these parameters.
        Then:
          - A GET request should be made correctly, and the expected email details should be returned.
        """
        email = "user@example.com"
        message_id = "12345"
        msg_format = "full"
        metadata_headers = "From,To"
        mock_http_request.return_value = {"id": message_id, "subject": "Test Email"}

        response = self.client.get_email_message(
            email, message_id, msg_format, metadata_headers
        )

        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{email}/messages/{message_id}",
            params={"format": msg_format, "metadata_headers": metadata_headers},
        )
        assert response == {"id": message_id, "subject": "Test Email"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_message_uses_default_email_when_none_provided(self, mock_http_request):
        """
        Test the default email address is used for retrieving an email message when no specific email is provided.

        Given:
          - Only a message ID is provided, without an email address.
        When:
          - The get_email_message method is called without an email address.
        Then:
          - The API should use the default email address for the request and successfully return the email message.
        """
        message_id = "12345"
        mock_http_request.return_value = {"id": message_id}

        response = self.client.get_email_message(None, message_id, "full", "")

        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/emails/mailboxes/{self.default_email}/messages/{message_id}",
            params={"format": "full", "metadata_headers": ""},
        )
        assert response == {"id": message_id}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_get_email_message_raises_error_if_no_default_email_set(self, mock_http_request):
        """
        Test that an error is raised when attempting to retrieve an email message without providing an email and no default is
         set.

        Given:
          - No default email is set and no email address is provided.
        When:
          - The get_email_message method is called without an email address.
        Then:
          - The method should raise a ValueError indicating that no email address was provided and no default is set.
        """
        client_without_default = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            None,  # No default email set
        )
        message_id = "12345"

        with self.assertRaises(ValueError) as context:
            client_without_default.get_email_message(None, message_id, "full", "")

        assert str(context.exception) == "No email address provided and no default set."


class TestZoomMailClientSendEmail(unittest.TestCase):
    """
    Tests for the ZoomMailClient's send_email method to ensure it properly handles sending emails.
    """

    def setUp(self):
        """
        Set up common test components and dependencies for each test case.
        """
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
        """
        Test successful sending of an email.

        Given:
          - An email address and raw_message are provided.
        When:
          - The send_email method is called with these parameters.
        Then:
          - A POST request should be made correctly, and the expected email send confirmation should be returned.
        """
        email = "user@example.com"
        raw_message = "encoded_message"
        mock_http_request.return_value = {"status": "sent", "id": "123"}

        response = self.client.send_email(email, raw_message)

        mock_http_request.assert_called_once_with(
            method="POST",
            url_suffix=f"/emails/mailboxes/{email}/messages/send",
            json_data={"raw": raw_message},
        )
        assert response == {"status": "sent", "id": "123"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_send_email_uses_default_email_when_none_provided(self, mock_http_request):
        """
        Test using default email when none is provided during the email sending operation.

        Given:
          - No email is provided, but a raw_message is specified.
        When:
          - The send_email method is called without an email address.
        Then:
          - The API should use the default email address for the send operation, confirming successful sending.
        """
        raw_message = "encoded_message"
        mock_http_request.return_value = {"status": "sent"}

        response = self.client.send_email(None, raw_message)

        mock_http_request.assert_called_once_with(
            method="POST",
            url_suffix=f"/emails/mailboxes/{self.default_email}/messages/send",
            json_data={"raw": raw_message},
        )
        assert response == {"status": "sent"}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_send_email_raises_error_if_no_default_email_set(self, mock_http_request):
        """
        Test that an error is raised if no email is provided and no default is set during the email sending operation.

        Given:
          - No default email is set and no email address is provided.
        When:
          - The send_email method is called without an email address.
        Then:
          - The method should raise a ValueError indicating that no email address was provided and no default is set.
        """
        client_without_default = ZoomMailClient(
            self.base_url,
            self.client_id,
            self.client_secret,
            self.account_id,
            None,  # No default email set
        )
        raw_message = "encoded_message"

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
        """Set up the environment for each test.

        Given:
        - Base URL, client ID, client secret, account ID, and a default email are provided to initialize the ZoomMailClient.
        """
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
        """Test listing users without pagination.

        When:
        - No pagination or other additional parameters are provided.

        Then:
        - The function should use default parameters to list users.
        - Assert that the HTTP request was made correctly.
        - Verify the response matches the expected empty list of users.
        """
        mock_http_request.return_value = {"users": [], "total": 0}
        response = self.client.list_users()
        expected_params = {
            "status": "active",
            "page_size": 30,
            "role_id": "",
            "page_number": "1",
            "include_fields": "",
            "next_page_token": "",
            "license": "",
        }
        mock_http_request.assert_called_once_with(method="GET", url_suffix="/users", params=expected_params)
        assert response == {"users": [], "total": 0}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_list_users_with_pagination(self, mock_http_request):
        """Test listing users with a pagination token.

        When:
        - A next_page_token is provided to fetch a specific page of users.

        Then:
        - The function should make an HTTP request including the pagination token.
        - Verify the response matches the expected empty list of users.
        """
        mock_http_request.return_value = {"users": [], "total": 0}
        response = self.client.list_users(next_page_token="abc123")
        mock_http_request.assert_called_once_with(method="GET", url_suffix="/users", params={"next_page_token": "abc123"})
        assert response == {"users": [], "total": 0}

    @patch("ZoomMail.ZoomMailClient._http_request")
    def test_list_users_with_advanced_filters(self, mock_http_request):
        """Test listing users with additional filter options such as status, role, and license.

        When:
        - Advanced filters such as status, role ID, page number, and license type are provided.

        Then:
        - The function should make an HTTP request with these filters.
        - Verify the HTTP request is called with the expected parameters.
        - Assert the response matches the expected output with an empty user list.
        """
        mock_http_request.return_value = {"users": [], "total": 0}
        advanced_filters = {
            "status": "inactive",
            "page_size": 50,
            "role_id": "admin",
            "page_number": "2",
            "include_fields": "email",
            "zoom_license": "pro",
        }
        response = self.client.list_users(**advanced_filters)
        expected_params = advanced_filters.copy()
        expected_params["license"] = expected_params.pop("zoom_license")
        expected_params["next_page_token"] = ""
        mock_http_request.assert_called_once_with(method="GET", url_suffix="/users", params=expected_params)
        assert response == {"users": [], "total": 0}


class TestTheTestingModule(unittest.TestCase):
    def setUp(self):
        """Prepare environment for each test.

        Given:
        - An instance of ZoomMailClient is initialized with test credentials and default configurations.
        - Test parameters for API interaction are set up.
        """
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
    def test_the_testing_module_success(self, mock_obtain_access_token, mock_validate_params):
        """Test if the module correctly handles successful authentication.

        When:
        - API credentials are validated successfully.

        Then:
        - The function should return 'ok' indicating successful authentication.
        - Ensure that the access token retrieval is invoked once.
        """
        mock_validate_params.return_value = []
        mock_obtain_access_token.return_value = {"success": True}

        result = the_testing_module(self.client, self.params)

        assert result == "ok"
        mock_obtain_access_token.assert_called_once()

    @patch("ZoomMail.validate_params")
    @patch("ZoomMail.ZoomMailClient.obtain_access_token")
    def test_the_testing_module_failed_authentication(self, mock_obtain_access_token, mock_validate_params):
        """Test handling of failed authentication due to invalid API credentials.

        When:
        - API responds with an error during authentication.

        Then:
        - The function should return a detailed error message.
        - Ensure that the result includes the specific error message from the API.
        """
        mock_validate_params.return_value = []
        mock_obtain_access_token.return_value = {
            "success": False,
            "error": "Invalid credentials",
        }

        result = the_testing_module(self.client, self.params)

        expected_error = "Errors were found while testing:\nInvalid credentials"
        assert result == expected_error

    @patch("ZoomMail.validate_params")
    @patch("ZoomMail.ZoomMailClient.obtain_access_token")
    def test_the_testing_module_invalid_params(self, mock_obtain_access_token, mock_validate_params):
        """Test the response when there are validation errors with the provided parameters.

        When:
        - Parameters are incomplete or improperly formatted.

        Then:
        - The function should return an error message listing all validation errors.
        """
        mock_validate_params.return_value = ["URL parameter is missing."]
        mock_obtain_access_token.return_value = {"success": True}

        result = the_testing_module(self.client, self.params)

        expected_error = "Errors were found while testing:\nURL parameter is missing."
        assert result == expected_error


class TestFetchIncidents(unittest.TestCase):
    def setUp(self):
        """
        Prepare environment for each test.

        Given:
        - An instance of ZoomMailClient is initialized with test configurations.
        - Common parameters for fetching incidents are defined.
        """
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.client.access_token = "TestToken"
        self.params = {
            "default_mailbox": "default@example.com",
            "first_fetch": "3 days",
            "max_fetch": "50",
        }

    @patch("ZoomMail.demisto.getLastRun")
    @patch("ZoomMail.demisto.setLastRun")
    @patch("ZoomMail.demisto.incidents")
    def test_no_emails_fetched(self, mock_incidents, mock_set_last_run, mock_get_last_run):
        """
        Test the scenario where no emails are fetched.

        When:
        - No new emails are available to fetch.

        Then:
        - Ensure no incidents are created and the last run is updated accordingly.
        """
        mock_get_last_run.return_value = {}
        mock_thread_response = load_test_data("test_data/fetch/fetch_list_response_empty.json")
        self.client.list_emails = MagicMock(return_value=mock_thread_response)

        fetch_incidents(self.client, self.params)

        mock_set_last_run.assert_called_once()
        mock_incidents.assert_called_once()

    @patch("ZoomMail.demisto.getLastRun")
    @patch("ZoomMail.demisto.setLastRun")
    @patch("ZoomMail.demisto.incidents")
    def test_emails_fetched(self, mock_incidents, mock_set_last_run, mock_get_last_run):
        """
        Test fetching emails successfully and creating incidents.

        When:
        - Emails are available to be fetched.

        Then:
        - Incidents should be created based on the fetched emails.
        """
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

        fetch_incidents(self.client, self.params)

        incidents = mock_incidents.call_args[0][0]
        assert len(incidents) == 2
        assert incidents[0]["name"] == "Zoom Encrypted Email"

    @patch("ZoomMail.demisto.getLastRun")
    @patch("ZoomMail.demisto.setLastRun")
    @patch("ZoomMail.demisto.incidents")
    def test_handle_pagination(self, mock_incidents, mock_set_last_run, mock_get_last_run):
        """
        Test handling pagination during incident fetch.

        When:
        - There are more emails to fetch than can be retrieved in one API call.

        Then:
        - Pagination should be handled correctly, ensuring all emails are fetched across multiple API calls.
        """
        mock_get_last_run.return_value = {
            "last_fetch_info": {"internalDate": 1622440000, "ids": []},
            "next_page_token": "abc123",
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
            "test_data/fetch/fetch_email_1.json"
        )
        mock_get_email_message_response_2 = load_test_data(
            "test_data/fetch/fetch_email_2.json"
        )
        self.client.get_email_message = MagicMock(
            side_effect=[
                mock_get_email_message_response_1,
                mock_get_email_message_response_2,
            ]
        )

        fetch_incidents(self.client, self.params)

        # Verify if nextPageToken is handled correctly
        calls = mock_set_last_run.call_args_list
        expected_call = {
            "last_fetch_info": {"internalDate": 1622440000, "ids": []},
            "next_page_token": "abc123",
        }
        # Check that setLastRun was called correctly
        assert len(calls) == 1
        assert calls[0][0][0] == expected_call

    @patch("ZoomMail.demisto.getLastRun")
    @patch("ZoomMail.demisto.setLastRun")
    @patch("ZoomMail.demisto.incidents")
    def test_deduplication_of_ids(self, mock_incidents, mock_set_last_run, mock_get_last_run):
        """
        Test deduplication of message IDs.

        When:
        - Fetched emails include IDs that are already in the last_fetch_info["ids"].

        Then:
        - Ensure no duplicate incidents are created.
        """
        mock_get_last_run.return_value = {
            "last_fetch_info": {
                "internalDate": 1622430000,
                "ids": [
                    "d9e0967700000000_e8332447bb77d2cc_012",
                    "d9e0967700000000_e83324610f26fd57_007"
                ]
            },
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

        fetch_incidents(self.client, self.params)

        incidents = mock_incidents.call_args[0][0]
        assert len(incidents) == 2  # Ensure only new incidents are created

    @patch("ZoomMail.demisto.getLastRun")
    @patch("ZoomMail.demisto.setLastRun")
    @patch("ZoomMail.demisto.incidents")
    def test_filtering_threads(self, mock_incidents, mock_set_last_run, mock_get_last_run):
        """
        Test filtering of threads when fetch_threads is false.

        When:
        - fetch_threads is false.
        - Emails are available to be fetched.

        Then:
        - Ensure only thread starter emails are fetched.
        """
        self.params["fetch_threads"] = False
        mock_get_last_run.return_value = {
            "last_fetch_info": {"internalDate": 1622430000, "ids": []},
            "next_page_token": "",
        }
        mock_list_response = load_test_data("test_data/fetch/fetch_list_response.json")
        self.client.list_emails = MagicMock(return_value=mock_list_response)
        mock_get_email_message_response_1 = load_test_data("test_data/fetch/fetch_email_1.json")
        mock_get_email_message_response_2 = load_test_data("test_data/fetch/fetch_email_2.json")
        mock_get_email_message_response_3 = load_test_data("test_data/fetch/fetch_email_3.json")

        self.client.get_email_message = MagicMock(
            side_effect=[
                mock_get_email_message_response_1,
                mock_get_email_message_response_2,
                mock_get_email_message_response_3,
            ]
        )

        fetch_incidents(self.client, self.params)

        incidents = mock_incidents.call_args[0][0]
        assert len(incidents) == 2  # Ensure only thread starter incidents are created

    @patch("ZoomMail.demisto.getLastRun")
    @patch("ZoomMail.demisto.setLastRun")
    @patch("ZoomMail.demisto.incidents")
    def test_not_filtering_threads(self, mock_incidents, mock_set_last_run, mock_get_last_run):
        """
        Test not filtering of threads when fetch_threads is true.

        When:
        - fetch_threads is false.
        - Emails are available to be fetched.

        Then:
        - Ensure all emails are fetched regardless of being thread starters or not.
        """
        self.params["fetch_threads"] = True
        mock_get_last_run.return_value = {
            "last_fetch_info": {"internalDate": 1, "ids": []},
            "next_page_token": "",
        }
        mock_list_response = load_test_data("test_data/fetch/fetch_list_response.json")
        self.client.list_emails = MagicMock(return_value=mock_list_response)
        mock_get_email_message_response_1 = load_test_data("test_data/fetch/fetch_email_1.json")
        mock_get_email_message_response_2 = load_test_data("test_data/fetch/fetch_email_2.json")
        mock_get_email_message_response_3 = load_test_data("test_data/fetch/fetch_email_3.json")

        self.client.get_email_message = MagicMock(
            side_effect=[
                mock_get_email_message_response_1,
                mock_get_email_message_response_2,
                mock_get_email_message_response_3,
            ]
        )

        fetch_incidents(self.client, self.params)

        incidents = mock_incidents.call_args[0][0]
        assert len(incidents) == 3  # Ensure all emails are fetched


class TestGetEmailThreadCommand(unittest.TestCase):
    def setUp(self):
        """
        Prepare environment for tests by initializing a mock ZoomMailClient.

        Given:
        - An instance of ZoomMailClient is initialized with test configurations.
        """
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.client.access_token = "TestToken"
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
        """
        Test successful retrieval of an email thread.

        When:
        - Retrieving an email thread with valid parameters.

        Then:
        - Ensure the result is successfully parsed and contains expected thread information.
        """
        test_data = load_test_data("test_data/thread/thread_list_response.json")
        mock_get_email_thread.return_value = test_data

        result = get_email_thread_command(self.client, self.args)

        assert isinstance(result, CommandResults)
        assert "Email Thread 1001" in result.readable_output
        assert "MYSTERY_GUID" in result.readable_output

    @patch("ZoomMail.ZoomMailClient.get_email_thread")
    def test_empty_email_thread(self, mock_get_email_thread):
        """
        Test the retrieval of an email thread that has no messages.

        When:
        - The API returns an empty thread.

        Then:
        - Ensure the output indicates that no messages were found.
        """
        test_data = load_test_data("test_data/thread/thread_list_response_empty.json")
        mock_get_email_thread.return_value = test_data

        result = get_email_thread_command(self.client, self.args)

        assert "has no messages" in result.readable_output

    @patch("ZoomMail.ZoomMailClient.get_email_thread")
    def test_email_thread_pagination_handling(self, mock_get_email_thread):
        """
        Test proper handling of pagination tokens when retrieving email threads.

        When:
        - Pagination is required to retrieve all messages in a thread.

        Then:
        - Ensure pagination tokens are handled correctly and all messages are retrieved.
        """
        mock_get_email_thread.return_value = {
            "messages": [{"id": "msg1"}, {"id": "msg2"}],
            "nextPageToken": "def456",
        }

        result = get_email_thread_command(self.client, self.args)

        mock_get_email_thread.assert_called_with(
            "user@example.com", "1001", "full", "Subject,Date", "10", "abc123"
        )
        assert "msg2" in result.readable_output

    def test_missing_thread_id_argument(self):
        """
        Test the response when the required 'thread_id' argument is missing.

        When:
        - The 'thread_id' argument is not provided in the command arguments.

        Then:
        - Ensure a ValueError is raised indicating that both 'email' and 'thread_id' are required.
        """
        self.args.pop("thread_id")

        with self.assertRaises(ValueError) as context:
            get_email_thread_command(self.client, self.args)

        assert "The 'thread_id' argument is required." in str(context.exception)


class TestTrashEmailCommand(unittest.TestCase):
    def setUp(self):
        """
        Prepare environment for tests, creating a mock client.
        Given:
        - An initialized ZoomMailClient with test configurations.
        """
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.client.access_token = "TestToken"
        self.args: dict[str, str] = {
            "email": "user@example.com",
            "message_id": "msg123",
        }

    @patch("ZoomMail.ZoomMailClient.trash_email")
    def test_successful_email_trashing(self, mock_trash_email):
        """
        Test successful trashing of an email.
        When:
        - Trashing an email with a specific email address provided.
        Then:
        - Ensure the email is moved to TRASH and the result is successful.
        """
        mock_trash_email.return_value = {"success": True, "id": "msg123"}

        result = trash_email_command(self.client, self.args)

        assert isinstance(result, CommandResults)
        assert "was moved to TRASH" in result.readable_output

    def test_missing_message_id_argument(self):
        """
        Test response when required message_id argument is missing.
        When:
        - The 'message_id' argument is not provided in the command arguments.
        Then:
        - Ensure a ValueError is raised indicating that both 'email' and 'message_id' are required.
        """
        self.args.pop("message_id")
        with self.assertRaises(ValueError) as context:
            trash_email_command(self.client, self.args)

        assert "The 'message_id' argument is required" in str(context.exception)


class TestListEmailsCommand(unittest.TestCase):
    def setUp(self):
        """
        Prepare environment for tests, creating a mock client.
        Given:
        - An initialized ZoomMailClient with test configurations.
        """
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
        """
        Test successful listing of emails.
        When:
        - Email listing is requested with specific filters.
        Then:
        - Verify the listing is successful and contains expected email messages.
        """
        mock_list_emails.return_value = {
            "messages": [{"id": "msg1", "threadId": "thread1"}, {"id": "msg2", "threadId": "thread2"}]
        }

        result = list_emails_command(self.client, self.args)

        assert isinstance(result, CommandResults)
        assert "msg1" in result.readable_output
        assert "thread1" in result.readable_output

    @patch("ZoomMail.ZoomMailClient.list_emails")
    def test_no_emails_found(self, mock_list_emails):
        """
        Test the scenario where no emails are found.
        When:
        - Email listing is requested but the API returns no messages.
        Then:
        - Verify the output indicates no messages were found.
        """
        mock_list_emails.return_value = {}

        result = list_emails_command(self.client, self.args)

        assert "No messages found" in result.readable_output

    @patch("ZoomMail.ZoomMailClient.list_emails")
    def test_optional_parameters_handling(self, mock_list_emails):
        """
        Test proper handling of optional parameters.
        When:
        - Email listing is requested with the 'include_spam_trash' set to True.
        Then:
        - Ensure the function is called with correct parameters, including the conversion of 'include_spam_trash' to a boolean.
        """
        self.args["include_spam_trash"] = "true"

        mock_list_emails.return_value = {}

        list_emails_command(self.client, self.args)

        assert mock_list_emails.called
        called_with_kwargs = mock_list_emails.call_args[0]
        assert called_with_kwargs[5] is True  # Checking 'include_spam_trash' boolean conversion


class TestGetEmailAttachmentCommand(unittest.TestCase):
    def setUp(self):
        """
        Prepare environment for tests, creating a mock client.
        Given:
        - An initialized ZoomMailClient with test configurations.
        """
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
    def test_successful_attachment_retrieval(self, mock_get_email_attachment):
        """
        Test successful retrieval of an email attachment.
        When:
        - An attachment is requested from a specific email.
        Then:
        - Ensure the attachment is retrieved successfully and matches expected content.
        """
        mock_get_email_attachment.return_value = {
            "data": "SGVsbG8sIHdvcmxkIQ==",  # base64 for "Hello, world!"
            "attachmentId": "2001",
        }

        result = get_email_attachment_command(self.client, self.args)

        assert isinstance(result, CommandResults)
        assert "retrieved successfully" in result.readable_output
        assert result.outputs["attachmentId"] == "2001"

    @patch("ZoomMail.ZoomMailClient.get_email_attachment")
    def test_no_attachment_found(self, mock_get_email_attachment):
        """
        Test the scenario where no attachment is found.
        When:
        - An attachment is requested but the API returns no data.
        Then:
        - Ensure the output indicates that no data was found.
        """
        mock_get_email_attachment.return_value = {}

        result = get_email_attachment_command(self.client, self.args)

        assert "No data found" in result.readable_output

    def test_missing_required_arguments(self):
        """
        Test response when required arguments are missing.
        When:
        - The command is executed with missing 'message_id' or 'attachment_id'.
        Then:
        - Ensure a ValueError is raised indicating that both 'message_id' and 'attachment_id' are required.
        """
        # Missing message_id
        with self.assertRaises(ValueError) as context:
            missing_args = self.args.copy()
            del missing_args["message_id"]
            get_email_attachment_command(self.client, missing_args)
        assert "The 'message_id', and 'attachment_id' arguments are required" in str(context.exception)

        # Missing attachment_id
        with self.assertRaises(ValueError) as context:
            missing_args = self.args.copy()
            del missing_args["attachment_id"]
            get_email_attachment_command(self.client, missing_args)
        assert "The 'message_id', and 'attachment_id' arguments are required" in str(context.exception)


class TestGetMailboxProfileCommand(unittest.TestCase):
    def setUp(self):
        """
        Prepare environment for tests, creating a mock client.
        Given:
        - An initialized ZoomMailClient with test configurations.
        """
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.client.access_token = "TestToken"
        self.args = {"email": "user@example.com"}

    @patch("ZoomMail.ZoomMailClient.get_mailbox_profile")
    def test_successful_mailbox_profile_retrieval(self, mock_get_mailbox_profile):
        """
        Test successful retrieval of a mailbox profile.
        When:
        - A mailbox profile retrieval command is executed with a valid email.
        Then:
        - Verify the command retrieves and displays the mailbox profile as expected.
        """
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


class TestListUsersCommand(unittest.TestCase):
    def setUp(self):
        """
        Prepare environment for tests, creating a mock client.
        Given:
        - An initialized ZoomMailClient with configuration for API connection.
        """
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.client.access_token = "TestToken"
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
        """
        Test successful listing of users.
        When:
        - Requesting to list users with specific filter settings.
        Then:
        - Ensure the users are listed as expected and verify key user information is displayed.
        """
        mock_list_users.return_value = {
            "users": [
                {
                    "email": "user1@example.com",
                    "first_name": "John",
                    "last_name": "Doe",
                    "type": "admin",
                    "status": "active"
                }, {
                    "email": "user2@example.com",
                    "first_name": "Jane",
                    "last_name": "Smith",
                    "type": "member",
                    "status": "inactive"},
            ]
        }

        result = list_users_command(self.client, self.args)

        assert isinstance(result, CommandResults)
        assert "user1@example.com" in result.readable_output
        assert "John" in result.readable_output

    @patch("ZoomMail.ZoomMailClient.list_users")
    def test_no_users_found(self, mock_list_users):
        """
        Test the scenario where no users are found.
        When:
        - Requesting to list users but the response contains no user data.
        Then:
        - Ensure the output indicates no users were found.
        """
        mock_list_users.return_value = {"users": []}

        result = list_users_command(self.client, self.args)

        assert "No entries" in result.readable_output

    @patch("ZoomMail.ZoomMailClient.list_users")
    def test_user_listing_with_pagination(self, mock_list_users):
        """
        Test user listing with pagination.
        When:
        - Requesting to list users with a pagination token to fetch additional pages.
        Then:
        - Ensure pagination is handled correctly and subsequent user data is retrieved.
        """
        mock_list_users.return_value = {
            "users": [
                {
                    "email": "user3@example.com",
                    "first_name": "Alice",
                    "last_name": "Johnson",
                    "type": "admin",
                    "status": "active"
                }
            ],
            "nextPageToken": "abc123",
        }
        self.args["next_page_token"] = "abc123"

        result = list_users_command(self.client, self.args)

        mock_list_users.assert_called_with("active", 50, "admin", "1", "email,status", "", "pro")
        assert "Alice" in result.readable_output


class TestProcessAttachments(unittest.TestCase):
    def setUp(self):
        """
        Prepare test environment.
        Given:
        - An initialized ZoomMailClient with configuration for API connection.
        - Mocked email details including attachments to process.
        """
        self.client = ZoomMailClient(
            base_url="https://api.example.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            account_id="test_account_id",
            default_email="default@example.com",
        )
        self.client.access_token = "TestToken"
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
        """
        Test handling errors while processing attachments.
        When:
        - Retrieval of an attachment fails due to an API error.
        Then:
        - No attachments are processed and an error is logged.
        """
        mock_get_email_attachment.side_effect = Exception("Failed to retrieve attachment")
        result = process_attachments(self.message, self.client, self.email)
        assert len(result) == 0  # Verify no attachments processed
        mock_demisto_error.assert_called()  # Error handling should be invoked

    @patch("ZoomMail.demisto.error")
    @patch("ZoomMail.ZoomMailClient.get_email_attachment")
    def test_process_attachments_success(
        self, mock_get_email_attachment, mock_demisto_error
    ):
        """
        Test successful processing of email attachments.
        When:
        - Attachment data is retrieved successfully.
        Then:
        - Attachments are processed and added to the result without any errors.
        """
        encoded_data = base64.urlsafe_b64encode(b"Test file content").decode("ascii")
        mock_get_email_attachment.return_value = {"data": encoded_data}
        result = process_attachments(self.message, self.client, self.email)
        assert len(result) == 2  # Ensure both attachments are processed
        assert result[0]["name"] == "file1.pdf"
        assert result[1]["name"] == "file2.pdf"
        mock_demisto_error.assert_not_called()  # No error should be logged


class TestCreateEmailMessage(unittest.TestCase):
    def setUp(self):
        """
        Given:
        - An email configuration including sender, recipient, subject, body text, HTML content, and attachment IDs.
        Prepare environment for tests, setting up the necessary email components.
        """
        self.from_email = "from@example.com"
        self.to_email = "to@example.com"
        self.subject = "Test Subject"
        self.body_text = "This is a plain text body."
        self.html_text = "<p>This is an HTML body.</p>"
        self.attachment_ids = ["attach1", "attach2"]

    @patch("ZoomMail.attach_files_to_email")
    def test_create_plain_text_email(self, mock_attach_files):
        """
        When:
        - Creating a plain text email without HTML or attachments.
        Then:
        - Verify the email object is correctly formed with the appropriate headers and body.
        """
        email = create_email_message(
            self.from_email, self.to_email, self.subject, self.body_text, None, []
        )
        assert isinstance(email, MIMEMultipart)
        assert mock_attach_files.called
        assert email["From"] == self.from_email
        assert email["To"] == self.to_email
        assert email["Subject"] == self.subject
        assert len(email.get_payload()) == 1
        assert isinstance(email.get_payload()[0], MIMEText)
        assert email.get_payload()[0].get_payload() == self.body_text

    @patch("ZoomMail.attach_files_to_email")
    def test_create_html_email(self, mock_attach_files):
        """
        When:
        - Creating an email with HTML content only.
        Then:
        - Verify the email object is correctly formed with HTML content.
        """
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
        """
        When:
        - Creating an email with both text, HTML content, and attachments.
        Then:
        - Verify the email object includes all parts and attachments are handled correctly.
        """
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
        """
        When:
        - Creating an email with all elements: plain text, HTML, and attachments.
        Then:
        - Verify the multipart email is correctly constructed with multiple payloads.
        """
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
        """
        Given:
        - A MIMEMultipart email message and a list of attachment IDs.
        Prepare environment for testing file attachment functionality.
        """
        self.message = MIMEMultipart()
        self.attachment_ids = ["123", "456", "789"]

    @patch("ZoomMail.demisto.getFilePath")
    @patch("ZoomMail.attach_file")
    def test_attach_files_success(self, mock_attach_file, mock_get_file_path):
        """
        When:
        - Attaching files to an email, and all files are found.
        Then:
        - Verify that all files are attached successfully and the correct methods are called.
        """
        mock_get_file_path.side_effect = [
            {"path": "/path/to/file1", "name": "file1.txt"},
            {"path": "/path/to/file2", "name": "file2.txt"},
            {"path": "/path/to/file3", "name": "file3.txt"},
        ]

        attach_files_to_email(self.message, self.attachment_ids)

        assert mock_attach_file.call_count == 3
        mock_attach_file.assert_any_call(self.message, "/path/to/file1", "file1.txt")
        mock_attach_file.assert_any_call(self.message, "/path/to/file2", "file2.txt")
        mock_attach_file.assert_any_call(self.message, "/path/to/file3", "file3.txt")

    @patch("ZoomMail.demisto.getFilePath")
    @patch("ZoomMail.attach_file")
    def test_attach_files_no_files_found(self, mock_attach_file, mock_get_file_path):
        """
        When:
        - Attempting to attach files, but no files are found.
        Then:
        - Verify that no files are attached and attach_file method is not called.
        """
        mock_get_file_path.return_value = None

        attach_files_to_email(self.message, self.attachment_ids)

        mock_attach_file.assert_not_called()

    @patch("ZoomMail.demisto.getFilePath")
    @patch("ZoomMail.attach_file")
    def test_attach_files_partial_files_found(
        self, mock_attach_file, mock_get_file_path
    ):
        """
        When:
        - Attempting to attach files, but only some of the files are found.
        Then:
        - Verify that only the found files are attached and the attach_file method is called correctly for those files.
        """
        mock_get_file_path.side_effect = [
            {"path": "/path/to/file1", "name": "file1.txt"},
            None,
            {"path": "/path/to/file3", "name": "file3.txt"},
        ]

        attach_files_to_email(self.message, self.attachment_ids)

        assert mock_attach_file.call_count == 2
        mock_attach_file.assert_any_call(self.message, "/path/to/file1", "file1.txt")
        mock_attach_file.assert_any_call(self.message, "/path/to/file3", "file3.txt")


class TestAttachFile(unittest.TestCase):
    def setUp(self):
        """
        Given:
        - A new MIMEMultipart message for testing attachment functionalities.
        Prepare environment for testing the attachment of a single file to an email message.
        """
        self.message = MIMEMultipart()

    @patch(
        "builtins.open", new_callable=unittest.mock.mock_open, read_data="file content"
    )
    @patch("ZoomMail.MIMEBase")
    @patch("ZoomMail.encoders.encode_base64")
    def test_attach_file(self, mock_encode_base64, mock_mime_base, mock_open):
        """
        When:
        - Attaching a file to an email message using the attach_file function.
        Then:
        - Ensure the file is opened, read, and encoded correctly.
        - Verify the MIME part is created with appropriate headers and attached to the message.
        """
        # Configure the MIMEBase mock to simulate file attachment behavior.
        mock_part = MagicMock(spec=MIMEBase)
        mock_mime_base.return_value = mock_part

        attach_file(self.message, "/fake/path/to/file.txt", "file.txt")

        # Validate file opening and content handling.
        mock_open.assert_called_once_with("/fake/path/to/file.txt", "rb")
        mock_mime_base.assert_called_once_with("application", "octet-stream")
        mock_part.set_payload.assert_called_once_with("file content")
        mock_encode_base64.assert_called_once_with(mock_part)
        mock_part.add_header.assert_called_once_with(
            "Content-Disposition", "attachment", filename="file.txt"
        )

        # Confirm the MIME part is correctly attached to the MIMEMultipart message.
        assert len(self.message.get_payload()) == 1


class TestMainFunction(unittest.TestCase):
    @patch("ZoomMail.demisto")
    def test_command_routing(self, mock_demisto):
        """
        Given:
        - Command name 'test-module' and necessary parameters and arguments are set in the demisto mock.
        When:
        - main function is called.
        Then:
        - Ensure that the correct function for 'test-module' is called and returns the expected result.
        """
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
        """
        Given:
        - A command 'non-existent-command' that is not implemented.
        When:
        - main function is called.
        Then:
        - An error is raised indicating the command is not implemented.
        """
        mock_demisto.command.return_value = "non-existent-command"
        with self.assertRaises(NotImplementedError):
            main()

    @patch("ZoomMail.demisto")
    def test_error_handling(self, mock_demisto):
        """
        Given:
        - An exception is expected to be thrown by the 'test-module' command.
        When:
        - main function is called.
        Then:
        - The exception is handled properly and the error message is processed.
        """
        mock_demisto.command.return_value = "test-module"
        mock_demisto.params.return_value = {}
        mock_demisto.args.return_value = {}

        # Simulate an exception in the command function
        with patch(
            "ZoomMail.the_testing_module", side_effect=DemistoException("Error")
        ), patch("ZoomMail.return_error") as mock_return_error:
            main()
            mock_return_error.assert_called_once()


class TestBase64Decoding(unittest.TestCase):

    def test_decode_base64_normal(self):
        # Test with a normal base64 encoded string
        encoded = base64.b64encode(b'hello world').decode('utf-8')
        result = decode_base64(encoded)
        assert result == "hello world"

    def test_decode_base64_incorrect_padding(self):
        # Test base64 string with incorrect padding
        encoded = base64.b64encode(b'hello world').decode('utf-8').rstrip('=')
        result = decode_base64(encoded)
        assert result == "hello world"

    def test_decode_base64_invalid_characters(self):
        # Test base64 string with invalid characters
        encoded = 'aGVsbG8gd29ybGQ$'
        result = decode_base64(encoded)
        assert result == "hello world"

    def test_decode_base64_special_characters(self):
        # Test base64 string with special URL characters
        encoded = base64.urlsafe_b64encode(b'hello?world!').decode('utf-8')
        result = decode_base64(encoded)
        assert result == "hello?world!"

    def test_decode_base64_empty_string(self):
        # Test with an empty string
        result = decode_base64('')
        assert result == ""

    def test_correct_base64_errors(self):
        # Test the correction of non-base64 characters
        encoded = 'aGVsbG8gd29ybGQ$=='
        corrected = correct_base64_errors(encoded)
        assert set(corrected) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        assert len(corrected) % 4 == 0

    def test_safe_bytes_to_string(self):
        # Test converting bytes to string safely
        byte_data = b'hello world'
        result = safe_bytes_to_string(byte_data)
        assert result == "hello world"

    def test_safe_bytes_to_string_decoding_error(self):
        # Test safe byte to string conversion with non-utf8 encodable bytes
        byte_data = bytes([0xff, 0xfe, 0xfd])
        result = safe_bytes_to_string(byte_data)
        assert result == ""


if __name__ == "__main__":
    unittest.main()
