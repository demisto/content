import unittest
from typing import Any
from unittest.mock import patch, MagicMock
import json

from CommonServerPython import CommandResults
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


class TestCommandFunctions(unittest.TestCase):
    @patch("ZoomMail.ZoomMailClient.obtain_access_token")
    @patch("ZoomMail.demisto.args")
    @patch("ZoomMail.demisto.command")
    def test_the_testing_module(
        self, mock_command, mock_args, mock_obtain_access_token
    ):
        # Setup mocks
        mock_obtain_access_token.return_value = {"success": True, "token": "test_token"}
        mock_args.return_value = {}
        mock_command.return_value = "test-module"

        # Assuming the_testing_module is a callable that checks token obtaining
        result = the_testing_module(
            ZoomMailClient("url", "id", "secret", "account", "testing@zmail.com"), {}
        )

        # Verify results
        assert result == "ok"

    # Add more tests for other command functions, particularly focusing on handling various API responses and errors.


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
                    "messages": [
                        {"id": "123", "threadId": "123"}
                    ],
                    "nextPageToken": "abc123",
                },
                {
                    "messages": [
                        {"id": "124", "threadId": "124"}
                    ]
                },
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
        assert calls[0][0][0] == expected_call  # Accessing the first argument of the first call


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
        self.args["include_spam_trash"] = "true"  # Adjust for boolean handling in function

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


if __name__ == "__main__":
    unittest.main()
