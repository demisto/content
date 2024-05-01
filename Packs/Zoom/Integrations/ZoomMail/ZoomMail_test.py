import unittest
from unittest.mock import patch
from ZoomMail import ZoomMailClient

class TestZoomMailClient(unittest.TestCase):
    def setUp(self):
        self.client = ZoomMailClient(
            base_url="https://api.zoom.us/v2",
            client_id="test_id",
            client_secret="test_secret",
            account_id="test_account",
            verify=False,
            proxy=False
        )

    @patch('ZoomMail.BaseClient._http_request')
    def test_obtain_access_token_success(self, mock_request):
        mock_request.return_value = {
            "access_token": "abcdef12345",
            "expires_in": 3600
        }
        token_info = self.client.obtain_access_token()
        self.assertTrue(token_info['success'])
        self.assertEqual(token_info['token'], "abcdef12345")

    @patch('ZoomMail.BaseClient._http_request')
    def test_obtain_access_token_failure(self, mock_request):
        mock_request.return_value = {}
        token_info = self.client.obtain_access_token()
        self.assertFalse(token_info['success'])
        self.assertIn("error", token_info)

    @patch('ZoomMail.ZoomMailClient._http_request')
    def test_get_email_thread(self, mock_request):
        mock_request.return_value = {'messages': [{'id': '123'}]}
        response = self.client.get_email_thread(email='me', thread_id='123')
        self.assertIn('messages', response)
        self.assertEqual(len(response['messages']), 1)

    @patch('ZoomMail.ZoomMailClient._http_request')
    def test_trash_email(self, mock_request):
        mock_request.return_value = {'success': True}
        response = self.client.trash_email(email='me', message_id='123')
        self.assertEqual(response['success'], True)

    #TODO: More tests for other methods such as send_email, list_emails, etc.


if __name__ == '__main__':
    unittest.main()