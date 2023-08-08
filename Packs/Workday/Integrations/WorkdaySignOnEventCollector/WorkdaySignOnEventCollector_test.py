import time
import unittest
import random
from unittest.mock import patch, Mock
from dicttoxml import dicttoxml
from xml.dom.minidom import parseString
from datetime import datetime, timezone
from WorkdaySignOnEventCollector import Client


class TestClient(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://workday.example.com"
        self.verify_certificate = False
        self.proxy = False
        self.tenant_name = "test_tenant"
        self.token = "test_token"
        self.username = "test_username"
        self.password = "test_password"
        self.client = Client(
            base_url=self.base_url,
            verify_certificate=self.verify_certificate,
            proxy=self.proxy,
            tenant_name=self.tenant_name,
            token=self.token,
            username=self.username,
            password=self.password,
        )

    @patch('WorkdaySignOnEventCollector.Client._http_request')
    def test_retrieve_events(self, mock_http_request):
        mock_response = {
            'Get_Workday_Account_Signons_Response': {
                'Response_Data': {
                    'Workday_Account_Signon': {
                        'User_Name': 'test_user',
                        'Signon_DateTime': '2023-08-01T12:00:00',
                        'Signoff_DateTime': '2023-08-01T13:00:00',
                        'Successful': 'true',
                        # Add more fields as needed...
                    }
                },
                'Response_Results': {
                    'Total_Pages': '1000.00'
                }
            }
        }

        # # Convert the mock_response dictionary to XML string
        # xml_response = parseString(dicttoxml(mock_response)).toprettyxml()
        mock_http_request.return_value = mock_response

        account_signon_data, total_pages = self.client.retrieve_events(page=1, count=1, to_time=None, from_time=None)

        # Note: you might need to adjust these assertions depending on the output of convert_to_json function.
        self.assertEqual(account_signon_data, mock_response['Get_Workday_Account_Signons_Response']['Response_Data'][
            'Workday_Account_Signon'])
        self.assertEqual(total_pages, 1)

        mock_http_request.assert_called_once()

    @patch('WorkdaySignOnEventCollector.Client._http_request')
    def test_test_connectivity(self, mock_http_request):
        mock_http_request.return_value = 'ok'

        result = self.client.test_connectivity()

        self.assertEqual(result, 'ok')

        mock_http_request.assert_called_once()

    @patch('WorkdaySignOnEventCollector.Client._http_request')
    def test_retrieve_events_performance(self, mock_http_request: Mock) -> None:
        """
        Test the performance of the retrieve_events function by simulating multiple pages of responses.
        The execution time is checked against a known value to assert performance requirements.

        :param mock_http_request: Mocked version of the _http_request method from the Client class.
        """
        items = 10000
        pages = 25
        mock_responses = [generate_mock_responses(pages=pages, items=items) for _ in
                          range(pages)]  # Generate n mock responses
        mock_http_request.side_effect = mock_responses

        start_time = time.time()  # Start the timer
        total_fetched_events = 0

        for i in range(pages):
            account_signon_data, total_pages = self.client.retrieve_events(page=i + 1, count=1, to_time=None,
                                                                           from_time=None)
            total_fetched_events += len(account_signon_data)
            self.assertEqual(account_signon_data,
                             mock_responses[i]['Get_Workday_Account_Signons_Response']['Response_Data'][
                                 'Workday_Account_Signon'])
            self.assertEqual(total_pages, 1)

        end_time = time.time()  # End the timer
        time_taken = end_time - start_time  # Calculate time delta

        known_value = 0.75  # Replace with the known value you want to compare with (in seconds)
        self.assertLess(time_taken, known_value, f"Execution took longer than expected: {time_taken} seconds")

        self.assertEqual(mock_http_request.call_count, pages)
        self.assertEqual(total_fetched_events, 250000)


def generate_mock_responses(pages, items):
    """
    Generate a response with n pages of data.

    Args:
        pages (int): The number of pages to generate.
        items (int): The number of pages to generate.

    Returns:
        dict: A mock response.
    """
    # Ensure repeatability
    random.seed(1)

    signons = []

    for _ in range(items):
        signon = {
            'User_Name': f'test_user_{random.randint(1, 100)}',
            'Signon_DateTime': '2023-08-01T12:00:00',
            'Signoff_DateTime': '2023-08-01T13:00:00',
            'Successful': random.choice(['true', 'false']),
            # Add more fields as needed...
        }
        signons.append(signon)

    response = {
        'Get_Workday_Account_Signons_Response': {
            'Response_Data': {
                'Workday_Account_Signon': signons
            },
            'Response_Results': {
                'Total_Pages': str(pages)
            }
        }
    }

    return response


if __name__ == '__main__':
    unittest.main()
