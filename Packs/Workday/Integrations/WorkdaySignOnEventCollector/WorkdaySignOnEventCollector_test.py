import re
import time
import unittest
import random
from unittest import TestCase, mock
from unittest.mock import patch, Mock

from datetime import datetime, timezone, timedelta
from freezegun import freeze_time

from CommonServerPython import DemistoException
import demistomock as demisto  # noqa: F401
from Packs.Workday.Integrations.WorkdaySignOnEventCollector import WorkdaySignOnEventCollector
from WorkdaySignOnEventCollector import Client, process_events, convert_to_json, fetch_sign_on_logs, DATE_FORMAT, main


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
    @freeze_time("2023-08-01 12:00:00")
    def test_get_from_time(self, mock_http_request):
        """Test the get_from_time nested function."""
        mock_http_request.return_value = '<sample successful response>'

        self.client.test_connectivity()

        # Extract the from_time from the request body using regex
        request_body = mock_http_request.call_args[1]['data']
        match = re.search(r'<bsvc:From_DateTime>([^<]+)</bsvc:From_DateTime>', request_body)
        from_time = match.group(1) if match else None

        expected_from_time = (datetime.now(tz=timezone.utc) - timedelta(seconds=5)).strftime(DATE_FORMAT)

        self.assertEqual(expected_from_time, from_time)

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


class TestProcessEvent(unittest.TestCase):

    def test_empty_list(self):
        """
        Given an empty list, the function should make no changes.
        """
        events = []
        process_events(events)
        self.assertEqual(events, [])

    def test_event_without_signon_datetime(self):
        """
        Given a list with an event that lacks 'Signon_DateTime', the function should add '_time' key with a None value.
        """
        events = [{'User_Name': 'user1'}]
        process_events(events)
        self.assertEqual(events, [{'User_Name': 'user1', '_time': None}])

    def test_event_with_signon_datetime(self):
        """
        Given a list with an event that has 'Signon_DateTime', the function should add '_time' key with the same value.
        """
        events = [{'User_Name': 'user1', 'Signon_DateTime': '2023-08-01T12:00:00'}]
        process_events(events)
        self.assertEqual(events, [
            {'User_Name': 'user1', 'Signon_DateTime': '2023-08-01T12:00:00', '_time': '2023-08-01T12:00:00'}])

    def test_multiple_events(self):
        """
        Given a list with multiple events, the function should process each event appropriately.
        """
        events = [
            {'User_Name': 'user1'},
            {'User_Name': 'user2', 'Signon_DateTime': '2023-08-01T13:00:00'}
        ]
        process_events(events)
        self.assertEqual(events, [
            {'User_Name': 'user1', '_time': None},
            {'User_Name': 'user2', 'Signon_DateTime': '2023-08-01T13:00:00', '_time': '2023-08-01T13:00:00'}
        ])

    def test_already_has_time_key(self):
        """
        Given a list with an event that already has a '_time' key, the function should overwrite its value.
        """
        events = [{'User_Name': 'user1', '_time': '2023-08-01T11:00:00'}]
        process_events(events)
        self.assertEqual(events, [{'User_Name': 'user1', '_time': None}])


class TestConvertToJson(unittest.TestCase):

    def test_empty_string(self):
        """
        Given an empty string, the function should raise a ValueError.
        """
        with self.assertRaises(ValueError):
            convert_to_json("")

    def test_invalid_xml(self):
        """
        Given an invalid XML string, the function should raise a descriptive error.
        """
        with self.assertRaisesRegex(Exception, "Error parsing XML to JSON: .*"):
            convert_to_json("<invalid><xml></xml>")

    def test_valid_xml_without_signon_data(self):
        """
        Given a valid XML without 'Workday_Account_Signon' data, the function should raise a ValueError.
        """
        xml_data = """
        <Envelope>
            <Body>
                <Get_Workday_Account_Signons_Response>
                    <Response_Data></Response_Data>
                </Get_Workday_Account_Signons_Response>
            </Body>
        </Envelope>
        """
        with self.assertRaises(ValueError):
            convert_to_json(xml_data)

    def test_valid_xml_with_signon_data(self):
        """
        Given a valid XML with 'Workday_Account_Signon' data, the function should return the JSON representation.
        """
        xml_data = """
        <Envelope>
            <Body>
                <Get_Workday_Account_Signons_Response>
                    <Response_Data>
                        <Workday_Account_Signon>
                            <User_Name>user1</User_Name>
                        </Workday_Account_Signon>
                    </Response_Data>
                </Get_Workday_Account_Signons_Response>
            </Body>
        </Envelope>
        """
        full_response, signon_data = convert_to_json(xml_data)
        self.assertIn('Envelope', full_response)
        self.assertEqual(signon_data, {'User_Name': 'user1'})

    def test_valid_dict_without_signon_data(self):
        """
        Given a valid dict without 'Workday_Account_Signon' data, the function should raise a ValueError.
        """
        response_dict = {
            'Get_Workday_Account_Signons_Response': {
                'Response_Data': {}
            }
        }
        with self.assertRaises(ValueError):
            convert_to_json(response_dict)

    def test_valid_dict_with_signon_data(self):
        """
        Given a valid dict with 'Workday_Account_Signon' data, the function should return the dict representation.
        """
        response_dict = {
            'Get_Workday_Account_Signons_Response': {
                'Response_Data': {
                    'Workday_Account_Signon': {
                        'User_Name': 'user1'
                    }
                }
            }
        }
        full_response, signon_data = convert_to_json(response_dict)
        self.assertIn('Get_Workday_Account_Signons_Response', full_response)
        self.assertEqual(signon_data, {'User_Name': 'user1'})


class TestFetchSignOnLogs(unittest.TestCase):

    def test_happy_path(self,):
        mock_client = Mock()
        pages = 3
        items_per_page = 2
        mock_responses = [generate_mock_responses(pages=pages, items=items_per_page) for _ in range(pages)]
        mock_client.retrieve_events.side_effect = [
            (res['Get_Workday_Account_Signons_Response']['Response_Data']['Workday_Account_Signon'], pages) for res in
            mock_responses]

        # Action

        logs = fetch_sign_on_logs(mock_client, 6, '2023-08-01', '2023-08-10')

        # Assert
        self.assertEqual(len(logs), 6)

    def test_single_page(self):
        mock_client = Mock()
        pages = 1
        items_per_page = 2
        mock_responses = [generate_mock_responses(pages=pages, items=items_per_page) for _ in range(pages)]
        mock_client.retrieve_events.side_effect = [
            (res['Get_Workday_Account_Signons_Response']['Response_Data']['Workday_Account_Signon'], pages) for res in
            mock_responses]

        logs = fetch_sign_on_logs(mock_client, 2, '2023-08-01', '2023-08-10')

        self.assertEqual(len(logs), 2)

    def test_empty_logs(self):
        mock_client = Mock()
        pages = 1
        items_per_page = 0
        mock_responses = [generate_mock_responses(pages=pages, items=items_per_page) for _ in range(pages)]
        mock_client.retrieve_events.side_effect = [
            (res['Get_Workday_Account_Signons_Response']['Response_Data']['Workday_Account_Signon'], pages) for res in
            mock_responses]

        logs = fetch_sign_on_logs(mock_client, 5, '2023-08-01', '2023-08-10')

        self.assertEqual(len(logs), 0)

    def test_limit_exceeds_total_logs(self):
        mock_client = Mock()
        pages = 1
        items_per_page = 2
        mock_responses = [generate_mock_responses(pages=pages, items=items_per_page) for _ in range(pages)]
        mock_client.retrieve_events.side_effect = [
            (res['Get_Workday_Account_Signons_Response']['Response_Data']['Workday_Account_Signon'], pages) for res in
            mock_responses]

        logs = fetch_sign_on_logs(mock_client, 1, '2023-08-01', '2023-08-10')

        self.assertEqual(len(logs), 2)

    def test_error_from_client(self):
        mock_client = Mock()
        mock_client.retrieve_events.side_effect = DemistoException("Error fetching logs")

        with self.assertRaises(DemistoException) as context:
            fetch_sign_on_logs(mock_client, 5, '2023-08-01', '2023-08-10')

        self.assertTrue("Error fetching logs" in str(context.exception))


# @patch('WorkdaySignOnEventCollector.Client._http_request')
# def test_test_module_command(mocker, mock_http_request):
#     # Mocked params
#     mocked_params = {
#         'base_url': 'https://sample-workday-url.com/ccx/api/v1/sample-tenant',
#         'credentials': {
#             'identifier': 'sample_username',
#             'password': 'sample_password'
#         },
#         'token': {
#             'password': 'sample_refresh_token'
#         },
#         'insecure': False,
#         'proxy': False,
#         'max_fetch': '1000',
#         'eventFetchInterval': '1'
#     }
#
#     # Mock demisto methods
#     mocker.patch.object(demisto, 'params', return_value=mocked_params)
#     mocker.patch.object(demisto, 'command', return_value='test-module')
#
#     # Mock the return_results function to simply collect its arguments
#     results = []
#
#     def mock_return_results(result):
#         results.append(result)
#
#     mocker.patch.object(WorkdaySignOnEventCollector, 'return_results', side_effect=mock_return_results)
#
#     # Mock the Client class and its method
#     mock_http_request.return_value = 'ok'
#
#     main()
#
#     # Assert that return_results was called with 'ok'
#     assert results[0] == 'ok'


if __name__ == '__main__':
    unittest.main()
