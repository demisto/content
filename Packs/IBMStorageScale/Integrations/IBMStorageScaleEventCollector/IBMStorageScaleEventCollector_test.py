import pytest
import demistomock as demisto
from typing import Dict, Any, List, Tuple
from pytest_mock import MockerFixture
import httpx

from IBMStorageScaleEventCollector import main, Client, CommandResults, arg_to_number
from Packs.IBMStorageScale.Integrations.IBMStorageScaleEventCollector import IBMStorageScaleEventCollector

pytestmark = pytest.mark.asyncio


# --- HELPER FUNCTIONS ---

def mock_client(mocker: MockerFixture, params: Dict[str, Any]) -> Client:
    """Helper function to create a mocked Client instance."""
    mocker.patch.object(demisto, 'params', return_value=params)
    return Client(
        server_url=params.get('server_url'),
        auth=(params.get('credentials', {}).get('identifier'), params.get('credentials', {}).get('password')),
        verify=not params.get('insecure', False),
        proxy=params.get('proxy', False)
    )


def mock_api_response(events: List[Dict[str, Any]], next_url: str = None) -> httpx.Response:
    """Helper to create a mock httpx.Response for a successful API call."""
    paging = {"next": next_url} if next_url is not None else {}
    response_json = {
        "auditLogRecords": events,
        "paging": paging
    }
    return httpx.Response(200, json=response_json)


def mock_http_status_error(status_code: int) -> httpx.HTTPStatusError:
    """Helper to create a mock httpx.HTTPStatusError."""
    return httpx.HTTPStatusError(
        message=f"Error {status_code}",
        request=httpx.Request('GET', 'https://test.com'),
        response=httpx.Response(status_code)
    )


# --- TEST CLASSES ---

class TestTestModule:
    """Unit tests for the test-module command."""

    async def test_test_module_success(self, mocker: MockerFixture):
        """
        Given:
            - A client configured with valid credentials.
        When:
            - The test-module command is executed.
            - The API returns a successful (200 OK) response.
        Then:
            - The command should complete successfully and return 'ok'.
        """
        # Arrange
        params = {'server_url': 'https://test.com', 'credentials': {'identifier': 'user', 'password': 'pw'}}
        client = mock_client(mocker, params)
        mocker.patch('httpx.AsyncClient.get', return_value=mock_api_response([]))

        # Act
        await client.test_connection()
        # No exception means success

    async def test_test_module_auth_error(self, mocker: MockerFixture):
        """
        Given:
            - A client configured with invalid credentials.
        When:
            - The test-module command is executed.
            - The API returns an authorization error (401 Unauthorized).
        Then:
            - The command should raise a DemistoException with an appropriate message.
        """
        # Arrange
        params = {'server_url': 'https://test.com', 'credentials': {'identifier': 'user', 'password': 'bad_pw'}}
        client = mock_client(mocker, params)
        mocker.patch('httpx.AsyncClient.get', side_effect=mock_http_status_error(401))

        # Act & Assert
        with pytest.raises(demisto.DemistoException, match='Authorization Error'):
            await client.test_connection()

    async def test_test_module_connection_error(self, mocker: MockerFixture):
        """
        Given:
            - A client configured with an invalid server URL.
        When:
            - The test-module command is executed.
            - The HTTP client raises a connection error.
        Then:
            - The command should raise a DemistoException with a connection error message.
        """
        # Arrange
        params = {'server_url': 'https://invalid-url.com', 'credentials': {'identifier': 'user', 'password': 'pw'}}
        client = mock_client(mocker, params)
        mocker.patch('httpx.AsyncClient.get', side_effect=httpx.RequestError("Connection Failed", request=mocker.MagicMock()))

        # Act & Assert
        with pytest.raises(demisto.DemistoException, match='Connection Error'):
            await client.test_connection()


class TestFetchEvents:
    """Unit tests for the fetch-events command."""

    @staticmethod
    def test_data() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Provides test data for fetch events."""
        page1_events = [{'oid': i, 'entryTime': f'2023-01-01T12:00:0{i}Z'} for i in range(2)]
        page2_events = [{'oid': i, 'entryTime': f'2023-01-01T12:00:1{i}Z'} for i in range(2, 4)]
        return page1_events, page2_events

    async def test_fetch_events_multiple_pages(self, mocker: MockerFixture):
        """
        Given:
            - A fetch-events command run.
            - The API has two pages of events.
        When:
            - The fetch_events command is executed.
        Then:
            - It should fetch all events from both pages.
            - It should add the '_time' field to each event.
            - It should call send_events_to_xsiam with the combined list of events.
        """
        # Arrange
        params = {'server_url': 'https://test.com', 'credentials': {}, 'max_fetch': 100}
        client = mock_client(mocker, params)
        send_events_mock = mocker.patch.object(IBMStorageScaleEventCollector, 'send_events_to_xsiam')
        page1_events, page2_events = self.test_data()

        async_client_mock = mocker.patch('httpx.AsyncClient').__enter__.return_value
        async_client_mock.get.side_effect = [
            mock_api_response(page1_events, next_url='https://test.com/api?page=2'),
            mock_api_response(page2_events, next_url=None),
            mock_api_response(page2_events, next_url=None),
        ]

        # Act
        await client.fetch_events(max_events=100)

        # Assert
        assert send_events_mock.call_count == 1
        sent_events = send_events_mock.call_args[0][0]
        assert len(sent_events) == 4
        assert all('_time' in event for event in sent_events)

    async def test_fetch_events_reaches_limit(self, mocker: MockerFixture):
        """
        Given:
            - A fetch-events command run with a max_fetch limit of 2.
            - The API has more than 2 events available across multiple pages.
        When:
            - The fetch_events command is executed.
        Then:
            - It should fetch only 2 events.
            - It should log that more events are available.
        """
        # Arrange
        params = {'server_url': 'https://test.com', 'credentials': {}, 'max_fetch': 2}
        client = mock_client(mocker, params)
        send_events_mock = mocker.patch.object(IBMStorageScaleEventCollector, 'send_events_to_xsiam')
        info_log_mock = mocker.patch.object(demisto, 'info')
        page1_events, _ = self.test_data()

        async_client_mock = mocker.patch('httpx.AsyncClient').__enter__.return_value
        async_client_mock.get.side_effect = [
            mock_api_response(page1_events, next_url='https://test.com/api?page=2'),
        ]

        # Act
        await client.fetch_events(max_events=2)

        # Assert
        sent_events = send_events_mock.call_args[0][0]
        assert len(sent_events) == 2
        info_log_mock.assert_any_call("Fetch cycle reached the event limit. More events may be available on the server.")

    async def test_fetch_events_producer_fails(self, mocker: MockerFixture):
        """
        Given:
            - A fetch-events command run.
        When:
            - The producer task fails with an HTTP 500 error while discovering pages.
        Then:
            - The fetch should stop gracefully.
            - Any events collected before the failure should still be sent.
        """
        # Arrange
        params = {'server_url': 'https://test.com', 'credentials': {}, 'max_fetch': 100}
        client = mock_client(mocker, params)
        send_events_mock = mocker.patch.object(IBMStorageScaleEventCollector, 'send_events_to_xsiam')
        error_log_mock = mocker.patch.object(demisto, 'error')
        page1_events, _ = self.test_data()

        async_client_mock = mocker.patch('httpx.AsyncClient').__enter__.return_value
        async_client_mock.get.side_effect = [
            mock_api_response(page1_events, next_url='https://test.com/api?page=2'),  # Worker success
            mock_http_status_error(500),  # Producer failure
        ]

        # Act
        await client.fetch_events(max_events=100)

        # Assert
        error_log_mock.assert_called_with('Producer failed to get next page link: Error 500')
        sent_events = send_events_mock.call_args[0][0]
        assert len(sent_events) == 2  # Only events from the first page are sent

    async def test_fetch_events_malformed_response(self, mocker: MockerFixture):
        """
        Given:
            - A fetch-events command run.
        When:
            - The API returns a malformed JSON response (e.g., missing 'auditLogRecords').
        Then:
            - The integration should handle the error gracefully and not crash.
            - An error should be logged.
        """
        # Arrange
        params = {'server_url': 'https://test.com', 'credentials': {}, 'max_fetch': 100}
        client = mock_client(mocker, params)
        send_events_mock = mocker.patch.object(IBMStorageScaleEventCollector, 'send_events_to_xsiam')
        error_log_mock = mocker.patch.object(demisto, 'error')

        malformed_response = httpx.Response(200, json={"unexpected_key": "value"})
        async_client_mock = mocker.patch('httpx.AsyncClient').__enter__.return_value
        async_client_mock.get.return_value = malformed_response

        # Act
        await client.fetch_events(max_events=100)

        # Assert
        send_events_mock.assert_not_called()
        error_log_mock.assert_called() # Should log the failure to process


class TestGetEvents:
    """Unit tests for the ibm-storage-scale-get-events command."""

    async def test_get_events_success(self, mocker: MockerFixture):
        """
        Given:
            - A get-events command with a limit of 10.
        When:
            - The command is executed.
            - The API returns 2 events.
        Then:
            - It should return a CommandResults object with the 2 events.
        """
        # Arrange
        params = {'server_url': 'https://test.com', 'credentials': {}}
        client = mock_client(mocker, params)
        events, _ = TestFetchEvents.test_data()
        async_client_mock = mocker.patch('httpx.AsyncClient').__enter__.return_value
        async_client_mock.get.return_value = mock_api_response(events, next_url=None)

        # Act
        fetched_events, _ = await client.get_events(limit=10)

        # Assert
        assert len(fetched_events) == 2


class TestMain:
    """Unit tests for the main command-routing function."""

    @pytest.fixture(autouse=True)
    def setup_mocks(self, mocker: MockerFixture):
        """Auto-used fixture to set up common mocks for main tests."""
        mocker.patch.object(demisto, 'params', return_value={'server_url': 'https://test.com', 'credentials': {}})
        mocker.patch.object(IBMStorageScaleEventCollector, 'Client')

    async def test_main_calls_test_module(self, mocker: MockerFixture):
        """
        Given:
            - The 'test-module' command is executed.
        When:
            - The main function is called.
        Then:
            - It should call the Client's test_connection method.
            - It should call return_results with 'ok'.
        """
        # Arrange
        mocker.patch.object(demisto, 'command', return_value='test-module')
        return_results_mock = mocker.patch.object(demisto, 'results')
        test_connection_mock = mocker.patch.object(IBMStorageScaleEventCollector.Client, 'test_connection')

        # Act
        main()

        # Assert
        test_connection_mock.assert_called_once()
        return_results_mock.assert_called_once_with('ok')

    async def test_main_calls_fetch_events(self, mocker: MockerFixture):
        """
        Given:
            - The 'fetch-events' command is executed.
        When:
            - The main function is called.
        Then:
            - It should call the Client's fetch_events method.
        """
        # Arrange
        mocker.patch.object(demisto, 'command', return_value='fetch-events')
        fetch_events_mock = mocker.patch.object(IBMStorageScaleEventCollector.Client, 'fetch_events')

        # Act
        main()

        # Assert
        fetch_events_mock.assert_called_once()

    async def test_main_calls_get_events(self, mocker: MockerFixture):
        """
        Given:
            - The 'ibm-storage-scale-get-events' command is executed.
        When:
            - The main function is called.
        Then:
            - It should call the Client's get_events method.
            - It should call return_results with a CommandResults object.
        """
        # Arrange
        mocker.patch.object(demisto, 'command', return_value='ibm-storage-scale-get-events')
        mocker.patch.object(demisto, 'args', return_value={'limit': '10'})
        return_results_mock = mocker.patch.object(demisto, 'results')
        get_events_mock = mocker.patch.object(IBMStorageScaleEventCollector.Client, 'get_events', return_value=([], False))

        # Act
        main()

        # Assert
        get_events_mock.assert_called_once_with(10)
        return_results_mock.assert_called_once()
        assert isinstance(return_results_mock.call_args[0][0], CommandResults)

    async def test_main_handles_unknown_command(self, mocker: MockerFixture):
        """
        Given:
            - An unknown command is executed.
        When:
            - The main function is called.
        Then:
            - It should call return_error with a NotImplementedError.
        """
        # Arrange
        mocker.patch.object(demisto, 'command', return_value='unknown-command')
        return_error_mock = mocker.patch.object(demisto, 'return_error')

        # Act
        main()

        # Assert
        return_error_mock.assert_called_once()
        assert 'not implemented' in return_error_mock.call_args[0][0]
