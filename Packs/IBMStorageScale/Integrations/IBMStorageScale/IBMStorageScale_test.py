from unittest.mock import MagicMock, AsyncMock

import pytest
import demistomock as demisto
from typing import Any
from pytest_mock import MockerFixture
import httpx

from CommonServerPython import DemistoException
from IBMStorageScale import main, Client, CommandResults
from Packs.IBMStorageScale.Integrations.IBMStorageScale import IBMStorageScale

pytestmark = pytest.mark.asyncio


# --- HELPER FUNCTIONS ---


def mock_client(mocker: MockerFixture, params: dict[str, Any]) -> Client:
    """Helper function to create a mocked Client instance."""
    mocker.patch.object(demisto, "params", return_value=params)
    return Client(
        server_url=params.get("server_url"),
        auth=(params.get("credentials", {}).get("identifier"), params.get("credentials", {}).get("password")),
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
    )


def mock_api_response(events: list[dict[str, Any]], next_url: str = None) -> httpx.Response:
    """Helper to create a mock httpx.Response for a successful API call."""
    paging = {"next": next_url} if next_url is not None else {}
    response_json = {"auditLogRecords": events, "paging": paging}
    request = httpx.Request(method="GET", url="https://mock-url/api")
    return httpx.Response(200, json=response_json, request=request)


def mock_http_status_error(status_code: int) -> httpx.HTTPStatusError:
    """Helper to create a mock httpx.HTTPStatusError."""
    return httpx.HTTPStatusError(
        message=f"Error {status_code}", request=httpx.Request("GET", "https://test.com"), response=httpx.Response(status_code)
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
        params = {
            "server_url": "https://test.com",
            "credentials": {"identifier": "user", "password": "pw"},
            "verify": False,
            "proxy": None,
        }
        client = mock_client(mocker, params)
        mocker.patch("httpx.AsyncClient.get", return_value=mock_api_response([]))

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
        params = {
            "server_url": "https://test.com",
            "credentials": {"identifier": "user", "password": "pw"},
            "verify": False,
            "proxy": None,
        }
        client = mock_client(mocker, params)
        mocker.patch("httpx.AsyncClient.get", side_effect=mock_http_status_error(401))

        # Act & Assert
        with pytest.raises(DemistoException, match="Authorization Error"):
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
        params = {
            "server_url": "https://test.com",
            "credentials": {"identifier": "user", "password": "pw"},
            "verify": False,
            "proxy": None,
        }
        client = mock_client(mocker, params)
        mocker.patch("httpx.AsyncClient.get", side_effect=httpx.RequestError("Connection Failed", request=mocker.MagicMock()))

        # Act & Assert
        with pytest.raises(DemistoException, match="Connection Error"):
            await client.test_connection()


class TestFetchEvents:
    """Unit tests for the fetch-events command."""

    @staticmethod
    def test_data() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Provides test data for fetch events."""
        page1_events = [{"oid": i, "entryTime": f"2023-01-01T12:00:0{i}Z"} for i in range(2)]
        page2_events = [{"oid": i, "entryTime": f"2023-01-01T12:00:1{i}Z"} for i in range(2, 4)]
        return page1_events, page2_events

    async def test_fetch_events_multiple_pages(self, mocker: MockerFixture):
        """Tests fetching all events from multiple pages."""
        # Arrange
        params = {"server_url": "https://test.com", "credentials": {}, "max_fetch": 100}
        client = mock_client(mocker, params)
        send_events_mock = mocker.patch("IBMStorageScale.send_events_to_xsiam")
        page1_events, page2_events = self.test_data()
        async_client_mock = mocker.patch("httpx.AsyncClient").__enter__.return_value
        async_client_mock.get = mocker.AsyncMock()

        mock_response_1 = mocker.AsyncMock()
        # CORRECTED LINE: Make .json an AsyncMock itself
        mock_response_1.json = mocker.AsyncMock(return_value={
            "auditLogRecords": page1_events, "paging": {"next": "https://test.com/api?page=2"}
        })
        mock_response_2 = mocker.AsyncMock()
        # CORRECTED LINE: Make .json an AsyncMock itself
        mock_response_2.json = mocker.AsyncMock(return_value={
            "auditLogRecords": page2_events, "paging": {"next": None}
        })
        async_client_mock.get.side_effect = [mock_response_1, mock_response_2]

        # Act
        await client.fetch_events(max_events=100)

        # Assert
        assert send_events_mock.call_count == 1
        sent_events = send_events_mock.call_args.kwargs.get('events')
        assert len(sent_events) == 4
        assert all("_time" in event for event in sent_events)

    async def test_fetch_events_reaches_limit(self, mocker: MockerFixture):
        """Tests that fetching stops when the event limit is reached."""
        # Arrange
        params = {"server_url": "https://test.com", "credentials": {}, "max_fetch": 2}
        client = mock_client(mocker, params)
        send_events_mock = mocker.patch("IBMStorageScale.send_events_to_xsiam")
        info_log_mock = mocker.patch("demistomock.info")
        page1_events, _ = self.test_data()
        async_client_mock = mocker.patch("httpx.AsyncClient").__enter__.return_value
        async_client_mock.get = mocker.AsyncMock()

        mock_response = mocker.AsyncMock()
        # CORRECTED LINE: Make .json an AsyncMock itself
        mock_response.json = mocker.AsyncMock(return_value={
            "auditLogRecords": page1_events, "paging": {"next": "https://test.com/api?page=2"}
        })
        async_client_mock.get.return_value = mock_response

        # Act
        await client.fetch_events(max_events=2)

        # Assert
        sent_events = send_events_mock.call_args.kwargs.get('events')
        assert len(sent_events) == 2
        info_log_mock.assert_any_call("Fetch cycle reached the event limit. More events may be available on the server.")

    async def test_fetch_events_producer_fails(self, mocker: MockerFixture):
        """Tests graceful handling of an API error during fetching."""
        # Arrange
        params = {"server_url": "https://test.com", "credentials": {}, "max_fetch": 100}
        client = mock_client(mocker, params)
        send_events_mock = mocker.patch("IBMStorageScale.send_events_to_xsiam")
        error_log_mock = mocker.patch("demistomock.error")
        page1_events, _ = self.test_data()
        async_client_mock = mocker.patch("httpx.AsyncClient").__enter__.return_value
        async_client_mock.get = mocker.AsyncMock()

        mock_response_1 = mocker.AsyncMock()
        # CORRECTED LINE: Make .json an AsyncMock itself
        mock_response_1.json = mocker.AsyncMock(return_value={
            "auditLogRecords": page1_events, "paging": {"next": "https://test.com/api?page=2"}
        })
        async_client_mock.get.side_effect = [
            mock_response_1,
            mock_http_status_error(500),
        ]

        # Act
        await client.fetch_events(max_events=100)

        # Assert
        error_log_mock.assert_called()
        assert "status 500" in error_log_mock.call_args.args[0]
        sent_events = send_events_mock.call_args.kwargs.get('events')
        assert len(sent_events) == 2

    async def test_fetch_events_malformed_response(self, mocker: MockerFixture):
        """Tests graceful handling of a malformed JSON response."""
        # Arrange
        params = {"server_url": "https://test.com", "credentials": {}, "max_fetch": 100}
        client = mock_client(mocker, params)
        send_events_mock = mocker.patch("IBMStorageScale.send_events_to_xsiam")
        error_log_mock = mocker.patch("demistomock.error")
        async_client_mock = mocker.patch("httpx.AsyncClient").__enter__.return_value
        async_client_mock.get = mocker.AsyncMock()

        mock_response = mocker.AsyncMock()
        # CORRECTED LINE: Make .json an AsyncMock itself
        mock_response.json = mocker.AsyncMock(return_value={"unexpected_key": "value"})
        async_client_mock.get.return_value = mock_response

        # Act
        await client.fetch_events(max_events=100)

        # Assert
        assert send_events_mock.call_count == 1
        sent_events = send_events_mock.call_args.kwargs.get('events')
        assert len(sent_events) == 0
        error_log_mock.assert_not_called()


class TestGetEvents:
    """Unit tests for the ibm-storage-scale-get-events command."""

    async def test_get_events_success(self, mocker: MockerFixture):
        """Tests the get-events command successfully retrieves events."""
        # Arrange
        params = {"server_url": "https://test.com", "credentials": {}}
        client = mock_client(mocker, params)
        events, _ = TestFetchEvents.test_data()
        async_client_mock = mocker.patch("httpx.AsyncClient").__enter__.return_value
        async_client_mock.get = mocker.AsyncMock()

        mock_response = mocker.AsyncMock()
        # CORRECTED LINE: Make .json an AsyncMock itself
        mock_response.json = mocker.AsyncMock(return_value={
            "auditLogRecords": events, "paging": {"next": None}
        })
        async_client_mock.get.return_value = mock_response

        # Act
        fetched_events, _ = await client.get_events(limit=10)

        # Assert
        assert len(fetched_events) == 2


class TestMain:
    """Unit tests for the main command-routing function."""

    @pytest.fixture
    def client_mock(self, mocker: MockerFixture) -> MagicMock:
        """
        Mocks the Client class.
        This fixture patches the Client constructor to return a MagicMock instance
        with its async methods configured as AsyncMocks.
        """
        # Patch the Client class in the module where it's used
        client_constructor_mock = mocker.patch("IBMStorageScale.Client")

        # Create a mock instance
        mock_instance = MagicMock()

        # CORRECTED: Configure the methods that need to be awaited as AsyncMocks
        mock_instance.test_connection = AsyncMock()
        mock_instance.fetch_events = AsyncMock()
        # For get_events, it needs to be an AsyncMock that returns a value when awaited
        mock_instance.get_events = AsyncMock(return_value=([], False))

        # Make the mocked constructor return our mock instance
        client_constructor_mock.return_value = mock_instance

        return mock_instance

    async def test_main_calls_test_module(self, mocker: MockerFixture, client_mock: MagicMock):
        """
        Given: The 'test-module' command is executed.
        When: The main function is called.
        Then: It should call the Client's test_connection method and return 'ok'.
        """
        # Arrange
        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(demisto, "params", return_value={"server_url": "https://test.com", "credentials": {}})
        return_results_mock = mocker.patch("IBMStorageScale.return_results")

        # Act
        await main()

        # Assert
        client_mock.test_connection.assert_called_once()
        return_results_mock.assert_called_once_with("ok")

    async def test_main_calls_fetch_events(self, mocker: MockerFixture, client_mock: MagicMock):
        """
        Given: The 'fetch-events' command is executed.
        When: The main function is called.
        Then: It should call the Client's fetch_events method.
        """
        # Arrange
        mocker.patch.object(demisto, "command", return_value="fetch-events")
        mocker.patch.object(
            demisto, "params", return_value={"server_url": "https://test.com", "credentials": {}, "max_fetch": "2500"}
        )

        # Act
        await main()

        # Assert
        client_mock.fetch_events.assert_called_once_with(2500)

    async def test_main_calls_get_events(self, mocker: MockerFixture, client_mock: MagicMock):
        """
        Given: The 'ibm-storage-scale-get-events' command is executed.
        When: The main function is called.
        Then: It should call the Client's get_events method and return results.
        """
        # Arrange
        mocker.patch.object(demisto, "command", return_value="ibm-storage-scale-get-events")
        mocker.patch.object(demisto, "params", return_value={"server_url": "https://test.com", "credentials": {}})
        mocker.patch.object(demisto, "args", return_value={"limit": "10"})
        return_results_mock = mocker.patch("IBMStorageScale.return_results")

        # Act
        await main()

        # Assert
        client_mock.get_events.assert_called_once_with(limit=10)
        return_results_mock.assert_called_once()
        assert isinstance(return_results_mock.call_args.args[0], CommandResults)

    async def test_main_handles_unknown_command(self, mocker: MockerFixture, client_mock: MagicMock):
        """
        Given: An unknown command is executed.
        When: The main function is called.
        Then: It should call return_error with a NotImplementedError.
        """
        # Arrange
        mocker.patch.object(demisto, "command", return_value="unknown-command")
        mocker.patch.object(demisto, "params", return_value={"server_url": "https://test.com", "credentials": {}})
        return_error_mock = mocker.patch("IBMStorageScale.return_error")

        # Act
        await main()

        # Assert
        return_error_mock.assert_called_once()
        assert "not implemented" in return_error_mock.call_args.args[0]
