import pytest
import httpx
from unittest.mock import MagicMock, AsyncMock
from typing import Any
from pytest_mock import MockerFixture

import demistomock as demisto
from CommonServerPython import DemistoException
from IBMStorageScale import main, Client, CommandResults

pytestmark = pytest.mark.asyncio


def mock_client(mocker: MockerFixture, params: dict[str, Any]) -> Client:
    mocker.patch.object(demisto, "params", return_value=params)
    return Client(
        server_url=params.get("server_url"),
        auth=(params.get("credentials", {}).get("identifier"), params.get("credentials", {}).get("password")),
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
    )


def mock_http_status_error(status_code: int) -> httpx.HTTPStatusError:
    return httpx.HTTPStatusError(
        message=f"Error {status_code}",
        request=httpx.Request("GET", "https://test.com"),
        response=httpx.Response(status_code),
    )


class TestTestModule:
    async def test_test_module_success(self, mocker: MockerFixture):
        """
        Given:
            - A client with valid credentials and server config.
        When:
            - The test_connection method is called and the server responds with 200 OK.
        Then:
            - The connection test should succeed with no exceptions raised.
        """
        params = {
            "server_url": "https://test.com",
            "credentials": {"identifier": "user", "password": "pw"},
            "verify": False,
            "proxy": None,
        }
        client = mock_client(mocker, params)

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = AsyncMock()
        mock_response.json = AsyncMock()
        mock_response.json.return_value = {"auditLogRecords": []}

        session = AsyncMock()
        session.get = AsyncMock(return_value=mock_response)
        session.__aenter__.return_value = session

        mocker.patch("IBMStorageScale.httpx.AsyncClient", return_value=session)
        await client.test_connection()

    async def test_test_module_auth_error(self, mocker: MockerFixture):
        """
        Given:
            - A client configured with invalid credentials.
        When:
            - The API responds with a 401 Unauthorized error.
        Then:
            - A DemistoException should be raised with an authorization error message.
        """
        params = {
            "server_url": "https://test.com",
            "credentials": {"identifier": "user", "password": "pw"},
            "verify": False,
            "proxy": None,
        }
        client = mock_client(mocker, params)

        response = httpx.Response(status_code=401, request=httpx.Request("GET", "https://test.com"))
        error = httpx.HTTPStatusError("Auth failed", request=response.request, response=response)

        session = AsyncMock()
        session.get.side_effect = error
        session.__aenter__.return_value = session

        mocker.patch("IBMStorageScale.httpx.AsyncClient", return_value=session)

        with pytest.raises(DemistoException, match="Authorization Error"):
            await client.test_connection()

    async def test_test_module_connection_error(self, mocker: MockerFixture):
        """
        Given:
            - A client with an unreachable server URL.
        When:
            - A connection error occurs during the test call.
        Then:
            - A DemistoException should be raised with a connection error message.
        """
        params = {
            "server_url": "https://test.com",
            "credentials": {"identifier": "user", "password": "pw"},
            "verify": False,
            "proxy": None,
        }
        client = mock_client(mocker, params)

        conn_error = httpx.RequestError("Connection Failed", request=httpx.Request("GET", "https://test.com"))

        session = AsyncMock()
        session.get.side_effect = conn_error
        session.__aenter__.return_value = session

        mocker.patch("IBMStorageScale.httpx.AsyncClient", return_value=session)

        with pytest.raises(DemistoException, match="Connection Error"):
            await client.test_connection()


class TestMain:
    @pytest.fixture
    def client_mock(self, mocker: MockerFixture) -> MagicMock:
        """
        Fixture to patch the Client constructor and return a mocked instance
        with async methods prepared for awaiting.
        """
        client_constructor_mock = mocker.patch("IBMStorageScale.Client")
        mock_instance = MagicMock()
        mock_instance.test_connection = AsyncMock()
        mock_instance.fetch_events = AsyncMock()
        mock_instance.get_events = AsyncMock(return_value=([], False))
        client_constructor_mock.return_value = mock_instance
        return mock_instance

    async def test_main_calls_test_module(self, mocker: MockerFixture, client_mock: MagicMock, capfd):
        """
        Given:
            - The 'test-module' command is triggered in the XSOAR War Room.
        When:
            - main() is invoked.
        Then:
            - The client's test_connection method should be called.
            - 'ok' should be returned as the result.
        """
        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(demisto, "params", return_value={"server_url": "https://test.com", "credentials": {}})
        return_results_mock = mocker.patch("IBMStorageScale.return_results")
        with capfd.disabled():
            await main()
        client_mock.test_connection.assert_called_once()
        return_results_mock.assert_called_once_with("ok")

    async def test_main_calls_fetch_events(self, mocker: MockerFixture, client_mock: MagicMock, capfd):
        """
        Given:
            - The 'fetch-events' command is triggered.
        When:
            - main() is called with max_fetch param set.
        Then:
            - The client's fetch_events method should be invoked with the parsed limit.
        """
        mocker.patch.object(demisto, "command", return_value="fetch-events")
        mocker.patch.object(
            demisto, "params", return_value={"server_url": "https://test.com", "credentials": {}, "max_fetch": "2500"}
        )
        with capfd.disabled():
            await main()
        client_mock.fetch_events.assert_called_once_with(2500)

    async def test_main_calls_get_events(self, mocker: MockerFixture, client_mock: MagicMock, capfd):
        """
        Given:
            - The 'ibm-storage-scale-get-events' command is triggered.
        When:
            - main() is called with a limit argument.
        Then:
            - The client's get_events method should be called with that limit.
            - CommandResults should be returned via return_results.
        """
        mocker.patch.object(demisto, "command", return_value="ibm-storage-scale-get-events")
        mocker.patch.object(demisto, "params", return_value={"server_url": "https://test.com", "credentials": {}})
        mocker.patch.object(demisto, "args", return_value={"limit": "10"})
        return_results_mock = mocker.patch("IBMStorageScale.return_results")
        with capfd.disabled():
            await main()
        client_mock.get_events.assert_called_once_with(limit=10)
        return_results_mock.assert_called_once()
        assert isinstance(return_results_mock.call_args.args[0], CommandResults)

    async def test_main_handles_unknown_command(self, mocker: MockerFixture, client_mock: MagicMock, capfd):
        """
        Given:
            - An unrecognized command is provided to the integration.
        When:
            - main() is invoked.
        Then:
            - return_error should be called indicating the command is not implemented.
        """
        mocker.patch.object(demisto, "command", return_value="unknown-command")
        mocker.patch.object(demisto, "params", return_value={"server_url": "https://test.com", "credentials": {}})
        return_error_mock = mocker.patch("IBMStorageScale.return_error")
        with capfd.disabled():
            await main()
        return_error_mock.assert_called_once()
        assert "not implemented" in return_error_mock.call_args.args[0]
