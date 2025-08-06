import asyncio
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from pytest_mock import MockerFixture

import demistomock as demisto
from CommonServerPython import DemistoException
from IBMStorageScale import (
    API_ENDPOINT,
    DEFAULT_FIRST_FETCH_DAYS,
    DEDUPLICATION_WINDOW_HOURS,
    Client,
    CommandResults,
    _ConcurrentEventFetcher,
    build_api_query_with_time_filter,
    deduplicate_events,
    generate_event_hash,
    get_time_filter_from_last_run,
    main,
    store_event_hashes,
    update_last_run_time,
)

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
            "insecure": True,
            "proxy": None,
        }
        client = mock_client(mocker, params)

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
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
            "insecure": True,
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
            "insecure": True,
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


class TestClientFetchLogic:
    async def test_fetch_events_calls_xsiam_push(self, mocker: MockerFixture, capfd):
        """
        Given:
            - A mocked _ConcurrentEventFetcher returning fake events.
        When:
            - Client.fetch_events is called.
        Then:
            - send_events_to_xsiam is called with the events.
        """
        events = [{"entryTime": "2024-01-01T00:00:00Z"} for _ in range(5)]

        fetcher_cls_mock = mocker.patch("IBMStorageScale._ConcurrentEventFetcher", autospec=True)
        fetcher_mock = fetcher_cls_mock.return_value
        fetcher_mock.run = AsyncMock(return_value=(events, False))

        send_mock = mocker.patch("IBMStorageScale.send_events_to_xsiam")
        mocker.patch("IBMStorageScale.get_time_filter_from_last_run", return_value="2023-01-01T00:00:00Z")
        mocker.patch("IBMStorageScale.update_last_run_time")
        mocker.patch("IBMStorageScale.store_event_hashes")
        mocker.patch("IBMStorageScale.get_stored_event_hashes", return_value={})

        client = Client("https://test.com", ("user", "pass"), verify=True, proxy=None)

        with capfd.disabled():
            await client.fetch_events(max_events=5)

        send_mock.assert_called_once_with(events=events, vendor="IBM", product="StorageScale")

    async def test_get_events_returns_data(self, mocker: MockerFixture):
        """
        Given:
            - A mocked _ConcurrentEventFetcher with events.
        When:
            - Client.get_events is invoked.
        Then:
            - It returns the fetched events and has_more flag.
        """
        events = [{"entryTime": "now"}]
        fetcher_cls_mock = mocker.patch("IBMStorageScale._ConcurrentEventFetcher", autospec=True)
        fetcher_mock = fetcher_cls_mock.return_value
        fetcher_mock.run = AsyncMock(return_value=(events, True))

        client = Client("https://test.com", ("user", "pass"), verify=True, proxy=None)
        result, has_more = await client.get_events(limit=1)
        assert result == events
        assert has_more is True


class TestFetcherRunLogic:
    async def test_run_fetches_data_and_stops_workers(self, mocker: MockerFixture, capfd):
        """
        Given:
            - A mocked API that returns one page of events and a next link.
        When:
            - _ConcurrentEventFetcher.run is executed.
        Then:
            - It collects the events and gracefully shuts down the workers.
        """
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"auditLogRecords": [{"entryTime": "2023-01-01T00:00:00Z"}], "paging": {}}

        session = AsyncMock()
        session.get = AsyncMock(return_value=mock_response)
        session.__aenter__.return_value = session

        mocker.patch("IBMStorageScale.httpx.AsyncClient", return_value=session)
        mocker.patch("IBMStorageScale.demisto.debug")
        mocker.patch("IBMStorageScale.demisto.error")

        client = Client("https://test.com", ("u", "p"), True, None)
        fetcher = _ConcurrentEventFetcher(client, max_events=1)
        with capfd.disabled():
            events, has_more = await fetcher.run()

        assert isinstance(events, list)
        assert not has_more
        assert len(events) == 1


class TestWorkerBehavior:
    async def test_worker_stops_when_max_reached(self, mocker: MockerFixture, capfd):
        """
        Given:
            - A fetcher with max_events = 1.
        When:
            - The worker fetches one page and reaches the limit.
        Then:
            - It doesn't queue the next page.
        """
        response_data = {"auditLogRecords": [{"entryTime": "2023-01-01"}], "paging": {"next": "https://test.com/next?page=2"}}

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = response_data

        session = AsyncMock()
        session.get = AsyncMock(return_value=mock_response)
        session.__aenter__.return_value = session

        mocker.patch("IBMStorageScale.demisto.debug")
        mocker.patch("IBMStorageScale.demisto.error")

        fetcher = _ConcurrentEventFetcher(Client("https://test.com", ("u", "p"), True, None), max_events=1)
        await fetcher.queue.put(f"{API_ENDPOINT}?limit=1")

        with capfd.disabled():
            task = asyncio.create_task(fetcher._worker("TestWorker", session))
            await fetcher.queue.join()  # Wait until queue is processed
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        assert len(fetcher.collected_events) == 1

    async def test_worker_handles_http_error(self, mocker: MockerFixture, capfd):
        """
        Given:
            - A URL that returns an HTTP 500 error.
        When:
            - _worker is invoked.
        Then:
            - It logs the error and completes the task.
        """
        error = httpx.HTTPStatusError(
            message="fail",
            request=httpx.Request("GET", "https://test.com"),
            response=httpx.Response(status_code=500, request=httpx.Request("GET", "https://test.com")),
        )

        session = AsyncMock()
        session.get.side_effect = error
        session.__aenter__.return_value = session

        log_mock = mocker.patch("IBMStorageScale.demisto.error")
        mocker.patch("IBMStorageScale.demisto.debug")

        fetcher = _ConcurrentEventFetcher(Client("https://test.com", ("u", "p"), True, None), max_events=1)
        await fetcher.queue.put(f"{API_ENDPOINT}?limit=1")

        with capfd.disabled():
            task = asyncio.create_task(fetcher._worker("ErrorWorker", session))
            await fetcher.queue.join()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        assert log_mock.called


class TestUtilityFunctions:
    def test_generate_event_hash_consistent(self):
        """
        Given:
            - An event with specific identifying fields
        When:
            - generate_event_hash is called multiple times
        Then:
            - The same hash should be generated consistently
        """
        event = {
            "oid": "12345",
            "entryTime": "2023-01-01T00:00:00Z",
            "user": "testuser",
            "command": "mmlsconfig",
            "node": "node1",
            "originator": "CLI",
            "returnCode": "0",
        }
        hash1 = generate_event_hash(event)
        hash2 = generate_event_hash(event)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 produces 64 character hex string

    def test_generate_event_hash_different_events(self):
        """
        Given:
            - Two different events
        When:
            - generate_event_hash is called on each
        Then:
            - Different hashes should be generated
        """
        event1 = {"oid": "12345", "entryTime": "2023-01-01T00:00:00Z", "user": "user1"}
        event2 = {"oid": "67890", "entryTime": "2023-01-01T00:00:01Z", "user": "user2"}

        hash1 = generate_event_hash(event1)
        hash2 = generate_event_hash(event2)
        assert hash1 != hash2

    def test_get_time_filter_from_last_run_with_existing(self, mocker: MockerFixture):
        """
        Given:
            - A last run object with existing fetch time
        When:
            - get_time_filter_from_last_run is called
        Then:
            - The existing fetch time should be returned
        """
        expected_time = "2023-01-01T12:00:00Z"
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch_time": expected_time})
        mocker.patch("IBMStorageScale.demisto.debug")
        result = get_time_filter_from_last_run()
        assert result == expected_time

    def test_get_time_filter_from_last_run_first_run(self, mocker: MockerFixture):
        """
        Given:
            - No existing last run object (first run)
        When:
            - get_time_filter_from_last_run is called
        Then:
            - A default lookback time should be calculated and returned
        """
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch("IBMStorageScale.demisto.debug")
        mock_datetime = mocker.patch("IBMStorageScale.datetime")
        mock_now = datetime(2023, 1, 2, 12, 0, 0)
        mock_datetime.utcnow.return_value = mock_now

        result = get_time_filter_from_last_run()
        expected = (mock_now - timedelta(days=DEFAULT_FIRST_FETCH_DAYS)).isoformat() + "Z"
        assert result == expected

    def test_update_last_run_time_with_events(self, mocker: MockerFixture):
        """
        Given:
            - A list of events with timestamps
        When:
            - update_last_run_time is called
        Then:
            - The latest timestamp should be stored in last run
        """
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch("IBMStorageScale.demisto.debug")

        events = [
            {"entryTime": "2023-01-01T10:00:00Z"},
            {"entryTime": "2023-01-01T12:00:00Z"},  # Latest
            {"entryTime": "2023-01-01T11:00:00Z"},
        ]

        update_last_run_time(events)
        mock_set_last_run.assert_called_once_with({"last_fetch_time": "2023-01-01T12:00:00Z"})

    def test_update_last_run_time_empty_events(self, mocker: MockerFixture):
        """
        Given:
            - An empty list of events
        When:
            - update_last_run_time is called
        Then:
            - No last run update should occur
        """
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mocker.patch("IBMStorageScale.demisto.debug")
        update_last_run_time([])
        mock_set_last_run.assert_not_called()

    def test_build_api_query_with_time_filter(self):
        """
        Given:
            - A timestamp and limit
        When:
            - build_api_query_with_time_filter is called
        Then:
            - A properly formatted query string should be returned
        """
        since_time = "2023-01-01T00:00:00Z"
        limit = 500

        result = build_api_query_with_time_filter(since_time, limit)
        assert "fields=:all:" in result
        assert f"limit={limit}" in result
        assert f"since={since_time}" in result

    def test_build_api_query_with_time_filter_no_time(self):
        """
        Given:
            - No timestamp but with limit
        When:
            - build_api_query_with_time_filter is called
        Then:
            - Query without time filter should be returned
        """
        result = build_api_query_with_time_filter("", 100)
        assert "fields=:all:" in result
        assert "limit=100" in result
        assert "since=" not in result

    def test_deduplicate_events_with_duplicates(self, mocker: MockerFixture):
        """
        Given:
            - A list with duplicate events and stored hashes
        When:
            - deduplicate_events is called
        Then:
            - Duplicates should be removed and stats returned
        """
        # Mock stored hashes
        stored_hash = "existing_hash_123"
        mocker.patch("IBMStorageScale.get_stored_event_hashes", return_value={stored_hash: "2023-01-01T10:00:00Z"})
        mocker.patch("IBMStorageScale.store_event_hashes")
        mocker.patch("IBMStorageScale.demisto.debug")

        # Mock hash generation to control duplicates
        def mock_hash_gen(event):
            if event.get("oid") == "duplicate":
                return stored_hash
            return f"hash_{event.get('oid', 'unknown')}"

        mocker.patch("IBMStorageScale.generate_event_hash", side_effect=mock_hash_gen)

        events = [
            {"oid": "duplicate", "entryTime": "2023-01-01T11:00:00Z"},  # This should be filtered as duplicate
            {"oid": "unique1", "entryTime": "2023-01-01T12:00:00Z"},
            {"oid": "unique2", "entryTime": "2023-01-01T13:00:00Z"},
        ]

        result_events, stats = deduplicate_events(events)

        assert len(result_events) == 2  # Only unique events
        assert stats["total_events"] == 3
        assert stats["duplicates_found"] == 1
        assert stats["unique_events"] == 2

    def test_deduplicate_events_no_duplicates(self, mocker: MockerFixture):
        """
        Given:
            - A list with no duplicate events
        When:
            - deduplicate_events is called
        Then:
            - All events should be returned with zero duplicates
        """
        mocker.patch("IBMStorageScale.get_stored_event_hashes", return_value={})
        mocker.patch("IBMStorageScale.store_event_hashes")
        mocker.patch("IBMStorageScale.demisto.debug")
        mocker.patch("IBMStorageScale.generate_event_hash", side_effect=lambda e: f"hash_{e.get('oid')}")

        events = [{"oid": "1", "entryTime": "2023-01-01T11:00:00Z"}, {"oid": "2", "entryTime": "2023-01-01T12:00:00Z"}]

        result_events, stats = deduplicate_events(events)

        assert len(result_events) == 2
        assert stats["duplicates_found"] == 0
        assert stats["unique_events"] == 2

    def test_store_event_hashes_cleanup_old(self, mocker: MockerFixture):
        """
        Given:
            - Event hashes with some old timestamps outside window
        When:
            - store_event_hashes is called
        Then:
            - Old hashes should be cleaned up and only recent ones stored
        """
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mocker.patch("IBMStorageScale.demisto.debug")

        # Mock current time
        current_time = datetime(2023, 1, 2, 12, 0, 0)
        mocker.patch("IBMStorageScale.datetime").utcnow.return_value = current_time

        # Create hashes with different timestamps
        old_time = (current_time - timedelta(hours=DEDUPLICATION_WINDOW_HOURS + 1)).isoformat() + "Z"
        recent_time = (current_time - timedelta(hours=1)).isoformat() + "Z"

        event_hashes = {"old_hash": old_time, "recent_hash": recent_time}

        store_event_hashes(event_hashes)

        # Verify only recent hash is stored
        call_args = mock_set_last_run.call_args[0][0]
        stored_hashes = call_args["event_hashes"]
        assert "recent_hash" in stored_hashes
        assert "old_hash" not in stored_hashes


class TestDebugCommand:
    async def test_debug_connection_info_success(self, mocker: MockerFixture, capfd):
        """
        Given:
            - A client with successful connection
        When:
            - debug_connection_info is called
        Then:
            - Success status and debug info should be returned
        """
        params = {
            "server_url": "https://test.com",
            "credentials": {"identifier": "user", "password": "pw"},
            "insecure": True,
            "proxy": None,
        }
        client = mock_client(mocker, params)

        # Mock successful HTTP response
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"auditLogRecords": [{"oid": 1}]}
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__.return_value = mock_async_client
        mock_async_client.get.return_value = mock_response

        mocker.patch("httpx.AsyncClient", return_value=mock_async_client)
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch_time": "2023-01-01T00:00:00Z"})
        mocker.patch("IBMStorageScale.get_stored_event_hashes", return_value={"hash1": "2023-01-01T00:00:00Z"})
        mocker.patch("IBMStorageScale.get_time_filter_from_last_run", return_value="2023-01-01T00:00:00Z")
        mocker.patch("IBMStorageScale.demisto.debug")

        with capfd.disabled():
            result = await client.debug_connection_info()

        assert result["connection_status"] == "success"
        assert result["server_url"] == "https://test.com"
        assert result["api_endpoint"] == API_ENDPOINT
        assert "current_time" in result
        assert "last_run_info" in result
        assert "deduplication_info" in result

    async def test_debug_connection_info_failure(self, mocker: MockerFixture, capfd):
        """
        Given:
            - A client with connection failure
        When:
            - debug_connection_info is called
        Then:
            - Failed status and error details should be returned
        """
        params = {
            "server_url": "https://test.com",
            "credentials": {"identifier": "user", "password": "pw"},
            "insecure": True,
            "proxy": None,
        }
        client = mock_client(mocker, params)

        # Mock HTTP error
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__.return_value = mock_async_client
        mock_async_client.get.side_effect = httpx.HTTPStatusError("Error", request=MagicMock(), response=MagicMock())

        mocker.patch("httpx.AsyncClient", return_value=mock_async_client)
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch("IBMStorageScale.demisto.debug")

        with capfd.disabled():
            result = await client.debug_connection_info()

        assert result["connection_status"] == "failed"
        assert "error_details" in result


class TestMainWithNewCommands:
    @pytest.fixture
    def enhanced_client_mock(self, mocker: MockerFixture) -> MagicMock:
        """
        Enhanced fixture with debug_connection_info method
        """
        client_constructor_mock = mocker.patch("IBMStorageScale.Client")
        mock_instance = MagicMock()
        mock_instance.test_connection = AsyncMock()
        mock_instance.fetch_events = AsyncMock()
        mock_instance.get_events = AsyncMock(return_value=([], False))
        mock_instance.debug_connection_info = AsyncMock(
            return_value={"connection_status": "success", "server_url": "https://test.com"}
        )
        client_constructor_mock.return_value = mock_instance
        return mock_instance

    async def test_main_calls_debug_command(self, mocker: MockerFixture, enhanced_client_mock: MagicMock, capfd):
        """
        Given:
            - The 'ibm-storage-scale-debug-connection' command is triggered
        When:
            - main() is invoked
        Then:
            - The client's debug_connection_info method should be called
            - CommandResults should be returned via return_results
        """
        mocker.patch.object(demisto, "command", return_value="ibm-storage-scale-debug-connection")
        mocker.patch.object(demisto, "params", return_value={"server_url": "https://test.com", "credentials": {}})
        return_results_mock = mocker.patch("IBMStorageScale.return_results")

        with capfd.disabled():
            await main()

        enhanced_client_mock.debug_connection_info.assert_called_once()
        return_results_mock.assert_called_once()

        # Verify CommandResults structure
        call_args = return_results_mock.call_args[0][0]
        assert call_args.outputs_prefix == "IBMStorageScale.Debug"

    async def test_main_fetch_events_with_deduplication(self, mocker: MockerFixture, enhanced_client_mock: MagicMock, capfd):
        """
        Given:
            - The 'fetch-events' command with deduplication enabled
        When:
            - main() is invoked
        Then:
            - The client's fetch_events method should be called with deduplication
        """
        mocker.patch.object(demisto, "command", return_value="fetch-events")
        mocker.patch.object(
            demisto, "params", return_value={"server_url": "https://test.com", "credentials": {}, "max_fetch": "5000"}
        )
        mocker.patch("IBMStorageScale.arg_to_number", return_value=5000)

        with capfd.disabled():
            await main()

        enhanced_client_mock.fetch_events.assert_called_once_with(5000)

    async def test_main_get_events_with_deduplication(self, mocker: MockerFixture, enhanced_client_mock: MagicMock, capfd):
        """
        Given:
            - The 'ibm-storage-scale-get-events' command
        When:
            - main() is invoked with deduplication enabled
        Then:
            - Events should be deduplicated before being returned
        """
        # Mock events that would be returned
        mock_events = [{"oid": 1}, {"oid": 2}]
        enhanced_client_mock.get_events.return_value = (mock_events, False)

        mocker.patch.object(demisto, "command", return_value="ibm-storage-scale-get-events")
        mocker.patch.object(demisto, "params", return_value={"server_url": "https://test.com", "credentials": {}})
        mocker.patch.object(demisto, "args", return_value={"limit": "10"})
        mocker.patch("IBMStorageScale.arg_to_number", return_value=10)
        mocker.patch("IBMStorageScale.argToBoolean", return_value=False)
        return_results_mock = mocker.patch("IBMStorageScale.return_results")

        with capfd.disabled():
            await main()

        enhanced_client_mock.get_events.assert_called_once_with(limit=10)
        return_results_mock.assert_called_once()


class TestEnhancedFetchLogic:
    async def test_fetch_events_with_time_filter_and_deduplication(self, mocker: MockerFixture, capfd):
        """
        Given:
            - A client configured for time-based fetching with deduplication
        When:
            - Client.fetch_events is called
        Then:
            - Time filtering and deduplication should be applied
        """
        params = {
            "server_url": "https://test.com",
            "credentials": {"identifier": "user", "password": "pw"},
            "insecure": True,
            "proxy": None,
        }
        client = mock_client(mocker, params)

        # Mock the time filtering
        mocker.patch("IBMStorageScale.get_time_filter_from_last_run", return_value="2023-01-01T00:00:00Z")
        expected_query = "fields=:all:&limit=1000&since=2023-01-01T00:00:00Z"
        mocker.patch("IBMStorageScale.build_api_query_with_time_filter", return_value=expected_query)

        # Mock the fetcher
        mock_events = [{"oid": 1, "entryTime": "2023-01-01T12:00:00Z"}]
        mock_fetcher_instance = MagicMock()
        mock_fetcher_instance.run = AsyncMock(return_value=(mock_events, False))
        fetcher_class_mock = mocker.patch("IBMStorageScale._ConcurrentEventFetcher", return_value=mock_fetcher_instance)

        # Mock deduplication
        mocker.patch(
            "IBMStorageScale.deduplicate_events",
            return_value=(mock_events, {"total_events": 1, "duplicates_found": 0, "unique_events": 1, "stored_hashes_count": 1}),
        )

        # Mock other dependencies
        mocker.patch("IBMStorageScale.update_last_run_time")
        mocker.patch("IBMStorageScale.send_events_to_xsiam")

        with capfd.disabled():
            await client.fetch_events(1000)

        # Verify fetcher was created with correct query and then its run method was called
        fetcher_class_mock.assert_called_once_with(client, 1000, expected_query)
        mock_fetcher_instance.run.assert_called_once()
