import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, ANY

import httpx
import pytest
from pytest_mock import MockerFixture

import demistomock as demisto
from CommonServerPython import DemistoException
from IBMStorageScale import (
    API_ENDPOINT,
    DEFAULT_FIRST_FETCH_MINUTES,
    Client,
    CommandResults,
    _ConcurrentEventFetcher,
    build_fetch_query,
    build_minute_fetch_queries,
    deduplicate_events,
    generate_event_hash,
    generate_time_filter_regex,
    get_fetch_start_time,
    parse_timezone_param,
    main,
    update_last_run_time,
)

try:  # Python 3.11+
    from datetime import UTC as _UTC  # type: ignore[attr-defined]

    UTC = _UTC
except Exception:
    UTC = _UTC

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


class TestRegexFetchLogic:
    async def test_fetch_events_uses_regex_filter(self, mocker: MockerFixture, capfd):
        """
        Given:
            - A client starting a fetch cycle.
        When:
            - Client.fetch_events is called.
        Then:
            - It should calculate a time window, build a regex query, and update last run time.
        """
        params = {"server_url": "https://test.com", "credentials": {}, "max_fetch": "1000"}
        client = mock_client(mocker, params)

        # Mock time
        start_dt = datetime(2025, 8, 10, 12, 0, 0, tzinfo=UTC)
        end_dt = datetime(2025, 8, 10, 12, 5, 0, tzinfo=UTC)
        mocker.patch("IBMStorageScale.get_fetch_start_time", return_value=start_dt)
        mocker.patch("IBMStorageScale.datetime").utcnow.return_value = end_dt

        # Mock dependencies
        mock_build_queries = mocker.patch("IBMStorageScale.build_minute_fetch_queries", return_value=["fake_query_string"])
        mock_update_last_run = mocker.patch("IBMStorageScale.update_last_run_time")
        mocker.patch("IBMStorageScale._ConcurrentEventFetcher.run", return_value=([], False))
        mocker.patch(
            "IBMStorageScale.deduplicate_events",
            return_value=([], {"total_events": 0, "duplicates_found": 0, "unique_events": 0, "stored_hashes_count": 0}),
        )
        mocker.patch("IBMStorageScale.send_events_to_xsiam")
        mocker.patch("IBMStorageScale.demisto.info")

        # Run the function
        with capfd.disabled():
            await client.fetch_events(max_events=1000)

        # Assertions
        expected_start = start_dt - timedelta(seconds=30)
        mock_build_queries.assert_called_once_with(1000, expected_start, end_dt, server_tz=ANY)
        mock_update_last_run.assert_called_once_with(end_dt)


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
        fetcher = _ConcurrentEventFetcher(client, max_events=1, query="fields=:all:&limit=1")
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
    def test_get_fetch_start_time_with_existing(self, mocker: MockerFixture):
        """Tests getting start time when last run exists."""
        expected_time_str = "2025-08-10T12:00:00Z"
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch_time": expected_time_str})
        mocker.patch("IBMStorageScale.demisto.debug")

        result = get_fetch_start_time()

        assert isinstance(result, datetime)
        expected_dt = datetime.fromisoformat(expected_time_str)
        assert result == expected_dt

    def test_get_fetch_start_time_first_run(self, mocker: MockerFixture):
        """Tests getting start time on the first run."""
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch("IBMStorageScale.demisto.debug")
        mock_now = datetime(2025, 8, 10, 12, 0, 0, tzinfo=UTC)
        mocker.patch("IBMStorageScale.datetime").utcnow.return_value = mock_now

        result = get_fetch_start_time()

        expected_dt = mock_now - timedelta(minutes=DEFAULT_FIRST_FETCH_MINUTES)
        assert result == expected_dt

    def test_update_last_run_time(self, mocker: MockerFixture):
        """Tests that last run time is updated correctly."""
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch("IBMStorageScale.demisto.debug")

        new_time = datetime(2025, 8, 10, 12, 30, 0, tzinfo=UTC)
        update_last_run_time(new_time)

        expected_last_run = {"last_fetch_time": "2025-08-10T12:30:00Z"}
        mock_set_last_run.assert_called_once_with(expected_last_run)

    def test_generate_time_filter_regex(self):
        """Tests regex generation for a multi-minute window."""
        start_time = datetime(2025, 8, 10, 10, 15, 30)
        end_time = datetime(2025, 8, 10, 10, 17, 10)

        expected_regex = "2025-08-10T10:15:[0-5][0-9]|" "2025-08-10T10:16:[0-5][0-9]|" "2025-08-10T10:17:[0-5][0-9]"
        result = generate_time_filter_regex(start_time, end_time)
        assert result == expected_regex

    def test_generate_time_filter_regex_cross_hour(self):
        """Tests regex generation across an hour boundary."""
        start_time = datetime(2025, 8, 10, 10, 59, 0)
        end_time = datetime(2025, 8, 10, 11, 0, 30)

        expected_regex = "2025-08-10T10:59:[0-5][0-9]|2025-08-10T11:00:[0-5][0-9]"
        result = generate_time_filter_regex(start_time, end_time)
        assert result == expected_regex

    def test_build_fetch_query(self):
        """Tests that the fetch query is built correctly with the regex filter."""
        start_time = datetime(2025, 8, 10, 10, 15, 0)
        end_time = datetime(2025, 8, 10, 10, 15, 59)

        result = build_fetch_query(limit=500, start_time=start_time, end_time=end_time)

        assert "fields=:all:" in result
        assert "limit=500" in result
        # '=' in the filter must NOT be percent-encoded; expect a literal '=' in the query param
        assert "filter=entryTime='''2025-08-10T10:15:[0-5][0-9]'''" in result

    def test_generate_time_filter_regex_with_server_tz(self):
        """Tests regex generation uses the server timezone when provided."""
        # UTC times 10:15:30 -> 10:17:10; with UTC+3 server tz, expect 13:15..13:17
        start_time = datetime(2025, 8, 10, 10, 15, 30, tzinfo=UTC)
        end_time = datetime(2025, 8, 10, 10, 17, 10, tzinfo=UTC)
        server_tz = timezone(timedelta(hours=3))
        expected_regex = "2025-08-10T13:15:[0-5][0-9]|2025-08-10T13:16:[0-5][0-9]|2025-08-10T13:17:[0-5][0-9]"
        assert generate_time_filter_regex(start_time, end_time, server_tz=server_tz) == expected_regex

    def test_build_minute_fetch_queries_server_tz_boundary(self):
        """Ensures per-minute queries reflect server local time, even across day boundaries."""
        start_time = datetime(2025, 8, 10, 23, 59, 30, tzinfo=UTC)
        end_time = datetime(2025, 8, 11, 0, 0, 30, tzinfo=UTC)
        server_tz = timezone(timedelta(hours=2))
        queries = build_minute_fetch_queries(100, start_time, end_time, server_tz=server_tz)
        assert len(queries) == 2
        # Expect local minutes 01:59 and 02:00 on 2025-08-11
        assert "filter=entryTime='''2025-08-11T01:59:[0-5][0-9]'''" in queries[0]
        assert "filter=entryTime='''2025-08-11T02:00:[0-5][0-9]'''" in queries[1]

    def test_deduplicate_events_with_duplicates(self, mocker: MockerFixture):
        """
        Given:
            - A list with duplicate events and stored hashes
        When:
            - deduplicate_events is called
        Then:
            - Duplicates should be removed and stats returned
        """
        stored_hash = "existing_hash_123"
        mocker.patch("IBMStorageScale.get_stored_event_hashes", return_value={stored_hash: "2023-01-01T10:00:00Z"})
        mocker.patch("IBMStorageScale.store_event_hashes")
        mocker.patch("IBMStorageScale.demisto.debug")

        def mock_hash_gen(event):
            return stored_hash if event.get("oid") == "duplicate" else f"hash_{event.get('oid', 'unknown')}"

        mocker.patch("IBMStorageScale.generate_event_hash", side_effect=mock_hash_gen)

        events = [
            {"oid": "duplicate", "entryTime": "2023-01-01T11:00:00Z"},
            {"oid": "unique1", "entryTime": "2023-01-01T12:00:00Z"},
            {"oid": "unique2", "entryTime": "2023-01-01T13:00:00Z"},
        ]

        result_events, stats = deduplicate_events(events)

        assert len(result_events) == 2
        assert stats["total_events"] == 3
        assert stats["duplicates_found"] == 1
        assert stats["unique_events"] == 2


class TestGenerateEventHash:
    def test_generate_event_hash_deterministic(self):
        """Ensures the hash matches the expected SHA256 of the joined key fields."""
        event = {
            "oid": "123",
            "entryTime": "2025-09-10T08:21:00Z",
            "user": "alice",
            "command": "ls",
            "node": "node1",
            "originator": "cli",
            "returnCode": 0,
        }

        expected_string = "123|2025-09-10T08:21:00Z|alice|ls|node1|cli|0"
        expected_hash = hashlib.sha256(expected_string.encode("utf-8")).hexdigest()

        assert generate_event_hash(event) == expected_hash

    def test_generate_event_hash_changes_when_field_changes(self):
        """Changing a key field should produce a different hash."""
        base_event = {
            "oid": "123",
            "entryTime": "2025-09-10T08:21:00Z",
            "user": "alice",
            "command": "ls",
            "node": "node1",
            "originator": "cli",
            "returnCode": 0,
        }
        modified_event = dict(base_event)
        modified_event["command"] = "cat"

        assert generate_event_hash(base_event) != generate_event_hash(modified_event)


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

        # Mock HTTP response
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"auditLogRecords": [{"oid": 1}]}
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__.return_value = mock_async_client
        mock_async_client.get.return_value = mock_response
        mocker.patch("httpx.AsyncClient", return_value=mock_async_client)

        # Mock time functions and query builder
        mocker.patch("IBMStorageScale.get_fetch_start_time")
        mocker.patch("IBMStorageScale.build_minute_fetch_queries", return_value=["q1", "q2"])
        mocker.patch("IBMStorageScale.demisto.debug")

        with capfd.disabled():
            result = await client.debug_connection_info()

        assert result["connection_status"] == "success"
        assert "time_filter_info" in result
        assert result["time_filter_info"]["server_timezone"] == "UTC"
        assert "fetch_window_start_local" in result["time_filter_info"]
        assert "constructed_queries_total" in result["time_filter_info"]


class TestParseTimezoneParam:
    def test_parse_timezone_param_utc_aliases(self):
        tz, name = parse_timezone_param("UTC")
        assert tz is UTC
        assert name == "UTC"
        tz, name = parse_timezone_param("Z")
        assert tz is UTC
        assert name == "UTC"
        tz, name = parse_timezone_param("GMT")
        assert tz is UTC
        assert name == "UTC"

    def test_parse_timezone_param_fixed_offsets(self):
        tz, name = parse_timezone_param("+03:00")
        assert tz.utcoffset(None) == timedelta(hours=3)
        assert name == "UTC+03:00"

        tz, name = parse_timezone_param("-0500")
        assert tz.utcoffset(None) == timedelta(hours=-5)
        assert name == "UTC-05:00"

        tz, name = parse_timezone_param("UTC+2")
        assert tz.utcoffset(None) == timedelta(hours=2)
        assert name == "UTC+02:00"

        tz, name = parse_timezone_param("-7")
        assert tz.utcoffset(None) == timedelta(hours=-7)
        assert name == "UTC-07:00"

    def test_parse_timezone_param_invalid_defaults_to_utc(self):
        tz, name = parse_timezone_param("Not/AZone")
        assert tz is UTC
        assert name == "UTC"
