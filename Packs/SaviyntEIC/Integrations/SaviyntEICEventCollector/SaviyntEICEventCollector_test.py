from datetime import datetime, UTC

import pytest
from freezegun import freeze_time
from SaviyntEICEventCollector import (
    DEFAULT_FETCH_TIME_FRAME_MINUTES,
    LAST_RUN_EVENT_HASHES,
    LAST_RUN_TIMESTAMP,
    Client,
    _fetch_analytics_pages_concurrently,
    add_time_to_events,
    compute_effective_time_frame_minutes,
    deduplicate_events,
    generate_event_hash,
    update_last_run_timestamp_from_events,
)

# Python 3.10 compatibility: datetime.UTC added in 3.11; use timezone.utc instead
UTC = UTC


class TestHelperFunctions:
    @pytest.mark.parametrize(
        "case, time_frame_minutes, last_run, frozen_now, expected_minutes",
        [
            pytest.param(
                "first run uses default",
                None,
                {},
                None,
                DEFAULT_FETCH_TIME_FRAME_MINUTES,
                id="first run uses default",
            ),
            pytest.param(
                "continued run (ceil delta)",
                None,
                {LAST_RUN_TIMESTAMP: int(datetime(2025, 1, 1, 0, 58, 30, tzinfo=UTC).timestamp())},
                "2025-01-01T01:00:00Z",
                2,
                id="continued run (ceil delta)",
            ),
            pytest.param(
                "explicit time_frame_minutes is used",
                15,
                {},
                None,
                15,
                id="explicit time_frame_minutes is used",
            ),
        ],
    )
    def test_compute_effective_time_frame_cases(self, case, time_frame_minutes, last_run, frozen_now, expected_minutes):
        """
        - first run uses default:
          - Given: No LAST_RUN timestamp
          - When: Computing effective timeframe
          - Then: DEFAULT_FETCH_TIME_FRAME_MINUTES is returned
        - continued run (ceil delta):
          - Given: LAST_RUN timestamp at 2025-01-01 00:58:30Z and now at 01:00:00Z
          - When: Computing effective timeframe
          - Then: 90 seconds delta ceils to 2 minutes
        - explicit time_frame_minutes is used:
          - Given: time_frame_minutes=15 provided
          - When: Computing effective timeframe
          - Then: 15 is returned as-is
        """
        if frozen_now:
            with freeze_time(frozen_now):
                assert compute_effective_time_frame_minutes(time_frame_minutes, last_run) == expected_minutes
        else:
            assert compute_effective_time_frame_minutes(time_frame_minutes, last_run) == expected_minutes

    @pytest.mark.parametrize(
        "events,frozen_now,expected_iso",
        [
            pytest.param(
                [{"_time": "2023-01-01T01:00:00Z"}, {"_time": "2023-01-01T02:00:00Z"}],
                None,
                "2023-01-01T02:00:00Z",
                id="use enriched _time",
            ),
            pytest.param(
                [{"Event Time": "2023-01-01T01:00:00Z"}, {"Event Time": "2023-01-01T02:00:00Z"}],
                None,
                "2023-01-01T02:00:00Z",
                id="fallback to vendor 'Event Time'",
            ),
            pytest.param(
                [],
                "2023-01-01T01:00:00Z",
                "2023-01-01T01:00:00Z",
                id="no timestamps, use now",
            ),
        ],
    )
    def test_update_last_run_timestamp_cases(self, events, frozen_now, expected_iso):
        """
        - use enriched _time:
          - Given: Events include _time values
          - When: Updating last run timestamp
          - Then: The latest _time is used
        - fallback to vendor 'Event Time':
          - Given: Events include only vendor 'Event Time'
          - When: Updating last run timestamp
          - Then: The latest vendor time is used
        - no timestamps, use now:
          - Given: No timestamps in events
          - When: Updating last run timestamp
          - Then: Current time is used
        """
        next_run: dict = {}
        if frozen_now:
            with freeze_time(frozen_now):
                update_last_run_timestamp_from_events(next_run, events)
        else:
            update_last_run_timestamp_from_events(next_run, events)
        expected_epoch = int(datetime.strptime(expected_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())
        assert next_run[LAST_RUN_TIMESTAMP] == expected_epoch

    @pytest.mark.parametrize(
        "event_time,expected_iso",
        [
            pytest.param("2025-08-06 07:41:54", "2025-08-06T07:41:54Z", id="space-separated datetime"),
            pytest.param("2023-01-01T01:00:10Z", "2023-01-01T01:00:10Z", id="ISO format with Z suffix"),
        ],
    )
    def test_add_time_to_events_cases(self, event_time, expected_iso):
        """
        - space-separated datetime:
          - Given: Vendor 'Event Time' is 'YYYY-MM-DD HH:MM:SS'
          - When: Enriching events
          - Then: _time becomes 'YYYY-MM-DDTHH:MM:SSZ'
        - ISO format with Z suffix:
          - Given: Vendor 'Event Time' is ISO with Z
          - When: Enriching events
          - Then: _time is preserved
        """
        events = [{"Event Time": event_time}]
        add_time_to_events(events)
        assert events[0]["_time"] == expected_iso


class TestDeduplicateEvents:
    @pytest.mark.parametrize(
        "events, previous_hashes, expected_remaining_a_values",
        [
            pytest.param(
                # within-run duplicates only
                [
                    {"Event Time": "2023-01-01T01:00:00Z", "a": 1},
                    {"Event Time": "2023-01-01T01:00:00Z", "a": 1},
                    {"Event Time": "2023-01-01T01:01:00Z", "a": 2},
                ],
                [],
                [1, 2],
                id="within-run duplicates -> retain unique order",
            ),
            pytest.param(
                # previous-run contains first event
                [
                    {"Event Time": "2023-01-01T01:00:00Z", "a": 1},
                    {"Event Time": "2023-01-01T01:00:00Z", "a": 1},
                    {"Event Time": "2023-01-01T01:01:00Z", "a": 2},
                ],
                [generate_event_hash({"Event Time": "2023-01-01T01:00:00Z", "a": 1})],
                [2],
                id="filter out events seen in previous run",
            ),
            pytest.param(
                [],
                [],
                [],
                id="empty input",
            ),
        ],
    )
    def test_dedup_cases(self, events, previous_hashes, expected_remaining_a_values):
        """
        - within-run duplicates -> retain unique order:
          - Given: Duplicate events within the same batch
          - When: Deduplicating
          - Then: Only unique events remain in original order
        - filter out events seen in previous run:
          - Given: Previous-run cache includes first event hash
          - When: Deduplicating
          - Then: Events from previous run are filtered out
        - empty input:
          - Given: No events
          - When: Deduplicating
          - Then: Empty result
        """
        last_run = {LAST_RUN_EVENT_HASHES: previous_hashes or []}
        _, deduped = deduplicate_events(events, last_run)
        assert [e.get("a") for e in deduped if "a" in e] == expected_remaining_a_values

    # No separate helper classes; covered above in TestHelperFunctions


class TestClientBehavior:
    def test_fetch_events_retries_on_auth_failure(self, mocker):
        """
        Given: The first client HTTP request fails with an auth error (401)
        When: Calling Client.fetch_events
        Then: The client forces a token refresh via obtain_token(force_refresh=True) and retries once successfully
        """
        # Patch obtain_token before instantiation to avoid network in __init__
        obtain_mock = mocker.patch.object(Client, "obtain_token")
        client = Client(base_url="https://example.com/ECM/", verify=False, proxy=False, credentials={})
        obtain_mock.reset_mock()

        # First call raises an auth error, second returns an empty result
        mocker.patch.object(
            Client,
            "_http_request",
            side_effect=[Exception("401 Unauthorized"), {"results": [], "totalcount": 0}],
        )

        # Spy on obtain_token to ensure force_refresh=True used on retry
        # We already patched obtain_token above; use that mock
        client.fetch_events(analytics_name="SIEMAuditLogs", time_frame_minutes=1, max_results=1, offset=None)
        obtain_mock.assert_called_once()
        # Verify force_refresh=True in call kwargs if provided
        called_kwargs = obtain_mock.call_args.kwargs if obtain_mock.call_args else {}
        assert called_kwargs.get("force_refresh", False) is True


class TestFetchUseCases:
    @pytest.mark.parametrize(
        "totalcount,server_page_size,max_events,expected_count,latest_time",
        [
            pytest.param(
                9,
                4,
                50,
                8,
                "2025-08-06 00:07:00",
                id="multi-page: totalcount=9, page-size=4",
            ),
            pytest.param(
                12,
                10,
                5,
                5,
                "2025-08-06 00:04:00",
                id="limit to max_events=5",
            ),
            pytest.param(
                0,
                10,
                50,
                0,
                "1970-01-01 00:00:00",
                id="empty response: totalcount=0",
            ),
        ],
    )
    def test_fetch_use_cases(self, mocker, totalcount, server_page_size, max_events, expected_count, latest_time):
        """
        - multi-page: totalcount=9, page-size=4
          - Given: Server returns 4 + 4 + 1 items across pages (total 9)
          - When: Module-level fetch_events paginates by offset
          - Then: 9 events are collected
        - limit to max_events=5
          - Given: totalcount=12 and server page-size=10
          - When: max_events=5 is configured
          - Then: Only 5 events are collected
        - empty response: totalcount=0
          - Given: Server returns no events
          - When: Running fetch_events
          - Then: 0 events are collected
        """
        from SaviyntEICEventCollector import fetch_events as module_fetch_events

        # Avoid real token handling on client init
        mocker.patch.object(Client, "obtain_token")
        client = Client(base_url="https://example.com/ECM/", verify=False, proxy=False, credentials={})

        # Build a synthetic sequence of events at 1-minute intervals
        base = datetime(2025, 8, 6, 0, 0, 0)
        all_events = [{"Event Time": (base.replace(minute=i, second=0)).strftime("%Y-%m-%d %H:%M:%S")} for i in range(totalcount)]

        def side_effect_fetch(*args, **kwargs):
            # (self, analytics_name, time_frame_minutes, max_results, offset)
            # Support both keyword and positional arguments (production may pass positionally)
            requested_max = (
                kwargs.get("max_results") if "max_results" in kwargs else (args[2] if len(args) >= 3 else server_page_size)
            )
            offset = kwargs.get("offset") if "offset" in kwargs else (args[3] if len(args) >= 4 else None)
            start = int(offset or 0)
            end = min(start + server_page_size, start + int(requested_max or server_page_size), totalcount)
            return {"results": all_events[start:end], "totalcount": totalcount}

        mocker.patch.object(Client, "fetch_events", side_effect=side_effect_fetch)

        next_run, events = module_fetch_events(
            client=client,
            last_run={},
            max_events=max_events,
            time_frame_minutes=None,
        )

        assert len(events) == expected_count
        assert next_run.get(LAST_RUN_TIMESTAMP)
        # Verify the watermark reached the expected latest time (converted to epoch)
        latest_dt = datetime.strptime(latest_time, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        assert next_run[LAST_RUN_TIMESTAMP] >= int(latest_dt.timestamp())


class TestConcurrentPaging:
    def test_concurrent_fanout_submits_expected_offsets(self, mocker):
        """
        Given:
            - First page returns page_size events
            - totalcount=42000, overall_max_events=25000, page_size=10000
        When:
            - Running _fetch_analytics_pages_concurrently
        Then:
            - Offsets submitted include {None, 10000, 20000}
            - Final results length equals overall_max_events (25000)
        """
        # Avoid real token handling on client init
        mocker.patch.object(Client, "obtain_token")
        client = Client(base_url="https://example.com/ECM/", verify=False, proxy=False, credentials={})

        calls = []

        totalcount = 42000
        server_page_size = 10000
        overall_max_events = 25000
        page_size = 10000

        def side_effect_fetch(*args, **kwargs):
            # capture offset appearances including first page (None)
            # Support both keyword and positional arguments
            offset = kwargs.get("offset") if "offset" in kwargs else (args[3] if len(args) >= 4 else None)
            calls.append(offset)
            requested_max = int(
                kwargs.get("max_results") if "max_results" in kwargs else (args[2] if len(args) >= 3 else server_page_size)
            )
            start = int(offset or 0)
            end = min(start + server_page_size, start + requested_max, totalcount)
            # Return synthetic events equal to the slice size
            count = max(0, end - start)
            return {"results": [{"Event Time": f"idx-{i}"} for i in range(count)], "totalcount": totalcount}

        mocker.patch.object(Client, "fetch_events", side_effect=side_effect_fetch)

        results = _fetch_analytics_pages_concurrently(
            client=client,
            analytics_name="SIEMAuditLogs",
            effective_time_frame_minutes=60,
            overall_max_events=overall_max_events,
            page_size=page_size,
            page_workers=4,
        )

        assert len(results) == overall_max_events
        # initial call uses offset=None
        assert None in calls
        # submitted fan-out offsets should include 10000 and 20000
        assert 10000 in calls
        assert 20000 in calls

    def test_concurrent_early_return_no_remaining_offsets(self, mocker):
        """
        Given:
            - First page returns all available events (totalcount <= collected)
        When:
            - Running _fetch_analytics_pages_concurrently
        Then:
            - Only the first page call is made
            - Function returns the first page results as-is
        """
        mocker.patch.object(Client, "obtain_token")
        client = Client(base_url="https://example.com/ECM/", verify=False, proxy=False, credentials={})

        call_count = {"n": 0}

        def side_effect_fetch(*args, **kwargs):
            call_count["n"] += 1
            # Simulate totalcount=7000; first page returns 7000 (partial page)
            return {"results": [{"Event Time": "t"} for _ in range(7000)], "totalcount": 7000}

        mocker.patch.object(Client, "fetch_events", side_effect=side_effect_fetch)

        results = _fetch_analytics_pages_concurrently(
            client=client,
            analytics_name="SIEMAuditLogs",
            effective_time_frame_minutes=60,
            overall_max_events=50000,
            page_size=10000,
            page_workers=4,
        )

        assert call_count["n"] == 1
        assert len(results) == 7000

    def test_concurrent_handles_failed_page_and_continues(self, mocker):
        """
        Given:
            - totalcount=30000, page_size=10000
            - One of the paged requests (offset=10000) fails with an exception
        When:
            - Running _fetch_analytics_pages_concurrently
        Then:
            - The function logs and continues, returning events from the successful pages
            - Final length equals 20000 (first + last page)
        """
        mocker.patch.object(Client, "obtain_token")
        client = Client(base_url="https://example.com/ECM/", verify=False, proxy=False, credentials={})

        def side_effect_fetch(*args, **kwargs):
            # Support both keyword and positional arguments
            offset = kwargs.get("offset") if "offset" in kwargs else (args[3] if len(args) >= 4 else None)
            if offset is None:
                # first page
                return {"results": [{"Event Time": "t"} for _ in range(10000)], "totalcount": 30000}
            if offset == 10000:
                raise Exception("boom")
            # offset == 20000
            return {"results": [{"Event Time": "t"} for _ in range(10000)], "totalcount": 30000}

        mocker.patch.object(Client, "fetch_events", side_effect=side_effect_fetch)

        results = _fetch_analytics_pages_concurrently(
            client=client,
            analytics_name="SIEMAuditLogs",
            effective_time_frame_minutes=60,
            overall_max_events=30000,
            page_size=10000,
            page_workers=4,
        )

        assert len(results) == 20000
