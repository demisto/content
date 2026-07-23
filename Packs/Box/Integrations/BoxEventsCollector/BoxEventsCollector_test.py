import json

import demistomock as demisto
import pytest
from BoxEventsCollector import BoxEventsClient, main


class TestBoxCollectEvents:
    params = {
        "url": "https://api.box.com",
        "credentials_json": {
            "password": json.dumps(
                {
                    "boxAppSettings": {
                        "clientID": "I AM A CLIENT ID",
                        "clientSecret": "I AM A CLIENT SECRET",
                        "appAuth": {
                            "publicKeyID": "PUBLIC KEY ID",
                            "privateKey": "I AM A PRIVATE KEY!!!",
                            "passphrase": "passphrase",
                        },
                    },
                    "enterpriseID": "000000000",
                }
            )
        },
        "created_after": "30 days",
        "verify": False,
    }

    def test_everything_is_called_in_main(self, mocker, requests_mock):
        """Just see that the main works as intended with the mocked data.
        No really running the jwt creation as it need real value"""
        requests_mock.get(
            "https://api.box.com/2.0/events",
            json={"next_stream_position": "0", "entries": []},
        )
        main("box-get-events", self.params)

    def test_fetch_events_is_running(self, mocker, requests_mock):
        """See that call to the fetch events function do calls set last run
        and sends the events to xsiam"""
        params = self.params.copy()
        params["limit"] = 2
        requests_mock.get(
            "https://api.box.com/2.0/events",
            [
                {
                    "json": {
                        "next_stream_position": "600",
                        "entries": [{"sample event": "event"}],
                    }
                },
                {"json": {"next_stream_position": "601", "entries": []}},
            ],
        )

        last_run = mocker.patch.object(demisto, "setLastRun")
        send_events_to_xsiam = mocker.patch("BoxEventsCollector.send_events_to_xsiam")
        main("fetch-events", params)
        assert last_run.call_args_list[0].args[0] == {"stream_position": "601"}
        assert len(send_events_to_xsiam.call_args_list[0].args[0]) == 1

    def _paged_events_callback(self, page_size_default: int):
        """Build a requests_mock callback that honors the `limit` query param like Box does.

        Each response returns exactly ``min(requested_limit, 2)`` events with a monotonically
        increasing stream position, so the test can verify the dynamic page-size shrinking that
        makes the total land exactly on ``max_events_per_fetch`` (XSUP-72996 data-loss fix).
        """
        state = {"counter": 0}

        def callback(request, context):
            requested = int(request.qs.get("limit", [str(page_size_default)])[0])
            # Box never returns more than the requested page size; cap our mock "page" at 2 events.
            page_len = min(requested, 2)
            entries = []
            for _ in range(page_len):
                state["counter"] += 1
                entries.append({"id": f"e{state['counter']}"})
            return {"next_stream_position": str(state["counter"]), "entries": entries}

        return callback

    def test_fetch_events_stops_at_max_events_per_fetch(self, mocker, requests_mock):
        """Regression test for XSUP-72996.

        Given an API that keeps returning non-empty pages (a large backlog), when
        `max_events_per_fetch` is set, the fetch must stop once that many events are reached
        instead of looping until the backlog is drained (which caused the timeout).

        The cap is EXACT and lossless: the per-request page size is shrunk to the remaining
        budget (`min(PAGE_SIZE, remaining)`), so the final page returns precisely the number of
        events needed and its stream position aligns exactly with what was returned - no mid-page
        slicing (which would have lost events) and no overshoot.
        """
        from BoxEventsCollector import PAGE_SIZE

        params = self.params.copy()
        params["max_events_per_fetch"] = 3
        # Mock honors the requested `limit`, returning up to 2 events per page. With a cap of 3:
        #   call 1 -> limit=min(500,3)=3 -> returns 2 events (mock max), total=2
        #   call 2 -> limit=min(500,1)=1 -> returns 1 event, total=3 -> exact stop.
        mocked = requests_mock.get(
            "https://api.box.com/2.0/events",
            json=self._paged_events_callback(page_size_default=PAGE_SIZE),
        )

        last_run = mocker.patch.object(demisto, "setLastRun")
        send_events_to_xsiam = mocker.patch("BoxEventsCollector.send_events_to_xsiam")
        main("fetch-events", params)

        # Exactly max_events_per_fetch events -> exact cap, no overshoot and no loss.
        pushed = send_events_to_xsiam.call_args_list[0].args[0]
        assert [event["id"] for event in pushed] == ["e1", "e2", "e3"]
        # The requested page size shrank across calls to hit the cap exactly: first 3, then 1.
        requested_limits = [req.qs["limit"][0] for req in mocked.request_history]
        assert requested_limits == ["3", "1"]
        # Stream position persisted matches the last event actually returned (3), so the next
        # cycle resumes exactly after e3 with no gap and no duplication.
        assert last_run.call_args_list[0].args[0] == {"stream_position": "3"}

    def test_fetch_events_default_cap_does_not_stop_small_backlog(self, mocker, requests_mock):
        """When max_events_per_fetch is omitted, the default cap applies and a small
        backlog still drains fully via the natural empty-`entries` exit (no premature stop)."""
        params = self.params.copy()  # no max_events_per_fetch -> DEFAULT_MAX_EVENTS_PER_FETCH
        requests_mock.get(
            "https://api.box.com/2.0/events",
            [
                {"json": {"next_stream_position": "1", "entries": [{"id": "e1"}]}},
                {"json": {"next_stream_position": "2", "entries": [{"id": "e2"}]}},
                {"json": {"next_stream_position": "2", "entries": []}},
            ],
        )
        last_run = mocker.patch.object(demisto, "setLastRun")
        send_events_to_xsiam = mocker.patch("BoxEventsCollector.send_events_to_xsiam")
        main("fetch-events", params)

        # All available events collected (backlog < default cap), stopped on empty entries.
        assert len(send_events_to_xsiam.call_args_list[0].args[0]) == 2
        assert last_run.call_args_list[0].args[0] == {"stream_position": "2"}

    def test_page_size_is_capped_by_page_size_constant(self, mocker, requests_mock):
        """When max_events_per_fetch exceeds PAGE_SIZE, the per-request page size sent to the API
        is capped at PAGE_SIZE (Box's maximum) - the total cap never inflates a single request."""
        from BoxEventsCollector import PAGE_SIZE

        params = self.params.copy()
        params["max_events_per_fetch"] = PAGE_SIZE + 100  # larger than a single page
        mocked_request = requests_mock.get(
            "https://api.box.com/2.0/events",
            [
                {"json": {"next_stream_position": "1", "entries": [{"id": "e1"}]}},
                {"json": {"next_stream_position": "1", "entries": []}},
            ],
        )
        mocker.patch.object(demisto, "setLastRun")
        send_events_to_xsiam = mocker.patch("BoxEventsCollector.send_events_to_xsiam")
        main("fetch-events", params)

        # Backlog drained (only 1 event available), and the first request's page size was capped
        # at PAGE_SIZE even though the total budget was larger.
        assert len(send_events_to_xsiam.call_args_list[0].args[0]) == 1
        assert mocked_request.request_history[0].qs["limit"] == [str(PAGE_SIZE)]

    def test_max_events_per_fetch_is_capped_at_the_allowed_maximum(self, mocker, requests_mock):
        """A max_events_per_fetch above MAX_EVENTS_PER_FETCH_LIMIT is clamped to the maximum,
        not passed through as-is, keeping a single fetch within the Docker timeout budget."""
        from BoxEventsCollector import MAX_EVENTS_PER_FETCH_LIMIT, BoxEventsGetter

        params = self.params.copy()
        params["max_events_per_fetch"] = MAX_EVENTS_PER_FETCH_LIMIT + 1000  # above the allowed max
        requests_mock.get(
            "https://api.box.com/2.0/events",
            json={"next_stream_position": "0", "entries": []},
        )
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch("BoxEventsCollector.send_events_to_xsiam")

        # Capture the effective options.limit at the moment run() is invoked.
        captured = {}

        def fake_run(self):
            captured["limit"] = self.client.options.limit
            return []

        mocker.patch.object(BoxEventsGetter, "run", fake_run)
        main("fetch-events", params)

        # The limit used for the fetch must be clamped to the maximum, not the requested value.
        assert captured["limit"] == MAX_EVENTS_PER_FETCH_LIMIT

    @pytest.fixture(autouse=True, scope="function")
    def remove_authentication(self, mocker):
        """We don't need to authenticate in the test functions"""
        mocker.patch.object(BoxEventsClient, "authenticate", return_value=None)

    def test_not_gate(self):
        """Well, I've been forced to raise the coverage"""
        from BoxEventsCollector import not_gate

        assert not_gate(None)
        assert not_gate(False)
        assert not_gate("No")
        assert not not_gate(True)
        assert not not_gate("yes")

    def test_url_as_param(self, mocker, requests_mock):
        """Assert the request url changes when url parameter changes."""
        new_url = "https://api.triangle.com"
        mocked_request = requests_mock.get(
            f"{new_url}/2.0/events",
            json={"next_stream_position": "0", "entries": []},
        )
        different_url_params = self.params.copy()
        different_url_params["url"] = new_url
        main("box-get-events", different_url_params)
        assert mocked_request.called
