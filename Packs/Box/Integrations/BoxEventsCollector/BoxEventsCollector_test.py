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

    def test_fetch_events_stops_at_max_events_per_fetch(self, mocker, requests_mock):
        """Regression test for XSUP-72996.

        Given an API that keeps returning non-empty pages (a large backlog), when
        `max_events_per_fetch` is set, the fetch must stop after that many events
        instead of looping until the backlog is drained (which caused the timeout).
        It must also still persist the stream position via setLastRun.
        """
        params = self.params.copy()
        params["page_size"] = 1
        params["max_events_per_fetch"] = 3
        # Every page returns one event and a new stream position -> never-empty backlog.
        requests_mock.get(
            "https://api.box.com/2.0/events",
            [
                {"json": {"next_stream_position": "1", "entries": [{"id": "e1"}]}},
                {"json": {"next_stream_position": "2", "entries": [{"id": "e2"}]}},
                {"json": {"next_stream_position": "3", "entries": [{"id": "e3"}]}},
                {"json": {"next_stream_position": "4", "entries": [{"id": "e4"}]}},
                {"json": {"next_stream_position": "5", "entries": [{"id": "e5"}]}},
            ],
        )

        last_run = mocker.patch.object(demisto, "setLastRun")
        send_events_to_xsiam = mocker.patch("BoxEventsCollector.send_events_to_xsiam")
        main("fetch-events", params)

        # Exactly max_events_per_fetch events pushed, not the whole backlog.
        assert len(send_events_to_xsiam.call_args_list[0].args[0]) == 3
        # Stream position was persisted so the next cycle resumes the backlog.
        # The marker reflects the position reached when the total cap was hit.
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

    def test_page_size_and_max_events_per_fetch_are_independent(self, mocker, requests_mock):
        """`page_size` is sent to the API as the per-request `limit` query param, while
        `max_events_per_fetch` caps the total. They must not be conflated (root cause of XSUP-72996)."""
        params = self.params.copy()
        params["page_size"] = 250
        params["max_events_per_fetch"] = 1
        mocked_request = requests_mock.get(
            "https://api.box.com/2.0/events",
            [
                {"json": {"next_stream_position": "1", "entries": [{"id": "e1"}]}},
                {"json": {"next_stream_position": "2", "entries": [{"id": "e2"}]}},
            ],
        )
        mocker.patch.object(demisto, "setLastRun")
        send_events_to_xsiam = mocker.patch("BoxEventsCollector.send_events_to_xsiam")
        main("fetch-events", params)

        # Total capped at max_events_per_fetch (1), independent of the 250 page size.
        assert len(send_events_to_xsiam.call_args_list[0].args[0]) == 1
        # page_size was sent to the API as the `limit` query param, not overridden by the total cap.
        assert mocked_request.last_request.qs["limit"] == ["250"]

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
