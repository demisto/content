import json
from datetime import datetime

import pytest
from freezegun import freeze_time
from WorkdayEventCollector import DATE_FORMAT, DEFAULT_MAX_FETCH, MAX_PAGE_SIZE, Client


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


class TestFetchActivity:
    @pytest.fixture(autouse=True)
    def create_client(self, mocker):
        self.base_url = "https://test.com"
        self.tenant_name = "test"
        self.token_url = f"{self.base_url}/ccx/oauth2/{self.tenant_name}/token"
        mocker.patch.object(Client, "get_access_token", return_value="1234")
        self.client = Client(
            base_url=self.base_url,
            refresh_token="refresh_token",
            client_id="test12",
            client_secret="test_sec1234",
            token_url=self.token_url,
            verify=False,
            proxy=False,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            max_fetch=25000,
        )

    @staticmethod
    def create_response_by_limit(from_date, to_date, offset, user_activity_entry_count=False, limit=1):
        single_response = util_load_json("test_data/single_loggings_response.json")
        return [single_response.copy() for i in range(limit)]

    @pytest.mark.parametrize("loggings_to_fetch", [1, 4, 6], ids=["Single", "Part", "All"])
    def test_get_max_fetch_activity_logging(self, loggings_to_fetch, requests_mock, mocker):
        """
        Given: number of logging to fetch.
        When: running get activity logging command or fetch.
        Then: return the correct number of loggings.

        """
        from WorkdayEventCollector import get_max_fetch_activity_logging

        mocker.patch.object(Client, "get_activity_logging_request", side_effect=self.create_response_by_limit)
        res = get_max_fetch_activity_logging(
            client=self.client,
            logging_to_fetch=loggings_to_fetch,
            from_date="2023-04-15T07:00:00.000Z",
            to_date="2023-04-16T07:00:00.000Z",
        )
        assert len(res) == loggings_to_fetch

    def test_get_max_fetch_activity_logging_paginates_above_page_size(self, mocker):
        """
        Given: a max_fetch (logging_to_fetch) larger than the per-call page cap (3 * MAX_PAGE_SIZE).
        When: running get_max_fetch_activity_logging.
        Then: the client is called multiple times (pagination), each call is capped at MAX_PAGE_SIZE,
              the offset advances by the number of events returned, and all events are collected.
        """
        from WorkdayEventCollector import get_max_fetch_activity_logging

        logging_to_fetch = 3 * MAX_PAGE_SIZE

        def response_by_requested_limit(from_date, to_date, offset, limit):
            # Workday returns up to `limit` events (page cap enforced by caller at MAX_PAGE_SIZE).
            single_response = util_load_json("test_data/single_loggings_response.json")
            return [single_response.copy() for _ in range(limit)]

        request_mock = mocker.patch.object(Client, "get_activity_logging_request", side_effect=response_by_requested_limit)

        res = get_max_fetch_activity_logging(
            client=self.client,
            logging_to_fetch=logging_to_fetch,
            from_date="2023-04-15T07:00:00.000Z",
            to_date="2023-04-16T07:00:00.000Z",
        )

        # logging_to_fetch / MAX_PAGE_SIZE => exactly 3 paginated API calls.
        assert request_mock.call_count == 3
        # Every call must be capped at the per-call page limit.
        assert [call.kwargs["limit"] for call in request_mock.call_args_list] == [MAX_PAGE_SIZE, MAX_PAGE_SIZE, MAX_PAGE_SIZE]
        # Offset must advance by the number of events collected so far.
        assert [call.kwargs["offset"] for call in request_mock.call_args_list] == [0, MAX_PAGE_SIZE, 2 * MAX_PAGE_SIZE]
        # All events are accumulated across the pages.
        assert len(res) == logging_to_fetch

    def test_get_max_fetch_activity_logging_stops_on_empty_page(self, mocker):
        """
        Given: a large max_fetch but the source runs out of events mid-pagination.
        When: running get_max_fetch_activity_logging.
        Then: pagination stops as soon as an empty page is returned (no infinite loop),
              and only the available events are collected.
        """
        from WorkdayEventCollector import get_max_fetch_activity_logging

        single_response = util_load_json("test_data/single_loggings_response.json")
        first_page = [single_response.copy() for _ in range(MAX_PAGE_SIZE)]
        second_page = [single_response.copy() for _ in range(MAX_PAGE_SIZE // 2)]
        request_mock = mocker.patch.object(
            Client,
            "get_activity_logging_request",
            side_effect=[first_page, second_page, []],
        )

        res = get_max_fetch_activity_logging(
            client=self.client,
            logging_to_fetch=3 * MAX_PAGE_SIZE,
            from_date="2023-04-15T07:00:00.000Z",
            to_date="2023-04-16T07:00:00.000Z",
        )

        available_events = MAX_PAGE_SIZE + MAX_PAGE_SIZE // 2
        # Third call returns empty -> loop breaks. Only the available events are collected.
        assert request_mock.call_count == 3
        assert [call.kwargs["offset"] for call in request_mock.call_args_list] == [0, MAX_PAGE_SIZE, available_events]
        assert len(res) == available_events

    def test_resolve_max_fetch_uses_provided_value(self):
        """
        Given: a max_fetch value is provided in the params.
        When: running resolve_max_fetch.
        Then: the provided value is returned (as an int).
        """
        from WorkdayEventCollector import resolve_max_fetch

        assert resolve_max_fetch({"max_fetch": "500"}) == 500

    @pytest.mark.parametrize("params", [{}, {"max_fetch": None}, {"max_fetch": ""}], ids=["missing", "none", "empty"])
    def test_resolve_max_fetch_falls_back_to_default(self, params):
        """
        Given: max_fetch is missing, None, or empty in the params.
        When: running resolve_max_fetch.
        Then: DEFAULT_MAX_FETCH is returned.
        """
        from WorkdayEventCollector import resolve_max_fetch

        assert resolve_max_fetch(params) == DEFAULT_MAX_FETCH

    @staticmethod
    def _event(task_id, request_time, session_id="s", system_account="a", activity_action="READ", ip="1.1.1.1"):
        """Builds a minimal activity logging event with the fields used for identity/dedup."""
        return {
            "taskId": str(task_id),
            "requestTime": request_time,
            "sessionId": session_id,
            "systemAccount": system_account,
            "activityAction": activity_action,
            "ipAddress": ip,
        }

    def test_remove_duplications_no_previous_ids_keeps_everything(self):
        """
        Given: a first fetch (last_run has no previous_event_ids).
        When: running remove_duplications.
        Then: nothing is removed.
        """
        from WorkdayEventCollector import remove_duplications

        loggings = [self._event(1, "2023-04-15T07:00:00.100Z"), self._event(2, "2023-04-15T07:00:00.200Z")]
        assert remove_duplications(loggings, {}) == loggings

    def test_remove_duplications_removes_only_previously_ingested(self):
        """
        Given: last_run tracks the identity of an event already ingested last cycle.
        When: running remove_duplications on a batch that re-contains that event plus new ones.
        Then: only the previously-ingested event is removed; new events are kept.
        """
        from WorkdayEventCollector import get_event_identity, remove_duplications

        already_ingested = self._event(1, "2023-04-15T07:00:00.100Z")
        new_event = self._event(2, "2023-04-15T07:00:00.150Z")
        last_run = {"previous_event_ids": [get_event_identity(already_ingested)]}

        result = remove_duplications([already_ingested, new_event], last_run)

        assert result == [new_event]

    def test_remove_duplications_keeps_new_event_that_sorts_before_checkpoint(self):
        """
        Regression for XSUP-75678: a NEW event in the boundary second that sorts BEFORE the stored
        checkpoint must NOT be dropped.

        Given: last cycle ingested an event at .697; this cycle the API returns (in a different
               order) a brand-new event at .300 (earlier in the same second) plus the old .697 event.
        When: running remove_duplications.
        Then: the new .300 event is kept (previously it was silently discarded by position), and the
              duplicate .697 event is removed.
        """
        from WorkdayEventCollector import get_event_identity, remove_duplications

        previously_ingested = self._event(10, "2026-08-26T10:27:53.697Z")
        brand_new_earlier = self._event(11, "2026-08-26T10:27:53.300Z")
        last_run = {"previous_event_ids": [get_event_identity(previously_ingested)]}

        # API returns the new (earlier) event first, then the already-ingested one.
        result = remove_duplications([brand_new_earlier, previously_ingested], last_run)

        assert brand_new_earlier in result
        assert previously_ingested not in result
        assert len(result) == 1

    def test_remove_milliseconds_from_time_of_logging(self):
        """
        Given: loggings with time string with milliseconds
        When: Building the whole-second request bound
        Then: Remove the milliseconds.

        """
        from WorkdayEventCollector import remove_milliseconds_from_time_of_logging

        activity_logging: dict = util_load_json("test_data/single_loggings_response.json")
        requests_time = "2023-04-24T07:00:00.123Z"
        final_time = "2023-04-24T07:00:00Z"
        activity_logging["requestTime"] = requests_time

        assert remove_milliseconds_from_time_of_logging(activity_logging) == final_time

    def test_build_next_last_run_tracks_boundary_second_ids(self):
        """
        Given: a batch of deduped events where several share the latest whole second.
        When: running build_next_last_run.
        Then: last_fetch_time is the whole-second floor of the latest event, and previous_event_ids
              contains exactly the identities of the events in that latest second (so the next cycle
              can dedup the re-requested second by identity).
        """
        from WorkdayEventCollector import build_next_last_run, get_event_identity

        earlier = self._event(1, "2026-08-26T10:27:52.900Z")
        boundary_a = self._event(2, "2026-08-26T10:27:53.100Z")
        boundary_b = self._event(3, "2026-08-26T10:27:53.800Z")

        next_last_run = build_next_last_run([earlier, boundary_a, boundary_b], {})

        assert next_last_run["last_fetch_time"] == "2026-08-26T10:27:53Z"
        assert next_last_run["latest_request_time"] == "2026-08-26T10:27:53.800Z"
        assert set(next_last_run["previous_event_ids"]) == {
            get_event_identity(boundary_a),
            get_event_identity(boundary_b),
        }

    def test_build_next_last_run_empty_preserves_previous(self):
        """
        Given: no new events this cycle.
        When: running build_next_last_run.
        Then: the previous last_run is preserved (no checkpoint regression).
        """
        from WorkdayEventCollector import build_next_last_run

        previous = {"last_fetch_time": "2026-08-26T10:27:53Z", "previous_event_ids": ["x"]}
        assert build_next_last_run([], previous) == previous

    @freeze_time("2023-04-15 08:00:00")
    def test_fetch_migrates_from_old_last_run_shape_without_loss(self, mocker):
        """
        Backward-compatibility / upgrade safety: when our new code is uploaded over the client's
        version, the FIRST fetch reads the OLD last_run shape (which only has `last_fetch_time` and
        `last_log`, and NO `previous_event_ids`).

        Given: an old-shape last_run (no `previous_event_ids`).
        When: running fetch_activity_logging.
        Then:
            - It continues from the old `last_fetch_time` (no gap, no crash on missing keys).
            - It does not silently drop events (keeps everything on this transition cycle).
            - It writes the NEW shape (adds `previous_event_ids`) so subsequent cycles self-heal.
        """
        from WorkdayEventCollector import fetch_activity_logging

        first_fetch_time = datetime.strptime("2023-04-12T07:00:00Z", DATE_FORMAT)
        fetched_events = util_load_json("test_data/fetch_activity_loggings.json")
        new_batch = fetched_events.get("fetch_loggings")  # taskIds 2 and 3

        # Old-shape last_run as it would exist on the client tenant before the upgrade.
        old_last_run = {
            "last_fetch_time": "2023-04-15T07:00:00Z",
            "last_log": {"taskId": "3", "requestTime": "2023-04-15T07:00:00.000Z"},
        }

        http_responses = mocker.patch.object(Client, "get_activity_logging_request", side_effect=[new_batch, []])

        activity_loggings, new_last_run = fetch_activity_logging(
            self.client, last_run=old_last_run, first_fetch=first_fetch_time, max_fetch=3
        )

        # Continues from the old checkpoint (no gap).
        assert http_responses.call_args_list[0][1]["from_date"] == "2023-04-15T07:00:00Z"
        # No silent loss on the transition cycle.
        assert activity_loggings == new_batch
        # New shape is now persisted so the next cycle deduplicates by identity.
        assert "previous_event_ids" in new_last_run
        assert len(new_last_run["previous_event_ids"]) == 2

    def test_get_activity_logging_command(self, mocker):
        """
        Given: params to run get_activity_logging_command
        When: running the command
        Then: Accurate response and readable output is returned.
        """
        from WorkdayEventCollector import get_activity_logging_command

        mocker.patch.object(Client, "get_activity_logging_request", side_effect=self.create_response_by_limit)
        activity_loggings, res = get_activity_logging_command(
            client=self.client, from_date="2023-04-15T07:00:00Z", to_date="2023-04-16T07:00:00Z", limit=4, offset=0
        )
        assert len(activity_loggings) == 4
        assert "Activity Logging List" in res.readable_output

    @freeze_time("2023-04-15 08:00:00")
    def test_fetch_activity_logging(self, mocker):
        """
        Tests the fetch_events function

        Given:
            - first_fetch_time
        When:
            - Running the 'fetch_activity_logging' function.
        Then:
            - Validates that the function generates the correct API requests with the expected parameters.
            - Validates that the function returns the expected events and next_run timestamps.
        """
        from WorkdayEventCollector import fetch_activity_logging

        first_fetch_time = datetime.strptime("2023-04-12T07:00:00Z", DATE_FORMAT)
        fetched_events = util_load_json("test_data/fetch_activity_loggings.json")
        http_responses = mocker.patch.object(
            Client,
            "get_activity_logging_request",
            side_effect=[
                fetched_events.get("fetch_loggings_before"),
                fetched_events.get("fetch_loggings"),
            ],
        )

        activity_loggings, new_last_run = fetch_activity_logging(
            self.client, last_run={}, first_fetch=first_fetch_time, max_fetch=3
        )

        assert http_responses.call_args_list[0][1] == {
            "limit": 3,
            "offset": 0,
            "from_date": "2023-04-12T07:00:00Z",
            "to_date": "2023-04-15T08:00:00Z",
        }
        assert http_responses.call_args_list[1][1] == {
            "limit": 2,
            "offset": 1,
            "from_date": "2023-04-12T07:00:00Z",
            "to_date": "2023-04-15T08:00:00Z",
        }

        assert activity_loggings == fetched_events.get("fetched_events")
        assert new_last_run.get("last_fetch_time") == "2023-04-15T07:00:00Z"
        # The boundary second (2023-04-15T07:00:00) contains taskIds 2 and 3 (identical requestTime),
        # both tracked for identity-based dedup on the next cycle.
        assert len(new_last_run.get("previous_event_ids")) == 2

        # assert no new results when the same boundary-second events are returned again:
        fetched_events = util_load_json("test_data/fetch_activity_loggings.json")
        http_responses = mocker.patch.object(
            Client, "get_activity_logging_request", side_effect=[fetched_events.get("fetch_loggings"), []]
        )

        activity_loggings, new_last_run = fetch_activity_logging(
            self.client, last_run=new_last_run, first_fetch=first_fetch_time, max_fetch=3
        )
        assert http_responses.call_args_list[0][1] == {
            "limit": 3,
            "offset": 0,
            "from_date": "2023-04-15T07:00:00Z",
            "to_date": "2023-04-15T08:00:00Z",
        }
        # Both re-returned events were already ingested -> deduped by identity -> nothing new.
        assert activity_loggings == []
        # Checkpoint is preserved unchanged when there are no new events (no regression, still tracks
        # the boundary-second identities so the next cycle keeps deduping correctly).
        assert new_last_run.get("last_fetch_time") == "2023-04-15T07:00:00Z"
        assert len(new_last_run.get("previous_event_ids")) == 2

    @freeze_time("2023-04-15 08:00:00")
    def test_fetch_activity_logging_keeps_new_event_in_rerequested_second(self, mocker):
        """
        Regression for XSUP-75678 at the fetch level.

        Given:
            - A previous checkpoint at the boundary second 2023-04-15T07:00:00 with two ingested
              events (taskIds 2 and 3).
            - The next API call re-returns those two events AND a brand-new event (taskId 99) in the
              same second that sorts BEFORE them.
        When:
            - Running fetch_activity_logging.
        Then:
            - Only the brand-new event is ingested (the two duplicates are removed), and no event is
              silently dropped despite sorting before the stored checkpoint.
        """
        from WorkdayEventCollector import fetch_activity_logging, get_event_identity

        first_fetch_time = datetime.strptime("2023-04-12T07:00:00Z", DATE_FORMAT)
        fetched_events = util_load_json("test_data/fetch_activity_loggings.json")
        boundary_events = fetched_events.get("fetch_loggings")  # taskIds 2 and 3 at ...07:00:00.000Z

        last_run = {
            "last_fetch_time": "2023-04-15T07:00:00Z",
            "previous_event_ids": [get_event_identity(event) for event in boundary_events],
        }

        brand_new = dict(boundary_events[0])
        brand_new["taskId"] = "99"
        # Same second, but the API returns it first (out of order) to reproduce the original bug.
        reordered_batch = [brand_new, boundary_events[0], boundary_events[1]]

        mocker.patch.object(Client, "get_activity_logging_request", side_effect=[reordered_batch, []])

        activity_loggings, new_last_run = fetch_activity_logging(
            self.client, last_run=last_run, first_fetch=first_fetch_time, max_fetch=3
        )

        assert activity_loggings == [brand_new]
        assert get_event_identity(brand_new) in new_last_run.get("previous_event_ids")

    @pytest.mark.parametrize("max_fetch, instance_returned", [(6000, 1), (15000, 2), (60000, 6)])
    def test_instance_returned_request(self, mocker, max_fetch, instance_returned):
        self.client.max_fetch = max_fetch
        http_request = mocker.patch.object(Client, "http_request")
        self.client.get_activity_logging_request(from_date="2023-04-15T07:00:00Z", to_date="2023-04-15T08:00:00Z")
        params_sent = http_request.call_args_list[0][1].get("params", {})
        assert params_sent.get("instancesReturned") == instance_returned
