import json
from datetime import UTC, datetime, timedelta

import dateutil.parser
import dateutil.parser._parser
import pytest
from OktaEventCollector import (
    Client,
    CommandResults,
    Config,
    DemistoException,
    add_time_to_events,
    fetch_events,
    get_events_command,
    get_last_run,
    okta_get_events_command,
    parse_link_header,
    parse_time_argument,
    remove_duplicates,
    resolve_page_size,
)
from OktaEventCollector import test_module as run_test_module

BASE_URL = "https://okta.example.com"
NEXT_URL = "https://okta.example.com/api/v1/logs?after=cursor2"
SELF_URL = "https://okta.example.com/api/v1/logs?after=cursor1"


class MockResponse:
    """Minimal stand-in for an httpx.Response.

    Only the attributes the collector actually touches are implemented: json() for the
    body and headers for the RFC 5988 Link pagination cursor.
    """

    def __init__(self, data=None, status_code=200, headers=None):
        self.data = data if data is not None else []
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return self.data

    @property
    def text(self):
        return json.dumps(self.data)


def link_headers(next_url=NEXT_URL, self_url=SELF_URL):
    """Build a Link header in the format the Okta System Log API returns."""
    parts = []
    if self_url:
        parts.append(f'<{self_url}>; rel="self"')
    if next_url:
        parts.append(f'<{next_url}>; rel="next"')
    return {"link": ", ".join(parts)}


def make_events(count, published="2022-04-17T12:32:36.667", prefix="uuid"):
    """Build a page of events sharing a published timestamp."""
    return [{"uuid": f"{prefix}-{i}", "published": published} for i in range(count)]


id1_pub = [{"uuid": "a5b57ec5feaa", "published": "2022-04-17T12:32:36.667"}]
id2_pub = [{"uuid": "a5b57ec5febb", "published": "2022-04-17T12:33:36.667"}]

id1 = {"uuid": "a5b57ec5febb"}
id2 = {"uuid": "a5b57ec5fecc"}
id3 = {"uuid": "a12f3c5d77f3"}


@pytest.fixture
def dummy_client():
    """A dummy client fixture for testing."""
    return Client(BASE_URL, "api_key")


# region parse_link_header


@pytest.mark.parametrize(
    "headers,rel,expected",
    [
        pytest.param(link_headers(), "next", NEXT_URL, id="next_relation_present"),
        pytest.param(link_headers(), "self", SELF_URL, id="self_relation_present"),
        pytest.param(link_headers(next_url=""), "next", "", id="only_self_relation"),
        pytest.param(link_headers(self_url=""), "next", NEXT_URL, id="only_next_relation"),
        pytest.param({}, "next", "", id="no_headers"),
        pytest.param({"link": ""}, "next", "", id="empty_link_header"),
        pytest.param({"Link": f'<{NEXT_URL}>; rel="next"'}, "next", NEXT_URL, id="capitalized_header_name"),
        pytest.param({"link": f'<{NEXT_URL}>;rel="next"'}, "next", NEXT_URL, id="no_whitespace"),
        pytest.param({"link": f'<{NEXT_URL}>  ;  rel = "next"'}, "next", NEXT_URL, id="extra_whitespace"),
        pytest.param({"link": "malformed-header"}, "next", "", id="malformed_no_brackets"),
        pytest.param({"link": f"<{NEXT_URL}>; rel=next"}, "next", "", id="unquoted_rel_ignored"),
        pytest.param(link_headers(), "prev", "", id="missing_relation"),
    ],
)
def test_parse_link_header(headers, rel, expected):
    """
    Given: A response carrying an RFC 5988 Link header in various shapes.
    When: Extracting a specific relation.
    Then: The matching URL is returned, or an empty string when absent or malformed.
    """
    assert parse_link_header(MockResponse(headers=headers), rel=rel) == expected


def test_parse_link_header_defaults_to_next():
    """
    Given: A Link header containing both self and next relations.
    When: Calling without an explicit relation.
    Then: The next relation is returned by default.
    """
    assert parse_link_header(MockResponse(headers=link_headers())) == NEXT_URL


# endregion

# region resolve_page_size


@pytest.mark.parametrize(
    "remaining,expected",
    [
        pytest.param(1, 1, id="single_event"),
        pytest.param(10, 10, id="below_maximum"),
        pytest.param(999, 999, id="just_below_maximum"),
        pytest.param(1000, 1000, id="exactly_maximum"),
        pytest.param(1001, 1000, id="just_above_maximum"),
        pytest.param(10000, 1000, id="default_limit"),
        pytest.param(50000, 1000, id="far_above_maximum"),
    ],
)
def test_resolve_page_size(remaining, expected):
    """
    Given: A number of events still required to satisfy the configured limit.
    When: Resolving the page size for the next request.
    Then: The page size never exceeds the Okta per-request maximum.
    """
    assert resolve_page_size(remaining) == expected


# endregion

# region remove_duplicates


@pytest.mark.parametrize(
    "events,ids,result",
    [
        pytest.param([id1, id2, id3], ["a12f3c5d77f3"], [id1, id2], id="one_duplicate"),
        pytest.param([id1, id2, id3], ["a12f3c5dxxxx"], [id1, id2, id3], id="no_matching_ids"),
        pytest.param([id1], ["a5b57ec5febb"], [], id="all_duplicates"),
        pytest.param([], ["a5b57ec5febb"], [], id="no_events"),
        pytest.param([id1, id2], [], [id1, id2], id="no_ids"),
        pytest.param([id1, id2], ["a5b57ec5febb", "a5b57ec5febb"], [id2], id="repeated_ids"),
        pytest.param([{"published": "x"}], ["a5b57ec5febb"], [{"published": "x"}], id="event_without_uuid_kept"),
        pytest.param(
            [{"uuid": i} for i in range(10)],
            [0, 4, 7, 9],
            [{"uuid": 1}, {"uuid": 2}, {"uuid": 3}, {"uuid": 5}, {"uuid": 6}, {"uuid": 8}],
            id="several_duplicates",
        ),
    ],
)
def test_remove_duplicates(events, ids, result):
    """
    Given: A page of events and the UUIDs collected in the previous run.
    When: Deduplicating.
    Then: Only events whose UUID was not previously seen remain.
    """
    assert remove_duplicates(events, ids) == result


# endregion

# region add_time_to_events


@pytest.mark.parametrize(
    "events,expected",
    [
        pytest.param([], [], id="empty_batch"),
        pytest.param(
            [{"uuid": "a", "published": "2022-04-17T12:32:36.667"}],
            ["2022-04-17T12:32:36.667"],
            id="single_event",
        ),
        pytest.param(
            [{"uuid": "a", "published": "2022-04-17T12:32:36.667"}, {"uuid": "b", "published": "2022-04-17T12:33:36.667"}],
            ["2022-04-17T12:32:36.667", "2022-04-17T12:33:36.667"],
            id="multiple_events",
        ),
    ],
)
def test_add_time_to_events(events, expected):
    """
    Given: Events carrying a published timestamp.
    When: Enriching them for XSIAM ingestion.
    Then: Each event gains a _time field mirroring its published value.
    """
    add_time_to_events(events)

    assert [event["_time"] for event in events] == expected


@pytest.mark.parametrize(
    "event",
    [
        pytest.param({"uuid": "a"}, id="published_absent"),
        pytest.param({"uuid": "a", "published": ""}, id="published_empty"),
        pytest.param({"uuid": "a", "published": None}, id="published_none"),
    ],
)
def test_add_time_to_events_without_published(event):
    """
    Given: A malformed event with no usable published timestamp.
    When: Enriching it for XSIAM ingestion.
    Then: No _time field is invented and the batch is not rejected.
    """
    add_time_to_events([event])

    assert "_time" not in event


# endregion

# region parse_time_argument


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("5 minutes ago", id="relative_minutes"),
        pytest.param("3 days", id="relative_days"),
        pytest.param(" 1 hour ", id="padded_whitespace"),
        pytest.param("2026-01-01T10:00:00Z", id="absolute_iso_utc"),
    ],
)
def test_parse_time_argument_returns_utc(value):
    """
    Given: A time argument in a supported format.
    When: Parsing it.
    Then: The result is timezone aware and normalized to UTC, because Okta reads an
          offset-less timestamp as UTC and a naive local value would shift the window.
    """
    parsed = dateutil.parser.isoparse(parse_time_argument(value, "start_time"))

    assert parsed.utcoffset() == timedelta(0)


def test_parse_time_argument_relative_value_is_in_the_past():
    """
    Given: A relative lookback argument.
    When: Parsing it while the container runs in a non UTC timezone.
    Then: The window starts in the past rather than drifting into the future.
    """
    parsed = dateutil.parser.isoparse(parse_time_argument(Config.DEFAULT_FROM_TIME, "start_time"))

    assert parsed < datetime.now(UTC)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("not a real date", id="nonsense_text"),
        pytest.param("", id="empty_string"),
        pytest.param("   ", id="whitespace_only"),
    ],
)
def test_parse_time_argument_invalid_raises(value):
    """
    Given: A time argument that cannot be parsed.
    When: Parsing it.
    Then: A DemistoException names the offending argument instead of an AttributeError.
    """
    with pytest.raises(DemistoException, match="Could not parse the 'start_time' argument"):
        parse_time_argument(value, "start_time")


# endregion

# region get_last_run


@pytest.mark.parametrize(
    "events,last_run_after,result",
    [
        pytest.param(
            [
                {"published": "2022-04-17T12:31:36.667", "uuid": "aaa"},
                {"published": "2022-04-17T12:32:36.667", "uuid": "bbb"},
                {"published": "2022-04-17T12:33:36.667", "uuid": "ccc"},
            ],
            "2022-04-17T11:30:00.000",
            {"after": "2022-04-17T12:33:36.667000", "ids": ["ccc"], "next_link": ""},
            id="distinct_timestamps",
        ),
        pytest.param(
            [
                {"published": "2022-04-17T12:31:36.667", "uuid": "aaa"},
                {"published": "2022-04-17T12:32:36.667", "uuid": "bbb"},
                {"published": "2022-04-17T12:32:36.667", "uuid": "ccc"},
            ],
            "2022-04-17T11:30:00.000",
            {"after": "2022-04-17T12:32:36.667000", "ids": ["ccc", "bbb"], "next_link": ""},
            id="shared_latest_timestamp",
        ),
        pytest.param(
            [
                {"published": "2022-04-17T12:32:36.667", "uuid": "aaa"},
                {"published": "2022-04-17T12:32:36.667", "uuid": "bbb"},
            ],
            "2022-04-17T11:30:00.000",
            {"after": "2022-04-17T12:32:36.667000", "ids": ["bbb", "aaa"], "next_link": ""},
            id="all_same_timestamp",
        ),
        pytest.param(
            [],
            "2022-04-17T12:31:36.667",
            {"after": "2022-04-17T12:31:36.667000", "ids": [], "next_link": ""},
            id="no_events_cursor_preserved",
        ),
    ],
)
def test_get_last_run(events, last_run_after, result):
    """
    Given: The events collected during a cycle.
    When: Building the last run object.
    Then: The cursor advances to the latest timestamp and its UUIDs are stored.
    """
    assert get_last_run(events, last_run_after, next_link="") == result


def test_get_last_run_with_different_format():
    """
    Given: Timestamps without sub-second precision.
    When: Building the last run object.
    Then: The fallback parser handles the format.
    """
    events = [
        {"published": "2022-04-17T12:31:36", "uuid": "aaa"},
        {"published": "2022-04-17T12:33:36", "uuid": "ccc"},
    ]
    expected = {"after": "2022-04-17T12:33:36", "ids": ["ccc"], "next_link": ""}
    assert get_last_run(events, "2022-04-17T11:30:00", next_link="") == expected


@pytest.mark.parametrize("next_link", [NEXT_URL, ""], ids=["with_cursor", "without_cursor"])
def test_get_last_run_preserves_next_link(next_link):
    """
    Given: A pagination cursor that must survive into the next fetch cycle.
    When: Building the last run object.
    Then: The next_link is stored alongside the timestamp cursor.
    """
    events = [{"published": "2022-04-17T12:31:36.667", "uuid": "aaa"}]
    assert get_last_run(events, "2022-04-17T11:30:00.000", next_link=next_link)["next_link"] == next_link


def test_get_last_run_invalid_date_format():
    """
    Given: An event whose published timestamp cannot be parsed.
    When: Building the last run object.
    Then: The parser error surfaces rather than silently corrupting the cursor.
    """
    events = [
        {"published": "2022-04-17T12:31:36", "uuid": "aaa"},
        {"published": "xxxyyyzzz", "uuid": "ccc"},
    ]
    with pytest.raises(dateutil.parser._parser.ParserError):
        get_last_run(events, "2022-04-17T11:30:00", next_link="")


def test_get_last_run_returns_empty_on_unexpected_error(mocker, capfd):
    """
    Given: A published value that raises an unexpected error while parsing.
    When: Building the last run object.
    Then: An empty dict is returned so the caller leaves the stored cursor untouched.
    """
    mocker.patch("OktaEventCollector.datetime").strptime.side_effect = TypeError("boom")
    mocker.patch("OktaEventCollector.parse", side_effect=TypeError("boom"))

    with capfd.disabled():
        assert get_last_run([{"published": "2022-04-17T12:31:36.667", "uuid": "aaa"}], "x", next_link="") == {}


# endregion

# region get_events_command


def test_get_events_success(dummy_client, mocker):
    """
    Given: A single page of events smaller than the requested page size.
    When: Running the pagination loop.
    Then: The events are returned and the loop stops.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])

    events, next_link = get_events_command(dummy_client, 10, "since")

    assert events == id1_pub
    assert next_link == ""


def test_get_events_dedup_removes_all(dummy_client, mocker):
    """
    Given: A page whose events were all collected in the previous run.
    When: Running the pagination loop with last_object_ids.
    Then: No events remain and the cursor is cleared.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub, headers=link_headers())])

    events, next_link = get_events_command(dummy_client, 10, "since", last_object_ids=["a5b57ec5feaa"])

    assert events == []
    assert next_link == ""


@pytest.mark.parametrize(
    "duplicate_pages",
    [
        pytest.param(1, id="one_all_duplicate_page"),
        pytest.param(3, id="three_all_duplicate_pages"),
    ],
)
def test_get_events_all_duplicate_page_terminates(dummy_client, mocker, duplicate_pages):
    """
    Given: Pages whose events were every one of them collected in a previous run, each
           still advertising a next cursor so the API keeps offering more.
    When: Running the pagination loop with a limit far larger than the page size.
    Then: The loop terminates instead of spinning forever.

    Regression guard for the reported infinite loop risk. side_effect is a finite list,
    so a loop that failed to break would raise StopIteration rather than hang the suite.
    """
    mocker.patch.object(Config, "PAGE_SIZE", 1)
    get_events_mock = mocker.patch.object(
        dummy_client,
        "get_events",
        side_effect=[MockResponse(data=id1_pub, headers=link_headers())] * duplicate_pages,
    )

    events, next_link = get_events_command(dummy_client, 10_000, "since", last_object_ids=["a5b57ec5feaa"])

    # The very first all-duplicate page breaks the loop, so only one request is issued
    # no matter how many further pages the API was willing to serve.
    assert get_events_mock.call_count == 1
    assert events == []
    assert next_link == ""


def test_get_events_advances_cursor_before_deduplication(dummy_client, mocker):
    """
    Given: A first page that is entirely duplicated, followed by a page of new events.
    When: Running the pagination loop across both.
    Then: The second request uses a cursor advanced past the duplicated page.

    This ordering is what makes an infinite loop impossible even if the all-duplicate
    break were removed: a repeated page can never be re-requested with the same cursor.
    """
    mocker.patch.object(Config, "PAGE_SIZE", 1)
    get_events_mock = mocker.patch.object(
        dummy_client,
        "get_events",
        side_effect=[MockResponse(data=id1_pub), MockResponse(data=id2_pub)],
    )

    get_events_command(dummy_client, 2, "original-since")

    assert get_events_mock.call_args_list[0].kwargs["since"] == "original-since"
    assert get_events_mock.call_args_list[1].kwargs["since"] == id1_pub[-1]["published"]


def test_get_events_dedup_keeps_new_events(dummy_client, mocker):
    """
    Given: A page mixing previously seen and new events.
    When: Running the pagination loop with last_object_ids.
    Then: Only the new events are kept.
    """
    page = id1_pub + id2_pub
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=page)])

    events, _ = get_events_command(dummy_client, 10, "since", last_object_ids=["a5b57ec5feaa"])

    assert events == id2_pub


def test_get_events_follows_link_header(dummy_client, mocker):
    """
    Given: A full page carrying a Link header with a next relation.
    When: More events are still required.
    Then: The cursor from the Link header is used for the following request.
    """
    mocker.patch.object(Config, "PAGE_SIZE", 1)
    get_events_mock = mocker.patch.object(
        dummy_client,
        "get_events",
        side_effect=[
            MockResponse(data=id1_pub, headers=link_headers()),
            MockResponse(data=id2_pub),
        ],
    )

    events, next_link = get_events_command(dummy_client, 2, "since")

    assert len(events) == 2
    assert next_link == ""
    assert get_events_mock.call_args_list[1].kwargs["next_link_url"] == NEXT_URL


def test_get_events_starts_from_supplied_next_link(dummy_client, mocker):
    """
    Given: A cursor stored by a previous cycle.
    When: Starting the pagination loop.
    Then: The very first request follows that cursor.
    """
    get_events_mock = mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])

    get_events_command(dummy_client, 10, "since", next_link=NEXT_URL)

    assert get_events_mock.call_args.kwargs["next_link_url"] == NEXT_URL


def test_get_events_returns_next_link_when_limit_reached(dummy_client, mocker):
    """
    Given: A page that satisfies the requested limit but has more available.
    When: The loop exits because the limit was reached.
    Then: The next_link is returned so the following cycle can resume.
    """
    mocker.patch.object(Config, "PAGE_SIZE", 1)
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub, headers=link_headers())])

    events, next_link = get_events_command(dummy_client, 1, "since")

    assert len(events) == 1
    assert next_link == NEXT_URL


def test_get_events_paginates_until_limit(dummy_client, mocker):
    """
    Given: A limit larger than the per-request page size.
    When: Every page comes back full.
    Then: The loop keeps paging until the total limit is satisfied.
    """
    mocker.patch.object(Config, "PAGE_SIZE", 2)
    mocker.patch.object(
        dummy_client,
        "get_events",
        side_effect=[
            MockResponse(data=make_events(2, prefix="p1"), headers=link_headers()),
            MockResponse(data=make_events(2, prefix="p2"), headers=link_headers()),
            MockResponse(data=make_events(2, prefix="p3"), headers=link_headers()),
        ],
    )

    events, _ = get_events_command(dummy_client, 6, "since")

    assert len(events) == 6


def test_get_events_stops_on_partial_page(dummy_client, mocker):
    """
    Given: A page smaller than the requested page size.
    When: The limit has not yet been reached.
    Then: The loop stops because the third party has no further events.
    """
    mocker.patch.object(Config, "PAGE_SIZE", 5)
    get_events_mock = mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=make_events(2))])

    events, _ = get_events_command(dummy_client, 100, "since")

    assert len(events) == 2
    assert get_events_mock.call_count == 1


def test_get_events_advances_cursor_between_pages(dummy_client, mocker):
    """
    Given: A first page with no next_link.
    When: A second request is required.
    Then: The since cursor advances to the last published timestamp.
    """
    mocker.patch.object(Config, "PAGE_SIZE", 1)
    get_events_mock = mocker.patch.object(
        dummy_client,
        "get_events",
        side_effect=[MockResponse(data=id1_pub), MockResponse(data=id2_pub)],
    )

    get_events_command(dummy_client, 2, "original-since")

    assert get_events_mock.call_args_list[0].kwargs["since"] == "original-since"


@pytest.mark.parametrize("next_link", [NEXT_URL, ""], ids=["with_cursor", "without_cursor"])
def test_get_events_no_events(dummy_client, mocker, next_link):
    """
    Given: An empty response from the API.
    When: Running the pagination loop.
    Then: No events are returned and the cursor is cleared.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=[])])

    events, resulting_link = get_events_command(dummy_client, 10, "since", next_link=next_link)

    assert events == []
    assert resulting_link == ""


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(Exception("retries exhausted"), id="generic_error"),
        pytest.param(ValueError("bad payload"), id="value_error"),
        pytest.param(ConnectionError("network down"), id="connection_error"),
    ],
)
def test_get_events_raises_when_nothing_collected(dummy_client, mocker, error, capfd):
    """
    Given: A request that fails after the client exhausted its retries.
    When: No events were collected beforehand.
    Then: The error propagates so the failure is visible.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=error)

    with capfd.disabled(), pytest.raises(type(error)):
        get_events_command(dummy_client, 10, "since")


def test_get_events_preserves_partial_batch_on_failure(dummy_client, mocker, capfd):
    """
    Given: A request that fails after an earlier page succeeded.
    When: The failure reaches the pagination loop.
    Then: The already collected events are returned rather than discarded.
    """
    mocker.patch.object(Config, "PAGE_SIZE", 1)
    mocker.patch.object(
        dummy_client,
        "get_events",
        side_effect=[
            MockResponse(data=id1_pub, headers=link_headers()),
            Exception("retries exhausted"),
        ],
    )

    with capfd.disabled():
        events, next_link = get_events_command(dummy_client, 2, "since")

    assert events == id1_pub
    assert next_link == NEXT_URL


def test_get_events_zero_limit_makes_no_request(dummy_client, mocker):
    """
    Given: A limit of zero.
    When: Running the pagination loop.
    Then: No API call is made.
    """
    get_events_mock = mocker.patch.object(dummy_client, "get_events")

    events, _ = get_events_command(dummy_client, 0, "since")

    assert events == []
    get_events_mock.assert_not_called()


# endregion

# region fetch_events


def test_fetch_events(dummy_client, mocker):
    """
    Given: A fetch cycle with a configured limit.
    When: Collecting events.
    Then: The events and the pagination cursor are returned.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])

    events, next_link = fetch_events(dummy_client, 10, "2022-04-17T11:30:00.000")

    assert events == id1_pub
    assert next_link == ""


def test_fetch_events_resumes_from_next_link(dummy_client, mocker):
    """
    Given: A stored pagination cursor from a previous cycle.
    When: Starting a new fetch.
    Then: The stored cursor is passed through to the API call.
    """
    get_events_mock = mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])

    fetch_events(dummy_client, 10, "2022-04-17T11:30:00.000", next_link=NEXT_URL)

    assert get_events_mock.call_args.kwargs["next_link_url"] == NEXT_URL


def test_fetch_events_applies_dedup_ids(dummy_client, mocker):
    """
    Given: UUIDs collected at the previous high-water mark.
    When: Fetching a page that repeats them.
    Then: The duplicates are excluded from the result.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub + id2_pub)])

    events, _ = fetch_events(dummy_client, 10, "since", last_object_ids=["a5b57ec5feaa"])

    assert events == id2_pub


def test_fetch_events_empty_result(dummy_client, mocker):
    """
    Given: No new events since the stored cursor.
    When: Fetching.
    Then: An empty batch is returned without error.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=[])])

    events, next_link = fetch_events(dummy_client, 10, "since")

    assert events == []
    assert next_link == ""


# endregion

# region commands


def test_test_module_command(dummy_client, mocker):
    """
    Given: A reachable Okta API.
    When: Running the test-module command.
    Then: 'ok' is returned.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])

    assert run_test_module(dummy_client) == "ok"


def test_test_module_propagates_failure(dummy_client, mocker, capfd):
    """
    Given: An unreachable or unauthorized Okta API.
    When: Running the test-module command.
    Then: The error propagates so the configuration is reported as invalid.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=Exception("unauthorized"))

    with capfd.disabled(), pytest.raises(Exception, match="unauthorized"):
        run_test_module(dummy_client)


def command_outputs(result) -> list:
    """Return the outputs of a CommandResults produced by okta-get-events."""
    assert isinstance(result, CommandResults)
    return result.outputs  # type: ignore[return-value]


@pytest.mark.parametrize(
    "start_time",
    [
        pytest.param("1 day", id="relative_day"),
        pytest.param("3 days", id="relative_days"),
        pytest.param(" 1 hour ", id="padded_whitespace"),
    ],
)
def test_okta_get_events_command(dummy_client, mocker, start_time):
    """
    Given: A start_time argument in a supported format.
    When: Running the okta-get-events command.
    Then: The collected events are returned in the command outputs.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])

    assert command_outputs(okta_get_events_command(dummy_client, {"start_time": start_time}, 10)) == id1_pub


def test_okta_get_events_command_from_date_backward_compatibility(dummy_client, mocker):
    """
    Given: Only the deprecated from_date argument.
    When: Running the okta-get-events command.
    Then: The legacy argument is still honoured.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])

    assert command_outputs(okta_get_events_command(dummy_client, {"from_date": "1 day"}, 10)) == id1_pub


def test_okta_get_events_command_with_end_time(dummy_client, mocker):
    """
    Given: Both a start_time and an end_time argument.
    When: Running the okta-get-events command.
    Then: The upper bound is forwarded to the API as the until parameter.
    """
    get_events = mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])

    okta_get_events_command(dummy_client, {"start_time": "3 days", "end_time": "1 day"}, 10)

    assert get_events.call_args.kwargs["until"] is not None


def test_okta_get_events_command_invalid_time_raises(dummy_client):
    """
    Given: A start_time argument that cannot be parsed.
    When: Running the okta-get-events command.
    Then: A DemistoException is raised instead of an AttributeError.
    """
    with pytest.raises(DemistoException, match="Could not parse the 'start_time' argument"):
        okta_get_events_command(dummy_client, {"start_time": "not a real date"}, 10)


@pytest.mark.parametrize(
    "args",
    [
        pytest.param({}, id="no_time_argument_at_all"),
        pytest.param({"from_date": ""}, id="from_date_empty_string"),
        pytest.param({"from_date": "   "}, id="from_date_whitespace_only"),
        pytest.param({"start_time": ""}, id="start_time_empty_string"),
        pytest.param({"start_time": "", "from_date": ""}, id="both_empty"),
    ],
)
def test_okta_get_events_command_missing_time_falls_back_to_default(dummy_client, mocker, args):
    """
    Given: The command invoked with no usable time argument.
    When: Running the okta-get-events command.
    Then: The default lookback is applied and no AttributeError is raised.

    Regression guard for the reported AttributeError. The previous implementation used
    cast(datetime, dateparser.parse(args.get("from_date", "").strip())); cast is a no-op
    at runtime, so dateparser returning None crashed on .isoformat().
    """
    get_events_mock = mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])

    assert command_outputs(okta_get_events_command(dummy_client, args, 10)) == id1_pub

    # A real timestamp reached the API rather than None or an empty string.
    assert get_events_mock.call_args.kwargs["since"]


def test_okta_get_events_command_start_time_takes_precedence_over_from_date(dummy_client, mocker):
    """
    Given: Both the modern start_time and the deprecated from_date arguments.
    When: Running the okta-get-events command.
    Then: start_time wins, so the deprecated alias cannot override the current argument.
    """
    get_events_mock = mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])

    okta_get_events_command(dummy_client, {"start_time": "1 hour", "from_date": "30 days"}, 10)

    since = dateutil.parser.isoparse(get_events_mock.call_args.kwargs["since"])
    assert since > datetime.now(UTC) - timedelta(days=1)


def test_okta_get_events_command_pushes_events(dummy_client, mocker):
    """
    Given: The should_push_events argument set to true on an XSIAM platform.
    When: Running the okta-get-events command.
    Then: The events are sent to XSIAM and a summary message is returned.
    """
    # resolve_should_push_events degrades to False off XSIAM, so the platform is mocked.
    # is_xsiam is resolved inside CommonServerPython, which is where it must be patched.
    mocker.patch("CommonServerPython.is_xsiam", return_value=True)
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])
    send_events = mocker.patch.object(dummy_client, "send_events")

    result = okta_get_events_command(dummy_client, {"start_time": "1 day", "should_push_events": "true"}, 10)

    send_events.assert_called_once()
    assert result == f"Successfully retrieved and pushed {len(id1_pub)} events to XSIAM"


def test_okta_get_events_command_does_not_push_events_off_xsiam(dummy_client, mocker):
    """
    Given: The should_push_events argument set to true on a non XSIAM platform.
    When: Running the okta-get-events command.
    Then: The events are not sent and the command results are returned instead.
    """
    mocker.patch("CommonServerPython.is_xsiam", return_value=False)
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])
    send_events = mocker.patch.object(dummy_client, "send_events")

    result = okta_get_events_command(dummy_client, {"start_time": "1 day", "should_push_events": "true"}, 10)

    send_events.assert_not_called()
    assert command_outputs(result) == id1_pub


def test_okta_get_events_command_respects_limit(dummy_client, mocker):
    """
    Given: A limit smaller than the number of available events.
    When: Running the okta-get-events command.
    Then: No more than the requested number of events is collected.
    """
    mocker.patch.object(Config, "PAGE_SIZE", 1)
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub, headers=link_headers())])

    assert len(command_outputs(okta_get_events_command(dummy_client, {"start_time": "1 day"}, 1))) == 1


def test_okta_get_events_command_limit_argument_overrides_instance_limit(dummy_client, mocker):
    """
    Given: A limit argument that is smaller than the instance level limit.
    When: Running the okta-get-events command.
    Then: The argument takes precedence over the instance level limit.
    """
    mocker.patch.object(Config, "PAGE_SIZE", 1)
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub, headers=link_headers())])

    assert len(command_outputs(okta_get_events_command(dummy_client, {"start_time": "1 day", "limit": "1"}, 10000))) == 1


def test_time_field_added_to_all_events(dummy_client, mocker):
    """
    Given: Events returned by the API with a published timestamp.
    When: Collecting the events.
    Then: Every event carries a _time field sourced from published.
    """
    mocker.patch.object(dummy_client, "get_events", side_effect=[MockResponse(data=id1_pub)])

    events, _ = get_events_command(dummy_client, total_events_to_fetch=10, since="2026-01-01T00:00:00")

    assert events
    assert all(event["_time"] == event["published"] for event in events)


def test_send_events(dummy_client, mocker):
    """
    Given: A batch of collected events.
    When: Publishing them.
    Then: They are forwarded to XSIAM with the correct vendor and product.
    """
    send_mock = mocker.patch("OktaEventCollector.send_events_to_xsiam", return_value={})

    dummy_client.send_events(id1_pub)

    send_mock.assert_called_once_with(events=id1_pub, vendor=Config.VENDOR, product=Config.PRODUCT)


def test_send_events_empty_batch(dummy_client, mocker):
    """
    Given: An empty batch.
    When: Publishing.
    Then: The call still succeeds without raising.
    """
    send_mock = mocker.patch("OktaEventCollector.send_events_to_xsiam", return_value={})

    dummy_client.send_events([])

    send_mock.assert_called_once_with(events=[], vendor=Config.VENDOR, product=Config.PRODUCT)


# endregion

# region client construction


def test_client_sets_ssws_authorization_header():
    """
    Given: An Okta API token.
    When: Building the client.
    Then: The token is registered for the Authorization header with the SSWS scheme.
    """
    client = Client(BASE_URL, "my-token")

    assert client._auth_handler.header_name == "Authorization"
    assert client._auth_handler.key == "SSWS my-token"


def test_client_retry_policy_includes_rate_limit():
    """
    Given: The Okta client.
    When: Inspecting its retry policy.
    Then: HTTP 429 is retried, so rate limits are handled by the transport layer.
    """
    client = Client(BASE_URL, "my-token")

    assert 429 in client._retry_policy.retryable_status_codes
    assert client._retry_policy.max_attempts == Config.RETRY_MAX_ATTEMPTS
    assert client._retry_policy.max_delay == Config.MAX_RETRY_DELAY


@pytest.mark.parametrize("status_code", [500, 502, 503, 504], ids=["500", "502", "503", "504"])
def test_client_retry_policy_includes_server_errors(status_code):
    """
    Given: The Okta client.
    When: Inspecting its retry policy.
    Then: Transient server-side failures are retried.
    """
    assert status_code in Client(BASE_URL, "my-token")._retry_policy.retryable_status_codes


def test_client_get_events_uses_full_url_for_next_link(dummy_client, mocker):
    """
    Given: A pagination cursor.
    When: Requesting the next page.
    Then: The request targets the full cursor URL rather than rebuilding the query.
    """
    request_mock = mocker.patch.object(dummy_client, "_http_request", return_value=MockResponse())

    dummy_client.get_events(since="ignored", next_link_url=NEXT_URL)

    assert request_mock.call_args.kwargs["full_url"] == NEXT_URL
    assert request_mock.call_args.kwargs["resp_type"] == "response"


def test_client_get_events_builds_query_without_next_link(dummy_client, mocker):
    """
    Given: No pagination cursor.
    When: Requesting the first page.
    Then: The request is built from the since timestamp and the page size.
    """
    request_mock = mocker.patch.object(dummy_client, "_http_request", return_value=MockResponse())

    dummy_client.get_events(since="2022-04-17T11:30:00.000", page_size=500)

    assert request_mock.call_args.kwargs["params"] == {
        "sortOrder": Config.SORT_ORDER,
        "since": "2022-04-17T11:30:00.000",
        "limit": 500,
    }
    assert request_mock.call_args.kwargs["url_suffix"] == Config.LOGS_ENDPOINT


def test_client_get_events_defaults_to_max_page_size(dummy_client, mocker):
    """
    Given: No explicit page size.
    When: Requesting a page.
    Then: The Okta per-request maximum is used.
    """
    request_mock = mocker.patch.object(dummy_client, "_http_request", return_value=MockResponse())

    dummy_client.get_events(since="2022-04-17T11:30:00.000")

    assert request_mock.call_args.kwargs["params"]["limit"] == Config.PAGE_SIZE


# endregion


def test_page_size_never_exceeds_okta_maximum():
    """
    Given: The Okta System Log API hard limit of 1000 records per request.
    When: Reading the configured page size.
    Then: It does not exceed that limit, and the user-facing default is a larger total.
    """
    assert Config.PAGE_SIZE <= 1000
    assert Config.DEFAULT_LIMIT > Config.PAGE_SIZE
