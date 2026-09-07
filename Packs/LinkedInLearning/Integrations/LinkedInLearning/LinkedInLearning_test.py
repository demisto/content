"""LinkedIn Learning Integration - Unit Tests

Unit tests for the LinkedIn Learning Event Collector integration.
Tests cover fetch-events, pagination, test-module, and get-events commands.
"""

import json
import pytest
from pytest_mock import MockerFixture
from CommonServerPython import DemistoException
from LinkedInLearning import (
    LinkedInLearningClient,
    LinkedInLearningParams,
    LinkedInLearningLastRun,
    LinkedInLearningGetEventsArgs,
    add_time_to_events,
    calculate_time_window,
    fetch_all_events,
    fetch_events_command,
    get_events_command,
    get_next_link,
    run_test_module,
    MAX_TIME_OFFSET_DAYS,
    MS_PER_DAY,
    PAGE_SIZE,
)


@pytest.fixture(autouse=True)
def mock_support_multithreading(mocker: MockerFixture):
    """Mock support_multithreading to prevent demistomock attribute errors."""
    mocker.patch("ContentClientApiModule.support_multithreading")


def util_load_json(path: str) -> dict:
    """Load JSON test data from file.

    Args:
        path: Path to JSON file.

    Returns:
        Parsed JSON data.
    """
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


MOCK_PARAMS = {
    "url": "https://api.linkedin.com",
    "client_id": "test-client-id",
    "client_secret": "test-client-secret",
    "insecure": False,
    "proxy": False,
    "max_fetch": 1000,
}


@pytest.fixture
def mock_client(mocker: MockerFixture) -> LinkedInLearningClient:
    """Create a mocked LinkedInLearningClient.

    Mocks the OAuth2ClientCredentialsHandler and ContentClient init to avoid
    real HTTP calls during testing.
    """
    mocker.patch("LinkedInLearning.OAuth2ClientCredentialsHandler")
    mocker.patch("LinkedInLearning.ContentClient.__init__", return_value=None)
    params = LinkedInLearningParams(**MOCK_PARAMS)
    return LinkedInLearningClient(params)


@pytest.fixture
def mock_params() -> LinkedInLearningParams:
    """Create LinkedInLearningParams for testing."""
    return LinkedInLearningParams(**MOCK_PARAMS)


@pytest.fixture
def sample_response() -> dict:
    """Load sample API response from test data."""
    return util_load_json("test_data/learning_activity_reports.json")


class TestAddTimeToEvents:
    """Tests for the add_time_to_events function."""

    def test_add_time_to_events(self):
        """Verify _time field is added correctly from latestDataAt."""
        events = [
            {"latestDataAt": 1719878400000, "name": "event1"},
            {"latestDataAt": 1719964800000, "name": "event2"},
        ]
        add_time_to_events(events)

        assert events[0]["_time"] == "2024-07-02T00:00:00Z"
        assert events[1]["_time"] == "2024-07-03T00:00:00Z"

    def test_add_time_to_events_missing_field(self):
        """Verify events without latestDataAt are handled gracefully."""
        events = [{"name": "event_without_time"}]
        add_time_to_events(events)

        assert "_time" not in events[0]


class TestBuildFilterQuery:
    """Tests for LinkedInLearningParams.build_filter_query."""

    def test_default_query_uses_discrete_params(self):
        """Verify the query is built from discrete criteria with design defaults."""
        params = LinkedInLearningParams(**MOCK_PARAMS)
        query = params.build_filter_query()

        assert query.startswith("?")
        assert "q=criteria" in query
        assert "aggregationCriteria.primary=ACCOUNT" in query
        assert "aggregationCriteria.secondary=CONTENT" in query
        assert "contentSource=ALL_SOURCES" in query
        # Without a sort metric type, the qualifier must NOT be sent on its own.
        assert "sortBy.engagementMetricType" not in query
        assert "sortBy.engagementMetricQualifier" not in query

    def test_query_includes_sort_by_engagement_metric_type_and_qualifier(self):
        """Verify sortBy metric type and its qualifier are added together when a type is configured."""
        params = LinkedInLearningParams(**{**MOCK_PARAMS, "engagement_metric_type": "DAYS_ACTIVE"})
        query = params.build_filter_query()

        assert "sortBy.engagementMetricType=DAYS_ACTIVE" in query
        assert "sortBy.engagementMetricQualifier=TOTAL" in query

    def test_qualifier_not_sent_without_metric_type(self):
        """Verify the qualifier is omitted when no sort metric type is configured, even if set."""
        params = LinkedInLearningParams(**{**MOCK_PARAMS, "engagement_metric_qualifier": "UNIQUE"})
        query = params.build_filter_query()

        assert "sortBy.engagementMetricQualifier" not in query

    def test_query_includes_asset_type(self):
        """Verify assetType is added when configured."""
        params = LinkedInLearningParams(**{**MOCK_PARAMS, "asset_type": "COURSE"})
        query = params.build_filter_query()

        assert "assetType=COURSE" in query


class TestCalculateTimeWindow:
    """Tests for the calculate_time_window function."""

    def test_window_capped_at_max(self):
        """Verify duration is capped at the API maximum of 14 days."""
        now_ms = 100 * MS_PER_DAY
        started_at = 0
        _, duration_days = calculate_time_window(started_at, now_ms)

        assert duration_days == MAX_TIME_OFFSET_DAYS

    def test_small_window_rounds_up_to_one(self):
        """Verify a sub-day window yields at least 1 day."""
        now_ms = 1_000_000_000_000
        started_at = now_ms - 1  # 1 ms in the past
        _, duration_days = calculate_time_window(started_at, now_ms)

        assert duration_days == 1

    def test_multi_day_window(self):
        """Verify a multi-day window is rounded up correctly."""
        now_ms = 5 * MS_PER_DAY
        started_at = 0
        _, duration_days = calculate_time_window(started_at, now_ms)

        assert duration_days == 5


class TestGetNextLink:
    """Tests for the get_next_link function."""

    def test_next_link_present(self):
        """Verify the next href is extracted when present."""
        response = {"paging": {"links": [{"rel": "next", "href": "/v2/x?start=100"}]}}
        assert get_next_link(response) == "/v2/x?start=100"

    def test_next_link_absent(self):
        """Verify None is returned when no next link exists."""
        response = {"paging": {"links": []}}
        assert get_next_link(response) is None


class TestFetchEvents:
    """Tests for the fetch_events_command function."""

    def test_fetch_events_first_run(
        self,
        mock_client: LinkedInLearningClient,
        mock_params: LinkedInLearningParams,
        sample_response: dict,
        mocker: MockerFixture,
    ):
        """Verify fetch-events works on first run with no last_run state."""
        mocker.patch.object(mock_client, "get_learning_activity_reports", return_value=sample_response)
        mocker.patch("LinkedInLearning.send_events_to_xsiam")

        last_run = LinkedInLearningLastRun()
        next_run = fetch_events_command(mock_client, mock_params, last_run)

        assert next_run.last_fetch_time is not None
        assert next_run.last_fetch_time == 1720051200001  # max latestDataAt + 1

    def test_fetch_events_with_last_run(
        self,
        mock_client: LinkedInLearningClient,
        mock_params: LinkedInLearningParams,
        sample_response: dict,
        mocker: MockerFixture,
    ):
        """Verify fetch-events uses last_run state correctly."""
        mocker.patch.object(mock_client, "get_learning_activity_reports", return_value=sample_response)
        mocker.patch("LinkedInLearning.send_events_to_xsiam")

        last_run = LinkedInLearningLastRun(last_fetch_time=1719800000000)
        fetch_events_command(mock_client, mock_params, last_run)

        mock_client.get_learning_activity_reports.assert_called_once()
        call_kwargs = mock_client.get_learning_activity_reports.call_args
        assert call_kwargs.kwargs["started_at"] == 1719800000000
        # duration is derived and capped at the API max
        assert call_kwargs.kwargs["duration_days"] == MAX_TIME_OFFSET_DAYS

    def test_fetch_events_no_events(
        self, mock_client: LinkedInLearningClient, mock_params: LinkedInLearningParams, mocker: MockerFixture
    ):
        """Verify fetch-events handles empty response correctly."""
        empty_response = {"elements": [], "paging": {"count": 100, "start": 0, "total": 0, "links": []}}
        mocker.patch.object(mock_client, "get_learning_activity_reports", return_value=empty_response)

        last_run = LinkedInLearningLastRun(last_fetch_time=1719800000000)
        next_run = fetch_events_command(mock_client, mock_params, last_run)

        # Should return the same last_run when no events found
        assert next_run.last_fetch_time == 1719800000000


class TestPagination:
    """Tests for pagination logic in fetch_all_events."""

    def test_single_page(self, mock_client: LinkedInLearningClient, mocker: MockerFixture):
        """Verify single page fetch when elements < page size."""
        response = {
            "elements": [{"latestDataAt": 1719878400000, "name": f"event_{i}"} for i in range(3)],
            "paging": {"count": 100, "start": 0, "total": 3, "links": []},
        }
        mocker.patch.object(mock_client, "get_learning_activity_reports", return_value=response)

        events = fetch_all_events(
            client=mock_client,
            filter_query="?q=criteria",
            started_at=1719792000000,
            duration_days=MAX_TIME_OFFSET_DAYS,
            max_fetch=1000,
        )

        assert len(events) == 3
        assert mock_client.get_learning_activity_reports.call_count == 1

    def test_multiple_pages_follows_next_link(self, mock_client: LinkedInLearningClient, mocker: MockerFixture):
        """Verify multi-page fetch follows the paging next link href."""
        page1_elements = [{"latestDataAt": 1719878400000 + i, "name": f"event_{i}"} for i in range(PAGE_SIZE)]
        page1_response = {
            "elements": page1_elements,
            "paging": {
                "count": PAGE_SIZE,
                "start": 0,
                "total": PAGE_SIZE + 5,
                "links": [{"rel": "next", "href": "/v2/learningActivityReports?start=100"}],
            },
        }

        page2_elements = [{"latestDataAt": 1719878400000 + PAGE_SIZE + i, "name": f"event_{PAGE_SIZE + i}"} for i in range(5)]
        page2_response = {
            "elements": page2_elements,
            "paging": {"count": PAGE_SIZE, "start": PAGE_SIZE, "total": PAGE_SIZE + 5, "links": []},
        }

        first_page = mocker.patch.object(mock_client, "get_learning_activity_reports", return_value=page1_response)
        next_page = mocker.patch.object(mock_client, "get_by_next_link", return_value=page2_response)

        events = fetch_all_events(
            client=mock_client,
            filter_query="?q=criteria",
            started_at=1719792000000,
            duration_days=MAX_TIME_OFFSET_DAYS,
            max_fetch=1000,
        )

        assert len(events) == PAGE_SIZE + 5
        first_page.assert_called_once()
        next_page.assert_called_once_with("/v2/learningActivityReports?start=100")

    def test_pagination_respects_max_fetch(self, mock_client: LinkedInLearningClient, mocker: MockerFixture):
        """Verify pagination stops when max_fetch is reached."""
        page_elements = [{"latestDataAt": 1719878400000 + i, "name": f"event_{i}"} for i in range(PAGE_SIZE)]
        page_response = {
            "elements": page_elements,
            "paging": {
                "count": PAGE_SIZE,
                "start": 0,
                "total": 500,
                "links": [{"rel": "next", "href": "/v2/learningActivityReports?start=100"}],
            },
        }
        mocker.patch.object(mock_client, "get_learning_activity_reports", return_value=page_response)
        mocker.patch.object(mock_client, "get_by_next_link", return_value=page_response)

        events = fetch_all_events(
            client=mock_client,
            filter_query="?q=criteria",
            started_at=1719792000000,
            duration_days=MAX_TIME_OFFSET_DAYS,
            max_fetch=50,
        )

        assert len(events) == 50


class TestTestModule:
    """Tests for the test_module_command function."""

    def test_test_module_success(
        self, mock_client: LinkedInLearningClient, mock_params: LinkedInLearningParams, mocker: MockerFixture
    ):
        """Verify test-module returns 'ok' on successful API call."""
        mocker.patch.object(
            mock_client,
            "get_learning_activity_reports",
            return_value={"elements": [], "paging": {"count": 1, "start": 0, "total": 0, "links": []}},
        )

        result = run_test_module(mock_client, mock_params)
        assert result == "ok"

    def test_test_module_failure(
        self, mock_client: LinkedInLearningClient, mock_params: LinkedInLearningParams, mocker: MockerFixture
    ):
        """Verify test-module raises on API failure."""
        mocker.patch.object(
            mock_client,
            "get_learning_activity_reports",
            side_effect=DemistoException("Unauthorized"),
        )

        with pytest.raises(DemistoException, match="Unauthorized"):
            run_test_module(mock_client, mock_params)


class TestGetEventsCommand:
    """Tests for the get_events_command function."""

    def test_get_events_command(
        self,
        mock_client: LinkedInLearningClient,
        mock_params: LinkedInLearningParams,
        sample_response: dict,
        mocker: MockerFixture,
    ):
        """Verify get-events command returns CommandResults with events."""
        mocker.patch.object(mock_client, "get_learning_activity_reports", return_value=sample_response)

        args = LinkedInLearningGetEventsArgs(limit=50, should_push_events=False)
        result = get_events_command(mock_client, mock_params, args)

        assert result.readable_output is not None
        assert "LinkedIn Learning Events" in result.readable_output

    def test_get_events_command_with_push(
        self,
        mock_client: LinkedInLearningClient,
        mock_params: LinkedInLearningParams,
        sample_response: dict,
        mocker: MockerFixture,
    ):
        """Verify get-events command pushes events when should_push_events is True."""
        mocker.patch.object(mock_client, "get_learning_activity_reports", return_value=sample_response)
        mock_send = mocker.patch("LinkedInLearning.send_events_to_xsiam")

        args = LinkedInLearningGetEventsArgs(limit=50, should_push_events=True)
        get_events_command(mock_client, mock_params, args)

        mock_send.assert_called_once()
        call_kwargs = mock_send.call_args
        assert call_kwargs.kwargs["vendor"] == "linkedin"
        assert call_kwargs.kwargs["product"] == "learning"


class TestParamsValidation:
    """Tests for parameter validation."""

    def test_max_fetch_capped(self):
        """Verify max_fetch is capped to PAGE_SIZE * MAX_PAGES."""
        params = LinkedInLearningParams(**{**MOCK_PARAMS, "max_fetch": 5000})
        assert params.max_fetch == 1000

    def test_url_trailing_slash_removed(self):
        """Verify trailing slash is removed from URL."""
        params = LinkedInLearningParams(**{**MOCK_PARAMS, "url": "https://api.linkedin.com/"})
        assert str(params.url) == "https://api.linkedin.com"
