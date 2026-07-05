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
    fetch_all_events,
    fetch_events_command,
    get_events_command,
    test_module_command,
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
    "activity_report_filter": "?aggregationCriteria.primary=INDIVIDUAL&aggregationCriteria.secondary=CONTENT&q=criteria&contentSource=LINKEDIN_LEARNING",
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


class TestFetchEvents:
    """Tests for the fetch_events_command function."""

    def test_fetch_events_first_run(self, mock_client: LinkedInLearningClient, mock_params: LinkedInLearningParams,
                                     sample_response: dict, mocker: MockerFixture):
        """Verify fetch-events works on first run with no last_run state."""
        mocker.patch.object(mock_client, "get_learning_activity_reports", return_value=sample_response)
        mocker.patch("LinkedInLearning.send_events_to_xsiam")

        last_run = LinkedInLearningLastRun()
        next_run = fetch_events_command(mock_client, mock_params, last_run)

        assert next_run.last_fetch_time is not None
        assert next_run.last_fetch_time == 1720051200001  # max latestDataAt + 1

    def test_fetch_events_with_last_run(self, mock_client: LinkedInLearningClient, mock_params: LinkedInLearningParams,
                                         sample_response: dict, mocker: MockerFixture):
        """Verify fetch-events uses last_run state correctly."""
        mocker.patch.object(mock_client, "get_learning_activity_reports", return_value=sample_response)
        mocker.patch("LinkedInLearning.send_events_to_xsiam")

        last_run = LinkedInLearningLastRun(last_fetch_time=1719800000000)
        next_run = fetch_events_command(mock_client, mock_params, last_run)

        mock_client.get_learning_activity_reports.assert_called_once()
        call_kwargs = mock_client.get_learning_activity_reports.call_args
        assert call_kwargs.kwargs["started_at"] == 1719800000000

    def test_fetch_events_no_events(self, mock_client: LinkedInLearningClient, mock_params: LinkedInLearningParams,
                                     mocker: MockerFixture):
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
            max_fetch=1000,
        )

        assert len(events) == 3
        assert mock_client.get_learning_activity_reports.call_count == 1

    def test_multiple_pages(self, mock_client: LinkedInLearningClient, mocker: MockerFixture):
        """Verify multi-page fetch follows pagination links."""
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

        mocker.patch.object(
            mock_client,
            "get_learning_activity_reports",
            side_effect=[page1_response, page2_response],
        )

        events = fetch_all_events(
            client=mock_client,
            filter_query="?q=criteria",
            started_at=1719792000000,
            max_fetch=1000,
        )

        assert len(events) == PAGE_SIZE + 5
        assert mock_client.get_learning_activity_reports.call_count == 2

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

        events = fetch_all_events(
            client=mock_client,
            filter_query="?q=criteria",
            started_at=1719792000000,
            max_fetch=50,
        )

        assert len(events) == 50


class TestTestModule:
    """Tests for the test_module_command function."""

    def test_test_module_success(self, mock_client: LinkedInLearningClient, mock_params: LinkedInLearningParams,
                                  mocker: MockerFixture):
        """Verify test-module returns 'ok' on successful API call."""
        mocker.patch.object(
            mock_client,
            "get_learning_activity_reports",
            return_value={"elements": [], "paging": {"count": 1, "start": 0, "total": 0, "links": []}},
        )

        result = test_module_command(mock_client, mock_params)
        assert result == "ok"

    def test_test_module_failure(self, mock_client: LinkedInLearningClient, mock_params: LinkedInLearningParams,
                                  mocker: MockerFixture):
        """Verify test-module raises on API failure."""
        mocker.patch.object(
            mock_client,
            "get_learning_activity_reports",
            side_effect=DemistoException("Unauthorized"),
        )

        with pytest.raises(DemistoException, match="Unauthorized"):
            test_module_command(mock_client, mock_params)


class TestGetEventsCommand:
    """Tests for the get_events_command function."""

    def test_get_events_command(self, mock_client: LinkedInLearningClient, mock_params: LinkedInLearningParams,
                                 sample_response: dict, mocker: MockerFixture):
        """Verify get-events command returns CommandResults with events."""
        mocker.patch.object(mock_client, "get_learning_activity_reports", return_value=sample_response)

        args = LinkedInLearningGetEventsArgs(limit=50, should_push_events=False)
        result = get_events_command(mock_client, mock_params, args)

        assert result.readable_output is not None
        assert "LinkedIn Learning Events" in result.readable_output

    def test_get_events_command_with_push(self, mock_client: LinkedInLearningClient, mock_params: LinkedInLearningParams,
                                           sample_response: dict, mocker: MockerFixture):
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
