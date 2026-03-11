import pytest
from CommonServerPython import *
from freezegun import freeze_time
from CitrixSPA import (
    Client,
    CitrixOAuth2Handler,
    get_events_command,
    fetch_events_command,
    module_test_command,
)


BASE_URL = "https://api.cloud.com"
CUSTOMER_ID = "test_customer"
CLIENT_ID = "test_client_id"
CLIENT_SECRET = "test_client_secret"


@pytest.fixture(autouse=True)
def mock_content_client_init(mocker):
    """Mock ContentClient.__init__ to avoid httpx/anyio initialization in tests."""
    mocker.patch("CitrixSPA.ContentClient.__init__", return_value=None)


@pytest.fixture
def client(mocker) -> Client:
    """Create a Client instance for testing with mocked ContentClient init."""
    c = Client(
        base_url=BASE_URL,
        customer_id=CUSTOMER_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        verify=True,
        proxy=False,
    )
    # Set attributes that ContentClient.__init__ would normally set
    c._base_url = BASE_URL
    c._verify = True
    c.customer_id = CUSTOMER_ID
    return c


# ----------------------------------------------------------------------
# AUTH HANDLER TESTS
# ----------------------------------------------------------------------


class TestCitrixOAuth2Handler:
    """Tests for the CitrixOAuth2Handler class."""

    def test_init_missing_token_url(self):
        """
        Given:
            - Empty token_url parameter.
        When:
            - Creating a CitrixOAuth2Handler instance.
        Then:
            - A ContentClientConfigurationError should be raised.
        """
        from ContentClientApiModule import ContentClientConfigurationError

        with pytest.raises(ContentClientConfigurationError, match="non-empty token_url"):
            CitrixOAuth2Handler(
                token_url="",
                client_id="id",
                client_secret="secret",
                customer_id="cust",
            )

    def test_init_missing_client_id(self):
        """
        Given:
            - Empty client_id parameter.
        When:
            - Creating a CitrixOAuth2Handler instance.
        Then:
            - A ContentClientConfigurationError should be raised.
        """
        from ContentClientApiModule import ContentClientConfigurationError

        with pytest.raises(ContentClientConfigurationError, match="non-empty client_id"):
            CitrixOAuth2Handler(
                token_url="https://api.cloud.com/token",
                client_id="",
                client_secret="secret",
                customer_id="cust",
            )

    def test_init_missing_client_secret(self):
        """
        Given:
            - Empty client_secret parameter.
        When:
            - Creating a CitrixOAuth2Handler instance.
        Then:
            - A ContentClientConfigurationError should be raised.
        """
        from ContentClientApiModule import ContentClientConfigurationError

        with pytest.raises(ContentClientConfigurationError, match="non-empty client_secret"):
            CitrixOAuth2Handler(
                token_url="https://api.cloud.com/token",
                client_id="id",
                client_secret="",
                customer_id="cust",
            )

    def test_init_missing_customer_id(self):
        """
        Given:
            - Empty customer_id parameter.
        When:
            - Creating a CitrixOAuth2Handler instance.
        Then:
            - A ContentClientConfigurationError should be raised.
        """
        from ContentClientApiModule import ContentClientConfigurationError

        with pytest.raises(ContentClientConfigurationError, match="non-empty customer_id"):
            CitrixOAuth2Handler(
                token_url="https://api.cloud.com/token",
                client_id="id",
                client_secret="secret",
                customer_id="",
            )

    def test_init_success(self):
        """
        Given:
            - Valid parameters for CitrixOAuth2Handler.
        When:
            - Creating a CitrixOAuth2Handler instance.
        Then:
            - The handler should be created successfully with correct attributes.
        """
        handler = CitrixOAuth2Handler(
            token_url="https://api.cloud.com/token",
            client_id="id",
            client_secret="secret",
            customer_id="cust",
        )
        assert handler._token_url == "https://api.cloud.com/token"
        assert handler._client_id == "id"
        assert handler._customer_id == "cust"
        assert handler._access_token is None


# ----------------------------------------------------------------------
# CLIENT TESTS
# ----------------------------------------------------------------------


class TestClient:
    """Tests for the Client class."""

    def test_get_records(self, client, mocker):
        """
        Given:
            - A client with mocked HTTP response.
        When:
            - Calling get_records with valid parameters.
        Then:
            - The function should return the API response with items.
        """
        mock_response = {"items": [{"recordId": "r1", "utcTimestamp": "2024-01-01T00:00:00Z"}], "continuationToken": None}
        mocker.patch.object(client, "get", return_value=mock_response)

        result = client.get_records(start_date_time="2024-01-01T00:00:00.000Z", end_date_time="2024-01-02T00:00:00.000Z")

        assert result["items"][0]["recordId"] == "r1"
        client.get.assert_called_once()

    def test_get_records_with_pagination_single_page(self, client, mocker):
        """
        Given:
            - A client returning a single page of records.
        When:
            - Calling get_records_with_pagination with limit=10.
        Then:
            - The function should return all records with _time field set.
        """
        mocker.patch.object(
            client,
            "get_records",
            return_value={
                "items": [{"recordId": "r1", "utcTimestamp": "2024-01-01T00:00:00Z"}],
                "continuationToken": None,
            },
        )

        records, raw_res = client.get_records_with_pagination(limit=10, start_date_time="2024-01-01T00:00:00.000Z")

        assert len(records) == 1
        assert records[0]["_time"] == "2024-01-01T00:00:00Z"
        assert raw_res is not None
        assert raw_res["continuationToken"] is None

    def test_get_records_with_pagination_multiple_pages(self, client, mocker):
        """
        Given:
            - A client returning multiple pages of records.
        When:
            - Calling get_records_with_pagination with limit=10.
        Then:
            - The function should merge pages and return all records with _time set.
        """
        responses = [
            {"items": [{"recordId": "r1", "utcTimestamp": "2024-01-01T00:00:00Z"}], "continuationToken": "abc"},
            {"items": [{"recordId": "r2", "utcTimestamp": "2024-01-01T01:00:00Z"}], "continuationToken": None},
        ]
        mocker.patch.object(client, "get_records", side_effect=responses)

        records, raw_res = client.get_records_with_pagination(limit=10, start_date_time=None)

        assert len(records) == 2
        assert records[0]["_time"] == "2024-01-01T00:00:00Z"
        assert records[1]["_time"] == "2024-01-01T01:00:00Z"

    def test_get_records_with_pagination_deduplication(self, client, mocker):
        """
        Given:
            - A client returning records that include a previously fetched record.
        When:
            - Calling get_records_with_pagination with last_record_id set.
        Then:
            - Records up to and including the last_record_id should be skipped.
        """
        mocker.patch.object(
            client,
            "get_records",
            return_value={
                "items": [
                    {"recordId": "r2", "utcTimestamp": "2024-01-01T01:00:00Z"},
                    {"recordId": "r1", "utcTimestamp": "2024-01-01T00:00:00Z"},
                ],
                "continuationToken": None,
            },
        )

        records, _ = client.get_records_with_pagination(
            limit=10,
            start_date_time="2024-01-01T00:00:00.000Z",
            last_record_id="r1",
        )

        # After reversing, items are [r1, r2]. Dedup skips r1, so only r2 remains.
        assert len(records) == 1
        assert records[0]["recordId"] == "r2"

    def test_get_records_with_pagination_respects_limit(self, client, mocker):
        """
        Given:
            - A client returning more records than the requested limit.
        When:
            - Calling get_records_with_pagination with limit=1.
        Then:
            - Only the requested number of records should be returned.
        """
        mocker.patch.object(
            client,
            "get_records",
            return_value={
                "items": [
                    {"recordId": "r2", "utcTimestamp": "2024-01-01T01:00:00Z"},
                    {"recordId": "r1", "utcTimestamp": "2024-01-01T00:00:00Z"},
                ],
                "continuationToken": None,
            },
        )

        records, _ = client.get_records_with_pagination(limit=1, start_date_time=None)

        assert len(records) == 1


# ----------------------------------------------------------------------
# COMMAND TESTS
# ----------------------------------------------------------------------


class TestGetEventsCommand:
    """Tests for the get_events_command function."""

    def test_returns_command_results(self, client, mocker):
        """
        Given:
            - A client returning mocked event records.
        When:
            - Running the citrix-spa-get-events command.
        Then:
            - A CommandResults object is returned containing the event data.
        """
        mocker.patch.object(
            client,
            "get_records_with_pagination",
            return_value=(
                [{"recordId": "r1", "utcTimestamp": "2024-01-01T00:00:00Z", "_time": "2024-01-01T00:00:00Z"}],
                {"meta": "ok"},
            ),
        )

        results = get_events_command(client, {"limit": "1", "should_push_events": "false"})

        assert isinstance(results, CommandResults)
        assert results.outputs
        assert results.outputs[0]["recordId"] == "r1"

    def test_pushes_events_when_requested(self, client, mocker):
        """
        Given:
            - A client returning mocked event records.
        When:
            - Running citrix-spa-get-events with should_push_events=true.
        Then:
            - Events should be sent to XSIAM via send_events_to_xsiam.
        """
        mocker.patch.object(
            client,
            "get_records_with_pagination",
            return_value=(
                [{"recordId": "r1", "utcTimestamp": "2024-01-01T00:00:00Z", "_time": "2024-01-01T00:00:00Z"}],
                {},
            ),
        )
        mock_send = mocker.patch("CitrixSPA.send_events_to_xsiam")

        get_events_command(client, {"limit": "1", "should_push_events": "true"})

        mock_send.assert_called_once_with(
            [{"recordId": "r1", "utcTimestamp": "2024-01-01T00:00:00Z", "_time": "2024-01-01T00:00:00Z"}],
            vendor="Citrix",
            product="SPA",
        )


class TestFetchEventsCommand:
    """Tests for the fetch_events_command function."""

    @freeze_time("2025-01-14T00:00:00Z")
    def test_first_run(self, client, mocker):
        """
        Given:
            - A client returning 2 event records.
        When:
            - Running fetch_events_command for the first time (empty last_run).
        Then:
            - The function should return events and set LastRun to the last event's timestamp.
            - The start_date_time should be datetime.utcnow() since no LastRun exists.
        """
        get_records_mocker = mocker.patch.object(
            client,
            "get_records_with_pagination",
            return_value=(
                [
                    {"_time": "2025-01-01T00:00:00Z", "recordId": "id2"},
                    {"_time": "2024-01-01T00:00:00Z", "recordId": "id1"},
                ],
                {},
            ),
        )

        events, last_run = fetch_events_command(client, 5, {})

        assert len(events) == 2
        assert last_run["LastRun"] == "2024-01-01T00:00:00Z"
        assert last_run["RecordId"] == "id1"
        assert get_records_mocker.call_args.kwargs["start_date_time"] == "2025-01-14T00:00:00.000Z"

    def test_subsequent_run(self, client, mocker):
        """
        Given:
            - A client returning one event record.
        When:
            - Running fetch_events_command with an existing last_run.
        Then:
            - The function should use the LastRun timestamp as start_date_time.
            - The function should pass the RecordId for deduplication.
        """
        get_records_mocker = mocker.patch.object(
            client,
            "get_records_with_pagination",
            return_value=(
                [{"_time": "2024-01-02T00:00:00Z", "recordId": "id2"}],
                {},
            ),
        )

        events, last_run = fetch_events_command(
            client,
            5,
            {"LastRun": "2024-01-01T00:00:00Z", "RecordId": "id1"},
        )

        assert len(events) == 1
        assert last_run["LastRun"] == "2024-01-02T00:00:00Z"
        assert last_run["RecordId"] == "id2"
        assert get_records_mocker.call_args.kwargs["start_date_time"] == "2024-01-01T00:00:00Z"
        assert get_records_mocker.call_args.kwargs["last_record_id"] == "id1"

    def test_no_events_preserves_last_run(self, client, mocker):
        """
        Given:
            - A client returning no events.
        When:
            - Running fetch_events_command.
        Then:
            - The last_run should remain unchanged.
        """
        mocker.patch.object(
            client,
            "get_records_with_pagination",
            return_value=([], {}),
        )

        existing_last_run = {"LastRun": "2024-01-01T00:00:00Z", "RecordId": "id1"}
        events, last_run = fetch_events_command(client, 5, existing_last_run)

        assert len(events) == 0
        assert last_run == existing_last_run


class TestModuleTestCommand:
    """Tests for the module_test_command function."""

    def test_returns_ok(self, client, mocker):
        """
        Given:
            - A client that can successfully fetch events.
        When:
            - Running the test-module command.
        Then:
            - The function should return 'ok'.
        """
        mocker.patch.object(
            client,
            "get_records_with_pagination",
            return_value=(
                [{"recordId": "r1", "utcTimestamp": "2024-01-01T00:00:00Z", "_time": "2024-01-01T00:00:00Z"}],
                {},
            ),
        )

        result = module_test_command(client, {})

        assert result == "ok"
