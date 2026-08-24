import demistomock as demisto
import pytest
from pytest_mock import MockerFixture
import json
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from CriblSearch import CriblSearchClient


def load_mock_response(file_path: str) -> dict | list:
    """
    Helper function to load mock response data from a JSON file.

    Args:
        file_path (str): The relative path under the test_data directory to the JSON file
            (e.g. "cribl-search-dataset-list/list.json").

    Returns:
        dict | list: The parsed JSON content.
    """
    with (Path(__file__).parent / "test_data" / file_path).open() as f:
        return json.load(f)


@pytest.fixture(autouse=True)
def mock_support_multithreading(mocker: MockerFixture) -> None:
    """Mock support_multithreading to prevent demistomock attribute errors.

    This fixture automatically runs before each test to mock the support_multithreading
    function which is called during ContentClient initialization. Without this mock,
    tests fail with: AttributeError: module 'demistomock' has no attribute '_Demisto__do'
    """
    mocker.patch("ContentClientApiModule.support_multithreading")


@pytest.fixture
def client() -> "CriblSearchClient":
    """
    Pytest fixture that initializes and returns a CriblSearchClient instance for testing.

    Returns:
        CriblSearchClient: An instance of the Cribl Search API client.
    """
    from pydantic import SecretStr
    from CriblSearch import CriblSearchClient, CriblSearchParams, Credentials

    params = CriblSearchParams(
        url="https://main-test-org.cribl.cloud",  # type: ignore[arg-type]
        credentials=Credentials(
            identifier="test-client-id",
            password=SecretStr("test-client-secret"),
        ),
    )
    return CriblSearchClient(params)


# region helpers


@pytest.mark.parametrize(
    "results, limit, all_results, expected",
    [
        pytest.param([1, 2, 3, 4, 5], 2, True, [1, 2, 3, 4, 5], id="all_results_true"),
        pytest.param([1, 2, 3, 4, 5], 2, False, [1, 2], id="all_results_false_exceeds_limit"),
        pytest.param([1, 2, 3], 5, False, [1, 2, 3], id="all_results_false_within_limit"),
        pytest.param([], 5, False, [], id="empty_list"),
    ],
)
def test_truncate_results(results: list, limit: int | None, all_results: bool, expected: list) -> None:
    """
    Given:
        - A list of results, a limit, and a flag to return all results.
    When:
        - Calling the truncate_results helper function.
    Then:
        - Assert the list is truncated correctly based on the limit and all_results flag.
    """
    from CriblSearch import truncate_results

    assert truncate_results(results, limit, all_results) == expected


def test_parse_ndjson_empty() -> None:
    """
    Given:
        - An empty string.
    When:
        - Calling _parse_ndjson.
    Then:
        - Returns an empty dict.
    """
    from CriblSearch import _parse_ndjson

    assert _parse_ndjson("") == {}


def test_parse_ndjson_bad_first_line() -> None:
    """
    Given:
        - A string whose first (and only) line is not valid JSON.
    When:
        - Calling _parse_ndjson.
    Then:
        - Raises DemistoException with a Cribl-specific metadata-parse message,
          because the first line is parsed as the metadata.
    """
    from CriblSearch import _parse_ndjson, DemistoException

    with pytest.raises(DemistoException, match="Failed to parse Cribl Search response metadata"):
        _parse_ndjson("not-json\n")


def test_parse_ndjson_skips_bad_event_lines() -> None:
    """
    Given:
        - An ndjson string with a valid metadata line, two valid event lines, and one bad line.
    When:
        - Calling _parse_ndjson.
    Then:
        - The metadata is parsed, the bad event line is skipped, and only valid events are returned.
    """
    from CriblSearch import _parse_ndjson

    text = '{"job":{"id":"x"},"events":[]}\n{"event":1}\nnot-json\n{"event":2}\n'
    result = _parse_ndjson(text)

    assert result["job"] == {"id": "x"}
    assert result["events"] == [{"event": 1}, {"event": 2}]


# endregion

# region parameters


class TestCredentials:
    """Tests for the Credentials pydantic model."""

    @pytest.mark.parametrize(
        "password",
        [
            pytest.param("simple-key", id="simple_key"),
            pytest.param("P@ssw0rd!#$%", id="complex_password"),
            pytest.param("a" * 64, id="long_key"),
        ],
    )
    def test_password_stored_as_secret_str(self, password: str) -> None:
        """
        Given:
            - A plain string password.
        When:
            - Constructing a Credentials model.
        Then:
            - The password field is stored as SecretStr and accessible via get_secret_value().
        """
        from pydantic import SecretStr
        from CriblSearch import Credentials

        creds = Credentials(identifier="test-id", password=password)  # type: ignore[arg-type]

        assert isinstance(creds.password, SecretStr)
        assert creds.password.get_secret_value() == password

    def test_identifier_field(self) -> None:
        """
        Given:
            - An identifier string.
        When:
            - Constructing a Credentials model.
        Then:
            - The identifier field is set correctly.
        """
        from pydantic import SecretStr
        from CriblSearch import Credentials

        creds = Credentials(identifier="my-client-id", password=SecretStr("secret"))

        assert creds.identifier == "my-client-id"

    def test_credentials_missing_password(self) -> None:
        """
        Given:
            - No password provided.
        When:
            - Initializing Credentials model.
        Then:
            - Assert DemistoException is raised.
        """
        from CommonServerPython import DemistoException
        from CriblSearch import Credentials

        with pytest.raises(DemistoException, match="password"):
            Credentials(identifier="test-id")  # type: ignore[call-arg]


class TestCriblSearchParams:
    """Tests for the CriblSearchParams pydantic model."""

    def test_client_id_property_returns_credentials_identifier(self) -> None:
        """
        Given:
            - Valid URL and credentials.
        When:
            - Constructing CriblSearchParams and accessing client_id.
        Then:
            - client_id returns the identifier from credentials.
        """
        from pydantic import SecretStr
        from CriblSearch import CriblSearchParams, Credentials

        params = CriblSearchParams(
            url="https://example.cribl.cloud",  # type: ignore[arg-type]
            credentials=Credentials(
                identifier="my-client-id",
                password=SecretStr("my-secret"),
            ),
        )

        assert params.client_id == "my-client-id"

    def test_client_secret_property_returns_credentials_password(self) -> None:
        """
        Given:
            - Valid URL and credentials.
        When:
            - Constructing CriblSearchParams and accessing client_secret.
        Then:
            - client_secret returns the SecretStr password from credentials.
        """
        from pydantic import SecretStr
        from CriblSearch import CriblSearchParams, Credentials

        params = CriblSearchParams(
            url="https://example.cribl.cloud",  # type: ignore[arg-type]
            credentials=Credentials(
                identifier="my-client-id",
                password=SecretStr("my-secret"),
            ),
        )

        assert isinstance(params.client_secret, SecretStr)
        assert params.client_secret.get_secret_value() == "my-secret"

    @pytest.mark.parametrize(
        "insecure, expected_verify",
        [
            pytest.param(False, True, id="insecure_false_verify_true"),
            pytest.param(True, False, id="insecure_true_verify_false"),
        ],
    )
    def test_verify_property(self, insecure: bool, expected_verify: bool) -> None:
        """
        Given:
            - CriblSearchParams with various insecure values.
        When:
            - Accessing the verify property.
        Then:
            - verify is the logical inverse of insecure.
        """
        from pydantic import SecretStr
        from CriblSearch import CriblSearchParams, Credentials

        params = CriblSearchParams(
            url="https://example.cribl.cloud",  # type: ignore[arg-type]
            credentials=Credentials(
                identifier="test-id",
                password=SecretStr("key"),
            ),
            insecure=insecure,
        )

        assert params.verify is expected_verify

    def test_url_accepted(self) -> None:
        """
        Given:
            - A valid URL string.
        When:
            - Constructing CriblSearchParams.
        Then:
            - The url field is set and contains the expected host.
        """
        from urllib.parse import urlparse
        from pydantic import SecretStr
        from CriblSearch import CriblSearchParams, Credentials

        params = CriblSearchParams(
            url="https://main-test-org.cribl.cloud",  # type: ignore[arg-type]
            credentials=Credentials(
                identifier="test-id",
                password=SecretStr("key"),
            ),
        )

        assert urlparse(str(params.url)).hostname == "main-test-org.cribl.cloud"

    def test_params_missing_url(self) -> None:
        """
        Given:
            - No URL provided.
        When:
            - Initializing CriblSearchParams.
        Then:
            - Assert DemistoException is raised.
        """
        from CommonServerPython import DemistoException
        from CriblSearch import CriblSearchParams

        with pytest.raises(DemistoException, match="url"):
            CriblSearchParams(
                credentials={"identifier": "test-id", "password": "secret"},  # type: ignore[call-arg]
            )

    def test_params_missing_credentials(self) -> None:
        """
        Given:
            - No credentials provided.
        When:
            - Initializing CriblSearchParams.
        Then:
            - Assert DemistoException is raised.
        """
        from CommonServerPython import DemistoException
        from CriblSearch import CriblSearchParams

        with pytest.raises(DemistoException, match="credentials"):
            CriblSearchParams(url="https://example.cribl.cloud")  # type: ignore[call-arg]


# endregion

# region test-module


def test_module_authentication_error(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - Client that raises ContentClientAuthenticationError.
    When:
        - Running test_module.
    Then:
        - Assert appropriate error message is returned.
    """
    from ContentClientApiModule import ContentClientAuthenticationError
    from CriblSearch import test_module

    mocker.patch.object(client, "search_datasets_list", side_effect=ContentClientAuthenticationError("Unauthorized"))
    # test_module logs the traceback via demisto.error on failure; patch it to keep stdout clean.
    mocker.patch.object(demisto, "error")

    result = test_module(client)

    assert result.startswith("AuthenticationError: Connection failed.")
    assert "Unauthorized" in result


# endregion

# region cribl-search-query


class TestSearchQueryArgs:
    """Tests for the SearchQueryArgs pydantic model."""

    def test_defaults(self) -> None:
        """
        Given:
            - Only the minimum required combo field provided (query_id) so the root validator passes.
        When:
            - Constructing SearchQueryArgs with defaults.
        Then:
            - limit defaults to 50, force defaults to False, and all other optional fields default to None.
        """
        from CriblSearch import SearchQueryArgs

        args = SearchQueryArgs(query_id="some-id")  # type: ignore[call-arg]

        assert args.limit == 50
        assert args.force is False
        assert args.query_id == "some-id"
        assert args.job_id is None
        assert args.query is None
        assert args.earliest is None
        assert args.latest is None
        assert args.sample_rate is None
        assert args.page is None

    @pytest.mark.parametrize(
        "limit_input, expected_limit",
        [
            pytest.param(50, 50, id="int_default"),
            pytest.param("42", 42, id="string_number_coerced"),
            pytest.param(10, 10, id="int_explicit"),
            pytest.param(None, None, id="none_passes_through"),
        ],
    )
    def test_limit_coercion(self, limit_input: int | str | None, expected_limit: int | None) -> None:
        """
        Given:
            - Various limit inputs (int, string number, None).
        When:
            - Constructing SearchQueryArgs (with query_id to satisfy the root validator).
        Then:
            - limit is coerced to int via arg_to_number or left as None.
        """
        from CriblSearch import SearchQueryArgs

        args = SearchQueryArgs(query_id="x", limit=limit_input)  # type: ignore[call-arg]

        assert args.limit == expected_limit

    @pytest.mark.parametrize(
        "force_input, expected",
        [
            pytest.param(False, False, id="bool_false"),
            pytest.param(True, True, id="bool_true"),
            pytest.param("true", True, id="string_true"),
            pytest.param("false", False, id="string_false"),
        ],
    )
    def test_force_coercion(self, force_input: bool | str, expected: bool) -> None:
        """
        Given:
            - Various force inputs (bool, string).
        When:
            - Constructing SearchQueryArgs (with query_id to satisfy the root validator).
        Then:
            - force is coerced to bool via argToBoolean.
        """
        from CriblSearch import SearchQueryArgs

        args = SearchQueryArgs(query_id="x", force=force_input)  # type: ignore[call-arg]

        assert args.force is expected

    def test_validator_requires_at_least_one_combo(self) -> None:
        """
        Given:
            - No combo field (query, query_id, or job_id) provided.
        When:
            - Constructing SearchQueryArgs.
        Then:
            - The root validator raises, wrapped by ContentBaseModel into DemistoException.
        """
        from CommonServerPython import DemistoException
        from CriblSearch import SearchQueryArgs

        with pytest.raises(DemistoException, match="At least one of"):
            SearchQueryArgs()  # type: ignore[call-arg]

    def test_validator_query_requires_earliest_and_latest(self) -> None:
        """
        Given:
            - Only `query` provided, without `earliest` or `latest`.
        When:
            - Constructing SearchQueryArgs.
        Then:
            - The root validator raises, wrapped by ContentBaseModel into DemistoException.
        """
        from CommonServerPython import DemistoException
        from CriblSearch import SearchQueryArgs

        with pytest.raises(DemistoException, match="earliest"):
            SearchQueryArgs(query="dataset=foo | limit 5")  # type: ignore[call-arg]


def test_search_query_command(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - Search query arguments.
    When:
        - Calling the search_query_command.
    Then:
        - Assert the client's search_query method is called.
        - Assert the response is correctly processed into CommandResults with expected outputs and prefix.
    """
    from CriblSearch import search_query_command, SearchQueryArgs

    mock_response = load_mock_response("cribl-search-query/response.json")
    mocker.patch.object(client, "search_query", return_value=mock_response)

    args = SearchQueryArgs(query='dataset="cribl_search_sample" | limit 5', earliest="-5m", latest="now")  # type: ignore[call-arg]

    response = search_query_command(client, args)

    assert response.outputs_prefix == "Cribl.SearchQuery"
    assert response.outputs_key_field == "job.id"
    assert "Search Query - Job Info" in response.readable_output

    outputs: dict[str, Any] = response.outputs  # type: ignore[assignment]

    assert outputs.get("isFinished") is False
    assert outputs.get("totalEventCount") == 0
    assert outputs.get("events") == []
    assert outputs.get("job", {}).get("id") == "1777383267244.i0hUyX"
    assert outputs.get("job", {}).get("status") == "queued"


# endregion

# region cribl-search-status


class TestSearchStatusArgs:
    """Tests for the SearchStatusArgs pydantic model."""

    def test_job_id_required(self) -> None:
        """
        Given:
            - A job_id string.
        When:
            - Constructing SearchStatusArgs.
        Then:
            - job_id is set correctly.
        """
        from CriblSearch import SearchStatusArgs

        args = SearchStatusArgs(job_id="job_abc123")

        assert args.job_id == "job_abc123"

    def test_job_id_missing_raises(self) -> None:
        """
        Given:
            - No job_id provided.
        When:
            - Constructing SearchStatusArgs.
        Then:
            - Assert DemistoException is raised.
        """
        from CommonServerPython import DemistoException
        from CriblSearch import SearchStatusArgs

        with pytest.raises(DemistoException, match="job_id"):
            SearchStatusArgs()  # type: ignore[call-arg]


def test_search_status_command(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - A job ID to check status.
    When:
        - Calling the search_status_command.
    Then:
        - Assert the client's search_job_status method is called.
        - Assert the response is correctly processed into CommandResults with expected outputs.
    """
    from CriblSearch import search_status_command, SearchStatusArgs

    mock_response = load_mock_response("cribl-search-status/response.json")
    mocker.patch.object(client, "search_job_status", return_value=mock_response)

    args = SearchStatusArgs(job_id="1777207075060.cCPnVx")

    response = search_status_command(client, args)

    assert response.outputs_prefix == "Cribl.SearchStatus"

    outputs: dict[str, Any] = response.outputs  # type: ignore[assignment]

    assert outputs.get("status") == "completed"
    assert outputs.get("timeStarted") == 1777207075512
    assert outputs.get("timeCompleted") == 1777207082580
    assert "Status" in response.readable_output


# endregion

# region cribl-search-result


class TestSearchResultArgs:
    """Tests for the SearchResultArgs pydantic model."""

    def test_defaults(self) -> None:
        """
        Given:
            - Only job_id provided.
        When:
            - Constructing SearchResultArgs with defaults.
        Then:
            - limit defaults to 50 and all_results defaults to False.
        """
        from CriblSearch import SearchResultArgs

        args = SearchResultArgs(job_id="job_abc123")  # type: ignore[call-arg]

        assert args.limit == 50
        assert args.all_results is False
        assert args.lower_bound is None
        assert args.upper_bound is None
        assert args.page is None

    @pytest.mark.parametrize(
        "limit_input, expected_limit",
        [
            pytest.param(50, 50, id="int_default"),
            pytest.param("25", 25, id="string_number_coerced"),
            pytest.param(None, None, id="none_passes_through"),
        ],
    )
    def test_limit_coercion(self, limit_input: int | str | None, expected_limit: int | None) -> None:
        """
        Given:
            - Various limit inputs (int, string number, None).
        When:
            - Constructing SearchResultArgs.
        Then:
            - limit is coerced to int via arg_to_number or left as None.
        """
        from CriblSearch import SearchResultArgs

        args = SearchResultArgs(job_id="job_abc123", limit=limit_input)  # type: ignore[call-arg]

        assert args.limit == expected_limit

    @pytest.mark.parametrize(
        "all_results_input, expected",
        [
            pytest.param(False, False, id="bool_false"),
            pytest.param(True, True, id="bool_true"),
            pytest.param("true", True, id="string_true"),
            pytest.param("false", False, id="string_false"),
        ],
    )
    def test_all_results_coercion(self, all_results_input: bool | str, expected: bool) -> None:
        """
        Given:
            - Various all_results inputs (bool, string).
        When:
            - Constructing SearchResultArgs.
        Then:
            - all_results is coerced to bool via argToBoolean.
        """
        from CriblSearch import SearchResultArgs

        args = SearchResultArgs(job_id="job_abc123", all_results=all_results_input)  # type: ignore[call-arg]

        assert args.all_results is expected


def test_search_result_command(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - A job ID to retrieve results.
    When:
        - Calling the search_result_command.
    Then:
        - Assert the client's search_job_results method is called.
        - Assert the response is correctly processed into CommandResults with expected outputs.
    """
    from CriblSearch import search_result_command, SearchResultArgs

    mock_response = load_mock_response("cribl-search-result/response.json")
    mocker.patch.object(client, "search_job_results", return_value=mock_response)

    args = SearchResultArgs(job_id="1777207075060.cCPnVx")  # type: ignore[call-arg]

    response = search_result_command(client, args)

    assert response.outputs_prefix == "Cribl.SearchResult"
    assert response.outputs_key_field == "job.id"

    outputs: dict[str, Any] = response.outputs  # type: ignore[assignment]

    assert outputs.get("isFinished") is True
    assert outputs.get("totalEventCount") == 33
    assert outputs.get("persistedEventCount") == 33
    assert outputs.get("job", {}).get("id") == "1777207075060.cCPnVx"
    assert outputs.get("job", {}).get("status") == "completed"

    events = outputs.get("events", [])
    assert len(events) == 5
    assert events[0].get("srcaddr") == "192.0.2.10"
    assert events[4].get("srcaddr") == "192.0.2.14"

    assert "Job Info" in response.readable_output


# endregion

# region cribl-search-job-create


class TestSearchJobCreateArgs:
    """Tests for the SearchJobCreateArgs pydantic model."""

    def test_required_query(self) -> None:
        """
        Given:
            - A query string.
        When:
            - Constructing SearchJobCreateArgs with only query.
        Then:
            - query is set and optional fields have defaults.
        """
        from CriblSearch import SearchJobCreateArgs

        args = SearchJobCreateArgs(query='dataset="cribl_search_sample"')  # type: ignore[call-arg]

        assert args.query == 'dataset="cribl_search_sample"'
        assert args.is_private is True
        assert args.earliest is None
        assert args.latest is None
        assert args.sample_rate is None
        assert args.num_events_before is None
        assert args.num_events_after is None
        assert args.target_event_time is None
        assert args.set_options is None
        assert args.expected_output_type is None

    @pytest.mark.parametrize(
        "is_private_input, expected",
        [
            pytest.param(True, True, id="bool_true"),
            pytest.param(False, False, id="bool_false"),
            pytest.param("true", True, id="string_true"),
            pytest.param("false", False, id="string_false"),
        ],
    )
    def test_is_private_coercion(self, is_private_input: bool | str, expected: bool) -> None:
        """
        Given:
            - Various is_private inputs (bool, string).
        When:
            - Constructing SearchJobCreateArgs.
        Then:
            - is_private is coerced to bool via argToBoolean.
        """
        from CriblSearch import SearchJobCreateArgs

        args = SearchJobCreateArgs(query="test", is_private=is_private_input)  # type: ignore[call-arg]

        assert args.is_private is expected

    @pytest.mark.parametrize(
        "set_options_input, expected",
        [
            pytest.param('{"key": "val", "num": 42}', {"key": "val", "num": 42}, id="json_string_parsed"),
            pytest.param({"a": 1, "b": "two"}, {"a": 1, "b": "two"}, id="dict_passthrough"),
        ],
    )
    def test_set_options_json_coercion(self, set_options_input: str | dict, expected: dict) -> None:
        """
        Given:
            - set_options as a JSON string or dict.
        When:
            - Constructing SearchJobCreateArgs.
        Then:
            - set_options is parsed from JSON string or passed through as dict.
        """
        from CriblSearch import SearchJobCreateArgs

        args = SearchJobCreateArgs(query="test", set_options=set_options_input)  # type: ignore[call-arg]

        assert args.set_options == expected

    def test_set_options_invalid_json_raises(self) -> None:
        """
        Given:
            - set_options as an invalid JSON string.
        When:
            - Constructing SearchJobCreateArgs.
        Then:
            - DemistoException is raised because the invalid string fails Pydantic's dict type check.
        """
        from CommonServerPython import DemistoException
        from CriblSearch import SearchJobCreateArgs

        with pytest.raises(DemistoException, match="set_options"):
            SearchJobCreateArgs(query="test", set_options="not-json{broken")  # type: ignore[call-arg]

    def test_missing_query_raises(self) -> None:
        """
        Given:
            - No query provided.
        When:
            - Constructing SearchJobCreateArgs.
        Then:
            - Assert DemistoException is raised.
        """
        from CommonServerPython import DemistoException
        from CriblSearch import SearchJobCreateArgs

        with pytest.raises(DemistoException, match="query"):
            SearchJobCreateArgs()  # type: ignore[call-arg]


def test_search_job_create_command(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - Search job creation arguments.
    When:
        - Calling the search_job_create_command.
    Then:
        - Assert the client's search_job_create method is called.
        - Assert the response is correctly processed into CommandResults with expected job details.
    """
    from CriblSearch import search_job_create_command, SearchJobCreateArgs

    mock_response = load_mock_response("cribl-search-job-create/response.json")
    mocker.patch.object(client, "search_job_create", return_value=mock_response)

    args = SearchJobCreateArgs(query='dataset="cribl_search_sample" | limit 5')  # type: ignore[call-arg]

    response = search_job_create_command(client, args)

    assert response.outputs_prefix == "Cribl.SearchJob"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore[assignment]

    assert outputs.get("id") == "1777381220097.F0vzpw"
    assert outputs.get("status") == "queued"
    assert outputs.get("user") == "EXAMPLECLIENTID0000000000000000@clients"
    assert outputs.get("isPrivate") is True
    assert "Search Job Created" in response.readable_output


# endregion

# region cribl-search-job-list


class TestSearchJobListArgs:
    """Tests for the SearchJobListArgs pydantic model."""

    def test_defaults(self) -> None:
        """
        Given:
            - No arguments provided.
        When:
            - Constructing SearchJobListArgs with defaults.
        Then:
            - limit defaults to 10, all_results defaults to False, job_id defaults to None.
        """
        from CriblSearch import SearchJobListArgs

        args = SearchJobListArgs()  # type: ignore[call-arg]

        assert args.limit == 10
        assert args.all_results is False
        assert args.job_id is None

    def test_job_id_optional(self) -> None:
        """
        Given:
            - A job_id string.
        When:
            - Constructing SearchJobListArgs with job_id.
        Then:
            - job_id is set correctly.
        """
        from CriblSearch import SearchJobListArgs

        args = SearchJobListArgs(job_id="job_abc123")  # type: ignore[call-arg]

        assert args.job_id == "job_abc123"

    @pytest.mark.parametrize(
        "limit_input, expected_limit",
        [
            pytest.param(10, 10, id="int_default"),
            pytest.param("5", 5, id="string_number_coerced"),
            pytest.param(None, None, id="none_passes_through"),
        ],
    )
    def test_limit_coercion(self, limit_input: int | str | None, expected_limit: int | None) -> None:
        """
        Given:
            - Various limit inputs.
        When:
            - Constructing SearchJobListArgs.
        Then:
            - limit is coerced to int via arg_to_number or left as None.
        """
        from CriblSearch import SearchJobListArgs

        args = SearchJobListArgs(limit=limit_input)  # type: ignore[call-arg]

        assert args.limit == expected_limit


def test_search_job_list_command_all(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - No specific job ID (requesting all jobs).
    When:
        - Calling the search_job_list_command.
    Then:
        - Assert the client's search_jobs_list method is called.
        - Assert the response is correctly processed into CommandResults containing a list of jobs.
    """
    from CriblSearch import search_job_list_command, SearchJobListArgs

    mock_response = load_mock_response("cribl-search-job-list/list.json")
    mocker.patch.object(client, "search_jobs_list", return_value=mock_response)

    args = SearchJobListArgs(job_id=None, limit=None, all_results=False)

    response = search_job_list_command(client, args)

    assert response.outputs_prefix == "Cribl.SearchJob"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore[assignment]

    assert len(outputs) == 3
    assert outputs[0].get("id") == "1777207075060.cCPnVx"
    assert outputs[1].get("id") == "1777207943198.pb0ZZ0"
    assert "Search Jobs List" in response.readable_output


def test_search_job_list_command_single(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - A specific job ID.
    When:
        - Calling the search_job_list_command.
    Then:
        - Assert the client's search_jobs_list method is called for the specific job.
        - Assert the response is correctly processed into CommandResults with detailed job information.
    """
    from CriblSearch import search_job_list_command, SearchJobListArgs

    mock_response = load_mock_response("cribl-search-job-list/get.json")
    mocker.patch.object(client, "search_jobs_list", return_value=mock_response)

    args = SearchJobListArgs(job_id="1777207075060.cCPnVx", limit=None, all_results=False)

    response = search_job_list_command(client, args)

    assert response.outputs_prefix == "Cribl.SearchJob"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore[assignment]

    assert outputs.get("id") == "1777207075060.cCPnVx"
    assert outputs.get("status") == "completed"
    assert outputs.get("user") == "EXAMPLECLIENTID0000000000000000@clients"
    assert "Search Job 1777207075060.cCPnVx Details" in response.readable_output


# endregion

# region cribl-search-job-update


class TestSearchJobUpdateArgs:
    """Tests for the SearchJobUpdateArgs pydantic model."""

    def test_job_id_required(self) -> None:
        """
        Given:
            - A job_id and status.
        When:
            - Constructing SearchJobUpdateArgs.
        Then:
            - job_id and status are set correctly.
        """
        from CriblSearch import SearchJobUpdateArgs

        args = SearchJobUpdateArgs(job_id="job_abc123", status="canceled")  # type: ignore[call-arg]

        assert args.job_id == "job_abc123"
        assert args.status == "canceled"
        assert args.is_private is None

    @pytest.mark.parametrize(
        "is_private_input, expected",
        [
            pytest.param(None, None, id="none_passthrough"),
            pytest.param(True, True, id="bool_true"),
            pytest.param(False, False, id="bool_false"),
            pytest.param("true", True, id="string_true"),
            pytest.param("false", False, id="string_false"),
        ],
    )
    def test_is_private_coercion(self, is_private_input: bool | str | None, expected: bool | None) -> None:
        """
        Given:
            - Various is_private inputs.
        When:
            - Constructing SearchJobUpdateArgs (with status to satisfy the root validator).
        Then:
            - is_private is coerced via argToBoolean or left as None.
        """
        from CriblSearch import SearchJobUpdateArgs

        args = SearchJobUpdateArgs(
            job_id="job_abc123",
            status="canceled",
            is_private=is_private_input,  # type: ignore[arg-type]
        )

        assert args.is_private is expected

    def test_job_id_missing_raises(self) -> None:
        """
        Given:
            - No job_id provided (status is provided so the at-least-one validator passes).
        When:
            - Constructing SearchJobUpdateArgs.
        Then:
            - Assert DemistoException is raised for the missing job_id.
        """
        from CommonServerPython import DemistoException
        from CriblSearch import SearchJobUpdateArgs

        with pytest.raises(DemistoException, match="job_id"):
            SearchJobUpdateArgs(status="canceled")  # type: ignore[call-arg]

    def test_validator_requires_status_or_is_private(self) -> None:
        """
        Given:
            - A job_id but neither status nor is_private.
        When:
            - Constructing SearchJobUpdateArgs.
        Then:
            - The root validator raises, wrapped by ContentBaseModel into DemistoException.
        """
        from CommonServerPython import DemistoException
        from CriblSearch import SearchJobUpdateArgs

        with pytest.raises(DemistoException, match="At least one of 'status' or 'is_private'"):
            SearchJobUpdateArgs(job_id="job_abc123")  # type: ignore[call-arg]


def test_search_job_update_command(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - A job ID and is_private flag to update.
    When:
        - Calling the search_job_update_command.
    Then:
        - Assert the client's search_job_update method is called.
        - Assert the readable output indicates successful update.
    """
    from CriblSearch import search_job_update_command, SearchJobUpdateArgs

    mock_response = load_mock_response("cribl-search-job-update/response.json")
    mocker.patch.object(client, "search_job_update", return_value=mock_response)

    args = SearchJobUpdateArgs(job_id="1777207075060.cCPnVx", is_private=False)  # type: ignore[call-arg]

    response = search_job_update_command(client, args)

    assert response.outputs_prefix == "Cribl.SearchJob"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore[assignment]

    assert outputs.get("id") == "1777207075060.cCPnVx"
    assert outputs.get("isPrivate") is False
    assert "successfully updated" in response.readable_output


# endregion

# region cribl-search-job-delete


class TestSearchJobDeleteArgs:
    """Tests for the SearchJobDeleteArgs pydantic model."""

    def test_job_id_required(self) -> None:
        """
        Given:
            - A job_id string.
        When:
            - Constructing SearchJobDeleteArgs.
        Then:
            - job_id is set correctly.
        """
        from CriblSearch import SearchJobDeleteArgs

        args = SearchJobDeleteArgs(job_id="job_abc123")

        assert args.job_id == "job_abc123"

    def test_job_id_missing_raises(self) -> None:
        """
        Given:
            - No job_id provided.
        When:
            - Constructing SearchJobDeleteArgs.
        Then:
            - Assert DemistoException is raised.
        """
        from CommonServerPython import DemistoException
        from CriblSearch import SearchJobDeleteArgs

        with pytest.raises(DemistoException, match="job_id"):
            SearchJobDeleteArgs()  # type: ignore[call-arg]


def test_search_job_delete_command(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - A job ID to delete.
    When:
        - Calling the search_job_delete_command.
    Then:
        - Assert the client's search_job_delete method is called with the correct job ID.
        - Assert the readable output indicates successful deletion.
        - Assert no outputs are returned.
    """
    from CriblSearch import search_job_delete_command, SearchJobDeleteArgs

    mocker.patch.object(client, "search_job_delete", return_value=None)

    args = SearchJobDeleteArgs(job_id="job_abc123")

    response = search_job_delete_command(client, args)

    assert "successfully deleted" in response.readable_output
    assert response.outputs is None
    client.search_job_delete.assert_called_once_with(job_id="job_abc123")  # type: ignore[attr-defined]


# endregion

# region cribl-search-dataset-list


class TestSearchDatasetListArgs:
    """Tests for the SearchDatasetListArgs pydantic model."""

    def test_defaults(self) -> None:
        """
        Given:
            - No arguments provided.
        When:
            - Constructing SearchDatasetListArgs with defaults.
        Then:
            - limit defaults to 10, all_results defaults to False, dataset_id defaults to None.
        """
        from CriblSearch import SearchDatasetListArgs

        args = SearchDatasetListArgs()  # type: ignore[call-arg]

        assert args.limit == 10
        assert args.all_results is False
        assert args.dataset_id is None

    @pytest.mark.parametrize(
        "limit_input, expected_limit",
        [
            pytest.param(10, 10, id="int_default"),
            pytest.param("5", 5, id="string_number_coerced"),
            pytest.param(None, None, id="none_passes_through"),
        ],
    )
    def test_limit_coercion(self, limit_input: int | str | None, expected_limit: int | None) -> None:
        """
        Given:
            - Various limit inputs.
        When:
            - Constructing SearchDatasetListArgs.
        Then:
            - limit is coerced to int via arg_to_number or left as None.
        """
        from CriblSearch import SearchDatasetListArgs

        args = SearchDatasetListArgs(limit=limit_input)  # type: ignore[call-arg]

        assert args.limit == expected_limit

    @pytest.mark.parametrize(
        "all_results_input, expected",
        [
            pytest.param(False, False, id="bool_false"),
            pytest.param(True, True, id="bool_true"),
            pytest.param("true", True, id="string_true"),
            pytest.param("false", False, id="string_false"),
        ],
    )
    def test_all_results_coercion(self, all_results_input: bool | str, expected: bool) -> None:
        """
        Given:
            - Various all_results inputs (bool, string).
        When:
            - Constructing SearchDatasetListArgs.
        Then:
            - all_results is coerced to bool via argToBoolean.
        """
        from CriblSearch import SearchDatasetListArgs

        args = SearchDatasetListArgs(all_results=all_results_input)  # type: ignore[call-arg]

        assert args.all_results is expected


def test_search_dataset_list_command_all(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - No specific dataset ID (requesting all datasets).
    When:
        - Calling the search_dataset_list_command.
    Then:
        - Assert the client's search_datasets_list method is called.
        - Assert the response is correctly processed into CommandResults containing a list of datasets.
    """
    from CriblSearch import search_dataset_list_command, SearchDatasetListArgs

    mock_response = load_mock_response("cribl-search-dataset-list/list.json")
    mocker.patch.object(client, "search_datasets_list", return_value=mock_response)

    args = SearchDatasetListArgs(dataset_id=None, limit=None, all_results=False)

    response = search_dataset_list_command(client, args)

    assert response.outputs_prefix == "Cribl.SearchDataset"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore[assignment]

    assert len(outputs) == 1
    assert outputs[0].get("id") == "cribl_search_sample"
    assert outputs[0].get("type") == "s3"
    assert "Datasets List" in response.readable_output


def test_search_dataset_list_command_single(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - A specific dataset ID.
    When:
        - Calling the search_dataset_list_command.
    Then:
        - Assert the client's search_datasets_list method is called for the specific dataset.
        - Assert the response is correctly processed into CommandResults with detailed dataset information.
    """
    from CriblSearch import search_dataset_list_command, SearchDatasetListArgs

    mock_response = load_mock_response("cribl-search-dataset-list/get.json")
    mocker.patch.object(client, "search_datasets_list", return_value=mock_response)

    args = SearchDatasetListArgs(dataset_id="cribl_search_sample", limit=None, all_results=False)

    response = search_dataset_list_command(client, args)

    assert response.outputs_prefix == "Cribl.SearchDataset"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore[assignment]

    assert outputs.get("id") == "cribl_search_sample"
    assert outputs.get("type") == "s3"
    assert outputs.get("provider") == "cribl_s3sample_provider"
    assert "Dataset cribl_search_sample Details" in response.readable_output


# endregion

# region cribl-saved-search-list


class TestSavedSearchListArgs:
    """Tests for the SavedSearchListArgs pydantic model."""

    def test_defaults(self) -> None:
        """
        Given:
            - No arguments provided.
        When:
            - Constructing SavedSearchListArgs with defaults.
        Then:
            - limit defaults to 10, all_results defaults to False, search_id defaults to None.
        """
        from CriblSearch import SavedSearchListArgs

        args = SavedSearchListArgs()  # type: ignore[call-arg]

        assert args.limit == 10
        assert args.all_results is False
        assert args.search_id is None

    @pytest.mark.parametrize(
        "limit_input, expected_limit",
        [
            pytest.param(10, 10, id="int_default"),
            pytest.param("5", 5, id="string_number_coerced"),
            pytest.param(None, None, id="none_passes_through"),
        ],
    )
    def test_limit_coercion(self, limit_input: int | str | None, expected_limit: int | None) -> None:
        """
        Given:
            - Various limit inputs.
        When:
            - Constructing SavedSearchListArgs.
        Then:
            - limit is coerced to int via arg_to_number or left as None.
        """
        from CriblSearch import SavedSearchListArgs

        args = SavedSearchListArgs(limit=limit_input)  # type: ignore[call-arg]

        assert args.limit == expected_limit

    @pytest.mark.parametrize(
        "all_results_input, expected",
        [
            pytest.param(False, False, id="bool_false"),
            pytest.param(True, True, id="bool_true"),
            pytest.param("true", True, id="string_true"),
            pytest.param("false", False, id="string_false"),
        ],
    )
    def test_all_results_coercion(self, all_results_input: bool | str, expected: bool) -> None:
        """
        Given:
            - Various all_results inputs (bool, string).
        When:
            - Constructing SavedSearchListArgs.
        Then:
            - all_results is coerced to bool via argToBoolean.
        """
        from CriblSearch import SavedSearchListArgs

        args = SavedSearchListArgs(all_results=all_results_input)  # type: ignore[call-arg]

        assert args.all_results is expected


def test_saved_search_list_command_all(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - No specific search ID (requesting all saved searches).
    When:
        - Calling the saved_search_list_command.
    Then:
        - Assert the client's saved_searches_list method is called.
        - Assert the response is correctly processed into CommandResults containing a list of saved searches.
    """
    from CriblSearch import saved_search_list_command, SavedSearchListArgs

    mock_response = load_mock_response("cribl-saved-search-list/list.json")
    mocker.patch.object(client, "saved_searches_list", return_value=mock_response)

    args = SavedSearchListArgs(search_id=None, limit=None, all_results=False)

    response = saved_search_list_command(client, args)

    assert response.outputs_prefix == "Cribl.SavedSearch"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore[assignment]

    assert len(outputs) == 2
    assert outputs[0].get("id") == "cribl_search_finished_1h"
    assert outputs[1].get("id") == "cribl_search_started_1h"
    assert "Saved Searches List" in response.readable_output


def test_saved_search_list_command_single(mocker: MockerFixture, client: "CriblSearchClient") -> None:
    """
    Given:
        - A specific search ID.
    When:
        - Calling the saved_search_list_command.
    Then:
        - Assert the client's saved_searches_list method is called for the specific saved search.
        - Assert the response is correctly processed into CommandResults with detailed saved search information.
    """
    from CriblSearch import saved_search_list_command, SavedSearchListArgs

    mock_response = load_mock_response("cribl-saved-search-list/get.json")
    mocker.patch.object(client, "saved_searches_list", return_value=mock_response)

    args = SavedSearchListArgs(search_id="cribl_search_finished_1h", limit=None, all_results=False)

    response = saved_search_list_command(client, args)

    assert response.outputs_prefix == "Cribl.SavedSearch"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore[assignment]

    assert outputs.get("id") == "cribl_search_finished_1h"
    assert outputs.get("name") == "cribl_search_finished_1h"
    assert outputs.get("description") == "Searches finished in the last 1h"
    assert "Saved Search cribl_search_finished_1h Details" in response.readable_output


# endregion
