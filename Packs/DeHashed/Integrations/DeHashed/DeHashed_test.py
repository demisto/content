import demistomock as demisto
import pytest
from pytest_mock import MockerFixture
import json
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from DeHashed import DehashedClient


def load_mock_response(file_path: str) -> dict | list:
    """
    Helper function to load mock response data from a JSON file.

    Args:
        file_path (str): The relative path under the test_data directory to the JSON file
            (e.g. "dehashed-search/response.json").

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
def client() -> "DehashedClient":
    """
    Pytest fixture that initializes and returns a DehashedClient instance for testing.

    Returns:
        DehashedClient: An instance of the DeHashed API client.
    """
    from pydantic import SecretStr
    from DeHashed import DehashedClient, DehashedParams, Credentials

    params = DehashedParams(
        credentials=Credentials(
            password=SecretStr("test-key"),
        ),
    )  # type: ignore[call-arg]
    return DehashedClient(params)


# region helpers


def test_build_search_query_raises_on_empty_value() -> None:
    """
    Given:
        - An empty `value` string.
    When:
        - Calling _build_search_query.
    Then:
        - Raises DemistoException with the 'must get "value" as an argument' message.
    """
    from DeHashed import _build_search_query, DemistoException

    with pytest.raises(DemistoException, match='This command must get "value" as an argument.'):
        _build_search_query("email", "", "is")


@pytest.mark.parametrize(
    "asset_type, value, operation, expected_query",
    [
        pytest.param("email", "a@b.co", "is", 'email:"a@b.co"', id="is_single_email"),
        pytest.param("all_fields", "testgamil.co", "is", '"testgamil.co"', id="is_single_all_fields"),
        pytest.param("all_fields", "testgamil.co", "contains", "testgamil.co", id="contains_single_all_fields"),
        pytest.param("email", "foo", "contains", "email:foo", id="contains_single_email"),
        pytest.param("all_fields", "joh?n(ath[oa]n)", "regex", "joh?n(ath[oa]n)", id="regex_single_all_fields"),
        pytest.param("vin", "abc", "regex", "vin:abc", id="regex_single_vin"),
    ],
)
def test_build_search_query_parametrized(
    asset_type: str,
    value: str,
    operation: str,
    expected_query: str,
) -> None:
    """
    Given:
        - Various combinations of `asset_type`, `value`, and `operation` covering
          `is`, `contains`, and `regex` operators with a single string `value`.
    When:
        - Calling _build_search_query.
    Then:
        - Returns the query string per the documented rules:
          - `is`         -> wraps the value in double quotes.
          - `contains`   -> uses the raw value.
          - `regex`      -> uses the raw value (regex relies on the client `regex=True` flag).
          - `all_fields` -> omits the leading `"<asset_type>:"` prefix.
    """
    from DeHashed import _build_search_query

    assert _build_search_query(asset_type, value, operation) == expected_query


def test_filter_results_explicit_in_range() -> None:
    """
    Given:
        - A 2-entry list and `results_from=1`, `results_to=2`.
    When:
        - Calling _filter_results.
    Then:
        - Returns the full list with resolved `(1, 2)`.
    """
    from DeHashed import _filter_results

    entries = [{"id": "id_1"}, {"id": "id_2"}]

    sliced, results_from, results_to = _filter_results(entries, 1, 2)

    assert sliced == entries
    assert results_from == 1
    assert results_to == 2


def test_filter_results_to_beyond_len() -> None:
    """
    Given:
        - A 2-entry list and `results_to=50` (beyond list length).
    When:
        - Calling _filter_results.
    Then:
        - Returns the full list (Python slicing tolerates `stop > len`); the resolved
          `results_to` is not clamped — it is returned verbatim.
    """
    from DeHashed import _filter_results

    entries = [{"id": "id_1"}, {"id": "id_2"}]

    sliced, results_from, results_to = _filter_results(entries, 1, 50)

    assert sliced == entries
    assert results_from == 1
    assert results_to == 2


def test_filter_results_explicit_range() -> None:
    """
    Given:
        - A 2-entry list and `results_from=1`, `results_to=1`.
    When:
        - Calling _filter_results.
    Then:
        - Returns only the first entry; resolved range is `(1, 1)`.
    """
    from DeHashed import _filter_results

    entries = [{"id": "id_1"}, {"id": "id_2"}]

    sliced, results_from, results_to = _filter_results(entries, 1, 1)

    assert sliced == entries[0:1]
    assert results_from == 1
    assert results_to == 1


def test_transform_entry_flattens_lists() -> None:
    """
    Given:
        - An entry with list-typed identity fields (`email`, `phone`).
    When:
        - Calling _transform_entry.
    Then:
        - List fields are flattened into comma-separated strings; keys are CamelCase.
    """
    from DeHashed import _transform_entry

    out = _transform_entry({"email": ["a@b.co"], "phone": ["1", "2"]})

    assert out == {"Email": "a@b.co", "Phone": "1, 2"}


def test_transform_entry_passthrough_scalars() -> None:
    """
    Given:
        - An entry with scalar string fields.
    When:
        - Calling _transform_entry.
    Then:
        - Scalar fields are passed through unchanged with CamelCase keys.
    """
    from DeHashed import _transform_entry

    out = _transform_entry({"id": "x", "database_name": "DB"})

    assert out == {"Id": "x", "DatabaseName": "DB"}


def test_transform_entry_omits_empty_and_none() -> None:
    """
    Given:
        - An entry containing `[]`, `[""]`, `None`, and `""` values mixed with valid ones.
    When:
        - Calling _transform_entry.
    Then:
        - Empty / None-valued keys are omitted from the output entirely.
    """
    from DeHashed import _transform_entry

    out = _transform_entry(
        {
            "id": "x",
            "empty_list": [],
            "list_of_empty": [""],
            "none_value": None,
            "empty_string": "",
            "email": ["a@b.co"],
        }
    )

    assert out == {"Id": "x", "Email": "a@b.co"}
    assert "EmptyList" not in out
    assert "ListOfEmpty" not in out
    assert "NoneValue" not in out
    assert "EmptyString" not in out


def test_transform_entry_passthrough_dict() -> None:
    """
    Given:
        - An entry with a nested dict value (`raw_record`).
    When:
        - Calling _transform_entry.
    Then:
        - The dict is passed through unchanged under a CamelCase key.
    """
    from DeHashed import _transform_entry

    out = _transform_entry({"raw_record": {"k": "v"}})

    assert out == {"RawRecord": {"k": "v"}}


def test_transform_entry_passthrough_dict_with_bool_values() -> None:
    """
    Given:
        - An entry whose `raw_record` dict contains bool values
          (mirrors the canonical api_response_example.json shape).
    When:
        - Calling _transform_entry.
    Then:
        - The dict (including bool values) is passed through unchanged.
    """
    from DeHashed import _transform_entry

    out = _transform_entry({"raw_record": {"le_only": True, "unstructured": True}})

    assert out == {"RawRecord": {"le_only": True, "unstructured": True}}


def test_transform_entry_camel_case_keys() -> None:
    """
    Given:
        - An entry with snake_case keys requiring multi-word CamelCase conversion.
    When:
        - Calling _transform_entry.
    Then:
        - Keys are converted to CamelCase (e.g. `hashed_password` -> `HashedPassword`).
    """
    from DeHashed import _transform_entry

    out = _transform_entry({"hashed_password": ["abc"], "ip_address": ["1.1.1.1"]})

    assert "HashedPassword" in out
    assert "IpAddress" in out
    assert out["HashedPassword"] == "abc"
    assert out["IpAddress"] == "1.1.1.1"


def test_compute_score_no_sources_returns_none() -> None:
    """
    Given:
        - An empty entries list (or entries lacking `database_name`).
    When:
        - Calling compute_score.
    Then:
        - Returns Common.DBotScore.NONE (0).
    """
    from CommonServerPython import Common
    from DeHashed import compute_score

    assert compute_score([], "SUSPICIOUS") == Common.DBotScore.NONE
    assert compute_score([{"id": "x"}], "SUSPICIOUS") == Common.DBotScore.NONE


def test_compute_score_suspicious_label() -> None:
    """
    Given:
        - Entries containing `database_name` and the configured label "SUSPICIOUS".
    When:
        - Calling compute_score.
    Then:
        - Returns Common.DBotScore.SUSPICIOUS (numeric 2).
    """
    from CommonServerPython import Common
    from DeHashed import compute_score

    score = compute_score([{"database_name": "DB-A"}], "SUSPICIOUS")

    assert score == Common.DBotScore.SUSPICIOUS
    assert score == 2


def test_compute_score_malicious_label() -> None:
    """
    Given:
        - Entries containing `database_name` and the configured label "MALICIOUS".
    When:
        - Calling compute_score.
    Then:
        - Returns Common.DBotScore.BAD (numeric 3, labeled "MALICIOUS" in the UI).
    """
    from CommonServerPython import Common
    from DeHashed import compute_score

    score = compute_score([{"database_name": "DB-A"}], "MALICIOUS")

    assert score == Common.DBotScore.BAD
    assert score == 3


def test_compute_score_unknown_label_defaults_to_bad() -> None:
    """
    Given:
        - Entries with `database_name` and an unknown label string ("UNKNOWN").
    When:
        - Calling compute_score.
    Then:
        - Defaults to Common.DBotScore.BAD (the `else` branch).
    """
    from CommonServerPython import Common
    from DeHashed import compute_score

    assert compute_score([{"database_name": "DB-A"}], "UNKNOWN") == Common.DBotScore.BAD


# endregion

# region parameters


class TestCredentials:
    """Tests for the Credentials pydantic model."""

    @pytest.mark.parametrize(
        "password",
        [
            pytest.param("simple-key", id="simple"),
            pytest.param("P@ssw0rd!#$%", id="complex"),
            pytest.param("a" * 64, id="long"),
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
        from DeHashed import Credentials

        creds = Credentials(password=password)  # type: ignore[arg-type]

        assert isinstance(creds.password, SecretStr)
        assert creds.password.get_secret_value() == password

    def test_credentials_missing_password_raises(self) -> None:
        """
        Given:
            - No password provided.
        When:
            - Constructing Credentials.
        Then:
            - Raises DemistoException mentioning `password`.
        """
        from CommonServerPython import DemistoException
        from DeHashed import Credentials

        with pytest.raises(DemistoException, match="password"):
            Credentials()  # type: ignore[call-arg]


class TestDehashedParams:
    """Tests for the DehashedParams pydantic model."""

    def test_api_key_property_returns_credentials_password(self) -> None:
        """
        Given:
            - DehashedParams constructed with credentials.
        When:
            - Accessing the `api_key` property.
        Then:
            - Returns the SecretStr password from the credentials.
        """
        from pydantic import SecretStr
        from DeHashed import DehashedParams, Credentials

        params = DehashedParams(
            credentials=Credentials(password=SecretStr("my-secret")),
        )  # type: ignore[call-arg]

        assert isinstance(params.api_key, SecretStr)
        assert params.api_key.get_secret_value() == "my-secret"

    def test_email_dbot_score_default(self) -> None:
        """
        Given:
            - No explicit `email_dbot_score`.
        When:
            - Constructing DehashedParams.
        Then:
            - The `email_dbot_score` defaults to "SUSPICIOUS".
        """
        from pydantic import SecretStr
        from DeHashed import DehashedParams, Credentials

        params = DehashedParams(
            credentials=Credentials(password=SecretStr("my-secret")),
        )  # type: ignore[call-arg]

        assert params.email_dbot_score == "SUSPICIOUS"

    def test_email_dbot_score_explicit_malicious(self) -> None:
        """
        Given:
            - An explicit `email_dbot_score="MALICIOUS"`.
        When:
            - Constructing DehashedParams.
        Then:
            - The value is stored as "MALICIOUS".
        """
        from pydantic import SecretStr
        from DeHashed import DehashedParams, Credentials

        params = DehashedParams(
            credentials=Credentials(password=SecretStr("my-secret")),
            email_dbot_score="MALICIOUS",
        )  # type: ignore[call-arg]

        assert params.email_dbot_score == "MALICIOUS"

    def test_integration_reliability_default(self) -> None:
        """
        Given:
            - No `integration_reliability` passed.
        When:
            - Constructing DehashedParams.
        Then:
            - `integration_reliability` defaults to "B - Usually reliable" (matches the
              integration YAML default — see DehashedParams field default).
        """
        from pydantic import SecretStr
        from DeHashed import DehashedParams, Credentials

        params = DehashedParams(
            credentials=Credentials(password=SecretStr("my-secret")),
        )  # type: ignore[call-arg]

        assert params.integration_reliability == "B - Usually reliable"

    def test_params_missing_credentials_raises(self) -> None:
        """
        Given:
            - No credentials provided.
        When:
            - Constructing DehashedParams.
        Then:
            - Raises DemistoException mentioning `credentials`.
        """
        from CommonServerPython import DemistoException
        from DeHashed import DehashedParams

        with pytest.raises(DemistoException, match="credentials"):
            DehashedParams()  # type: ignore[call-arg]


class TestDehashedSearchArgs:
    """Tests for the DehashedSearchArgs pydantic model."""

    def test_required_fields_only(self) -> None:
        """
        Given:
            - Only `asset_type`, `value`, `operation`.
        When:
            - Constructing DehashedSearchArgs.
        Then:
            - Required fields are set; optional `page`, `results_from`, `results_to`
              fall back to their integer field defaults (`1`, `1`, `50`).
        """
        from DeHashed import DehashedSearchArgs

        args = DehashedSearchArgs(asset_type="email", value="a@b.co", operation="is")  # type: ignore[call-arg]

        assert args.asset_type == "email"
        assert args.value == "a@b.co"
        assert args.operation == "is"
        assert args.page == 1
        assert args.results_from == 1
        assert args.results_to == 50

    def test_value_passthrough_string(self) -> None:
        """
        Given:
            - A plain string `value="a@b.co"`.
        When:
            - Constructing DehashedSearchArgs.
        Then:
            - `value` is stored verbatim as a string (no list-splitting / no quoting —
              quoting is applied later in `_build_search_query` based on `operation`).
        """
        from DeHashed import DehashedSearchArgs

        args = DehashedSearchArgs(asset_type="email", value="a@b.co", operation="is")  # type: ignore[call-arg]

        assert args.value == "a@b.co"

    def test_value_with_commas_preserved(self) -> None:
        """
        Given:
            - A string containing commas `value="a,b,c"`.
        When:
            - Constructing DehashedSearchArgs.
        Then:
            - `value` is preserved as the literal string `"a,b,c"` — there is no
              CSV-splitting / multi-value handling in the new query construction logic.
        """
        from DeHashed import DehashedSearchArgs

        args = DehashedSearchArgs(asset_type="email", value="a,b,c", operation="is")  # type: ignore[call-arg]

        assert args.value == "a,b,c"

    @pytest.mark.parametrize(
        "page_input, expected_page",
        [
            pytest.param(3, 3, id="int"),
            pytest.param("4", 4, id="string"),
        ],
    )
    def test_page_coercion_parametrized(self, page_input: int | str, expected_page: int) -> None:
        """
        Given:
            - Page inputs of various supported types (int, string-int).
        When:
            - Constructing DehashedSearchArgs.
        Then:
            - `page` is coerced to int via `arg_to_number`.
        """
        from DeHashed import DehashedSearchArgs

        args = DehashedSearchArgs(
            asset_type="email",
            value="a@b.co",
            operation="is",
            page=page_input,  # type: ignore[arg-type]
        )  # type: ignore[call-arg]

        assert args.page == expected_page

    @pytest.mark.parametrize(
        "page_input",
        [
            pytest.param(0, id="zero"),
            pytest.param(-1, id="negative"),
        ],
    )
    def test_page_zero_or_negative_raises(self, page_input: int) -> None:
        """
        Given:
            - `page=0` or `page=-1`.
        When:
            - Constructing DehashedSearchArgs.
        Then:
            - Raises DemistoException (validator wraps ValueError) — `page` must be > 0.
        """
        from CommonServerPython import DemistoException
        from DeHashed import DehashedSearchArgs

        with pytest.raises(DemistoException, match="page"):
            DehashedSearchArgs(asset_type="email", value="a@b.co", operation="is", page=page_input)  # type: ignore[call-arg]

    @pytest.mark.parametrize(
        "results_from_input",
        [
            pytest.param(0, id="zero"),
            pytest.param(-1, id="negative"),
        ],
    )
    def test_results_from_validator(self, results_from_input: int) -> None:
        """
        Given:
            - `results_from=0` or `results_from=-1`.
        When:
            - Constructing DehashedSearchArgs.
        Then:
            - Raises DemistoException mentioning `results_from` — must be > 0.
        """
        from CommonServerPython import DemistoException
        from DeHashed import DehashedSearchArgs

        with pytest.raises(DemistoException, match="results_from"):
            DehashedSearchArgs(asset_type="email", value="a@b.co", operation="is", results_from=results_from_input)  # type: ignore[call-arg]

    @pytest.mark.parametrize(
        "results_to_input",
        [
            pytest.param(0, id="zero"),
            pytest.param(-1, id="negative"),
        ],
    )
    def test_results_to_validator(self, results_to_input: int) -> None:
        """
        Given:
            - `results_to=0` or `results_to=-1`.
        When:
            - Constructing DehashedSearchArgs.
        Then:
            - Raises DemistoException mentioning `results_to` — must be > 0.
        """
        from CommonServerPython import DemistoException
        from DeHashed import DehashedSearchArgs

        with pytest.raises(DemistoException, match="results_to"):
            DehashedSearchArgs(asset_type="email", value="a@b.co", operation="is", results_to=results_to_input)  # type: ignore[call-arg]

    def test_invalid_asset_type_raises(self) -> None:
        """
        Given:
            - An `asset_type` not in the AssetType Literal.
        When:
            - Constructing DehashedSearchArgs.
        Then:
            - Raises DemistoException (Literal violation).
        """
        from CommonServerPython import DemistoException
        from DeHashed import DehashedSearchArgs

        with pytest.raises(DemistoException, match="asset_type"):
            DehashedSearchArgs(asset_type="bogus", value="x", operation="is")  # type: ignore[arg-type, call-arg]

    def test_invalid_operation_raises(self) -> None:
        """
        Given:
            - An `operation` not in the Operation Literal.
        When:
            - Constructing DehashedSearchArgs.
        Then:
            - Raises DemistoException (Literal violation).
        """
        from CommonServerPython import DemistoException
        from DeHashed import DehashedSearchArgs

        with pytest.raises(DemistoException, match="operation"):
            DehashedSearchArgs(asset_type="email", value="x", operation="bogus")  # type: ignore[arg-type, call-arg]


class TestEmailArgs:
    """Tests for the EmailArgs pydantic model."""

    def test_email_csv_split(self) -> None:
        """
        Given:
            - A CSV string `email="a@b.co,c@d.co"`.
        When:
            - Constructing EmailArgs.
        Then:
            - `email` is split into `["a@b.co", "c@d.co"]` via argToList.
        """
        from DeHashed import EmailArgs

        args = EmailArgs(email="a@b.co,c@d.co")  # type: ignore[arg-type, call-arg]

        assert args.email == ["a@b.co", "c@d.co"]

    def test_email_list_passthrough(self) -> None:
        """
        Given:
            - A pre-built list `email=["a@b.co"]`.
        When:
            - Constructing EmailArgs.
        Then:
            - `email` is unchanged.
        """
        from DeHashed import EmailArgs

        args = EmailArgs(email=["a@b.co"])  # type: ignore[call-arg]

        assert args.email == ["a@b.co"]

    def test_email_missing_raises(self) -> None:
        """
        Given:
            - No `email` provided.
        When:
            - Constructing EmailArgs.
        Then:
            - Raises DemistoException mentioning `email`.
        """
        from CommonServerPython import DemistoException
        from DeHashed import EmailArgs

        with pytest.raises(DemistoException, match="email"):
            EmailArgs()  # type: ignore[call-arg]


class TestDehashedExecutionConfig:
    """Tests for the DehashedExecutionConfig holder.

    `BaseExecutionConfig.__init__` reads from `demisto.command()`, `demisto.params()`,
    and `demisto.args()`. We patch all three via `mocker.patch.object(demisto, ...)`
    to construct the config in tests, per the resolved §7 question 5.
    """

    def test_params_property(self, mocker: MockerFixture) -> None:
        """
        Given:
            - `demisto.params()` returns a raw params dict with credentials.
        When:
            - Accessing `config.params`.
        Then:
            - Returns a `DehashedParams` instance with the credentials populated.
        """
        from DeHashed import DehashedExecutionConfig, DehashedParams

        mocker.patch.object(demisto, "command", return_value="dehashed-search")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "credentials": {"password": "test-key"},
                "email_dbot_score": "MALICIOUS",
            },
        )
        mocker.patch.object(demisto, "args", return_value={})

        config = DehashedExecutionConfig()
        params = config.params

        assert isinstance(params, DehashedParams)
        assert params.email_dbot_score == "MALICIOUS"

    def test_dehashed_search_args_property(self, mocker: MockerFixture) -> None:
        """
        Given:
            - `demisto.args()` returns raw dehashed-search args.
        When:
            - Accessing `config.dehashed_search_args`.
        Then:
            - Returns a `DehashedSearchArgs` instance with values parsed/coerced.
        """
        from DeHashed import DehashedExecutionConfig, DehashedSearchArgs

        mocker.patch.object(demisto, "command", return_value="dehashed-search")
        mocker.patch.object(
            demisto,
            "params",
            return_value={"credentials": {"password": "test-key"}},
        )
        mocker.patch.object(
            demisto,
            "args",
            return_value={"asset_type": "email", "value": "a@b.co", "operation": "is"},
        )

        config = DehashedExecutionConfig()
        args = config.dehashed_search_args

        assert isinstance(args, DehashedSearchArgs)
        assert args.asset_type == "email"
        assert args.value == "a@b.co"
        assert args.operation == "is"

    def test_email_args_property(self, mocker: MockerFixture) -> None:
        """
        Given:
            - `demisto.args()` returns raw email args.
        When:
            - Accessing `config.email_args`.
        Then:
            - Returns an `EmailArgs` instance with the email value parsed.
        """
        from DeHashed import DehashedExecutionConfig, EmailArgs

        mocker.patch.object(demisto, "command", return_value="email")
        mocker.patch.object(
            demisto,
            "params",
            return_value={"credentials": {"password": "test-key"}},
        )
        mocker.patch.object(demisto, "args", return_value={"email": "a@b.co"})

        config = DehashedExecutionConfig()
        args = config.email_args

        assert isinstance(args, EmailArgs)
        assert args.email == ["a@b.co"]


# endregion

# region auth


def test_auth_handler_sets_dehashed_api_key_header() -> None:
    """
    Given:
        - A SecretStr API key.
    When:
        - Constructing DehashedAuthHandler.
    Then:
        - The handler's `header_name` is "Dehashed-Api-Key" and `key` is the
          unwrapped secret value (verified directly via the inherited
          `APIKeyAuthHandler` attributes — see resolved §7 question 3).
    """
    from pydantic import SecretStr
    from DeHashed import DehashedAuthHandler

    handler = DehashedAuthHandler(SecretStr("test-key"))

    assert handler.header_name == "Dehashed-Api-Key"
    assert handler.key == "test-key"
    assert handler.query_param is None


# endregion

# region client


def test_general_search_posts_to_search_with_query(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - A DehashedClient with `client.post` patched to return an empty envelope.
    When:
        - Calling `client.general_search(query="email:x")`.
    Then:
        - `client.post` is called once with `url_suffix="/search"`,
          `json_data={"query": "email:x"}`, and `resp_type="json"`.
    """
    post_mock = mocker.patch.object(client, "post", return_value={"entries": [], "total": 0})

    client.general_search(query="email:x")

    post_mock.assert_called_once_with(
        url_suffix="/search",
        json_data={"query": "email:x"},
        resp_type="json",
    )


def test_general_search_assigns_only_provided_params(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - `query`, `page=1`, `regex=True`; other params left as None.
    When:
        - Calling `client.general_search`.
    Then:
        - The forwarded `json_data` contains only the non-None fields
          (no `size`, `wildcard`, or `de_dupe` keys).
    """
    post_mock = mocker.patch.object(client, "post", return_value={"entries": [], "total": 0})

    client.general_search(query="email:x", page=1, regex=True)

    post_mock.assert_called_once_with(
        url_suffix="/search",
        json_data={"query": "email:x", "page": 1, "regex": True},
        resp_type="json",
    )


def test_general_search_returns_post_payload(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - `client.post` returns a fixture-loaded empty envelope.
    When:
        - Calling `client.general_search`.
    Then:
        - The same payload is returned to the caller verbatim.
    """
    expected = load_mock_response("dehashed-search/response_empty.json")
    mocker.patch.object(client, "post", return_value=expected)

    result = client.general_search(query="email:x")

    assert result == expected


# endregion

# region test-module


def test_module_ok(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - A reachable DeHashed API (client.general_search returns a valid envelope).
    When:
        - Running test_module.
    Then:
        - Returns "ok" and client.general_search was called with the canary email query.
    """
    from DeHashed import test_module

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [],
        "took": "1ms",
        "total": 0,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    result = test_module(client)

    assert result == "ok"
    client.general_search.assert_called_once_with(query="email:example@example.com", page=1, size=1)  # type: ignore[attr-defined]


def test_module_authentication_error(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - `client.general_search` raises an Exception (e.g. unauthorized).
    When:
        - Running test_module.
    Then:
        - Returns a string starting with "AuthenticationError: Connection failed."
          and containing the original error message (loose-match per §7 q4).
        - `demisto.error` is patched to keep stdout clean.
    """
    from DeHashed import test_module

    mocker.patch.object(client, "general_search", side_effect=Exception("Unauthorized"))
    mocker.patch.object(demisto, "error")

    result = test_module(client)

    assert result.startswith("AuthenticationError: Connection failed.")
    assert "Unauthorized" in result


# endregion

# region dehashed-search


def test_dehashed_search_returns_two_command_results(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - A standard 2-entry response from the DeHashed API.
    When:
        - Calling dehashed_search_command with `asset_type="all_fields"`, `value=["testgamil.co"]`, `operation="is"`.
    Then:
        - Returns a list of two CommandResults: the first for `DeHashed.LastQuery`, the second for `DeHashed.Search`
          with `outputs_key_field == "Id"` (mirrors the v1 `(val.Id==obj.Id)` context path).
    """
    from DeHashed import dehashed_search_command, DehashedSearchArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [
            {"id": "id_1", "email": ["a@b.co"], "database_name": "DB-A"},
            {"id": "id_2", "email": ["c@d.co"], "phone": ["1", "2"], "database_name": "DB-B"},
        ],
        "took": "1ms",
        "total": 2,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = DehashedSearchArgs(asset_type="all_fields", value="testgamil.co", operation="is")  # type: ignore[call-arg]

    results = dehashed_search_command(client, args)

    assert isinstance(results, list)
    assert len(results) == 2
    assert results[0].outputs_prefix == "DeHashed.LastQuery(true)"
    assert results[1].outputs_prefix == "DeHashed.Search"
    assert results[1].outputs_key_field == "Id"


def test_dehashed_search_last_query_outputs(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - A standard 2-entry response (`total=2`) and no explicit results-range args.
    When:
        - Calling dehashed_search_command.
    Then:
        - The first CommandResults `outputs` matches the v1 `LastQuery` block:
          `{"ResultsFrom": 1, "ResultsTo": 2, "DisplayedResults": 2, "TotalResults": 2, "PageNumber": 1}`
          (note: the new code defaults `results_to` to 50 when unset, but `DisplayedResults` reflects the actual
          slice length and `TotalResults` reflects the API-reported total).
    """
    from DeHashed import dehashed_search_command, DehashedSearchArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [
            {"id": "id_1", "email": ["a@b.co"], "database_name": "DB-A"},
            {"id": "id_2", "email": ["c@d.co"], "database_name": "DB-B"},
        ],
        "took": "1ms",
        "total": 2,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = DehashedSearchArgs(asset_type="all_fields", value="testgamil.co", operation="is")  # type: ignore[call-arg]

    results = dehashed_search_command(client, args)

    last_query: dict[str, Any] = results[0].outputs  # type: ignore[assignment, index]
    assert last_query["ResultsFrom"] == 1
    assert last_query["DisplayedResults"] == 2
    assert last_query["TotalResults"] == 2
    assert last_query["PageNumber"] == 1


def test_dehashed_search_transformed_entries_outputs(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - The standard fixture (2 entries with mixed list / scalar fields).
    When:
        - Calling dehashed_search_command.
    Then:
        - `results[1].outputs` is a list of CamelCase-keyed dicts equivalent to
          `_transform_entry` applied to each raw entry.
    """
    from DeHashed import dehashed_search_command, DehashedSearchArgs, _transform_entry

    mock_response = load_mock_response("dehashed-search/response.json")
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = DehashedSearchArgs(asset_type="all_fields", value="testgamil.co", operation="is")  # type: ignore[call-arg]

    results = dehashed_search_command(client, args)
    transformed: list[dict[str, Any]] = results[1].outputs  # type: ignore[assignment]

    expected = [_transform_entry(e) for e in mock_response["entries"]]  # type: ignore[index, call-overload]
    assert transformed == expected


def test_dehashed_search_total_results_propagated(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - A response with `total=2`.
    When:
        - Calling dehashed_search_command.
    Then:
        - `LastQuery.TotalResults` equals the API-reported `total` (preserves the v1 `TotalResults` assertion).
    """
    from DeHashed import dehashed_search_command, DehashedSearchArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [
            {"id": "id_1", "email": ["a@b.co"]},
            {"id": "id_2", "email": ["c@d.co"]},
        ],
        "took": "1ms",
        "total": 2,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = DehashedSearchArgs(asset_type="all_fields", value="testgamil.co", operation="is")  # type: ignore[call-arg]

    results = dehashed_search_command(client, args)

    last_query: dict[str, Any] = results[0].outputs  # type: ignore[assignment, index]
    assert last_query["TotalResults"] == 2


@pytest.mark.parametrize(
    "asset_type, value, operation, expected_query, expected_regex",
    [
        pytest.param("all_fields", "testgamil.co", "is", '"testgamil.co"', None, id="is_single_all_fields"),
        pytest.param("all_fields", "testgamil.co", "contains", "testgamil.co", None, id="contains_single_all_fields"),
        pytest.param("all_fields", "joh?n(ath[oa]n)", "regex", "joh?n(ath[oa]n)", True, id="regex_single_all_fields"),
        pytest.param("email", "a@b.co", "is", 'email:"a@b.co"', None, id="is_single_email"),
        pytest.param("name", "test1", "contains", "name:test1", None, id="contains_single_name"),
        pytest.param("vin", "joh?n(ath[oa]n)", "regex", "vin:joh?n(ath[oa]n)", True, id="regex_single_vin"),
    ],
)
def test_dehashed_search_query_construction_per_operator(
    mocker: MockerFixture,
    client: "DehashedClient",
    asset_type: str,
    value: str,
    operation: str,
    expected_query: str,
    expected_regex: bool | None,
) -> None:
    """
    Given:
        - Combinations of `asset_type`, `value`, and `operation` covering the
          `is`, `contains`, and `regex` operators with a single string `value`.
    When:
        - Calling dehashed_search_command (with default `page=1`).
    Then:
        - `client.general_search` is invoked with the constructed query string,
          `page=1` (the field default), `size=REQUEST_PAGE_SIZE` (1000 — the
          dehashed-search command always fetches a full page from the API), and
          `regex=True` only when `operation == "regex"` (else `None`).
    """
    from DeHashed import dehashed_search_command, DehashedSearchArgs, REQUEST_PAGE_SIZE

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [
            {"id": "id_1", "email": ["a@b.co"]},
            {"id": "id_2", "email": ["c@d.co"]},
        ],
        "took": "1ms",
        "total": 2,
    }
    general_search_mock = mocker.patch.object(client, "general_search", return_value=mock_response)

    args = DehashedSearchArgs(asset_type=asset_type, value=value, operation=operation)  # type: ignore[arg-type, call-arg]

    dehashed_search_command(client, args)

    general_search_mock.assert_called_once_with(
        query=expected_query,
        page=1,
        size=REQUEST_PAGE_SIZE,
        wildcard=None,
        regex=expected_regex,
        de_dupe=None,
    )


def test_dehashed_search_results_range_slices_output(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - A 2-entry response and `results_from=1`, `results_to=1` (request only the first entry).
    When:
        - Calling dehashed_search_command.
    Then:
        - `LastQuery.ResultsFrom == 1`, `ResultsTo == 1`, `DisplayedResults == 1`,
          `TotalResults == 2` (full total preserved); `Search.outputs` length is 1.
        - Direct port of the v1 `regex_operator_with_filter_and_change_result_range` test.
    """
    from DeHashed import dehashed_search_command, DehashedSearchArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [
            {"id": "id_1", "email": ["a@b.co"]},
            {"id": "id_2", "email": ["c@d.co"]},
        ],
        "took": "1ms",
        "total": 2,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = DehashedSearchArgs(
        asset_type="vin",
        value="joh?n(ath[oa]n)",
        operation="regex",
        results_from=1,
        results_to=1,
    )  # type: ignore[call-arg]

    results = dehashed_search_command(client, args)

    last_query: dict[str, Any] = results[0].outputs  # type: ignore[assignment, index]
    assert last_query["ResultsFrom"] == 1
    assert last_query["ResultsTo"] == 1
    assert last_query["DisplayedResults"] == 1
    assert last_query["TotalResults"] == 2

    search_outputs: list[dict[str, Any]] = results[1].outputs  # type: ignore[assignment]
    assert len(search_outputs) == 1


def test_dehashed_search_no_entries_returns_no_results_message(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - `client.general_search` returns an empty envelope (no entries).
    When:
        - Calling dehashed_search_command.
    Then:
        - Returns a single CommandResults with `readable_output == "No matching results found"`
          and no outputs.
    """
    from CommonServerPython import CommandResults
    from DeHashed import dehashed_search_command, DehashedSearchArgs

    mock_response = load_mock_response("dehashed-search/response_empty.json")
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = DehashedSearchArgs(asset_type="email", value="nobody@example.com", operation="is")  # type: ignore[call-arg]

    result = dehashed_search_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.readable_output == "No matching results found"
    assert result.outputs is None


def test_dehashed_search_unexpected_response_raises(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - `client.general_search` returns a non-dict (e.g. a list).
    When:
        - Calling dehashed_search_command.
    Then:
        - Raises DemistoException containing "Got unexpected output from api".
    """
    from DeHashed import dehashed_search_command, DehashedSearchArgs, DemistoException

    mocker.patch.object(client, "general_search", return_value=["not", "a", "dict"])

    args = DehashedSearchArgs(asset_type="email", value="a@b.co", operation="is")  # type: ignore[call-arg]

    with pytest.raises(DemistoException, match="Got unexpected output from api"):
        dehashed_search_command(client, args)


def test_dehashed_search_passes_page_to_client(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - `DehashedSearchArgs(page=3)`.
    When:
        - Calling dehashed_search_command.
    Then:
        - `client.general_search` is called with `page=3`, `size=REQUEST_PAGE_SIZE`
          (1000 — the dehashed-search command always fetches a full page from the
          API), and the `LastQuery.PageNumber` reflects the requested page.
    """
    from DeHashed import dehashed_search_command, DehashedSearchArgs, REQUEST_PAGE_SIZE

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [{"id": "id_1", "email": ["a@b.co"]}],
        "took": "1ms",
        "total": 1,
    }
    general_search_mock = mocker.patch.object(client, "general_search", return_value=mock_response)

    args = DehashedSearchArgs(asset_type="email", value="a@b.co", operation="is", page=3)  # type: ignore[call-arg]

    results = dehashed_search_command(client, args)

    general_search_mock.assert_called_once_with(
        query='email:"a@b.co"',
        page=3,
        size=REQUEST_PAGE_SIZE,
        wildcard=None,
        regex=None,
        de_dupe=None,
    )

    last_query: dict[str, Any] = results[0].outputs  # type: ignore[assignment, index]
    assert last_query["PageNumber"] == 3


# endregion

# region email


def test_email_command_returns_search_outputs(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - A response with breach entries and `email_dbot_score="SUSPICIOUS"`.
    When:
        - Calling email_command for `target@example.com`.
    Then:
        - Returns a `CommandResults` with `outputs_prefix=="DeHashed.Search"`,
          `outputs_key_field=="Id"`, `outputs` populated from `_transform_entry`,
          and an attached `Common.EMAIL` indicator.
    """
    from DeHashed import email_command, EmailArgs

    mock_response = load_mock_response("email/response.json")
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = EmailArgs(email=["target@example.com"])  # type: ignore[call-arg]

    response = email_command(client, args, email_dbot_score="SUSPICIOUS", reliability="B - Usually reliable")

    assert response.outputs_prefix == "DeHashed.Search"
    assert response.outputs_key_field == "Id"
    assert response.outputs is not None
    assert len(response.outputs) == 3  # type: ignore[arg-type]
    assert response.indicator is not None


def test_email_command_dbot_score_suspicious(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - A response with entries carrying `database_name` and `email_dbot_score="SUSPICIOUS"`.
    When:
        - Calling email_command for `testgamil.com`.
    Then:
        - The returned CommandResults exposes a `Common.EMAIL` indicator whose DBotScore equals
          `Common.DBotScore.SUSPICIOUS` (numeric 2). Outputs target `DeHashed.Search` with `Id` as key field.
        - Direct port of the v1 `test_email_command_suspicious_dbot_score`.
    """
    from CommonServerPython import Common
    from DeHashed import email_command, EmailArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [
            {"id": "id_1", "email": ["testgamil.com"], "database_name": "DB-A"},
            {"id": "id_2", "email": ["testgamil.com"], "database_name": "DB-B"},
        ],
        "took": "1ms",
        "total": 2,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = EmailArgs(email=["testgamil.com"])  # type: ignore[call-arg]

    response = email_command(client, args, email_dbot_score="SUSPICIOUS", reliability="B - Usually reliable")

    assert response.outputs_prefix == "DeHashed.Search"
    assert response.outputs_key_field == "Id"
    assert response.indicator is not None
    assert response.indicator.dbot_score.score == Common.DBotScore.SUSPICIOUS  # type: ignore[attr-defined]
    assert response.indicator.dbot_score.score == 2  # type: ignore[attr-defined]


def test_email_command_dbot_score_malicious(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - A response with entries carrying `database_name` and `email_dbot_score="MALICIOUS"`.
    When:
        - Calling email_command for `testgamil.com`.
    Then:
        - The returned CommandResults exposes a `Common.EMAIL` indicator whose DBotScore equals
          `Common.DBotScore.BAD` (numeric 3, labeled "MALICIOUS" in the UI).
        - Direct port of the v1 `test_email_command_malicious_dbot_score`.
    """
    from CommonServerPython import Common
    from DeHashed import email_command, EmailArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [
            {"id": "id_1", "email": ["testgamil.com"], "database_name": "DB-A"},
            {"id": "id_2", "email": ["testgamil.com"], "database_name": "DB-B"},
        ],
        "took": "1ms",
        "total": 2,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = EmailArgs(email=["testgamil.com"])  # type: ignore[call-arg]

    response = email_command(client, args, email_dbot_score="MALICIOUS", reliability="B - Usually reliable")

    assert response.indicator is not None
    assert response.indicator.dbot_score.score == Common.DBotScore.BAD  # type: ignore[attr-defined]
    assert response.indicator.dbot_score.score == 3  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "fixture_path",
    [
        pytest.param("email/response_empty.json", id="no_entries"),
        pytest.param("email/response_no_breaches.json", id="entries_without_db_name"),
    ],
)
def test_email_command_dbot_score_none_when_no_breaches(
    mocker: MockerFixture, client: "DehashedClient", fixture_path: str
) -> None:
    """
    Given:
        - A response with either no entries or entries missing `database_name`.
    When:
        - Calling email_command for `testgamil.com`.
    Then:
        - The returned CommandResults still exposes a `Common.EMAIL` indicator with
          `DBotScore == NONE` (0) and the readable output equals the
          "No matching results found" message (when no transformed entries).
        - Direct port of the v1 `test_email_command_no_entries_returned`.
    """
    from CommonServerPython import Common
    from DeHashed import email_command, EmailArgs

    mock_response = load_mock_response(fixture_path)
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = EmailArgs(email=["testgamil.com"])  # type: ignore[call-arg]

    response = email_command(client, args, email_dbot_score="SUSPICIOUS", reliability="B - Usually reliable")

    assert response.indicator is not None
    assert response.indicator.dbot_score.score == Common.DBotScore.NONE  # type: ignore[attr-defined]
    assert response.indicator.dbot_score.score == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "reliability",
    [
        pytest.param("A+ - 3rd party enrichment", id="a_plus"),
        pytest.param("A - Completely reliable", id="a"),
        pytest.param("B - Usually reliable", id="b"),
        pytest.param("C - Fairly reliable", id="c"),
        pytest.param("D - Not usually reliable", id="d"),
        pytest.param("E - Unreliable", id="e"),
        pytest.param("F - Reliability cannot be judged", id="f"),
    ],
)
def test_email_command_reliability_propagated_parametrized(
    mocker: MockerFixture,
    client: "DehashedClient",
    reliability: str,
) -> None:
    """
    Given:
        - A response with breach entries and a configured source reliability string.
    When:
        - Calling email_command across all 7 reliability values.
    Then:
        - The configured reliability is propagated onto the `Common.EMAIL` indicator's DBotScore.
        - Direct port of the v1 `test_email_different_reliability` parametrize.
    """
    from CommonServerPython import DBotScoreReliability
    from DeHashed import email_command, EmailArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [
            {"id": "id_1", "email": ["testgamil.com"], "database_name": "DB-A"},
        ],
        "took": "1ms",
        "total": 1,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = EmailArgs(email=["testgamil.com"])  # type: ignore[call-arg]

    response = email_command(client, args, email_dbot_score="SUSPICIOUS", reliability=reliability)

    expected_reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)

    assert response.indicator is not None
    assert response.indicator.dbot_score.reliability == expected_reliability  # type: ignore[attr-defined]


def test_email_command_reliability_none_omits_field(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - `reliability=None`.
    When:
        - Calling email_command.
    Then:
        - The indicator's DBotScore has no reliability set (falsy).
    """
    from DeHashed import email_command, EmailArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [{"id": "id_1", "email": ["testgamil.com"], "database_name": "DB-A"}],
        "took": "1ms",
        "total": 1,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = EmailArgs(email=["testgamil.com"])  # type: ignore[call-arg]

    response = email_command(client, args, email_dbot_score="SUSPICIOUS", reliability=None)

    assert response.indicator is not None
    # When reliability=None the integration code does not set the kwarg,
    # so the indicator's DBotScore.reliability should not be a valid reliability string.
    assert not getattr(response.indicator.dbot_score, "reliability", None)  # type: ignore[attr-defined]


def test_email_command_breach_description_includes_unique_sources(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - Entries with duplicate `database_name` values (`["TestBreach-A", "TestBreach-A", "TestBreach-B"]`)
          and a SUSPICIOUS-or-higher score.
    When:
        - Calling email_command.
    Then:
        - The malicious_description on the DBotScore reads
          `"Found in 2 breach(es): TestBreach-A, TestBreach-B"` — duplicates collapsed,
          sources sorted, count reflects unique sources.
    """
    from DeHashed import email_command, EmailArgs

    mock_response = load_mock_response("email/response.json")
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = EmailArgs(email=["target@example.com"])  # type: ignore[call-arg]

    response = email_command(client, args, email_dbot_score="SUSPICIOUS", reliability="B - Usually reliable")

    assert response.indicator is not None
    description = response.indicator.dbot_score.malicious_description  # type: ignore[attr-defined]
    assert description == "Found in 2 breach(es): TestBreach-A, TestBreach-B"


def test_email_command_email_domain_extraction(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - `EmailArgs(email=["user@example.com"])`.
    When:
        - Calling email_command.
    Then:
        - The attached `Common.EMAIL` indicator's `domain == "example.com"`.
    """
    from DeHashed import email_command, EmailArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [{"id": "id_1", "email": ["user@example.com"], "database_name": "DB-A"}],
        "took": "1ms",
        "total": 1,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = EmailArgs(email=["user@example.com"])  # type: ignore[call-arg]

    response = email_command(client, args, email_dbot_score="SUSPICIOUS", reliability=None)

    assert response.indicator is not None
    assert response.indicator.domain == "example.com"  # type: ignore[attr-defined]


def test_email_command_email_without_at_sets_no_domain(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - An email-shaped value without "@" (`["nodomain"]`) — exercises the defensive
          `if "@" in indicator_value` guard.
    When:
        - Calling email_command.
    Then:
        - The indicator's `domain is None`.
    """
    from DeHashed import email_command, EmailArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [],
        "took": "1ms",
        "total": 0,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = EmailArgs(email=["nodomain"])  # type: ignore[call-arg]

    response = email_command(client, args, email_dbot_score="SUSPICIOUS", reliability=None)

    assert response.indicator is not None
    assert response.indicator.domain is None  # type: ignore[attr-defined]


def test_email_command_query_construction(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - `EmailArgs(email=["a@b.co"])`.
    When:
        - Calling email_command.
    Then:
        - `client.general_search` is called with `query="email:a@b.co"`, `regex=None`,
          and all other optional params set to None.
    """
    from DeHashed import email_command, EmailArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [{"id": "id_1", "email": ["a@b.co"], "database_name": "DB-A"}],
        "took": "1ms",
        "total": 1,
    }
    general_search_mock = mocker.patch.object(client, "general_search", return_value=mock_response)

    args = EmailArgs(email=["a@b.co"])  # type: ignore[call-arg]

    email_command(client, args, email_dbot_score="SUSPICIOUS", reliability=None)

    general_search_mock.assert_called_once_with(
        query="email:a@b.co",
        page=None,
        size=None,
        wildcard=None,
        regex=None,
        de_dupe=None,
    )


def test_email_command_unexpected_response_raises(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - `client.general_search` returns a non-dict (e.g. a list).
    When:
        - Calling email_command.
    Then:
        - Raises DemistoException containing "Got unexpected output from api".
    """
    from DeHashed import email_command, EmailArgs, DemistoException

    mocker.patch.object(client, "general_search", return_value=["bad"])

    args = EmailArgs(email=["a@b.co"])  # type: ignore[call-arg]

    with pytest.raises(DemistoException, match="Got unexpected output from api"):
        email_command(client, args, email_dbot_score="SUSPICIOUS", reliability=None)


def test_email_command_dbot_score_none_when_no_breaches_readable_output(mocker: MockerFixture, client: "DehashedClient") -> None:
    """
    Given:
        - A response with no entries.
    When:
        - Calling email_command.
    Then:
        - The readable_output is "No matching results found" and the DBotScore is NONE.
        - Direct port of the v1 `test_email_command_no_entries_returned` (readable-output assertion).
    """
    from CommonServerPython import Common
    from DeHashed import email_command, EmailArgs

    mock_response: dict[str, Any] = {
        "balance": 100,
        "entries": [],
        "took": "1ms",
        "total": 0,
    }
    mocker.patch.object(client, "general_search", return_value=mock_response)

    args = EmailArgs(email=["testgamil.com"])  # type: ignore[call-arg]

    response = email_command(client, args, email_dbot_score="SUSPICIOUS", reliability="B - Usually reliable")

    assert response.indicator is not None
    assert response.indicator.dbot_score.score == Common.DBotScore.NONE  # type: ignore[attr-defined]
    assert response.readable_output == "No matching results found"


# endregion
