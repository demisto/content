import pytest
from pytest_mock import MockerFixture
import json
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from MagnetAutomate import MagnetAutomateClient


def load_mock_response(file_name: str) -> dict:
    """
    Helper function to load mock response data from a JSON file.

    Args:
        file_name (str): The name of the JSON file to load from the test_data directory.

    Returns:
        dict: The parsed JSON content as a dictionary.
    """
    with open(f"test_data/{file_name}") as f:
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
def client() -> "MagnetAutomateClient":
    """
    Pytest fixture that initializes and returns a MagnetAutomateClient instance for testing.

    Returns:
        MagnetAutomateClient: An instance of the Magnet Automate API client.
    """
    from pydantic import SecretStr
    from MagnetAutomate import MagnetAutomateClient, MagnetAutomateParams, Credentials

    params = MagnetAutomateParams(
        url="https://test.com",  # type: ignore[arg-type]
        credentials=Credentials(password=SecretStr("test-key")),
    )
    return MagnetAutomateClient(params)


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
    from MagnetAutomate import truncate_results

    assert truncate_results(results, limit, all_results) == expected


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
        from MagnetAutomate import Credentials

        creds = Credentials(password=password)  # type: ignore[arg-type]

        assert isinstance(creds.password, SecretStr)
        assert creds.password.get_secret_value() == password

    def test_credentials_missing_password(self):
        """
        Given:
            - No password provided.
        When:
            - Initializing Credentials model.
        Then:
            - Assert DemistoException is raised.
        """
        from CommonServerPython import DemistoException
        from MagnetAutomate import Credentials

        with pytest.raises(DemistoException, match="password"):
            Credentials()  # type: ignore[call-arg]


class TestMagnetAutomateParams:
    """Tests for the MagnetAutomateParams pydantic model."""

    def test_api_key_property_returns_credentials_password(self) -> None:
        """
        Given:
            - Valid URL and credentials.
        When:
            - Constructing MagnetAutomateParams and accessing api_key.
        Then:
            - api_key returns the SecretStr password from credentials.
        """
        from pydantic import SecretStr
        from MagnetAutomate import MagnetAutomateParams, Credentials

        params = MagnetAutomateParams(
            url="https://example.com",  # type: ignore[arg-type]
            credentials=Credentials(password=SecretStr("api-key-value")),
        )

        assert isinstance(params.api_key, SecretStr)
        assert params.api_key.get_secret_value() == "api-key-value"

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
            - MagnetAutomateParams with various insecure values.
        When:
            - Accessing the verify property.
        Then:
            - verify is the logical inverse of insecure.
        """
        from pydantic import SecretStr
        from MagnetAutomate import MagnetAutomateParams, Credentials

        params = MagnetAutomateParams(
            url="https://example.com",  # type: ignore[arg-type]
            credentials=Credentials(password=SecretStr("key")),
            insecure=insecure,
        )

        assert params.verify is expected_verify

    def test_url_accepted(self) -> None:
        """
        Given:
            - A valid URL string.
        When:
            - Constructing MagnetAutomateParams.
        Then:
            - The url field is set and contains the expected host.
        """
        from urllib.parse import urlparse
        from pydantic import SecretStr
        from MagnetAutomate import MagnetAutomateParams, Credentials

        params = MagnetAutomateParams(
            url="https://automate.example.com",  # type: ignore[arg-type]
            credentials=Credentials(password=SecretStr("key")),
        )

        assert urlparse(str(params.url)).hostname == "automate.example.com"

    def test_params_missing_url(self):
        """
        Given:
            - No URL provided.
        When:
            - Initializing MagnetAutomateParams.
        Then:
            - Assert DemistoException is raised.
        """
        from CommonServerPython import DemistoException
        from MagnetAutomate import MagnetAutomateParams

        with pytest.raises(DemistoException, match="url"):
            MagnetAutomateParams(credentials={"password": "secret"})  # type: ignore[call-arg]

    def test_params_missing_credentials(self):
        """
        Given:
            - No credentials provided.
        When:
            - Initializing MagnetAutomateParams.
        Then:
            - Assert DemistoException is raised.
        """
        from CommonServerPython import DemistoException
        from MagnetAutomate import MagnetAutomateParams

        with pytest.raises(DemistoException, match="credentials"):
            MagnetAutomateParams(url="https://automate.example.com")  # type: ignore[call-arg,arg-type]


# endregion


# region test-module


def test_module_authentication_error(mocker: MockerFixture, client: "MagnetAutomateClient"):
    """
    Given:
        - Client that raises ContentClientAuthenticationError.
    When:
        - Running test_module.
    Then:
        - Assert appropriate error message is returned.
    """
    from ContentClientApiModule import ContentClientAuthenticationError
    from MagnetAutomate import test_module

    mocker.patch.object(client, "custom_fields_list", side_effect=ContentClientAuthenticationError("Unauthorized"))

    result = test_module(client)

    assert result.startswith("AuthenticationError: Connection failed.")
    assert "Unauthorized" in result


# endregion


# region mf-automate-custom-fields-list


class TestCustomFieldsListArgs:
    """Tests for the CustomFieldsListArgs pydantic model."""

    def test_defaults(self) -> None:
        """
        Given:
            - No arguments provided.
        When:
            - Constructing CustomFieldsListArgs with defaults.
        Then:
            - limit defaults to 50 and all_results defaults to False.
        """
        from MagnetAutomate import CustomFieldsListArgs

        args = CustomFieldsListArgs()  # type: ignore[arg-type]

        assert args.limit == 50
        assert args.all_results is False

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
            - Constructing CustomFieldsListArgs.
        Then:
            - limit is coerced to int via arg_to_number or left as None.
        """
        from MagnetAutomate import CustomFieldsListArgs

        args = CustomFieldsListArgs(limit=limit_input, all_results=False)  # type: ignore[arg-type]

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
            - Constructing CustomFieldsListArgs.
        Then:
            - all_results is coerced to bool via argToBoolean.
        """
        from MagnetAutomate import CustomFieldsListArgs

        args = CustomFieldsListArgs(limit=50, all_results=all_results_input)  # type: ignore[arg-type]

        assert args.all_results is expected


def test_custom_fields_list_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A workflow ID.
    When:
        - Calling the custom_fields_list_command.
    Then:
        - Assert the client's custom_fields_list method is called.
        - Assert the response is correctly processed into CommandResults with expected outputs and prefix.
    """
    from MagnetAutomate import custom_fields_list_command, CustomFieldsListArgs

    mock_response = load_mock_response("custom_fields_list.json")
    mocker.patch.object(client, "custom_fields_list", return_value=mock_response)

    args = CustomFieldsListArgs(limit=None, all_results=False)

    response = custom_fields_list_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.CustomFields"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 2
    assert outputs[0].get("id") == 0
    assert outputs[1].get("id") == 1
    assert "Custom Fields" in response.readable_output


# endregion

# region mf-automate-case-create


class TestCaseCreateArgs:
    """Tests for the CaseCreateArgs pydantic model."""

    def test_happy_path_with_dict(self) -> None:
        """
        Given:
            - A case number string and a dict of custom field values.
        When:
            - Constructing CaseCreateArgs.
        Then:
            - case_number and custom_field_values are set correctly.
        """
        from MagnetAutomate import CaseCreateArgs

        args = CaseCreateArgs(case_number="CASE-001", custom_field_values={"field1": "value1"})

        assert args.case_number == "CASE-001"
        assert args.custom_field_values == {"field1": "value1"}

    def test_custom_field_values_defaults_to_none(self) -> None:
        """
        Given:
            - Only case_number provided.
        When:
            - Constructing CaseCreateArgs.
        Then:
            - custom_field_values defaults to None.
        """
        from MagnetAutomate import CaseCreateArgs

        args = CaseCreateArgs(case_number="CASE-003")  # type: ignore[arg-type]

        assert args.custom_field_values is None

    @pytest.mark.parametrize(
        "cfv_input, expected",
        [
            pytest.param('{"key": "val", "num": 42}', {"key": "val", "num": 42}, id="json_string_parsed"),
            pytest.param({"a": 1, "b": "two"}, {"a": 1, "b": "two"}, id="dict_passthrough"),
        ],
    )
    def test_custom_field_values_coercion(self, cfv_input: str | dict, expected: dict) -> None:
        """
        Given:
            - custom_field_values as a JSON string or dict.
        When:
            - Constructing CaseCreateArgs.
        Then:
            - custom_field_values is parsed from JSON string or passed through as dict.
        """
        from MagnetAutomate import CaseCreateArgs

        args = CaseCreateArgs(case_number="CASE-002", custom_field_values=cfv_input)  # type: ignore[arg-type]

        assert args.custom_field_values == expected


def test_case_create_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - Case creation arguments including case number and custom field values.
    When:
        - Calling the case_create_command.
    Then:
        - Assert the client's case_create method is called with the provided arguments.
        - Assert the response is correctly processed into CommandResults with expected case details.
    """
    from MagnetAutomate import case_create_command, CaseCreateArgs

    mock_response = load_mock_response("case_create.json")
    mocker.patch.object(client, "case_create", return_value=mock_response)

    args = CaseCreateArgs(case_number="CASE-001", custom_field_values={"field1": "value1", "field2": 2})

    response = case_create_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.Case"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore

    assert outputs.get("id") == 10
    assert outputs.get("caseNumber") == "CASE-001"
    assert "Case Created" in response.readable_output


# endregion

# region mf-automate-cases-list


class TestCasesListArgs:
    """Tests for the CasesListArgs pydantic model."""

    def test_defaults(self) -> None:
        """
        Given:
            - Only required fields provided.
        When:
            - Constructing CasesListArgs with defaults.
        Then:
            - limit defaults to 50, all_results defaults to False, case_id defaults to None.
        """
        from MagnetAutomate import CasesListArgs

        args = CasesListArgs(case_id=1)  # type: ignore[arg-type]

        assert args.limit == 50
        assert args.all_results is False

    @pytest.mark.parametrize(
        "case_id_input, expected",
        [
            pytest.param(None, None, id="none"),
            pytest.param(5, 5, id="int"),
            pytest.param("10", 10, id="string_coerced"),
        ],
    )
    def test_case_id_coercion(self, case_id_input: int | str | None, expected: int | None) -> None:
        """
        Given:
            - Various case_id inputs.
        When:
            - Constructing CasesListArgs.
        Then:
            - case_id is coerced to int or left as None.
        """
        from MagnetAutomate import CasesListArgs

        args = CasesListArgs(case_id=case_id_input, limit=50, all_results=False)  # type: ignore[arg-type]

        assert args.case_id == expected

    def test_all_results_string_coercion(self) -> None:
        """
        Given:
            - all_results as string "true".
        When:
            - Constructing CasesListArgs.
        Then:
            - all_results is coerced to True.
        """
        from MagnetAutomate import CasesListArgs

        args = CasesListArgs(case_id=None, limit=None, all_results="true")  # type: ignore[arg-type]

        assert args.all_results is True


def test_cases_list_command_all(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - No specific case ID (requesting all cases).
    When:
        - Calling the cases_list_command.
    Then:
        - Assert the client's cases_list method is called.
        - Assert the response is correctly processed into CommandResults containing a list of cases.
    """
    from MagnetAutomate import cases_list_command, CasesListArgs

    mock_response = load_mock_response("cases_list.json")
    mocker.patch.object(client, "cases_list", return_value=mock_response)

    args = CasesListArgs(case_id=None, limit=None, all_results=False)

    response = cases_list_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.Case"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 2
    assert outputs[0].get("id") == 1
    assert outputs[1].get("id") == 2
    assert "Cases List" in response.readable_output


def test_cases_list_command_single(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A specific case ID.
    When:
        - Calling the cases_list_command.
    Then:
        - Assert the client's cases_list method is called for the specific case.
        - Assert the response is correctly processed into CommandResults with detailed case information.
    """
    from MagnetAutomate import cases_list_command, CasesListArgs

    mock_response = load_mock_response("case_get.json")
    mocker.patch.object(client, "cases_list", return_value=mock_response)

    args = CasesListArgs(case_id=1, limit=None, all_results=False)

    response = cases_list_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.Case"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore

    assert outputs.get("id") == 10
    assert outputs.get("caseNumber") == "CASE-001"
    assert "Case 1 Details" in response.readable_output


# endregion

# region mf-automate-case-delete


class TestCaseDeleteArgs:
    """Tests for the CaseDeleteArgs pydantic model."""

    @pytest.mark.parametrize(
        "case_id_input, expected",
        [
            pytest.param(123, 123, id="int"),
            pytest.param("456", 456, id="string_coerced"),
        ],
    )
    def test_case_id_coercion(self, case_id_input: int | str, expected: int) -> None:
        """
        Given:
            - case_id as int or string.
        When:
            - Constructing CaseDeleteArgs.
        Then:
            - case_id is set or coerced to int correctly.
        """
        from MagnetAutomate import CaseDeleteArgs

        args = CaseDeleteArgs(case_id=case_id_input)  # type: ignore[arg-type]

        assert args.case_id == expected


def test_case_delete_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID to delete.
    When:
        - Calling the case_delete_command.
    Then:
        - Assert the client's case_delete method is called with the correct case ID.
        - Assert the readable output indicates successful deletion.
    """
    from MagnetAutomate import case_delete_command, CaseDeleteArgs

    mocker.patch.object(client, "case_delete", return_value=None)

    args = CaseDeleteArgs(case_id=123)

    response = case_delete_command(client, args)

    assert response.readable_output == "Case 123 deleted successfully"
    client.case_delete.assert_called_once_with(case_id=123)  # type: ignore


# endregion

# region mf-automate-case-cancel


class TestCaseCancelArgs:
    """Tests for the CaseCancelArgs pydantic model."""

    @pytest.mark.parametrize(
        "case_id_input, expected",
        [
            pytest.param(789, 789, id="int"),
            pytest.param("99", 99, id="string_coerced"),
        ],
    )
    def test_case_id_coercion(self, case_id_input: int | str, expected: int) -> None:
        """
        Given:
            - case_id as int or string.
        When:
            - Constructing CaseCancelArgs.
        Then:
            - case_id is set or coerced to int correctly.
        """
        from MagnetAutomate import CaseCancelArgs

        args = CaseCancelArgs(case_id=case_id_input)  # type: ignore[arg-type]

        assert args.case_id == expected


def test_case_cancel_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID to cancel.
    When:
        - Calling the case_cancel_command.
    Then:
        - Assert the client's case_cancel method is called with the correct case ID.
        - Assert the readable output indicates successful cancellation.
    """
    from MagnetAutomate import case_cancel_command, CaseCancelArgs

    mocker.patch.object(client, "case_cancel", return_value=None)

    args = CaseCancelArgs(case_id=123)

    response = case_cancel_command(client, args)

    assert response.readable_output == "Case 123 cancelled successfully"
    client.case_cancel.assert_called_once_with(case_id=123)  # type: ignore


# endregion

# region mf-automate-workflow-run-start


class TestWorkflowRunStartArgs:
    """Tests for the WorkflowRunStartArgs pydantic model."""

    def test_happy_path_required_fields(self) -> None:
        """
        Given:
            - All required fields with valid values.
        When:
            - Constructing WorkflowRunStartArgs.
        Then:
            - All fields are set correctly.
        """
        from MagnetAutomate import WorkflowRunStartArgs

        args = WorkflowRunStartArgs(  # type: ignore[arg-type]
            case_id=10,
            evidence_number="ExhibitA",
            type={"ImageSource": {"path": "C:\\image.001"}},
            workflow_id=3,
        )

        assert args.case_id == 10
        assert args.evidence_number == "ExhibitA"
        assert args.evidence_type == {"ImageSource": {"path": "C:\\image.001"}}
        assert args.workflow_id == 3

    def test_evidence_type_set_via_alias(self) -> None:
        """
        Given:
            - evidence_type set via its alias 'type'.
        When:
            - Constructing WorkflowRunStartArgs.
        Then:
            - evidence_type field is populated correctly via the alias.
        """
        from MagnetAutomate import WorkflowRunStartArgs

        evidence = {"ImageSource": {"path": "/data/image.e01"}}
        args = WorkflowRunStartArgs(  # type: ignore[arg-type]
            case_id=1,
            evidence_number="E001",
            type=evidence,
            workflow_id=5,
        )

        assert args.evidence_type == evidence

    @pytest.mark.parametrize(
        "evidence_input, expected",
        [
            pytest.param(
                '{"ImageSource": {"path": "/some/path"}}',
                {"ImageSource": {"path": "/some/path"}},
                id="json_string_parsed",
            ),
            pytest.param(
                '{"ImageSource": {"path": "C:\\\\testdata\\\\image\\\\image123.001"}}',
                {"ImageSource": {"path": "C:\\testdata\\image\\image123.001"}},
                id="json_string_with_backslashes_parsed",
            ),
            pytest.param(
                {"ImageSource": {"path": "C:\\image.001"}},
                {"ImageSource": {"path": "C:\\image.001"}},
                id="dict_passthrough",
            ),
        ],
    )
    def test_evidence_type_coercion(self, evidence_input: str | dict, expected: dict) -> None:
        """
        Given:
            - evidence_type as a JSON string or dict.
        When:
            - Constructing WorkflowRunStartArgs.
        Then:
            - evidence_type is parsed from JSON string or passed through as dict.
        """
        from MagnetAutomate import WorkflowRunStartArgs

        args = WorkflowRunStartArgs(  # type: ignore[arg-type]
            case_id=1,
            evidence_number="E001",
            type=evidence_input,
            workflow_id=2,
        )

        assert args.evidence_type == expected

    def test_evidence_type_invalid_json_raises(self) -> None:
        """
        Given:
            - evidence_type as an invalid JSON string.
        When:
            - Constructing WorkflowRunStartArgs.
        Then:
            - The validator returns the original string (validate_json does not raise),
              but ContentBaseModel raises a DemistoException because evidence_type expects dict[str, Any].
        """
        from CommonServerPython import DemistoException
        from MagnetAutomate import WorkflowRunStartArgs

        with pytest.raises(DemistoException, match="type"):
            WorkflowRunStartArgs(  # type: ignore[arg-type]
                case_id=1,
                evidence_number="E001",
                type="not-valid-json{",
                workflow_id=2,
            )

    def test_evidence_type_empty_string_passthrough(self) -> None:
        """
        Given:
            - evidence_type as an empty string.
        When:
            - Constructing WorkflowRunStartArgs.
        Then:
            - validate_json returns the empty string unchanged (empty string is falsy,
              so the JSON parsing branch is skipped).
        """
        from MagnetAutomate import validate_json

        result = validate_json("")
        assert result == ""

    @pytest.mark.parametrize(
        "case_id_input, workflow_id_input, expected_case_id, expected_workflow_id",
        [
            pytest.param("42", "7", 42, 7, id="both_strings_coerced"),
            pytest.param(10, 3, 10, 3, id="both_ints"),
        ],
    )
    def test_numeric_field_coercions(
        self,
        case_id_input: int | str,
        workflow_id_input: int | str,
        expected_case_id: int,
        expected_workflow_id: int,
    ) -> None:
        """
        Given:
            - case_id and workflow_id as strings or ints.
        When:
            - Constructing WorkflowRunStartArgs.
        Then:
            - Both are coerced to int via arg_to_number.
        """
        from MagnetAutomate import WorkflowRunStartArgs

        args = WorkflowRunStartArgs(  # type: ignore[arg-type]
            case_id=case_id_input,
            evidence_number="E001",
            type={"ImageSource": {}},
            workflow_id=workflow_id_input,
        )

        assert args.case_id == expected_case_id
        assert args.workflow_id == expected_workflow_id

    def test_decryption_value_stored_as_secret_str(self) -> None:
        """
        Given:
            - decryption_value as a SecretStr.
        When:
            - Constructing WorkflowRunStartArgs.
        Then:
            - decryption_value is stored as SecretStr and accessible via get_secret_value().
        """
        from pydantic import SecretStr
        from MagnetAutomate import WorkflowRunStartArgs

        args = WorkflowRunStartArgs(  # type: ignore[arg-type]
            case_id=1,
            evidence_number="E001",
            type={"ImageSource": {}},
            workflow_id=2,
            decryption_value=SecretStr("MyPassword"),
        )

        assert isinstance(args.decryption_value, SecretStr)
        assert args.decryption_value.get_secret_value() == "MyPassword"

    @pytest.mark.parametrize(
        "codf_input, expected",
        [
            pytest.param(None, None, id="none"),
            pytest.param("true", True, id="string_true"),
            pytest.param("false", False, id="string_false"),
            pytest.param(True, True, id="bool_true"),
            pytest.param(False, False, id="bool_false"),
        ],
    )
    def test_continue_on_decryption_fail_coercion(self, codf_input: bool | str | None, expected: bool | None) -> None:
        """
        Given:
            - Various continue_on_decryption_fail inputs.
        When:
            - Constructing WorkflowRunStartArgs.
        Then:
            - continue_on_decryption_fail is coerced via arg_to_bool_or_none.
        """
        from MagnetAutomate import WorkflowRunStartArgs

        args = WorkflowRunStartArgs(  # type: ignore[arg-type]
            case_id=1,
            evidence_number="E001",
            type={"ImageSource": {}},
            workflow_id=2,
            continue_on_decryption_fail=codf_input,
        )

        assert args.continue_on_decryption_fail is expected

    @pytest.mark.parametrize(
        "cfv_input, expected",
        [
            pytest.param('{"5": "Evidence Value A"}', {"5": "Evidence Value A"}, id="json_string_parsed"),
            pytest.param({"key": "val"}, {"key": "val"}, id="dict_passthrough"),
        ],
    )
    def test_custom_field_values_coercion(self, cfv_input: str | dict, expected: dict) -> None:
        """
        Given:
            - custom_field_values as a JSON string or dict.
        When:
            - Constructing WorkflowRunStartArgs.
        Then:
            - custom_field_values is parsed from JSON string or passed through as dict.
        """
        from MagnetAutomate import WorkflowRunStartArgs

        args = WorkflowRunStartArgs(  # type: ignore[arg-type]
            case_id=1,
            evidence_number="E001",
            type={"ImageSource": {}},
            workflow_id=2,
            custom_field_values=cfv_input,
        )

        assert args.custom_field_values == expected

    def test_optional_fields_default_to_none(self) -> None:
        """
        Given:
            - Only required fields provided.
        When:
            - Constructing WorkflowRunStartArgs.
        Then:
            - All optional fields default to None.
        """
        from MagnetAutomate import WorkflowRunStartArgs

        args = WorkflowRunStartArgs(  # type: ignore[arg-type]
            case_id=1,
            evidence_number="E001",
            type={"ImageSource": {}},
            workflow_id=2,
        )

        assert args.output_path is None
        assert args.platform is None
        assert args.decryption_type is None
        assert args.decryption_value is None
        assert args.continue_on_decryption_fail is None
        assert args.custom_field_values is None
        assert args.assigned_node_name is None


def test_workflow_run_start_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - Workflow run arguments including case ID, evidence details, and decryption parameters.
    When:
        - Calling the workflow_run_start_command.
    Then:
        - Assert the client's workflow_run_start method is called with all provided arguments.
        - Assert the response is correctly processed into CommandResults with expected workflow run details.
    """
    from pydantic import SecretStr
    from MagnetAutomate import workflow_run_start_command, WorkflowRunStartArgs

    mock_response = load_mock_response("workflow_run_start.json")
    mocker.patch.object(client, "workflow_run_start", return_value=mock_response)

    args = WorkflowRunStartArgs(
        case_id=10,
        evidence_number="ExhibitA",
        type={"ImageSource": {"path": "C:\\testdata\\image\\image123.001"}},
        workflow_id=3,
        output_path="C:\\testdata\\output",
        platform="windows",
        decryption_type="password",
        decryption_value=SecretStr("MySecretPassword"),
        continue_on_decryption_fail=False,
        custom_field_values={"5": "Evidence Value A"},
        assigned_node_name="AGENT1",
    )

    response = workflow_run_start_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.WorkflowRun"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 1
    assert outputs[0].get("id") == 11
    assert outputs[0].get("caseId") == 10
    assert "Workflow Run Started" in response.readable_output

    client.workflow_run_start.assert_called_once_with(  # type: ignore
        case_id=10,
        evidence_number="ExhibitA",
        evidence_type={"ImageSource": {"path": "C:\\testdata\\image\\image123.001"}},
        workflow_id=3,
        output_path="C:\\testdata\\output",
        platform="windows",
        decryption={"type": "password", "value": SecretStr("MySecretPassword"), "continueOnDecryptionFail": False},
        custom_field_values={"5": "Evidence Value A"},
        assigned_node_name="AGENT1",
    )


# endregion

# region mf-automate-workflow-run-list


class TestWorkflowRunListArgs:
    """Tests for the WorkflowRunListArgs pydantic model."""

    def test_happy_path(self) -> None:
        """
        Given:
            - Valid case_id, run_id, limit, and all_results.
        When:
            - Constructing WorkflowRunListArgs.
        Then:
            - All fields are set correctly.
        """
        from MagnetAutomate import WorkflowRunListArgs

        args = WorkflowRunListArgs(case_id=10, run_id=23, limit=5, all_results=False)

        assert args.case_id == 10
        assert args.run_id == 23
        assert args.limit == 5
        assert args.all_results is False

    def test_defaults(self) -> None:
        """
        Given:
            - Only required case_id provided.
        When:
            - Constructing WorkflowRunListArgs.
        Then:
            - run_id defaults to None, limit defaults to 50, all_results defaults to False.
        """
        from MagnetAutomate import WorkflowRunListArgs

        args = WorkflowRunListArgs(case_id=10)  # type: ignore[arg-type]

        assert args.run_id is None
        assert args.limit == 50
        assert args.all_results is False

    @pytest.mark.parametrize(
        "case_id, run_id, limit, all_results, exp_case_id, exp_run_id, exp_limit, exp_all_results",
        [
            pytest.param("10", "23", "5", "false", 10, 23, 5, False, id="all_strings_coerced"),
            pytest.param(10, None, None, True, 10, None, None, True, id="none_run_id_and_limit"),
        ],
    )
    def test_field_coercions(
        self,
        case_id: int | str,
        run_id: int | str | None,
        limit: int | str | None,
        all_results: bool | str,
        exp_case_id: int,
        exp_run_id: int | None,
        exp_limit: int | None,
        exp_all_results: bool,
    ) -> None:
        """
        Given:
            - Various field inputs as strings or ints.
        When:
            - Constructing WorkflowRunListArgs.
        Then:
            - All numeric fields are coerced to int, all_results to bool.
        """
        from MagnetAutomate import WorkflowRunListArgs

        args = WorkflowRunListArgs(case_id=case_id, run_id=run_id, limit=limit, all_results=all_results)  # type: ignore[arg-type]

        assert args.case_id == exp_case_id
        assert args.run_id == exp_run_id
        assert args.limit == exp_limit
        assert args.all_results is exp_all_results


def test_workflow_run_list_command_specific(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID.
        - A run ID.
    When:
        - Calling the workflow_run_list_command.
    Then:
        - Assert the client's workflow_run_list method is called with the correct case and run IDs.
        - Assert the response is correctly processed into CommandResults with expected workflow run details.
    """
    from MagnetAutomate import workflow_run_list_command, WorkflowRunListArgs

    mock_response = load_mock_response("workflow_run_list_specific.json")
    mocker.patch.object(client, "workflow_run_list_specific", return_value=mock_response)

    args = WorkflowRunListArgs(case_id=10, run_id=23, limit=None, all_results=False)

    response = workflow_run_list_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.WorkflowRun"
    assert response.outputs_key_field == "id"

    output: dict[str, Any] = response.outputs  # type: ignore

    assert output.get("id") == 23
    assert "Workflow Run 23 Details" in response.readable_output
    client.workflow_run_list_specific.assert_called_once_with(case_id=10, run_id=23)  # type: ignore


def test_workflow_run_list_command_all(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID.
    When:
        - Calling the workflow_run_list_command.
    Then:
        - Assert the client's workflow_run_list method is called with the correct case ID.
        - Assert the response is correctly processed into CommandResults with expected workflow run details.
    """
    from MagnetAutomate import workflow_run_list_command, WorkflowRunListArgs

    mock_response = load_mock_response("workflow_run_list_all.json")
    mocker.patch.object(client, "workflow_run_list_all", return_value=mock_response)

    args = WorkflowRunListArgs(case_id=10, run_id=None, limit=None, all_results=False)

    response = workflow_run_list_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.WorkflowRun"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 2
    assert outputs[0].get("id") == 23
    assert outputs[1].get("id") == 42
    assert "Workflow Runs for Case 10" in response.readable_output
    client.workflow_run_list_all.assert_called_once_with(case_id=10)  # type: ignore


# endregion


# region mf-automate-workflow-run-delete


class TestWorkflowRunDeleteArgs:
    """Tests for the WorkflowRunDeleteArgs pydantic model."""

    @pytest.mark.parametrize(
        "case_id_input, run_id_input, expected_case_id, expected_run_id",
        [
            pytest.param(123, 456, 123, 456, id="both_ints"),
            pytest.param("123", "456", 123, 456, id="both_strings_coerced"),
        ],
    )
    def test_field_coercions(
        self,
        case_id_input: int | str,
        run_id_input: int | str,
        expected_case_id: int,
        expected_run_id: int,
    ) -> None:
        """
        Given:
            - case_id and run_id as int or string.
        When:
            - Constructing WorkflowRunDeleteArgs.
        Then:
            - Both fields are set or coerced to int correctly.
        """
        from MagnetAutomate import WorkflowRunDeleteArgs

        args = WorkflowRunDeleteArgs(case_id=case_id_input, run_id=run_id_input)  # type: ignore[arg-type]

        assert args.case_id == expected_case_id
        assert args.run_id == expected_run_id


def test_workflow_run_delete_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID and a workflow run ID to delete.
    When:
        - Calling the workflow_run_delete_command.
    Then:
        - Assert the client's workflow_run_delete method is called with the correct case ID and run ID.
        - Assert the readable output indicates successful deletion.
    """
    from MagnetAutomate import workflow_run_delete_command, WorkflowRunDeleteArgs

    mocker.patch.object(client, "workflow_run_delete", return_value=None)

    args = WorkflowRunDeleteArgs(case_id=123, run_id=456)

    response = workflow_run_delete_command(client, args)

    assert response.readable_output == "Workflow run 456 for case 123 deleted successfully"
    client.workflow_run_delete.assert_called_once_with(case_id=123, run_id=456)  # type: ignore


# endregion

# region mf-automate-workflow-run-cancel


class TestWorkflowRunCancelArgs:
    """Tests for the WorkflowRunCancelArgs pydantic model."""

    @pytest.mark.parametrize(
        "case_id_input, run_id_input, expected_case_id, expected_run_id",
        [
            pytest.param(10, 20, 10, 20, id="both_ints"),
            pytest.param("10", "20", 10, 20, id="both_strings_coerced"),
        ],
    )
    def test_field_coercions(
        self,
        case_id_input: int | str,
        run_id_input: int | str,
        expected_case_id: int,
        expected_run_id: int,
    ) -> None:
        """
        Given:
            - case_id and run_id as int or string.
        When:
            - Constructing WorkflowRunCancelArgs.
        Then:
            - Both fields are set or coerced to int correctly.
        """
        from MagnetAutomate import WorkflowRunCancelArgs

        args = WorkflowRunCancelArgs(case_id=case_id_input, run_id=run_id_input)  # type: ignore[arg-type]

        assert args.case_id == expected_case_id
        assert args.run_id == expected_run_id


def test_workflow_run_cancel_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID and a workflow run ID to cancel.
    When:
        - Calling the workflow_run_cancel_command.
    Then:
        - Assert the client's workflow_run_cancel method is called with the correct case ID and run ID.
        - Assert the readable output indicates successful cancellation.
    """
    from MagnetAutomate import workflow_run_cancel_command, WorkflowRunCancelArgs

    mocker.patch.object(client, "workflow_run_cancel", return_value=None)

    args = WorkflowRunCancelArgs(case_id=123, run_id=456)

    response = workflow_run_cancel_command(client, args)

    assert response.readable_output == "Workflow run 456 for case 123 cancelled successfully"
    client.workflow_run_cancel.assert_called_once_with(case_id=123, run_id=456)  # type: ignore


# endregion


# region mf-automate-merge-workflow-run-start


class TestMergeWorkflowRunStartArgs:
    """Tests for the MergeWorkflowRunStartArgs pydantic model."""

    def test_happy_path(self) -> None:
        """
        Given:
            - Valid case_id, run_ids list, and workflow_id.
        When:
            - Constructing MergeWorkflowRunStartArgs.
        Then:
            - All fields are set correctly.
        """
        from MagnetAutomate import MergeWorkflowRunStartArgs

        args = MergeWorkflowRunStartArgs(case_id=10, run_ids=[11, 12], workflow_id=5)  # type: ignore[arg-type]

        assert args.case_id == 10
        assert args.run_ids == [11, 12]
        assert args.workflow_id == 5

    def test_optional_fields_default_to_none(self) -> None:
        """
        Given:
            - Only required fields provided.
        When:
            - Constructing MergeWorkflowRunStartArgs.
        Then:
            - output_path and assigned_node_name default to None.
        """
        from MagnetAutomate import MergeWorkflowRunStartArgs

        args = MergeWorkflowRunStartArgs(case_id=10, run_ids=[1], workflow_id=5)  # type: ignore[arg-type]

        assert args.output_path is None
        assert args.assigned_node_name is None

    @pytest.mark.parametrize(
        "run_ids_input, expected",
        [
            pytest.param("1,2,3", [1, 2, 3], id="comma_separated_string"),
            pytest.param([11, 12], [11, 12], id="list_of_ints"),
        ],
    )
    def test_run_ids_coercion(self, run_ids_input: str | list, expected: list) -> None:
        """
        Given:
            - run_ids as a comma-separated string or list of ints.
        When:
            - Constructing MergeWorkflowRunStartArgs.
        Then:
            - run_ids is parsed to a list of ints via argToList + arg_to_number.
        """
        from MagnetAutomate import MergeWorkflowRunStartArgs

        args = MergeWorkflowRunStartArgs(case_id=10, run_ids=run_ids_input, workflow_id=5)  # type: ignore[arg-type]

        assert args.run_ids == expected

    @pytest.mark.parametrize(
        "case_id_input, workflow_id_input, expected_case_id, expected_workflow_id",
        [
            pytest.param("10", "5", 10, 5, id="both_strings_coerced"),
            pytest.param(10, 5, 10, 5, id="both_ints"),
        ],
    )
    def test_numeric_field_coercions(
        self,
        case_id_input: int | str,
        workflow_id_input: int | str,
        expected_case_id: int,
        expected_workflow_id: int,
    ) -> None:
        """
        Given:
            - case_id and workflow_id as strings or ints.
        When:
            - Constructing MergeWorkflowRunStartArgs.
        Then:
            - Both are coerced to int.
        """
        from MagnetAutomate import MergeWorkflowRunStartArgs

        args = MergeWorkflowRunStartArgs(case_id=case_id_input, run_ids=[1], workflow_id=workflow_id_input)  # type: ignore[arg-type]

        assert args.case_id == expected_case_id
        assert args.workflow_id == expected_workflow_id


def test_merge_workflow_run_start_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - Merge workflow run arguments including case ID, run IDs, and workflow ID.
    When:
        - Calling the merge_workflow_run_start_command.
    Then:
        - Assert the client's merge_workflow_run_start method is called with all provided arguments.
        - Assert the response is correctly processed into CommandResults with expected workflow run details.
    """
    from MagnetAutomate import merge_workflow_run_start_command, MergeWorkflowRunStartArgs

    mock_response = load_mock_response("merge_workflow_run_start.json")
    mocker.patch.object(client, "merge_workflow_run_start", return_value=mock_response)

    args = MergeWorkflowRunStartArgs(
        case_id=10,
        run_ids=[11, 12],
        workflow_id=5,
        output_path="C:\\testdata\\output",
        assigned_node_name="AGENT1",
    )

    response = merge_workflow_run_start_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.WorkflowRun"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore

    assert outputs.get("id") == 14
    assert outputs.get("caseId") == 10
    assert "Merge Workflow Run Started" in response.readable_output

    client.merge_workflow_run_start.assert_called_once_with(  # type: ignore
        case_id=10,
        run_ids=[11, 12],
        workflow_id=5,
        output_path="C:\\testdata\\output",
        assigned_node_name="AGENT1",
    )


# endregion


# region mf-automate-workflow-list


class TestWorkflowListArgs:
    """Tests for the WorkflowListArgs pydantic model."""

    def test_defaults(self) -> None:
        """
        Given:
            - No arguments provided.
        When:
            - Constructing WorkflowListArgs with defaults.
        Then:
            - limit defaults to 50 and all_results defaults to False.
        """
        from MagnetAutomate import WorkflowListArgs

        args = WorkflowListArgs()  # type: ignore[arg-type]

        assert args.limit == 50
        assert args.all_results is False

    @pytest.mark.parametrize(
        "limit_input, expected",
        [
            pytest.param("25", 25, id="string_coerced"),
            pytest.param(10, 10, id="int"),
            pytest.param(None, None, id="none"),
        ],
    )
    def test_limit_coercion(self, limit_input: int | str | None, expected: int | None) -> None:
        """
        Given:
            - Various limit inputs.
        When:
            - Constructing WorkflowListArgs.
        Then:
            - limit is coerced correctly.
        """
        from MagnetAutomate import WorkflowListArgs

        args = WorkflowListArgs(limit=limit_input, all_results=False)  # type: ignore[arg-type]

        assert args.limit == expected

    @pytest.mark.parametrize(
        "all_results_input, expected",
        [
            pytest.param("true", True, id="string_true"),
            pytest.param("false", False, id="string_false"),
            pytest.param(True, True, id="bool_true"),
        ],
    )
    def test_all_results_coercion(self, all_results_input: bool | str, expected: bool) -> None:
        """
        Given:
            - Various all_results inputs.
        When:
            - Constructing WorkflowListArgs.
        Then:
            - all_results is coerced to bool via argToBoolean.
        """
        from MagnetAutomate import WorkflowListArgs

        args = WorkflowListArgs(limit=50, all_results=all_results_input)  # type: ignore[arg-type]

        assert args.all_results is expected


def test_workflow_list_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - No specific arguments (requesting all workflows).
    When:
        - Calling the workflow_list_command.
    Then:
        - Assert the client's workflows_list method is called.
        - Assert the response is correctly processed into CommandResults containing a list of workflows.
    """
    from MagnetAutomate import workflow_list_command, WorkflowListArgs

    mock_response = load_mock_response("workflows_list.json")
    mocker.patch.object(client, "workflows_list", return_value=mock_response)

    args = WorkflowListArgs(limit=None, all_results=False)

    response = workflow_list_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.Workflow"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 2
    assert outputs[0].get("id") == 9
    assert outputs[1].get("id") == 17
    assert "Workflows" in response.readable_output
    client.workflows_list.assert_called_once()  # type: ignore


# endregion


# region mf-automate-workflow-delete


class TestWorkflowDeleteArgs:
    """Tests for the WorkflowDeleteArgs pydantic model."""

    @pytest.mark.parametrize(
        "workflow_id_input, expected",
        [
            pytest.param(9, 9, id="int"),
            pytest.param("17", 17, id="string_coerced"),
        ],
    )
    def test_workflow_id_coercion(self, workflow_id_input: int | str, expected: int) -> None:
        """
        Given:
            - workflow_id as int or string.
        When:
            - Constructing WorkflowDeleteArgs.
        Then:
            - workflow_id is set or coerced to int correctly.
        """
        from MagnetAutomate import WorkflowDeleteArgs

        args = WorkflowDeleteArgs(workflow_id=workflow_id_input)  # type: ignore[arg-type]

        assert args.workflow_id == expected


def test_workflow_delete_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A workflow ID to delete.
    When:
        - Calling the workflow_delete_command.
    Then:
        - Assert the client's workflow_delete method is called with the correct workflow ID.
        - Assert the readable output indicates successful deletion.
    """
    from MagnetAutomate import workflow_delete_command, WorkflowDeleteArgs

    mocker.patch.object(client, "workflow_delete", return_value=None)

    args = WorkflowDeleteArgs(workflow_id=9)

    response = workflow_delete_command(client, args)

    assert response.readable_output == "Workflow 9 deleted successfully"
    client.workflow_delete.assert_called_once_with(workflow_id=9)  # type: ignore


# endregion


# region mf-automate-workflow-get


class TestWorkflowGetArgs:
    """Tests for the WorkflowGetArgs pydantic model."""

    @pytest.mark.parametrize(
        "workflow_id_input, expected",
        [
            pytest.param(1, 1, id="int"),
            pytest.param("42", 42, id="string_coerced"),
        ],
    )
    def test_workflow_id_coercion(self, workflow_id_input: int | str, expected: int) -> None:
        """
        Given:
            - workflow_id as int or string.
        When:
            - Constructing WorkflowGetArgs.
        Then:
            - workflow_id is set or coerced to int correctly.
        """
        from MagnetAutomate import WorkflowGetArgs

        args = WorkflowGetArgs(workflow_id=workflow_id_input)  # type: ignore[arg-type]

        assert args.workflow_id == expected


def test_workflow_get_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A workflow ID to export.
    When:
        - Calling the workflow_get_command.
    Then:
        - Assert the client's workflow_get method is called with the correct workflow ID.
        - Assert the response is correctly processed into CommandResults with expected workflow export details.
    """
    from MagnetAutomate import workflow_get_command, WorkflowGetArgs

    mock_response = load_mock_response("workflow_get.json")
    mocker.patch.object(client, "workflow_get", return_value=mock_response)

    args = WorkflowGetArgs(workflow_id=1)

    response = workflow_get_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.Workflow"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore

    assert outputs.get("name") == "Process - Image"
    assert outputs.get("automateVersion") == "1.2.3.0000"
    assert outputs.get("id") == 1
    assert "Workflow 1 Export" in response.readable_output
    client.workflow_get.assert_called_once_with(workflow_id=1)  # type: ignore


# endregion


# region mf-automate-node-create


class TestNodeCreateArgs:
    """Tests for the NodeCreateArgs pydantic model."""

    def test_happy_path(self) -> None:
        """
        Given:
            - Valid name, address, and working_directory.
        When:
            - Constructing NodeCreateArgs.
        Then:
            - All fields are set correctly.
        """
        from MagnetAutomate import NodeCreateArgs

        args = NodeCreateArgs(  # type: ignore[arg-type]
            name="NODE-001",
            address="192.168.1.10",
            working_directory="C:\\automate\\temp",
        )

        assert args.name == "NODE-001"
        assert args.address == "192.168.1.10"
        assert args.working_directory == "C:\\automate\\temp"
        assert args.applications_json is None

    def test_all_optional_defaults_to_none(self) -> None:
        """
        Given:
            - No arguments provided.
        When:
            - Constructing NodeCreateArgs.
        Then:
            - All fields default to None.
        """
        from MagnetAutomate import NodeCreateArgs

        args = NodeCreateArgs()  # type: ignore[arg-type]

        assert args.name is None
        assert args.address is None
        assert args.working_directory is None
        assert args.applications_json is None

    @pytest.mark.parametrize(
        "applications_json_input, expected",
        [
            pytest.param(
                '[{"applicationName": "AXIOM Process", "applicationVersion": "7.0.0"}]',
                [{"applicationName": "AXIOM Process", "applicationVersion": "7.0.0"}],
                id="json_string_parsed",
            ),
            pytest.param(
                [{"applicationName": "AXIOM", "applicationVersion": "6.0.0"}],
                [{"applicationName": "AXIOM", "applicationVersion": "6.0.0"}],
                id="list_passthrough",
            ),
        ],
    )
    def test_applications_json_coercion(self, applications_json_input: str | list, expected: list) -> None:
        """
        Given:
            - applications_json as a JSON string or list of dicts.
        When:
            - Constructing NodeCreateArgs.
        Then:
            - applications_json is parsed from JSON string or passed through as list.
        """
        from MagnetAutomate import NodeCreateArgs

        args = NodeCreateArgs(applications_json=applications_json_input)  # type: ignore[arg-type]

        assert args.applications_json == expected


def test_node_create_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - Node creation arguments including name, address, and working directory.
    When:
        - Calling the node_create_command.
    Then:
        - Assert the client's node_create method is called with the provided arguments.
        - Assert the response is correctly processed into CommandResults with expected node details.
    """
    from MagnetAutomate import node_create_command, NodeCreateArgs

    mock_response = load_mock_response("node_create.json")
    mocker.patch.object(client, "node_create", return_value=mock_response)

    args = NodeCreateArgs(
        name="NODE-002",
        address="automate-node-2",
        working_directory="C:\\automate\\updatedTemp",
        applications_json='[{"applicationName": "AXIOM Process", "applicationVersion": "7.0.0", "applicationPath": "C:\\\\Program Files\\\\Magnet Forensics\\\\Magnet AUTOMATE\\\\agent\\\\AXIOM Process\\\\AXIOMProcess.CLI.exe"}]',  # noqa: E501
    )

    response = node_create_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.Node"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore

    assert outputs.get("id") == 1
    assert outputs.get("name") == "NODE-002"
    assert "The node 'NODE-002' was created successfully" in response.readable_output

    client.node_create.assert_called_once_with(  # type: ignore
        name="NODE-002",
        address="automate-node-2",
        working_directory="C:\\automate\\updatedTemp",
        applications=[
            {
                "applicationName": "AXIOM Process",
                "applicationVersion": "7.0.0",
                "applicationPath": "C:\\Program Files\\Magnet Forensics\\Magnet AUTOMATE\\agent\\AXIOM Process\\AXIOMProcess.CLI.exe",  # noqa: E501
            }
        ],
    )


# endregion


# region mf-automate-nodes-list


class TestNodesListArgs:
    """Tests for the NodesListArgs pydantic model."""

    def test_defaults(self) -> None:
        """
        Given:
            - No arguments provided.
        When:
            - Constructing NodesListArgs with defaults.
        Then:
            - limit defaults to 50 and all_results defaults to False.
        """
        from MagnetAutomate import NodesListArgs

        args = NodesListArgs()  # type: ignore[arg-type]

        assert args.limit == 50
        assert args.all_results is False

    @pytest.mark.parametrize(
        "limit_input, expected",
        [
            pytest.param("5", 5, id="string_coerced"),
            pytest.param(20, 20, id="int"),
            pytest.param(None, None, id="none"),
        ],
    )
    def test_limit_coercion(self, limit_input: int | str | None, expected: int | None) -> None:
        """
        Given:
            - Various limit inputs.
        When:
            - Constructing NodesListArgs.
        Then:
            - limit is coerced correctly.
        """
        from MagnetAutomate import NodesListArgs

        args = NodesListArgs(limit=limit_input, all_results=False)  # type: ignore[arg-type]

        assert args.limit == expected

    @pytest.mark.parametrize(
        "all_results_input, expected",
        [
            pytest.param("true", True, id="string_true"),
            pytest.param("false", False, id="string_false"),
            pytest.param(True, True, id="bool_true"),
        ],
    )
    def test_all_results_coercion(self, all_results_input: bool | str, expected: bool) -> None:
        """
        Given:
            - Various all_results inputs.
        When:
            - Constructing NodesListArgs.
        Then:
            - all_results is coerced to bool via argToBoolean.
        """
        from MagnetAutomate import NodesListArgs

        args = NodesListArgs(limit=50, all_results=all_results_input)  # type: ignore[arg-type]

        assert args.all_results is expected


def test_nodes_list_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - No specific arguments (requesting all nodes).
    When:
        - Calling the nodes_list_command.
    Then:
        - Assert the client's nodes_list method is called.
        - Assert the response is correctly processed into CommandResults containing a list of nodes.
    """
    from MagnetAutomate import nodes_list_command, NodesListArgs

    mock_response = load_mock_response("nodes_list.json")
    mocker.patch.object(client, "nodes_list", return_value=mock_response)

    args = NodesListArgs(limit=None, all_results=False)

    response = nodes_list_command(client, args)

    assert response.outputs_prefix == "MagnetAutomate.Node"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 3
    assert outputs[0].get("id") == 1
    assert outputs[1].get("id") == 2
    assert outputs[2].get("id") == 3
    assert "Nodes List" in response.readable_output
    client.nodes_list.assert_called_once()  # type: ignore


# endregion


# region mf-automate-node-update


class TestNodeUpdateArgs:
    """Tests for the NodeUpdateArgs pydantic model."""

    def test_happy_path(self) -> None:
        """
        Given:
            - Valid node_id, address, and working_directory.
        When:
            - Constructing NodeUpdateArgs.
        Then:
            - All fields are set correctly.
        """
        from MagnetAutomate import NodeUpdateArgs

        args = NodeUpdateArgs(  # type: ignore[arg-type]
            node_id=1,
            address="192.168.1.20",
            working_directory="C:\\automate\\updatedTemp",
        )

        assert args.node_id == 1
        assert args.address == "192.168.1.20"
        assert args.working_directory == "C:\\automate\\updatedTemp"

    def test_optional_fields_default_to_none(self) -> None:
        """
        Given:
            - Only required node_id provided.
        When:
            - Constructing NodeUpdateArgs.
        Then:
            - address, working_directory, and applications_json default to None.
        """
        from MagnetAutomate import NodeUpdateArgs

        args = NodeUpdateArgs(node_id=1)  # type: ignore[arg-type]

        assert args.address is None
        assert args.working_directory is None
        assert args.applications_json is None

    @pytest.mark.parametrize(
        "node_id_input, expected",
        [
            pytest.param(7, 7, id="int"),
            pytest.param("7", 7, id="string_coerced"),
        ],
    )
    def test_node_id_coercion(self, node_id_input: int | str, expected: int) -> None:
        """
        Given:
            - node_id as int or string.
        When:
            - Constructing NodeUpdateArgs.
        Then:
            - node_id is set or coerced to int correctly.
        """
        from MagnetAutomate import NodeUpdateArgs

        args = NodeUpdateArgs(node_id=node_id_input)  # type: ignore[arg-type]

        assert args.node_id == expected

    @pytest.mark.parametrize(
        "applications_json_input, expected",
        [
            pytest.param(
                '[{"applicationName": "AXIOM Process", "applicationVersion": "7.0.0", "applicationPath": "C:\\\\path\\\\app.exe"}]',  # noqa: E501
                [{"applicationName": "AXIOM Process", "applicationVersion": "7.0.0", "applicationPath": "C:\\path\\app.exe"}],
                id="json_string_parsed",
            ),
            pytest.param(
                [{"applicationName": "AXIOM", "applicationVersion": "6.0.0"}],
                [{"applicationName": "AXIOM", "applicationVersion": "6.0.0"}],
                id="list_passthrough",
            ),
        ],
    )
    def test_applications_json_coercion(self, applications_json_input: str | list, expected: list) -> None:
        """
        Given:
            - applications_json as a JSON string or list of dicts.
        When:
            - Constructing NodeUpdateArgs.
        Then:
            - applications_json is parsed from JSON string or passed through as list.
        """
        from MagnetAutomate import NodeUpdateArgs

        args = NodeUpdateArgs(node_id=1, applications_json=applications_json_input)  # type: ignore[arg-type]

        assert args.applications_json == expected


def test_node_update_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - Node update arguments including node ID, address, and working directory.
    When:
        - Calling the node_update_command.
    Then:
        - Assert the client's node_update method is called with the provided arguments.
    """
    from MagnetAutomate import node_update_command, NodeUpdateArgs

    mocker.patch.object(client, "node_update", return_value=None)

    args = NodeUpdateArgs(
        node_id=1,
        address="automate-node-2",
        working_directory="C:\\automate\\updatedTemp",
        applications_json='[{"applicationName": "AXIOM Process", "applicationVersion": "7.0.0", "applicationPath": "C:\\\\Program Files\\\\Magnet Forensics\\\\Magnet AUTOMATE\\\\agent\\\\AXIOM Process\\\\AXIOMProcess.CLI.exe"}]',  # noqa: E501
    )

    response = node_update_command(client, args)

    assert "Node 1 was updated successfully" in response.readable_output

    client.node_update.assert_called_once_with(  # type: ignore
        node_id=1,
        address="automate-node-2",
        working_directory="C:\\automate\\updatedTemp",
        applications=[
            {
                "applicationName": "AXIOM Process",
                "applicationVersion": "7.0.0",
                "applicationPath": "C:\\Program Files\\Magnet Forensics\\Magnet AUTOMATE\\agent\\AXIOM Process\\AXIOMProcess.CLI.exe",  # noqa: E501
            }
        ],
    )


# endregion


# region mf-automate-node-delete


class TestNodeDeleteArgs:
    """Tests for the NodeDeleteArgs pydantic model."""

    @pytest.mark.parametrize(
        "node_id_input, expected",
        [
            pytest.param(123, 123, id="int"),
            pytest.param("55", 55, id="string_coerced"),
        ],
    )
    def test_node_id_coercion(self, node_id_input: int | str, expected: int) -> None:
        """
        Given:
            - node_id as int or string.
        When:
            - Constructing NodeDeleteArgs.
        Then:
            - node_id is set or coerced to int correctly.
        """
        from MagnetAutomate import NodeDeleteArgs

        args = NodeDeleteArgs(node_id=node_id_input)  # type: ignore[arg-type]

        assert args.node_id == expected


def test_node_delete_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A node ID to delete.
    When:
        - Calling the node_delete_command.
    Then:
        - Assert the client's node_delete method is called with the correct node ID.
        - Assert the readable output indicates successful deletion.
    """
    from MagnetAutomate import node_delete_command, NodeDeleteArgs

    mocker.patch.object(client, "node_delete", return_value=None)

    args = NodeDeleteArgs(node_id=123)

    response = node_delete_command(client, args)

    assert response.readable_output == "The Node 123 was deleted successfully"
    client.node_delete.assert_called_once_with(node_id=123)  # type: ignore


# endregion
