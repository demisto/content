import pytest
from collections import defaultdict

from IndicatorEnrichment import (
    IndicatorType,
    EnrichmentRequest,
    EnrichmentResult,
    ResponseFormatter,
    EnrichmentService,
    UnsupportedIndicator,
    AllExecutionsFailedError,
    EnrichmentRequestBuilder,
    ValidationError,
    GracefulExit,
    main,
)


class TestIndicatorType:
    """
    Tests the configuration enum, ensuring aliases map correctly to strict types.
    """

    @pytest.mark.parametrize(
        "input_str, expected_enum",
        [
            ("ip", IndicatorType.IP),
            ("IPv4", IndicatorType.IP),
            ("url", IndicatorType.URL),
            ("Domain", IndicatorType.DOMAIN),
            ("file", IndicatorType.FILE),
            ("cve", IndicatorType.CVE),
        ],
        ids=["lower_case_ip", "camel_case_ipv4", "simple_url", "capitalized_domain", "file", "simple_cve"],
    )
    def test_resolve_valid_types(self, input_str, expected_enum):
        """
        Scenario: Resolving valid aliases.
        Given: A string representing a supported indicator type (various casings).
        When: IndicatorType.resolve_from_string is called.
        Then: The correct Enum member is returned.
        """
        assert IndicatorType.resolve_from_string(input_str) == expected_enum

    @pytest.mark.parametrize(
        "invalid_input",
        ["garbage_type", "email", "  ", None],
        ids=["unknown_string", "unsupported_type", "whitespace_only", "none_value"],
    )
    def test_resolve_invalid_types(self, invalid_input):
        """
        Scenario: Resolving unsupported inputs.
        Given: An input string that does not match any configured alias.
        When: IndicatorType.resolve_from_string is called.
        Then: None is returned.
        """
        assert IndicatorType.resolve_from_string(invalid_input) is None


class TestResponseFormatter:
    """
    Tests the transformation of internal results into XSOAR Output formats
    (Markdown and Context).
    """

    def test_format_markdown_happy_path(self):
        """
        Scenario: Standard successful enrichment.
        Given: A Result object with one Markdown section and no errors.
        When: format() is called.
        Then: The output contains the section and NO error table or duplicate notes.
        """
        # Arrange
        result = EnrichmentResult()
        result.markdown_sections.append("### IP Results\n|IP|Geo|\n|---|---|\n|1.1.1.1|US|")

        request = EnrichmentRequest(
            valid_indicators_by_type=defaultdict(list),
            unsupported_items=[],
            unknown_items=[],
            duplicates_removed_count=0,  # No duplicates
            sub_command_arguments={},
            include_raw_context=False,
        )

        # Act
        formatter = ResponseFormatter()
        cmd_results = formatter.format(result, request)

        # Assert
        assert cmd_results.readable_output == "### IP Results\n|IP|Geo|\n|---|---|\n|1.1.1.1|US|"

    def test_format_markdown_with_duplicates_and_errors(self):
        """
        Scenario: Enrichment with mixed issues.
        Given: A Request with 2 duplicates removed and 1 unknown item.
        When: format() is called.
        Then: The output includes the Duplicate Note AND the Error Table.
        """
        # Arrange
        result = EnrichmentResult()  # Empty result logic for this test

        request = EnrichmentRequest(
            valid_indicators_by_type=defaultdict(list),
            unsupported_items=[],
            unknown_items=["bad_hash"],
            duplicates_removed_count=2,
            sub_command_arguments={},
            include_raw_context=False,
        )

        # Act
        formatter = ResponseFormatter()
        cmd_results = formatter.format(result, request)

        # Assert
        assert cmd_results.readable_output == (
            "Note: Removed 2 duplicate indicator occurrences before enrichment.\n"
            "\n"
            "### Invalid or unsupported indicators\n"
            "|Type|Value|Status|Message|\n"
            "|---|---|---|---|\n"
            "| Unknown | bad_hash | Error | Not a valid indicator. |\n"
        )

    def test_context_filtering_default(self):
        """
        Scenario: Default context filtering (raw_context=False).
        Given: Context containing 'IPEnrichment' (raw) and 'DBotScore' (side-effect).
        When: format() is called with include_raw_context=False.
        Then: 'IPEnrichment' is removed, 'DBotScore' is preserved.
        """
        # Arrange
        result = EnrichmentResult()
        result.raw_context = {
            "IPEnrichment": {"data": "raw"},  # Should be removed
            "IndicatorEnrichment": [{"Value": "1.1.1.1", "Type": "IP"}],
            "Core": {"Score": 3},  # Should be kept
            "EndpointData": {"Name": "X"},  # Should be kept
        }

        request = EnrichmentRequest(
            valid_indicators_by_type=defaultdict(list),
            unsupported_items=[],
            unknown_items=[],
            duplicates_removed_count=0,
            sub_command_arguments={},
            include_raw_context=False,  # <--- Default behavior
        )

        # Act
        formatter = ResponseFormatter()
        cmd_results = formatter.format(result, request)
        ctx = cmd_results.outputs

        # Assert
        assert ctx == {
            "Core": {"Score": 3},
            "EndpointData": {"Name": "X"},
            "IndicatorEnrichment": [{"Type": "IP", "Value": "1.1.1.1"}],
        }

    def test_context_filtering_include_raw(self):
        """
        Scenario: raw_context=True.
        Given: Context containing 'IPEnrichment' (raw).
        When: format() is called with include_raw_context=True.
        Then: 'IPEnrichment' is preserved in the final output.
        """
        # Arrange
        result = EnrichmentResult()
        result.raw_context = {
            "IPEnrichment": {"data": "raw"},  # Should be removed
            "IndicatorEnrichment": [{"Value": "1.1.1.1", "Type": "IP"}],
            "Core": {"Score": 3},  # Should be kept
            "EndpointData": {"Name": "X"},  # Should be kept
        }

        request = EnrichmentRequest(
            valid_indicators_by_type=defaultdict(list),
            unsupported_items=[],
            unknown_items=[],
            duplicates_removed_count=0,
            sub_command_arguments={},
            include_raw_context=True,  # <--- Explicit inclusion
        )

        # Act
        formatter = ResponseFormatter()
        cmd_results = formatter.format(result, request)

        # Assert
        assert "IPEnrichment" in cmd_results.outputs

    def test_unified_context_creation(self):
        """
        Scenario: Unified context generation.
        Given: A result with enriched data and a request with an error item.
        When: format() is called.
        Then: 'IndicatorEnrichment' list contains both the success entry and the error entry.
        """
        # Arrange
        result = EnrichmentResult()
        result.enriched_data = [{"Value": "1.1.1.1", "Type": "IP"}]  # Success item

        request = EnrichmentRequest(
            valid_indicators_by_type=defaultdict(list),
            unsupported_items=[UnsupportedIndicator("IPv6", "2001::1")],  # Error item
            unknown_items=[],
            duplicates_removed_count=0,
            sub_command_arguments={},
            include_raw_context=False,
        )

        # Act
        formatter = ResponseFormatter()
        cmd_results = formatter.format(result, request)
        unified_list = cmd_results.outputs["IndicatorEnrichment"]

        # Assert
        assert len(unified_list) == 2

        # Check Success Item
        assert unified_list[0]["Value"] == "1.1.1.1"
        assert unified_list[0]["Type"] == "IP"

        # Check Error Item
        assert unified_list[1]["Value"] == "2001::1"
        assert unified_list[1]["Type"] == "IPv6"
        assert unified_list[1]["Status"] == "Error"

    def test_format_happy_path(self):
        """
        Scenario: Standard successful execution.
        Given: A Result object with enriched data and markdown.
        When: format() is called.
        Then: It returns a CommandResults object with populated readable_output and outputs.
        """
        # Arrange
        result = EnrichmentResult()
        result.enriched_data = [{"Value": "8.8.8.8", "Type": "IP", "Geo": "US"}]
        result.markdown_sections = ["### IP Results\n|IP|Geo|\n|---|---|\n|8.8.8.8|US|"]
        result.raw_context = {"IPEnrichment": [{"Value": "8.8.8.8"}]}  # Should be filtered out by default

        request = EnrichmentRequest(
            valid_indicators_by_type=defaultdict(list),
            unsupported_items=[],
            unknown_items=[],
            duplicates_removed_count=0,
            sub_command_arguments={},
            include_raw_context=False,
        )

        # Act
        formatter = ResponseFormatter()
        cmd_results = formatter.format(result, request)

        # Assert
        # 1. Verify Markdown
        assert cmd_results.readable_output == "### IP Results\n|IP|Geo|\n|---|---|\n|8.8.8.8|US|"

        # 2. Verify Context
        # Ensure the unified key is present and correct, and no raw context
        assert cmd_results.outputs == {"IndicatorEnrichment": [{"Geo": "US", "Type": "IP", "Value": "8.8.8.8"}]}

    def test_format_fatal_execution_error(self):
        """
        Scenario: All commands failed (Fatal Error).
        Given: A Result object with 0 enriched data rows and >0 execution errors.
        When: format() is called.
        Then: A ValidationError is raised containing the specific error details.
        """
        # Arrange
        result = EnrichmentResult()
        result.enriched_data = []  # Crucial: No success data
        result.execution_errors = ["Error 1: Timeout", "Error 2: API Limit"]

        # Dummy request (content irrelevant for this specific check)
        request = EnrichmentRequest(
            valid_indicators_by_type=defaultdict(list),
            unsupported_items=[],
            unknown_items=[],
            duplicates_removed_count=0,
            sub_command_arguments={},
            include_raw_context=False,
        )

        # Act & Assert
        formatter = ResponseFormatter()

        with pytest.raises(AllExecutionsFailedError) as excinfo:
            formatter.format(result, request)

        # Verify the exception message matches the template and includes the errors
        error_msg = str(excinfo.value)
        assert error_msg == (
            "Fatal error while executing enrichment. View the logs or try again.\n" "Error 1: Timeout\n" "Error 2: API Limit"
        )


class TestEnrichmentService:
    """
    Tests the orchestration of child commands and result parsing.
    """

    @pytest.fixture
    def mock_batch_executor(self, mocker):
        mock_executor = mocker.patch("IndicatorEnrichment.BatchExecutor")
        mock_instance = mock_executor.return_value
        return mock_instance

    def test_execute_empty_request(self, mock_batch_executor):
        request = EnrichmentRequest(
            valid_indicators_by_type=defaultdict(list),
            unsupported_items=[],
            unknown_items=[],
            duplicates_removed_count=0,
            sub_command_arguments={},
            include_raw_context=False,
        )

        service = EnrichmentService(request)
        result = service.execute()

        assert len(result.enriched_data) == 0
        assert len(result.execution_errors) == 0
        mock_batch_executor.execute_batch.assert_not_called()

    def test_execute_happy_path(self, mock_batch_executor):
        """
        Scenario: Standard execution.
        Mock Structure: List (Tasks) -> List (Batch Results) -> Tuple (Entry, HR, Err)
        """
        # Arrange Request
        valid_map = defaultdict(list)
        valid_map[IndicatorType.IP] = ["8.8.8.8"]
        request = EnrichmentRequest(
            valid_indicators_by_type=valid_map,
            unsupported_items=[],
            unknown_items=[],
            duplicates_removed_count=0,
            sub_command_arguments={},
            include_raw_context=False,
        )

        # Arrange Mock Output
        mock_entry_dict = {"Type": 1, "EntryContext": {"IPEnrichment": [{"Address": "8.8.8.8", "Geo": "US"}]}}

        # Structure: [ [ (Entry, HR, Err) ] ]
        mock_batch_executor.execute_batch.return_value = [[(mock_entry_dict, "### IP Info", None)]]

        # Act
        service = EnrichmentService(request)
        result = service.execute()

        # Assert
        assert len(result.enriched_data) == 1
        assert result.enriched_data[0]["Address"] == "8.8.8.8"
        assert "### IP Info" in result.markdown_sections[0]

    def test_execute_with_command_error(self, mock_batch_executor):
        """
        Scenario: Child command fails.
        Mock Structure: [ [ (None, None, ErrorString) ] ]
        """
        # Arrange Request
        valid_map = defaultdict(list)
        valid_map[IndicatorType.URL] = ["bad.com"]
        request = EnrichmentRequest(
            valid_indicators_by_type=valid_map,
            unsupported_items=[],
            unknown_items=[],
            duplicates_removed_count=0,
            sub_command_arguments={},
            include_raw_context=False,
        )

        # Arrange Mock Output
        mock_batch_executor.execute_batch.return_value = [[(None, None, "Error: Timeout connecting to API")]]

        # Act
        service = EnrichmentService(request)
        result = service.execute()

        # Assert
        assert len(result.enriched_data) == 0
        assert len(result.execution_errors) == 1
        assert "Timeout connecting to API" in result.execution_errors[0]

    def test_execute_mixed_results(self, mock_batch_executor):
        """
        Scenario: Two commands run; one succeeds (IP), one fails (URL).
        Mock Structure: [ [(SuccessTuple)], [(FailureTuple)] ]
        """
        # Arrange Request with 2 types
        valid_map = defaultdict(list)
        valid_map[IndicatorType.IP] = ["1.1.1.1"]
        valid_map[IndicatorType.URL] = ["bad.com"]

        request = EnrichmentRequest(
            valid_indicators_by_type=valid_map,
            unsupported_items=[],
            unknown_items=[],
            duplicates_removed_count=0,
            sub_command_arguments={},
            include_raw_context=False,
        )

        mock_ip_entry = {"EntryContext": {"IPEnrichment": [{"Address": "1.1.1.1"}]}}

        # Two items in the main list (one per command task)
        mock_batch_executor.execute_batch.return_value = [
            [(mock_ip_entry, "IP Table", None)],  # Result for Command 1 (IP)
            [(None, None, "404 Not Found")],  # Result for Command 2 (URL)
        ]

        # Act
        service = EnrichmentService(request)
        result = service.execute()

        # Assert
        # Success Check
        assert len(result.enriched_data) == 1
        assert result.enriched_data[0]["Address"] == "1.1.1.1"

        # Failure Check
        assert len(result.execution_errors) == 1
        assert "404 Not Found" in result.execution_errors[0]


class TestEnrichmentRequestBuilder:
    """
    Tests input parsing, deduplication, and validation logic.
    """

    @pytest.fixture
    def mock_execute_command(self, mocker):
        """Mocks the Demisto execute_command for text extraction."""
        # Update 'IndicatorEnrichment' to your actual file name
        return mocker.patch("IndicatorEnrichment.execute_command")

    @pytest.fixture
    def mock_arg_to_list(self, mocker):
        """Mocks the CommonServerPython argToList helper."""
        return mocker.patch(
            "IndicatorEnrichment.argToList", side_effect=lambda x, transform=None: [y.strip() for y in x.split(",")] if x else []
        )

    @pytest.fixture
    def mock_auto_detect(self, mocker):
        """Mocks the auto_detect_indicator_type function."""
        return mocker.patch("IndicatorEnrichment.auto_detect_indicator_type")

    def test_build_and_validate_happy_path_list(self, mock_arg_to_list, mock_auto_detect):
        """
        Scenario: Standard list input with one IP and one Domain.
        """
        raw_args = {"indicator_list": "1.1.1.1, google.com"}

        mock_arg_to_list.side_effect = lambda arg, transform=None: ["1.1.1.1", "google.com"]
        mock_auto_detect.side_effect = lambda x: "IP" if "1.1.1.1" in x else "Domain"

        builder = EnrichmentRequestBuilder(raw_args)
        request = builder.build_and_validate()

        assert request.total_valid_count == 2
        assert "1.1.1.1" in request.valid_indicators_by_type[IndicatorType.IP]
        assert "google.com" in request.valid_indicators_by_type[IndicatorType.DOMAIN]

    def test_build_and_validate_deduplication_text_vs_list(self, mock_execute_command, mock_arg_to_list, mock_auto_detect):
        """
        Scenario: The same IP appears in 'text' and 'indicator_list'.
        """
        raw_args = {"text": "check 8.8.8.8", "indicator_list": "8.8.8.8"}

        mock_execute_command.return_value = [{"EntryContext": {"ExtractedIndicators": {"IP": ["8.8.8.8"]}}}]
        mock_arg_to_list.return_value = ["8.8.8.8"]
        mock_auto_detect.return_value = "IP"

        builder = EnrichmentRequestBuilder(raw_args)
        request = builder.build_and_validate()

        assert request.total_valid_count == 1
        assert request.valid_indicators_by_type[IndicatorType.IP] == ["8.8.8.8"]
        assert request.duplicates_removed_count == 1

    def test_build_and_validate_mixed_valid_and_invalid(self, mock_arg_to_list, mock_auto_detect):
        """
        Scenario: Input contains mixed types: Valid (IP), Unsupported (IPv6), and Unknown.
        Goal: Verify bucketing logic works. (Must have at least 1 valid to succeed).
        """
        raw_args = {"indicator_list": "1.1.1.1, 2001:db8::1, bad_hash"}

        # Return all 3 items
        mock_arg_to_list.return_value = ["1.1.1.1", "2001:db8::1", "bad_hash"]

        # Define behavior: 1.1.1.1 is IP, 2001 is IPv6, bad_hash is None
        def auto_detect_side_effect(val):
            if "1.1.1.1" in val:
                return "IP"
            if "2001" in val:
                return "IPv6"
            return None

        mock_auto_detect.side_effect = auto_detect_side_effect

        builder = EnrichmentRequestBuilder(raw_args)
        request = builder.build_and_validate()

        # Verify Valid
        assert request.total_valid_count == 1
        assert "1.1.1.1" in request.valid_indicators_by_type[IndicatorType.IP]

        # Verify Unsupported (IPv6)
        assert len(request.unsupported_items) == 1
        assert request.unsupported_items[0].type == "IPv6"
        assert request.unsupported_items[0].value == "2001:db8::1"

        # Verify Unknown (bad_hash)
        assert len(request.unknown_items) == 1
        assert request.unknown_items[0] == "bad_hash"

    def test_validation_only_invalid_indicators(self, mock_arg_to_list, mock_auto_detect):
        """
        Scenario: Input contains *only* invalid/unsupported items (no valid ones).
        Goal: Verify that this raises ValidationError (because total_valid == 0).
        """
        raw_args = {"indicator_list": "2001:db8::1, bad_hash"}
        mock_arg_to_list.return_value = ["2001:db8::1", "bad_hash"]

        def auto_detect_side_effect(val):
            if "2001" in val:
                return "IPv6"
            return None

        mock_auto_detect.side_effect = auto_detect_side_effect

        builder = EnrichmentRequestBuilder(raw_args)

        # Must raise because we strictly require at least 1 valid indicator
        with pytest.raises(ValidationError) as excinfo:
            builder.build_and_validate()

        assert "No valid indicators provided" in str(excinfo.value)

    def test_validation_no_inputs(self, mock_arg_to_list):
        """
        Scenario: No text, no list provided.
        """
        raw_args = {}
        mock_arg_to_list.return_value = []

        builder = EnrichmentRequestBuilder(raw_args)

        with pytest.raises(ValidationError) as excinfo:
            builder.build_and_validate()

        assert "No valid indicators provided" in str(excinfo.value)

    def test_graceful_exit_text_only_nothing_found(self, mock_execute_command, mock_arg_to_list):
        """
        Scenario: Text provided, but extractIndicators finds nothing.
        """
        raw_args = {"text": "hello world"}
        mock_execute_command.return_value = [{"EntryContext": {}}]
        mock_arg_to_list.return_value = []

        builder = EnrichmentRequestBuilder(raw_args)

        with pytest.raises(GracefulExit) as excinfo:
            builder.build_and_validate()

        assert "No valid indicators provided" in str(excinfo.value)

    def test_limit_enforcement(self, mock_arg_to_list, mock_auto_detect):
        """
        Scenario: More than 100 valid indicators found.
        """
        many_ips = [f"1.1.1.{i}" for i in range(101)]
        raw_args = {"indicator_list": ",".join(many_ips)}

        mock_arg_to_list.return_value = many_ips
        mock_auto_detect.return_value = "IP"

        builder = EnrichmentRequestBuilder(raw_args)

        with pytest.raises(ValidationError) as excinfo:
            builder.build_and_validate()

        assert "Indicator limit exceeded" in str(excinfo.value)

    def test_limit_bypass(self, mock_arg_to_list, mock_auto_detect):
        """
        Scenario: 101 IPs found, but ignore_indicator_limit is True.
        """
        many_ips = [f"1.1.1.{i}" for i in range(101)]
        raw_args = {"indicator_list": ",".join(many_ips), "ignore_indicator_limit": "true"}

        mock_arg_to_list.return_value = many_ips
        mock_auto_detect.return_value = "IP"

        builder = EnrichmentRequestBuilder(raw_args)
        request = builder.build_and_validate()

        assert request.total_valid_count == 101


class TestMain:
    """
    Tests the entry point execution, ensuring the correct flow between
    Builder -> Service -> Formatter, and correct handling of exceptions.
    """

    @pytest.fixture
    def mock_demisto_args(self, mocker):
        return mocker.patch("IndicatorEnrichment.demisto.args")

    @pytest.fixture
    def mock_return_results(self, mocker):
        return mocker.patch("IndicatorEnrichment.return_results")

    @pytest.fixture
    def mock_return_error(self, mocker):
        return mocker.patch("IndicatorEnrichment.return_error")

    @pytest.fixture
    def mock_components(self, mocker):
        """Mocks the classes instantiated inside main()."""
        mocks = {
            "builder_cls": mocker.patch("IndicatorEnrichment.EnrichmentRequestBuilder"),
            "service_cls": mocker.patch("IndicatorEnrichment.EnrichmentService"),
            "formatter_cls": mocker.patch("IndicatorEnrichment.ResponseFormatter"),
        }
        return mocks

    def test_main_happy_path(self, mock_demisto_args, mock_return_results, mock_return_error, mock_components):
        """
        Scenario: Successful execution.
        Flow: Args -> Build -> Execute -> Format -> return_results.
        """
        # Arrange
        mock_demisto_args.return_value = {"indicator_list": "1.1.1.1"}

        # Setup Component Mocks
        mock_builder_instance = mock_components["builder_cls"].return_value

        mock_builder_instance.build_and_validate.return_value = "dummy_request"

        mock_service_instance = mock_components["service_cls"].return_value
        mock_service_instance.execute.return_value = "dummy_result"

        mock_formatter_instance = mock_components["formatter_cls"].return_value
        mock_formatter_instance.format.return_value = "final_command_results"

        # Act
        main()

        # Assert
        # 1. Builder Check
        mock_components["builder_cls"].assert_called_once_with({"indicator_list": "1.1.1.1"})

        # 2. Service Check
        # Verify the *Constructor* received the request (from the builder mock)
        mock_components["service_cls"].assert_called_once_with("dummy_request")
        # Verify execute() was called with NO arguments
        mock_service_instance.execute.assert_called_once_with()

        # 3. Formatter Check
        mock_formatter_instance.format.assert_called_once_with("dummy_result", "dummy_request")

        # 4. Final Output Check
        mock_return_results.assert_called_once_with("final_command_results")
        mock_return_error.assert_not_called()

    def test_main_graceful_exit(self, mock_demisto_args, mock_return_results, mock_return_error, mock_components):
        """
        Scenario: Builder raises GracefulExit (e.g. text input with no indicators).
        Flow: Args -> Build -> GracefulExit -> return_results(info_message).
        """
        # Arrange
        mock_demisto_args.return_value = {"text": "nothing here"}

        # Make builder raise the exception
        mock_builder_instance = mock_components["builder_cls"].return_value

        mock_builder_instance.build_and_validate.side_effect = GracefulExit("No indicators found.")

        # Act
        main()

        # Assert
        # Should call return_results (Green check), NOT return_error
        assert mock_return_results.call_count == 1
        args = mock_return_results.call_args[0][0]
        assert args.readable_output == "No indicators found."

        mock_return_error.assert_not_called()

    def test_main_validation_error(self, mock_demisto_args, mock_return_results, mock_return_error, mock_components):
        """
        Scenario: Builder raises ValidationError (e.g. limit exceeded or garbage list).
        Flow: Args -> Build -> ValidationError -> return_error.
        """
        # Arrange
        mock_demisto_args.return_value = {"indicator_list": "garbage"}

        # Make builder raise exception
        mock_builder_instance = mock_components["builder_cls"].return_value

        mock_builder_instance.build_and_validate.side_effect = ValidationError("Invalid input.")

        # Act
        main()

        # Assert
        # Should call return_error (Red X)
        mock_return_error.assert_called_once_with("Invalid input.")
        mock_return_results.assert_not_called()

    def test_main_fatal_execution_error(self, mock_demisto_args, mock_return_results, mock_return_error, mock_components):
        """
        Scenario: Formatter raises ValidationError (Fatal Execution Error).
        Flow: Args -> Build -> Execute -> Format -> ValidationError -> return_error.
        """
        # Arrange
        mock_builder_instance = mock_components["builder_cls"].return_value

        # We need this to return a value so main() proceeds to the service execution
        mock_builder_instance.build_and_validate.return_value = "req"

        mock_service_instance = mock_components["service_cls"].return_value
        mock_service_instance.execute.return_value = "res"

        # Make formatter raise the fatal error
        mock_formatter_instance = mock_components["formatter_cls"].return_value
        mock_formatter_instance.format.side_effect = ValidationError("Fatal execution error.")

        # Act
        main()

        # Assert
        mock_return_error.assert_called_once_with("Fatal execution error.")

    def test_main_system_exception(self, mock_demisto_args, mock_return_results, mock_return_error, mock_components, mocker):
        """
        Scenario: Unexpected crash (e.g. NoneType error).
        Flow: Args -> Build -> Exception -> return_error (caught by generic try/except).
        """
        # Arrange
        mock_demisto_error = mocker.patch("IndicatorEnrichment.demisto.error")  # To verify logging

        # Simulate a crash in the builder
        mock_components["builder_cls"].side_effect = RuntimeError("Unexpected Crash")

        # Act
        main()

        # Assert
        # 1. return_error is called with a generic wrapper message
        mock_return_error.assert_called_once()
        error_msg = mock_return_error.call_args[0][0]
        assert "Failed to execute !indicator-enrichment" in error_msg
        assert "Unexpected Crash" in error_msg

        # 2. demisto.error is called to log the stack trace
        mock_demisto_error.assert_called()
