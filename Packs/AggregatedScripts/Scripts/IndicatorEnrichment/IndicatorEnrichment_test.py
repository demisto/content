import pytest
import demistomock as demisto

import IndicatorEnrichment
from IndicatorEnrichment import (
    main,
    FatalArgException,
    NO_VALID_INDICATORS_MESSAGE,
    ERR_INDICATOR_LIMIT_EXCEEDED_TEMPLATE,
)

# -------------------------
# Helpers / Fixtures
# -------------------------


def normalize_captured_command(cmd_obj):
    """
    Extract (command_name, args_dict) from captured Command-like object/dict.
    Works with several common shapes.
    """
    # command name extraction
    name = None
    for attr in ("command", "name", "cmd", "command_name"):
        if hasattr(cmd_obj, attr):
            name = getattr(cmd_obj, attr)
            break
    if name is None and isinstance(cmd_obj, dict):
        name = cmd_obj.get("command") or cmd_obj.get("cmd") or cmd_obj.get("name")

    # args extraction
    args = {}
    for arg_attr in ("args", "kwargs", "args_dict", "raw_args", "params"):
        if hasattr(cmd_obj, arg_attr):
            possible = getattr(cmd_obj, arg_attr)
            if isinstance(possible, dict):
                args = possible
                break
            try:
                args = dict(possible)
                break
            except Exception:
                pass

    if not args and isinstance(cmd_obj, dict):
        args = cmd_obj.get("args") or cmd_obj.get("kwargs") or cmd_obj.get("params") or {}

    # ensure plain dict where possible
    try:
        if not isinstance(args, dict):
            args = dict(args)
    except Exception:
        pass

    return name, args


@pytest.fixture
def return_handlers(mocker):
    """Patch return_results and return_error and return their mocks."""
    results_mock = mocker.patch.object(IndicatorEnrichment, "return_results")
    error_mock = mocker.patch.object(IndicatorEnrichment, "return_error")
    return results_mock, error_mock


@pytest.fixture
def patch_demisto_args(mocker):
    """Helper fixture to patch demisto.args with a function that tests call."""
    def _patch(args_dict):
        return mocker.patch.object(demisto, "args", return_value=args_dict)
    return _patch


@pytest.fixture
def mock_extract_indicators(mocker):
    """
    Patch execute_command for extractIndicators; returns a setter function.
    Usage:
        mock_set = mock_extract_indicators
        mock_set([entry_dict])  # will patch execute_command to return that
    """
    def _set(return_value):
        def _mock_execute(name, args, extract_contents=False):
            # ensure we only intercept extractIndicators in these fixtures
            assert name == "extractIndicators"
            return return_value
        return mocker.patch.object(IndicatorEnrichment, "execute_command", side_effect=_mock_execute)
    return _set


@pytest.fixture
def batch_executor_factory(mocker):
    """
    Returns a helper that patches IndicatorEnrichment.BatchExecutor to return
    a DummyBatchExecutor whose execute_batch returns the supplied batches list.
    batches is a list where each item corresponds to a command and is itself
    a list of tuples (entry_dict, hr_string, error_string).
    """
    def _set(batches):
        class DummyBatchExecutor:
            def __init__(self, *a, **k):
                pass
            def execute_batch(self, commands, brands_to_run=None, verbose=False):
                return batches
        return mocker.patch.object(IndicatorEnrichment, "BatchExecutor", return_value=DummyBatchExecutor())
    return _set


@pytest.fixture
def capture_batch_commands(mocker):
    """
    Capture the 'commands' passed into BatchExecutor.execute_batch.
    Returns (state, set_return) where:
      - state['captured_calls'] is a list of commands-lists for each execute_batch call.
      - set_return(batches) sets what execute_batch returns.
    """
    state = {"captured_calls": [], "batches_to_return": None}

    class DummyBatchExecutor:
        def __init__(self, *args, **kwargs):
            pass

        def execute_batch(self, commands, brands_to_run=None, verbose=False):
            state["captured_calls"].append(list(commands))
            return state["batches_to_return"] if state["batches_to_return"] is not None else []

    mocker.patch.object(IndicatorEnrichment, "BatchExecutor", return_value=DummyBatchExecutor())

    def set_return(batches):
        state["batches_to_return"] = batches

    return state, set_return


@pytest.fixture
def assert_expected_commands():
    """
    Returns a helper to assert captured commands match exactly expected mapping.
    Usage:
        state, _ = capture_batch_commands
        assert_expected_commands(state, {"ip-enrichment": {"ip_list": ["1.1.1.1"]}})
    """
    def _assert(state, expected: dict, call_index: int = 0):
        captured_calls = state.get("captured_calls", [])
        if not captured_calls:
            raise AssertionError("No execute_batch calls were captured.")
        if call_index >= len(captured_calls):
            raise AssertionError(f"Requested call_index {call_index} >= number of captured calls {len(captured_calls)}")

        commands_list = captured_calls[call_index]
        normalized = [normalize_captured_command(c) for c in commands_list]
        captured_map = {name: args for name, args in normalized}

        if set(captured_map.keys()) != set(expected.keys()):
            raise AssertionError(f"Captured command names {set(captured_map.keys())} != expected {set(expected.keys())}")

        for cmd_name, exp_args in expected.items():
            got_args = captured_map.get(cmd_name)
            if got_args != exp_args:
                raise AssertionError(f"Args mismatch for '{cmd_name}'.\nExpected: {exp_args}\nGot: {got_args}")

    return _assert


@pytest.fixture
def last_cmdresult(return_handlers):
    """
    After the script runs, get the CommandResults object passed to return_results.
    Usage: cmd = last_cmdresult(); then inspect cmd.readable_output, cmd.outputs
    """
    results_mock, _ = return_handlers
    def _get():
        assert results_mock.call_count >= 1, "return_results not called"
        return results_mock.call_args[0][0]
    return _get


def make_enrichment_entry(enrich_key: str, value: str, brand="TIM", extra_results=None, hr=None):
    """
    build a raw "entry" dict an underlying enrichment script would return.
    enrich_key: e.g. "IPEnrichment(val.Value && val.Value == obj.Value)"
    value: string value to put in the enrichment object (Value)
    extra_results: list of result dicts to include under Results
    hr: optional human readable string for the entry
    """
    results = extra_results or [{"Brand": brand, "Data": value, "Score": 1}]
    entry = {
        "ModuleName": "",
        "Brand": "",
        "Type": 1,
        "EntryContext": {
            enrich_key: [
                {
                    "Value": value,
                    "MaxScore": max((r.get("Score", 0) for r in results), default=1),
                    "Status": "Fresh",
                    "Results": results,
                }
            ]
        },
        "HumanReadable": hr or (
            "### Final Results\n"
            "|Brand|Arguments|Status|Message|\n"
            "|---|---|---|---|\n"
            f"| {brand} | {value} | Success | Found indicator from brands: {brand} |\n"
        )
    }
    return entry


def expected_indicator_entry(type_name, value, raw_obj=None, status=None, message=None):
    """
    Build the expected context item for IndicatorEnrichment.
    raw_obj is the unpacked underlying object (optional).
    """
    base = {"Type": type_name, "Value": value}
    if raw_obj:
        for k, v in raw_obj.items():
            if k != "Value":
                base[k] = v
    if status:
        base["Status"] = status
    if message:
        base["Message"] = message
    return base


# -------------------------
# Tests
# -------------------------


class TestMainWrapper:
    """
    Tests for the main() wrapper, ensuring it:
    - Pulls arguments from demisto.args()
    - Delegates to indicator_enrichment_command()
    - Uses return_results() on success
    - Uses return_error() on FatalArgException
    """

    def test_main_calls_indicator_enrichment_command_and_handles_success(self, mocker, return_handlers):
        """
        Case:
            main() is invoked with valid arguments that result in a successful indicator_enrichment_command() call.

        Example:
            demisto.args() returns {"indicators_list": "1.1.1.1"} and
            indicator_enrichment_command() returns a dummy result.

        Expectation:
            - main() calls indicator_enrichment_command() with demisto.args().
            - return_results() is called once with that result.
            - return_error() is NOT called.
        """
        # Arrange
        mocker.patch.object(demisto, "args", return_value={"indicators_list": "1.1.1.1"})

        mock_indicator = mocker.patch.object(
            IndicatorEnrichment,
            "indicator_enrichment_command",
            return_value="OK",
        )

        mock_return_results, mock_return_error = return_handlers

        # Act
        main()

        # Assert
        mock_indicator.assert_called_once_with({"indicators_list": "1.1.1.1"})
        mock_return_results.assert_called_once_with("OK")
        mock_return_error.assert_not_called()

    def test_main_handles_fatalargexception_via_return_error(self, mocker, return_handlers):
        """
        Case:
            main() is invoked with invalid arguments that cause
            indicator_enrichment_command() to raise FatalArgException.

        Example:
            demisto.args() returns {}, and indicator_enrichment_command()
            raises FatalArgException(NO_VALID_INDICATORS_MESSAGE).

        Expectation:
            - indicator_enrichment_command() is called once.
            - return_error() is called once with the exception message (or
              a string that contains it).
            - return_results() is NOT called.
        """
        fake_args = {}
        mocker.patch.object(demisto, "args", return_value=fake_args)

        mocker.patch.object(
            IndicatorEnrichment,
            "indicator_enrichment_command",
            side_effect=FatalArgException("No valid indicators provided"),
        )

        mock_return_results, mock_return_error = return_handlers

        # Act
        main()

        # Assert
        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        msg = mock_return_error.call_args[0][0]
        assert "No valid indicators provided" == msg

    def test_main_handles_exception_via_return_error(self, mocker, return_handlers):
        """
        Case:
            main() is invoked with valid arguments
            indicator_enrichment_command() executes, and raises unexpect Exception

        Example:
            demisto.args() returns {"indicators_list": "1.1.1.1"}, and indicator_enrichment_command()
            raises Exception().

        Expectation:
            - indicator_enrichment_command() is called once.
            - return_error() is called once with the exception message and the expected prefix.
            - return_results() is NOT called.
        """
        mocker.patch.object(demisto, "args", return_value={"indicators_list": "1.1.1.1"})

        mocker.patch.object(
            IndicatorEnrichment,
            "indicator_enrichment_command",
            side_effect=Exception("exception raised from ip-enrichment"),
        )

        mock_return_results, mock_return_error = return_handlers

        # Act
        main()

        # Assert
        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        msg = mock_return_error.call_args[0][0]
        assert ('Failed to execute !indicator-enrichment. Error: exception raised from ip-enrichment') == msg


class TestArgsValidation:
    """
    Argument validation tests executed through main()
    ensuring full inline E2E argument behavior.
    """

    def test_no_args_calls_return_error(self, mocker, return_handlers):
        """
        Case:
            Both text and indicators_list are missing.

        Example:
            !indicators-enrichment

        Expectation:
            - return_error(NO_VALID_INDICATORS_MESSAGE) is called.
            - return_results is not called.
        """
        mocker.patch.object(demisto, "args", return_value={})

        mock_return_results, mock_return_error = return_handlers

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        assert NO_VALID_INDICATORS_MESSAGE == mock_return_error.call_args[0][0]

    def test_empty_indicators_list_only_calls_return_error(self, mocker, return_handlers):
        """
        Case:
            indicators_list is provided but empty/whitespace.

        Example:
            !indicators-enrichment indicators_list="   "

        Expectation:
            - return_error(NO_VALID_INDICATORS_MESSAGE)
        """
        mocker.patch.object(demisto, "args", return_value={"indicators_list": "   "})

        mock_return_results, mock_return_error = return_handlers

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        assert NO_VALID_INDICATORS_MESSAGE == mock_return_error.call_args[0][0]

    def test_both_text_and_list_empty_calls_return_error(self, mocker, return_handlers):
        """
        Case:
            Both text and indicators_list provided but empty/whitespace.

        Example:
            !indicators-enrichment text="   " indicators_list="  "

        Expectation:
            - return_error(NO_VALID_INDICATORS_MESSAGE)
        """
        mocker.patch.object(
            demisto,
            "args",
            return_value={"text": "   ", "indicators_list": "   "},
        )

        mock_return_results, mock_return_error = return_handlers

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        assert NO_VALID_INDICATORS_MESSAGE == mock_return_error.call_args[0][0]

    def test_text_only_no_supported_indicators_returns_informational(self, mocker, return_handlers):
        """
        Case:
            extractIndicators finds only unsupported/unknown types.

        Example:
            !indicators-enrichment text="fe80::1 junk"

        Expectation:
            - return_results(CommandResults(NO_VALID_INDICATORS_MESSAGE))
            - return_error is NOT called
        """
        def mock_execute(name, args, extract_contents=False):
            return [{
                "EntryContext": {
                    "ExtractedIndicators": {
                        "IPv6": ["fe80::1"],
                        "Unknown": ["junk"]
                    }
                }
            }]

        mocker.patch.object(IndicatorEnrichment, "execute_command", side_effect=mock_execute)
        mocker.patch.object(demisto, "args", return_value={"text": "fe80::1 junk"})

        mock_return_results, mock_return_error = return_handlers

        main()

        mock_return_error.assert_not_called()
        mock_return_results.assert_called_once()
        result = mock_return_results.call_args[0][0]
        assert getattr(result, "readable_output") == NO_VALID_INDICATORS_MESSAGE

    def test_text_only_no_valid_indicators_returns_informational(self, mocker, return_handlers):
        """
        Case:
            text is provided but contains no valid indicators.
            indicators_list is not provided.

        Example:
            !indicators-enrichment text="nothing"

        Expectation:
            - return_results is called once with the informational
              NO_VALID_INDICATORS_MESSAGE.
            - return_error is NOT called.
            - No batch execution performed.
        """
        mocker.patch.object(demisto, "args", return_value={"text": "nothing"})

        def mock_extract(name, args, extract_contents=False):
            return [{
                "EntryContext": {
                    "ExtractedIndicators": {
                        # empty dict = no indicators parsed
                    }
                }
            }]

        mocker.patch.object(IndicatorEnrichment, "execute_command", side_effect=mock_extract)

        mock_return_results, mock_return_error = return_handlers

        mock_batch = mocker.patch.object(IndicatorEnrichment, "BatchExecutor")

        main()

        mock_return_error.assert_not_called()
        mock_batch.assert_not_called()
        mock_return_results.assert_called_once()

        result = mock_return_results.call_args[0][0]
        assert IndicatorEnrichment.NO_VALID_INDICATORS_MESSAGE == result.readable_output

    def test_indicators_list_only_unsupported_calls_return_error(self, mocker, return_handlers):
        """
        Case:
            Only unsupported indicators in indicators_list.

        Example:
            !indicators-enrichment indicators_list="10.0.0.0/8,fe80::1"

        Expectation:
            - return_error(NO_VALID_INDICATORS_MESSAGE)
        """
        vals = ["10.0.0.0/8", "fe80::1"]

        def mock_detect(v):
            if v == "10.0.0.0/8":
                return "CIDR"
            if v == "fe80::1":
                return "IPv6"
            return None

        mocker.patch.object(IndicatorEnrichment, "auto_detect_indicator_type", side_effect=mock_detect)
        mocker.patch.object(demisto, "args", return_value={"indicators_list": ",".join(vals)})

        mock_return_results, mock_return_error = return_handlers

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        assert NO_VALID_INDICATORS_MESSAGE == mock_return_error.call_args[0][0]

    def test_indicators_list_all_invalid_calls_return_error(self, mocker, return_handlers):
        """
        Case:
            indicators_list contains values with no detectable type.

        Example:
            !indicators-enrichment indicators_list="foo,bar"

        Expectation:
            - return_error(NO_VALID_INDICATORS_MESSAGE)
        """
        def mock_detect(_):
            return None  # everything is invalid

        mocker.patch.object(IndicatorEnrichment, "auto_detect_indicator_type", side_effect=mock_detect)
        mocker.patch.object(demisto, "args", return_value={"indicators_list": "foo,bar"})

        mock_return_results, mock_return_error = return_handlers

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        assert NO_VALID_INDICATORS_MESSAGE == mock_return_error.call_args[0][0]

    def test_both_text_and_list_no_supported_calls_return_error(self, mocker, return_handlers):
        """
        Case:
            Both text & list exist but yield no supported types.

        Example:
            !indicators-enrichment text="fe80::1" indicators_list="10.0.0.0/8,foo"

        Expectation:
            - return_error(NO_VALID_INDICATORS_MESSAGE)
        """
        def mock_extract(name, args, extract_contents=False):
            return [{
                "EntryContext": {
                    "ExtractedIndicators": {
                        "IPv6": ["fe80::1"],
                        "Unknown": ["junk"]
                    }
                }
            }]

        def mock_detect(v):
            if v == "10.0.0.0/8":
                return "CIDR"
            if v == "foo":
                return None
            return None

        mocker.patch.object(IndicatorEnrichment, "execute_command", side_effect=mock_extract)
        mocker.patch.object(IndicatorEnrichment, "auto_detect_indicator_type", side_effect=mock_detect)

        mocker.patch.object(
            demisto,
            "args",
            return_value={"text": "fe80::1", "indicators_list": "10.0.0.0/8,foo"},
        )

        mock_return_results, mock_return_error = return_handlers

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        assert NO_VALID_INDICATORS_MESSAGE == mock_return_error.call_args[0][0]

    def test_indicator_limit_exceeded_calls_return_error(self, mocker, return_handlers):
        """
        Case:
            >100 supported indicators and ignore_indicator_limit is false.

        Example:
            !indicators-enrichment indicators_list="1.1.1.1,1.1.1.2,...(102 items)"

        Expectation:
            - return_error()
            - BatchExecutor NOT called
        """
        ips = [f"1.1.1.{i}" for i in range(1, 102)]

        mocker.patch.object(IndicatorEnrichment, "auto_detect_indicator_type", return_value="IP")
        mocker.patch.object(demisto, "args", return_value={"indicators_list": ",".join(ips)})

        mock_batch = mocker.patch.object(IndicatorEnrichment, "BatchExecutor")
        mock_return_results, mock_return_error = return_handlers

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        assert ERR_INDICATOR_LIMIT_EXCEEDED_TEMPLATE.format(found="101",limit="100",)  == mock_return_error.call_args[0][0]
        mock_batch.assert_not_called()

    def test_indicator_limit_exceeded_ignore_flag_runs_batch(self, mocker, return_handlers):
        """
        Case:
            >100 supported indicators but ignore_indicator_limit=true.

        Example:
            !indicators-enrichment indicators_list="..." ignore_indicator_limit=true

        Expectation:
            - return_error NOT called
            - BatchExecutor.execute_batch is called
            - return_results called
        """
        ips = [f"1.1.1.{i}" for i in range(1, 102)]

        mocker.patch.object(IndicatorEnrichment, "auto_detect_indicator_type", return_value="IP")
        mocker.patch.object(
            demisto,
            "args",
            return_value={"indicators_list": ",".join(ips), "ignore_indicator_limit": "true"},
        )

        mock_batch_cls = mocker.patch.object(IndicatorEnrichment, "BatchExecutor")
        mock_batch_instance = mock_batch_cls.return_value
        mock_batch_instance.execute_batch.return_value = []

        mock_return_results, mock_return_error = return_handlers

        main()

        mock_return_error.assert_not_called()
        mock_batch_cls.assert_called_once()
        mock_batch_instance.execute_batch.assert_called()
        mock_return_results.assert_called_once()


class TestEnrichmentE2E:
    """
    End-to-end tests (extraction -> mapping -> batch execution -> context + HR).
    These tests also assert that the correct commands are created and that the
    exact args are passed to them.
    """

    def test_extract_supported_and_unsupported_from_text(
        self, patch_demisto_args, mock_extract_indicators, batch_executor_factory, return_handlers, last_cmdresult,
        capture_batch_commands, assert_expected_commands
    ):
        """
        Case:
            text contains mix of supported (IP & URL) and unsupported/unknown (IPv6, junk).

        Example:
            !indicators-enrichment text="1.1.1.1 fe80::1 junk and a URL https://example.com"

        Expectation:
            - Exact HR output must match EXPECTED_HR string below.
            - Exact context output must match EXPECTED_CTX dictionary below.
            - ip-enrichment and url-enrichment are called with exact args.
        """
        # Arrange
        patch_demisto_args({"text": "1.1.1.1 fe80::1 junk and a URL https://example.com"})

        mock_extract_indicators([{
            "EntryContext": {
                "ExtractedIndicators": {
                    "IP": ["1.1.1.1"],
                    "IPv6": ["fe80::1"],
                    "Unknown": ["junk"],
                    "URL": ["https://example.com"]
                }
            }
        }])

        ip_entry = make_enrichment_entry("IPEnrichment(val.Value && val.Value == obj.Value)", "1.1.1.1")
        url_entry = make_enrichment_entry("URLEnrichment(val.Value && val.Value == obj.Value)", "https://example.com")

        # set what execute_batch returns and also capture commands
        state, set_return = capture_batch_commands
        set_return([[(ip_entry, ip_entry["HumanReadable"], "")], [(url_entry, url_entry["HumanReadable"], "")]])

        # Act
        main()

        # Assert HR & context
        results_mock, error_mock = return_handlers
        error_mock.assert_not_called()
        results_mock.assert_called_once()

        cmd = last_cmdresult()
        hr = cmd.readable_output

        EXPECTED_HR = (
            "### ip-enrichment\n\n"
            "### Final Results\n"
            "|Brand|Arguments|Status|Message|\n"
            "|---|---|---|---|\n"
            "| TIM | 1.1.1.1 | Success | Found indicator from brands: TIM |\n\n\n"
            "### url-enrichment\n\n"
            "### Final Results\n"
            "|Brand|Arguments|Status|Message|\n"
            "|---|---|---|---|\n"
            "| TIM | https://example.com | Success | Found indicator from brands: TIM |\n\n\n"
            "### Invalid or unsupported indicators\n"
            "|Type|Value|Status|Message|\n"
            "|---|---|---|---|\n"
            "| IPv6 | fe80::1 | Error | No script supports this indicator type. |\n"
            "| Unknown | junk | Error | Not a valid indicator. |\n"
        )

        assert hr == EXPECTED_HR

        expected_ctx = {
            "IndicatorEnrichment": [
                expected_indicator_entry("IP", "1.1.1.1",
                                         raw_obj=ip_entry["EntryContext"]["IPEnrichment(val.Value && val.Value == obj.Value)"][0]),
                expected_indicator_entry("URL", "https://example.com",
                                         raw_obj=url_entry["EntryContext"]["URLEnrichment(val.Value && val.Value == obj.Value)"][0]),
                expected_indicator_entry("IPv6", "fe80::1", status="Error", message="No script supports this indicator type."),
                expected_indicator_entry("Unknown", "junk", status="Error", message="Not a valid indicator.")
            ]
        }
        assert cmd.outputs == expected_ctx

        # Assert commands and exact args
        expected = {
            "ip-enrichment": {"ip_list": ["1.1.1.1"]},
            "url-enrichment": {"url_list": ["https://example.com"]},
        }
        assert_expected_commands(state, expected)

    def test_merging_text_and_list_with_dedup_keeps_all_types_from_text(
        self, patch_demisto_args, mock_extract_indicators, batch_executor_factory, return_handlers, last_cmdresult,
        capture_batch_commands, assert_expected_commands
    ):
        """
        Case:
            Same indicator appears in text AND indicators_list, BUT text extraction
            returns multiple types (URL + Domain) while indicator_list detects only 1 type.

        Example:
            !indicator-enrichment text="Check https://google.com" indicators_list="https://google.com"

        Expectation:
            - Dedup removes duplicate VALUE only AFTER type mapping.
            - Types from text MUST be preserved (URL + Domain).
            - Underlying called for BOTH domain-enrichment AND url-enrichment with exact args.
            - Final context contains both entries (Type "Domain" and Type "URL") once each.
        """
        # Arrange: text contains both domain+url via extractIndicators; indicators_list contains the same URL
        patch_demisto_args({"text": "Check https://google.com", "indicators_list": "https://google.com"})

        mock_extract_indicators([{
            "EntryContext": {
                "ExtractedIndicators": {
                    "Domain": ["google.com"],
                    "URL": ["https://google.com"]
                }
            }
        }])

        # Build underlying entries for both domain and url
        domain_entry = make_enrichment_entry("DomainEnrichment(val.Value && val.Value == obj.Value)", "google.com")
        url_entry = make_enrichment_entry("URLEnrichment(val.Value && val.Value == obj.Value)", "https://google.com")

        # capture commands & set return batches
        state, set_return = capture_batch_commands
        set_return([[(domain_entry, domain_entry["HumanReadable"], "")],
                    [(url_entry, url_entry["HumanReadable"], "")]])

        # Act
        main()

        # Assert return handlers
        results_mock, error_mock = return_handlers
        error_mock.assert_not_called()
        results_mock.assert_called_once()

        # Check HR: we expect both domain and url final results present
        cmd = last_cmdresult()
        hr = cmd.readable_output
        EXPECTED_HR = ('Note: Removed 1 duplicate indicator occurrences before enrichment.\n'
                 '\n'
                 '### domain-enrichment\n'
                 '\n'
                 '### Final Results\n'
                 '|Brand|Arguments|Status|Message|\n'
                 '|---|---|---|---|\n'
                 '| TIM | google.com | Success | Found indicator from brands: TIM |\n'
                 '\n'
                 '\n'
                 '### url-enrichment\n'
                 '\n'
                 '### Final Results\n'
                 '|Brand|Arguments|Status|Message|\n'
                 '|---|---|---|---|\n'
                 '| TIM | https://google.com | Success | Found indicator from brands: TIM |\n')
        assert hr == EXPECTED_HR

        # Expected context: both Domain and URL entries, each once
        expected_ctx = {
            "IndicatorEnrichment": [
                expected_indicator_entry(
                    "Domain", "google.com",
                    raw_obj=domain_entry["EntryContext"]["DomainEnrichment(val.Value && val.Value == obj.Value)"][0]
                ),
                expected_indicator_entry(
                    "URL", "https://google.com",
                    raw_obj=url_entry["EntryContext"]["URLEnrichment(val.Value && val.Value == obj.Value)"][0]
                )
            ]
        }
        assert cmd.outputs == expected_ctx

        # Assert commands created and exact args used
        expected = {
            "domain-enrichment": {"domain_list": ["google.com"]},
            "url-enrichment": {"url_list": ["https://google.com"]},
        }
        assert_expected_commands(state, expected)

    def test_raw_context_true_includes_raw_root_and_indicator_enrichment(
        self, patch_demisto_args, mock_extract_indicators, batch_executor_factory, return_handlers, last_cmdresult,
        capture_batch_commands, assert_expected_commands
    ):
        """
        Case:
            raw_context=true => we should include the original underlying enrichment
            object at root (e.g., 'IPEnrichment') plus the aggregated 'IndicatorEnrichment' list.
            Also underlying scripts may return Core and EndpointData entries at root which must be preserved.

        Example:
            !indicator-enrichment text="1.1.1.1" raw_context=true

        Expectation:
            - Underlying called for ip-enrichment with exact args.
            - Final context contains both IndicatorEnrichment and IPEnrichment
        """
        patch_demisto_args({"text": "1.1.1.1", "raw_context": "true"})

        # extractIndicators says IP
        mock_extract_indicators([{
            "EntryContext": {"ExtractedIndicators": {"IP": ["1.1.1.1"]}}
        }])

        # Build an ip entry that also includes Core and EndpointData in its EntryContext --
        # this simulates an underlying script returning Core and EndpointData as part of its EntryContext
        ip_entry = make_enrichment_entry("IPEnrichment(val.Value && val.Value == obj.Value)", "1.1.1.1")
        # Simulate underlying script also returning root Core and EndpointData keys (as if its EntryContext had them)
        # For the batch return, we include the original (raw) entry so that when raw_context=True the script can put it in root
        # We'll craft a second structure to simulate the raw root keys the underlying script would add to EntryContext.
        raw_root = {
            "ModuleName": "",
            "Brand": "",
            "Type": 1,
            "EntryContext": {
                "Core": {"AnalyticsPrevalence": {"Ip": [{"value": False, "ip_address": "1.1.1.1"}]}},
                "EndpointData": [
                    {"Brand": "CrowdstrikeFalcon", "IPAddress": "1.1.1.1", "Message": "Command failed - no endpoint found"}],
                "IPEnrichment": ip_entry["EntryContext"][
                    "IPEnrichment(val.Value && val.Value == obj.Value)"]
            },
            "HumanReadable": ip_entry["HumanReadable"]
        }

        state, set_return = capture_batch_commands
        # return the unpacked entry (for aggregated unpacking) and the raw root so the script can copy root keys when raw_context=True
        set_return([[(raw_root, "", "")]])

        main()
        results_mock, error_mock = return_handlers
        error_mock.assert_not_called()
        results_mock.assert_called_once()

        cmd = last_cmdresult()
        # Context should include Core, EndpointData at top-level and IndicatorEnrichment list
        ctx = cmd.outputs
        assert "Core" in ctx
        assert "EndpointData" in ctx
        assert "IndicatorEnrichment" in ctx
        assert "IPEnrichment" in ctx
        # IndicatorEnrichment should contain the IP unpacked result with Type added
        ie = ctx["IndicatorEnrichment"]
        assert isinstance(ie, list) and ie[0]["Type"] == "IP" and ie[0]["Value"] == "1.1.1.1"

        # Verify that the IPEnrichment and IndicatorEnrichment are the same besides for the "Type" key
        ip = ctx["IPEnrichment"]
        ie[0].pop("Type")
        assert ip == ie

    def test_mapping_all_supported_types_calls_correct_commands(
        self, patch_demisto_args, mock_extract_indicators, batch_executor_factory, return_handlers, last_cmdresult,
        capture_batch_commands, assert_expected_commands
    ):
        """
        Case:
            Verify mapping for IP, URL, Domain, CVE, File -> correct commands & arg names

        Example:
            !indicator-enrichment indicator_list="1.1.1.1,https://example.com,example.com,CVE-2025-0001,
                                                    badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0"

        Expectation:
            - Calls the correct underlying scripts
        """
        patch_demisto_args({"indicators_list": ",".join([
            "1.1.1.1",
            "https://example.com",
            "example.com",
            "CVE-2025-0001",
            "badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0"
        ])})
        # auto-detect mapping (we patch to return the exact type needed)
        def mock_detect(v):
            if v == "1.1.1.1": return "IP"
            if v == "https://example.com": return "URL"
            if v == "example.com": return "Domain"
            if v == "CVE-2025-0001": return "CVE"
            if v.startswith("badf4752"): return "File"
            return None
        # Patch auto_detect_indicator_type to our mapping
        pytest_monkey = pytest  # placeholder - we just use mocker below
        # patch with mocker: (we don't have mocker here so patch via the module directly with lambda in tests uses fixtures)
        IndicatorEnrichment.auto_detect_indicator_type = mock_detect

        # Don't need actual enrichment results; just capture commands
        state, set_return = capture_batch_commands
        set_return([[], [], [], [], []])  # one batch placeholder per expected command

        main()
        # Assert commands called with exact args
        expected = {
            "ip-enrichment": {"ip_list": ["1.1.1.1"]},
            "url-enrichment": {"url_list": ["https://example.com"]},
            "domain-enrichment": {"domain_list": ["example.com"]},
            "cve-enrichment": {"cve_list": ["CVE-2025-0001"]},
            "file-enrichment": {"file_hash": ["badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0"]}
        }
        assert_expected_commands(state, expected)

    def test_text_list_mismatch_preserve_text_type_and_log_unknown(
        self, patch_demisto_args, mock_extract_indicators, batch_executor_factory, return_handlers, last_cmdresult,
        capture_batch_commands, assert_expected_commands
    ):
        """
        Case:
            indicators_list has a value that auto_detect reports as Unknown,
            but extractIndicators from text returns a supported type for the same value.
            Expectation: we run the enrichment for the text-detected type and also
            include the unknown/list-provided item in IndicatorEnrichment with Status=Error.

        Example:
            !indicator-enrichment indicator_list="1.1.1.1" text="some IP: 1.1.1.1"

        Expectation:
            - Calls ip-enrichment 1.1.1.1
            - Logs the unknown
        """
        patch_demisto_args({"text": "1.1.1.1", "indicators_list": "1.1.1.1"})
        # extractIndicators returns IP for text
        mock_extract_indicators([{"EntryContext": {"ExtractedIndicators": {"IP": ["1.1.1.1"]}}}])
        # auto_detect_indicator_type for list returns None/Unknown for that value
        def mock_detect(v):
            return None
        IndicatorEnrichment.auto_detect_indicator_type = mock_detect

        # Prepare enrichment entry for IP
        ip_entry = make_enrichment_entry("IPEnrichment(val.Value && val.Value == obj.Value)", "1.1.1.1")
        state, set_return = capture_batch_commands
        set_return([[(ip_entry, ip_entry["HumanReadable"], "")]])  # only ip cmd executed

        main()
        results_mock, error_mock = return_handlers
        error_mock.assert_not_called()
        results_mock.assert_called_once()
        cmd = last_cmdresult()
        # The outputs should include both the IP successful entry and an Unknown error entry for the list detection
        ctx = cmd.outputs
        assert "IndicatorEnrichment" in ctx
        ie = ctx["IndicatorEnrichment"]
        # Expect one success (Type IP) and one Unknown with Status Error
        assert any(e.get("Type") == "IP" and e.get("Value") == "1.1.1.1" for e in ie)
        assert any(e.get("Type") == "Unknown" and e.get("Value") == "1.1.1.1" and e.get("Status") == "Error" for e in ie)
        # Assert the executed command was ip-enrichment only
        expected = {"ip-enrichment": {"ip_list": ["1.1.1.1"]}}
        assert_expected_commands(state, expected)

    def test_indicator_limit_checked_after_dedup_unknown_unsupported(
        self, patch_demisto_args, mock_extract_indicators, batch_executor_factory, return_handlers, last_cmdresult,
        capture_batch_commands, assert_expected_commands
    ):
        """
        Case:
            Make sure the 100 indicator limit is checked AFTER:
            - merging indicators from text and list
            - removing duplicates
            - excluding unknown/unsupported types

        Example:
            !indicator-enrichment indicator_list="{100 unique IPs},{duplicate ips...},not-an-ioc,fe80::1"

        Expectation:
            - no error as we have 100 unique and valid indicators
        """
        # Build a list with 105 items: 100 valid IPs + 3 duplicates + 2 unsupported (IPv6/Unknown)
        valid_ips = [f"1.2.3.{i}" for i in range(1, 101)]
        duplicates = ["1.2.3.1", "1.2.3.2", "1.2.3.3"]
        unsupported = ["fe80::1", "not-an-ioc"]

        indicators_list = ",".join(valid_ips + duplicates + unsupported)

        # auto_detect returns IP for our 100 unique IPs, and appropriate for others
        def mock_detect(v):
            if v.startswith("1.2.3."):
                return "IP"
            if v == "fe80::1":
                return "IPv6"
            return None
        IndicatorEnrichment.auto_detect_indicator_type = mock_detect

        # No text provided here
        patch_demisto_args({"indicators_list": indicators_list})

        # We expect the script to count unique supported IPs only (100) and thus NOT raise limit error.
        state, set_return = capture_batch_commands
        set_return([[]])  # simulate executor will run (we don't care about results here)

        main()
        results_mock, error_mock = return_handlers
        # Should NOT call return_error because after dedup and filtering supported count == 100
        error_mock.assert_not_called()
        results_mock.assert_called_once()
