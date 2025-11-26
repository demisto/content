import pytest
import demistomock as demisto

import IndicatorEnrichment
from IndicatorEnrichment import (
    main,
    indicator_enrichment_command,
    FatalArgException,
    NO_VALID_INDICATORS_MESSAGE,
)


class TestMainWrapper:
    """
    Tests for the main() wrapper, ensuring it:
    - Pulls arguments from demisto.args()
    - Delegates to indicator_enrichment_command()
    - Uses return_results() on success
    - Uses return_error() on FatalArgException
    """
    def test_main_calls_indicator_enrichment_command_and_handles_success(self, mocker):
        """
        Case:
            main() is invoked with valid arguments that result in a successful
            indicator_enrichment_command() call.

        Example:
            demisto.args() returns {"indicators_list": "1.1.1.1"} and
            indicator_enrichment_command() returns a dummy result.

        Expectation:
            - main() calls indicator_enrichment_command() with demisto.args().
            - return_results() is called once with that result.
            - return_error() is NOT called.
        """
        # Arrange
        # Mock demisto.args
        mocker.patch.object(demisto, "args", return_value={"indicators_list": "1.1.1.1"})

        # Mock indicator_enrichment_command → return a simple object
        mock_indicator = mocker.patch.object(
            IndicatorEnrichment,
            "indicator_enrichment_command",
            return_value="OK",
        )

        # Mock return_results and return_error
        mock_return_results = mocker.patch.object(
            IndicatorEnrichment,
            "return_results",
        )
        mock_return_error = mocker.patch.object(
            IndicatorEnrichment,
            "return_error",
        )

        # Act
        main()

        # Assert
        mock_indicator.assert_called_once_with({"indicators_list": "1.1.1.1"})
        mock_return_results.assert_called_once_with("OK")
        mock_return_error.assert_not_called()

    def test_main_handles_fatalargexception_via_return_error(self, mocker):
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
        # Arrange
        fake_args = {}

        mocker.patch.object(demisto, "args", return_value=fake_args)

        # indicator_enrichment_command will raise FatalArgException
        mock_indicator = mocker.patch.object(
            IndicatorEnrichment,
            "indicator_enrichment_command",
            side_effect=FatalArgException("No valid indicators provided"),
        )

        mock_return_results = mocker.patch.object(
            IndicatorEnrichment,
            "return_results",
        )
        mock_return_error = mocker.patch.object(
            IndicatorEnrichment,
            "return_error",
        )

        # Act
        main()

        # Assert
        mock_indicator.assert_called_once_with(fake_args)
        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()

        # Check the message content
        msg = mock_return_error.call_args[0][0]
        assert "No valid indicators provided" in msg

    def test_main_handles_exception_via_return_error(self, mocker):
        """
        Case:
            main() is invoked with valid arguments
            indicator_enrichment_command() executes, and raises unexpect Exception

        Example:
            demisto.args() returns {}, and indicator_enrichment_command()
            raises Exception().

        Expectation:
            - indicator_enrichment_command() is called once.
            - return_error() is called once with the exception message and the expected prefix.
            - return_results() is NOT called.
        """
        # Arrange

        mocker.patch.object(demisto, "args", return_value={"indicators_list": "1.1.1.1"})

        # indicator_enrichment_command will raise FatalArgException
        mock_indicator = mocker.patch.object(
            IndicatorEnrichment,
            "indicator_enrichment_command",
            side_effect=Exception("exception raised from ip-enrichment"),
        )

        mock_return_results = mocker.patch.object(
            IndicatorEnrichment,
            "return_results",
        )
        mock_return_error = mocker.patch.object(
            IndicatorEnrichment,
            "return_error",
        )

        # Act
        main()

        # Assert
        mock_indicator.assert_called_once_with({"indicators_list": "1.1.1.1"})
        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()

        # Check the message content
        msg = mock_return_error.call_args[0][0]
        assert ('Failed to execute !indicator-enrichment. Error: exception raised from ip-enrichment') == msg

class TestArgsValidation:
    """
    Argument validation tests executed through main(), to get an e2e feel:
    - demisto.args() → indicator_enrichment_command → FatalArgException → main → return_error
    """

    # --------------------------
    # Basic missing/empty args
    # --------------------------

    def test_no_args_calls_return_error(self, mocker):
        """
        Case:
            Both text and indicators_list are missing.

        Expectation:
            - main() calls return_error() once.
            - return_results() is not called.
            - Error message contains NO_VALID_INDICATORS_MESSAGE.
        """
        mocker.patch.object(demisto, "args", return_value={})

        mock_return_results = mocker.patch.object(IndicatorEnrichment, "return_results")
        mock_return_error = mocker.patch.object(IndicatorEnrichment, "return_error")

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        msg = mock_return_error.call_args[0][0]
        assert NO_VALID_INDICATORS_MESSAGE in msg

    def test_empty_indicators_list_only_calls_return_error(self, mocker):
        """
        Case:
            indicators_list is provided but is an empty/whitespace-only string,
            and text is not provided.

        Expectation:
            return_error() called once with NO_VALID_INDICATORS_MESSAGE.
        """
        mocker.patch.object(demisto, "args", return_value={"indicators_list": "   "})

        mock_return_results = mocker.patch.object(IndicatorEnrichment, "return_results")
        mock_return_error = mocker.patch.object(IndicatorEnrichment, "return_error")

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        msg = mock_return_error.call_args[0][0]
        assert NO_VALID_INDICATORS_MESSAGE in msg

    def test_both_text_and_list_empty_strings_calls_return_error(self, mocker):
        """
        Case:
            Both text and indicators_list are provided but both are empty/whitespace.

        Expectation:
            return_error() with NO_VALID_INDICATORS_MESSAGE.
        """
        mocker.patch.object(
            demisto,
            "args",
            return_value={"text": "   ", "indicators_list": "   "},
        )

        mock_return_results = mocker.patch.object(IndicatorEnrichment, "return_results")
        mock_return_error = mocker.patch.object(IndicatorEnrichment, "return_error")

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        msg = mock_return_error.call_args[0][0]
        assert NO_VALID_INDICATORS_MESSAGE in msg

    # --------------------------
    # No supported indicators
    # --------------------------

    def test_text_only_no_supported_indicators_returns_informational(self, mocker):
        """
        Case:
            text is provided, no indicators_list, and extractIndicators finds
            no supported indicators (only unsupported/Unknown).

        Expectation:
            - main() does NOT call return_error().
            - return_results() is called once with CommandResults-like object.
            - That result.readable_output == NO_VALID_INDICATORS_MESSAGE.
        """
        def mock_execute_command(name, args, extract_contents=False):
            assert name == "extractIndicators"
            return [{
                "EntryContext": {
                    "ExtractedIndicators": {
                        "IPv6": ["fe80::1"],
                        "Unknown": ["junk"],
                    }
                }
            }]

        mocker.patch.object(IndicatorEnrichment, "execute_command", side_effect=mock_execute_command)
        mocker.patch.object(demisto, "args", return_value={"text": "fe80::1 junk"})

        mock_return_results = mocker.patch.object(IndicatorEnrichment, "return_results")
        mock_return_error = mocker.patch.object(IndicatorEnrichment, "return_error")

        main()

        mock_return_error.assert_not_called()
        mock_return_results.assert_called_once()
        result = mock_return_results.call_args[0][0]
        assert getattr(result, "readable_output", None) == NO_VALID_INDICATORS_MESSAGE

    def test_indicators_list_only_unsupported_types_calls_return_error(self, mocker):
        """
        Case:
            indicators_list contains only unsupported indicator types (e.g. CIDR, IPv6),
            and no text is provided.

        Expectation:
            - main() calls return_error() with NO_VALID_INDICATORS_MESSAGE.
        """
        values = ["10.0.0.0/8", "fe80::1"]

        def mock_auto_detect(indicator_value):
            if indicator_value == "10.0.0.0/8":
                return "CIDR"  # unsupported
            if indicator_value == "fe80::1":
                return "IPv6"  # unsupported
            return None

        mocker.patch.object(IndicatorEnrichment, "auto_detect_indicator_type", side_effect=mock_auto_detect)
        mocker.patch.object(demisto, "args", return_value={"indicators_list": ",".join(values)})

        mock_return_results = mocker.patch.object(IndicatorEnrichment, "return_results")
        mock_return_error = mocker.patch.object(IndicatorEnrichment, "return_error")

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        msg = mock_return_error.call_args[0][0]
        assert NO_VALID_INDICATORS_MESSAGE in msg

    def test_indicators_list_only_invalid_values_calls_return_error(self, mocker):
        """
        Case:
            indicators_list contains only invalid/non-indicator values
            (auto_detect returns None), and no text is provided.

        Expectation:
            return_error() with NO_VALID_INDICATORS_MESSAGE.
        """
        values = ["foo", "bar"]

        def mock_auto_detect(indicator_value):
            return None  # everything invalid

        mocker.patch.object(IndicatorEnrichment, "auto_detect_indicator_type", side_effect=mock_auto_detect)
        mocker.patch.object(demisto, "args", return_value={"indicators_list": ",".join(values)})

        mock_return_results = mocker.patch.object(IndicatorEnrichment, "return_results")
        mock_return_error = mocker.patch.object(IndicatorEnrichment, "return_error")

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        msg = mock_return_error.call_args[0][0]
        assert NO_VALID_INDICATORS_MESSAGE in msg

    def test_indicators_list_mixed_unsupported_and_invalid_no_supported_calls_return_error(self, mocker):
        """
        Case:
            indicators_list contains a mix of unsupported indicator types and invalid values,
            and no text is provided.

        Expectation:
            return_error() with NO_VALID_INDICATORS_MESSAGE.
        """
        values = ["10.0.0.0/8", "foo"]

        def mock_auto_detect(indicator_value):
            if indicator_value == "10.0.0.0/8":
                return "CIDR"  # unsupported
            if indicator_value == "foo":
                return None   # invalid
            return None

        mocker.patch.object(IndicatorEnrichment, "auto_detect_indicator_type", side_effect=mock_auto_detect)
        mocker.patch.object(demisto, "args", return_value={"indicators_list": ",".join(values)})

        mock_return_results = mocker.patch.object(IndicatorEnrichment, "return_results")
        mock_return_error = mocker.patch.object(IndicatorEnrichment, "return_error")

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        msg = mock_return_error.call_args[0][0]
        assert NO_VALID_INDICATORS_MESSAGE in msg

    def test_both_text_and_list_have_no_supported_or_known_indicators_calls_return_error(self, mocker):
        """
        Case:
            Both text and indicators_list are provided, and neither source yields
            any supported indicators (only unsupported/Unknown).

        Expectation:
            return_error() with NO_VALID_INDICATORS_MESSAGE.
        """
        def mock_execute_command(name, args, extract_contents=False):
            assert name == "extractIndicators"
            return [{
                "EntryContext": {
                    "ExtractedIndicators": {
                        "IPv6": ["fe80::1"],
                        "Unknown": ["junk"]
                    }
                }
            }]

        def mock_auto_detect(indicator_value):
            if indicator_value == "10.0.0.0/8":
                return "CIDR"  # unsupported
            if indicator_value == "foo":
                return None   # invalid
            return None

        mocker.patch.object(IndicatorEnrichment, "execute_command", side_effect=mock_execute_command)
        mocker.patch.object(IndicatorEnrichment, "auto_detect_indicator_type", side_effect=mock_auto_detect)

        mocker.patch.object(
            demisto,
            "args",
            return_value={"text": "fe80::1 junk", "indicators_list": "10.0.0.0/8,foo"},
        )

        mock_return_results = mocker.patch.object(IndicatorEnrichment, "return_results")
        mock_return_error = mocker.patch.object(IndicatorEnrichment, "return_error")

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        msg = mock_return_error.call_args[0][0]
        assert NO_VALID_INDICATORS_MESSAGE in msg

    # --------------------------
    # Indicator limit
    # --------------------------

    def test_indicator_limit_exceeded_calls_return_error_and_not_batch(self, mocker):
        """
        Case:
            More than 100 unique supported indicators, ignore_indicator_limit is false.

        Expectation:
            - main() calls return_error().
            - BatchExecutor is never instantiated.
        """
        ips = [f"1.1.1.{i}" for i in range(1, 102)]

        def mock_auto_detect(indicator_value):
            return "IP"  # supported

        mocker.patch.object(IndicatorEnrichment, "auto_detect_indicator_type", side_effect=mock_auto_detect)
        mocker.patch.object(demisto, "args", return_value={"indicators_list": ",".join(ips)})

        mock_batch_executor_cls = mocker.patch.object(IndicatorEnrichment, "BatchExecutor")
        mock_return_results = mocker.patch.object(IndicatorEnrichment, "return_results")
        mock_return_error = mocker.patch.object(IndicatorEnrichment, "return_error")

        main()

        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()
        # should not try running underlying scripts at all
        mock_batch_executor_cls.assert_not_called()

    def test_indicator_limit_exceeded_ignored_when_flag_true_calls_batch(self, mocker):
        """
        Case:
            More than 100 unique supported indicators, but ignore_indicator_limit=true.

        Expectation:
            - main() does NOT call return_error().
            - BatchExecutor is used (execute_batch called).
        """
        ips = [f"1.1.1.{i}" for i in range(1, 102)]

        def mock_auto_detect(indicator_value):
            return "IP"

        mocker.patch.object(IndicatorEnrichment, "auto_detect_indicator_type", side_effect=mock_auto_detect)
        mocker.patch.object(
            demisto,
            "args",
            return_value={"indicators_list": ",".join(ips), "ignore_indicator_limit": "true"},
        )

        mock_batch_executor_cls = mocker.patch.object(IndicatorEnrichment, "BatchExecutor")
        mock_batch_executor_instance = mock_batch_executor_cls.return_value
        mock_batch_executor_instance.execute_batch.return_value = []

        mock_return_results = mocker.patch.object(IndicatorEnrichment, "return_results")
        mock_return_error = mocker.patch.object(IndicatorEnrichment, "return_error")

        main()

        mock_return_error.assert_not_called()
        mock_batch_executor_cls.assert_called_once()
        mock_batch_executor_instance.execute_batch.assert_called()
        mock_return_results.assert_called_once()
