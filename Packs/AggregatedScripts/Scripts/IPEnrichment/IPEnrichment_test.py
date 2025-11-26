import pytest
import demistomock as demisto

import IndicatorEnrichment
from IndicatorEnrichment import main, FatalArgException


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
        fake_args = {"indicators_list": "1.1.1.1"}

        # Capture side effects
        captured = {
            "called_with_args": None,
            "return_results_called": False,
            "return_results_value": None,
            "return_error_called": False,
            "return_error_message": None,
        }

        class DummyResult:
            def __init__(self, value):
                self.value = value

        # Mock demisto.args
        mocker.patch.object(demisto, "args", return_value=fake_args)

        # Mock indicator_enrichment_command to capture arguments and return a dummy result
        def mock_indicator_enrichment_command(args):
            captured["called_with_args"] = args
            return DummyResult("ok")

        mocker.patch.object(
            IndicatorEnrichment,
            "indicator_enrichment_command",
            side_effect=mock_indicator_enrichment_command,
        )

        # Mock return_results and return_error
        def mock_return_results(result):
            captured["return_results_called"] = True
            captured["return_results_value"] = result

        def mock_return_error(message):
            captured["return_error_called"] = True
            captured["return_error_message"] = message

        mocker.patch.object(IndicatorEnrichment, "return_results", side_effect=mock_return_results)
        mocker.patch.object(IndicatorEnrichment, "return_error", side_effect=mock_return_error)

        # Act
        main()

        # Assert
        assert captured["called_with_args"] == fake_args
        assert captured["return_results_called"] is True
        assert isinstance(captured["return_results_value"], DummyResult)
        assert captured["return_error_called"] is False
        assert captured["return_error_message"] is None

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
        fake_args = {}

        captured = {
            "called_with_args": None,
            "return_results_called": False,
            "return_results_value": None,
            "return_error_called": False,
            "return_error_message": None,
        }

        # Mock demisto.args
        mocker.patch.object(demisto, "args", return_value=fake_args)

        # Mock indicator_enrichment_command to raise FatalArgException
        def mock_indicator_enrichment_command(args):
            captured["called_with_args"] = args
            raise FatalArgException("No valid indicators provided")

        mocker.patch.object(
            IndicatorEnrichment,
            "indicator_enrichment_command",
            side_effect=mock_indicator_enrichment_command,
        )

        # Mock return_results and return_error
        def mock_return_results(result):
            captured["return_results_called"] = True
            captured["return_results_value"] = result

        def mock_return_error(message):
            captured["return_error_called"] = True
            captured["return_error_message"] = message

        mocker.patch.object(IndicatorEnrichment, "return_results", side_effect=mock_return_results)
        mocker.patch.object(IndicatorEnrichment, "return_error", side_effect=mock_return_error)

        # Act
        main()

        # Assert
        assert captured["called_with_args"] == fake_args
        assert captured["return_results_called"] is False
        assert captured["return_results_value"] is None
        assert captured["return_error_called"] is True
        # main might prepend something like 'Failed to execute ...', so be flexible
        assert "No valid indicators provided" in (captured["return_error_message"] or "")
