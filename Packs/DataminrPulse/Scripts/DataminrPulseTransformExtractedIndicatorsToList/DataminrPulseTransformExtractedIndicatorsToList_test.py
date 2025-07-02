import pytest
from DataminrPulseTransformExtractedIndicatorsToList import transform_extracted_indicators_command


def test_transform_extracted_indicators_command():
    """
    Test the transform_extracted_indicators_command function.

    Given:
        - ExtractedIndicators argument containing a JSON string of extracted indicators

    When:
        - Calling `transform_extracted_indicators_command` function

    Then:
        - Verify that the function returns a CommandResults object with proper outputs and readable output.
    """
    args = {"ExtractedIndicators": '{"url": ["http://example.com", "http://example.org"], "ip": ["1.2.3.4", "5.6.7.8"]}'}

    expected_output = {"indicatorList": ["http://example.com", "http://example.org", "1.2.3.4", "5.6.7.8"]}
    expected_readable_output = "List of indicators\n\nhttp://example.com, http://example.org, 1.2.3.4, 5.6.7.8"

    result = transform_extracted_indicators_command(args)

    assert result.outputs == expected_output
    assert result.readable_output == expected_readable_output


def test_transform_extracted_indicators_command_with_empty_extracted_indicators():
    """
    Test the transform_extracted_indicators_command function with empty ExtractedIndicators argument.

    Given:
        - Empty ExtractedIndicators argument

    When:
        - Calling `transform_extracted_indicators_command` function

    Then:
        - Raise ValueError with proper error message.
    """
    with pytest.raises(ValueError, match="ExtractedIndicators not specified"):
        transform_extracted_indicators_command({"ExtractedIndicators": ""})
