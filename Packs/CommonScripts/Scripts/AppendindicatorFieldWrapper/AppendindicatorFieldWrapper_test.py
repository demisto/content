import demistomock as demisto
import pytest


def test_run_append_indicator_field_script(mocker):
    """
    Given:
        - A list of Indicators values.
        - A list of tags to append to the given indicators.
    When:
        Running the 'run_append_indicator_field_script' function.
    Then:
        - Verify that the readable output is as expected.
        - Verify that 'appendIndicatorField' is called once per indicator (not once for all).

    """
    import AppendindicatorFieldWrapper

    indicators_values = ["test_indicator1", "test_indicator2"]
    tags = ["test_tag1", "test_tag2"]

    execute_command_mock = mocker.patch.object(AppendindicatorFieldWrapper, "execute_command")
    response = AppendindicatorFieldWrapper.run_append_indicator_field_script(indicators_values, tags)

    assert (
        response.readable_output == "### The following tags were added successfully:\n|Indicator|Tags|\n"
        "|---|---|\n| test_indicator1 | test_tag1,<br>test_tag2 |\n| test_indicator2 |"
        " test_tag1,<br>test_tag2 |\n"
    )
    # Each indicator must be processed individually to avoid the server-side comma-split bug
    assert execute_command_mock.call_count == len(indicators_values)
    for i, indicator_value in enumerate(indicators_values):
        call_args = execute_command_mock.call_args_list[i]
        assert call_args[0][0] == "appendIndicatorField"
        assert call_args[0][1]["indicatorsValues"] == indicator_value


def test_run_append_indicator_field_script_url_with_commas(mocker):
    """
    Given:
        - A URL indicator whose value contains commas
          (e.g. "http://example.com/path825,295,688,41525479,2004").
        - A tag to append.
    When:
        Running the 'run_append_indicator_field_script' function.
    Then:
        - Verify that 'appendIndicatorField' is called exactly once with the full URL value,
          not split into multiple partial values by the comma in the URL.
        - This is a regression test for XSUP-57677: the server splits 'indicatorsValues' by
          comma, so passing the full URL as a single string (not joined with other values)
          prevents the "Indicator not found" error.
    """
    import AppendindicatorFieldWrapper

    url_with_commas = "http://secure.oldschool.com-yy.cz/assisted-login825,295,688,41525479,2004"
    indicators_values = [url_with_commas]
    tags = ["test-tag"]

    execute_command_mock = mocker.patch.object(AppendindicatorFieldWrapper, "execute_command")
    response = AppendindicatorFieldWrapper.run_append_indicator_field_script(indicators_values, tags)

    # Must be called exactly once with the full URL — not split into partial comma-separated tokens
    assert execute_command_mock.call_count == 1
    call_args = execute_command_mock.call_args_list[0]
    assert call_args[0][0] == "appendIndicatorField"
    assert call_args[0][1]["indicatorsValues"] == url_with_commas

    assert "The following tags were added successfully" in response.readable_output
    assert url_with_commas in response.readable_output


@pytest.mark.parametrize(
    "args, expected_err_message",
    [
        ({"indicators_values": "", "tags": "test_tag1,test_tag2"}, "Indicators values were not specified."),
        ({"indicators_values": "test_indicator1,test_indicator2", "tags": ""}, "Tags were not specified."),
    ],
)
def test_missing_arguments(mocker, args, expected_err_message):
    """
    Given:
        1. Demisto args object containing an empty string as the Indicator values argument, and a
           comma-separated list of tags to append to the indicators.
           An error message about missing indicators.

        2. Demisto args object containing an empty string as the Tags argument, and a
           comma-separated list of indicators values.
           An error message about missing tags.
    When:
        Running the 'main' function.

    Then:
        Verify that the expected error message is returned as an error.
    """

    import AppendindicatorFieldWrapper

    mocker.patch.object(demisto, "args", return_value=args)
    return_error_mock = mocker.patch.object(AppendindicatorFieldWrapper, "return_error")

    AppendindicatorFieldWrapper.main()

    assert return_error_mock.call_count == 1
    assert return_error_mock.call_args[0][0] == (f"Failed to execute AppendindicatorFieldWrapper. Error: {expected_err_message}")
