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
        Verify that the readable output is as expected.

    """
    import AppendindicatorFieldWrapper

    indicators_values = ['test_indicator1', 'test_indicator2']
    tags = ['test_tag1', 'test_tag2']

    mocker.patch.object(AppendindicatorFieldWrapper, 'execute_command')
    response = AppendindicatorFieldWrapper.run_append_indicator_field_script(indicators_values, tags)

    assert response.readable_output == '### The following tags were added successfully:\n|Indicator|Tags|\n' \
                                       '|---|---|\n| test_indicator1 | test_tag1,<br>test_tag2 |\n| test_indicator2 |' \
                                       ' test_tag1,<br>test_tag2 |\n'


@pytest.mark.parametrize('args, expected_err_message', [
    ({'indicators_values': '', 'tags': 'test_tag1,test_tag2'}, 'Indicators values were not specified.'),
    ({'indicators_values': 'test_indicator1,test_indicator2', 'tags': ''}, 'Tags were not specified.')
])
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

    mocker.patch.object(demisto, 'args', return_value=args)
    return_error_mock = mocker.patch.object(AppendindicatorFieldWrapper, 'return_error')

    AppendindicatorFieldWrapper.main()

    assert return_error_mock.call_count == 1
    assert return_error_mock.call_args[0][0] == (f'Failed to execute AppendindicatorFieldWrapper. '
                                                 f'Error: {expected_err_message}')
