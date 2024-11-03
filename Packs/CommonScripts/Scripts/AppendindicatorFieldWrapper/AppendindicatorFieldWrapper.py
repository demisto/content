import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""
A wrapper script to the 'AppendindicatorField' script, that enables adding tags to certain indicators.
Note: You can use this script as a layout button that allows adding tags to indicators.
"""

from CommonServerUserPython import *


''' COMMAND FUNCTION '''


def run_append_indicator_field_script(indicators_values: list, tags: list) -> CommandResults:
    """
    Run the 'appendIndicatorField' script in order to add the given tags to the given indicators.
    Args:
        indicators_values: The values of the indicators. For example, for an IP indicator, 1.1.1.1.
        tags: The values to add to the indicators tags.

    Returns: A CommandResults object contains the readable output string.

    """
    execute_command('appendIndicatorField',
                    {'indicatorsValues': indicators_values, 'field': 'tags', 'fieldValue': tags})

    readable_output = tableToMarkdown('The following tags were added successfully:',
                                      [{'Indicator': indicator, 'Tags': tags} for indicator in indicators_values])

    return CommandResults(
        outputs_prefix='AppendindicatorFieldWrapper',
        outputs_key_field='',
        readable_output=readable_output
    )


''' MAIN FUNCTION '''


def main():
    args = demisto.args()
    indicators_values = argToList(args.get('indicators_values'))
    tags = argToList(args.get('tags'))

    try:
        # Handle missing arguments:
        if not indicators_values:
            raise Exception('Indicators values were not specified.')
        if not tags:
            raise Exception('Tags were not specified.')

        return_results(run_append_indicator_field_script(indicators_values, tags))

    except Exception as ex:
        return_error(f'Failed to execute AppendindicatorFieldWrapper. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
