import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any


STATUS_NEW = 'new'
STATUS_EXISTING = 'existing'
STATUS_UNAVAILABLE = 'unavailable'

KEY_CREATION_STATUS = 'CreationStatus'


def normalize_indicator_value(indicator_value: Any) -> str:
    if isinstance(indicator_value, int):
        return str(indicator_value)
    elif isinstance(indicator_value, str) and indicator_value:
        return indicator_value
    else:
        raise DemistoException(f'Invalid indicator value: {str(indicator_value)}')


def add_new_indicator(indicator_value: Any,
                      create_new_indicator_args: dict[str, Any]) -> dict[str, Any]:
    indicator_value = normalize_indicator_value(indicator_value)
    escaped_indicator_value = indicator_value.replace('"', r'\"')

    if indicators := execute_command('findIndicators', {'value': escaped_indicator_value}):
        indicator = indicators[0]
        indicator[KEY_CREATION_STATUS] = STATUS_EXISTING
    else:
        args = dict(create_new_indicator_args, value=indicator_value)
        indicator = execute_command('createNewIndicator', args)
        if isinstance(indicator, dict):
            indicator[KEY_CREATION_STATUS] = STATUS_NEW
        elif isinstance(indicator, str):
            # createNewIndicator has been successfully done, but the indicator
            # wasn't created for some reasons.
            if 'done - Indicator was not created' in indicator:
                demisto.debug(f'Indicator was not created. Make sure "{indicator_value}" is not excluded.')
            else:
                demisto.debug(indicator)

            indicator = {
                'value': indicator_value,
                'indicator_type': args.get('type', 'Unknown'),
                KEY_CREATION_STATUS: STATUS_UNAVAILABLE,
            }
        else:
            raise DemistoException(f'Unknown response from createNewIndicator: str{indicator_value}')

    return indicator


def add_new_indicators(indicator_values: list[Any] | None,
                       create_new_indicator_args: dict[str, Any]) -> list[dict[str, Any]]:
    return [add_new_indicator(indicator_value, create_new_indicator_args)
            for indicator_value in indicator_values or []]


def main():
    try:
        args = assign_params(**demisto.args())

        # Don't use argToList to make a list in order to accept an indicator including commas.
        # The `indicator_values` parameter doesn't support a comma separated list.
        if (indicator_values := args.get('indicator_values', [])) and not isinstance(indicator_values, list):
            indicator_values = [indicator_values]

        create_new_indicator_args = dict(args)
        create_new_indicator_args.pop('indicator_values', None)
        create_new_indicator_args.pop('verbose', None)
        ents = add_new_indicators(indicator_values, create_new_indicator_args)

        outputs = [assign_params(
            ID=ent.get('id'),
            Score=ent.get('score'),
            CreationStatus=ent.get(KEY_CREATION_STATUS),
            Type=ent.get('indicator_type'),
            Value=ent.get('value'),
        ) for ent in ents]

        count_new = sum(1 for ent in ents if ent.get(KEY_CREATION_STATUS) == STATUS_NEW)
        readable_output = f'{count_new} new indicators have been added.'
        if argToBoolean(args.get('verbose', 'false')):
            readable_output += '\n' + tblToMd('New Indicator Created', outputs,
                                              ['ID', 'Score', 'CreationStatus', 'Type', 'Value'])

        return_results(CommandResults(
            outputs_prefix='CreateNewIndicatorsOnly',
            outputs_key_field=['Value', 'Type'],
            outputs=outputs,
            raw_response=ents,
            readable_output=readable_output
        ))
    except Exception as e:
        return_error(
            f'Failed to execute CreateNewIndicatorsOnly.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
