import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import time


STATUS_NEW = 'new'
STATUS_EXISTING = 'existing'
STATUS_UNAVAILABLE = 'unavailable'

KEY_CREATION_STATUS = 'CreationStatus'

MAX_FIND_INDICATOR_RETRIES = 10
SLEEP_TIME = 2


def associate_indicator_to_incident(indicator_value: Any) -> None:
    """
    Associate an indicator to this incident. Raise an exception if an error occurs.
    """

    incident_id = demisto.incidents()[0].get('id')
    demisto.debug(f"The incident id is {incident_id}")

    cmd_args = {
        'incidentId': incident_id,
        'value': f"{indicator_value}"  # Force an error
    }

    retry_num = 1
    res = ''
    while res != 'done' and retry_num <= MAX_FIND_INDICATOR_RETRIES:
        try:
            demisto.debug(f"Executing associateIndicatorToIncident command with retry {retry_num}/{MAX_FIND_INDICATOR_RETRIES}")
            res = execute_command('associateIndicatorToIncident', cmd_args)
            demisto.debug(f"The associateIndicatorToIncident response is: {res}")

        except Exception as err:
            if "For associateIndicatorToIncident found no indicator" not in str(err):
                raise err
            # else log and continue with retries after sleeping
            demisto.debug(f"Failed to find indicator {indicator_value} in the system.")
            if retry_num != MAX_FIND_INDICATOR_RETRIES:
                time.sleep(SLEEP_TIME)  # pylint: disable=E9003
            retry_num += 1

    if res != 'done':
        raise Exception(f"Failed to associate {indicator_value} with incident {incident_id}")


def normalize_indicator_value(indicator_value: Any) -> str:
    if isinstance(indicator_value, int):
        return str(indicator_value)
    elif isinstance(indicator_value, str) and indicator_value:
        return indicator_value
    else:
        raise DemistoException(f'Invalid indicator value: {str(indicator_value)}')


def add_new_indicator(indicator_value: Any,
                      create_new_indicator_args: dict[str, Any],
                      associate_to_incident: bool = False) -> dict[str, Any]:
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

    if associate_to_incident:
        demisto.debug(f"Associating {indicator_value} to incident.")
        associate_indicator_to_incident(indicator_value)

    return indicator


def add_new_indicators(indicator_values: list[Any] | None,
                       create_new_indicator_args: dict[str, Any],
                       associate_to_incident: bool = False) -> list[dict[str, Any]]:
    return [add_new_indicator(indicator_value, create_new_indicator_args, associate_to_incident)
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
        associate_to_incident = argToBoolean(create_new_indicator_args.pop('associate_to_current', 'false'))
        ents = add_new_indicators(indicator_values, create_new_indicator_args, associate_to_incident)

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
