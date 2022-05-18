import pandas as pd
from typing import List, Dict
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_incidents_ids_from_context() -> list:
    """
    Gets the campaign incident ids.

    Returns:
        List of incident ids.
    """
    relevant_incidents = demisto.get(demisto.context(), 'EmailCampaign.incidents')
    ids = [item.get('id') for item in relevant_incidents]

    if not ids:
        ids = []

    return ids


def get_indicatos_from_incidents(incident_ids: List) -> List:
    """
    Gets the campaign indicators by the incident ids.

    Args:
        incident_ids: List of the campaign incident ids.

    Returns:
        List of the campaign indicators.
    """
    indicators_query = 'investigationIDs:({})'.format(' '.join('"{}"'.format(id_) for id_ in incident_ids))
    fields = ['id', 'indicator_type', 'investigationIDs', 'relatedIncCount', 'score', 'value']
    indicators_args = {'query': indicators_query, 'limit': '150', 'populateFields': ','.join(fields)}
    return execute_command('GetIndicatorsByQuery', args=indicators_args)


def format_results(indicators: List, incident_ids: List):
    """
    Format the indicators result to a readable markdown table.

    Args:
        indicators: The campaign indicators.
        incident_ids: The campaign incident ids.

    Returns:
        A readable markdown table of the campaign indicators.
    """
    indicators_df = pd.DataFrame(data=indicators)

    if len(indicators_df) == 0:
        return 'No mutual indicators were found.'

    indicators_df = indicators_df[indicators_df['relatedIncCount'] < 150]
    indicators_df['Involved Incidents Count'] = \
        indicators_df['investigationIDs'].apply(lambda x: sum(id_ in x for id_ in incident_ids))
    indicators_df = indicators_df[indicators_df['Involved Incidents Count'] > 1]

    if len(indicators_df) == 0:
        return 'No mutual indicators were found.'

    associate_to_current_incident(indicators)
    indicators_df['Id'] = indicators_df['id'].apply(lambda x: "[%s](#/indicator/%s)" % (x, x))
    indicators_df = indicators_df.sort_values(['score', 'Involved Incidents Count'], ascending=False)
    indicators_df['Reputation'] = indicators_df['score'].apply(scoreToReputation)
    indicators_df.rename({'value': 'Value', 'indicator_type': 'Type'}, axis=1, inplace=True)
    indicators_headers = ['Id', 'Value', 'Type', 'Reputation', 'Involved Incidents Count']

    return tableToMarkdown('', indicators_df.to_dict(orient='records'), headers=indicators_headers)


def associate_to_current_incident(indicators: List[Dict[str, str]]):
    incident_id = demisto.incident()['id']
    execute_command(
        'associateIndicatorsToIncident',
        {
            'incidentId': incident_id,
            'indicatorsValues': list(map(lambda x: x['value'], indicators))
        }
    )


def main():  # pragma: no cover
    """ This script should run from a campaign incident, and expect to have incidents
    to get indicators from."""
    try:
        incident_ids = get_incidents_ids_from_context()
        indicators = get_indicatos_from_incidents(incident_ids)
        formated_results = format_results(indicators, incident_ids)
        execute_command('setIncident', {'campaignmutualindicators': formated_results})
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
