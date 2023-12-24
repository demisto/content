import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pandas as pd


def get_incidents_ids_from_context() -> list:
    """
    Gets the campaign incident ids.

    Returns:
        List of incident ids.
    """
    relevant_incidents = demisto.get(demisto.context(), 'EmailCampaign.incidents')
    ids = [item.get('id') for item in relevant_incidents] if relevant_incidents else []

    return ids


def get_indicators_from_incidents(incident_ids: list):
    """
    Gets the campaign indicators by the incident ids.

    Args:
        incident_ids: List of the campaign incident ids.

    Returns:
        List of the campaign indicators.
    """
    indicators_query = f"""investigationIDs:({' '.join(f'"{id_}"' for id_ in incident_ids)})"""
    fields = ['id', 'indicator_type', 'investigationIDs', 'relatedIncCount', 'score', 'value']
    indicators_args = {'query': indicators_query, 'limit': '150', 'populateFields': ','.join(fields)}
    res = execute_command('GetIndicatorsByQuery', args=indicators_args)
    if is_error(res):
        return_error(f'Error in GetIndicatorsByQuery. {get_error(res)}')
    return res


def format_results(indicators: list, incident_ids: list):
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
    indicators_df['Id'] = indicators_df['id'].apply(lambda x: f"[{x}](#/indicator/{x})")
    indicators_df = indicators_df.sort_values(['score', 'Involved Incidents Count'], ascending=False)
    indicators_df['Reputation'] = indicators_df['score'].apply(scoreToReputation)
    indicators_df = indicators_df.rename({'value': 'Value', 'indicator_type': 'Type'}, axis=1)
    indicators_headers = ['Id', 'Value', 'Type', 'Reputation', 'Involved Incidents Count']

    return tableToMarkdown('', indicators_df.to_dict(orient='records'), headers=indicators_headers)


def associate_to_current_incident(indicators: list[dict[str, str]]):
    incident_id = demisto.incident()['id']
    execute_command(
        'associateIndicatorsToIncident',
        {
            'incidentId': incident_id,
            'indicatorsValues': [x['value'] for x in indicators]
        }
    )


def main():  # pragma: no cover
    """ This script should run from a campaign incident, and expect to have incidents
    to get indicators from."""
    try:
        if incident_ids := get_incidents_ids_from_context():
            indicators = get_indicators_from_incidents(incident_ids)
            formated_results = format_results(indicators, incident_ids)
            execute_command('setIncident', {'campaignmutualindicators': formated_results})
        return_results(CommandResults(
            content_format='html',
            raw_response=("<div style='font-size:17px; text-align:center; padding: 50px;'> Mutual Indicators"
                          "</br> <div style='font-size:17px;'> No mutual indicators were found. </div></div>")
        ))
    except Exception as ex:
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
