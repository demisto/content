import demistomock as demisto
from CommonServerPython import *

from collections import defaultdict


def calculate_all_average_scores(context_data: list[dict[str, Any]]) -> CommandResults:
    """
    Calculates the average score for each indicator in the context, and returns the results.

    Args:
        context_data (dict): 'DBotScore' context data, containing DBotScore entries to calculate the average for.

    Returns:
        CommandResults: A CommandResults object containing command's outputs.
    """
    scores = defaultdict(list)  # Format is 'indicator: [collected scores]'

    for dbot_score_item in context_data:
        indicator = dbot_score_item['Indicator']

        scores[indicator].append(dbot_score_item['Score'])

    context_output = []

    for indicator, scores_list in scores.items():
        context_output.append(calculate_average_score(indicator=indicator, scores_list=scores_list))

    return CommandResults(
        outputs_prefix='DBotAvgScore',
        outputs_key_field='Indicator',
        outputs=context_output,
        readable_output=tableToMarkdown('DBot Average Scores', t=context_output),
    )


def calculate_average_score(indicator: str, scores_list: list[int]) -> dict:
    """
    Calculates the average score of a list of scores, and return a context entry with the average.
    '0' values are ignored (since they indicate "unknown" score).
    If no scores are provided, the average is 0.

    Args:
        indicator (str): The indicator for which the average is calculated.
        scores_list (list[int]): A list of scores.

    Returns:
        dict: A context entry for a single indicator, containing the average score.
    """
    scores_list = [score for score in scores_list if score != 0]  # Remove '0' values

    if not scores_list:  # If all values were '0', we have an empty list
        return {'Indicator': indicator, 'Score': 0}

    return {'Indicator': indicator, 'Score': sum(scores_list) / len(scores_list)}


def main():   # pragma: no cover
    dbot_score_context_data: list | dict = demisto.context().get('DBotScore', [])

    # If there is only a single DBotScore entry, the server returns it as a single dict, and not inside a list.
    if isinstance(dbot_score_context_data, dict):
        dbot_score_context_data = [dbot_score_context_data]

    return_results(calculate_all_average_scores(dbot_score_context_data))


if __name__ in ("__main__", "builtin", "builtins"):   # pragma: no cover
    main()
