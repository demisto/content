import demistomock as demisto
from CommonServerPython import *


def main():
    context_data = demisto.context()
    scores: dict[str, list[int]] = {}  # Format is 'indicator: [collected scores]'

    for dbot_score_item in context_data.get('DBotScore', []):
        indicator = dbot_score_item['Indicator']

        if indicator not in scores:
            scores[indicator] = []

        scores[indicator].append(dbot_score_item['Score'])

    context_output = []

    for indicator, score_list in scores.items():
        context_output.append(create_average_score_context(indicator, score_list))

    return_results(CommandResults(
        outputs_prefix='DBotAvgScore',
        outputs_key_field='Indicator',
        outputs=context_output,
        readable_output=tableToMarkdown('DBot Average Scores', t=context_output),
    ))


def create_average_score_context(indicator: str, scores_list: list[int]) -> dict:
    """
    Calculates the average score of a list of scores, and return a context entry with the average.
    '0' values are ignored (since they indicate "unknown" score).
    If no scores are provided, the average is 0.

    Args:
        indicator (str): The indicator for which the average is calculated.
        scores_list (list[int]): A list of scores.

    Returns:
        float: The average score.
    """
    scores_list = [score for score in scores_list if score != 0]

    if not scores_list:  # All values were '0'
        return {'Indicator': indicator, 'Score': 0}

    else:
        return {'Indicator': indicator, 'Score': sum(scores_list) / len(scores_list)}


if __name__ in ("__main__", "builtin", "builtins"):   # pragma: no cover
    main()
