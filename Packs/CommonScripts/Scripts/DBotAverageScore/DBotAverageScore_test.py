from CommonServerPython import *

from pathlib import Path

import pytest

from DBotAverageScore import *


def load_test_data(json_file_name: str) -> list | dict:
    """
    Loads test data from a JSON file.
    """
    with open(Path('test_data', json_file_name)) as json_file:
        return json.load(json_file)


SAMPLE_DATA = load_test_data('sample_data.json')


@pytest.mark.parametrize('indicator, scores_list, expected_average', [
    ('192.0.2.0', [1, 2, 3], 2),  # General check
    ('192.0.2.1', [0, 0, 0], 0),  # Assure '0' is returned when all scores are '0'
    ('192.0.2.2', [1, 1, 0, 0], 1),  # Assure '0' values are ignored
    ('192.0.2.3', [1, 2, 3, 4], 2.5),  # Assure float value is returned
])
def test_calculate_average_score(indicator: str, scores_list: list[int], expected_average: float):
    """
    Given:
        An indicator and a list of scores.
    When:
        Creating a context entry with the average score.
    Then:
        Ensure the average and context entry are valid and correct.
    """
    assert calculate_average_score(indicator, scores_list) == {'Indicator': indicator, 'Score': expected_average}


@pytest.mark.parametrize('context_data, expected_context_output, expected_readable_output', [
    (SAMPLE_DATA['context_data'], SAMPLE_DATA['expected_context_output'], SAMPLE_DATA['expected_readable_output']),
])
def test_calculate_all_average_scores(context_data: list[dict[str, Any]],
                                      expected_context_output: dict, expected_readable_output: str):
    """
    Given:
        A list of DBotScore context entries.
    When:
        Calculating the average score for each indicator using 'calculate_all_average_scores' function.
    Then:
        Ensure the context and readable outputs are valid and correct.
    """
    results = calculate_all_average_scores(context_data)
    assert results.outputs_prefix == 'DBotAvgScore'
    assert results.outputs_key_field == 'Indicator'
    assert results.outputs == expected_context_output
    assert results.readable_output == expected_readable_output
