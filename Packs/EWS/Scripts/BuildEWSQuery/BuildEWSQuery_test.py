from typing import Dict
import pytest

DEMISTO_ARGS: Dict = {"stripSubject": 'True',
                      "escapeColons": 'False',
                      "searchThisWeek": 'true'}
EXPECTED_RESULTS = ' AND Received:"this week"'


@pytest.mark.parametrize('args, expected_results', [
    (DEMISTO_ARGS, EXPECTED_RESULTS),
])
def test_buildewsquery(args, expected_results):
    """
    Given:
        - args dictionary.

    When:
        - running BuildEWSQuery script.

    Then:
        - Ensure that the query was built correctly.

    """
    from BuildEWSQuery import build_ews_query
    results = build_ews_query(args)
    assert expected_results == results.readable_output
