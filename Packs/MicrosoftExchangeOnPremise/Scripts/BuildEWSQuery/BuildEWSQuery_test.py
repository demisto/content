import pytest

DEMISTO_ARGS: dict = {"stripSubject": 'True',
                      "escapeColons": 'False',
                      "searchThisWeek": 'true',
                      "from": "my_test_mail@test.com",
                      "subject": "test",
                      "body": "this is a test"}
EXPECTED_RESULTS = 'From:"my_test_mail@test.com" AND Subject:"test" AND Body:"this is a test" AND Received:"this week"'


@pytest.mark.parametrize('args, expected_results', [
    (DEMISTO_ARGS, EXPECTED_RESULTS),
])
def test_build_ews_query(args, expected_results):
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
