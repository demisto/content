import pytest
import Intel471WatcherAlerts as feed


GET_REPORT_TYPE_DATA = [
    (
        'https://titan.intel471.com/report/inforep/fd1636d9f5a66098bcea8ae341b0304d',  # input
        'INFO REPORT:\n'  # expected
    ),
    (
        'https://titan.intel471.com/report/fintel/3820588e7fab5f9e24cd582fe2a9f276',  # input
        'FINTEL:\n'  # expected
    ),
    (
        'https://titan.intel471.com/report/spotrep/3ff4ef482649a94e792f8476edc84381',  # input
        'SPOT REPORT:\n'  # expected
    )
]


@pytest.mark.parametrize('input,expected_results', GET_REPORT_TYPE_DATA)
def test_get_report_type(mocker, input, expected_results):
    """
    Given:
        - set of parameters from demisto.

    When:
        - create an instance and on every run.

    Then:
        - Returns a report type.

    """
    report_type: str = feed.get_report_type(input)
    assert report_type == expected_results
