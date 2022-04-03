import APIMetricsValidation
from CommonServerPython import *  # noqa: F401


def test_scenario_one():
    """
    Given: 10 successful API Calls
    When: API Metrics Validation scenario one is run
    Then: API Metrics Validation should return an execution_metrics object with 10 successful API calls
    """
    expected_result = [{'MetricType': 'Successful', 'ApiCalls': 10}]

    returned_result = APIMetricsValidation.scenario_one()
    assert expected_result == returned_result[10].execution_metrics


def test_scenario_two():
    """
    Given: 5 successful and 5 failed API Calls
    When: API Metrics Validation scenario two is run
    Then: API Metrics Validation should return an execution_metrics object with 5 failed API calls and 5 successful API calls
    """
    expected_result = [
        {'MetricType': 'Successful', 'ApiCalls': 5},
        {'MetricType': 'QuotaError', 'ApiCalls': 5}
    ]

    returned_result = APIMetricsValidation.scenario_two()
    assert expected_result == returned_result[6].execution_metrics


def test_scenario_three(mocker):
    """
    Given: 5 API calls which fail on quota error
    When: API Metrics Validation scenario three is run
    Then: 5 scheduled command results, and no exeuction metrics
    """
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    expected_result = [
        {'MetricType': 'Successful', 'ApiCalls': 5},
        {'MetricType': 'QuotaError', 'ApiCalls': 5}
    ]

    returned_result = APIMetricsValidation.scenario_three()
    assert expected_result == returned_result.execution_metrics

