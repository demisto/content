import APIMetricsValidation
import demistomock as demisto
from CommonServerPython import *  # noqa: F401


def test_scenario_one():
    """
    Given: 10 successful API Calls
    When: API Metrics Validation scenario one is run
    Then: API Metrics Validation should return an execution_metrics object with 10 successful API calls
    """
    expected_result = [{'Type': 'Successful', 'APICallsCount': 10}]

    returned_result = APIMetricsValidation.scenario_one()
    assert expected_result == returned_result[10].execution_metrics


def test_scenario_two(mocker):
    """
    Given: 5 successful and 5 failed API Calls
    When: API Metrics Validation scenario two is run
    Then: API Metrics Validation should return an execution_metrics object with 5 failed API calls and 5 successful API calls
    """
    expected_result = [
        {'Type': 'Successful', 'APICallsCount': 5},
        {'Type': 'QuotaError', 'APICallsCount': 5}
    ]
    mocker.patch.object(demisto, 'demistoVersion', return_value={'version': '6.5.0', 'buildNumber': '61000'})

    returned_result = APIMetricsValidation.scenario_two()
    assert expected_result == returned_result[6].execution_metrics


def test_scenario_three(mocker):
    """
    Given: 5 API calls which fail on quota error
    When: API Metrics Validation scenario three is run
    Then: 5 scheduled command results, and no execution metrics
    """
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    expected_result = {
        'items_to_schedule': [
            'sixsix',
            'sevenseven',
            'eighteight',
            'ninenine',
            'tenten'
        ],
        'polling': True
    }

    returned_result = APIMetricsValidation.scenario_three()
    assert expected_result == returned_result[0].scheduled_command._args


def test_scenario_four(mocker):
    """
    Given: 5 API calls 2 succeed and 3 which are scheduled
    When: API Metrics Validation scenario four is run
    Then: 3 scheduled command results, and 2 successful execution metrics
    """
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    expected_result = [{'Type': 'Successful', 'APICallsCount': 2}]

    returned_result = APIMetricsValidation.scenario_four()
    assert expected_result == returned_result[3].execution_metrics


def test_scenario_five(mocker):
    """
    Given: 1 API call which passes
    When: API Metrics Validation scenario five is run
    Then: 1 execution metrics containing one successful API call
    """
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    expected_result = [{'Type': 'Successful', 'APICallsCount': 1}]

    returned_result = APIMetricsValidation.scenario_five()
    assert expected_result == returned_result[1].execution_metrics


def test_scenario_six(mocker):
    """
    Given: 1 API call which fails on quota error
    When: API Metrics Validation scenario six is run
    Then: 1 scheduled command result, and execution metrics containing one quota error
    """
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    expected_result = [{'APICallsCount': 1, 'Type': 'QuotaError'}]

    returned_result = APIMetricsValidation.scenario_six()
    assert expected_result == returned_result[1].execution_metrics


def test_scenario_seven(mocker):
    """
    Given: 1 API calls which fails on quota error
    When: API Metrics Validation scenario seven is run
    Then: 1 scheduled command results, and no execution metrics
    """
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    expected_result = {
        'items_to_schedule': [[
            'oneone',
            'twotwo',
            'threethree',
            'fourfour',
            'fivefive',
            'sixsix',
            'sevenseven',
            'eighteight',
            'ninenine',
            'tenten'
        ]],
        'polling': True
    }

    returned_result = APIMetricsValidation.scenario_seven()
    assert expected_result == returned_result[0].scheduled_command._args


def test_scenario_eight(mocker):
    """
    Given: 1 API call which fails on quota error
    When: API Metrics Validation scenario eight is run
    Then: 1 scheduled command results, and no execution metrics
    """
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    expected_result = {
        'items_to_schedule': [[
            'oneone',
            'twotwo',
            'threethree',
            'fourfour',
            'fivefive',
            'sixsix',
            'sevenseven',
            'eighteight',
            'ninenine',
            'tenten'
        ]],
        'polling': True
    }

    returned_result = APIMetricsValidation.scenario_eight()
    assert expected_result == returned_result[0].scheduled_command._args


def test_scenario_nine(mocker):
    """
    Given: 5 API calls which fail on quota error
    When: API Metrics Validation scenario nine is run
    Then: 1 Execution Metrics containing 5 quota error API calls
    """
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    expected_result = [{'APICallsCount': 5, 'Type': 'QuotaError'}]

    returned_result = APIMetricsValidation.scenario_nine()
    assert expected_result == returned_result[5].execution_metrics


def test_scenario_ten(mocker):
    """
    Given: 1 API call which is successful
    When: API Metrics Validation scenario ten is run
    Then: 1 Execution metric result with one success
    """
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    expected_result = [{'APICallsCount': 1, 'Type': 'Successful'}]

    returned_result = APIMetricsValidation.scenario_ten()
    assert expected_result == returned_result[1].execution_metrics
