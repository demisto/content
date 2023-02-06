import pytest as pytest

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from IsIntegrationAvailable import is_integration_available


@pytest.mark.parametrize('expected, brand_name', [
    ('yes', 'Integration1'),
    ('no', 'Integration2')
])
def test_is_integration_available(mocker, expected, brand_name):
    """
    Given:
        - The script args.
    When:
        - Running the print_context function.
    Then:
        - Validating the outputs as expected.
    """
    results_mock = mocker.patch.object(demisto, 'results')
    all_instances = {
        'Integration1_instanse': {'brand': 'Integration1', 'state': 'active'},
        'Integration2_instanse': {'brand': 'Integration2', 'state': 'not active'}
    }
    mocker.patch.object(demisto, 'setContext')
    mocker.patch.object(demisto, 'get', return_value=True)
    is_integration_available(brand_name, all_instances)
    res = results_mock.call_args[0][0]
    assert expected == res
