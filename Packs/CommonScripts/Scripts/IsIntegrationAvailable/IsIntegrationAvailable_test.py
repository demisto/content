import pytest


@pytest.mark.parametrize('expected, brand_name', [
    ('yes', 'Integration1'),
    ('no', 'Integration2')
])
def test_is_integration_available(expected, brand_name):
    """
    Given:
        - The script args.
    When:
        - Running the is_integration_available function.
    Then:
        - Validating the outputs as expected.
    """
    from IsIntegrationAvailable import is_integration_available

    all_instances = {
        'Integration1_instanse': {'brand': 'Integration1', 'state': 'active'},
        'Integration2_instanse': {'brand': 'Integration2', 'state': 'not active'}
    }

    result = is_integration_available(brand_name, all_instances)
    assert expected == result.readable_output
