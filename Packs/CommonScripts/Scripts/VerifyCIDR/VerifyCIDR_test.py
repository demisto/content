import pytest

import demistomock as demisto
from VerifyCIDR import is_valid_cidr, main

invalid_host_bit = ('190.0.0.0/1', False)
valid_network = ('200.200.200.200/29', True)
invalid_network = ('300.0.0.0', False)


@pytest.mark.parametrize('cidr_input, expected_output',
                         [
                             invalid_host_bit,
                             valid_network,
                             invalid_network,
                         ])
def test_is_valid_cidr(cidr_input, expected_output):
    """
    Given:
        - One CIDR as input
    When:
        - Checking if it is a valid CIDR
    Then:
        - Ensure the CIDR is marked correctly
    """
    assert is_valid_cidr(cidr_input) == expected_output


@pytest.mark.parametrize('cidr_input, expected_output',
                         [
                             ('190.0.0.0/1,200.200.200.200/29,300.0.0.0', ['', '200.200.200.200/29', '']),
                             ('200.200.200.200/29,190.0.0.0/1', ['200.200.200.200/29', '']),
                             ('200.200.200.200/29', ['200.200.200.200/29']),
                             ('190.0.0.0/1', ['']),
                         ])
def test_main(mocker, cidr_input, expected_output):
    """
    Given:
        - List of CIDRs as input
    When:
        - Running the script
    Then:
        - Ensure the CIDRs are marked correctly, and returns array with the correct CIDRs or empty string
    """
    mocker.patch.object(demisto, 'args', return_value={'input': cidr_input})
    mocker.patch.object(demisto, 'results')
    main()
    demisto.results.assert_called_with(expected_output)
