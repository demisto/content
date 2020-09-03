from isBitcoin import verify_is_bitcoin
import pytest


# Bitcoin address, expected_output
testdata = [
    ('1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i', True),
    ('1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9', True),
    ('1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62X', False),
    ('1ANNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i', False),
    ('1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62X', False),
    ('1A Na15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i', False),
    ('gygy', False),
    ('/', False)
]


@pytest.mark.parametrize('bitcoin_address,expected_output', testdata)
def test_verify_is_bitcoin(bitcoin_address, expected_output):
    '''Verifies that a Bitcoin address is valid.
    Given
    - address.
    When
    - When there is an address that looks like a bitcoin address.
    Then
    - Checks if it's a bitcoin address or not
    '''
    assert verify_is_bitcoin(bitcoin_address) == expected_output
