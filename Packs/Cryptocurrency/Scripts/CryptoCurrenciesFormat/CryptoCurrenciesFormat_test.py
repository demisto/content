from CryptoCurrenciesFormat import verify_is_bitcoin, main
import pytest
import demistomock as demisto

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
    """Verifies that a Bitcoin address is valid.
    Given
    - address.
    When
    - When there is an address that looks like a bitcoin address.
    Then
    - Checks if it's a bitcoin address or not
    """
    assert verify_is_bitcoin(bitcoin_address) == expected_output


ARGS = {
    'input': '1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i,1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9,1ANNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i'}
EXPECTED_RESULTS = ['bitcoin-1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i', 'bitcoin-1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9']


def test_main(mocker):
    """Verifies that all valid addresses get returned.
       Given
       - addresses.
       When
       - When there are multiple addresses that looks like a bitcoin address.
       Then
       - Return all valid addresses
       """
    mocker.patch.object(demisto, 'args', return_value=ARGS)
    mocker.patch.object(demisto, 'results')
    main()
    assert EXPECTED_RESULTS == demisto.results.call_args[0][0]
