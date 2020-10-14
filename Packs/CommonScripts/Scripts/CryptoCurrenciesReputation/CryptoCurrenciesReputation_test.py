from CryptoCurrenciesReputation import main
import demistomock as demisto

ARGS = {
    'input': '1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i,1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9'}
EXPECTED_RESULTS = [{'Type': 1, 'ContentsFormat': 'json', 'Contents': 2, 'EntryContext': {
    'DBotScore': {'Indicator': '1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i', 'Type': 'Cryptocurrency Wallet', 'Score': 2,
                  'Vendor': 'Cryptocurrency',
                  'TypeEnnricher': {'WalletType': 'bitcoin'}}}}, {'Type': 1, 'ContentsFormat': 'json', 'Contents': 2,
                                                                  'EntryContext': {'DBotScore': {
                                                                      'Indicator': '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9',
                                                                      'Type': 'Cryptocurrency Wallet', 'Score': 2,
                                                                      'Vendor': 'Cryptocurrency',
                                                                      'TypeEnnricher': {'WalletType': 'bitcoin'}}}}]


def test_main(mocker):
    """Verifies that a reputation data and the wallet_type field are being set for a given valid bitcoin address.
       Given
       - list of bitcoin addresses.
       When
       - When a cryptocurrency is being auto extracted.
       Then
       - Return the updated context for each address.
       """
    mocker.patch.object(demisto, 'args', return_value=ARGS)
    mocker.patch.object(demisto, 'results')
    main()
    assert EXPECTED_RESULTS == demisto.results.call_args[0][0]
