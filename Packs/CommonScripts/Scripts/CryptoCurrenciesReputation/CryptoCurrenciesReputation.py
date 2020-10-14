import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

BITCOIN = 'bitcoin'


def main():
    """
    Reputation scripts are getting triggered after formatting scripts, hence the `input` argument would
    only contain valid bitcoins addresses (We support only bitcoins at the moment)

    Returns:

    """
    address_list = argToList(demisto.args().get('input'))
    context = {'WalletType': BITCOIN}
    entry_list = []

    for address in address_list:
        entry_list.append({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': 2,
            'EntryContext': {
                'DBotScore': {
                    'Indicator': address,
                    'Type': 'Cryptocurrency Wallet',
                    'Score': 2,  # suspicious
                    'Vendor': 'Cryptocurrency',
                    'TypeEnnricher': context
                }
            }
        })

    demisto.results(entry_list)


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
