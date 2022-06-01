import demistomock as demisto
from CommonServerPython import *

import urllib3
import traceback
from typing import Dict, List

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
BITCOIN = 'bitcoin'
INTEGRATION_NAME = 'Cryptocurrency'
SCORE = {
    'None': 0,
    'Good': 1,
    'Suspicious': 2,
    'Bad': 3,
}


def get_bitcoin_reputation(addresses, reliability, reputation, score) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    for address in addresses:
        dbot_score = Common.DBotScore(
            indicator=address,
            indicator_type=DBotScoreType.CRYPTOCURRENCY,
            integration_name=INTEGRATION_NAME,  # Vendor
            score=score,
            reliability=reliability,
        )
        crypto_context = Common.Cryptocurrency(
            address=address,
            address_type=BITCOIN,
            dbot_score=dbot_score,
        )
        table_data = {
            'Address': address,
            'Cryptocurrency Address Type': BITCOIN,
            'Reputation': reputation,
        }
        table_name = f'{INTEGRATION_NAME} reputation for {address}'
        hr = tableToMarkdown(table_name, table_data)

        command_results.append(CommandResults(
            outputs_prefix='Cryptocurrency',
            readable_output=hr,
            outputs_key_field='Address',
            indicator=crypto_context,
        ))
    return command_results


def crypto_reputation_command(args: Dict[str, str], reliability: str, reputation: str):
    crypto_addresses = argToList(args.get('crypto', ''))

    # For cases the command was executed by a playbook/user and the addresses received are verified
    # Stripping the `bitcoin` prefix from the given addresses (if exists) then add it to match the convention.
    if args.get('address_type') == BITCOIN:
        bitcoin_addresses = [f'bitcoin:{address.lstrip("bitcoin:")}' for address in crypto_addresses]

    else:
        bitcoin_addresses = [address for address in crypto_addresses if BITCOIN in address]

    score = SCORE[reputation]
    result = get_bitcoin_reputation(bitcoin_addresses, reliability, reputation, score)

    return result


def main():
    params = demisto.params()
    reliability = params['reliability']
    reputation = params['reputation']

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            return_results('ok')

        elif demisto.command() == 'crypto':
            return_results(crypto_reputation_command(demisto.args(), reliability, reputation))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
