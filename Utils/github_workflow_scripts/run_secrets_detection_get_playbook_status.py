#!/usr/bin/env python3

import argparse
import ast
import sys
import time

import demisto_client

import urllib3
from demisto_client.demisto_api.rest import ApiException
from demisto_sdk.commands.common.constants import PB_Status

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ----- Constants ----- #
DEFAULT_TIMEOUT = 60 * 12
SLEEP_WAIT_SECONDS = 10
GOLD_SERVER_URL = "https://content-gold.paloaltonetworks.com"


def get_playbook_state(client: demisto_client, inv_id: str):
    # returns current investigation playbook state - 'inprogress'/'failed'/'completed'
    try:
        investigation_playbook_raw = demisto_client.generic_request_func(self=client, method='GET',
                                                                         path='/inv-playbook/' + inv_id)
        investigation_playbook = ast.literal_eval(investigation_playbook_raw[0])
    except ApiException:
        print('Failed to get investigation playbook state, error trying to communicate with demisto server')
        return PB_Status.FAILED

    return investigation_playbook.get('state', PB_Status.NOT_SUPPORTED_VERSION)


def wait_for_playbook_to_complete(investigation_id, client):
    investigation_url = f'{GOLD_SERVER_URL}/#/Custom/caseinfoid/{investigation_id}'
    print(f'Investigation URL: {investigation_url}')

    timeout = time.time() + DEFAULT_TIMEOUT

    # wait for playbook to finish run
    while True:
        # give playbook time to run
        time.sleep(SLEEP_WAIT_SECONDS)
        try:
            playbook_state = get_playbook_state(client, investigation_id)
        except demisto_client.demisto_api.rest.ApiException:
            playbook_state = 'Pending'
            client = demisto_client.configure(base_url=client.api_client.configuration.host,
                                              api_key=client.api_client.configuration.api_key, verify_ssl=False)

        if playbook_state == PB_Status.COMPLETED:
            print("Secrets playbook finished successfully, no secrets were found.")
            break

        if playbook_state == PB_Status.FAILED:
            print(f'Secrets playbook was failed as secrets were found. To investigate go to: {investigation_url}')
            sys.exit(1)

        if time.time() > timeout:
            print(f'Secrets playbook timeout reached. To investigate go to: {investigation_url}')
            sys.exit(1)


def arguments_handler():
    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.

     """
    parser = argparse.ArgumentParser(description='Get playbook status.')
    parser.add_argument('-i', '--investigation_id', help='The investigation id of the secrets detection playbook.')
    parser.add_argument('-k', '--api_key', help='Gold Api key')
    return parser.parse_args()


def main():
    options = arguments_handler()
    investigation_id = options.investigation_id
    api_key = options.api_key
    if investigation_id and api_key:
        client = demisto_client.configure(base_url=GOLD_SERVER_URL, api_key=api_key, verify_ssl=False)
        wait_for_playbook_to_complete(investigation_id, client)
    else:
        print("Secrets detection step failed - API key or investigation ID were not supplied.")
        sys.exit(1)


if __name__ == "__main__":
    main()
