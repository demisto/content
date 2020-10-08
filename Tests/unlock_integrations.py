import sys

import demisto_client

from Tests.tools import update_server_configuration

if __name__ == "__main__":
    try:
        integration_to_unlock = sys.argv[1]
        client = demisto_client.configure(verify_ssl=False)
        update_server_configuration(client, {'content.unlock.integrations': integration_to_unlock}, 'Could not update configurations')
    except IndexError:
        print('You must supply an integration to unlock. Can be comma separated values.')
