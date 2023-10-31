import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests


def send_to_roksit_blacklist(url, yourkey, domain):
    headers = {'Content-Type': 'application/json',
               'ApiKey': yourkey}

    blacklist = {'items': [domain]}
    x = requests.post(url, headers=headers, json=blacklist)
    if x.status_code == 200:
        return CommandResults(
            readable_output=f"{domain} was successfully added to the blacklist."
        )
    else:
        raise DemistoException(message="Failed to add domain to blacklist")


def main():
    try:
        params = demisto.params()
        command = demisto.command()
        url = params.get('url', 'https://portal.roksit.com/api/integration/blacklist')
        yourkey = params.get('credentials', {}).get('password')
        domain = demisto.args().get('Domain')

        if command == 'test-module':
            # send a period as a dummy domain to check connectivity
            send_to_roksit_blacklist(url, yourkey, '.')
            return_results('ok')
        elif command == 'Roksit-add-to-blacklist':
            return_results(send_to_roksit_blacklist(url, yourkey, domain))
    except DemistoException as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}.')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
