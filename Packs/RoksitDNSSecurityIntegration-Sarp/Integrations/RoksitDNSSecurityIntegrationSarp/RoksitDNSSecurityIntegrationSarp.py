import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests


def send_to_roksit_blacklist(url, yourkey, args):
    domain = args.get('Domain')
    headers = {'Content-Type': 'application/json',
               'ApiKey': yourkey}

    blacklist = {'items': [domain]}
    x = requests.post(url, headers=headers, json=blacklist)
    if x.status_code == 200:
        return CommandResults(
            readable_output="Domain added to blacklist"
        )
    else:
        raise DemistoException(message="Failed to add domain to blacklist")


def main():
    try:
        params = demisto.params()
        args = demisto.args()
        command = demisto.command()
        url = params.get('url', 'https://portal.roksit.com/api/integration/blacklist')
        yourkey = params.get('credentials', {}).get('password')

        if command == 'test-module':
            pass
        elif command == 'Roksit-add-to-blacklist':
            return_results(send_to_roksit_blacklist(url, yourkey, args))
    except DemistoException as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}.')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
