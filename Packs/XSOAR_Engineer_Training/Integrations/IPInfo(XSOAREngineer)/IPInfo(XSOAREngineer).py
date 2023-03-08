import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import urllib3
urllib3.disable_warnings()

def get_ipinfo_command(params, args):
    token = params.get('token')
    ip = args.get('ip')

    res = requests.get(f"http://ipinfo.io/{ip}?token={token}")

    readable = tableToMarkdown("IpInfo.io Results", res.json())
    result = CommandResults(readable_output=readable,
                            outputs_prefix="IpInfo",
                            outputs=res.json())
    return result

def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    LOG(f'Command being called is {command}')

    if command == 'xsoar-engineer-ipinfo':
        return_results(get_ipinfo_command(params, args))

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
