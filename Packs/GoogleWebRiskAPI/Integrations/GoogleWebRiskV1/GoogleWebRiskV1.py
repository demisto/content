import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
from ast import literal_eval

Apikey = demisto.params().get('APIkey')
ThreatCategories = demisto.params().get('ThreatCategories')
search = ''

for item in ThreatCategories:
    cat = "&threatTypes="+item
    search = search + cat

endpoint = "https://webrisk.googleapis.com/v1/uris:search?%s&uri=%s&key=%s"
headers = {"Content-Type": "application/json; charset=utf-8"}

def check_url(url):
    x = requests.get(endpoint % (cat, url, Apikey),  headers=headers)
    command_results = CommandResults(
        outputs_prefix='GoogleWebRisk',
        outputs_key_field=url,
        outputs=x.json())
    return command_results

def main() -> None:
    command = demisto.command()

    try:
        if command == 'gwr-check-url':
            return_results(check_url(demisto.args().get('value')))
        elif command == 'test-module':
            # if any issue would occur we would not get this far
            return_results('ok')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
