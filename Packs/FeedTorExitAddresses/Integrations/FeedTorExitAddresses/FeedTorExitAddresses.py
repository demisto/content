import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


import requests
from dateutil.parser import parse
from typing import Dict, List

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

SOURCE_NAME = "Tor Exit Addresses"


class Client(BaseClient):
    def __init__(self, insecure: bool = False, proxy: bool = False):
        super().__init__(base_url='https://check.torproject.org/exit-addresses', verify=not insecure, proxy=proxy)
        self.url = 'https://check.torproject.org/exit-addresses'

    def http_request_indicators(self):
        res = requests.get(
            url=self.url,
            verify=self._verify
        )

        try:
            res.raise_for_status()

        except Exception:
            LOG(f'Tor Exit Addresses - exception in request: {res.status_code!r} {res.content!r}')
            raise

        return res.text

    def datestring_to_millisecond_timestamp(self, date_string):
        date = parse(str(date_string))
        return int(date.timestamp() * 1000)

    def build_iterator(self, limit):
        raw_res = self.http_request_indicators()
        raw_indicator_list = raw_res.split('\n')
        indicator_list = []  # type: List
        indicator = {}  # type: Dict
        current_indicator_index = 0
        for line in raw_indicator_list:
            if line.startswith('ExitNode'):
                indicator = {
                    "type": FeedIndicatorType.IP,
                    'name': line.split()[1]
                }

            elif line.startswith('Published'):
                date = line.split(' ', 1)[1]
                indicator['firstseenbyfeed'] = self.datestring_to_millisecond_timestamp(date)

            elif line.startswith('LastStatus'):
                date = line.split(' ', 1)[1]
                indicator['lastseenbyfeed'] = self.datestring_to_millisecond_timestamp(date)

            elif line.startswith('ExitAddress'):
                indicator['value'] = line.split()[1]
                raw_json = indicator.copy()
                indicator['rawJSON'] = raw_json
                indicator['fields'] = {
                    'firstseenbyfeed': indicator.get('firstseenbyfeed'),
                    'lastseenbyfeed': indicator.get('lastseenbyfeed'),
                    'name': indicator.get('name')
                }
                indicator_list.append(indicator)

                current_indicator_index = current_indicator_index + 1
                if limit is not None and current_indicator_index == limit:
                    break

        return indicator_list


def fetch_indicators_command(client, limit=None):
    indicator_list = client.build_iterator(limit)
    return indicator_list


def get_indicators_command(client: Client, args: dict):
    limit = args.get('limit')
    if limit:
        limit = int(limit)
    indicator_list = fetch_indicators_command(client, limit)
    human_readable = tableToMarkdown("Indicators from Tor Exit Addresses:", indicator_list,
                                     headers=['value', 'type', 'firstseenbyfeed', 'lastseenbyfeed', 'name'],
                                     removeNull=True)
    return human_readable, {}, indicator_list


def module_test_command(client: Client, args: dict):
    client.http_request_indicators()
    return 'ok', {}, {}


def main():
    params = demisto.params()

    client = Client(params.get('insecure'),
                    params.get('proxy'))

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    # Switch case
    commands = {
        'test-module': module_test_command,
        'tor-get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        raise Exception(f'Error in {SOURCE_NAME} Integration [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
