import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import requests
import urllib3
from typing import Optional

# Disable insecure warnings
urllib3.disable_warnings()

SOURCE_NAME = "Tor Exit Addresses"
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    def __init__(self, insecure: bool = False, proxy: bool = False, tlp_color: Optional[str] = None):
        super().__init__(base_url='https://check.torproject.org/exit-addresses', verify=not insecure, proxy=proxy)
        self.url = 'https://check.torproject.org/exit-addresses'
        self.tlp_color = tlp_color

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

    def datestring_to_server_format(self, date_string):
        """
        formats a datestring to the ISO-8601 format which the server expects to recieve
        :param date_string: Date represented as a tring
        :return: ISO-8601 date string
        """
        parsed_date = dateparser.parse(date_string, settings={'TIMEZONE': 'UTC'})
        assert parsed_date is not None, f'could not parse {date_string}'
        return parsed_date.strftime(DATE_FORMAT)

    def build_iterator(self, feedTags, limit):
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
                indicator['firstseenbysource'] = self.datestring_to_server_format(date)

            elif line.startswith('LastStatus'):
                date = line.split(' ', 1)[1]
                indicator['lastseenbysource'] = self.datestring_to_server_format(date)

            elif line.startswith('ExitAddress'):
                indicator['value'] = line.split()[1]
                raw_json = indicator.copy()
                indicator['rawJSON'] = raw_json
                indicator['fields'] = {
                    'firstseenbysource': indicator.get('firstseenbysource'),
                    'lastseenbysource': indicator.get('lastseenbysource'),
                    'tags': feedTags,
                }

                if self.tlp_color:
                    indicator['fields']['trafficlightprotocol'] = self.tlp_color

                indicator_list.append(indicator)

                current_indicator_index = current_indicator_index + 1
                if limit is not None and current_indicator_index >= limit:
                    break

        return indicator_list


def fetch_indicators_command(client, feedTags=None, limit=None):
    indicator_list = client.build_iterator(feedTags, limit)
    return indicator_list


def get_indicators_command(client: Client, args: dict):
    limit = args.get('limit')
    if limit:
        limit = int(limit)
    indicator_list = fetch_indicators_command(client, None, limit)
    human_readable = tableToMarkdown("Indicators from Tor Exit Addresses:", indicator_list,
                                     headers=['value', 'type', 'firstseenbysource', 'lastseenbysource', 'name'],
                                     removeNull=True)
    return human_readable, {}, indicator_list


def module_test_command(client: Client, args: dict):
    client.http_request_indicators()
    return 'ok', {}, {}


def main():
    params = demisto.params()
    feedTags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    client = Client(params.get('insecure'),
                    params.get('proxy'),
                    tlp_color)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    # Switch case
    commands = {
        'test-module': module_test_command,
        'tor-get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client, feedTags)
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
