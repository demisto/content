import demistomock as demisto
from CommonServerPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'VirusTotal Livehunt'


class Client(BaseClient):
    def __init__(self, params: dict):
        super().__init__(
            'https://www.virustotal.com/api/v3/',
            verify=not argToBoolean(params.get('insecure')),
            proxy=argToBoolean(params.get('proxy')),
            headers={'x-apikey': params['credentials']['password']}
        )


def test_module(client: Client, args: dict):
    pass


def get_indicators_command(client: Client, args: dict):
    """Initiate a single fetch-indicators

    Args:
        client(Client): The AutoFocus Client.
        args(dict): Command arguments.

    Returns:
        str, dict, list. the markdown table, context JSON and list of indicators
    """
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 100))
    indicators = fetch_indicators_command(client, limit, offset)

    hr_indicators = []
    for indicator in indicators:
        hr_indicators.append({
            'Value': indicator.get('value'),
            'Type': indicator.get('type'),
            'rawJSON': indicator.get('rawJSON'),
            'fields': indicator.get('fields'),
        })

    human_readable = tableToMarkdown("Indicators from VirusTotal Livehunt:",
                                     hr_indicators,
                                     headers=['Value', 'Type', 'rawJSON', 'fields'],
                                     removeNull=True)

    if args.get('limit'):
        human_readable = human_readable + f"\nTo bring the next batch of indicators run:\n!vt-livehunt-get-indicators " \
                                          f"limit={args.get('limit')} " \
                                          f"offset={int(str(args.get('limit'))) + int(str(args.get('offset')))}"

    return human_readable, {}, indicators


def fetch_indicators_command(client, limit=None, offset=None):
    pass


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # params = demisto.params()

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client({})
        commands = {
            'test-module': test_module,
            'vt-livehunt-get-indicators': get_indicators_command
        }

        if command == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        elif command in commands:

            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration. [{err}]'
        return_error(err_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
