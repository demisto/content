import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def test_module(client, args):
    client.build_iterator()
    return 'ok', {}, {}


def main():
    # Write configure here
    params = {k: v for k, v in demisto.params().items() if v is not None}
    client = Client(**params)
    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))
    # Switch case
    commands = {
        'test-module': test_module,
        'get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client, params.get('indicator_type'))
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in Spamhaus feed [{e}]'
        return_error(err_msg)


from HTTPFeedApiModule import *  # noqa: E402


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
