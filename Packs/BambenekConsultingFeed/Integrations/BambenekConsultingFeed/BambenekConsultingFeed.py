import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def module_test_command(client, args):
    fieldnames = demisto.params().get('fieldnames')
    if fieldnames == 'indicator' or any(field in fieldnames for field in ('indicator,', ',indicator')):
        client.build_iterator()
        return 'ok', {}, {}
    return_error('Please provide a column named "indicator" in fieldnames')


def fetch_indicators_command(client, itype):
    iterator = client.build_iterator()
    indicators = []
    for item in iterator:
        raw_json = dict(item)
        raw_json['value'] = value = item.get('indicator')
        raw_json['type'] = itype
        indicators.append({
            "value": value,
            "type": itype,
            "rawJSON": raw_json,
        })
    return indicators


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    handle_proxy()
    client = Client(**params)
    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))
    # Switch case
    commands = {
        'test-module': module_test_command,
        'get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client, params.get('indicator_type'))
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)  # type: ignore
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in Bambenek Consulting Feed Integration [{e}]'
        return_error(err_msg)


from CSVFeedApiModule import *  # noqa: E402


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
