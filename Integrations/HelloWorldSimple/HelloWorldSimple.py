import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json


def test_module():
    """
    returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.
    """
    return 'ok'


def fetch_incidents(last_run):
    """
    This function will execute every 1 minute.

    :return: next_run, list of incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch = 0

    incidents = [
        {
            'name': f'Hello incident {last_fetch + 1}',
            'rawJSON': json.dumps({
                'hello': 'world'
            })
        },
        {
            'name': f'Hello incident {last_fetch + 2}',
            'rawJSON': json.dumps({
                'hello': 'world'
            })
        }
    ]

    next_run = {'last_fetch': last_fetch + 2}
    return next_run, incidents


def say_hello_command(args):
    name = args.get('name')

    return f'## Hello {name}'


def main():
    try:
        if demisto.command() == 'test-module':
            result = test_module()
            demisto.results(result)

        if demisto.command() == 'helloworldsimple-say-hello':
            results = say_hello_command(demisto.args())
            return_outputs(readable_output=results, outputs=None)

        if demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
