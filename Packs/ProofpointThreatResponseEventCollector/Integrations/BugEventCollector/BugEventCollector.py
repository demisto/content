import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import


def send_events(params):
    vendor, product = 'testvendor', 'testproduct'
    events = [{"id": "1"}, {"id": "2"}]
    demisto.updateModuleHealth({'eventsPulled': len(events)})
    demisto.info("Ran update module health")
    send_events_to_xsiam(events=events, vendor=vendor, product=product)


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    demisto.info(f'Darya: Command being called is {command}')
    demisto.debug(f'Darya: Command being called is {command}')

    try:
        if command == 'test-module':
            return_results('ok')
        elif command == 'fetch-events':
            demisto.info(f'Darya: fetch-events Bug Event collector {command}')
            demisto.debug(f'Darya: fetch-events Bug Event collector {command}')
            send_events(params)
        else:
            raise ValueError(f'Command {command} is not implemented in bug integration.')
    except Exception as e:
        raise Exception(f'Error in BUG Event Collector Integration [{e}]')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
