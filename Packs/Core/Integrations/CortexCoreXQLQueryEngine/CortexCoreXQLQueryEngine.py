from CoreXQLApiModule import *
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

''' CLIENT CLASS '''


class Client(CoreClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """


''' MAIN FUNCTION '''

# COMMAND CONSTANTS

BUILT_IN_QUERY_COMMANDS = {
    'xdr-xql-file-event-query': {
        'func': get_file_event_query,
        'name': 'FileEvent',
    },
    'xdr-xql-process-event-query': {
        'func': get_process_event_query,
        'name': 'ProcessEvent',
    },
    'xdr-xql-dll-module-query': {
        'func': get_dll_module_query,
        'name': 'DllModule',
    },
    'xdr-xql-network-connection-query': {
        'func': get_network_connection_query,
        'name': 'NetworkConnection',
    },
    'xdr-xql-registry-query': {
        'func': get_registry_query,
        'name': 'Registry',
    },
    'xdr-xql-event-log-query': {
        'func': get_event_log_query,
        'name': 'EventLog',
    },
    'xdr-xql-dns-query': {
        'func': get_dns_query,
        'name': 'DNS',
    },
    'xdr-xql-file-dropper-query': {
        'func': get_file_dropper_query,
        'name': 'FileDropper',
    },
    'xdr-xql-process-instance-network-activity-query': {
        'func': get_process_instance_network_activity_query,
        'name': 'ProcessInstanceNetworkActivity',
    },
    'xdr-xql-process-causality-network-activity-query': {
        'func': get_process_causality_network_activity_query,
        'name': 'ProcessCausalityNetworkActivity',
    },
}

GENERIC_QUERY_COMMANDS = {
    'test-module': test_module,
    'xdr-xql-generic-query': start_xql_query_polling_command,
    'xdr-xql-get-query-results': get_xql_query_results_polling_command,
    'xdr-xql-get-quota': get_xql_quota_command,
}


def main() -> None:
    """
        executes an integration command
    """
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    args = demisto.args()
    url_suffix = "/public_api/v1"
    try:
        url = "/api/webapp/"
        base_url = urljoin(url, url_suffix)
        client = Client(
            base_url=base_url,
            proxy=proxy,
            verify=verify_certificate,
            headers={},
            is_core=True
        )

        if command in GENERIC_QUERY_COMMANDS:
            return_results(GENERIC_QUERY_COMMANDS[command](client, args))
        elif command in BUILT_IN_QUERY_COMMANDS:
            return_results(get_built_in_query_results_polling_command(client, args))
        else:
            raise NotImplementedError(f'Command {command} does not exist.')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
