import hashlib

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from CoreXQLApiModule import *

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
DEFAULT_LIMIT = 100

""" CLIENT CLASS """


class Client(CoreClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """


""" MAIN FUNCTION """

# COMMAND CONSTANTS

BUILT_IN_QUERY_COMMANDS = {
    "xdr-xql-file-event-query": {
        "func": get_file_event_query,
        "name": "FileEvent",
    },
    "xdr-xql-process-event-query": {
        "func": get_process_event_query,
        "name": "ProcessEvent",
    },
    "xdr-xql-dll-module-query": {
        "func": get_dll_module_query,
        "name": "DllModule",
    },
    "xdr-xql-network-connection-query": {
        "func": get_network_connection_query,
        "name": "NetworkConnection",
    },
    "xdr-xql-registry-query": {
        "func": get_registry_query,
        "name": "Registry",
    },
    "xdr-xql-event-log-query": {
        "func": get_event_log_query,
        "name": "EventLog",
    },
    "xdr-xql-dns-query": {
        "func": get_dns_query,
        "name": "DNS",
    },
    "xdr-xql-file-dropper-query": {
        "func": get_file_dropper_query,
        "name": "FileDropper",
    },
    "xdr-xql-process-instance-network-activity-query": {
        "func": get_process_instance_network_activity_query,
        "name": "ProcessInstanceNetworkActivity",
    },
    "xdr-xql-process-causality-network-activity-query": {
        "func": get_process_causality_network_activity_query,
        "name": "ProcessCausalityNetworkActivity",
    },
}

GENERIC_QUERY_COMMANDS = {
    "test-module": test_module,
    "xdr-xql-generic-query": start_xql_query_polling_command,
    "xdr-xql-get-query-results": get_xql_query_results_polling_command,
    "xdr-xql-get-quota": get_xql_quota_command,
}

def add_playbook_metadata_headers(headers:dict, command: str):
    ctx_output: dict = demisto.callingContext or {}
    entry_task: dict = ctx_output.get('context', {}).get('ParentEntry', {}).get('entryTask',{})
    incidents: list = ctx_output.get('context', {}).get('Incidents', [])
    playbook_id = incidents[0].get('playbookId', 'missing_playbookId') if incidents else ''
    playbook_name = entry_task.get('playbookName', 'missing_playbook_name') if entry_task else ''
    task_name = entry_task.get('taskName', 'missing_task_name') if entry_task else ''
    task_id = entry_task.get('taskId', 'missing_task_id') if entry_task else ''
    headers['playbook_metadata'] = {
        'playbook_name': playbook_name,
        'playbook_id': playbook_id,
        'task_name': task_name,
        'task_id': task_id,
        'integration_name': 'Cortex XDR - XQL Query Engine',
        'command_name': command}


def main() -> None:
    """main function, parses params and runs command functions"""
    args = demisto.args()
    params = demisto.params()
    # using two different credentials object as they both fields need to be encrypted
    apikey = params.get("apikey", {}).get("password", "")
    apikey_id = params.get("apikey_id", {}).get("password", "")
    if not apikey:
        raise DemistoException("Missing API Key. Fill in a valid key in the integration configuration.")
    if not apikey_id:
        raise DemistoException("Missing API Key ID. Fill in a valid key ID in the integration configuration.")
    base_url = urljoin(params["url"], "/public_api/v1")
    verify_cert = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        # generate a 64 bytes random string
        nonce = get_nonce()
        # get the current timestamp as milliseconds.
        timestamp = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
        # generate the auth key:
        auth_key = f"{apikey}{nonce}{timestamp}".encode()
        # convert to bytes object and calculate sha256
        api_key_hash = hashlib.sha256(auth_key).hexdigest()  # lgtm [py/weak-sensitive-data-hashing]
        ctx_output: dict = demisto.callingContext or {}
        entry_task: dict = ctx_output.get('context', {}).get('ParentEntry', {}).get('entryTask',{})
        incidents: list = ctx_output.get('context', {}).get('Incidents', [])
        playbook_id = incidents[0].get('playbookId', 'missing_playbookId') if incidents else ''
        playbook_name = entry_task.get('playbookName', 'missing_playbook_name') if entry_task else ''
        task_name = entry_task.get('taskName', 'missing_task_name') if entry_task else ''
        task_id = entry_task.get('taskId', 'missing_task_id') if entry_task else ''
        # generate HTTP call headers
        headers = {
            "x-xdr-timestamp": timestamp,
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": apikey_id,
            "Authorization": api_key_hash,
            "playbook_metadata": f"{{'playbook_name': {playbook_name},'playbook_id': {playbook_id},'task_name': {task_name},'task_id': {task_id},'integration_name': 'Cortex XDR - XQL Query Engine','command_name': {command}}}"
        }
        # add_playbook_metadata_headers(headers, command)
        print(f"DANF: headers: {headers}")

        client = Client(base_url=base_url, verify=verify_cert, headers=headers, proxy=proxy, is_core=False)
        if command in GENERIC_QUERY_COMMANDS:
            return_results(GENERIC_QUERY_COMMANDS[command](client, args))
        elif command in BUILT_IN_QUERY_COMMANDS:
            return_results(get_built_in_query_results_polling_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} does not exist.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError: {e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
