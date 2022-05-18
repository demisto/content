from CommonServerPython import *

from typing import Dict, Any
import traceback

SERVER_SYSTEM_CONFIG_PATH = '/system/config'
''' STANDALONE FUNCTION '''


def get_current_server_config() -> dict:
    res = execute_command("demisto-api-get", {"uri": SERVER_SYSTEM_CONFIG_PATH})
    config_json = res['response']
    return config_json.get('sysConf', {})


def set_system_config(server_config: dict):
    execute_command(
        "demisto-api-post",
        {
            "uri": SERVER_SYSTEM_CONFIG_PATH,
            "body": {"data": server_config,
                     "version": -1},
        })


def remove_key_from_server_config(key: str, server_config: dict):
    if key in server_config:
        server_config.pop(key)
        set_system_config(server_config)


def update_server_config(key: str, value: str, server_config: dict):
    if not value:
        raise DemistoException(
            "EditServerConfig Error: You must give a value when you want to update a server configuration.")
    server_config[key] = value
    set_system_config(server_config)


def edit_server_config(args: Dict[str, Any]) -> CommandResults:
    action = args.get('action', "")
    key = args.get('key', "")
    value = args.get('value', "")

    sys_conf = get_current_server_config()

    if action == "update":
        update_server_config(key, value, sys_conf)
    elif action == "remove":
        remove_key_from_server_config(key, sys_conf)
    else:
        raise DemistoException("EditServerConfig Error: action must be update or remove.")

    return CommandResults(readable_output=f"Server configuration with {key} was {action}d successfully.")


def main():
    try:
        return_results(edit_server_config(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute EditServerConfig. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
