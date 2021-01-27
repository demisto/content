import re
from datetime import datetime
from time import sleep

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def walk_key(input_list: list = [], structure: dict = {}):
    found = True
    current_dict = structure
    for key in input_list:
        if key.startswith("[") and key.endswith("]"):
            try:
                index = int(key[1:-1])
                current_dict = current_dict[index]
            except:
                found = False
                break
        else:
            try:
                current_dict = current_dict.get(key)
            except:
                found = False
                break

    return current_dict if found else None


def main():
    debug = True
    args = demisto.args()
    command = args.get('PollingCommandName')
    id_argument_name = args.get('PollingCommandArgName')
    initial_command_id = args.get('InitialId')
    consequent_id_key_name = args.get('ConsequentIdKeyName', '').split(".")
    monitor_key_name = args.get('PollingCommandMonitorKeyName').split(".")
    monitor_regex = args.get('PollingCommandRegex', '.+')
    additional_arguments = args.get('AdditionalPollingCommandArgs', None)
    if additional_arguments:
        if type(additional_arguments) != dict:
            try:
                additional_arguments = json.loads(additional_arguments)
            except Exception as err:
                return_error(f"'additional_arguments' should be a JSON dict - {err}")
    timeout = args.get('Timeout', 10)
    delay = args.get('Delay', 10)
    runs = 0

    compiled_regex = re.compile('.+')
    try:
        compiled_regex = re.compile(monitor_regex)
    except Exception as err:
        return_error(f"'monitor_regex' is not valid - {err}")

    try:
        timeout = int(timeout)
    except Exception as err:
        return_error(f"'timeout' should be a valid integer - {err}")

    try:
        delay = int(delay)
    except Exception as err:
        return_error(f"'delay' should be a valid integer - {err}")

    continue_running = True

    command_args = {
        id_argument_name: initial_command_id
    }
    if additional_arguments and type(additional_arguments) == dict:
        command_args.extend(additional_args)

    start = datetime.utcnow()
    found = False

    while continue_running:
        try:
            result = demisto.executeCommand(command, command_args)[0]['Contents']
        except Exception as err:
            reutrn_error(f"Error executing {command} - {err}")
        runs += 1
        result_key_value = walk_key(input_list=monitor_key_name, structure=result)
        if result_key_value and compiled_regex.match(result_key_value):
            continue_running = False
            found = True
        if not continue_running:
            break
        if consequent_id_key_name:
            new_id = walk_key(input_list=consequent_id_key_name, structure=result)
            if new_id:
                command_args[id_argument_name] = new_id

        now = datetime.utcnow()
        if (now - start).total_seconds() > (timeout * 60):
            continue_running = False
        sleep(delay)

    command_results = CommandResults(
        outputs_prefix="",
        outputs_key_field="PollingSuccessful",
        outputs={
            "GenericPolling": {
                "PollingSucccessful": found,
                "FinalResult": {
                    ".".join(monitor_key_name): result_key_value
                },
                "Runs": runs
            }
        },
        readable_output=f"PollingSuccessful - {found}"
    )
    return_results(command_results)


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
