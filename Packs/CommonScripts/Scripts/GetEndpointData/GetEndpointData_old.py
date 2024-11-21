import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, Callable

class MappedCommand:
    def __init__(
        self,
        brand: str,
        name: str,
        args_mapping: dict=None,
        output_mapping: dict=None,
        output_mapping_function: Callable = None
    ):
        """
        Initialize a MappedCommand object.

        Args:
            brand (str): The brand associated with the command.
            name (str): The name of the command.
            args_mapping (dict): A dictionary containing the command arguments
            output_mapping (dict): A dictionary containing the output of the command.
        """
        self.brand = brand
        self.name = name
        self.args_mapping = args_mapping
        self.output_mapping = output_mapping
        self.output_mapping_function = output_mapping_function

    def __repr__(self):
        return f'{{ name: {self.name}, brand: {self.brand} }}'


class ModuleManager:
    def __init__(self, modules: dict[str, Any], brands_to_run: list[str]) -> None:
        """
        Initialize the Modules instance.

        Args:
            modules (dict[str, Any]): A dictionary containing module information.
            brands_to_run (list[str]): A list of brands to run.

        Attributes:
            modules_context (dict[str, Any]): The modules dictionary.
            _brands_to_run (list[str]): The list of brands to run.
            _enabled_brands (set[str]): A set of active brands extracted from the modules.
        """
        demisto.debug(f'Initializing module manager with ')
        self.modules_context = modules
        self._brands_to_run = brands_to_run
        self._enabled_brands = {
            module.get("brand")
            for module in self.modules_context.values()
            if module.get("state") == "active"
        }

    def is_brand_in_brands_to_run(self, command: MappedCommand) -> bool:
        """
        Check if a brand is in the list of brands to run.

        Args:
            command (Command): The command object containing the brand to check.

        Returns:
            bool: True if the brand is in the list of brands to run, False otherwise.
        """
        return command.brand in self._brands_to_run if self._brands_to_run else True

    def is_brand_available(self, command: MappedCommand) -> bool:
        """
        Check if a brand is available and in the list of brands to run.

        Args:
            command (Command): The command object containing the brand to check.

        Returns:
            bool: True if the brand is available and in the list of brands to run, False otherwise.
        """
        is_available = command.brand in self._enabled_brands
        if not self.is_brand_in_brands_to_run(command):
            is_available = False

        return is_available


class CommandRunner:
    def __init__(self, module_manager: ModuleManager, endpoint_args: dict[str, Any]):
        self.module_manager = module_manager
        self._endpoint_args = endpoint_args

    def run_command_if_available(self, commands: list[MappedCommand]) -> list[dict[str, Any]]:
        command_results = self._run_execute_command(commands)
        command_outputs = self._get_commands_outputs(command_results)
        demisto.debug(f'ran commands and returning {command_outputs=}')
        return command_outputs


    def _run_execute_command(self, commands: list[MappedCommand]) -> list[dict[str, Any]]:
        command_results = []

        for command in commands:
            if not self.module_manager.is_brand_available(command):
                demisto.debug(f'Skipping command "{command.name}" since the brand {command.brand}is not available.')
                continue

            args = {
                command_arg_key: self._endpoint_args[endpoint_arg_key] if self._endpoint_args[endpoint_arg_key] else None
                    for command_arg_key, endpoint_arg_key in command.args_mapping.items()
            }
            demisto.debug(f'Running command "{command.name}" with args {args}')
            current_command_results = to_list(demisto.executeCommand(command.name, args))
            demisto.debug(f'Command "{command.name}" returned {current_command_results}')
            command_results.append({'command': command, 'results': current_command_results})
        return command_results

    def _get_commands_outputs(self, command_results: list[dict[str, Any]]):
        demisto.debug(f'starting _get_command_outputs with {command_results=}')
        outputs = []
        for curr_result in command_results:
            command, result = curr_result['command'], curr_result['results']
            args = {command_arg_key: self._endpoint_args[endpoint_arg_key] for command_arg_key, endpoint_arg_key in
                command.args_mapping.items()}
            command_context_outputs = []
            human_readable_outputs = []
            command_error_outputs = []
            demisto.debug(f'extracting outputs for command "{command.name}" with result {result}')

            for entry in result:
                demisto.debug(f'entry{json.dumps(entry)}')
                command_context_outputs.append(entry.get("EntryContext", {}))
                if is_error(entry):
                    command_error_outputs.extend(
                        prepare_human_readable(
                            command.name, args, get_error(entry), is_error=True
                        )
                    )
                else:
                    human_readable_outputs.append(entry.get("HumanReadable") or "")
            human_readable = "\n".join(human_readable_outputs)
            command_outputs = {
                'command': command,
                'context': command_context_outputs,
                'hr': human_readable,
                'errors': command_error_outputs
            }
            demisto.debug(f'{command_outputs=}')
            outputs.append(command_outputs)
        return outputs

    def _map_command_results(self, command_results: list[dict[str, Any]]):
        for curr_command_result in command_results:
            command = curr_command_result.get('command')
            if command.output_mapping_function:
                return command.output_mapping_function(curr_command_result)

            if command.output_mapping:
                command_results.append({
                    endpoint_output_key: {'value': curr_command_result[command_output_key], 'source': command.brand}
                    for command_output_key, endpoint_output_key in command.output_mapping.items()
                })

            else:
                command_results.append({
                    key: {'value': value, 'source': command.brand}
                    for key, value in curr_command_result.items()
                })

            demisto.debug(f'Mapped results for command "{command.name}" are {command_results[-1]}')



''' HELPER FUNCTIONS '''
to_list = lambda var: [var] if not isinstance(var, list) else var

def get_clean_output_key(full_output_key: str): return full_output_key[:full_output_key.index('(')]


def get_full_output_key(output_key: str, raw_context: dict[str, Any]) -> str:
    """
    Retrieves the full output key from the raw_context dictionary.

    This function searches for the output key in the raw_context dictionary. If an exact match is not found,
    it looks for a key that starts with the given output_key followed by an opening parenthesis.

    Args:
        output_key (str): The base output key to search for.
        raw_context (dict[str, Any]): The dictionary containing the raw_context.

    Returns:
        str: The full output key if found, otherwise an empty string.

    Example:
        raw_context = {
            "Account(val.ID == obj.ID)": [
                {
                    "Username": "john.doe",
                    "Email": "john.doe@example.com",
                    "DisplayName": "John Doe"
                }
            ]
        }
        output_key = "Account"
        result = get_outputs(output_key, raw_context)
        # result will be: "Account(val.Username == obj.Username)"
    """
    full_output_key = ""
    if raw_context:
        if output_key in raw_context:
            full_output_key = output_key
        else:
            for key in raw_context:
                if key.startswith(f"{output_key}("):
                    full_output_key = key
                    break
        if not full_output_key:
            demisto.debug(
                f"Output key {output_key} not found in entry context keys: {list(raw_context.keys())}"
            )
    return full_output_key

def get_outputs(output_key: str, raw_context: dict[str, Any]) -> dict[str, Any]:
    """
    Retrieves the output context for a given output key from the raw context.

    This function uses the get_output_key function to find the full output key,
    then extracts the corresponding context from the raw_context dictionary.
    If the context is a list, it returns the first item.

    Args:
        output_key (str): The base output key to search for.
        raw_context (dict[str, Any]): The raw context dictionary to search in.

    Returns:
        dict[str, Any]: The extracted context for the given output key,
        or an empty dictionary if not found.

    Example:
        raw_context = {
            "Account(val.Username == obj.Username)": [
                {
                    "Username": "john.doe",
                    "Email": "john.doe@example.com",
                    "DisplayName": "John Doe"
                }
            ]
        }
        output_key = "Account(val.Username == obj.Username)"
        result = get_outputs(output_key, raw_context)
        # result will be:
        # {
        #     "Username": "john.doe",
        #     "Email": "john.doe@example.com",
        #     "DisplayName": "John Doe"
        # }

    """
    if raw_context and output_key:
        context = raw_context.get(output_key, {})
        if not isinstance(context, list):
            context = [context]
    else:
        context = {}
    return context

def prepare_human_readable(
    command_name: str, args: dict[str, Any], human_readable: str, is_error: bool = False
) -> list[CommandResults]:
    """
    Prepare human-readable output for a command execution.

    Args:
        command_name (str): The name of the command executed.
        args (dict[str, Any]): The arguments passed to the command.
        human_readable (str): The human-readable output of the command.
        is_error (bool, optional): Whether the command resulted in an error. Defaults to False.

    Returns:
        list[CommandResults]: A list containing CommandResults objects with the formatted output.
    """
    result = []
    if human_readable:
        command = f'!{command_name} {" ".join([f"{arg}={value}" for arg, value in args.items() if value])}'
        if not is_error:
            result_message = f"#### Result for {command}\n{human_readable}"
            result.append(
                CommandResults(readable_output=result_message, mark_as_note=True)
            )
        else:
            result_message = f"#### Error for {command}\n{human_readable}"
            result.append(
                CommandResults(
                    readable_output=result_message,
                    entry_type=EntryType.ERROR,
                    mark_as_note=True,
                )
            )
    return result

def get_nested_value(d, key_path):
    keys = key_path.split('.')
    value = d
    try:
        for clean_key in keys:
            full_key = get_full_output_key(clean_key, value)
            value = value[full_key]
        return value
    except KeyError:
        return None

def build_endpoints(command_outputs: list[dict[str, Any]]):
    """
    command_outputs = {
                'command': command,
                'context': command_context_outputs,
                'hr': human_readable,
                'errors': command_error_outputs
            }
    """
    endpoints = []
    for output in command_outputs:
        command, context, hr, errors = output['command'], output['context'], output['hr'], output['errors']
        if command.output_mapping_function:
            continue
        elif command.output_mapping:
            endpoint = {}
            for command_output_key, endpoint_output_key in command.output_mapping.items():
                endpoint[endpoint_output_key] = get_nested_value(context, command_output_key)
            endpoints.append(endpoint)

        for entry in context:
            endpoint = {}
            for key, value in entry.items():
                endpoint[key] = value



'''MAPPING FUNCTIONS'''
def map_extrahop_outputs(command_results: CommandResults):
    pass

''' MAIN FUNCTION '''


def main():
    try:
        demisto.debug(f'starting get-endpoint-data {demisto.args()}')
        args = demisto.args()
        agent_ids = argToList(args.get("agent_id", []))
        agent_ips = argToList(args.get("agent_ip", []))
        agent_host_names = argToList(args.get("agent_hostname", []))
        brands_to_run = argToList(args.get("brands", []))
        verbose = argToBoolean(args.get("verbose", False))
        modules = demisto.getModules()

        module_manager = ModuleManager(modules, brands_to_run)

        command_runner = CommandRunner(module_manager, {
            'agent_id': agent_ids,
            'agent_ip': agent_ips,
            'agent_hostname': agent_host_names
        })

        ad_get_computer_mapped_command = MappedCommand(
            brand='Active Directory Query v2',
            name='ad-get-computer',
            args_mapping={'name': 'agent_hostname'}
        )

        epo_find_system_mapped_command = MappedCommand(
            brand='McAfee ePO v2',
            name='epo-find-system',
            args_mapping={'searchText': 'agent_hostname'}
        )

        cb_edr_sensors_list_mapped_command = MappedCommand(
            brand='VMware Carbon Black EDR v2',
            name='cb-edr-sensors-list',
            args_mapping={'hostname': 'agent_hostname', 'id': 'agent_id', 'ip': 'agent_ip'},
            output_mapping={ 'id': 'ID', 'computer_name': 'Hostname', 'status': 'Status' }
        )

        extrahop_devices_search_mapped_command = MappedCommand(
            brand='ExtraHop v2',
            name='extrahop-devices-search',
            args_mapping={'name': 'agent_hostname'},
            output_mapping_function=map_extrahop_outputs
        )

        cs_falcon_search_device_mapped_command = MappedCommand(
            brand='CrowdstrikeFalcon',
            name='cs-falcon-search-device',
            args_mapping={'ids': 'agent_id', 'hostname': 'agent_hostname'}
        )

        xdr_get_endpoints_mapped_command = MappedCommand(
            brand='Cortex XDR - IR',
            name='xdr-get-endpoints',
            args_mapping={'endpoint_id_list': 'agent_id', 'ip_list': 'agent_ip', 'hostname': 'agent_hostname'}
        )

        xdr_list_risky_hosts_mapped_command = MappedCommand(
            brand='Cortex XDR - IR',
            name='xdr-list-risky-hosts',
            args_mapping={'host_id': 'agent_id'},
            output_mapping={'id': 'ID'}
        )

        core_list_risky_hosts_mapped_command = MappedCommand(
            brand='Cortex Core - IR',
            name='core-list-risky-hosts',
            args_mapping={'host_id': 'agent_id'},
            output_mapping={'id': 'ID'}
        )

        core_get_endpoints_mapped_command = MappedCommand(
            brand='Cortex Core - IR',
            name='core-get-endpoints',
            args_mapping={'endpoint_id_list': 'agent_id', 'ip_list': 'agent_ip', 'hostname': 'agent_hostname'}
        )

        commands = [
            ad_get_computer_mapped_command,
            epo_find_system_mapped_command,
            cb_edr_sensors_list_mapped_command,
            extrahop_devices_search_mapped_command,
            cs_falcon_search_device_mapped_command,
            xdr_get_endpoints_mapped_command,
            xdr_list_risky_hosts_mapped_command,
            core_list_risky_hosts_mapped_command,
            core_get_endpoints_mapped_command
        ]

        command_outputs = command_runner.run_command_if_available(commands)
        build_endpoint(command_outputs)

    except Exception as e:
        return_error(f'Failed to execute GetEndpointData. Error: {str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
