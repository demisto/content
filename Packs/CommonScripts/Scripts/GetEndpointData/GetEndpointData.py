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
        command_results = []
        for command in commands:
            if not self.module_manager.is_brand_available(command):
                demisto.debug(f'Skipping command "{command.name}" since the brand {command.brand }is not available.')
                continue

            args = {command_arg_key: self._endpoint_args[endpoint_arg_key] for command_arg_key, endpoint_arg_key in command.args_mapping.items()}
            demisto.debug(f'Running command "{command.name}" with args {args}')
            current_command_results = demisto.executeCommand(command.name, args)
            demisto.debug(f'Command "{command.name}" returned {current_command_results}')

            if command.output_mapping_function:
                return command.output_mapping_function(current_command_results)

            if command.output_mapping:
                command_results.append({
                    endpoint_output_key: {'value': current_command_results[command_output_key], 'source': command.brand}
                    for command_output_key, endpoint_output_key in command.output_mapping.items()
                })

            else:
                command_results.append({
                    key: {'value': value, 'source': command.brand}
                    for key, value in current_command_results.items()
                })

            demisto.debug(f'Mapped results for command "{command.name}" are {command_results[-1]}')

        return command_results



''' HELPER FUNCTIONS '''
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

        command_results = command_runner.run_command_if_available(commands)
        demisto.debug(f"command_results: {command_results}")

    except Exception as e:
        return_error(f'Failed to execute GetEndpointData. Error: {str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
