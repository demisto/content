from CommonServerPython import *
from typing import Any
from collections.abc import Callable
from itertools import zip_longest

SERVERS_RELEASES = []

""" PREPROCESS FUNCTIONS """


def check_conditions_cybereason_isolate_machine(pre_command_context) -> bool:
    #  checks preprocess_command_context
    return True


def check_conditions_cb_edr_quarantine_device(pre_command_context) -> bool:
    return True


def check_conditions_fireeye_hx_host_containment(pre_command_context) -> bool:
    return True


def check_conditions_cs_falcon_contain_host(pre_command_context) -> bool:
    return True


class Command:
    def __init__(
        self,
        brand: str,
        name: str,
        args_mapping: dict,
        post_command_name: str,
        preprocess_checks: Callable = None,
    ):
        self.brand = brand
        self.name = name
        self.args_mapping = args_mapping
        self.post_command_name = post_command_name
        self.preprocess_checks = preprocess_checks


class CommandsManager:
    def __init__(self, command_runner):
        self.command_runner = command_runner
        self.first_layer_commands_list = []
        self.second_layer_commands_list = []
        self.initialize_commands()

    def initialize_commands(self):
        first_layer_commands_list = [
            Command(
                brand='Cortex Core - IR',
                name='core-isolate-endpoint',
                args_mapping={'endpoint_id': 'agent_id'},
                post_command_name='',
                preprocess_checks=None
            ),
            Command(
                brand='Cybereason',
                name='cybereason-is-probe-connected',
                args_mapping={'machine': 'agent_hostname'},
                post_command_name='cybereason-is-probe-connected',
                preprocess_checks=None
            ),
            Command(
                brand='CrowdstrikeFalcon',
                name='cs-falcon-search-device',
                args_mapping={'ids': 'agent_id', 'hostname': 'agent_hostname'},
                post_command_name='cs-falcon-contain-host',
                preprocess_checks=None
            ),
            Command(
                brand='FireEyeHX v2',
                name='fireeye-hx-get-host-information',
                args_mapping={'agentId': 'agent_id', 'hostName': 'agent_hostname'},
                post_command_name='fireeye-hx-host-containment',
                preprocess_checks=None
            ),
            Command(
                brand='VMware Carbon Black EDR v2',
                name='cb-edr-sensors-list',
                args_mapping={'id': 'agent_id', 'ip': 'agent_ip', 'hostname': 'agent_hostname'},
                post_command_name='cb-edr-quarantine-device',
                preprocess_checks=None
            )
            # TODO to add microsoft
        ]

        second_layer_commands_list = [
            Command(
                brand='Cybereason',
                name='cybereason-isolate-machine',
                args_mapping={'machine': 'agent_hostname'},
                post_command_name='',
                preprocess_checks=check_conditions_cybereason_isolate_machine
            ),
            Command(
                brand='CrowdstrikeFalcon',
                name='cs-falcon-contain-host',
                args_mapping={'ids': 'agent_id'},
                post_command_name='',
                preprocess_checks=check_conditions_cs_falcon_contain_host
            ),
            Command(
                brand='FireEyeHX v2',
                name='fireeye-hx-host-containment',
                args_mapping={'agentId': 'agent_id', 'hostName': 'agent_hostname'},
                post_command_name='',
                preprocess_checks=check_conditions_fireeye_hx_host_containment
            ),
            Command(
                brand='VMware Carbon Black EDR v2',
                name='cb-edr-quarantine-device',
                args_mapping={'sensor_id': 'agent_id'},
                post_command_name='',
                preprocess_checks=check_conditions_cb_edr_quarantine_device
            ),
        ]
        self.first_layer_commands_list = first_layer_commands_list
        self.second_layer_commands_list = second_layer_commands_list

    def get_first_layer_command_by_name(self, name) -> Command:
        return next((cmd for cmd in self.first_layer_commands_list if cmd.name == name), None)

    def get_second_layer_command_by_name(self, name) -> Command:
        return next((cmd for cmd in self.second_layer_commands_list if cmd.name == name), None)

    def run_commands_for_endpoint(self, agent_id, agent_ip, agent_hostname):
        single_output = []
        single_human_readable = []
        for command in self.first_layer_commands_list:
            human_readable, context_outputs = not self.command_runner.run_command(
                command=command,
                args={
                    'agent_id': agent_id,
                    'agent_ip': agent_ip,
                    'agent_hostname': agent_hostname
                }
            )

            single_output.append(context_outputs)
            single_human_readable.extend(human_readable)

            if command.post_command_name:
                post_command = self.get_second_layer_command_by_name(command.post_command_name)
                if not post_command.preprocess_checks(context_outputs):
                    demisto.debug(
                        f'Skipping command "{post_command.name}" since the previous command {command} context did not'
                        f' satisfied the conditions for this command.')
                    continue
                human_readable, context_outputs = self.command_runner.run_command(
                    command=post_command,
                    args={
                        'agent_id': agent_id,
                        'agent_ip': agent_ip,
                        'agent_hostname': agent_hostname
                    }
                )

            single_output.append(context_outputs)
            single_human_readable.extend(human_readable)

        return single_human_readable, single_output


class ModuleManager:
    def __init__(self, modules: dict[str, Any], brands_to_run: list[str]) -> None:
        demisto.debug(f'Initializing ModuleManager with {modules=}')
        self.modules_context = modules
        self._brands_to_run = brands_to_run
        self._enabled_brands = {
            module.get("brand")
            for module in self.modules_context.values()
            if module.get("state") == "active"
        }

    def is_brand_in_brands_to_run(self, command: Command) -> bool:
        if self._brands_to_run:
            return command.brand in self._brands_to_run
        return True

    def is_brand_available(self, command: Command) -> bool:
        if not self.is_brand_in_brands_to_run(command):
            return False
        return command.brand in self._enabled_brands


class IsolateEndpointCommandRunner:
    def __init__(self, module_manager: ModuleManager) -> None:
        self.module_manager = module_manager

    def run_command(self, command: Command, args: dict[str, list[str] | str]):
        command_args = self.prepare_args(command, args)
        if not self.is_command_runnable(command, command_args):
            return [], []

        raw_outputs = self.run_execute_command(command, command_args)
        entry_context, human_readable, readable_errors = self.get_command_results(command.name, raw_outputs, command_args)

        if not entry_context:
            return readable_errors, []

        return human_readable, entry_context

    def is_command_runnable(self, command: Command, args: dict[str, Any]) -> bool:
        # checks if the integration required for the command is installed and active
        if not self.module_manager.is_brand_available(command):
            demisto.debug(f'Skipping command "{command.name}" since the brand {command.brand} is not available.')
            return False

        # checks if the command has argument mapping
        if command.args_mapping and not args.values():
            demisto.debug(f'Skipping command "{command.name}" since the provided arguments does not match the command.')
            return False

        return True

    @staticmethod
    def prepare_args(command, args):
        command_args = {}
        for command_arg_key, endpoint_arg_key in command.args_mapping.items():
            if command_arg_value := args.get(endpoint_arg_key):
                command_args[command_arg_key] = command_arg_value

        return command_args

    @staticmethod
    def run_execute_command(command: Command, args: dict[str, Any]) -> list[dict[str, Any]]:
        return to_list(demisto.executeCommand(command.name, args))

    @staticmethod
    def get_command_results(command: str, results: list[dict[str, Any]], args: dict[str, Any]) -> tuple[list, list, list]:
        # todo need to change the context by the pattern in the design
        command_context_outputs = []
        human_readable_outputs = []
        command_error_outputs = []
        demisto.debug(f'get_commands_outputs for command "{command}" with {len(results)} entry results')

        for entry in results:
            if is_error(entry):
                command_error_outputs.append(hr_to_command_results(command, args, get_error(entry), is_error=True))
            else:
                command_context_outputs.append(entry.get("EntryContext", {}))
                human_readable_outputs.append(entry.get("HumanReadable") or "")

        human_readable = "\n".join(human_readable_outputs)
        human_readable = [hr] if (hr := hr_to_command_results(command, args, human_readable)) else []
        return command_context_outputs, human_readable, command_error_outputs


def run_commands(commands_manager,
                 zipped_args,
                 verbose: bool = False,
                 force: bool = False,
                 ):
    human_readable_list = []
    context_list = []
    for agent_id, agent_ip, agent_hostname in zipped_args:
        if not check_servers_using_get_endpoint_data(args={'agent_id': agent_id, 'agent_ip': agent_ip,
                                                           'agent_hostname': agent_hostname}, force=force):
            continue
        single_human_readable, single_output = commands_manager.run_commands_for_endpoint(agent_id, agent_ip, agent_hostname)

        if verbose:
            human_readable_list.extend(single_human_readable)
        context_list.append(single_output)

    return human_readable_list, context_list


def check_servers_using_get_endpoint_data(args: dict, force: bool):
    get_endpoint_data_results: list[CommandResults] = execute_command(command="get-endpoint-data", args=args)
    for command_results in get_endpoint_data_results:
        server = command_results.outputs.get('Endpoint', {}).get('OS', {}).get('value')
        is_isolated = command_results.outputs.get('Endpoint', {}).get('IsIsolated', {}).get('value')
        server_status = command_results.outputs.get('Endpoint', {}).get('Status', {}).get('value')
        if server in SERVERS_RELEASES and not force:
            demisto.debug('Error with isolating the endpoint: Server detected and force parameter is False.')
        if is_isolated:
            demisto.debug('Error with isolating the endpoint: Endpoint is already isolated.')
        if server_status == 'DISCONNECTED':  # TODO to check this condition
            demisto.debug('Error with isolating the endpoint: Server is disconnected.')


def main():
    try:
        args = demisto.args()

        agent_ids = argToList(args.get("agent_id", []))
        agent_ips = argToList(args.get("agent_ip", []))
        agent_hostnames = argToList(args.get("agent_hostname", []))
        force = argToBoolean(args.get("force", False))
        brands_to_run = argToList(args.get("brands", []))
        verbose = argToBoolean(args.get("verbose", False))

        zipped_args: list[tuple] = list(zip_longest(agent_ids, agent_ips, agent_hostnames, fillvalue=''))

        module_manager = ModuleManager(
            modules=demisto.getModules(),
            brands_to_run=brands_to_run
        )
        command_runner = IsolateEndpointCommandRunner(
            module_manager=module_manager
        )
        commands_manager = CommandsManager(
            command_runner=command_runner,
        )

        human_readable_list, context_list = run_commands(
            commands_manager=commands_manager,
            zipped_args=zipped_args,
            verbose=verbose,
            force=force
        )

    except Exception as e:
        return_error(f"Failed to execute get-endpoint-data. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()