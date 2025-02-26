from CommonServerPython import *
from typing import Any
from collections.abc import Callable
from itertools import zip_longest

SERVERS_RELEASES = []  # TODO

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


""" COMMAND CLASS """


class Command:
    def __init__(
        self,
        brand: str,
        name: str,
        args_mapping: dict,
        post_cmd_name: str = '',
        post_cmd_check: Callable = None,
    ):
        self.brand = brand
        self.name = name
        self.args_mapping = args_mapping
        self.post_cmd_name = post_cmd_name
        self.post_cmd_check = post_cmd_check


""" COMMANDS MANAGER CLASS """


class CommandsManager:
    def __init__(self):
        self.first_layer_commands_list = []
        self.second_layer_commands_list = []
        self.initialize_commands()

    def initialize_commands(self):
        first_layer_commands_list = [
            Command(
                brand='Cortex Core - IR',
                name='core-isolate-endpoint',
                args_mapping={'endpoint_id': 'agent_id'},
                post_cmd_name='',
                post_cmd_check=None
            ),
            Command(
                brand='Cybereason',
                name='cybereason-is-probe-connected',
                args_mapping={'machine': 'agent_hostname'},
                post_cmd_name='cybereason-is-probe-connected',
                post_cmd_check=check_conditions_cybereason_isolate_machine
            ),
            Command(
                brand='CrowdstrikeFalcon',
                name='cs-falcon-search-device',
                args_mapping={'ids': 'agent_id', 'hostname': 'agent_hostname'},
                post_cmd_name='cs-falcon-contain-host',
                post_cmd_check=check_conditions_cs_falcon_contain_host
            ),
            Command(
                brand='FireEyeHX v2',
                name='fireeye-hx-get-host-information',
                args_mapping={'agentId': 'agent_id', 'hostName': 'agent_hostname'},
                post_cmd_name='fireeye-hx-host-containment',
                post_cmd_check=check_conditions_fireeye_hx_host_containment
            ),
            Command(
                brand='VMware Carbon Black EDR v2',
                name='cb-edr-sensors-list',
                args_mapping={'id': 'agent_id', 'ip': 'agent_ip', 'hostname': 'agent_hostname'},
                post_cmd_name='cb-edr-quarantine-device',
                post_cmd_check=check_conditions_cb_edr_quarantine_device
            )
            # TODO to add microsoft
        ]

        second_layer_commands_list = [
            Command(
                brand='Cybereason',
                name='cybereason-isolate-machine',
                args_mapping={'machine': 'agent_hostname'},
                post_cmd_name='',
                post_cmd_check=None
            ),
            Command(
                brand='CrowdstrikeFalcon',
                name='cs-falcon-contain-host',
                args_mapping={'ids': 'agent_id'},
                post_cmd_name='',
                post_cmd_check=None
            ),
            Command(
                brand='FireEyeHX v2',
                name='fireeye-hx-host-containment',
                args_mapping={'agentId': 'agent_id', 'hostName': 'agent_hostname'},
                post_cmd_name='',
                post_cmd_check=None
            ),
            Command(
                brand='VMware Carbon Black EDR v2',
                name='cb-edr-quarantine-device',
                args_mapping={'sensor_id': 'agent_id'},
                post_cmd_name='',
                post_cmd_check=None
            ),
        ]
        self.first_layer_commands_list = first_layer_commands_list
        self.second_layer_commands_list = second_layer_commands_list

    def get_first_layer_command_by_name(self, name) -> Command:
        return next((cmd for cmd in self.first_layer_commands_list if cmd.name == name), None)

    def get_second_layer_command_by_name(self, name) -> Command:
        return next((cmd for cmd in self.second_layer_commands_list if cmd.name == name), None)


""" MODULE MANAGER CLASS """


class ModuleManager:
    def __init__(self, brands_to_run: list[str]) -> None:
        self.modules_context = demisto.getModules()
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


""" HELPER FUNCTIONS """


def check_endpoint_data_results(endpoint_data, force: bool) -> bool:
    server = endpoint_data.get('os_environment_display_string', {}).get('Value')
    is_isolated = endpoint_data.get('is_isolating', {}).get('Value')
    server_status = endpoint_data.get('Status', {}).get('Value')

    if server in SERVERS_RELEASES and not force:
        demisto.debug('Error with isolating endpoint: Server detected and force parameter is False.')
        return False
    elif is_isolated:
        demisto.debug('Error with isolating the endpoint: Endpoint is already isolated.')
        return False
    elif server_status == 'Offline':  # TODO to check this condition
        demisto.debug('Error with isolating the endpoint: Server is disconnected.')
        return False
    return True


def create_message_to_context_and_hr(endpoint_data, result, brand, message):
    endpoint_name = endpoint_data.get('agent_hostname') or endpoint_data.get('agent_id') or endpoint_data.get('agent_ip')
    context = {
        'endpoint_name': endpoint_name,
        'results': {
            'result': result,
            'brand': brand,
            'message': message
        }
    }
    hr = {
        'Status': result,
        'Result': result,
        'Entity': endpoint_name,
        'Message': message
    }

    return context, hr


def check_missing_args(args_mapping: dict, args: dict) -> list[str]:
    missing_keys = [key for key in args_mapping.values() if key not in args]
    return missing_keys


def map_args(args_mapping: dict, args: dict) -> dict:
    return {k: args[v] for k, v in args_mapping.items()}


def map_zipped_args(agent_ids, agent_ips, agent_hostnames):
    return [
        {'agent_id': agent_id, 'agent_hostname': agent_hostname, 'agent_ip': agent_ip}
        for agent_id, agent_ip, agent_hostname in zip_longest(agent_ids, agent_ips, agent_hostnames, fillvalue='')
    ]

def main():
    # results = execute_command('cb-edr-sensors-list', {})
    # demisto.debug(f'these are the results from executeCommandBatch {results}')
    # get_endpoint_data_results = execute_command(command="get-endpoint-data",
                                                # args={'agent_hostname': 'WIN-SOSSKVTTQAB,justesting'})
    # demisto.debug(f'these are the results from get_endpoint_data_results execute_command {get_endpoint_data_results}')
    # get_endpoint_data_results = demisto.executeCommand(command="get-endpoint-data",
                                                       # args={'agent_hostname': 'WIN-SOSSKVTTQAB,justesting'})
    # demisto.debug(f'these are the results from get_endpoint_data_results demisto.executeCommand {get_endpoint_data_results}')
    crowstrike = execute_command(command="cs-falcon-search-device",
                                                args={'ids': '8ed44198a6f64f9fabd0479c3098f303'})
    demisto.debug(f'these are the results from crowstrike execute_command {crowstrike}')

    try:
        args = demisto.args()
        agent_ids = argToList(args.get("agent_id", []))
        agent_ips = argToList(args.get("agent_ip", []))
        agent_hostnames = argToList(args.get("agent_hostname", []))
        force = argToBoolean(args.get("force", False))
        verbose = argToBoolean(args.get("verbose", False))
        brands_to_run = argToList(args.get('brands', []))

        zipped_args = map_zipped_args(agent_ids, agent_ips, agent_hostnames)

        get_endpoint_data_results = execute_command(command="get-endpoint-data", args=args)
        if not isinstance(get_endpoint_data_results, list):
            get_endpoint_data_results = [get_endpoint_data_results]

        outputs = []  # TODO global?
        human_readable_outputs = []  # TODO global?
        valid_args = []
        for endpoint_data in get_endpoint_data_results:
            agent_hostname = endpoint_data.get('Hostname', {}).get('Value')
            agent_id = endpoint_data.get('ID', {}).get('Value')
            agent_ip = endpoint_data.get('IPAddress', {}).get('Value')  # Maybe network_adapters?
            if check_endpoint_data_results(endpoint_data, force):
                args = {'agent_id': agent_id, 'agent_hostname': agent_hostname, 'agent_ip': agent_ip}
                valid_args.append(args)
            else:
                context, hr = create_message_to_context_and_hr(endpoint_data=args,
                                                               result='Fail',
                                                               brand='GetEndpointData',
                                                               message='Failed to execute GetEndpointData script.')
                outputs.append(context)
                if verbose:
                    human_readable_outputs.append(hr)

        # TODO to check which (id, ip, hostname) failed

        command_manager = CommandsManager()
        module_manager = ModuleManager(brands_to_run)
        second_layer_commands_to_run = []
        for args in valid_args:
            for command in command_manager.first_layer_commands_list:
                if not module_manager.is_brand_available(command):
                    context, hr = create_message_to_context_and_hr(endpoint_data=args,
                                                     result='Fail',
                                                     brand=command.brand,
                                                     message='Brand is not available.')
                    outputs.append(context)
                    if verbose:
                        human_readable_outputs.append(hr)
                    continue
                missing_args = check_missing_args(command.args_mapping, args)
                if missing_args:
                    context, hr = create_message_to_context_and_hr(endpoint_data=args,
                                                     result='Fail',
                                                     brand=command.brand,
                                                     message=f'Missing the next args: {missing_args} for {command.name}.')
                    outputs.append(context)
                    if verbose:
                        human_readable_outputs.append(hr)
                    continue
                mapped_args = map_args(command.args_mapping, args)
                raw_response = execute_command(command.name, mapped_args)
                if not raw_response:
                    context, hr = create_message_to_context_and_hr(endpoint_data=args,
                                                     result='Fail',
                                                     brand=command.brand,
                                                     message=f'Failed to execute command {command.name}.')
                    outputs.append(context)
                    if verbose:
                        human_readable_outputs.append(hr)
                    continue
                if command.post_cmd_check(raw_response):
                    post_cmd = command_manager.get_second_layer_command_by_name(command.post_cmd_name)
                    second_layer_commands_to_run.append((args, post_cmd))

    except Exception as e:
        return_error(f"Failed to execute get-endpoint-data. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
