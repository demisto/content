from CommonServerPython import *
from typing import Any
from collections.abc import Callable
from itertools import zip_longest

SERVERS_RELEASES = ["Windows Server 2019",
                    "Windows Server 2016",
                    "Windows Server 2012 R2",
                    "Windows Server 2008 R2",
                    "Ubuntu Server",
                    "CentOS",
                    "Red Hat Enterprise Linux (RHEL)",
                    "Fedora Server",
                    "Debian",
                    "SUSE Linux Enterprise Server (SLES)",
                    "Oracle Linux",
                    "IBM AIX",
                    "HP-UX",
                    "Solaris",
                    "FreeBSD",
                    "OpenBSD",
                    "NetBSD",
                    "VMware ESXi",
                    "Proxmox VE",
                    "OpenVMS",
                    "ZOS"
                    ]

""" PRE COMMAND CLASS """


class PreCommand:
    def __init__(
        self,
        brand: str,
        name: str,
        args_mapping: dict,
        post_cmd_name: str = '',
    ):
        self.brand = brand
        self.name = name
        self.args_mapping = args_mapping
        self.post_cmd_name = post_cmd_name


""" COMMAND CLASS """


class Command:
    def __init__(
        self,
        brand: str,
        name: str,
        args_mapping: dict,
        pre_command_name: str = '',
        pre_command_check: Callable = None
    ):
        self.brand = brand
        self.name = name
        self.args_mapping = args_mapping
        self.pre_command_name = pre_command_name
        self.pre_command_check = pre_command_check


""" COMMANDS MANAGER CLASS """


class CommandsManager:
    def __init__(self):
        self.pre_commands = []
        self.commands = []
        self.initialize_commands()

    def initialize_commands(self):
        pre_commands = [
            PreCommand(
                brand='Cybereason',
                name='cybereason-is-probe-connected',
                args_mapping={'machine': 'agent_hostname'},
                post_cmd_name='cybereason-is-probe-connected',
            ),
            PreCommand(
                # TODO to add to get-endpoint-data
                brand='FireEyeHX v2',
                name='fireeye-hx-get-host-information',
                args_mapping={'agentId': 'agent_id', 'hostName': 'agent_hostname'},
                post_cmd_name='fireeye-hx-host-containment',
            ),
            PreCommand(
                brand='Microsoft Defender Advanced Threat Protection',
                name='endpoint',
                args_mapping={},
                post_cmd_name='microsoft-atp-isolate-machine',
            )
        ]

        commands = [
            Command(
                brand='Cortex Core - IR',
                name='core-isolate-endpoint',
                args_mapping={'endpoint_id': 'agent_id'},
                pre_command_name='',
                pre_command_check=None
            ),
            Command(
                brand='Cybereason',
                name='cybereason-isolate-machine',
                args_mapping={'machine': 'agent_hostname'},
                pre_command_name='cybereason-is-probe-connected',
                pre_command_check=check_conditions_cybereason_isolate_machine
            ),
            Command(
                brand='CrowdstrikeFalcon',
                name='cs-falcon-contain-host',
                args_mapping={'ids': 'agent_id'},
                pre_command_name='',
                pre_command_check=check_conditions_cs_falcon_contain_host,
            ),
            Command(
                brand='FireEyeHX v2',
                name='fireeye-hx-host-containment',
                args_mapping={'agentId': 'agent_id', 'hostName': 'agent_hostname'},
                pre_command_name='fireeye-hx-get-host-information',
                pre_command_check=check_conditions_fireeye_hx_host_containment,
            ),
            Command(
                brand='VMware Carbon Black EDR v2',
                name='cb-edr-quarantine-device',
                args_mapping={'sensor_id': 'agent_id'},
                pre_command_name='',
                pre_command_check=check_conditions_cb_edr_quarantine_device,
            ),
            Command(
                brand='Microsoft Defender Advanced Threat Protection',
                name='microsoft-atp-isolate-machine',
                args_mapping={},
                pre_command_name='endpoint',
                pre_command_check=check_conditions_microsoft_atp_isolate_machine
            ),
        ]
        self.pre_commands = pre_commands
        self.commands = commands

    def get_pre_command(self, name) -> Command:
        return next((cmd for cmd in self.pre_commands if cmd.name == name), None)

    def get_command(self, name) -> Command:
        return next((cmd for cmd in self.commands if cmd.name == name), None)


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


""" PREPROCESS FUNCTIONS """


def check_conditions_cb_edr_quarantine_device(module_manager, verbose, pre_command, outputs, human_readable_outputs, args, endpoint_data) -> bool:
    if not check_validation_for_running_command(module_manager, verbose, pre_command, outputs, human_readable_outputs, args):
        #insert an error
        return False
    # check another conditions for the endpoint_data - if false - insert an error and return False
    return True


def check_conditions_cybereason_isolate_machine(module_manager, verbose, pre_command, outputs, human_readable_outputs, args, endpoint_data):
    if not check_validation_for_running_command(module_manager, verbose, pre_command, outputs, human_readable_outputs, args):
        #insert an error
        return False
    return True


def check_conditions_fireeye_hx_host_containment(module_manager, verbose, pre_command, outputs, human_readable_outputs, args, endpoint_data) -> bool:
    if not check_validation_for_running_command(module_manager, verbose, pre_command, outputs, human_readable_outputs, args):
        #insert an error
        return False
    return True


def check_conditions_cs_falcon_contain_host(module_manager, verbose, pre_command, outputs, human_readable_outputs, args, endpoint_data) -> bool:
    if not check_validation_for_running_command(module_manager, verbose, pre_command, outputs, human_readable_outputs, args):
        #insert an error
        return False
    return True


def check_conditions_microsoft_atp_isolate_machine(module_manager, verbose, pre_command, outputs, human_readable_outputs, args, endpoint_data) -> bool:
    if not check_validation_for_running_command(module_manager, verbose, pre_command, outputs, human_readable_outputs, args):
        #insert an error
        return False
    return True


""" HELPER FUNCTIONS """


def check_validation_for_running_command(module_manager, verbose, command, outputs, human_readable_outputs, args):
    if not module_manager.is_brand_available(command):  # checks if brand is enable
        create_message_to_context_and_hr(endpoint_data=args,
                                         result='Fail',
                                         brand=command.brand,
                                         message='Brand is not available.',
                                         outputs=outputs,
                                         human_readable_outputs=human_readable_outputs,
                                         verbose=verbose)
        return False

    missing_args = check_missing_args(command.args_mapping, args)  # checks that there are not missing args
    if missing_args:
        create_message_to_context_and_hr(endpoint_data=args,
                                         result='Fail',
                                         brand=command.brand,
                                         message=f'Missing the next args: {missing_args} for {command.name}.',
                                         outputs=outputs,
                                         human_readable_outputs=human_readable_outputs,
                                         verbose=verbose)
        return False


def check_endpoint_data_results(endpoint_data: dict, force: bool, server_os: list) -> bool:
    server = endpoint_data.get('os_environment_display_string', {}).get('Value')
    is_isolated = endpoint_data.get('is_isolating', {}).get('Value')
    server_status = endpoint_data.get('Status', {}).get('Value')

    if (server in SERVERS_RELEASES or server in server_os) and not force:
        demisto.debug('Error with isolating endpoint: Server detected and force parameter is False.')
        return False
    elif is_isolated:
        demisto.debug('Error with isolating the endpoint: Endpoint is already isolated.')
        return False
    elif server_status == 'Offline':  # TODO to check this condition
        demisto.debug('Error with isolating the endpoint: Server is disconnected.')
        return False
    return True


def create_message_to_context_and_hr(endpoint_data, result, brand, message, outputs, human_readable_outputs, verbose):
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
    outputs.append(context)
    if verbose:
        human_readable_outputs.append(hr)


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


def do_args_exist_in_valid(zipped_args, valid_args):
    for agent_id, agent_ip, agent_hostname in zipped_args:
        if any(
            (agent_id and agent_id in (entry.get("agent_id") for entry in valid_args)) or
            (agent_ip and agent_ip in (entry.get("agent_ip") for entry in valid_args)) or
            (agent_hostname and agent_hostname in (entry.get("agent_hostname") for entry in valid_args))
        ):
            return True
    return False


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
        server_os = argToList(args.get('server_os', []))

        command_manager = CommandsManager()
        module_manager = ModuleManager(brands_to_run)

        zipped_args = map_zipped_args(agent_ids, agent_ips, agent_hostnames)

        get_endpoint_data_results = execute_command(command="get-endpoint-data", args=args)
        if not isinstance(get_endpoint_data_results, list):
            get_endpoint_data_results = [get_endpoint_data_results]

        outputs = []
        human_readable_outputs = []
        args_returned_in_get_endpoint_data_results = []
        for endpoint_data in get_endpoint_data_results:
            agent_hostname = endpoint_data.get('Hostname', {}).get('Value')
            agent_id = endpoint_data.get('ID', {}).get('Value')
            agent_ip = endpoint_data.get('IPAddress', {}).get('Value')  # Maybe network_adapters?
            args = {'agent_id': agent_id, 'agent_hostname': agent_hostname, 'agent_ip': agent_ip}

            if not check_endpoint_data_results(endpoint_data, force, server_os):
                create_message_to_context_and_hr(endpoint_data=args,
                                                 result='Fail',
                                                 brand='GetEndpointData',
                                                 message='Failed to execute GetEndpointData script.',
                                                 outputs=outputs,
                                                 human_readable_outputs=human_readable_outputs,
                                                 verbose=verbose)
                continue

            for command in command_manager.commands:
                pre_command = command_manager.get_pre_command(command.pre_command_name)
                if not command.pre_command_check(module_manager, verbose, pre_command, outputs, human_readable_outputs, args, endpoint_data):
                    continue
                if not check_validation_for_running_command(module_manager, verbose, command, outputs, human_readable_outputs, args):
                    continue
                mapped_args = map_args(command.args_mapping, args)
                raw_response = execute_command(command.name, mapped_args)
                if not raw_response:
                    create_message_to_context_and_hr(endpoint_data=args,
                                                     result='Fail',
                                                     brand=command.brand,
                                                     message=f'Failed to execute command {command.name}.',
                                                     outputs=outputs,
                                                     human_readable_outputs=human_readable_outputs,
                                                     verbose=verbose)
                    continue
                else:
                    create_message_to_context_and_hr(endpoint_data=args,
                                                     result='Success',
                                                     brand=command.brand,
                                                     message=f'Command {command.name} was executed successfully.',
                                                     outputs=outputs,
                                                     human_readable_outputs=human_readable_outputs,
                                                     verbose=verbose)


        # TODO to check which (id, ip, hostname) don't appear in get_endpoint_data results

    except Exception as e:
        return_error(f"Failed to execute isolate-endpoint. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
