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

""" COMMAND CLASS """


class Command:
    def __init__(
        self,
        brand: str,
        name: str,
        args_mapping: dict,
        pre_command_check: Callable = None
    ):
        self.brand = brand
        self.name = name
        self.args_mapping = args_mapping
        self.pre_command_check = pre_command_check


def initialize_commands() -> list:
    # pre_commands = [
    #     PreCommand(
    #         brand='Cybereason',
    #         name='cybereason-is-probe-connected',
    #         args_mapping={'machine': 'agent_hostname'},
    #         post_cmd_name='cybereason-is-probe-connected',
    #     ),
    #     PreCommand(
    #         # TODO to add to get-endpoint-data
    #         brand='FireEyeHX v2',
    #         name='fireeye-hx-get-host-information',
    #         args_mapping={'agentId': 'agent_id', 'hostName': 'agent_hostname'},
    #         post_cmd_name='fireeye-hx-host-containment',
    #     ),
    #     PreCommand(
    #         # TODO to add to get-endpoint-data
    #         brand='Microsoft Defender Advanced Threat Protection',
    #         name='endpoint',
    #         args_mapping={},
    #         post_cmd_name='microsoft-atp-isolate-machine',
    #     )
    # ]

    commands = [
        # Command(
        #     brand='Cortex Core - IR',
        #     name='core-isolate-endpoint',
        #     args_mapping={'endpoint_id': 'agent_id'},
        #     pre_command_check=None
        # ),
        # Command(
        #     brand='Cybereason',
        #     name='cybereason-isolate-machine',
        #     args_mapping={'machine': 'agent_hostname'},
        #     pre_command_check=check_conditions_cybereason_isolate_machine
        # ),
        Command(
            brand='CrowdstrikeFalcon',
            name='cs-falcon-contain-host',
            args_mapping={'ids': 'agent_id'},
            pre_command_check=check_conditions_cs_falcon_contain_host,
        ),
        # Command(
        #     brand='FireEyeHX v2',
        #     name='fireeye-hx-host-containment',
        #     args_mapping={'agentId': 'agent_id', 'hostName': 'agent_hostname'},
        #     pre_command_check=check_conditions_fireeye_hx_host_containment,
        # ),
        Command(
            brand='VMware Carbon Black EDR v2',
            name='cb-edr-quarantine-device',
            args_mapping={'sensor_id': 'agent_id'},
            pre_command_check=check_conditions_cb_edr_quarantine_device,
        ),
        #     Command(
        #         brand='Microsoft Defender Advanced Threat Protection',
        #         name='microsoft-atp-isolate-machine',
        #         args_mapping={},
        #         pre_command_check=check_conditions_microsoft_atp_isolate_machine
        #     ),
    ]
    return commands


""" MODULE MANAGER CLASS """


class ModuleManager:
    def __init__(self, brands_to_run: list[str]) -> None:
        self.modules_context = demisto.getModules()
        self._brands_to_run = brands_to_run  # todo to check the logic
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


def check_conditions_cb_edr_quarantine_device(verbose, outputs, human_readable_outputs, args, endpoint_data) -> bool:
    return True


def check_conditions_cybereason_isolate_machine(verbose, outputs, human_readable_outputs, args, endpoint_data):
    pass


def check_conditions_fireeye_hx_host_containment(verbose, outputs, human_readable_outputs, args, endpoint_data) -> bool:
    pass


def check_conditions_cs_falcon_contain_host(verbose, outputs, human_readable_outputs, args, endpoint_data) -> bool:
    if not endpoint_data.get('Status', {}).get('Source', '') == 'CrowdstrikeFalcon':
        create_message_to_context_and_hr(endpoint_data=args,
                                         result='Fail',
                                         brand='CrowdstrikeFalcon',
                                         message=f'cs_falcon_contain_host command can not be executed.',
                                         outputs=outputs,
                                         human_readable_outputs=human_readable_outputs,
                                         verbose=verbose)
    return True


def check_conditions_microsoft_atp_isolate_machine(verbose, outputs, human_readable_outputs, args, endpoint_data) -> bool:
    pass


""" HELPER FUNCTIONS """


def check_validation_for_running_command(module_manager, verbose, command, outputs, human_readable_outputs, args):
    if not module_manager.is_brand_available(command):  # checks if brand is enable
        demisto.debug(f'Brand {command.brand} is unavailable for command.name')
        create_message_to_context_and_hr(endpoint_data=args,
                                         result='Fail',
                                         brand=command.brand,
                                         message=f'{command.brand} integration is available.',
                                         outputs=outputs,
                                         human_readable_outputs=human_readable_outputs,
                                         verbose=verbose)
        return False

    missing_args = check_missing_args(command.args_mapping, args)  # checks that there are not missing args
    if missing_args:
        demisto.debug(f'Missing the next args {missing_args} for command.name')
        create_message_to_context_and_hr(endpoint_data=args,
                                         result='Fail',
                                         brand=command.brand,
                                         message=f'Missing the next args: {missing_args} for {command.name}.',
                                         outputs=outputs,
                                         human_readable_outputs=human_readable_outputs,
                                         verbose=verbose)
        return False
    return True


def is_endpoint_isolatable(args: dict, endpoint_data: dict, force: bool, server_os_list: list) -> tuple[bool, str]:
    server = endpoint_data.get('OSVersion', {}).get('Value')  # todo to check if there a field that says - it's a server
    is_isolated = endpoint_data.get('IsIsolated', {}).get('Value', 'No')
    server_status = endpoint_data.get('Status', {}).get('Value', 'Online')

    hostname = args.get('agent_hostname', args.get('agent_ip'))

    demisto.debug(f'{server_status=}, {is_isolated=}, {server=}, {force=}')

    if server and (server in SERVERS_RELEASES or server in server_os_list) and not force:
        message = f'Error isolating {hostname}: Server detected, but force parameter is False.'
        demisto.debug(message)
        return False, message

    if is_isolated == 'Yes':
        message = f'Error isolating {hostname}: Endpoint is already isolated.'
        demisto.debug(message)
        return False, message

    if server_status == 'Offline':
        message = f'Error isolating {hostname}: Endpoint is offline.'
        demisto.debug(message)
        return False, message

    return True, ''


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
    agent_hostname = zipped_args.get('agent_hostname')
    agent_id = zipped_args.get('agent_id')
    agent_ip = zipped_args.get('agent_ip')
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
    # get_endpoint_data_results = execute_command(command="get-endpoint-data", args={'agent_hostname': 'DC1ENV11ADC01,'
    #                                                                                                  'DC1ENV11ADC02,'
    #                                                                                                  'falcon-crowdstrike-sensor-centos7'})
    # demisto.debug(f'these are the results from get_endpoint_data_results execute_command {get_endpoint_data_results}')
    # get_endpoint_data_results = demisto.executeCommand(command="get-endpoint-data",
    # args={'agent_hostname': 'WIN-SOSSKVTTQAB,justesting'})
    # demisto.debug(f'these are the results from get_endpoint_data_results demisto.executeCommand {get_endpoint_data_results}')
    # crowstrike = execute_command(command="cs-falcon-search-device",
    #                              args={'ids': '8ed44198a6f64f9fabd0479c3098f303'})
    # demisto.debug(f'these are the results from crowstrike execute_command {crowstrike}')

    try:
        # args = demisto.args()
        args = {'agent_hostname': 'DC1ENV11ADC01,DC1ENV11ADC02,falcon-crowdstrike-sensor-centos7,Arts-MacBook-Pro'}
        agent_ids = argToList(args.get("agent_id", []))
        agent_ips = argToList(args.get("agent_ip", []))
        agent_hostnames = argToList(args.get("agent_hostname", []))
        force = argToBoolean(args.get("force", False))
        # verbose = argToBoolean(args.get("verbose", False))
        verbose = True
        brands_to_run = argToList(args.get('brands', []))
        server_os_list = argToList(args.get('server_os', []))
        module_manager = ModuleManager(brands_to_run)

        zipped_args = map_zipped_args(agent_ids, agent_ips, agent_hostnames)

        get_endpoint_data_results = execute_command(command="get-endpoint-data", args=args)
        if not isinstance(get_endpoint_data_results, list):
            get_endpoint_data_results = [get_endpoint_data_results]

        demisto.debug(f'these are the results from get_endpoint_data_results execute_command {get_endpoint_data_results}')

        outputs = []
        human_readable_outputs = []
        args_from_endpoint_data = []
        commands = initialize_commands()
        for endpoint_data in get_endpoint_data_results:
            agent_hostname = endpoint_data.get('Hostname', {}).get('Value', '')
            agent_id = endpoint_data.get('ID', {}).get('Value', '')
            agent_ip = endpoint_data.get('IPAddress', {}).get('Value', '')
            agent_brand = endpoint_data.get('ID', {}).get('Source', '')
            args = {'agent_id': agent_id, 'agent_hostname': agent_hostname, 'agent_ip': agent_ip, 'agent_brand': agent_brand}
            args_from_endpoint_data.append(args)

            endpoint_isolatable, message = is_endpoint_isolatable(args, endpoint_data, force, server_os_list)
            if not endpoint_isolatable:
                create_message_to_context_and_hr(endpoint_data=args,
                                                 result='Fail',
                                                 brand='IsolateEndpoint',
                                                 message=message,
                                                 outputs=outputs,
                                                 human_readable_outputs=human_readable_outputs,
                                                 verbose=verbose)
                continue

            for command in commands:
                demisto.debug(f'executing command {command.name} with {args=}')
                if command.brand != agent_brand:
                    demisto.debug(f'Skipping command {command.name} as its brand does not match the endpoint brand.')
                    continue
                if command.pre_command_check and not command.pre_command_check(verbose=verbose,
                                                                               outputs=outputs,
                                                                               human_readable_outputs=human_readable_outputs,
                                                                               args=args,
                                                                               endpoint_data=endpoint_data):
                    continue
                if not check_validation_for_running_command(module_manager, verbose, command, outputs, human_readable_outputs,
                                                            args):
                    continue
                mapped_args = map_args(command.args_mapping, args)
                demisto.debug(f'Mapped args {mapped_args} for command {command.name} with {args=}')
                try:
                    raw_response = execute_command(command.name, mapped_args)
                    demisto.debug(f'Got raw response for execute_command {command.name} with {args=}: {raw_response=}')
                except Exception as e:
                    create_message_to_context_and_hr(endpoint_data=args,
                                                     result='Fail',
                                                     brand=command.brand,
                                                     message=f'Failed to execute command {command.name}. Error: {str(e)}',
                                                     outputs=outputs,
                                                     human_readable_outputs=human_readable_outputs,
                                                     verbose=verbose)
                    continue
                if raw_response and raw_response.get('errors', []):
                    create_message_to_context_and_hr(endpoint_data=args,
                                                     result='Fail',
                                                     brand=command.brand,
                                                     message=f'Failed to execute command {command.name}.',
                                                     outputs=outputs,
                                                     human_readable_outputs=human_readable_outputs,
                                                     verbose=verbose)
                else:
                    create_message_to_context_and_hr(endpoint_data=args,
                                                     result='Success',
                                                     brand=command.brand,
                                                     message=f'Command {command.name} was executed successfully.',
                                                     outputs=outputs,
                                                     human_readable_outputs=human_readable_outputs,
                                                     verbose=verbose)

        # for agent_id, agent_ip, agent_hostname in zipped_args:
        #     args = {'agent_id': agent_id,
        #             'agent_hostname': agent_hostname,
        #             'agent_ip': agent_ip}
        #     if not do_args_exist_in_valid(agent_id, args_from_endpoint_data):
        #         create_message_to_context_and_hr(endpoint_data=args,
        #                                          result='Fail',
        #                                          brand='GetEndpointData',
        #                                          message=f'Failed to execute GetEndpointData script for {args}.',
        #                                          outputs=outputs,
        #                                          human_readable_outputs=human_readable_outputs,
        #                                          verbose=verbose)

        readable_output = tableToMarkdown(name='IsolateEndpoint Results', t=human_readable_outputs, removeNull=True)
        results = CommandResults(
            outputs_prefix='IsolateEndpoint',
            outputs=outputs,
            readable_output=readable_output,
        )
        demisto.debug(f'these are the args from get_endpoint_data {args_from_endpoint_data}')

    except Exception as e:
        demisto.debug(f"Failed to execute isolate-endpoint. Error: {str(e)}")
        results = CommandResults(
            outputs_prefix='IsolateEndpoint',
            outputs=[],
            readable_output='The Isolate Action did not succeed.'
                            ' Please validate your input or check if the machine is already in an Isolate state.'
                            ' The Device ID/s that were not Isolated',

        )

    return_results(results)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
