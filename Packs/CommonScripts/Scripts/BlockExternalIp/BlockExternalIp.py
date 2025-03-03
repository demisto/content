import datetime
from time import sleep
from typing import Any, Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


class Module:
    def __init__(self,
                 ip_list: list,
                 rule_name: str,
                 log_forwarding_name: str,
                 address_group: str,
                 tag: str,
                 custom_block_rule: bool,
                 auto_commit: bool,
                 verbose: bool,
                 brand: str):
        """
        Initialize a Module object, that will store the needed arguments to run each brand/module.
        Args:
            ip_list (list): The list of IPs to block,
            rule_name (str): The rule name,
            log_forwarding_name(str): The log forwarding name,
            address_group (str): The address group,
            tag(str): The designated tag name for the IPs,
            custom_block_rule (bool): Whether to creates a custom block policy rule,
            auto_commit (bool): Whether to automatically commit the changes or not,
            verbose (bool): Whether to retrieve human readable entry for every command or only the final result.,
            brand (str): The integration name.
        """
        self.ip_list = ip_list
        self.rule_name = rule_name
        self.log_forwarding_name = log_forwarding_name
        self.address_group = address_group
        self.tag = tag
        self.custom_block_rule = custom_block_rule
        self.auto_commit = auto_commit
        self.verbose = verbose
        self.brand = brand

""" STANDALONE FUNCTION """


def create_final_human_readable(failure_message: str, used_integration: str, rule_name: str = '') -> str:
    """
    Creates the human readable of the command.
    Args:
        failure_message (str): a failure message if relevant.
        used_integration (str): The integration that was used.
        rule_name (str): The name of the created rule
    Returns:
        A string representing the human readable of the entire command.
    """
    demisto.debug(f"BEI: {failure_message=}")
    headers = ['Status', 'Result', 'Created rule name', 'Used integration', 'Message']
    if failure_message:
        d = {
            "Status": "Done",
            "Result": "Failed",
            "Used integration": used_integration,
            'Message': failure_message
        }
        demisto.debug(f"BEI: in failed {d=}")
        return tableToMarkdown(
            name='Failed to block the IP',
            t=d,
            headers=headers,
            removeNull=True
        )
    else:
        d = {
            "Status": "Done",
            "Result": "Success",
            "Used integration": used_integration,
            "Created rule name": rule_name
        }
        demisto.debug(f"BEI: in success {d=}")
        return tableToMarkdown(
            name='The IP was blocked successfully',
            t=d,
            headers=headers,
            removeNull=True
        )


def create_final_context(failure_message: str, used_integration: str, ip_list_arr: list, rule_name: str = '') -> list[dict]:
    """
    Creates the context data of the command.
    Args:
        failure_message (str): a failure message if relevant.
        used_integration (str): The integration that was used.
        rule_name (str): The name of the created rule.
        ip_list_arr (list): A list of ips
    Returns:
        A dict, representing the context of the command.
    """
    context = []
    for ip in ip_list_arr:
        if failure_message:
            context.append({
                "IP": ip,
                "results": {
                    "Message": failure_message,
                    "result": "Failed",
                    "Brand": used_integration,
                }
            })
        else:
            context.append({
                "IP": ip,
                "results": {
                    "Message": f"created_rule_name:{rule_name}" if rule_name else '',
                    "Result": "OK",
                    "Brand": used_integration,
                }
            })
    return context

def prepare_context_and_hr_multiple_executions(responses: list[list[dict]], verbose, rule_name: str, address_group: str, ip_list_arr: list[str]) -> list[CommandResults]:
    results = []
    failed_messages = []
    used_integration = responses[0][0].get('Metadata', {}).get('brand')  # all executions are for the same brand.
    if verbose:
        for res in responses:
            for entry in res:
                command_hr = entry.get('HumanReadable')
                message = entry.get('Contents')
                demisto.debug(f"In prepare_context_and_hr_multiple_executions {command_hr=} {message=}")
                if command_hr:
                    demisto.debug(f"BEI: The command has {verbose=}, adding {command_hr=}")
                    results.append(CommandResults(readable_output=command_hr))
                if (message and 'Failed' in message) or not command_hr:
                    demisto.debug(f"A failure was found {message=}")
                    failed_messages.append(message)
    combined_failure_message = ', '.join(failed_messages)
    final_hr = create_final_human_readable(combined_failure_message, used_integration, rule_name)
    final_context = create_final_context(combined_failure_message, used_integration, ip_list_arr, rule_name)
    results.append(CommandResults(
        readable_output=final_hr,
        outputs_prefix="BlockExternalIPResults",
        outputs=final_context,
        raw_response=final_context
    ))
    return results


def prepare_context_and_hr(response: list[dict], verbose, ip_list: list[str]) -> list[CommandResults]:
    results = []
    entry = {}
    failed_message = ''
    for entry in response:  # There is only 1 entry
        command_hr = entry.get('HumanReadable')
        if verbose and command_hr:
            demisto.debug(f"BEI: The command has {verbose=}, adding {command_hr=}")
            results.append(CommandResults(readable_output=command_hr))
        contents = entry.get('Contents')
        failed_message = contents if (contents and 'Failed' in contents) or not command_hr else ''
    used_integration = entry.get('Metadata', {}).get('brand')
    hr = create_final_human_readable(failed_message, used_integration)
    context = create_final_context(failed_message, used_integration, ip_list)
    demisto.debug(f"BEI: {hr=} {context=}")
    results.append(CommandResults(
        readable_output=hr,
        outputs_prefix="BlockExternalIPResults",
        outputs=context,
        raw_response=context
    ))
    return results


def check_tag_exist(res_list_tags: dict, tag_name: str) -> bool:
    tag_list = res_list_tags.get('Contents', {}).get('response', {}).get('result', {}).get('tag', {}).get('entry', [])
    demisto.debug(f"The {tag_list=}")
    for tag_dict in tag_list:
        cur_tag_name = tag_dict.get('name', '')
        if tag_name == cur_tag_name:
            demisto.debug(f"The tag exists {tag_name=} == {cur_tag_name=}")
            return True
    return False

# TODO consider combining
# TODO check outbound
def check_rule_exist(res_list_rules: dict, rule_name:str) -> bool:
    rules_list = res_list_rules.get('Contents', [])
    demisto.debug(f"The {rules_list=}")
    for rule in rules_list:
        cur_rule_name = rule.get('@name', '')
        if cur_rule_name == rule_name:
            demisto.debug(f"The rule exists {cur_rule_name=} == {rule_name=}")
            return True
    demisto.debug(f"The rule {rule_name} doesn't exist")
    return False


""" COMMAND FUNCTION """


def prisma_sase_candidate_config_push(auto_commit: bool) -> tuple[list[dict], CommandResults]:
    res_auto_commit, auto_commit_message = None, None
    if auto_commit:
        res_auto_commit = demisto.executeCommand("prisma-sase-candidate-config-push",
                                                 {
                                                     "folders": "Remote Networks, Mobile Users, Service Connections"})
        demisto.debug(f"The response of prisma-sase-candidate-config-push is {res_auto_commit}")
    else:
        auto_commit_message = CommandResults(readable_output=f"Not commiting the changes in Palo Alto Networks - Prisma SASE, "
                                       f"since {auto_commit=}. Please do so manually for the changes to take affect.")
    return res_auto_commit, auto_commit_message


def prisma_sase_block_ip(ip_list_arr: list, address_group: str, verbose: bool, rule_name: str, auto_commit: bool) -> list[CommandResults]:
    responses = []
    response_address_group_list = demisto.executeCommand("prisma-sase-address-group-list", {"name": address_group})
    response_address_group_list_contents = response_address_group_list[0].get('Contents', {})
    demisto.debug(f"The contents response of prisma-sase-address-group-list {response_address_group_list_contents}")
    if isinstance(response_address_group_list_contents, str) and 'Failed' in response_address_group_list_contents:
        demisto.debug(f"The {address_group=} doesn't exist, creating it.")
        res_address_group_create = demisto.executeCommand("prisma-sase-address-group-create",
                                                          {"name": address_group,
                                                           "type": "static",
                                                           "static_addresses": ip_list_arr})
        demisto.debug(f"The response from prisma-sase-address-group-create is {res_address_group_create}")
        responses.append(res_address_group_create)
        res_rule_create = demisto.executeCommand("prisma-sase-security-rule-create",
                                                 {"action": "deny", "name": rule_name})
        demisto.debug(f"The response from prisma-sase-security-rule-create is {res_rule_create}")
        if not 'Object Already Exists' in res_rule_create[0].get('Contents', ''):
            demisto.debug(f"A new rule '{rule_name}' was created")
            responses.append(res_rule_create)  # If the object already exists, no need to add a failure message.
        else:
            # no rule was created in this scenario. Avoid adding it to the human readable, and no need to add a failure message.
            rule_name = ''
        res_auto_commit, auto_commit_cr = prisma_sase_candidate_config_push(auto_commit)
        if res_auto_commit:
            responses.append(res_auto_commit)
    else:
        # add the response of the execution prisma-sase-address-group-list only in case the address_group exist,
        # not to add a "failed" execution to the responses stack.
        responses.append(response_address_group_list)
        addresses = response_address_group_list_contents.get('static', [])
        demisto.debug(f"The found addresses are {addresses}.")
        non_existing_ips = [ip for ip in ip_list_arr if ip not in addresses]

        if not non_existing_ips:
            demisto.debug(f"All the ips in the command argument {ip_list_arr} exist in the {address_group=}.")
            return prepare_context_and_hr(response_address_group_list, verbose, ip_list_arr)
        else:
            demisto.debug(f"The {address_group=} exists, but the {non_existing_ips=} aren't in the {addresses=} of {address_group=}")
            group_id = response_address_group_list[0].get('Contents', {}).get('id')
            res_address_group_update = demisto.executeCommand("prisma-sase-address-group-update", {
                "group_id": group_id,
                "static_addresses": non_existing_ips
            })
            demisto.debug(f"The result of prisma-sase-address-group-update with {group_id=} is {res_address_group_update}")
            responses.append(res_address_group_update)
            res_auto_commit, auto_commit_cr = prisma_sase_candidate_config_push(auto_commit)
            if res_auto_commit:
                responses.append(res_auto_commit)
            rule_name = ''  # no rule was created in this scenario. Avoid adding it to the human readable.

    command_results_list = prepare_context_and_hr_multiple_executions(responses, verbose, rule_name, address_group, ip_list_arr)
    if auto_commit_cr:
        command_results_list.append(auto_commit_cr)
    return command_results_list


def pan_os_block_ip(module: Module) -> list[CommandResults | PollResult]:
    responses = []
    res_list_tags = demisto.executeCommand('pan-os-list-tag', {})
    demisto.debug(f"The response of pan-os-list-tag is {res_list_tags}")
    responses.append(res_list_tags)
    if check_tag_exist(res_list_tags[0], module.tag):
        res_register_ip_tag = demisto.executeCommand("pan-os-register-ip-tag", {'tag': module.tag, 'IPs': module.ip_list})
        demisto.debug(f"The response of pan-os-register-ip-tag is {res_register_ip_tag}")
        responses.append(res_register_ip_tag)
    else:
        demisto.debug(f"The tag {module.tag} doesn't exit. Creating it.")
        args = {
            'name': module.address_group,
            'tags': module.tag,
            'match': module.ip_list
        }
        res_create_address_group = demisto.executeCommand("pan-os-create-address-group", args)
        demisto.debug(f"The response from pan-os-create-address-group is {res_create_address_group}")
        responses.append(res_create_address_group)
    res_list_rules = demisto.executeCommand("pan-os-list-rules", {'pre_post': 'pre-rulebase'})
    demisto.debug(f"The response from pan-os-list-rules is {res_list_rules}")
    responses.append(res_list_rules)
    # TODO add the inbound
    if check_rule_exist(res_list_rules[0], module.rule_name):
        args = {
            'rulename': module.rule_name,
            'element_value': module.address_group,
            'element_to_change': 'destination',
            'pre_post': 'pre-rulebase'
        }
        res_edit_rule = demisto.executeCommand("pan-os-edit-rule", args)
        demisto.debug(f"The result of pan-os-edit-rule is {res_edit_rule}")
        responses.append(res_edit_rule)
    else:
        args_create_rule = {'rulename': module.rule_name, 'action': 'deny', 'pre_post': 'pre-rulebase'}
        res_create_rule = demisto.executeCommand("pan-os-create-rule", args_create_rule)
        demisto.debug(f"The result of pan-os-create-rule is {res_create_rule}")
        responses.append(res_create_rule)
        args = {
            'rulename': module.rule_name,
            'where': 'top',
            'pre_post': 'pre-rulebase'
        }
        res_move_rule = demisto.executeCommand("pan-os-move-rule", args)
        demisto.debug(f"The result of pan-os-move-rule is {res_move_rule}")
        responses.append(res_move_rule)
        return [pan_os_commit({'polling': True, 'timeout': 600, 'interval_in_seconds': 60, 'ip_list': module.ip_list, 'brands': module.brand})]

    return [CommandResults()]  # TODO


@polling_function(
    name='block-external-ip',
    interval=60,
    timeout=600,
    requires_polling_arg=True,
)
def pan_os_commit(args: dict) -> PollResult:
    # commit the changes
    demisto.debug(f"The arguments to the pan_os_commit are {args=}")
    ip_list = args.pop('ip_list')
    brand = args.pop('brands')
    demisto.debug(f"The ip_list in pan_os_commit {ip_list} and {brand=}")
    if job_id := args.get('commit_job_id'):
        res_commit_status = demisto.executeCommand("pan-os-commit-status", {'job_id': job_id})
        demisto.debug(f"The response of pan-os-commit-status is {res_commit_status}")
        job_result = res_commit_status[0].get('Contents', {}).get('response', {}).get('result', {}).get('job', {}).get('result')
        demisto.debug(f"The result is {job_result=}")
        commit_output = {
            'JobID': job_id,
            'Status': 'Success' if job_result == 'OK' else 'Failure',
        }
        continue_to_poll = res_commit_status[0].get('Contents', {}).get('response', {}).get('result', {}).get('job', {}).get('status') != 'FIN'
        demisto.debug(f"after pan-os-commit-status {continue_to_poll=} {job_id=}")
        if not continue_to_poll and job_result == 'OK':
            call_pan_os_cmd({})
        return PollResult(
            response=CommandResults(
                outputs=commit_output,
                outputs_key_field='JobID',
                readable_output=tableToMarkdown('Commit Status:', commit_output, removeNull=True)
            ),
            args_for_next_run={
                'commit_job_id': job_id,
                'interval_in_seconds': arg_to_number(args.get('interval_in_seconds')),
                'timeout': arg_to_number(args.get('timeout')),
                'ip_list': ip_list,
                'brands': brand,
            },
            continue_to_poll=continue_to_poll,  # continue polling if job isn't done
        )
    else:
        res_commit = demisto.executeCommand("pan-os-commit", args)
        demisto.debug(f"The response of pan-os-commit is {res_commit}")
        polling_args = res_commit[0].get('Metadata', {}).get('pollingArgs', {})
        job_id = polling_args.get('commit_job_id')
        if job_id:
            context_output = {
                'JobID': job_id,
                'Status': 'Pending'
            }
            continue_to_poll = True
            commit_output = CommandResults(
                outputs=context_output,
                readable_output=tableToMarkdown('Commit Status:', context_output, removeNull=True)
            )
        else:  # nothing to commit in pan-os, hence even if polling=true, no reason to poll anymore.
            commit_output = res_commit[0].get('Contents') or 'There are no changes to commit.'  # type: ignore[assignment]
            continue_to_poll = False
        demisto.debug(f"Initiated a commit execution {continue_to_poll=} {job_id=}")
        args_for_next_run = {
            'commit_job_id': job_id,
            'interval_in_seconds': arg_to_number(args.get('interval_in_seconds')),
            'timeout': arg_to_number(args.get('timeout')),
            'ip_list': ip_list,
            'brands': brand,
        }
        return PollResult(
            response=commit_output,
            continue_to_poll=continue_to_poll,
            args_for_next_run=args_for_next_run,
            partial_result=CommandResults(
                readable_output=f'Waiting for commit job ID {job_id} to finish...'
            )
        )


@polling_function(
    name='block-external-ip',
    interval=60,
    timeout=600,
    requires_polling_arg=True,
)
def call_pan_os_cmd(args: dict):
    if not args:
        res_pan_os = demisto.executeCommand("pan-os", {'cmd': '<show><system><info></info></system></show>'})
        demisto.debug(f"The response from pan-os is {res_pan_os}")
        # TODO if panorama
        res_push_to_device = demisto.executeCommand("pan-os-push-to-device-group", {'polling': True, 'timeout': 600, 'interval_in_seconds': 60})
        demisto.debug(f"The response of pan-os-push-to-device-group {res_push_to_device}")
        polling_args = res_push_to_device[0].get('Metadata', {}).get('pollingArgs', {})
        job_id = polling_args.get('push_job_id')
        device_group = polling_args.get('device-group')
        demisto.debug(f"The polling args are {job_id=} {device_group=}")
        if job_id:
            context_output = {
                'DeviceGroup': device_group,
                'JobID': job_id,
                'Status': 'Pending'
            }
            continue_to_poll = True
            push_output = CommandResults(
                outputs_key_field='JobID',
                outputs=context_output,
                readable_output=tableToMarkdown('Push to Device Group:', context_output, removeNull=True)
            )
        else:
            push_output = CommandResults(
                readable_output=res_push_to_device[0].get('Contents') or 'There are no changes to push.'
            )
            continue_to_poll = False

        args_for_next_run = {
            'push_job_id': job_id,
            'polling': True,
            'interval_in_seconds': 60,
            'device_group': device_group
        }
        demisto.debug(f"The args for the next run of pan-os-push-to-device-group {args_for_next_run}")
        return PollResult(
            response=push_output,
            continue_to_poll=continue_to_poll,
            args_for_next_run=args_for_next_run,
            partial_result=CommandResults(
                readable_output=f'Waiting for Job-ID {job_id} to finish push changes to device-group {device_group}...'
            )
        )
    else:
        demisto.debug(f"The polling {args=}")
        push_job_id = args.get('push_job_id')
        device_group = args.get('device_group')
        res_push_to_device = demisto.executeCommand("pan-os-push-to-device-group", {'push_job_id': push_job_id})
        demisto.debug(f"The response from pan-os-push-to-device-group with {push_job_id=} is {res_push_to_device}")
        args_for_next_run = {
            'push_job_id': push_job_id,
            'polling': True,
            'interval_in_seconds': 60,
            'device_group': device_group
        }

        return PollResult(
            response={},
            continue_to_poll=False,
            args_for_next_run=args_for_next_run,
            partial_result=CommandResults(
                readable_output=f'Waiting for Job-ID {push_job_id} to finish push changes to device-group {device_group}...'
            )
        )


def run_execute_command(command_name: str, args: dict[str, Any], verbose : bool, ip_list: list) -> list[CommandResults]:
    """
    Executes a command and processes its results.
    This function runs a specified command with given arguments, handles any errors,
    and prepares the command results for further processing.
    Args:
        command_name (str): The name of the command to execute.
        args (dict[str, Any]): A dictionary of arguments to pass to the command.
        verbose (boll): Whether to retrieve human readable entry for every command or only the final result.
        ip_list (list): the list of ips.
    Returns:
        A list of the relevant command results.
    """
    demisto.debug(f"BEI: Executing command: {command_name} {args=}")
    res = demisto.executeCommand(command_name, args)
    demisto.debug(f"BEI: The response {res}")
    return prepare_context_and_hr(res, verbose, ip_list)


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        demisto.debug(f"The script block-external-ip was called with the arguments {args=}")
        ip_list_arg = args.get("ip_list", [])
        ip_list_arr = argToList(ip_list_arg)
        rule_name = args.get("rule_name", "XSIAM - Block IP")
        log_forwarding_name = args.get("log_forwarding_name", "")
        address_group = args.get("address_group", "Blocked IPs - XSIAM")
        tag = args.get("tag", "")
        custom_block_rule = argToBoolean(args.get("custom_block_rule", False))
        auto_commit = argToBoolean(args.get("auto_commit", True))
        verbose = argToBoolean(args.get("verbose", False))
        brands_to_run = argToList(args.get("brands", "Palo Alto Networks - Prisma SASE,Panorama,CheckPointFirewall_v2,FortiGate,"
                                                     "F5Silverline,Cisco ASA,Zscaler"))
        modules = demisto.getModules()
        enabled_brands = {
            module.get("brand")
            for module in modules.values()
            if module.get("state") == "active"
        }
        demisto.debug(f"BEI: the enabled modules are: {enabled_brands=}")
        demisto.debug(f"BEI: {brands_to_run=}")

        results = []
        for brand in brands_to_run:
            demisto.debug(f"BEI: the current brand is {brand}")
            if brand in enabled_brands:
                if brand == "Zscaler":
                    args = {
                        'ip': ip_list_arg
                    }
                    command_name = 'zscaler-blacklist-ip'
                    results.append(run_execute_command(command_name, args, verbose, ip_list_arr))

                elif brand == "Cisco ASA":
                    command_name = 'cisco-asa-create-rule'
                    for ip in ip_list_arr:
                        args = {
                            "destination": ip,
                            "interface_type": "Global",
                            "source": "0.0.0.0",
                            "permit": False
                        }
                        results.append(run_execute_command(command_name, args, verbose, [ip]))

                elif brand == "F5Silverline":
                    command_name = "f5-silverline-ip-object-add"
                    for ip in ip_list_arr:
                        args = {
                            "list_type": "denylist",
                            "cidr_range": ip,
                            "tags": tag
                        }
                        results.append(run_execute_command(command_name, args, verbose, [ip]))

                elif brand == "FortiGate":
                    command_name = "fortigate-ban-ip"
                    args = {
                        "ip_address": ip_list_arg
                    }
                    results.append(run_execute_command(command_name, args, verbose, ip_list_arr))

                elif brand == "Palo Alto Networks - Prisma SASE":
                    results.append(prisma_sase_block_ip(ip_list_arr, address_group, verbose, rule_name, auto_commit))

                elif brand == "Panorama":
                    commit_job_id = args.get('commit_job_id')
                    push_job_id = args.get('push_job_id')
                    if commit_job_id:
                        demisto.debug(f"In Panorama recurring polling {commit_job_id=}")
                        return_results(pan_os_commit(args))
                    else:
                        demisto.debug("No polling running for Panorama")
                        module = Module(ip_list_arr, rule_name, log_forwarding_name, address_group, tag, custom_block_rule, auto_commit, verbose, brand)
                        return_results(pan_os_block_ip(module))

                else:
                    return_error(f"The brand {brand} isn't a part of the supported integration for 'block-external-ip'. "
                                 f"The supported integrations are: Palo Alto Networks - Prisma SASE, Panorama, "
                                 f"CheckPointFirewall_v2, FortiGate, F5Silverline, Cisco ASA, Zscaler.")
            else:
                demisto.info(f"The brand {brand} isn't enabled.")
        return_results(results)

    except Exception as ex:
        return_error(f"Failed to execute block-external-ip. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
