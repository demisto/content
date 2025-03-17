import datetime
from time import sleep
from typing import Any, Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


""" STANDALONE FUNCTION """

# TODO think about adding the command name to the human readable.
def create_final_human_readable(failure_message: str, used_integration: str, ip_list: list, rule_name: str = '') -> str:
    """
    Creates the human readable of the command.
    Args:
        failure_message (str): a failure message if relevant.
        used_integration (str): The integration that was used.
        rule_name (str): The name of the created rule
        ip_list (list): The list of ip/s to block
    Returns:
        A string representing the human readable of the entire command.
    """
    demisto.debug(f"BEI: {failure_message=}")
    headers = ['IP', 'Status', 'Result', 'Created rule name', 'Used integration', 'Message']
    if failure_message:
        d = {
            "Status": "Done",
            "Result": "Failed",
            "Used integration": used_integration,
            'Message': failure_message,
            'IP': ip_list
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
            "Created rule name": rule_name,
            "IP": ip_list
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
    demisto.debug(f"BEI: creating context with {failure_message=} {used_integration=} {ip_list_arr=}")
    for ip in ip_list_arr:
        if failure_message:
            demisto.debug(f"BEI: in failure case, creating context {failure_message=}")
            context.append({
                "IP": ip,
                "results": {
                    "Message": failure_message,
                    "result": "Failed",
                    "Brand": used_integration,
                }
            })
        else:
            demisto.debug("BEI: in a success case, creating context")
            context.append({
                "IP": ip,
                "results": {
                    "Message": f"created_rule_name:{rule_name}" if rule_name else '',
                    "Result": "OK",
                    "Brand": used_integration,
                }
            })
    return context

def prepare_context_and_hr_multiple_executions(responses: list[list[dict]], verbose, rule_name: str, ip_list_arr: list[str]) -> list[CommandResults]:
    results = []
    failed_messages = []
    used_integration = responses[0][0].get('Metadata', {}).get('brand')  # all executions are for the same brand.

    for res in responses:
        for entry in res:
            command_hr = entry.get('HumanReadable')
            message = entry.get('Contents')
            demisto.debug(f"In prepare_context_and_hr_multiple_executions {command_hr=} {message=}")
            if command_hr:
                demisto.debug(f"BEI: The command has {verbose=}, adding {command_hr=}")
                results.append(CommandResults(readable_output=command_hr))
            if (message and 'Failed' in message) or is_error(entry):
                demisto.debug(f"A failure was found {message=}")
                failed_messages.append(message)
            elif message and isinstance(message, str):
                results.append(CommandResults(readable_output=message))
    combined_failure_message = ', '.join(failed_messages)
    final_hr = create_final_human_readable(combined_failure_message, used_integration, ip_list_arr, rule_name)
    final_context = create_final_context(combined_failure_message, used_integration, ip_list_arr, rule_name)
    final_cr = CommandResults(
            readable_output=final_hr,
            outputs_prefix="BlockExternalIPResults",
            outputs=final_context,
            raw_response=final_context
        )
    if verbose:
        results.append(final_cr)
    else:
        results = [final_cr]
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
    hr = create_final_human_readable(failed_message, used_integration, ip_list)
    context = create_final_context(failed_message, used_integration, ip_list)
    demisto.debug(f"BEI: {hr=} {context=}")
    results.append(CommandResults(
        readable_output=hr,
        outputs_prefix="BlockExternalIPResults",
        outputs=context,
        raw_response=context
    ))
    return results


def get_relevant_context(original_context: dict[str, Any], key: str) -> dict | list:
    if not original_context:
        return {}
    if relevant_context := original_context.get(key, {}):
        demisto.debug(f"The {key=} was found in the first search.")
        return relevant_context
    else:
        for k in original_context:
            if k.startswith(key):
                demisto.debug(f"The {key=} was found in the context as {k}")
                return original_context.get(k)
        return {}


def check_value_exist_in_context(value: str, context: list[dict], key: str) -> bool:
    for item in context:
        match = item.get(key)
        if match and match == value:
            return True
    return False


""" COMMAND FUNCTION """


def prisma_sase_candidate_config_push(auto_commit: bool, responses: list) -> tuple[list[dict], CommandResults]:
    res_auto_commit, auto_commit_message = None, None
    if auto_commit:
        res_auto_commit = run_execute_command("prisma-sase-candidate-config-push",
                                                 {
                                                     "folders": "Remote Networks, Mobile Users, Service Connections"})
        responses.append(res_auto_commit)
    else:
        auto_commit_message = CommandResults(readable_output=f"Not commiting the changes in Palo Alto Networks - Prisma SASE, "
                                       f"since {auto_commit=}. Please do so manually for the changes to take affect.")
    return res_auto_commit, auto_commit_message


def prisma_sase_block_ip(brand_args: dict) -> list[CommandResults]:
    demisto.debug(f"The arguments to prisma_sase_block_ip is {brand_args=}")
    responses = []
    ip = brand_args['ip']
    address_group = brand_args.get('address_group')
    rule_name = brand_args.get('rule_name')
    auto_commit_message = None

    res_address_object_list = run_execute_command("prisma-sase-address-object-list", {'name': ip})
    responses.append(res_address_object_list)
    contents_address_object_list = res_address_object_list[0].get('Contents')

    if isinstance(contents_address_object_list, str) and "does not exist" in contents_address_object_list:
        res_add_obj_create = run_execute_command("prisma-sase-address-object-create", {'name': ip, 'type': 'ip_netmask', 'address_value': ip})
        responses.append(res_add_obj_create)
        if is_error(res_add_obj_create):
            return prepare_context_and_hr_multiple_executions(responses, brand_args.get('verbose'), '', [ip])
        res_auto_commit, auto_commit_message = prisma_sase_candidate_config_push(brand_args.get('auto_commit'), responses)

    res_add_group_list = run_execute_command("prisma-sase-address-group-list", {'name': address_group})
    responses.append(res_add_group_list)
    contents_add_group_list = res_add_group_list[0].get('Contents', '')
    if isinstance(contents_add_group_list, str) and "does not exist" in contents_add_group_list:
        demisto.debug(f"The {address_group=} doesn't exist, creating it.")
        res_address_group_create = run_execute_command("prisma-sase-address-group-create",
                                                       {"name": address_group,
                                                        "type": "static",
                                                        "static_addresses": ip})
        responses.append(res_address_group_create)
        if is_error(res_address_group_create):
            return prepare_context_and_hr_multiple_executions(responses, brand_args.get('verbose'), '', [ip])

        res_rule_list = run_execute_command("prisma-sase-security-rule-list", {"name": rule_name})
        contents_rule_list = res_rule_list[0].get('Contents', '')
        if isinstance(contents_rule_list, str) and "does not exist" in contents_rule_list:
            demisto.debug(f"Creating a new rule {rule_name}")
            res_rule_create = run_execute_command("prisma-sase-security-rule-create",
                                                  {"action": "deny", "name": rule_name, 'destination': address_group})
            responses.append(res_rule_create)
            if is_error(res_rule_create):
                return prepare_context_and_hr_multiple_executions(responses, brand_args.get('verbose'), '', [ip])
        else:
            demisto.debug(f"The rule {rule_name} exists.")
            context_rule_list = get_relevant_context(res_rule_list[0].get('EntryContext', {}), 'PrismaSase.SecurityRule')
            rule_id = context_rule_list.get('id', '')
            rule_destination = context_rule_list.get('destination', [])
            if address_group not in rule_destination:
                rule_destination.append(address_group)
                res_rule_update = run_execute_command("prisma-sase-security-rule-update", {'rule_id': rule_id, 'action': 'deny', 'destination': rule_destination})
                responses.append(res_rule_update)
                if is_error(res_rule_update):
                    return prepare_context_and_hr_multiple_executions(responses, brand_args.get('verbose'), rule_name, [ip])

        res_auto_commit, auto_commit_message = prisma_sase_candidate_config_push(brand_args.get('auto_commit'), responses)
    else:
        demisto.debug(f"The {address_group=} exists, editing it.")
        rule_name = ''  # no rule will be created in this scenario. Avoid adding it to the human readable.
        context_add_group_list = get_relevant_context(res_add_group_list[0].get('EntryContext', {}), 'PrismaSase.AddressGroup')
        addresses_group_ip_list = context_add_group_list.get('addresses', [])
        if ip not in addresses_group_ip_list:
            demisto.debug(
                f"The {address_group=} exists, but the {ip=} isn't in the {addresses_group_ip_list=} of {address_group=}")
            group_id = context_add_group_list.get('id')
            res_add_group_update = run_execute_command("prisma-sase-address-group-update",{'group_id': group_id, 'static_addresses': ip})
            responses.append(res_add_group_update)
            if is_error(res_add_group_update):
                return prepare_context_and_hr_multiple_executions(responses, brand_args.get('verbose'), '', [ip])
            res_auto_commit, auto_commit_message = prisma_sase_candidate_config_push(brand_args.get('auto_commit'), responses)

    command_results_list = prepare_context_and_hr_multiple_executions(responses, brand_args.get('verbose'), rule_name, [ip])
    if auto_commit_message:
        command_results_list.append(auto_commit_message)
    return  command_results_list


@polling_function(
   name='block-external-ip',
   interval=60,
   timeout=600,
   requires_polling_arg=True,
)
def pan_os_commit_status(args: dict) -> PollResult:
    commit_job_id = args['commit_job_id']
    res_commit_status = run_execute_command("pan-os-commit-status", {'job_id': commit_job_id})
    result_commit_status = res_commit_status[0].get('Contents', {}).get('response', {}).get('result', {}).get('job', {})
    job_result = result_commit_status.get('result')
    demisto.debug(f"The result is {job_result=}")
    commit_output = {
        'JobID': commit_job_id,
        'Status': 'Success' if job_result == 'OK' else 'Failure',
    }
    continue_to_poll = result_commit_status.get('status') != 'FIN'
    args['continue_to_poll'] = continue_to_poll
    demisto.debug(f"after pan-os-commit-status {continue_to_poll=} {commit_job_id=}")
    return PollResult(
        response=CommandResults(
            outputs=commit_output,
            outputs_key_field='JobID',
            readable_output=tableToMarkdown('Commit Status:', commit_output, removeNull=True)
        ),
        args_for_next_run=args,
        continue_to_poll=continue_to_poll,  # continue polling if job isn't done
    )


def pan_os_check_trigger_push_to_device() -> bool:
    res_pan_os = run_execute_command("pan-os", {'cmd': '<show><system><info></info></system></show>', 'type': 'op'})
    context = get_relevant_context(res_pan_os[0].get('EntryContext', {}), 'Panorama.Command')
    model = context.get('response', {}).get('result', {}).get('system', {}).get('model', '')
    if model == "Panorama":
        return True
    return False


@polling_function(
   name='block-external-ip',
   interval=60,
   timeout=600,
   requires_polling_arg=True,
)
def pan_os_push_to_device(args: dict) -> PollResult:
    res_push_to_device = run_execute_command("pan-os-push-to-device-group", {'polling': True})
    polling_args = res_push_to_device[0].get('Metadata', {}).get('pollingArgs', {})
    job_id = polling_args.get('push_job_id')
    device_group = polling_args.get('device-group')
    # context_commit = get_relevant_context(res_push_to_device[0].get('EntryContext', {}), "Panorama.Push")
    # job_id = context_commit.get('JobID')
    # status = context_commit.get('Status')
    # device_group = context_commit.get('DeviceGroup')
    demisto.debug(f"The polling args are {job_id=} {device_group=}")
    if job_id:
        context_output = {
            'DeviceGroup': device_group,
            'JobID': job_id,
            'Status': 'Pending'
        }
        continue_to_poll = True
        push_cr = CommandResults(
            outputs_key_field='JobID',
            outputs=context_output,
            readable_output=tableToMarkdown('Push to Device Group:', context_output, removeNull=True)
        )
    else:
        push_cr = CommandResults(
            readable_output=res_push_to_device[0].get('Contents') or 'There are no changes to push.'
        )
        continue_to_poll = False

    args_for_next_run = {
        'push_job_id': job_id,
        'polling': True,
        'interval_in_seconds': 60,
        'device_group': device_group
    }
    args_for_next_run = args | args_for_next_run
    if args_for_next_run.get('commit_job_id'):
        args_for_next_run.pop('commit_job_id')
        args.pop('commit_job_id')
        args['push_job_id'] = job_id
    demisto.debug(f"The args for the next run of pan-os-push-to-device-group {args_for_next_run}")
    return PollResult(
        response=push_cr,
        continue_to_poll=continue_to_poll,
        args_for_next_run=args_for_next_run,
        partial_result=CommandResults(
            readable_output=f'Waiting for Job-ID {job_id} to finish push changes to device-group {device_group}...'
        )
    )


@polling_function(
   name='block-external-ip',
   interval=60,
   timeout=600,
   requires_polling_arg=True,
)
def pan_os_push_status(args: dict):
    push_job_id = args['push_job_id']
    return run_execute_command("pan-os-push-to-device-group", {'push_job_id': push_job_id})
    # TODO check and continue


def final_part_pan_os(args: dict, responses: list) -> list[CommandResults]:
    tag = args.get('tag')
    ip_list = args.get('ip_list')
    responses.append(run_execute_command('pan-os-register-ip-tag', {'tag': tag, 'IPs': ip_list}))
    results = prepare_context_and_hr_multiple_executions(responses, args['verbose'], '', ip_list)
    return results


def start_pan_os_flow(args: dict) -> tuple[list, bool]:
    responses = []
    tag = args['tag']
    address_group = args['address_group']
    rule_name = args['rule_name']
    log_forwarding_name = args.get('log_forwarding_name')
    auto_commit = args['auto_commit']

    res_list_add_group = run_execute_command("pan-os-list-address-groups", {})
    responses.append(res_list_add_group)
    context_list_add_group = get_relevant_context(res_list_add_group[0].get('EntryContext', {}), "Panorama.AddressGroups")
    if not check_value_exist_in_context(tag, context_list_add_group, 'Match'):
        # TODO check if the group already exists we should update the tag.
        demisto.debug(f"The {tag=} doesn't exist in the address groups")
        res_create_add_group = run_execute_command("pan-os-create-address-group", {'name': address_group, 'type': 'dynamic', 'match': tag})
        responses.append(res_create_add_group)
        res_list_rules = run_execute_command("pan-os-list-rules", {'pre_post': 'pre-rulebase'})
        context_list_rules = get_relevant_context(res_list_rules[0].get('EntryContext', {}), 'Panorama.SecurityRule')
        if check_value_exist_in_context(rule_name, context_list_rules, 'Name'):
            responses.append(run_execute_command("pan-os-edit-rule", {'rulename': rule_name, 'element_to_change': 'source', 'element_value': address_group, 'pre_post': 'pre-rulebase'}))
        else:
            create_rule_args = {'action': 'deny', 'rulename': rule_name, 'pre_post': 'pre-rulebase'}
            if log_forwarding_name:
                args['log_forwarding'] = log_forwarding_name
            responses.append(run_execute_command("pan-os-create-rule", create_rule_args))
        responses.append(run_execute_command("pan-os-move-rule", {'rulename': rule_name, 'where': 'top', 'pre_post': 'pre-rulebase'}))
        return responses, auto_commit  # should perform the commit section
    else:
        demisto.debug(f"The {tag=} does exist in the address groups, registering the ip.")
        results = final_part_pan_os(args, responses)
        return results, False


@polling_function(
   name='block-external-ip',
   interval=60,
   timeout=600,
   #requires_polling_arg=True,
)
def pan_os_commit(args: dict, responses: list) -> PollResult:
    res_commit = run_execute_command("pan-os-commit", {'polling': True})
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
        demisto.debug(f"Initiated a commit execution {continue_to_poll=} {job_id=}")
        args['continue_to_poll'] = continue_to_poll

    else:  # nothing to commit in pan-os, no reason to poll.
        commit_output = res_commit[0].get('Contents') or 'There are no changes to commit.'  # type: ignore[assignment]
        demisto.debug(f"No job_id, {commit_output}")
        continue_to_poll = False
        args['continue_to_poll'] = continue_to_poll

    args_for_next_run = {
        'commit_job_id': job_id,
        'interval_in_seconds': arg_to_number(args.get('interval_in_seconds', 60)),
        'timeout': arg_to_number(args.get('timeout', 600)),
        'polling': True,
        'push_job_id': ''
    }
    demisto.debug(f"The initial {args_for_next_run=}")
    args_for_next_run = args | args_for_next_run
    demisto.debug(f"After adding the original args {args_for_next_run=}")
    responses.append(res_commit)
    poll_result =  PollResult(
        response=commit_output,
        continue_to_poll=continue_to_poll,
        args_for_next_run=args_for_next_run,
        partial_result=CommandResults(
            readable_output=f'Waiting for commit job ID {job_id} to finish...'
        )
    )
    demisto.debug(f"{poll_result.continue_to_poll=} {isinstance(poll_result.continue_to_poll, bool)=}")
    return poll_result

def manage_pan_os_flow(args: dict):
    auto_commit = args['auto_commit']
    push_job_id = None
    res_push_status = None
    if commit_job_id := args.get('commit_job_id'):
        demisto.debug(f"Has a {commit_job_id=}")
        poll_commit_status = pan_os_commit_status(args)
        if not args['continue_to_poll']:
            demisto.debug("Finished polling, checking if we need to trigger pan_os_push_to_device")
            if pan_os_check_trigger_push_to_device():
                demisto.debug("Triggering pan_os_push_to_device")
                poll_push_to_device = pan_os_push_to_device(args)
                demisto.debug(f"returning {poll_commit_status=} {poll_push_to_device=}")
                return poll_push_to_device ,None
            else:
                demisto.debug("Not a Panorama instance, not pushing to device. Continue to register the IP.")
        else:
            return poll_commit_status, None
    elif push_job_id := args.get('push_job_id'):
        demisto.debug(f"Has a {push_job_id=}")
        res_push_status = pan_os_push_status(push_job_id)
        return_results(res_push_status)

    # check if we are in the initial run or should execute pan-os-register-ip-tag
    if commit_job_id or push_job_id:
        demisto.debug(f"{commit_job_id=} or {push_job_id=}")
        responses = args.get('panorama', [])
        if res_push_status:
            responses.append(res_push_status)
        return final_part_pan_os(args, responses), None
    else:
        res, should_commit = start_pan_os_flow(args)
        demisto.debug(f"The length of the responses is {len(res)}")
        if should_commit:
            poll_result = pan_os_commit(args, res)
            demisto.debug(f"The result that returned from the commit execution is {poll_result=} and {args=}")
            demisto.debug(f"The length of the responses after adding the res_commit is {len(res)}")
            if not args['continue_to_poll']:
                result = final_part_pan_os(args, res)
                demisto.debug(f"The result after continue_to_poll is false {result=}")
                return result, None
            return poll_result, res
        elif isinstance(res[0], CommandResults): # already did the final part in start_pan_os_flow
            return res, None
        else:
            cr_should_commit = CommandResults(readable_output=f"Not commiting the changes in Panorama, since "
                                                              f"{auto_commit=}. Please do so manually for the changes "
                                                              f"to take affect.")
            result = final_part_pan_os(args, res)
            result.append(cr_should_commit)
            return result, None


def run_execute_command(command_name: str, args: dict[str, Any]) -> list[dict]:
    """
    Executes a command and processes its results.
    This function runs a specified command with given arguments, handles any errors,
    and prepares the command results for further processing.
    Args:
        command_name (str): The name of the command to execute.
        args (dict[str, Any]): A dictionary of arguments to pass to the command.
    Returns:
        A list of the relevant command results.
    """
    demisto.debug(f"BEI: Executing command: {command_name} with {args=}")
    res = demisto.executeCommand(command_name, args)
    demisto.debug(f"BEI: The response of {command_name} is {res}")
    return res


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
        tag = args.get("tag", "xsiam-blocked-external-ip")
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
                    result = run_execute_command(command_name, args)
                    results.append(prepare_context_and_hr(result, verbose, ip_list_arr))

                elif brand == "Cisco ASA":
                    command_name = 'cisco-asa-create-rule'
                    for ip in ip_list_arr:
                        args = {
                            "destination": ip,
                            "interface_type": "Global",
                            "source": "0.0.0.0",
                            "permit": False
                        }
                        result = run_execute_command(command_name, args)
                        results.append(prepare_context_and_hr(result, verbose, [ip]))

                elif brand == "F5Silverline":
                    command_name = "f5-silverline-ip-object-add"
                    for ip in ip_list_arr:
                        args = {
                            "list_type": "denylist",
                            "cidr_range": ip,
                            "tags": tag
                        }
                        result = run_execute_command(command_name, args)
                        results.append(prepare_context_and_hr(result, verbose, [ip]))

                elif brand == "FortiGate":
                    command_name = "fortigate-ban-ip"
                    args = {
                        "ip_address": ip_list_arg
                    }
                    result = run_execute_command(command_name, args)
                    results.append(prepare_context_and_hr(result, verbose, ip_list_arr))

                elif brand == "Palo Alto Networks - Prisma SASE":
                    for ip in ip_list_arr:
                        brand_args = {
                            'ip': ip,
                            'address_group': address_group,
                            'verbose': verbose,
                            'rule_name': rule_name,
                            'auto_commit': auto_commit,
                        }
                        results.append(prisma_sase_block_ip(brand_args))

                elif brand == "Panorama":
                    brand_args = {
                        'ip_list': ip_list_arr,
                        'rule_name': rule_name,
                        'log_forwarding_name': log_forwarding_name,
                        'address_group': address_group,
                        'tag': tag,
                        'auto_commit': auto_commit,
                        'verbose': verbose,
                        'brands': brands_to_run,
                        'commit_job_id': args.get('commit_job_id'),
                        'push_job_id': args.get('push_job_id'),
                        'polling': True
                    }
                    result, responses = manage_pan_os_flow(brand_args)  # TODO in the end of the flow return CommandResult list
                    if not isinstance(result, list) or len(result) == 2:
                        demisto.debug(f"We are in a polling scenario {result=} {isinstance(result, list)=}")
                        # if we are in polling situation, save the existing results from other brands
                        # if args.get('commit_job_id') or args.get('push_job_id'):
                        #     # during a polling execution, we want to add the new values without overwriting the previous ones
                        #     prev_context = args.get('script_context', {})
                        #     prev_responses = prev_context.get('panorama', [])
                        #     responses = prev_responses.append(responses) if responses else prev_responses
                        #     results = prev_context.get('command_results_list', [])
                        #
                        # script_context = {
                        #     'panorama': responses,
                        #     'command_results_list': results
                        # }
                        #result.args_for_next_run['script_context'] = script_context
                        #demisto.debug(f"After updating {result.args_for_next_run=}")
                        return_results(result)

                    else:
                        demisto.debug(f"The result object is {result}")
                        script_context = args.get('script_context', {})
                        demisto.debug(f"{script_context=}")
                        results_from_context = script_context.get('command_results_list', [])
                        results_from_context.append(result)
                        demisto.debug(f"{results_from_context=}")
                        results = results_from_context
                        return_results(results)

                else:
                    return_error(f"The brand {brand} isn't a part of the supported integration for 'block-external-ip'. "
                                 f"The supported integrations are: Palo Alto Networks - Prisma SASE, Panorama, "
                                 f"CheckPointFirewall_v2, FortiGate, F5Silverline, Cisco ASA, Zscaler.")
            else:
                demisto.info(f"The brand {brand} isn't enabled.")
        demisto.debug(f"returning at the end of main() {results=}")
        return_results(results)

    except Exception as ex:
        return_error(f"Failed to execute block-external-ip. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
