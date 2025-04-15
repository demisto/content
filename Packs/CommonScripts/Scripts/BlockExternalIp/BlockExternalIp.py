import ast

import demistomock as demisto
from CommonServerPython import *


POLLING = False

""" STANDALONE FUNCTION """


def create_final_human_readable(failure_message: str, used_integration: str, ip_list: list, rule_name: str = '') -> str:
    """
    Creates the human readable of the command.
    Args:
        failure_message (str): a failure message if relevant.
        used_integration (str): The integration that was used.
        ip_list (list): The list of ip/s to block
        rule_name (str): The name of the created rule
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


def prepare_context_and_hr_multiple_executions(responses: list[list[dict]], verbose: bool, rule_name: str,
                                               ip_list_arr: list[str]) -> list[CommandResults]:
    """ Creates the relevant context and human readable in case of multiple command executions.
    Args:
        responses (list[list[dict]]): The responses returned from the execute command.
        verbose (bool): Whether to print the all the human readable from the executions of all the commands or just the summary.
        rule_name (str): The name of the security rule.
        ip_list_arr (list[str]): The list of ips.
    Returns:
        A list containing the relevant Command results.
    """
    demisto.debug(f"In prepare_context_and_hr_multiple_executions, {len(responses)=} {responses=}")
    results = []
    failed_messages = []
    used_integration = responses[0][0].get('Metadata', {}).get('brand')  # all executions are for the same brand.
    demisto.debug(f"In prepare_context_and_hr_multiple_executions, {used_integration=}")

    for res in responses:
        for entry in res:
            command_hr = entry.get('HumanReadable')
            message = entry.get('Contents')
            demisto.debug(f"In prepare_context_and_hr_multiple_executions {command_hr=} {message=}")
            if command_hr and command_hr != str(None):
                demisto.debug(f"BEI: The command has {verbose=}, adding {command_hr=}")
                results.append(CommandResults(readable_output=command_hr))
            elif is_error(entry):  # (message and 'Failed' in message) or
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


def reduce_pan_os_responses(responses: list) -> list[list[dict]]:
    """ Returns a list of just the information needed for later usage by the flow.
    Args:
        responses (list[list[dict]]): The responses returned from the execute command.
    Returns:
        A list containing the relevant parts of the command responses.
    """
    demisto.debug("Updating the responses in sanitize_pan_os_responses.")
    sanitize_responses = []
    for res in responses:
        current_new_res = []
        for entry in res:
            command_hr = entry.get('HumanReadable')
            message = entry.get('Contents')
            entry_type = entry.get('Type')
            demisto.debug(f"got {entry_type=} , {command_hr=} , {message=}")
            current_new_res.append({
                'HumanReadable': command_hr,
                'Contents': message,
                'Type': entry_type
            })
        sanitize_responses.append(current_new_res)
    demisto.debug(f"{len(sanitize_responses)=}, {len(responses)=}")
    return sanitize_responses


def prepare_context_and_hr(response: list[dict], verbose: bool, ip_list: list[str]) -> list[CommandResults]:
    """ Creates the relevant context and human readable in case of a single command execution.
    Args:
        response (list[dict]): The response returned from the execute command.
        verbose (bool): Whether to print the all the human readable from the executions of all the commands or just the summary.
        ip_list (list[str]): The list of ips.
    Returns:
        A list containing the relevant Command results.
    """
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
    """ Get the relevant context object from the execute_command response.
    Args:
        original_context (dict[str, Any]): The original context ('EntryContext') returned in the execute_command response.
        key (str): The key to extract from the original_context.
    Returns:
        A dict or a list that are the relevant command context.
    """
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
    """ Verify if a specific value of a specific key is present in the context.
    Args:
        value (str): The value we want to verify its existence.
        context (list[dict]): The command context.
        key (str): The key to extract from the context.
    Returns:
        A boolean representing the existence of the value (True) or False.
    """
    for item in context:
        match = item.get(key, '')
        if match and match == value:
            demisto.debug(f"The {value=} was found")
            return True
        elif match:
            match_split = match.split('or') if isinstance(match, str) else match.get('#text', '').split('or')
            match_split_strip = [m.strip() for m in match_split]
            if value in match_split_strip:
                demisto.debug(f"The {value=} was found in an 'or' case")
                return True
    demisto.debug(f"The {value=} isn't in the context with the {key=}")
    return False


def get_match_by_name(name: str, context: list | dict) -> str:
    """ Get the relevant "Match" value where the address_group_name == name.
    Args:
        name (str): The name of the relevant address group.
        context (list | dict): The original context ('EntryContext') returned in the execute_command response.
    Returns:
        The match value.
    """
    for item in context:
        address_group_name = item.get('Name', '')
        if address_group_name and address_group_name == name:
            match = item.get('Match', '')
            if isinstance(match, dict):
                match = match.get('#text')
            demisto.debug(f"The {name=} was found, returning the {match}")
            return match
    return ''  # when creating a dynamic address group a match value is a required, so it won't get here


def update_brands_to_run(brands_to_run: list) -> tuple[list, set]:
    """ Delete the brands that were executed already from the list of brands_to_run.
        Would be used in a case that at least one brand finished its execution before the polling of the other brand is over.
    Args:
        brands_to_run (list): The list of brands that should be executed.
    Returns:
        The list of brands that were executed in previous runs and a set of the brands that should be executed in the current run.
    """
    incident_context = demisto.context()
    executed_brands = incident_context.get('executed_brands', '')
    executed_brands = ast.literal_eval(incident_context.get('executed_brands', '')) if executed_brands else []
    updated_brands_to_run = {b for b in brands_to_run if b not in executed_brands}
    demisto.debug(f"Removed {executed_brands=} from {brands_to_run=}")
    return executed_brands, updated_brands_to_run


""" COMMAND FUNCTION """


def prisma_sase_candidate_config_push(auto_commit: bool, responses: list) -> CommandResults:
    """ Execute the command prisma-sase-candidate-config-push if needed.
    Args:
        auto_commit (bool): Whether to execute the command prisma-sase-candidate-config-push.
        responses (list): The list of current responses from the previous execute command executions of prisma-sase.
    Returns:
        A tuple of
        1. The response of the execution of the command prisma-sase-candidate-config-push or None if wasn't executed
        2. None or the command result created in case the auto_commit == false.
    """
    auto_commit_message = None
    if auto_commit:
        res_auto_commit = run_execute_command("prisma-sase-candidate-config-push",
                                                 {
                                                     "folders": "Remote Networks, Mobile Users, Service Connections"})
        responses.append(res_auto_commit)
    else:
        auto_commit_message = CommandResults(readable_output=f"Not commiting the changes in Palo Alto Networks - Prisma SASE, "
                                       f"since {auto_commit=}. Please do so manually for the changes to take affect.")
    return auto_commit_message


def prisma_sase_security_rule_update(rule_name: str, address_group: str, responses: list) -> list:
    """ Execute the command prisma-sase-security-rule-update if needed.
    Args:
        rule_name (str): The name of the rule.
        address_group (list[dict]): The address group name.
        responses (list): The list of current responses from the previous execute command executions of prisma-sase.
    Returns:
        The response of prisma-sase-security-rule-update if it was executed, else an empty list.
    """
    demisto.debug(f"The rule {rule_name} exists.")
    res_rule_list = responses[-1]
    context_rule_list = get_relevant_context(res_rule_list[0].get('EntryContext', {}), 'PrismaSase.SecurityRule')
    rule_id = context_rule_list.get('id', '')
    rule_destination = context_rule_list.get('destination', [])
    if address_group not in rule_destination:
        res_rule_update = run_execute_command("prisma-sase-security-rule-update",
                                              {'rule_id': rule_id, 'action': 'deny', 'destination': address_group})
        responses.append(res_rule_update)
        return res_rule_update
    return []


def prisma_sase_block_ip(brand_args: dict) -> list[CommandResults]:
    """ Execute the flow of prisma sase.
    Args:
        brand_args (dict): The flow arguments.
    Returns:
        A list of CommandResults.
    """
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
        demisto.debug(f"The {ip} does not exist in the address-object list.")
        res_add_obj_create = run_execute_command("prisma-sase-address-object-create",
                                                 {'name': ip, 'type': 'ip_netmask', 'address_value': ip})
        responses.append(res_add_obj_create)
        if is_error(res_add_obj_create):
            return prepare_context_and_hr_multiple_executions(responses, brand_args.get('verbose'), '', [ip])
        auto_commit_message = prisma_sase_candidate_config_push(brand_args.get('auto_commit'), responses)

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
        responses.append(res_rule_list)
        if isinstance(contents_rule_list, str) and "does not exist" in contents_rule_list:
            demisto.debug(f"Creating a new rule {rule_name}")
            res_rule_create = run_execute_command("prisma-sase-security-rule-create",
                                                  {"action": "deny", "name": rule_name, 'destination': address_group})
            responses.append(res_rule_create)
            if is_error(res_rule_create):
                return prepare_context_and_hr_multiple_executions(responses, brand_args.get('verbose'), '', [ip])
        else:
            res_rule_update = prisma_sase_security_rule_update(rule_name, address_group, responses)
            if res_rule_update and is_error(res_rule_update):
                return prepare_context_and_hr_multiple_executions(responses, brand_args.get('verbose'), rule_name, [ip])

        auto_commit_message = prisma_sase_candidate_config_push(brand_args.get('auto_commit'), responses)
    else:
        demisto.debug(f"The {address_group=} exists, editing it.")
        context_add_group_list = get_relevant_context(res_add_group_list[0].get('EntryContext', {}), 'PrismaSase.AddressGroup')
        addresses_group_ip_list = context_add_group_list.get('addresses', [])
        if ip not in addresses_group_ip_list:
            demisto.debug(
                f"The {address_group=} exists, but the {ip=} isn't in the {addresses_group_ip_list=} of {address_group=}")
            group_id = context_add_group_list.get('id')
            res_add_group_update = run_execute_command("prisma-sase-address-group-update",
                                                       {'group_id': group_id, 'static_addresses': ip})
            responses.append(res_add_group_update)
            if is_error(res_add_group_update):
                return prepare_context_and_hr_multiple_executions(responses, brand_args.get('verbose'), '', [ip])
            auto_commit_message = prisma_sase_candidate_config_push(brand_args.get('auto_commit'), responses)

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
def pan_os_commit_status(args: dict, responses: list) -> PollResult:
    """ Check the status of the commit process in pan-os.
    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the previous command.
    Returns:
        The PollResult object.
    """
    commit_job_id = args['commit_job_id']
    res_commit_status = run_execute_command("pan-os-commit-status", {'job_id': commit_job_id})
    responses.append(res_commit_status)
    result_commit_status = res_commit_status[0].get('Contents', {}).get('response', {}).get('result', {}).get('job', {})
    job_result = result_commit_status.get('result')
    demisto.debug(f"The result is {job_result=}")
    commit_output = {
        'JobID': commit_job_id,
        'Status': 'Success' if job_result == 'OK' else 'Failure',
    }
    continue_to_poll = result_commit_status.get('status') != 'FIN'
    global POLLING
    POLLING = continue_to_poll
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


def pan_os_check_trigger_push_to_device(responses: list) -> bool:
    """ Verify if this is a Panorama instance.
    Args:
        responses (list): The responses of the previous command.
    Returns:
        The PollResult object.
    """
    res_pan_os = run_execute_command("pan-os", {'cmd': '<show><system><info></info></system></show>', 'type': 'op'})
    responses.append(res_pan_os)
    context = get_relevant_context(res_pan_os[0].get('EntryContext', {}), 'Panorama.Command')
    model = context.get('response', {}).get('result', {}).get('system', {}).get('model', '')
    return model == 'Panorama'


@polling_function(
   name='block-external-ip',
   interval=60,
   timeout=600,
   requires_polling_arg=True,
)
def pan_os_push_to_device(args: dict, responses: list) -> PollResult:
    """ Execute pan-os-push-to-device-group.
    Args:
        responses (list): The responses of the previous command.
    Returns:
        The PollResult object.
    """
    res_push_to_device = run_execute_command("pan-os-push-to-device-group", {'polling': True})
    responses.append(res_push_to_device)
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
        push_cr = CommandResults(
            outputs_key_field='JobID',
            outputs=context_output,
            readable_output=tableToMarkdown('Push to Device Group:', context_output, removeNull=True)
        )
        demisto.setContext('push_job_id', job_id)
    else:
        push_cr = CommandResults(
            readable_output=res_push_to_device[0].get('Contents') or 'There are no changes to push.'
        )
        continue_to_poll = False
    global POLLING
    POLLING = continue_to_poll

    return PollResult(
        response=push_cr,
        continue_to_poll=continue_to_poll,
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
def pan_os_push_status(args: dict, responses: list):
    """ Check the status of the push operation in pan-os.
    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the previous command.
    Returns:
        The PollResult object.
    """
    push_job_id = args['push_job_id']
    res_push_device_status = run_execute_command("pan-os-push-status", {'job_id': push_job_id})
    responses.append(res_push_device_status)
    push_status = (res_push_device_status[0].get('Contents', {}).get('response', {}).get('result', {}).get('job', {})
                   .get('status', ''))

    continue_to_poll = bool(push_status and push_status != 'FIN')
    demisto.debug(f"{push_status=}")
    demisto.debug(f"{continue_to_poll=}")
    context_output = {
        'Status': push_status,
        'JobID': push_job_id,
    }
    push_cr = CommandResults(
        outputs_key_field='JobID',
        outputs=context_output,  # update it according to the output from the execution.
        readable_output=tableToMarkdown('Push to Device Group:', context_output, removeNull=True)
    )
    global POLLING
    POLLING = continue_to_poll
    return PollResult(
        response=push_cr,
        continue_to_poll=continue_to_poll,
        partial_result=CommandResults(
            readable_output=f'Waiting for Job-ID {push_job_id} to finish push changes...'
        )
    )


def final_part_pan_os(args: dict, responses: list) -> list[CommandResults]:
    """ Execute the final part of the pan-os flow.
    1. Initialize all the context values.
    2. Create the list of Command Results.
    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the previous commands.
    Returns:
        The list of Command Results.
    """
    tag = args.get('tag')
    ip_list = args.get('ip_list')
    demisto.setContext('push_job_id', '')  # delete any previous value if exists
    demisto.setContext('commit_job_id', '')  # delete any previous value if exists
    demisto.setContext('panorama_responses', '')  # delete any previous value if exists
    responses.append(run_execute_command('pan-os-register-ip-tag', {'tag': tag, 'IPs': ip_list}))
    results = prepare_context_and_hr_multiple_executions(responses, args['verbose'], args['rule_name'], ip_list)
    return results


def pan_os_create_edit_address_group(address_group: str, context_list_add_group: list, tag: str, responses: list):
    """ Checks whether to create a new address group or update an existing one, and does it.
    Args:
        address_group (str): The address group.
        context_list_add_group (list): The context of pan-os-list-address-group.
        tag (str): The tag.
        responses (list): The responses of the previous commands.
    """
    if check_value_exist_in_context(address_group, context_list_add_group, 'Name'):
        current_match = get_match_by_name(address_group, context_list_add_group)
        new_match = f'{current_match} or {tag}' if current_match else tag
        res_edit_add_group = run_execute_command("pan-os-edit-address-group",
                                                 {'name': address_group, 'type': 'dynamic', 'match': new_match})
        responses.append(res_edit_add_group)
    else:
        res_create_add_group = run_execute_command("pan-os-create-address-group",
                                                   {'name': address_group, 'type': 'dynamic', 'match': tag})
        responses.append(res_create_add_group)


def pan_os_create_edit_rule(rule_name: str, context_list_rules: list, address_group: str, log_forwarding_name: str,
                            responses: list):
    """ Checks whether to create a new address group or update an existing one, and does it.
    Args:
        rule_name (str): The rule name.
        address_group (str): The address group.
        context_list_rules (list): The context of pan-os-list-rules.
        log_forwarding_name (str): Panorama log forwarding object name.
        responses (list): The responses of the previous commands.
    """
    if check_value_exist_in_context(rule_name, context_list_rules, 'Name'):
        responses.append(run_execute_command("pan-os-edit-rule", {'rulename': rule_name,
                                                                  'element_to_change': 'source',
                                                                  'element_value': address_group,
                                                                  'pre_post': 'pre-rulebase'}))
    else:
        create_rule_args = {'action': 'deny', 'rulename': rule_name, 'pre_post': 'pre-rulebase',
                            'source': address_group}
        if log_forwarding_name:
            create_rule_args['log_forwarding'] = log_forwarding_name
        responses.append(run_execute_command("pan-os-create-rule", create_rule_args))
    responses.append(run_execute_command("pan-os-move-rule", {'rulename': rule_name, 'where': 'top', 'pre_post': 'pre-rulebase'}))


def start_pan_os_flow(args: dict) -> tuple[list, bool]:
    """ Start the flow of pan-os.
    Args:
        args (dict): The arguments of the function.
    Returns:
        A tuple that can be one of 2 options:
        1. A list of the responses of all the command executions until this point, a boolean represents whether to
            commit the changes to pan-os. This option will take effect if the input tag doesn't exist in pan-os.
        2. A list of command results, and a "False" representing the fact that a commit to pan-os shouldn't be
            performed since the tag already exists.
    """
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
        # check if the group already exists we should update the tag.
        demisto.debug(f"The {tag=} doesn't exist in the address groups")
        pan_os_create_edit_address_group(address_group, context_list_add_group, tag, responses)

        res_list_rules = run_execute_command("pan-os-list-rules", {'pre_post': 'pre-rulebase'})
        responses.append(res_list_rules)
        context_list_rules = get_relevant_context(res_list_rules[0].get('EntryContext', {}), 'Panorama.SecurityRule')
        pan_os_create_edit_rule(rule_name, context_list_rules, address_group, log_forwarding_name, responses)
        return responses, auto_commit  # should perform the commit section
    else:
        args['rule_name'] = ''
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
    """ Execute pan-os-commit.
    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the command executions so far.
    Returns:
        A PollResult object.
    """
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
        demisto.setContext('commit_job_id', job_id)

    else:  # nothing to commit in pan-os, no reason to poll.
        commit_output = res_commit[0].get('Contents') or 'There are no changes to commit.'  # type: ignore[assignment]
        demisto.debug(f"No job_id, {commit_output}")
        continue_to_poll = False
    global POLLING
    POLLING = continue_to_poll

    args_for_next_run = {
        'commit_job_id': job_id,
        'interval_in_seconds': arg_to_number(args.get('interval_in_seconds', 60)),
        'timeout': arg_to_number(args.get('timeout', 600)),
        'polling': True,
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
    return poll_result

def manage_pan_os_flow(args: dict) -> CommandResults | list[CommandResults] | PollResult:  # pragma: no cover
    """ Manage the different states of the pan-os flow.
    Args:
        args (dict): The arguments of the function.
    Returns:
        The relevant result of the current state. If it is a polling state than a PollResult object will be returned, otherwise
        a Command Result or a list of Command Results, depends on the commands that were executed.
    """
    incident_context = demisto.context()
    demisto.debug(f"The context in the beginning of manage_pan_os_flow {incident_context=}")
    auto_commit = args['auto_commit']
    res_push_status = None
    responses = []
    commit_job_id = args.get('commit_job_id') or demisto.get(incident_context, 'commit_job_id')
    if push_job_id := demisto.get(incident_context, 'push_job_id'):
        demisto.debug(f"Has a {push_job_id=}")
        responses = ast.literal_eval(incident_context.get('panorama_responses', ''))
        args['push_job_id'] = push_job_id
        res_push_status = pan_os_push_status(args, responses)
        if not POLLING:
            demisto.debug("Finished polling, finishing the flow")
            return final_part_pan_os(args, responses)
        else:
            demisto.debug(f"Poll for the push status. Save the responses to the context {len(responses)=}")
            responses = reduce_pan_os_responses(responses)
            demisto.setContext('panorama_responses', str(responses))
            return res_push_status
    elif commit_job_id:
        demisto.debug(f"Has a {commit_job_id=}")
        args['commit_job_id'] = commit_job_id
        responses = ast.literal_eval(incident_context.get('panorama_responses', ''))
        poll_commit_status = pan_os_commit_status(args, responses)
        if not POLLING:
            demisto.debug("Finished polling for the commit status, checking if we need to trigger pan_os_push_to_device")
            if pan_os_check_trigger_push_to_device(responses):
                demisto.debug("Triggering pan_os_push_to_device")
                poll_push_to_device = pan_os_push_to_device(args, responses)
                if not POLLING:
                    demisto.debug("Nothing to push. Finish the process.")
                    return final_part_pan_os(args, responses)
                else:
                    demisto.debug(f"Poll for the push status. Save the responses to the context {len(responses)=}")
                    responses = reduce_pan_os_responses(responses)
                    demisto.setContext('panorama_responses', str(responses))
                    return poll_push_to_device
            else:
                demisto.debug("Not a Panorama instance, not pushing to device. Continue to register the IP.")
                return final_part_pan_os(args, responses)
        else:
            demisto.debug(f"Poll for the commit status. Save the responses to the context {len(responses)=}")
            responses = reduce_pan_os_responses(responses)
            demisto.setContext('panorama_responses', str(responses))
            return poll_commit_status

    # if we are here, it is the beginning of the flow
    responses, should_commit = start_pan_os_flow(args)
    demisto.debug(f"The length of the responses is {len(responses)}")
    if should_commit:
        poll_result = pan_os_commit(args, responses)
        demisto.debug(f"The result that returned from the commit execution is {poll_result=} and {args=}")
        demisto.debug(f"The length of the responses after adding the res_commit is {len(responses)}")
        if not POLLING:
            result = final_part_pan_os(args, responses)
            demisto.debug(f"The result after continue_to_poll is false {result=}")
            return result
        else:
            demisto.debug(f"Poll for the commit status. Save the responses to the context {len(responses)=}")
            responses = reduce_pan_os_responses(responses)
            demisto.setContext('panorama_responses', str(responses))
            return poll_result
    elif isinstance(responses[0], CommandResults): # already did the final part in start_pan_os_flow
        return responses
    else:
        cr_should_commit = CommandResults(readable_output=f"Not commiting the changes in Panorama, since "
                                                          f"{auto_commit=}. Please do so manually for the changes "
                                                          f"to take affect.")
        result = final_part_pan_os(args, responses)
        result.append(cr_should_commit)
        return result


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


def main():  # pragma: no cover
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

        executed_brands, updated_brands_to_run = update_brands_to_run(brands_to_run)

        results = []
        for brand in updated_brands_to_run:
            demisto.debug(f"BEI: the current brand is {brand}")
            if brand in enabled_brands:
                if brand == "Zscaler":
                    brand_args = {
                        'ip': ip_list_arg
                    }
                    command_name = 'zscaler-blacklist-ip'
                    result = run_execute_command(command_name, brand_args)
                    results.append(prepare_context_and_hr(result, verbose, ip_list_arr))
                    executed_brands.append(brand)

                elif brand == "Cisco ASA":
                    command_name = 'cisco-asa-create-rule'
                    for ip in ip_list_arr:
                        brand_args = {
                            "destination": ip,
                            "interface_type": "Global",
                            "source": "0.0.0.0",
                            "permit": False
                        }
                        result = run_execute_command(command_name, brand_args)
                        results.append(prepare_context_and_hr(result, verbose, [ip]))
                    executed_brands.append(brand)

                elif brand == "F5Silverline":
                    command_name = "f5-silverline-ip-object-add"
                    for ip in ip_list_arr:
                        brand_args = {
                            "list_type": "denylist",
                            "cidr_range": ip,
                            "tags": tag
                        }
                        result = run_execute_command(command_name, brand_args)
                        results.append(prepare_context_and_hr(result, verbose, [ip]))
                    executed_brands.append(brand)

                elif brand == "FortiGate":
                    command_name = "fortigate-ban-ip"
                    brand_args = {
                        "ip_address": ip_list_arg
                    }
                    result = run_execute_command(command_name, brand_args)
                    results.append(prepare_context_and_hr(result, verbose, ip_list_arr))
                    executed_brands.append(brand)

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
                    executed_brands.append(brand)

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
                        'polling': True
                    }
                    result = manage_pan_os_flow(brand_args)
                    if not POLLING:
                        demisto.debug("Not in a polling mode, adding Panorama to the executed_brands.")
                        executed_brands.append(brand)
                    demisto.setContext('executed_brands', str(executed_brands))
                    demisto.debug(f"Before returning {result=} in panorama")
                    results.append(result)

                else:
                    return_error(f"The brand {brand} isn't a part of the supported integration for 'block-external-ip'. "
                                 f"The supported integrations are: Palo Alto Networks - Prisma SASE, Panorama, "
                                 f"FortiGate, F5Silverline, Cisco ASA, Zscaler.")
            else:
                demisto.info(f"The brand {brand} isn't enabled.")
        demisto.debug(f"returning at the end of main(), {results=}")
        if not POLLING:
            demisto.debug("Not in a polling mode, initializing the executed_brands.")
            demisto.setContext('executed_brands', '')
        return_results(results)

    except Exception as ex:
        return_error(f"Failed to execute block-external-ip. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
