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

def prepare_context_and_hr_multiple_executions(responses: list[list[dict]], verbose: bool, rule_name: str, ip_list_arr: list[str]) -> list:  # a list of command results
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


def checkpoint_object_names_to_members(context: list[dict], ips: list) -> list:
    """ Return the list of names of the ipv4-address object in checkpoint.
    Args:
        context (list): The command context.
        ips (list): The list of input ips.
    Returns:
        The list of the object names.
    """
    output_names = []
    for obj in context:
        ipv4_address = obj.get('ipv4-address', '')
        if ipv4_address and ipv4_address in ips:
            obj_name = obj.get('name')
            output_names.append(obj_name)
            demisto.debug(f"Added the name {obj_name} to the list of object names since {ipv4_address=} is in the input ips.")
    return output_names


""" COMMAND FUNCTION """


@polling_function(
   name='block-external-ip',
   interval=60,
   timeout=600,
)
def checkpoint_publish(args: dict, responses: list, next_command: str) -> PollResult:
    """ Execute the checkpoint-publish command.
    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the command executions so far.
        next_command (str): The command that should be executed after the publish process.
    Returns:
        A PollResult object.
    """
    session_id = args['session_id']
    res_checkpoint_publish = run_execute_command("checkpoint-publish", {"session_id": session_id})
    responses.append(res_checkpoint_publish)
    task_id = get_relevant_context(res_checkpoint_publish[0].get('EntryContext', {}), "CheckPoint.Publish").get('task-id')
    if task_id:
        context_output = {
            'JobID': task_id,
            'Status': 'Pending'
        }
        continue_to_poll = True
        publish_output = CommandResults(
            outputs=context_output,
            readable_output=tableToMarkdown('Publish Status:', context_output, removeNull=True)
        )
        demisto.debug(f"Initiated a publish execution {continue_to_poll=} {task_id=}")
        demisto.setContext("publish_job_id", task_id)
        demisto.setContext("next_command", next_command)
    else:
        publish_output = res_checkpoint_publish[0].get('Contents') or 'There are no changes to publish.'
        demisto.debug(f"No task_id, {publish_output}")
        continue_to_poll = False
    global POLLING
    POLLING = continue_to_poll

    args_for_next_run = {
        'publish_job_id': task_id,
        'interval_in_seconds': arg_to_number(args.get('interval_in_seconds', 60)),
        'timeout': arg_to_number(args.get('timeout', 600)),
        'polling': True,
    }
    args_for_next_run = args | args_for_next_run
    demisto.debug(f"After adding the original args {args_for_next_run=}")
    return PollResult(
        response=publish_output,
        continue_to_poll=continue_to_poll,
        args_for_next_run=args_for_next_run,
        partial_result=CommandResults(
            readable_output=f'Waiting for commit job ID {task_id} to finish...'
        )
    )


@polling_function(
   name='block-external-ip',
   interval=60,
   timeout=600,
)
def checkpoint_show_task(args: dict, responses: list) -> PollResult:
    """ Execute the checkpoint-show-task command to check the status of the publish process.
    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the command executions so far.
    Returns:
        A PollResult object.
    """
    session_id = args['session_id']
    task_id = args['publish_job_id']
    res_show_task = run_execute_command("checkpoint-show-task", {"session_id": session_id, 'task_id': task_id})
    responses.append(res_show_task)
    context = get_relevant_context(res_show_task[0].get('EntryContext', {}), 'CheckPoint.ShowTask')
    status_show_task = context[0].get('status', '') if isinstance(context, list) else context.get('status', '')
    progress_percentage_show_task = context[0].get('progress-percentage', '') if isinstance(context, list) else context.get('progress-percentage', '')
    show_task_output = {
        'JobID': task_id,
        'Status': 'Success' if status_show_task == 'succeeded' else 'Failure',
    }
    continue_to_poll = progress_percentage_show_task != 100
    global POLLING
    POLLING = continue_to_poll
    demisto.debug(f"after checkpoint-show-task {continue_to_poll=} {task_id=}")
    return PollResult(
        response=CommandResults(
            outputs=show_task_output,
            outputs_key_field='JobID',
            readable_output=tableToMarkdown('Publish Status:', show_task_output, removeNull=True)
        ),
        args_for_next_run=args,
        continue_to_poll=continue_to_poll,  # continue polling if job isn't done
    )


def checkpoint_get_session_id() -> str:
    """ Execute the checkpoint-login-and-get-session-id command to get a session_id.
    Returns:
        The session_id.
    """
    res_login = run_execute_command("checkpoint-login-and-get-session-id", {})
    context_login = get_relevant_context(res_login[0].get('EntryContext', {}), 'CheckPoint.Login')
    session_id = context_login.get('session-id')
    demisto.setContext("session_id", session_id)
    return session_id


def checkpoint_get_group_members(context: dict, key: str) -> list:
    """ Get the current members of a specific address_group in checkpoint.
    Args:
        context (dict): The checkpoint-group-get context.
        key (str): The relevant information of the member, for example the name or the related ip.
    Returns:
        A list of the asked information about the current group members.
    """
    demisto.debug(f"in checkpoint_get_group_members {context=}")
    group_members = context.get('members', [])
    group_members_name = []
    for member in group_members:
        demisto.debug(f"Getting the {key=} from {member=}")
        group_members_name.append(member.get(key))
    return group_members_name


def start_checkpoint_flow(args: dict, responses: list) -> PollResult | None:
    """ Execute the first part of the checkpoint flow (up until the first publish, and trigger it if needed).
    Args:
        args (dict): the function arguments.
        responses (list): The object that will be used for saving the different execute_command responses.
    Returns:
        A PollResult if a publish process was triggered or None.
    """
    session_id = args['session_id']
    ip_list = args['ip_list']
    address_group = args['address_group']
    res_show_object = run_execute_command("checkpoint-show-objects",
                                          {'session_id': session_id, 'filter_search': ip_list, 'ip_only': True})
    responses.append(res_show_object)
    res_group_get = run_execute_command("checkpoint-group-get", {'identifier': address_group, 'session_id': session_id})
    res_group_get[0]['Type'] = 1  # updating the entry type so it won't reflect an error in case the group wasn't found.
    responses.append(res_group_get)
    contents_group_get = res_group_get[0].get('Contents')

    if contents_group_get and isinstance(contents_group_get, str) and 'Not Found' in contents_group_get:
        demisto.debug(f"The {address_group=} wasn't found, creating it.")
        res_group_add = run_execute_command("checkpoint-group-add", {'name': address_group, 'session_id': session_id})
        responses.append(res_group_add)

    demisto.debug(f"The {address_group=} exists, check if there are missing ips.")
    context_show_obj = get_relevant_context(res_show_object[0].get('EntryContext', {}), 'CheckPoint.Objects')
    group_members = checkpoint_get_group_members(
        get_relevant_context(res_group_get[0].get('EntryContext', {}), 'CheckPoint.Group'), 'member-name')
    demisto.debug(f"{group_members=}")
    args['current_members'] = group_members
    demisto.setContext('currentMembers', str(group_members))
    checkpoint_ips = [obj.get('ipv4-address') for obj in context_show_obj if obj.get('ipv4-address')]
    demisto.debug(f"{checkpoint_ips=}")
    missing_ips = [ip for ip in ip_list if ip not in checkpoint_ips]
    if missing_ips:
        demisto.debug(f"There are {missing_ips=}. Adding a host.")
        res_host_add = run_execute_command("checkpoint-host-add",
                                           {'session_id': session_id, 'name': missing_ips, 'ip_address': missing_ips})
        responses.append(res_host_add)
        return checkpoint_publish(args, responses, "checkpoint-show-objects")
    else:
        demisto.debug("There aren't any missing ips.")
    return None


def checkpoint_middle_part(args: dict, responses: list):
    """ Execute the middle part of the checkpoint flow (between the 2 publish processes).
    Args:
        args (dict): the function arguments.
        responses (list): The object that will be used for saving the different execute_command responses.
    Returns:
        A PollResult if a publish process was triggered or None.
    """
    session_id = args['session_id']
    ip_list = args['ip_list']
    address_group = args['address_group']
    current_members = args.get('current_members')
    res_show_object = run_execute_command("checkpoint-show-objects", {'session_id': session_id, 'filter_search': ip_list, 'ip_only': True})
    responses.append(res_show_object)

    context_show_obj = get_relevant_context(res_show_object[0].get('EntryContext', {}), "CheckPoint.Objects")
    objects_names = checkpoint_object_names_to_members(context_show_obj, ip_list)
    if current_members:
        demisto.debug(f"The {current_members=}")
        objects_names.extend(current_members)
        objects_names = list(set(objects_names))
    res_group_update = run_execute_command("checkpoint-group-update", {'session_id': session_id, 'identifier': address_group, 'members': objects_names})
    responses.append(res_group_update)
    if is_error(res_group_update):
        global POLLING
        POLLING = False
        return None
    else:
        return checkpoint_publish(args, responses, "checkpoint-group-get")


def verify_group_added_successfully(args: dict, responses: list) -> bool:
    """ Verify that the group was added successfully.
    Args:
        args (dict): the function arguments.
        responses (list): The object that will be used for saving the different execute_command responses.
    Returns:
        A boolean that represents whether the group was added successfully (True) or not (False).
    """
    session_id = args['session_id']
    address_group = args['address_group']
    res_group_get = run_execute_command('checkpoint-group-get', {'session_id': session_id, 'identifier': address_group})
    responses.append(res_group_get)
    context = get_relevant_context(res_group_get[0].get('EntryContext', {}), 'CheckPoint.Group')
    ip_address = checkpoint_get_group_members(context, 'member-ipv4-address')
    demisto.debug(f"in verify_group_added_successfully {ip_address=}")
    if ip_address:
        return True
    else:
        return False


def checkpoint_rule_name_part(args: dict, responses: list):
    """ Verify if the rule_name was given as an argument (is different from the default value) and adds it.
    Args:
        args (dict): the function arguments.
        responses (list): The object that will be used for saving the different execute_command responses.
    """
    rule_name = args['rule_name']
    session_id = args['session_id']
    address_group = args['address_group']
    if rule_name != 'XSIAM - Block IP':
        command_args = {
            'destination': address_group,
            'layer': 'Network',
            'position': 'top',
            'name': rule_name,
            'session_id': session_id
        }
        res_access_rule_add = run_execute_command("checkpoint-access-rule-add", command_args)
        responses.append(res_access_rule_add)


def checkpoint_logout(args: dict, responses: list) -> list[CommandResults]:
    """ Logout from the current checkpoint session, clean the context, and create the relevant command results.
    Args:
        args (dict): the function arguments.
        responses (list): The object that will be used for saving the different execute_command responses.
    Returns:
        A list of CommandResults.
    """
    session_id = args['session_id']
    ip_list = args['ip_list']
    run_execute_command("checkpoint-logout", {'session_id': session_id})
    demisto.setContext('next_command', '')
    demisto.setContext('publish_job_id', '')
    demisto.setContext('session_id', '')
    demisto.setContext('currentMembers', '[]')
    demisto.setContext('checkpoint_responses', '[]')
    results = prepare_context_and_hr_multiple_executions(responses, args['verbose'], '', ip_list)
    return results


def manage_checkpoint_flow(args: dict) -> PollResult | list[CommandResults]:
    """ Manage the different stages of the checkpoint flow.
    Args:
        args (dict): the function arguments.
    Returns:
        A PollResult if a publish process was triggered or a list of CommandResults in case the flow is finished.
    """
    incident_context = demisto.context()
    publish_job_id = incident_context.get('publish_job_id')
    next_command = incident_context.get('next_command')
    demisto.debug(f"The info about {publish_job_id=} , {next_command=}")
    responses = ast.literal_eval(incident_context.get('checkpoint_responses', '[]'))
    session_id = incident_context.get('session_id', '')
    args['session_id'] = session_id
    global POLLING
    if publish_job_id:
        result = checkpoint_show_task(args, responses)
        if POLLING:
            demisto.setContext("checkpoint_responses", str(responses))
            return result
        else:
            demisto.setContext("publish_job_id", '')
    if not next_command:
        session_id = checkpoint_get_session_id()
        args['session_id'] = session_id
        result = start_checkpoint_flow(args, responses)
        if POLLING:
            demisto.setContext("checkpoint_responses", str(responses))
            return result

    if not next_command or next_command == "checkpoint-show-objects":
        if not args.get('current_members', []):
            demisto.debug(f"{incident_context.get('currentMembers', '[]')=}")
            current_members = incident_context.get('currentMembers', '[]')
            args['current_members'] = ast.literal_eval(current_members) if current_members else []
        result_middle_part = checkpoint_middle_part(args, responses)
        if POLLING:
            demisto.setContext("checkpoint_responses", str(responses))
            return result_middle_part
        elif not result_middle_part: # There was an error, finish the process
            return checkpoint_logout(args, responses)
        else: # nothing to publish
            if verify_group_added_successfully(args, responses):
                demisto.debug("The group was added successfully.")
                checkpoint_rule_name_part(args, responses)
            return checkpoint_logout(args, responses)
    else:  # next_command == "checkpoint-group-get"
        if verify_group_added_successfully(args, responses):
            demisto.debug("The group was added successfully.")
            checkpoint_rule_name_part(args, responses)
        return checkpoint_logout(args, responses)


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

        executed_brands, updated_brands_to_run = update_brands_to_run(brands_to_run)

        results = []
        for brand in updated_brands_to_run:
            demisto.debug(f"BEI: the current brand is {brand}")
            if brand in enabled_brands:
                if brand == "CheckPointFirewall_v2":
                    brand_args = {
                        'ip_list': ip_list_arr,
                        'address_group': address_group,
                        'auto_commit': auto_commit,
                        'verbose': verbose,
                        'brands': brands_to_run,
                        'polling': True,
                        'publish_job_id': args.get('publish_job_id'),
                        'rule_name': rule_name
                    }
                    result = manage_checkpoint_flow(brand_args)
                    if not POLLING:
                        demisto.debug("Not in a polling mode, adding Panorama to the executed_brands.")
                        executed_brands.append(brand)
                    demisto.setContext('executed_brands', str(executed_brands))
                    results.append(result)

                else:
                    return_error(f"The brand {brand} isn't a part of the supported integration for 'block-external-ip'. "
                                 f"The supported integrations are: Palo Alto Networks - Prisma SASE, Panorama, "
                                 f"CheckPointFirewall_v2, FortiGate, F5Silverline, Cisco ASA, Zscaler.")
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
