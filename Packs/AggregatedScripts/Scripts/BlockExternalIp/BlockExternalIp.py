import ast
import json

import demistomock as demisto
from CommonServerPython import *


POLLING = False


""" CLIENT CLASS """


class PrismaSase:
    def __init__(self, args: dict):
        self.args = args
        self.responses: list = []

    def prisma_sase_candidate_config_push(self) -> CommandResults | None:
        """Execute the command prisma-sase-candidate-config-push if needed.
        Returns:
            A tuple of
            1. The response of the execution of the command prisma-sase-candidate-config-push or None if wasn't executed
            2. None or the command result created in case the auto_commit == false.
        """
        auto_commit_message = None
        auto_commit = self.args.get("auto_commit", True)
        if auto_commit:
            command_name = "prisma-sase-candidate-config-push"
            res_auto_commit = run_execute_command(command_name, {"folders": "Remote Networks, Mobile Users, Service Connections"})
            self.responses.append(res_auto_commit)
        else:
            auto_commit_message = CommandResults(
                readable_output=f"Not commiting the changes in Palo Alto Networks - Prisma SASE, "
                f"since {auto_commit=}. Please do so manually for the changes to take affect."
            )
        return auto_commit_message

    def prisma_sase_security_rule_update(self, res_rule_list: list) -> list:
        """Execute the command prisma-sase-security-rule-update if needed.
        Args:
            res_rule_list (list): The response from prisma-sase-security-rule-list.
        Returns:
            The response of prisma-sase-security-rule-update if it was executed, else an empty list.
        """
        rule_name = self.args["rule_name"]
        address_group = self.args["address_group"]
        demisto.debug(f"The rule {rule_name} exists.")
        context_rule_list = get_relevant_context(res_rule_list[0].get("EntryContext", {}), "PrismaSase.SecurityRule")
        rule_id = context_rule_list.get("id", "")  # type: ignore
        rule_destination = context_rule_list.get("destination", [])  # type: ignore
        demisto.debug(f"The info of the existing rule {rule_name=} {rule_id=} {rule_destination=}")
        if address_group not in rule_destination:
            command_name = "prisma-sase-security-rule-update"
            res_rule_update = run_execute_command(
                command_name, {"rule_id": rule_id, "action": "deny", "destination": address_group}
            )
            self.responses.append(res_rule_update)
            return res_rule_update
        demisto.debug(f"The {address_group=} is in {rule_destination=}.")
        return []

    def prisma_sase_block_ip(self) -> list[CommandResults]:
        """Execute the flow of prisma sase.
        Returns:
            A list of CommandResults.
        """
        demisto.debug(f"The arguments to prisma_sase_block_ip are {self.args=}")
        ip = self.args["ip"]
        address_group = self.args["address_group"]
        rule_name = self.args["rule_name"]
        auto_commit_message = None
        verbose = self.args.get("verbose", False)

        command_name_address_object_list = "prisma-sase-address-object-list"
        res_address_object_list = run_execute_command(command_name_address_object_list, {"name": ip})
        self.responses.append(res_address_object_list)
        contents_address_object_list = res_address_object_list[0].get("Contents")

        if isinstance(contents_address_object_list, str) and "does not exist" in contents_address_object_list:
            demisto.debug(f"The {ip} does not exist in the address-object list. Hence we are creating an address object.")
            command_name_address_object_create = "prisma-sase-address-object-create"
            res_add_obj_create = run_execute_command(
                command_name_address_object_create, {"name": ip, "type": "ip_netmask", "address_value": ip}
            )
            self.responses.append(res_add_obj_create)
            if is_error(res_add_obj_create):
                return prepare_context_and_hr_multiple_executions(self.responses, verbose, "", [ip])
            auto_commit_message = self.prisma_sase_candidate_config_push()

        command_name_address_group_list = "prisma-sase-address-group-list"
        res_add_group_list = run_execute_command(command_name_address_group_list, {"name": address_group})
        self.responses.append(res_add_group_list)
        contents_add_group_list = res_add_group_list[0].get("Contents", "")
        if isinstance(contents_add_group_list, str) and "does not exist" in contents_add_group_list:
            demisto.debug(f"The {address_group=} doesn't exist, creating it.")
            command_name_group_create = "prisma-sase-address-group-create"
            res_address_group_create = run_execute_command(
                command_name_group_create, {"name": address_group, "type": "static", "static_addresses": ip}
            )
            self.responses.append(res_address_group_create)
            if is_error(res_address_group_create):
                return prepare_context_and_hr_multiple_executions(self.responses, verbose, "", [ip])

            command_name_security_rule_list = "prisma-sase-security-rule-list"
            res_rule_list = run_execute_command(command_name_security_rule_list, {"name": rule_name})
            contents_rule_list = res_rule_list[0].get("Contents", "")
            self.responses.append(res_rule_list)
            if isinstance(contents_rule_list, str) and "does not exist" in contents_rule_list:
                demisto.debug(f"The security rule doesn't exist. Creating a new rule {rule_name}")
                command_name_rule_create = "prisma-sase-security-rule-create"
                res_rule_create = run_execute_command(
                    command_name_rule_create, {"action": "deny", "name": rule_name, "destination": address_group}
                )
                self.responses.append(res_rule_create)
                if is_error(res_rule_create):
                    return prepare_context_and_hr_multiple_executions(self.responses, verbose, "", [ip])
            else:
                # The security rule exist, check whether to update it.
                res_rule_update = self.prisma_sase_security_rule_update(res_rule_list)
                if res_rule_update and is_error(res_rule_update):
                    return prepare_context_and_hr_multiple_executions(self.responses, verbose, rule_name, [ip])

            auto_commit_message = self.prisma_sase_candidate_config_push()
        else:
            demisto.debug(f"The {address_group=} exists, editing it.")
            context_add_group_list = get_relevant_context(
                res_add_group_list[0].get("EntryContext", {}), "PrismaSase.AddressGroup"
            )
            addresses_group_ip_list = context_add_group_list.get("addresses", [])  # type: ignore
            if ip not in addresses_group_ip_list:
                demisto.debug(
                    f"The {address_group=} exists, but the {ip=} isn't in the {addresses_group_ip_list=} of {address_group=}"
                )
                group_id = context_add_group_list.get("id")  # type: ignore
                command_name_address_group_update = "prisma-sase-address-group-update"
                res_add_group_update = run_execute_command(
                    command_name_address_group_update, {"group_id": group_id, "static_addresses": ip}
                )
                self.responses.append(res_add_group_update)
                if is_error(res_add_group_update):
                    return prepare_context_and_hr_multiple_executions(self.responses, verbose, "", [ip])
                auto_commit_message = self.prisma_sase_candidate_config_push()

        command_results_list = prepare_context_and_hr_multiple_executions(self.responses, verbose, rule_name, [ip])
        if auto_commit_message:
            command_results_list.append(auto_commit_message)
        return command_results_list


class PanOs:
    def __init__(self, args: dict):
        self.args = args
        self.responses: list = []

    def reduce_pan_os_responses(self) -> list[list[dict]]:
        """Returns a list of just the information needed for later usage by the flow.
        Returns:
            A list containing the relevant parts of the command responses.
        """
        demisto.debug("Updating the responses in sanitize_pan_os_responses.")
        sanitize_responses = []
        for res in self.responses:
            current_new_res = []
            for entry in res:
                command_hr = entry.get("HumanReadable")
                message = entry.get("Contents")
                entry_type = entry.get("Type")
                metadata = entry.get("Metadata")
                demisto.debug(f"got {entry_type=} , {command_hr=} , {message=}")
                current_new_res.append(
                    {"HumanReadable": command_hr, "Contents": message, "Type": entry_type, "Metadata": metadata}
                )
            sanitize_responses.append(current_new_res)
        demisto.debug(f"{len(sanitize_responses)=}, {len(self.responses)=}")
        return sanitize_responses

    def check_value_exist_in_context(self, value: str, context: list[dict], key: str) -> bool:
        """Verify if a specific value of a specific key is present in the context.
        Args:
            value (str): The value we want to verify its existence.
            context (list[dict]): The command context.
            key (str): The key to extract from the context.
        Returns:
            A boolean representing the existence of the value (True) or False.
        """
        if isinstance(context, dict):
            context = [context]
        for item in context:
            match = item.get(key, "")
            if match and match == value:
                demisto.debug(f"The {value=} was found")
                return True
            elif match:
                match_split = match.split("or") if isinstance(match, str) else match.get("#text", "").split("or")
                match_split_strip = [m.strip() for m in match_split]
                if value in match_split_strip:
                    demisto.debug(f"The {value=} was found in an 'or' case")
                    return True
        demisto.debug(f"The {value=} isn't in the context with the {key=}")
        return False

    def get_match_by_name(self, name: str, context: list | dict) -> str:
        """Get the relevant "Match" value where the address_group_name == name.
        Args:
            name (str): The name of the relevant address group.
            context (list | dict): The original context ('EntryContext') returned in the execute_command response.
        Returns:
            The match value.
        """
        for item in context:
            address_group_name = item.get("Name", "")
            if address_group_name and address_group_name == name:
                match = item.get("Match", "")
                if isinstance(match, dict):
                    match = match.get("#text")
                demisto.debug(f"The {name=} was found, returning the {match}")
                return match
        return ""  # when creating a dynamic address group a match value is a required, so it won't get here

    def pan_os_check_trigger_push_to_device(self) -> bool:
        """Verify if this is a Panorama instance.
        Returns:
            The PollResult object.
        """
        command_name = "pan-os"
        res_pan_os = run_execute_command(command_name, {"cmd": "<show><system><info></info></system></show>", "type": "op"})
        self.responses.append(res_pan_os)
        context = get_relevant_context(res_pan_os[0].get("EntryContext", {}), "Panorama.Command")
        model = context.get("response", {}).get("result", {}).get("system", {}).get("model", "")  # type: ignore
        return model == "Panorama"

    def pan_os_register_ip_finish(self) -> list[CommandResults]:
        """Execute the final part of the pan-os flow.
        1. Initialize all the context values.
        2. Create the list of Command Results.
        Returns:
            The list of Command Results.
        """
        tag = self.args.get("tag", "")
        ip_list = self.args["ip_list"]
        verbose = self.args.get("verbose", False)
        rule_name = self.args["rule_name"]
        command_name = "pan-os-register-ip-tag"
        demisto.setContext("push_job_id", "")  # delete any previous value if exists
        demisto.setContext("commit_job_id", "")  # delete any previous value if exists
        demisto.setContext("panorama_responses", "")  # delete any previous value if exists
        self.responses.append(run_execute_command(command_name, {"tag": tag, "IPs": ip_list}))
        results = prepare_context_and_hr_multiple_executions(self.responses, verbose, rule_name, ip_list)
        return results

    def pan_os_create_edit_address_group(self, context_list_add_group: list):
        """Checks whether to create a new address group or update an existing one, and does it.
        Args:
            context_list_add_group (list): The context of pan-os-list-address-group.
        """
        address_group = self.args["address_group"]
        tag = self.args.get("tag", "")
        if self.check_value_exist_in_context(address_group, context_list_add_group, "Name"):
            current_match = self.get_match_by_name(address_group, context_list_add_group)
            new_match = f"{current_match} or {tag}" if current_match else tag
            command_name_edit = "pan-os-edit-address-group"
            res_edit_add_group = run_execute_command(
                command_name_edit, {"name": address_group, "type": "dynamic", "match": new_match}
            )
            self.responses.append(res_edit_add_group)
        else:
            command_name_create = "pan-os-create-address-group"
            res_create_add_group = run_execute_command(
                command_name_create, {"name": address_group, "type": "dynamic", "match": tag}
            )
            self.responses.append(res_create_add_group)

    def pan_os_create_edit_rule(self, context_list_rules: list):
        """Checks whether to create a new address group or update an existing one, and does it.
        Args:
            context_list_rules (list): The context of pan-os-list-rules.
        """
        rule_name = self.args["rule_name"]
        address_group = self.args["address_group"]
        log_forwarding_name = self.args.get("log_forwarding_name", "")
        if self.check_value_exist_in_context(rule_name, context_list_rules, "Name"):
            command_name_edit = "pan-os-edit-rule"
            self.responses.append(
                run_execute_command(
                    command_name_edit,
                    {
                        "rulename": rule_name,
                        "element_to_change": "source",
                        "element_value": address_group,
                        "pre_post": "pre-rulebase",
                    },
                )
            )
        else:
            create_rule_args = {"action": "deny", "rulename": rule_name, "pre_post": "pre-rulebase", "source": address_group}
            command_name_create = "pan-os-create-rule"
            if log_forwarding_name:
                create_rule_args["log_forwarding"] = log_forwarding_name
            self.responses.append(run_execute_command(command_name_create, create_rule_args))
        command_name_move = "pan-os-move-rule"
        self.responses.append(
            run_execute_command(command_name_move, {"rulename": rule_name, "where": "top", "pre_post": "pre-rulebase"})
        )

    def start_pan_os_flow(self) -> tuple[list, bool]:
        """Start the flow of pan-os.
        Returns:
            A tuple that can be one of 2 options:
            1. An empty list (the responses were added to self.responses), a boolean represents whether to
                commit the changes to pan-os. This option will take effect if the input tag doesn't exist in pan-os.
            2. A list of command results, and a "False" representing the fact that a commit to pan-os shouldn't be
                performed since the tag already exists.
        """
        tag = self.args["tag"]
        auto_commit = self.args.get("auto_commit", True)

        command_name_list_address_group = "pan-os-list-address-groups"
        res_list_add_group = run_execute_command(command_name_list_address_group, {})
        self.responses.append(res_list_add_group)
        context_list_add_group = get_relevant_context(res_list_add_group[0].get("EntryContext", {}), "Panorama.AddressGroups")
        if not self.check_value_exist_in_context(tag, context_list_add_group, "Match"):  # type: ignore
            # check if the group already exists we should update the tag.
            demisto.debug(f"The {tag=} doesn't exist in the address groups")
            self.pan_os_create_edit_address_group(context_list_add_group)  # type: ignore

            command_name_list_rules = "pan-os-list-rules"
            res_list_rules = run_execute_command(command_name_list_rules, {"pre_post": "pre-rulebase"})
            self.responses.append(res_list_rules)
            context_list_rules = get_relevant_context(res_list_rules[0].get("EntryContext", {}), "Panorama.SecurityRule")
            self.pan_os_create_edit_rule(context_list_rules)  # type: ignore
            return [], auto_commit  # should perform the commit section
        else:
            self.args["rule_name"] = ""
            demisto.debug(f"The {tag=} does exist in the address groups, registering the ip.")
            results = self.pan_os_register_ip_finish()
            return results, False

    def manage_pan_os_flow(self) -> CommandResults | list[CommandResults] | PollResult:  # pragma: no cover
        """Manage the different states of the pan-os flow.
            1. The flow start.
            2. If auto_commit == true, and there were changes to commit, execute pan-os-commit.
            3. There is a commit job id in the arguments, check what is the status of the commit.
            4. The commit was executed successfully, check if this is a panorama instance and push to the devices.
            5. There is a push job id, check what id the status of the push action.
            6. The push action was successful, register the ip & tag and finish the flow.
        Returns:
            The relevant result of the current state. If it is a polling state than a PollResult object will be returned,
            otherwise a Command Result or a list of Command Results, depends on the commands that were executed.
        """
        incident_context = demisto.context()
        demisto.debug(f"The context in the beginning of manage_pan_os_flow {incident_context=}")
        auto_commit = self.args["auto_commit"]
        commit_job_id = self.args.get("commit_job_id") or demisto.get(incident_context, "commit_job_id")
        # state 5
        if push_job_id := demisto.get(incident_context, "push_job_id"):
            demisto.debug(f"Has a {push_job_id=}")
            self.responses = ast.literal_eval(incident_context.get("panorama_responses", ""))
            self.args["push_job_id"] = push_job_id
            res_push_status = pan_os_push_status(self.args, self.responses)
            # state 6
            if not POLLING:
                demisto.debug("Finished polling, finishing the flow")
                return self.pan_os_register_ip_finish()
            else:
                demisto.debug(f"Poll for the push status. Save the responses to the context {len(self.responses)=}")
                responses = self.reduce_pan_os_responses()
                demisto.setContext("panorama_responses", str(responses))
                return res_push_status
        # state 3
        elif commit_job_id:
            demisto.debug(f"Has a {commit_job_id=}")
            self.args["commit_job_id"] = commit_job_id
            self.responses = ast.literal_eval(incident_context.get("panorama_responses", ""))
            poll_commit_status = pan_os_commit_status(self.args, self.responses)
            # state 4
            if not POLLING:
                demisto.debug("Finished polling for the commit status, checking if we need to trigger pan_os_push_to_device")
                if self.pan_os_check_trigger_push_to_device():
                    demisto.debug("Triggering pan_os_push_to_device")
                    poll_push_to_device = pan_os_push_to_device(self.args, self.responses)
                    if not POLLING:
                        demisto.debug("Nothing to push. Finish the process.")
                        return self.pan_os_register_ip_finish()
                    else:
                        demisto.debug(f"Poll for the push status. Save the responses to the context {len(self.responses)=}")
                        responses = self.reduce_pan_os_responses()
                        demisto.setContext("panorama_responses", str(responses))
                        return poll_push_to_device
                else:
                    demisto.debug("Not a Panorama instance, not pushing to device. Continue to register the IP.")
                    return self.pan_os_register_ip_finish()
            else:
                demisto.debug(f"Poll for the commit status. Save the responses to the context {len(self.responses)=}")
                responses = self.reduce_pan_os_responses()
                demisto.setContext("panorama_responses", str(responses))
                return poll_commit_status

        # if we are here, it is the beginning of the flow, state 1
        results, should_commit = self.start_pan_os_flow()
        if should_commit:
            # state 2
            poll_result = pan_os_commit(self.args, self.responses)
            demisto.debug(f"The length of the responses after adding the res_commit is {len(self.responses)}")
            if not POLLING:
                result = self.pan_os_register_ip_finish()
                demisto.debug(f"The result after continue_to_poll is false {result=}")
                return result
            else:
                demisto.debug(f"Poll for the commit status. Save the responses to the context {len(self.responses)=}")
                responses = self.reduce_pan_os_responses()
                demisto.setContext("panorama_responses", str(responses))
                return poll_result
        elif isinstance(results[0], CommandResults):  # already did the final part in start_pan_os_flow
            return results
        else:
            cr_should_commit = CommandResults(
                readable_output=f"Not commiting the changes in Panorama, since "
                f"{auto_commit=}. Please do so manually for the changes "
                f"to take affect."
            )
            result = self.pan_os_register_ip_finish()
            result.append(cr_should_commit)
            return result


""" STANDALONE FUNCTION """


def create_final_human_readable(failure_message: str, used_integration: str, ip_list: list, rule_name: str = "") -> str:
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
    headers = ["IP", "Status", "Result", "Created rule name", "Used integration", "Message"]
    if failure_message:
        d = {
            "Status": "Done",
            "Result": "Failed",
            "Used integration": used_integration,
            "Message": failure_message,
            "IP": ip_list,
        }
        demisto.debug(f"BEI: in failed {d=}")
        return tableToMarkdown(name="Failed to block the IP", t=d, headers=headers, removeNull=True)
    else:
        d = {
            "Status": "Done",
            "Result": "Success",
            "Used integration": used_integration,
            "Created rule name": rule_name,
            "IP": ip_list,
        }
        demisto.debug(f"BEI: in success {d=}")
        return tableToMarkdown(name="The IP was blocked successfully", t=d, headers=headers, removeNull=True)


def create_final_context(failure_message: str, used_integration: str, ip_list_arr: list, rule_name: str = "") -> list[dict]:
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
            context.append(
                {
                    "IP": ip,
                    "Message": failure_message,
                    "Result": "Failed",
                    "Brand": used_integration,
                }
            )
        else:
            demisto.debug("BEI: in a success case, creating context")
            context.append(
                {
                    "IP": ip,
                    "Message": "External IP was blocked successfully",
                    "Result": "Success",
                    "Brand": used_integration,
                }
            )
    return context


def prepare_context_and_hr_multiple_executions(
    responses: list[list[dict]], verbose: bool, rule_name: str, ip_list_arr: list[str]
) -> list[CommandResults]:
    """Creates the relevant context and human readable in case of multiple command executions.
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
    used_integration = responses[0][0].get("Metadata", {}).get("brand")  # all executions are for the same brand.
    demisto.debug(f"In prepare_context_and_hr_multiple_executions, {used_integration=}")

    for res in responses:
        for entry in res:
            command_hr = entry.get("HumanReadable")
            message = f"{used_integration}: {entry.get('Contents', '')}"
            demisto.debug(f"In prepare_context_and_hr_multiple_executions {command_hr=} {message=}")
            if command_hr and command_hr != str(None):
                demisto.debug(f"BEI: The command has {verbose=}, adding {command_hr=}")
                results.append(CommandResults(readable_output=f"{used_integration}:\n{command_hr}"))
            elif is_error(entry):
                demisto.debug(f"A failure was found {message=}")
                failed_messages.append(message)
            elif message and isinstance(message, str):
                results.append(CommandResults(readable_output=message))
    combined_failure_message = ", ".join(failed_messages)
    final_hr = create_final_human_readable(combined_failure_message, used_integration, ip_list_arr, rule_name)
    final_context = create_final_context(combined_failure_message, used_integration, ip_list_arr, rule_name)
    final_cr = CommandResults(
        readable_output=final_hr, outputs_prefix="BlockExternalIPResults", outputs=final_context, raw_response=final_context
    )
    if verbose:
        results.append(final_cr)
    else:
        results = [final_cr]
    return results


def get_relevant_context(original_context: dict[str, Any], key: str) -> dict | list:
    """Get the relevant context object from the execute_command response.
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
                return original_context.get(k, {})
        return {}


def update_brands_to_run(brands_to_run: list) -> tuple[list, set]:
    """Delete the brands that were executed already from the list of brands_to_run.
        Would be used in a case that at least one brand finished its execution before the polling of the other brand is over.
    Args:
        brands_to_run (list): The list of brands that should be executed.
    Returns:
        The list of brands that were executed in previous runs and a set of the brands that should be executed in the current run.
    """
    if "Panorama" not in brands_to_run:
        return [], set(brands_to_run)
    incident_context = demisto.context()
    executed_brands = (incident_context.get("executed_brands", "[]")).replace("'", '"')
    try:
        executed_brands = json.loads(executed_brands)
    except json.JSONDecodeError:
        demisto.debug("There was a failure in the json.loads for the executed_brands.")
        executed_brands = []
    updated_brands_to_run = {b for b in brands_to_run if b not in executed_brands}
    demisto.debug(f"Removed {executed_brands=} from {brands_to_run=}")
    return executed_brands, updated_brands_to_run


""" COMMAND FUNCTION """


@polling_function(
    name="block-external-ip",
    interval=60,
    timeout=1200,
)
def pan_os_commit_status(args: dict, responses: list) -> PollResult:
    """Check the status of the commit process in pan-os.
    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the previous command.
    Returns:
        The PollResult object.
    """
    commit_job_id = args["commit_job_id"]
    command_name = "pan-os-commit-status"
    res_commit_status = run_execute_command(command_name, {"job_id": commit_job_id})
    responses.append(res_commit_status)
    result_commit_status = res_commit_status[0].get("Contents", {}).get("response", {}).get("result", {}).get("job", {})
    job_result = result_commit_status.get("result")
    demisto.debug(f"The result is {job_result=}")
    commit_output = {
        "JobID": commit_job_id,
        "Status": "Success" if job_result == "OK" else "Failure",
    }
    continue_to_poll = result_commit_status.get("status") != "FIN"
    global POLLING
    POLLING = continue_to_poll
    demisto.debug(f"after pan-os-commit-status {continue_to_poll=} {commit_job_id=}")
    return PollResult(
        response=CommandResults(
            outputs=commit_output,
            outputs_key_field="JobID",
            readable_output=tableToMarkdown("Commit Status:", commit_output, removeNull=True),
        ),
        args_for_next_run=args,
        continue_to_poll=continue_to_poll,  # continue polling if job isn't done
    )


@polling_function(
    name="block-external-ip",
    interval=60,
    timeout=1200,
)
def pan_os_push_to_device(args: dict, responses: list) -> PollResult:
    """Execute pan-os-push-to-device-group.
    Args:
        responses (list): The responses of the previous command.
    Returns:
        The PollResult object.
    """
    command_name = "pan-os-push-to-device-group"
    res_push_to_device = run_execute_command(command_name, {"polling": True})
    responses.append(res_push_to_device)
    polling_args = res_push_to_device[0].get("Metadata", {}).get("pollingArgs", {})
    job_id = polling_args.get("push_job_id")
    device_group = polling_args.get("device-group")
    demisto.debug(f"The polling args are {job_id=} {device_group=}")
    if job_id:
        context_output = {"DeviceGroup": device_group, "JobID": job_id, "Status": "Pending"}
        continue_to_poll = True
        push_cr = CommandResults(
            outputs_key_field="JobID",
            outputs=context_output,
            readable_output=tableToMarkdown("Push to Device Group:", context_output, removeNull=True),
        )
        demisto.setContext("push_job_id", job_id)
    else:
        push_cr = CommandResults(readable_output=res_push_to_device[0].get("Contents") or "There are no changes to push.")
        continue_to_poll = False
    global POLLING
    POLLING = continue_to_poll

    return PollResult(
        response=push_cr,
        continue_to_poll=continue_to_poll,
        partial_result=CommandResults(readable_output=f"Waiting for Job-ID {job_id} to finish pushing the changes..."),
    )


@polling_function(
    name="block-external-ip",
    interval=60,
    timeout=1200,
)
def pan_os_push_status(args: dict, responses: list):
    """Check the status of the push operation in pan-os.
    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the previous command.
    Returns:
        The PollResult object.
    """
    push_job_id = args["push_job_id"]
    command_name = "pan-os-push-status"
    res_push_device_status = run_execute_command(command_name, {"job_id": push_job_id})
    responses.append(res_push_device_status)
    push_status = (
        res_push_device_status[0].get("Contents", {}).get("response", {}).get("result", {}).get("job", {}).get("status", "")
    )

    continue_to_poll = bool(push_status and push_status != "FIN")
    demisto.debug(f"{push_status=}")
    demisto.debug(f"{continue_to_poll=}")
    context_output = {
        "Status": push_status,
        "JobID": push_job_id,
    }
    push_cr = CommandResults(
        outputs_key_field="JobID",
        outputs=context_output,  # update it according to the output from the execution.
        readable_output=tableToMarkdown("Push to Device Group:", context_output, ["JobID", "Status"], removeNull=True),
    )
    global POLLING
    POLLING = continue_to_poll
    return PollResult(
        response=push_cr,
        continue_to_poll=continue_to_poll,
        partial_result=CommandResults(readable_output=f"Waiting for Job-ID {push_job_id} to finish pushing the changes..."),
    )


@polling_function(
    name="block-external-ip",
    interval=60,
    timeout=1200,
)
def pan_os_commit(args: dict, responses: list) -> PollResult:
    """Execute pan-os-commit.
    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the command executions so far.
    Returns:
        A PollResult object.
    """
    command_name = "pan-os-commit"
    res_commit = run_execute_command(command_name, {"polling": True})
    polling_args = res_commit[0].get("Metadata", {}).get("pollingArgs", {})
    job_id = polling_args.get("commit_job_id")
    if job_id:
        context_output = {"JobID": job_id, "Status": "Pending"}
        continue_to_poll = True
        commit_output = CommandResults(
            outputs=context_output, readable_output=tableToMarkdown("Commit Status:", context_output, removeNull=True)
        )
        demisto.debug(f"Initiated a commit execution {continue_to_poll=} {job_id=}")
        demisto.setContext("commit_job_id", job_id)

    else:  # nothing to commit in pan-os, no reason to poll.
        commit_output = res_commit[0].get("Contents") or "There are no changes to commit."  # type: ignore
        demisto.debug(f"No job_id, {commit_output}")
        continue_to_poll = False
    global POLLING
    POLLING = continue_to_poll

    args_for_next_run = {
        "commit_job_id": job_id,
        "interval_in_seconds": arg_to_number(args.get("interval_in_seconds", 60)),
        "timeout": arg_to_number(args.get("timeout", 1200)),
        "polling": True,
    }
    demisto.debug(f"The initial {args_for_next_run=}")
    args_for_next_run = args | args_for_next_run
    demisto.debug(f"After adding the original args {args_for_next_run=}")
    responses.append(res_commit)
    poll_result = PollResult(
        response=commit_output,
        continue_to_poll=continue_to_poll,
        args_for_next_run=args_for_next_run,
        partial_result=CommandResults(readable_output=f"Waiting for commit job ID {job_id} to finish..."),
    )
    return poll_result


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
        brands_to_run = argToList(
            args.get(
                "brands",
                "Palo Alto Networks - Prisma SASE,Panorama,FortiGate,F5Silverline,Cisco ASA,Zscaler",
            )
        )
        modules = demisto.getModules()
        enabled_brands = {module.get("brand") for module in modules.values() if module.get("state") == "active"}
        demisto.debug(f"BEI: the enabled modules are: {enabled_brands=}")
        demisto.debug(f"BEI: {brands_to_run=}")

        executed_brands, updated_brands_to_run = update_brands_to_run(brands_to_run)

        results = []
        for brand in updated_brands_to_run:
            demisto.debug(f"BEI: the current brand is {brand}")
            if brand in enabled_brands:
                if brand == "Zscaler":
                    brand_args = {"ip": ip_list_arg}
                    command_name = "zscaler-blacklist-ip"
                    result = run_execute_command(command_name, brand_args)
                    results.append(prepare_context_and_hr_multiple_executions([result], verbose, "", ip_list_arr))
                    executed_brands.append(brand)

                elif brand == "Cisco ASA":
                    command_name = "cisco-asa-create-rule"
                    for ip in ip_list_arr:
                        brand_args = {"destination": ip, "interface_type": "Global", "source": "0.0.0.0", "permit": False}
                        result = run_execute_command(command_name, brand_args)
                        results.append(prepare_context_and_hr_multiple_executions([result], verbose, "", [ip]))
                    executed_brands.append(brand)

                elif brand == "F5Silverline":
                    command_name = "f5-silverline-ip-object-add"
                    for ip in ip_list_arr:
                        brand_args = {"list_type": "denylist", "cidr_range": ip, "tags": tag}
                        result = run_execute_command(command_name, brand_args)
                        results.append(prepare_context_and_hr_multiple_executions([result], verbose, "", [ip]))
                    executed_brands.append(brand)

                elif brand == "FortiGate":
                    command_name = "fortigate-ban-ip"
                    brand_args = {"ip_address": ip_list_arg}
                    result = run_execute_command(command_name, brand_args)
                    results.append(prepare_context_and_hr_multiple_executions([result], verbose, "", ip_list_arr))
                    executed_brands.append(brand)

                elif brand == "Palo Alto Networks - Prisma SASE":
                    for ip in ip_list_arr:
                        brand_args = {
                            "ip": ip,
                            "address_group": address_group,
                            "verbose": verbose,
                            "rule_name": rule_name,
                            "auto_commit": auto_commit,
                        }
                        prisma_sase = PrismaSase(brand_args)
                        results.append(prisma_sase.prisma_sase_block_ip())
                    executed_brands.append(brand)

                elif brand == "Panorama":
                    brand_args = {
                        "ip_list": ip_list_arr,
                        "rule_name": rule_name,
                        "log_forwarding_name": log_forwarding_name,
                        "address_group": address_group,
                        "tag": tag,
                        "auto_commit": auto_commit,
                        "verbose": verbose,
                        "brands": brands_to_run,
                        "commit_job_id": args.get("commit_job_id"),
                        "polling": True,
                    }
                    pan_os = PanOs(brand_args)
                    result_pan_os = pan_os.manage_pan_os_flow()
                    if not POLLING:
                        demisto.debug("Not in a polling mode, adding Panorama to the executed_brands.")
                        executed_brands.append(brand)
                    demisto.debug(f"Before returning {result_pan_os=} in panorama")
                    results.append(result_pan_os)  # type: ignore

                else:
                    return_error(
                        f"The brand {brand} isn't a part of the supported integration for 'block-external-ip'. "
                        f"The supported integrations are: Palo Alto Networks - Prisma SASE, Panorama, "
                        f"FortiGate, F5Silverline, Cisco ASA, Zscaler."
                    )
            else:
                results.append(CommandResults(readable_output=f"The brand {brand} isn't enabled."))  # type: ignore
                executed_brands.append(brand)
        if POLLING:
            demisto.debug(f"Updating the executed_brands {executed_brands=}")
            demisto.setContext("executed_brands", str(executed_brands))
        else:
            if "Panorama" in brands_to_run:
                demisto.debug("Not in a polling mode, initializing the executed_brands")
                demisto.setContext("executed_brands", "")
        demisto.debug(f"returning at the end of main(), {results=}")
        return_results(results)

    except Exception as ex:
        return_error(f"Failed to execute block-external-ip. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
