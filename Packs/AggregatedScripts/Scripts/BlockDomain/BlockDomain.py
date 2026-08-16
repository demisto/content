import ast
import hashlib
import re
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

""" CONSTANTS """

SUPPORTED_BRANDS = ["Panorama"]  # v1 supports Panorama only; extended in the multi-brand follow-up.

OBJECT_NAME_PREFIX = "Cortex-"
# PAN-OS object names are limited to 63 characters. Reserve room for the prefix and a hash suffix on overflow.
MAX_OBJECT_NAME_LENGTH = 63
HASH_SUFFIX_LENGTH = 8
# Characters that are not allowed in a PAN-OS object name are normalised to a hyphen.
OBJECT_NAME_SANITIZE_REGEX = re.compile(r"[^A-Za-z0-9.\-]")

PRE_POST = "pre-rulebase"  # Q2: hard-coded for v1 (may become an argument later).

# A permissive FQDN matcher: labels of alphanumerics/hyphens separated by dots, at least one dot.
FQDN_REGEX = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

# Status values.
STATUS_DONE = "Done"
STATUS_PENDING = "Pending"
STATUS_SKIPPED = "Skipped"
STATUS_FAILED = "Failed"

# Result values.
RESULT_SUCCESS = "Success"
RESULT_FAILED = "Failed"

# Action values (ordered by significance for aggregation).
ACTION_CREATED = "Created"
ACTION_MODIFIED = "Modified"
ACTION_UNCHANGED = "Unchanged"
ACTION_SIGNIFICANCE = {ACTION_UNCHANGED: 0, ACTION_MODIFIED: 1, ACTION_CREATED: 2}

# Controls the polling loop, mirroring the BlockExternalIp pattern. It starts False and is only
# switched on by a polling function when a job is actually in flight.
POLLING = False

""" INPUT-VALIDATION / NAMING HELPERS """


def is_wildcard(domain: str) -> bool:
    """Check whether a domain is a wildcard (unsupported).

    Args:
        domain (str): The domain to check.
    Returns:
        True if the domain contains an asterisk, False otherwise.
    """
    return "*" in domain


def is_valid_fqdn(domain: str) -> bool:
    """Check whether a value is a valid, non-wildcard FQDN.

    Args:
        domain (str): The domain to validate.
    Returns:
        True if the value looks like a valid FQDN, False otherwise.
    """
    return bool(FQDN_REGEX.match(domain))


def derive_object_name(domain: str) -> str:
    """Derive a deterministic PAN-OS address-object name from a domain.

    The name is a pure function of the domain so re-runs are idempotent. On overflow of the PAN-OS
    max object-name length, the sanitised body is truncated and a short deterministic hash suffix is
    appended to keep the name unique.

    Args:
        domain (str): The domain to derive the object name from.
    Returns:
        The derived object name (for example, 'Cortex-evil.example.com').
    """
    sanitised = OBJECT_NAME_SANITIZE_REGEX.sub("-", domain).strip("-")
    candidate = f"{OBJECT_NAME_PREFIX}{sanitised}"
    if len(candidate) <= MAX_OBJECT_NAME_LENGTH:
        return candidate

    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:HASH_SUFFIX_LENGTH]
    keep = MAX_OBJECT_NAME_LENGTH - len(OBJECT_NAME_PREFIX) - 1 - HASH_SUFFIX_LENGTH  # 1 for the '-' separator.
    truncated = sanitised[:keep].strip("-")
    return f"{OBJECT_NAME_PREFIX}{truncated}-{digest}"


def most_significant_action(actions: list) -> str:
    """Return the most significant action from a list.

    Args:
        actions (list): A list of action strings.
    Returns:
        The most significant action (Created > Modified > Unchanged).
    """
    if not actions:
        return ACTION_UNCHANGED
    return max(actions, key=lambda action: ACTION_SIGNIFICANCE.get(action, 0))


def build_result_row(
    domain: str,
    brand: str,
    status: str,
    result: str,
    action: str,
    message: str,
    instance: str = "",
    rule_name: str = "",
) -> dict:
    """Assemble a single BlockDomainResults row.

    Args:
        domain (str): The processed domain.
        brand (str): The brand used.
        status (str): The lifecycle status.
        result (str): Success or Failed.
        action (str): Created, Modified, or Unchanged.
        message (str): A human-readable message.
        instance (str): The integration instance.
        rule_name (str): The rule name used (empty if none).
    Returns:
        A dict representing a single result row.
    """
    return {
        "Domain": domain,
        "Brand": brand,
        "Instance": instance,
        "Status": status,
        "Result": result,
        "Action": action,
        "RuleName": rule_name,
        "Message": message,
    }


def validate_domains(domain_list: list) -> tuple[list, list]:
    """Split the input into valid domains and failed-validation rows.

    Wildcard and invalid entries fail validation and never reach a vendor; they produce a per-row
    Failed result while the rest of the list continues.

    Args:
        domain_list (list): The list of domains to validate.
    Returns:
        A tuple of (valid_domains, failed_rows).
    """
    valid_domains: list = []
    failed_rows: list = []
    for domain in domain_list:
        if is_wildcard(domain):
            failed_rows.append(
                build_result_row(
                    domain=domain,
                    brand="",
                    status=STATUS_FAILED,
                    result=RESULT_FAILED,
                    action=ACTION_UNCHANGED,
                    message=f"Wildcard domain '{domain}' is not supported by this script; skipped.",
                )
            )
        elif not is_valid_fqdn(domain):
            failed_rows.append(
                build_result_row(
                    domain=domain,
                    brand="",
                    status=STATUS_FAILED,
                    result=RESULT_FAILED,
                    action=ACTION_UNCHANGED,
                    message=f"Invalid FQDN '{domain}' - skipped.",
                )
            )
        else:
            valid_domains.append(domain)
    return valid_domains, failed_rows


def get_enabled_brands() -> set:
    """Return the set of brands that have at least one active instance.

    Returns:
        A set of enabled brand names.
    """
    modules = demisto.getModules()
    enabled_brands = {module.get("brand") for module in modules.values() if module.get("state") == "active"}
    demisto.debug(f"BlockDomain: the enabled modules are: {enabled_brands=}")
    return enabled_brands


""" EXECUTE-COMMAND / CONTEXT HELPERS """


def run_execute_command(command_name: str, args: dict[str, Any]) -> list[dict]:
    """Execute a command and return its raw entries.

    Args:
        command_name (str): The command to execute.
        args (dict): The command arguments.
    Returns:
        The raw list of command entries.
    """
    demisto.debug(f"BlockDomain: Executing command: {command_name} with {args=}")
    res = demisto.executeCommand(command_name, args)
    demisto.debug(f"BlockDomain: The response of {command_name} is {res}")
    return res


def get_relevant_context(original_context: dict[str, Any], key: str) -> dict | list:
    """Get the relevant context object from the execute_command response, tolerating suffixed keys.

    Args:
        original_context (dict): The 'EntryContext' from the command response.
        key (str): The key to extract.
    Returns:
        A dict or list that is the relevant command context.
    """
    if not original_context:
        return {}
    if relevant_context := original_context.get(key, {}):
        return relevant_context
    for k in original_context:
        if k.startswith(key):
            return original_context.get(k, {})
    return {}


""" PAN-OS FLOW """


class DynamicGroupError(Exception):
    """Raised when the target address-group exists and is dynamic (customer-managed)."""


class PanOs:
    """Implements the PAN-OS static-address-group domain-blocking flow.

    The address-group and the deny rule are singletons (their names are constant), so they are
    ensured once per run. Each valid domain then gets an FQDN address-object that is added to the
    group. Commit + optional push happen once after all domains are processed. Every write records
    its effect (Created / Modified / Unchanged) so the aggregated per-domain row reflects the most
    significant change.
    """

    def __init__(self, args: dict):
        """Initialize the PanOs flow.

        Args:
            args (dict): The flow arguments (domains, rule_name, address_group, tag, etc.).
        """
        self.args = args
        self.brand = "Panorama"
        self.rule_name = args["rule_name"]
        self.address_group = args["address_group"]
        self.tag = args.get("tag", "")
        self.log_forwarding_name = args.get("log_forwarding_name", "")
        self.domains: list = args.get("domains", [])
        self.responses: list = []

    # ---- execution helper ----------------------------------------------

    def execute_or_raise(self, command_name: str, command_args: dict, error_prefix: str) -> list[dict]:
        """Run a command, record its response, and raise on error.

        Args:
            command_name (str): The command to execute.
            command_args (dict): The command arguments.
            error_prefix (str): A prefix for the raised error message.
        Returns:
            The raw command entries.
        """
        res = run_execute_command(command_name, command_args)
        self.responses.append(res)
        if is_error(res):
            raise DemistoException(f"{error_prefix}: {get_error(res)}")
        return res

    # ---- context probes -------------------------------------------------

    def address_object_exists(self, object_name: str) -> bool:
        """Check whether an address-object already exists.

        Args:
            object_name (str): The address-object name to probe.
        Returns:
            True if the object exists, False otherwise.
        """
        res = run_execute_command("pan-os-get-address", {"name": object_name})
        if is_error(res):
            # get-address raises when the object is absent; treat that as 'does not exist'.
            demisto.debug(f"BlockDomain: address '{object_name}' not found ({get_error(res)}).")
            return False
        self.responses.append(res)
        context = get_relevant_context(res[0].get("EntryContext", {}), "Panorama.Addresses")
        items = context if isinstance(context, list) else [context]
        return any(item.get("Name") == object_name for item in items)

    def get_address_group(self) -> dict | None:
        """Return the target address-group context dict, or None if it does not exist.

        Returns:
            The address-group context dict, or None.
        """
        res = self.execute_or_raise("pan-os-list-address-groups", {}, "Failed to list address groups")
        context = get_relevant_context(res[0].get("EntryContext", {}), "Panorama.AddressGroups")
        items = context if isinstance(context, list) else [context]
        for item in items:
            if item.get("Name") == self.address_group:
                return item
        return None

    def rule_destinations(self) -> tuple[bool, list]:
        """Return whether the rule exists and its current destination list.

        Returns:
            A tuple of (rule_exists, destination_list).
        """
        res = self.execute_or_raise("pan-os-list-rules", {"pre_post": PRE_POST}, "Failed to list rules")
        context = get_relevant_context(res[0].get("EntryContext", {}), "Panorama.SecurityRule")
        items = context if isinstance(context, list) else [context]
        for item in items:
            if item.get("Name") == self.rule_name:
                destination = item.get("Destination")
                destination_list = destination if isinstance(destination, list) else [destination] if destination else []
                return True, destination_list
        return False, []

    # ---- single-run writes (group + rule are singletons) ----------------

    def ensure_group(self, group_context: dict | None) -> None:
        """Ensure the static address-group exists, aborting if it is dynamic.

        Args:
            group_context (dict | None): The existing group context, or None if missing.
        """
        if group_context is None:
            create_args: dict = {"name": self.address_group, "type": "static"}
            if self.tag:
                create_args["tags"] = self.tag
            self.execute_or_raise(
                "pan-os-create-address-group", create_args, f"Failed to create address-group '{self.address_group}'"
            )
            return
        group_type = (group_context.get("Type") or "").lower()
        if group_type == "dynamic":
            raise DynamicGroupError(
                f"Address-group '{self.address_group}' already exists as dynamic; "
                f"will not modify a customer-managed dynamic group."
            )

    def ensure_rule(self, rule_present: bool, rule_destinations: list) -> None:
        """Ensure the deny rule exists, points at the group, and sits at the top.

        Args:
            rule_present (bool): Whether the rule already exists.
            rule_destinations (list): The rule's current destination list.
        """
        if not rule_present:
            create_rule_args: dict = {
                "rulename": self.rule_name,
                "action": "deny",
                "source": "any",
                "destination": self.address_group,
                "application": "any",
                "service": "any",
                "pre_post": PRE_POST,
                "where": "top",
            }
            if self.tag:
                create_rule_args["tags"] = self.tag
            if self.log_forwarding_name:
                create_rule_args["log_forwarding"] = self.log_forwarding_name
            self.execute_or_raise("pan-os-create-rule", create_rule_args, f"Failed to create rule '{self.rule_name}'")
        elif self.address_group not in rule_destinations:
            # The rule exists but does not yet reference our group - add it without replacing existing destinations.
            self.execute_or_raise(
                "pan-os-edit-rule",
                {
                    "rulename": self.rule_name,
                    "element_to_change": "destination",
                    "element_value": self.address_group,
                    "behaviour": "add",
                    "pre_post": PRE_POST,
                },
                f"Failed to add group to rule '{self.rule_name}'",
            )
        # Always ensure the rule sits at the top of the rulebase.
        self.execute_or_raise(
            "pan-os-move-rule",
            {"rulename": self.rule_name, "where": "top", "pre_post": PRE_POST},
            f"Failed to move rule '{self.rule_name}' to top",
        )

    def ensure_domain(self, domain: str, current_members: list) -> tuple[str, str]:
        """Ensure a single domain's address-object exists and belongs to the group.

        Args:
            domain (str): The domain to block.
            current_members (list): The group's current member names.
        Returns:
            A tuple of (action, message) describing the effect for this domain.
        """
        object_name = derive_object_name(domain)
        actions: list = []
        messages: list = []

        if self.address_object_exists(object_name):
            actions.append(ACTION_UNCHANGED)
            messages.append(f"Address-object '{object_name}' already exists.")
        else:
            create_args: dict = {"name": object_name, "fqdn": domain}
            if self.tag:
                create_args["tag"] = self.tag
            self.execute_or_raise("pan-os-create-address", create_args, f"Failed to create address-object '{object_name}'")
            actions.append(ACTION_CREATED)
            messages.append(f"Address-object '{object_name}' created for '{domain}'.")

        if object_name in current_members:
            actions.append(ACTION_UNCHANGED)
            messages.append(f"Already a member of '{self.address_group}'.")
        else:
            self.execute_or_raise(
                "pan-os-edit-address-group",
                {"name": self.address_group, "type": "static", "element_to_add": object_name},
                f"Failed to add object to address-group '{self.address_group}'",
            )
            current_members.append(object_name)
            actions.append(ACTION_MODIFIED)
            messages.append(f"Added to '{self.address_group}'.")

        return most_significant_action(actions), " ".join(messages)

    # ---- orchestration --------------------------------------------------

    def process_domains(self) -> list:
        """Ensure the group and rule once, then loop over domains adding each object.

        Returns:
            The list of BlockDomainResults rows for the processed domains.
        """
        rows: list = []
        try:
            group_context = self.get_address_group()
            self.ensure_group(group_context)
            current_members = []
            if group_context is not None:
                members = group_context.get("Addresses")
                current_members = list(members) if isinstance(members, list) else [members] if members else []

            rule_present, rule_destinations = self.rule_destinations()
            self.ensure_rule(rule_present, rule_destinations)

            for domain in self.domains:
                action, message = self.ensure_domain(domain, current_members)
                rows.append(
                    build_result_row(
                        domain=domain,
                        brand=self.brand,
                        status=STATUS_DONE,
                        result=RESULT_SUCCESS,
                        action=action,
                        rule_name=self.rule_name,
                        message=f"{message} Rule '{self.rule_name}' enforced at top.",
                    )
                )
        except DynamicGroupError as dyn_err:
            # Abort the whole brand for this run; other brands (future) would continue.
            for domain in self.domains:
                rows.append(
                    build_result_row(
                        domain=domain,
                        brand=self.brand,
                        status=STATUS_SKIPPED,
                        result=RESULT_SUCCESS,
                        action=ACTION_UNCHANGED,
                        rule_name="",
                        message=str(dyn_err),
                    )
                )
        except Exception as ex:
            for domain in self.domains:
                rows.append(
                    build_result_row(
                        domain=domain,
                        brand=self.brand,
                        status=STATUS_FAILED,
                        result=RESULT_FAILED,
                        action=ACTION_UNCHANGED,
                        rule_name=self.rule_name,
                        message=f"Failed to block '{domain}' on Panorama: {ex!s}",
                    )
                )
        return rows

    def pan_os_is_panorama(self) -> bool:
        """Check whether the instance is a Panorama (vs a single firewall).

        Returns:
            True if the instance model is 'Panorama', False otherwise.
        """
        res = run_execute_command("pan-os", {"cmd": "<show><system><info></info></system></show>", "type": "op"})
        self.responses.append(res)
        context = get_relevant_context(res[0].get("EntryContext", {}), "Panorama.Command")
        model = context.get("response", {}).get("result", {}).get("system", {}).get("model", "")  # type: ignore
        return model == "Panorama"

    def reduce_responses(self) -> list:
        """Reduce the accumulated responses to the parts needed across polling cycles.

        Returns:
            A list of reduced response entries suitable for serialization to context.
        """
        reduced = []
        for res in self.responses:
            reduced.append(
                [
                    {
                        "HumanReadable": entry.get("HumanReadable"),
                        "Contents": entry.get("Contents"),
                        "Type": entry.get("Type"),
                        "Metadata": entry.get("Metadata"),
                    }
                    for entry in res
                ]
            )
        return reduced

    def restore_responses(self) -> None:
        """Restore the accumulated responses that were serialized to context in a previous cycle."""
        self.responses = ast.literal_eval(demisto.context().get("panorama_responses", "[]") or "[]")

    def save_responses(self) -> None:
        """Serialize the accumulated responses to context for the next polling cycle."""
        demisto.setContext("panorama_responses", str(self.reduce_responses()))

    def manage_pan_os_flow(self) -> Any:  # pragma: no cover
        """Dispatch the PAN-OS flow to the correct state.

        On re-entry (a push or commit job is in flight) the flow jumps straight to the relevant
        status poller. Otherwise it starts the object/group/rule flow.

        Returns:
            A PollResult when a job is in flight, or the list of result rows when finished.
        """
        incident_context = demisto.context()
        commit_job_id = self.args.get("commit_job_id") or demisto.get(incident_context, "commit_job_id")
        push_job_id = demisto.get(incident_context, "push_job_id")

        if push_job_id:
            return self.handle_push_in_flight(push_job_id)
        if commit_job_id:
            return self.handle_commit_in_flight(commit_job_id)
        return self.start_flow()

    def handle_push_in_flight(self, push_job_id: str) -> Any:  # pragma: no cover
        """Poll the status of an in-flight push-to-device-group job.

        Args:
            push_job_id (str): The push job ID to poll.
        Returns:
            A PollResult while the push is running, or the final result rows when it finishes.
        """
        self.restore_responses()
        self.args["push_job_id"] = push_job_id
        res_push_status = pan_os_push_status(self.args, self.responses)
        if not POLLING:
            return self.finish()
        self.save_responses()
        return res_push_status

    def handle_commit_in_flight(self, commit_job_id: str) -> Any:  # pragma: no cover
        """Poll the status of an in-flight commit job, then start the push if needed.

        Args:
            commit_job_id (str): The commit job ID to poll.
        Returns:
            A PollResult while commit/push is running, or the final result rows when finished.
        """
        self.args["commit_job_id"] = commit_job_id
        self.restore_responses()
        poll_commit_status = pan_os_commit_status(self.args, self.responses)
        if POLLING:
            self.save_responses()
            return poll_commit_status
        # Commit finished - push to the device group if this is a Panorama instance.
        if self.pan_os_is_panorama():
            poll_push = pan_os_push_to_device(self.args, self.responses)
            if not POLLING:
                return self.finish()
            self.save_responses()
            return poll_push
        return self.finish()

    def start_flow(self) -> Any:  # pragma: no cover
        """Run the object/group/rule flow, then start the commit if there were changes.

        Returns:
            A PollResult while the commit is running, or the final result rows when finished.
        """
        rows = self.process_domains()
        demisto.setContext("block_domain_rows", str(rows))
        made_changes = any(row["Status"] == STATUS_DONE for row in rows)
        auto_commit = argToBoolean(self.args.get("auto_commit", True))
        if made_changes and auto_commit:
            poll_commit = pan_os_commit(self.args, self.responses)
            if not POLLING:
                return self.finish()
            self.save_responses()
            return poll_commit
        return rows

    def finish(self) -> list:  # pragma: no cover
        """Clean up polling context and return the final result rows.

        Returns:
            The list of BlockDomainResults rows accumulated for the run.
        """
        rows_raw = demisto.context().get("block_domain_rows", "[]")
        demisto.setContext("commit_job_id", "")
        demisto.setContext("push_job_id", "")
        demisto.setContext("panorama_responses", "")
        demisto.setContext("block_domain_rows", "")
        try:
            return ast.literal_eval(rows_raw) if rows_raw else []
        except (ValueError, SyntaxError):
            return []


""" POLLING FUNCTIONS (commit / push) """


@polling_function(name="block-domain", interval=60, timeout=1200)
def pan_os_commit(args: dict, responses: list) -> PollResult:
    """Execute pan-os-commit.

    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the commands executed so far.
    Returns:
        The PollResult object.
    """
    res_commit = run_execute_command("pan-os-commit", {"polling": True})
    polling_args = res_commit[0].get("Metadata", {}).get("pollingArgs", {})
    job_id = polling_args.get("commit_job_id")
    if job_id:
        context_output = {"JobID": job_id, "Status": "Pending"}
        continue_to_poll = True
        commit_output: Any = CommandResults(
            outputs=context_output, readable_output=tableToMarkdown("Commit Status:", context_output, removeNull=True)
        )
        demisto.setContext("commit_job_id", job_id)
    else:
        commit_output = res_commit[0].get("Contents") or "There are no changes to commit."
        continue_to_poll = False
    global POLLING
    POLLING = continue_to_poll

    args_for_next_run = args | {
        "commit_job_id": job_id,
        "interval_in_seconds": arg_to_number(args.get("interval_in_seconds", 60)),
        "timeout": arg_to_number(args.get("timeout", 1200)),
        "polling": True,
    }
    responses.append(res_commit)
    return PollResult(
        response=commit_output,
        continue_to_poll=continue_to_poll,
        args_for_next_run=args_for_next_run,
        partial_result=CommandResults(readable_output=f"Waiting for commit job ID {job_id} to finish..."),
    )


@polling_function(name="block-domain", interval=60, timeout=1200)
def pan_os_commit_status(args: dict, responses: list) -> PollResult:
    """Check the status of the commit job in pan-os.

    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the previous command.
    Returns:
        The PollResult object.
    """
    commit_job_id = args["commit_job_id"]
    res_commit_status = run_execute_command("pan-os-commit-status", {"job_id": commit_job_id})
    responses.append(res_commit_status)
    result_commit_status = res_commit_status[0].get("Contents", {}).get("response", {}).get("result", {}).get("job", {})
    job_result = result_commit_status.get("result")
    commit_output = {"JobID": commit_job_id, "Status": "Success" if job_result == "OK" else "Failure"}
    continue_to_poll = result_commit_status.get("status") != "FIN"
    global POLLING
    POLLING = continue_to_poll
    return PollResult(
        response=CommandResults(
            outputs=commit_output,
            outputs_key_field="JobID",
            readable_output=tableToMarkdown("Commit Status:", commit_output, removeNull=True),
        ),
        args_for_next_run=args,
        continue_to_poll=continue_to_poll,
    )


@polling_function(name="block-domain", interval=60, timeout=1200)
def pan_os_push_to_device(args: dict, responses: list) -> PollResult:
    """Execute pan-os-push-to-device-group.

    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the previous command.
    Returns:
        The PollResult object.
    """
    res_push_to_device = run_execute_command("pan-os-push-to-device-group", {"polling": True})
    responses.append(res_push_to_device)
    polling_args = res_push_to_device[0].get("Metadata", {}).get("pollingArgs", {})
    job_id = polling_args.get("push_job_id")
    device_group = polling_args.get("device-group")
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


@polling_function(name="block-domain", interval=60, timeout=1200)
def pan_os_push_status(args: dict, responses: list) -> PollResult:
    """Check the status of the push job in pan-os.

    Args:
        args (dict): The arguments of the function.
        responses (list): The responses of the previous command.
    Returns:
        The PollResult object.
    """
    push_job_id = args["push_job_id"]
    res_push_status = run_execute_command("pan-os-push-status", {"job_id": push_job_id})
    responses.append(res_push_status)
    push_status = res_push_status[0].get("Contents", {}).get("response", {}).get("result", {}).get("job", {}).get("status", "")
    continue_to_poll = bool(push_status and push_status != "FIN")
    context_output = {"Status": push_status, "JobID": push_job_id}
    push_cr = CommandResults(
        outputs_key_field="JobID",
        outputs=context_output,
        readable_output=tableToMarkdown("Push to Device Group:", context_output, ["JobID", "Status"], removeNull=True),
    )
    global POLLING
    POLLING = continue_to_poll
    return PollResult(
        response=push_cr,
        continue_to_poll=continue_to_poll,
        partial_result=CommandResults(readable_output=f"Waiting for Job-ID {push_job_id} to finish pushing the changes..."),
    )


""" MAIN FUNCTION """


def main():  # pragma: no cover
    try:
        args = demisto.args()
        demisto.debug(f"The script block-domain was called with the arguments {args=}")

        domain_list = argToList(args.get("domain_list", []))
        rule_name = args.get("rule_name", "Cortex - Block Domain")
        log_forwarding_name = args.get("log_forwarding_name", "")
        address_group = args.get("address_group", "Blocked Domains - Cortex")
        tag = args.get("tag", "cortex-blocked-domains")
        auto_commit = argToBoolean(args.get("auto_commit", True))
        verbose = argToBoolean(args.get("verbose", False))
        brands_to_run = argToList(args.get("brands", ",".join(SUPPORTED_BRANDS)))
        demisto.debug(f"BlockDomain: {verbose=}, {brands_to_run=}")

        if not domain_list:
            return_error("domain_list argument is required.")

        valid_domains, failed_rows = validate_domains(domain_list)
        demisto.debug(f"BlockDomain: {valid_domains=}, {len(failed_rows)} entries failed validation.")

        enabled_brands = get_enabled_brands()
        brands_to_run = brands_to_run or list(SUPPORTED_BRANDS)

        runnable_brands = [b for b in brands_to_run if b in SUPPORTED_BRANDS and b in enabled_brands]
        if not runnable_brands:
            return_error(
                f"No integrations were found for the brands {brands_to_run}. "
                f"Please verify the brand instances' setup. Supported brands: {SUPPORTED_BRANDS}."
            )

        results: list = list(failed_rows)

        for brand in brands_to_run:
            if brand not in SUPPORTED_BRANDS:
                results.append(
                    build_result_row(
                        domain="",
                        brand=brand,
                        status=STATUS_FAILED,
                        result=RESULT_FAILED,
                        action=ACTION_UNCHANGED,
                        message=f"The brand {brand} is not supported by 'block-domain'. Supported: {SUPPORTED_BRANDS}.",
                    )
                )
            elif brand not in enabled_brands:
                results.append(
                    build_result_row(
                        domain="",
                        brand=brand,
                        status=STATUS_FAILED,
                        result=RESULT_FAILED,
                        action=ACTION_UNCHANGED,
                        message=f"The brand {brand} isn't enabled.",
                    )
                )
            elif brand == "Panorama" and valid_domains:
                pan_os = PanOs(
                    {
                        "domains": valid_domains,
                        "rule_name": rule_name,
                        "log_forwarding_name": log_forwarding_name,
                        "address_group": address_group,
                        "tag": tag,
                        "auto_commit": auto_commit,
                        "verbose": verbose,
                        "commit_job_id": args.get("commit_job_id"),
                        "push_job_id": args.get("push_job_id"),
                        "polling": True,
                    }
                )
                pan_os_result = pan_os.manage_pan_os_flow()
                if isinstance(pan_os_result, PollResult):
                    return_results(pan_os_result)
                    return
                results.extend(pan_os_result)

        return_results(
            CommandResults(
                outputs_prefix="BlockDomainResults",
                outputs_key_field=["Domain", "Brand", "Instance"],
                outputs=results,
                readable_output=tableToMarkdown(
                    "Block Domain",
                    results,
                    headers=["Domain", "Brand", "Instance", "Status", "Result", "Action", "RuleName", "Message"],
                    removeNull=False,
                ),
            )
        )

    except Exception as ex:
        return_error(f"Failed to execute block-domain. Error: {ex!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
