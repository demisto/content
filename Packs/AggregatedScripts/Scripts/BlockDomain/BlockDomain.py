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

PRE_POST = "pre-rulebase"  # Q2: hard-coded for v1 (may become an argument later).

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

# A permissive FQDN matcher: labels of alphanumerics/hyphens separated by dots, at least one dot.
FQDN_REGEX = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

# Controls the polling loop, mirroring the BlockExternalIp pattern.
POLLING = True

""" INPUT-VALIDATION / NAMING HELPERS """


def is_wildcard(domain: str) -> bool:
    """A domain is treated as a wildcard (and therefore unsupported) if it contains an asterisk."""
    return "*" in domain


def is_valid_fqdn(domain: str) -> bool:
    """Return True if the value looks like a valid, non-wildcard FQDN."""
    return bool(FQDN_REGEX.match(domain))


def derive_object_name(domain: str) -> str:
    """Derive a deterministic address-object name from a domain.

    The name is a pure function of the domain so re-runs are idempotent. On overflow of the PAN-OS
    max object-name length, the sanitised body is truncated and a short deterministic hash suffix is
    appended to keep the name unique.
    """
    sanitised = re.sub(r"[^A-Za-z0-9.\-]", "-", domain).strip("-")
    candidate = f"{OBJECT_NAME_PREFIX}{sanitised}"
    if len(candidate) <= MAX_OBJECT_NAME_LENGTH:
        return candidate

    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:HASH_SUFFIX_LENGTH]
    keep = MAX_OBJECT_NAME_LENGTH - len(OBJECT_NAME_PREFIX) - 1 - HASH_SUFFIX_LENGTH  # 1 for the '-' separator.
    truncated = sanitised[:keep].strip("-")
    return f"{OBJECT_NAME_PREFIX}{truncated}-{digest}"


def most_significant_action(actions: list) -> str:
    """Return the most significant action from a list (Created > Modified > Unchanged)."""
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
    """Assemble a single BlockDomainResults row in the canonical field order."""
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
    """Split the input into (valid_domains, skipped_rows).

    Wildcard and invalid entries never reach a vendor; they produce a per-row Skipped result while
    the rest of the list continues.
    """
    valid_domains: list = []
    skipped_rows: list = []
    for domain in domain_list:
        if is_wildcard(domain):
            skipped_rows.append(
                build_result_row(
                    domain=domain,
                    brand="",
                    status=STATUS_SKIPPED,
                    result=RESULT_FAILED,
                    action=ACTION_UNCHANGED,
                    message=f"Wildcard domain '{domain}' is not supported by this script; skipped.",
                )
            )
        elif not is_valid_fqdn(domain):
            skipped_rows.append(
                build_result_row(
                    domain=domain,
                    brand="",
                    status=STATUS_SKIPPED,
                    result=RESULT_FAILED,
                    action=ACTION_UNCHANGED,
                    message=f"Invalid FQDN '{domain}' - skipped.",
                )
            )
        else:
            valid_domains.append(domain)
    return valid_domains, skipped_rows


def get_enabled_brands() -> set:
    """Return the set of brands that have at least one active instance."""
    modules = demisto.getModules()
    enabled_brands = {module.get("brand") for module in modules.values() if module.get("state") == "active"}
    demisto.debug(f"BlockDomain: the enabled modules are: {enabled_brands=}")
    return enabled_brands


""" EXECUTE-COMMAND / CONTEXT HELPERS """


def run_execute_command(command_name: str, args: dict[str, Any]) -> list[dict]:
    """Execute a command and return its raw entries."""
    demisto.debug(f"BlockDomain: Executing command: {command_name} with {args=}")
    res = demisto.executeCommand(command_name, args)
    demisto.debug(f"BlockDomain: The response of {command_name} is {res}")
    return res


def get_relevant_context(original_context: dict[str, Any], key: str) -> dict | list:
    """Get the relevant context object from the execute_command response, tolerating suffixed keys."""
    if not original_context:
        return {}
    if relevant_context := original_context.get(key, {}):
        return relevant_context
    for k in original_context:
        if k.startswith(key):
            return original_context.get(k, {})
    return {}


def is_error_entry(entry: dict) -> bool:
    """Return True if an execute_command entry is an error entry."""
    return isinstance(entry, dict) and entry.get("Type") == entryTypes["error"]


def get_entry_error(entry: dict) -> str:
    """Extract a human-readable error message from an error entry."""
    return str(entry.get("Contents", "Unknown error"))


def as_list(value: Any) -> list:
    """Normalise a context value that may be a dict, list, or None into a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


""" POLLING FUNCTIONS (commit / push) """


@polling_function(name="block-domain", interval=60, timeout=1200)
def pan_os_commit(args: dict, responses: list) -> PollResult:
    """Execute pan-os-commit and start polling on the returned job."""
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
    """Check the status of the commit job in pan-os."""
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
    """Execute pan-os-push-to-device-group and start polling on the returned job."""
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
    """Check the status of the push job in pan-os."""
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


""" PAN-OS FLOW """


class DynamicGroupError(Exception):
    """Raised when the target address-group exists and is dynamic (customer-managed)."""


class PanOs:
    """Implements the PAN-OS static-address-group domain-blocking flow.

    For each valid domain the flow probes/creates an FQDN address-object, ensures it belongs to the
    static address-group, and ensures a single deny rule points at the group. Commit + optional push
    happen once after all domains are processed. Every step records its effect (Created / Modified /
    Unchanged) so the aggregated per-domain row reflects the most significant change.
    """

    def __init__(self, args: dict):
        self.args = args
        self.brand = "Panorama"
        self.rule_name = args["rule_name"]
        self.address_group = args["address_group"]
        self.tag = args.get("tag", "")
        self.log_forwarding_name = args.get("log_forwarding_name", "")
        self.domains: list = args.get("domains", [])
        self.responses: list = []
        # Per-domain accumulated actions and messages, keyed by domain.
        self.domain_actions: dict = {domain: [] for domain in self.domains}
        self.domain_messages: dict = {domain: [] for domain in self.domains}

    # ---- context probes -------------------------------------------------

    def address_object_exists(self, object_name: str) -> bool:
        """Return True if an address-object with this name already exists."""
        res = run_execute_command("pan-os-get-address", {"name": object_name})
        entry = res[0] if res else {}
        if is_error_entry(entry):
            # get-address raises when the object is absent; treat that as 'does not exist'.
            demisto.debug(f"BlockDomain: address '{object_name}' not found ({get_entry_error(entry)}).")
            return False
        self.responses.append(res)
        context = get_relevant_context(entry.get("EntryContext", {}), "Panorama.Addresses")
        return any(item.get("Name") == object_name for item in as_list(context))

    def get_address_group(self) -> dict | None:
        """Return the target address-group context dict, or None if it does not exist."""
        res = run_execute_command("pan-os-list-address-groups", {})
        self.responses.append(res)
        entry = res[0] if res else {}
        if is_error_entry(entry):
            raise DemistoException(f"Failed to list address groups: {get_entry_error(entry)}")
        context = get_relevant_context(entry.get("EntryContext", {}), "Panorama.AddressGroups")
        for item in as_list(context):
            if item.get("Name") == self.address_group:
                return item
        return None

    def group_members(self, group_context: dict) -> list:
        """Return the current static-group member names."""
        return as_list(group_context.get("Addresses"))

    def rule_exists(self) -> bool:
        """Return True if a rule named self.rule_name already exists in the rulebase."""
        res = run_execute_command("pan-os-list-rules", {"pre_post": PRE_POST})
        self.responses.append(res)
        entry = res[0] if res else {}
        if is_error_entry(entry):
            raise DemistoException(f"Failed to list rules: {get_entry_error(entry)}")
        context = get_relevant_context(entry.get("EntryContext", {}), "Panorama.SecurityRule")
        return any(item.get("Name") == self.rule_name for item in as_list(context))

    # ---- writes ---------------------------------------------------------

    def ensure_address_object(self, domain: str, object_name: str) -> None:
        """Create the FQDN address-object if it does not already exist."""
        if self.address_object_exists(object_name):
            self.domain_actions[domain].append(ACTION_UNCHANGED)
            self.domain_messages[domain].append(f"Address-object '{object_name}' already exists.")
            return
        create_args: dict = {"name": object_name, "fqdn": domain}
        if self.tag:
            create_args["tag"] = self.tag
        res = run_execute_command("pan-os-create-address", create_args)
        self.responses.append(res)
        entry = res[0] if res else {}
        if is_error_entry(entry):
            raise DemistoException(f"Failed to create address-object '{object_name}': {get_entry_error(entry)}")
        self.domain_actions[domain].append(ACTION_CREATED)
        self.domain_messages[domain].append(f"Address-object '{object_name}' created for '{domain}'.")

    def ensure_group_membership(self, domain: str, object_name: str, group_context: dict | None) -> None:
        """Create the static group or add the object to it, aborting if the group is dynamic."""
        if group_context is None:
            create_args: dict = {"name": self.address_group, "type": "static", "addresses": [object_name]}
            if self.tag:
                create_args["tags"] = self.tag
            res = run_execute_command("pan-os-create-address-group", create_args)
            self.responses.append(res)
            entry = res[0] if res else {}
            if is_error_entry(entry):
                raise DemistoException(f"Failed to create address-group '{self.address_group}': {get_entry_error(entry)}")
            self.domain_actions[domain].append(ACTION_CREATED)
            self.domain_messages[domain].append(f"Static address-group '{self.address_group}' created.")
            return

        group_type = (group_context.get("Type") or "").lower()
        if group_type == "dynamic":
            raise DynamicGroupError(
                f"Address-group '{self.address_group}' already exists as dynamic; "
                f"will not modify a customer-managed dynamic group."
            )

        if object_name in self.group_members(group_context):
            self.domain_actions[domain].append(ACTION_UNCHANGED)
            self.domain_messages[domain].append(
                f"Address-object '{object_name}' is already a member of '{self.address_group}'."
            )
            return

        res = run_execute_command(
            "pan-os-edit-address-group",
            {"name": self.address_group, "type": "static", "element_to_add": object_name},
        )
        self.responses.append(res)
        entry = res[0] if res else {}
        if is_error_entry(entry):
            raise DemistoException(f"Failed to add object to address-group '{self.address_group}': {get_entry_error(entry)}")
        self.domain_actions[domain].append(ACTION_MODIFIED)
        self.domain_messages[domain].append(f"Address-object '{object_name}' added to '{self.address_group}'.")

    def ensure_rule(self, rule_present: bool) -> str:
        """Create the deny rule if missing, then move it to the top. Returns the rule action."""
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
            res = run_execute_command("pan-os-create-rule", create_rule_args)
            self.responses.append(res)
            entry = res[0] if res else {}
            if is_error_entry(entry):
                raise DemistoException(f"Failed to create rule '{self.rule_name}': {get_entry_error(entry)}")
            rule_action = ACTION_CREATED
        else:
            rule_action = ACTION_UNCHANGED

        # Always ensure the rule sits at the top of the rulebase.
        res_move = run_execute_command("pan-os-move-rule", {"rulename": self.rule_name, "where": "top", "pre_post": PRE_POST})
        self.responses.append(res_move)
        move_entry = res_move[0] if res_move else {}
        if is_error_entry(move_entry):
            raise DemistoException(f"Failed to move rule '{self.rule_name}' to top: {get_entry_error(move_entry)}")
        return rule_action

    # ---- orchestration --------------------------------------------------

    def process_domains(self) -> list:
        """Run the per-domain object + group flow, then the single shared rule step.

        Returns the list of BlockDomainResults rows for the processed domains.
        """
        rows: list = []
        try:
            group_context = self.get_address_group()
            for domain in self.domains:
                object_name = derive_object_name(domain)
                self.ensure_address_object(domain, object_name)
                self.ensure_group_membership(domain, object_name, group_context)
                # Re-read the group once created so subsequent domains see the new membership.
                if group_context is None:
                    group_context = self.get_address_group()

            rule_present = self.rule_exists()
            rule_action = self.ensure_rule(rule_present)

            for domain in self.domains:
                actions = self.domain_actions[domain] + [rule_action]
                rows.append(
                    build_result_row(
                        domain=domain,
                        brand=self.brand,
                        status=STATUS_DONE,
                        result=RESULT_SUCCESS,
                        action=most_significant_action(actions),
                        rule_name=self.rule_name,
                        message=" ".join(self.domain_messages[domain])
                        + (f" Rule '{self.rule_name}' created at top." if rule_action == ACTION_CREATED else "")
                        + (f" Rule '{self.rule_name}' already present; moved to top." if rule_action == ACTION_UNCHANGED else ""),
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

    def run(self) -> list:  # pragma: no cover
        """Execute the full PAN-OS flow: per-domain writes, then commit + optional push."""
        rows = self.process_domains()

        # Only commit/push if at least one domain actually reached Done (i.e. no dynamic-group abort / failure).
        made_changes = any(row["Status"] == STATUS_DONE for row in rows)
        auto_commit = argToBoolean(self.args.get("auto_commit", True))
        if made_changes and auto_commit:
            try:
                pan_os_commit(self.args, self.responses)
                if self.pan_os_is_panorama():
                    pan_os_push_to_device(self.args, self.responses)
            except Exception as ex:
                rows.append(
                    build_result_row(
                        domain="",
                        brand=self.brand,
                        status=STATUS_FAILED,
                        result=RESULT_FAILED,
                        action=ACTION_UNCHANGED,
                        message=f"Commit/push failed: {ex!s}. Objects and rule are staged but may not be active.",
                    )
                )
        return rows

    def pan_os_is_panorama(self) -> bool:
        """Return True if the instance is a Panorama (vs a single firewall)."""
        res = run_execute_command("pan-os", {"cmd": "<show><system><info></info></system></show>", "type": "op"})
        self.responses.append(res)
        context = get_relevant_context(res[0].get("EntryContext", {}), "Panorama.Command")
        model = context.get("response", {}).get("result", {}).get("system", {}).get("model", "")  # type: ignore
        return model == "Panorama"


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

        valid_domains, skipped_rows = validate_domains(domain_list)
        demisto.debug(f"BlockDomain: {valid_domains=}, skipped {len(skipped_rows)} entries.")

        enabled_brands = get_enabled_brands()
        brands_to_run = brands_to_run or list(SUPPORTED_BRANDS)

        runnable_brands = [b for b in brands_to_run if b in SUPPORTED_BRANDS and b in enabled_brands]
        if not runnable_brands:
            return_error(
                f"No integrations were found for the brands {brands_to_run}. "
                f"Please verify the brand instances' setup. Supported brands: {SUPPORTED_BRANDS}."
            )

        results: list = list(skipped_rows)

        for brand in brands_to_run:
            if brand not in SUPPORTED_BRANDS:
                results.append(
                    build_result_row(
                        domain="",
                        brand=brand,
                        status=STATUS_SKIPPED,
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
                        status=STATUS_SKIPPED,
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
                results.extend(pan_os.run())

        return_results(
            CommandResults(
                outputs_prefix="BlockDomainResults",
                outputs_key_field=["Domain", "Brand"],
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
