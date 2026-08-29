import hashlib
import re
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

""" CONSTANTS """

SUPPORTED_BRANDS = ["Panorama"]

OBJECT_NAME_PREFIX = "Cortex-"
# PAN-OS object names are capped at 63 chars; reserve room for the prefix and hash suffix.
MAX_OBJECT_NAME_LENGTH = 63
HASH_SUFFIX_LENGTH = 8
OBJECT_NAME_SANITIZE_REGEX = re.compile(r"[^A-Za-z0-9.\-]")

PRE_POST = "pre-rulebase"

FQDN_REGEX = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

# Status values.
STATUS_DONE = "Done"
STATUS_PENDING = "Pending"
STATUS_SKIPPED = "Skipped"
STATUS_FAILED = "Failed"

# Result values.
RESULT_SUCCESS = "Success"
RESULT_FAILED = "Failed"


# Single searchable tag for every log line; grep tenant logs for "[BlockDomain]" to trace a run.
LOG_TAG = "[BlockDomain]"

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


def normalize_tags(raw_tags: Any) -> list[str]:
    """Normalize a PAN-OS tags value into a clean list of tag names.

    PAN-OS may return an entity's tags as a single string, a list of strings, or None/absent.
    This flattens all of those into a list (empty when there are no tags).

    Args:
        raw_tags (Any): The raw 'Tags' value from a PAN-OS context entry.
    Returns:
        A list of tag-name strings (possibly empty).
    """
    if not raw_tags:
        return []
    if isinstance(raw_tags, list):
        return [str(tag) for tag in raw_tags if tag]
    return [str(raw_tags)]


def build_result_row(
    domain: str,
    brand: str | None,
    status: str,
    result: str,
    message: str,
    rule_name: str | None = None,
) -> dict:
    """Assemble a single BlockDomain row.

    Any field with no meaningful value is stored as ``None`` (real JSON null) rather than an empty
    string, so downstream context never carries empty-string placeholders (e.g. a failed-validation
    row has ``Brand: null`` and ``RuleName: null`` instead of ``""``).

    Note: there is intentionally no ``Action`` field - the security team confirmed that ``Result``
    plus ``Message`` convey everything they need, so per-row Created/Modified/Unchanged is not
    surfaced. Change-detection is still performed internally to gate the commit/push.

    Args:
        domain (str): The processed domain.
        brand (str | None): The brand used, or None when not applicable (e.g. failed validation).
        status (str): The lifecycle status.
        result (str): Success or Failed.
        message (str): A human-readable message.
        rule_name (str | None): The rule name used, or None when no rule was involved.
    Returns:
        A dict representing a single result row, with empty values normalised to None.
    """
    return {
        "Domain": domain or None,
        "Brand": brand or None,
        "Status": status or None,
        "Result": result or None,
        "RuleName": rule_name or None,
        "Message": message or None,
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
                    brand=None,
                    status=STATUS_FAILED,
                    result=RESULT_FAILED,
                    message=f"Wildcard domain '{domain}' is not supported by this script; skipped.",
                )
            )
        elif not is_valid_fqdn(domain):
            failed_rows.append(
                build_result_row(
                    domain=domain,
                    brand=None,
                    status=STATUS_FAILED,
                    result=RESULT_FAILED,
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
    return {module.get("brand") for module in modules.values() if module.get("state") == "active"}


""" EXECUTE-COMMAND / CONTEXT HELPERS """


def run_execute_command(command_name: str, args: dict[str, Any]) -> list[dict]:
    """Execute a command and return its raw entries.

    Args:
        command_name (str): The command to execute.
        args (dict): The command arguments.
    Returns:
        The raw list of command entries.
    """
    return demisto.executeCommand(command_name, args)


def is_polling_in_progress(poll_response: Any) -> bool:
    """Return whether a polling function's result indicates it should keep polling.

    The @polling_function decorator attaches a ScheduledCommand to the returned CommandResults only
    while polling should continue; when the job finishes it returns the plain response with none.

    Args:
        poll_response (Any): The value returned by a @polling_function-decorated call.
    Returns:
        True if polling should continue, False when the job has finished.
    """
    return getattr(poll_response, "scheduled_command", None) is not None


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


""" HUMAN-READABLE / FINAL-RESULT AGGREGATION """


def build_verbose_human_readable(responses: list) -> str:
    """Concatenate the per-command human-readable outputs into a single, blank-line-separated string.

    Args:
        responses (list): The accumulated command responses (each a list of entries).
    Returns:
        A single markdown string with each command's human-readable output separated by a blank line,
        or an empty string if no command produced human-readable output.
    """
    human_readables: list = []
    for res in responses or []:
        for entry in res or []:
            command_hr = entry.get("HumanReadable")
            if command_hr and command_hr != str(None):
                human_readables.append(command_hr)
    # A leading "" yields a blank line separating the summary table from the first verbose entry.
    return "\n\n".join(["", *human_readables]) if human_readables else ""


def build_final_command_results(rows: list, verbose: bool, responses: list) -> CommandResults:
    """Build the single final CommandResults for the run.

    The CommandResults carries the aggregated BlockDomain context and a markdown summary table.
    When verbose is True, the per-command human-readable outputs are appended to the same readable
    output (blank-line separated), mirroring the ExpirePassword aggregated script.

    When there is at least one row and every row failed, the whole run is reported as an error.

    Args:
        rows (list): The aggregated BlockDomain rows.
        verbose (bool): Whether to append per-command human-readable output.
        responses (list): The accumulated command responses (used only when verbose).
    Returns:
        A single CommandResults to return from the script.
    """
    all_failed = bool(rows) and all(row.get("Result") == RESULT_FAILED for row in rows)
    table_title = "Block Domain: All runs failed." if all_failed else "Block Domain"
    readable_output = tableToMarkdown(
        table_title,
        rows,
        headers=["Domain", "Brand", "Status", "Result", "RuleName", "Message"],
        removeNull=True,
    )
    if all_failed:
        readable_output += "\n\n**All runs failed.** Review the table above for the specific error messages."
    if verbose:
        readable_output += build_verbose_human_readable(responses)
    command_results = CommandResults(
        outputs_prefix="BlockDomain",
        outputs_key_field=["Domain", "Brand"],
        outputs=rows,
        readable_output=readable_output,
    )
    if all_failed:
        # Surface the whole run as an error entry so the war room / playbook can branch on failure.
        command_results.entry_type = EntryType.ERROR
    return command_results


""" PAN-OS FLOW """


class DynamicGroupError(Exception):
    """Raised when the target address-group exists and is dynamic (customer-managed)."""


class PanOs:
    """Implements the PAN-OS static-address-group domain-blocking flow.

    The address-group and the deny rule are singletons (their names are constant), so they are
    ensured once per run. Each valid domain then gets an FQDN address-object that is added to the
    group. Commit + optional push happen once after all domains are processed.
    """

    def __init__(self, args: dict) -> None:
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
        # Key MUST match the YAML arg name; args_for_next_run re-passes it during polling re-entry.
        self.domains: list = args.get("domain_list", [])
        self.responses: list = []
        # True once the rule was created or edited this run
        self._rule_changed: bool = False
        # True once any address object was created, or added to the group, this run.
        self._address_made_changes: bool = False
        # The pre-existing rule's current tags (captured once per run by rule_destinations), used to
        # merge in the configured tag without duplicating it.
        self._rule_tags: list[str] = []
        # The pre-existing rule's current log-forwarding profile (single value, captured once per
        # run by rule_destinations).
        self._rule_log_forwarding: str = ""

    # ---- tag helper ----------------------------------------------------

    def ensure_tag(self) -> None:
        """Create the configured tag up front so the group and rule can reference it.

        Creating the tag here decouples it from address-object creation, which is important when
        every object already exists and the create-address auto-create path is skipped. An error
        from an already-existing tag is expected and tolerated (logged, not raised).

        Returns:
            None.
        """
        if not self.tag:
            return
        command_name = "pan-os-create-tag"
        res = run_execute_command(command_name, {"name": self.tag})
        self.responses.append(res)
        if is_error(res):
            # An already-existing tag is the common, benign case; log and continue.
            demisto.debug(
                f"{LOG_TAG} pan-os-create-tag for '{self.tag}' returned an error " f"(likely already exists): {get_error(res)}"
            )

    def merged_tags_if_missing(self, existing_tags: list[str]) -> list[str] | None:
        """Return the tag list to write when the configured tag is not already present.

        Args:
            existing_tags (list[str]): The entity's current tags.
        Returns:
            The merged tag list to write, or None when nothing needs to change.
        """
        if not self.tag or self.tag in existing_tags:
            return None
        return [*existing_tags, self.tag]

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

    def address_object_exists(self, object_name: str) -> tuple[bool, list[str]]:
        """Check whether an address-object already exists, and return its current tags.

        Args:
            object_name (str): The address-object name to probe.
        Returns:
            A tuple of (exists, current_tags). current_tags is empty when the object is absent or
            has no tags.
        """
        command_name = "pan-os-get-address"
        res = run_execute_command(command_name, {"name": object_name})
        # pan-os-get-address raises when the object is absent; treat that as 'does not exist'.
        if is_error(res):
            return False, []
        self.responses.append(res)
        context = get_relevant_context(res[0].get("EntryContext", {}), "Panorama.Addresses")
        items = context if isinstance(context, list) else [context]
        for item in items:
            if item.get("Name") == object_name:
                return True, normalize_tags(item.get("Tags"))
        return False, []

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

    def rule_destinations(self) -> tuple[bool, list, list[str]]:
        """Return whether the rule exists, its current destination list, and its current tags.

        Also records the rule's current log-forwarding profile on ``self._rule_log_forwarding``
        (single-value profile) so ensure_rule can add it only when the configured profile differs.

        Returns:
            A tuple of (rule_exists, destination_list, current_tags).
        """
        res = self.execute_or_raise("pan-os-list-rules", {"pre_post": PRE_POST}, "Failed to list rules")
        context = get_relevant_context(res[0].get("EntryContext", {}), "Panorama.SecurityRule")
        items = context if isinstance(context, list) else [context]
        for item in items:
            if item.get("Name") == self.rule_name:
                destination = item.get("Destination")
                destination_list = destination if isinstance(destination, list) else [destination] if destination else []
                self._rule_log_forwarding = item.get("LogForwardingProfile") or ""
                return True, destination_list, normalize_tags(item.get("Tags"))
        return False, [], []

    # ---- single-run writes (group + rule are singletons) ----------------

    def ensure_group(self, group_context: dict | None, object_names: list[str]) -> None:
        """Create the static address-group with all members, or add this run's members to it.

        A static group references its members by name, so every address object must already exist on
        the device before the group is created or edited (otherwise PAN-OS rejects the reference).
        Callers must create all objects first, then call this once with the full list of names.

        pan-os-edit-address-group requires exactly one of element_to_add/element_to_remove for a
        static group and applies tags only alongside it, so the configured tag is merged into the
        same element_to_add call. Re-adding an existing member is a no-op (the command de-duplicates).

        Args:
            group_context (dict | None): The existing group's context, or None if it does not exist.
            object_names (list[str]): Every address-object name for this run (the full member list).
        Returns:
            None.
        Raises:
            DynamicGroupError: If the group exists but is a customer-managed dynamic group.
        """
        if group_context is None:
            create_args: dict = {"name": self.address_group, "type": "static", "addresses": object_names}
            if self.tag:
                create_args["tags"] = self.tag
            self.execute_or_raise(
                "pan-os-create-address-group", create_args, f"Failed to create address-group '{self.address_group}'"
            )
            self._address_made_changes = True
            return

        group_type = (group_context.get("Type") or "").lower()
        if group_type == "dynamic":
            raise DynamicGroupError(
                f"Address-group '{self.address_group}' already exists as dynamic; " f"will not modify a managed dynamic group."
            )

        existing_members = normalize_tags(group_context.get("Addresses"))
        members_to_add = [name for name in object_names if name not in existing_members]
        merged_tags = self.merged_tags_if_missing(normalize_tags(group_context.get("Tags")))
        if not members_to_add and merged_tags is None:
            return
        # element_to_add is required by the edit; when only the tag changed, re-add existing members.
        edit_args: dict = {"name": self.address_group, "type": "static", "element_to_add": members_to_add or object_names}
        if merged_tags is not None:
            edit_args["tags"] = merged_tags
        self.execute_or_raise(
            "pan-os-edit-address-group",
            edit_args,
            f"Failed to add object(s) to address-group '{self.address_group}'",
        )
        self._address_made_changes = True

    def ensure_rule(self, rule_present: bool, rule_destinations: list) -> None:
        """Ensure the deny rule exists, points at the group, carries the tag, and sits at the top.

        Args:
            rule_present (bool): Whether the rule already exists.
            rule_destinations (list): The rule's current destination list.
        Returns:
            None.
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
            self._rule_changed = True
        else:
            if self.address_group not in rule_destinations:
                # Rule exists but doesn't reference our group - add without replacing existing destinations.
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
                self._rule_changed = True
            # Add the configured tag to the pre-existing rule if it isn't already present. Uses
            # behaviour=add so it never clobbers or duplicates the rule's existing tags.
            if self.tag and self.tag not in self._rule_tags:
                self.execute_or_raise(
                    "pan-os-edit-rule",
                    {
                        "rulename": self.rule_name,
                        "element_to_change": "tag",
                        "element_value": self.tag,
                        "behaviour": "add",
                        "pre_post": PRE_POST,
                    },
                    f"Failed to add tag to rule '{self.rule_name}'",
                )
                self._rule_changed = True
            # Add the configured log-forwarding profile to the pre-existing rule if it differs.
            if self.log_forwarding_name and self.log_forwarding_name != self._rule_log_forwarding:
                self.execute_or_raise(
                    "pan-os-edit-rule",
                    {
                        "rulename": self.rule_name,
                        "element_to_change": "log-forwarding",
                        "element_value": self.log_forwarding_name,
                        "pre_post": PRE_POST,
                    },
                    f"Failed to set log-forwarding profile on rule '{self.rule_name}'",
                )
                self._rule_changed = True
        # Always enforce top placement.
        self.execute_or_raise(
            "pan-os-move-rule",
            {"rulename": self.rule_name, "where": "top", "pre_post": PRE_POST},
            f"Failed to move rule '{self.rule_name}' to top",
        )

    def ensure_address_object(self, domain: str) -> tuple[str, bool, str]:
        """Ensure a single domain's FQDN address-object exists and carries the configured tag.

        Object-only: it does not touch the group or the rule. The group is built afterwards from the
        full set of object names, so every member reference resolves at group-creation time.

        Args:
            domain (str): The domain to block.
        Returns:
            A tuple of (object_name, changed, message). 'changed' is True when the object was created
            or its tag was added.
        """
        object_name = derive_object_name(domain)
        object_exists, object_tags = self.address_object_exists(object_name)
        if object_exists:
            # Merge the configured tag onto the existing object only when it is missing.
            merged = self.merged_tags_if_missing(object_tags)
            if merged is not None:
                self.execute_or_raise(
                    "pan-os-edit-address",
                    {"name": object_name, "element_to_change": "tag", "element_value": merged},
                    f"Failed to add tag to address-object '{object_name}'",
                )
                return object_name, True, f"Address-object '{object_name}' already existed; tag '{self.tag}' added."
            return object_name, False, f"Address-object '{object_name}' already exists."

        create_args: dict = {"name": object_name, "fqdn": domain}
        if self.tag:
            # create_tag=true auto-creates the tag; pan-os-create-address fails otherwise.
            create_args["tag"] = self.tag
            create_args["create_tag"] = "true"
        self.execute_or_raise("pan-os-create-address", create_args, f"Failed to create address-object '{object_name}'")
        return object_name, True, f"Address-object '{object_name}' created for '{domain}'."

    # ---- orchestration --------------------------------------------------

    def process_domains(self) -> list:
        """Block all domains in three phases: objects, then the static group, then the rule.

        The phased order is required because a static address-group references its members by name,
        so every address object must exist before the group is created or edited.

        Returns:
            The list of BlockDomain rows for the processed domains.
        """
        rows: list = []
        try:
            # Create the tag up front so group/rule creation can reference it even when every
            # address object already exists (and the create-address auto-create path is skipped).
            self.ensure_tag()

            # Phase 1: create/verify EVERY address object first (each carrying the tag).
            object_names: list[str] = []
            per_domain_messages: list[tuple[str, str]] = []
            for domain in self.domains:
                object_name, changed, message = self.ensure_address_object(domain)
                object_names.append(object_name)
                per_domain_messages.append((domain, message))
                self._address_made_changes = self._address_made_changes or changed

            # Phase 2: create/edit the static group ONCE with the full member list (all objects now
            # exist, so every reference resolves). Tag is merged in the same call.
            group_context = self.get_address_group()
            self.ensure_group(group_context, object_names)

            # Phase 3: ensure the rule once (group now exists, so its destination reference resolves).
            rule_present, rule_destinations, self._rule_tags = self.rule_destinations()
            self.ensure_rule(rule_present, rule_destinations)

            for domain, message in per_domain_messages:
                rows.append(
                    build_result_row(
                        domain=domain,
                        brand=self.brand,
                        status=STATUS_DONE,
                        result=RESULT_SUCCESS,
                        rule_name=self.rule_name,
                        message=f"{message} Added to '{self.address_group}'. Rule '{self.rule_name}' enforced at top.",
                    )
                )
        except DynamicGroupError as dyn_err:
            # Abort the whole brand for this run.
            for domain in self.domains:
                rows.append(
                    build_result_row(
                        domain=domain,
                        brand=self.brand,
                        status=STATUS_SKIPPED,
                        result=RESULT_SUCCESS,
                        rule_name="",
                        message=str(dyn_err),
                    )
                )
        except Exception as ex:
            demisto.error(f"{LOG_TAG} process_domains failed: {traceback.format_exc()}")
            for domain in self.domains:
                rows.append(
                    build_result_row(
                        domain=domain,
                        brand=self.brand,
                        status=STATUS_FAILED,
                        result=RESULT_FAILED,
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
        command_name = "pan-os"
        res = run_execute_command(command_name, {"cmd": "<show><system><info></info></system></show>", "type": "op"})
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
        stored = demisto.context().get("panorama_responses", "") or ""
        self.responses = json.loads(stored) if stored else []

    def save_responses(self) -> None:
        """Serialize the accumulated responses to context for the next polling cycle."""
        demisto.setContext("panorama_responses", json.dumps(self.reduce_responses()))

    def manage_pan_os_flow(self) -> Any:  # pragma: no cover
        """Dispatch the PAN-OS flow to the correct state.

        On re-entry (a push or commit job is in flight) the flow jumps straight to the relevant
        status poller. Otherwise it starts the object/group/rule flow.

        Returns:
            A PollResult when a job is in flight, or the list of result rows when finished.
        """
        # Polling re-entry rules:
        #  - commit_job_id is carried in self.args by args_for_next_run.
        #  - push_job_id is only written to demisto.context() by pan_os_push_to_device.
        #  - A fresh manual invocation has neither in args; any leftover context is stale and
        #    must be scrubbed so it can't hijack the fresh run.
        incident_context = demisto.context()
        commit_job_id = self.args.get("commit_job_id")
        context_push_job_id = demisto.get(incident_context, "push_job_id")
        context_commit_job_id = demisto.get(incident_context, "commit_job_id")

        is_polling_reentry = bool(commit_job_id)
        if not is_polling_reentry and (context_commit_job_id or context_push_job_id):
            demisto.debug(
                f"{LOG_TAG} Stale polling context on fresh invocation "
                f"(commit={context_commit_job_id!r}, push={context_push_job_id!r}); clearing."
            )
            demisto.setContext("commit_job_id", "")
            demisto.setContext("push_job_id", "")
            demisto.setContext("panorama_responses", "")
            demisto.setContext("block_domain_rows", "")
            context_push_job_id = None

        push_job_id = context_push_job_id if is_polling_reentry else None

        demisto.debug(f"{LOG_TAG} dispatch: {commit_job_id=}, {push_job_id=}")
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
        if not is_polling_in_progress(res_push_status):
            demisto.debug(f"{LOG_TAG} Push job {push_job_id} finished.")
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
        if is_polling_in_progress(poll_commit_status):
            self.save_responses()
            return poll_commit_status
        demisto.debug(f"{LOG_TAG} Commit job {commit_job_id} finished.")
        # Commit finished - push to the device group if this is Panorama.
        if self.pan_os_is_panorama():
            poll_push = pan_os_push_to_device(self.args, self.responses)
            if not is_polling_in_progress(poll_push):
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
        demisto.setContext("block_domain_rows", json.dumps(rows))
        # Commit/push only when the run mutated Panorama state, to avoid a needless multi-minute
        # push poll on a pure "nothing changed" run.
        made_changes = self._address_made_changes or self._rule_changed
        auto_commit = argToBoolean(self.args.get("auto_commit", True))
        demisto.debug(f"{LOG_TAG} start_flow: {made_changes=}, {auto_commit=}, {len(rows)} row(s)")
        if made_changes and auto_commit:
            poll_commit = pan_os_commit(self.args, self.responses)
            if not is_polling_in_progress(poll_commit):
                return self.finish()
            self.save_responses()
            return poll_commit
        # Nothing changed on the device: return the rows and skip the commit/push.
        demisto.debug(f"{LOG_TAG} start_flow: no changes detected; skipping commit/push.")
        return rows

    def finish(self) -> list:  # pragma: no cover
        """Clean up polling context and return the final result rows.

        The accumulated responses (restored from context across polling cycles) are kept on the
        instance so the caller can build verbose output before they are cleared from context.

        Returns:
            The list of BlockDomain rows accumulated for the run.
        """
        rows_raw = demisto.context().get("block_domain_rows", "") or ""
        # Preserve responses on the instance for verbose output before clearing context.
        stored = demisto.context().get("panorama_responses", "") or ""
        if stored:
            try:
                self.responses = json.loads(stored)
            except (ValueError, TypeError) as err:
                demisto.debug(f"{LOG_TAG} Could not parse stored responses from context; ignoring. Error: {err}")
        demisto.setContext("commit_job_id", "")
        demisto.setContext("push_job_id", "")
        demisto.setContext("panorama_responses", "")
        demisto.setContext("block_domain_rows", "")
        try:
            return json.loads(rows_raw) if rows_raw else []
        except (ValueError, TypeError):
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
    command_name = "pan-os-commit"
    res_commit = run_execute_command(command_name, {"polling": True})
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
    command_name = "pan-os-commit-status"
    res_commit_status = run_execute_command(command_name, {"job_id": commit_job_id})
    responses.append(res_commit_status)
    # When pan-os-commit-status errors, Contents is a plain string instead of the nested dict.
    # Treat as a terminal failure to avoid a `.get()` crash on a string.
    raw_contents = res_commit_status[0].get("Contents", {}) if res_commit_status else {}
    if not isinstance(raw_contents, dict):
        commit_output = {"JobID": commit_job_id, "Status": "Failure"}
        return PollResult(
            response=CommandResults(
                outputs=commit_output,
                outputs_key_field="JobID",
                readable_output=tableToMarkdown("Commit Status:", commit_output, removeNull=True),
            ),
            args_for_next_run=args,
            continue_to_poll=False,
        )
    result_commit_status = raw_contents.get("response", {}).get("result", {}).get("job", {})
    job_result = result_commit_status.get("result")
    commit_output = {"JobID": commit_job_id, "Status": "Success" if job_result == "OK" else "Failure"}
    continue_to_poll = result_commit_status.get("status") != "FIN"
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
    command_name = "pan-os-push-to-device-group"
    res_push_to_device = run_execute_command(command_name, {"polling": True})
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
    command_name = "pan-os-push-status"
    res_push_status = run_execute_command(command_name, {"job_id": push_job_id})
    responses.append(res_push_status)
    # When pan-os-push-status errors, Contents is a plain string instead of the nested dict.
    # Treat as a terminal failure to avoid a `.get()` crash on a string (mirrors pan_os_commit_status).
    raw_contents = res_push_status[0].get("Contents", {}) if res_push_status else {}
    if is_error(res_push_status) or not isinstance(raw_contents, dict):
        push_output = {"JobID": push_job_id, "Status": "Failure"}
        return PollResult(
            response=CommandResults(
                outputs=push_output,
                outputs_key_field="JobID",
                readable_output=tableToMarkdown("Push to Device Group:", push_output, ["JobID", "Status"], removeNull=True),
            ),
            args_for_next_run=args,
            continue_to_poll=False,
        )
    push_status = raw_contents.get("response", {}).get("result", {}).get("job", {}).get("status", "")
    continue_to_poll = bool(push_status and push_status != "FIN")
    context_output = {"Status": push_status, "JobID": push_job_id}
    push_cr = CommandResults(
        outputs_key_field="JobID",
        outputs=context_output,
        readable_output=tableToMarkdown("Push to Device Group:", context_output, ["JobID", "Status"], removeNull=True),
    )
    return PollResult(
        response=push_cr,
        continue_to_poll=continue_to_poll,
        partial_result=CommandResults(readable_output=f"Waiting for Job-ID {push_job_id} to finish pushing the changes..."),
    )


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    try:
        args = demisto.args()
        demisto.debug(f"{LOG_TAG} block-domain invoked with {args=}")

        domain_list = argToList(args.get("domain_list", []))
        rule_name = args.get("rule_name", "Cortex - Block Domain")
        log_forwarding_name = args.get("log_forwarding_name", "")
        address_group = args.get("address_group", "Blocked Domains - Cortex")
        tag = args.get("tag", "cortex-blocked-domains")
        auto_commit = argToBoolean(args.get("auto_commit", True))
        verbose = argToBoolean(args.get("verbose", False))
        brands_to_run = argToList(args.get("brands", ",".join(SUPPORTED_BRANDS)))

        if not domain_list:
            return_error("domain_list argument is required.")

        valid_domains, failed_rows = validate_domains(domain_list)
        enabled_brands = get_enabled_brands()
        brands_to_run = brands_to_run or list(SUPPORTED_BRANDS)

        runnable_brands = [b for b in brands_to_run if b in SUPPORTED_BRANDS and b in enabled_brands]
        if not runnable_brands:
            return_error(
                f"No integrations were found for the brands {brands_to_run}. "
                f"Please verify the brand instances' setup. Supported brands: {SUPPORTED_BRANDS}."
            )

        results: list = list(failed_rows)
        command_responses: list = []  # accumulated per-command responses, used for verbose output.

        for brand in brands_to_run:
            if brand not in SUPPORTED_BRANDS:
                results.append(
                    build_result_row(
                        domain="",
                        brand=brand,
                        status=STATUS_FAILED,
                        result=RESULT_FAILED,
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
                        message=f"The brand {brand} isn't enabled.",
                    )
                )
            elif brand == "Panorama" and valid_domains:
                pan_os = PanOs(
                    {
                        # Key MUST match the YAML arg name; polling re-invocation validates it.
                        "domain_list": valid_domains,
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
                # A list means the run finished. Anything else (PollResult / bare CommandResults
                # from a freshly-started poll) means a job is in flight.
                if not isinstance(pan_os_result, list):
                    return_results(pan_os_result)
                    return
                results.extend(pan_os_result)
                command_responses.extend(pan_os.responses)

        return_results(build_final_command_results(results, verbose, command_responses))

    except Exception as ex:
        demisto.error(f"{LOG_TAG} block-domain failed: {traceback.format_exc()}")
        return_error(f"Failed to execute block-domain. Error: {ex!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
