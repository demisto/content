import ast
import json
import re

import demistomock as demisto
from CommonServerPython import *


POLLING = False
# Set by the commit and the push status functions when PAN-OS reported a terminal failure. Read by
# manage_pan_os_flow, which must then skip the push and report the failure instead of a success.
JOB_FAILURE_MESSAGE = ""

SUPPORTED_BRANDS = ["Panorama"]
PAN_OS_BRAND = "Panorama"

# PAN-OS returns this substring when an object does not exist. The generic "Request Failed." prefix
# is shared with real failures, so it must not be used for the not-found decision.
OBJECT_NOT_FOUND = "Object not present"
# Raised by pan-os-edit-custom-url-category / pan-os-edit-url-filter when the target object still
# carries uncommitted changes (@dirtyId).
DIRTY_OBJECT_ERROR = "Please commit the instance prior to editing"

URL_LIST_TYPE = "URL List"
MAX_URL_LENGTH = 255

# The description stamped on every object this script creates, so an operator can tell them apart
# from user-managed objects.
OBJECT_DESCRIPTION = "Created by the Cortex block-url script."

POLLING_INTERVAL = 30
POLLING_TIMEOUT = 1200

# A commit job that finished with any result other than "OK" failed. Warnings are not a failure.
COMMIT_JOB_FINISHED_STATUS = "FIN"
COMMIT_JOB_SUCCESS_RESULT = "OK"
# The terminal statuses of a push job. Anything else, including an empty status, means "keep polling".
PUSH_COMPLETED_STATUS = "Completed"
PUSH_FAILURE_STATUSES = ("FAIL", "Failed")


class BlockUrlError(Exception):
    """Raised when the PAN-OS flow cannot continue and the failure must be reported to the user."""


""" HELPER FUNCTIONS """


def _text(value: Any) -> str:
    """Normalize a PAN-OS context value that may be wrapped in a '#text' dictionary.

    PAN-OS returns plain strings for committed objects, but dictionaries carrying '#text' and
    '@dirtyId' keys while the object has uncommitted changes.
    Args:
        value (Any): The raw context value.
    Returns:
        The plain string value.
    """
    if isinstance(value, dict):
        return str(value.get("#text", ""))
    if value is None:
        return ""
    return str(value)


def _text_list(value: Any) -> list[str]:
    """Normalize a PAN-OS context value that holds zero, one or many possibly wrapped members.

    Args:
        value (Any): The raw context value, a single member or a list of members.
    Returns:
        A list of plain string values, without empty entries.
    """
    if value is None:
        return []
    members = value if isinstance(value, list) else [value]
    return [text for text in (_text(member) for member in members) if text]


def normalize_url(raw_url: str) -> tuple[str, str]:
    """Normalize a URL into the form PAN-OS custom URL categories expect.

    PAN-OS validates almost nothing: it stores a scheme, a wildcard or a mixed-case host verbatim
    and then silently fails to match them. Every rule below therefore prevents a silent non-block.
    Args:
        raw_url (str): The URL as supplied by the user.
    Returns:
        A tuple of (submitted_url, rejection_message). On rejection the submitted URL is empty.
    """
    url = (raw_url or "").strip()
    if not url:
        return "", "URL is empty."
    if re.search(r"\s", url):
        return "", "URL contains whitespace, which is not supported by PAN-OS custom URL categories."
    if "," in url:
        return "", "URL contains a comma, which would split it into two entries when submitted to PAN-OS."
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    if "://" in url:
        return "", "URL scheme is not supported. Only the http and https schemes are supported."
    if "*" in url:
        return "", "Wildcards are not supported and will not be passed to PAN-OS."
    url = url.rstrip("/")
    if not url:
        return "", "URL is empty."
    if len(url) > MAX_URL_LENGTH:
        return "", f"URL exceeds {MAX_URL_LENGTH} chars (PAN-OS limit)."
    return lowercase_host(url), ""


def lowercase_host(url: str) -> str:
    """Lowercase only the host part of a URL. PAN-OS does not fold case, and paths are case sensitive.

    Args:
        url (str): A scheme-less URL.
    Returns:
        The URL with a lowercased host.
    """
    host, separator, path = url.partition("/")
    return f"{host.lower()}{separator}{path}"


def partition_urls(url_list: list[str]) -> tuple[list[dict], list[dict]]:
    """Split the requested URLs into the ones that can be submitted and the ones that were rejected.

    Rejected URLs never reach any brand, and are reported with an empty SubmittedURL.
    Args:
        url_list (list[str]): The raw URLs supplied by the user.
    Returns:
        A tuple of (accepted entries, rejected entries).
    """
    accepted: list[dict] = []
    rejected: list[dict] = []
    for raw_url in url_list:
        submitted_url, rejection_message = normalize_url(raw_url)
        if rejection_message:
            rejected.append({"URL": raw_url, "SubmittedURL": "", "Result": "Failed", "Message": rejection_message})
        else:
            accepted.append({"URL": raw_url, "SubmittedURL": submitted_url})
    demisto.debug(f"BU: partitioned the URLs into {len(accepted)} accepted and {len(rejected)} rejected.")
    return accepted, rejected


def get_error_message(res: list[dict]) -> str:
    """Collect the contents of every error entry in a command response.

    Args:
        res (list[dict]): The response of demisto.executeCommand.
    Returns:
        The joined error messages, or an empty string when there was no error.
    """
    messages = [str(entry.get("Contents", "")) for entry in res or [] if is_error(entry)]
    return ", ".join(messages)


def raise_on_command_error(res: list[dict], object_description: str) -> None:
    """Raise a BlockUrlError with an actionable message when a command response holds an error.

    Args:
        res (list[dict]): The response of demisto.executeCommand.
        object_description (str): A human readable description of the PAN-OS object being handled.
    Raises:
        BlockUrlError: When the response contains an error entry.
    """
    message = get_error_message(res)
    if not message:
        return
    if DIRTY_OBJECT_ERROR in message:
        raise BlockUrlError(
            f"The {object_description} has uncommitted changes on PAN-OS, so it cannot be edited. "
            f"Commit the pending changes on PAN-OS and re-run the script. PAN-OS error: {message}"
        )
    raise BlockUrlError(message)


def get_relevant_context(original_context: dict[str, Any], key: str) -> dict | list:
    """Get the relevant context object from the execute_command response.

    Args:
        original_context (dict[str, Any]): The original context ('EntryContext') of the response.
        key (str): The key to extract from the original_context.
    Returns:
        A dict or a list that is the relevant command context.
    """
    if not original_context:
        return {}
    if relevant_context := original_context.get(key, {}):
        demisto.debug(f"BU: the {key=} was found in the first search.")
        return relevant_context
    for context_key in original_context:
        if context_key.startswith(key):
            demisto.debug(f"BU: the {key=} was found in the context as {context_key}")
            return original_context.get(context_key, {})
    return {}


def get_context_entry(res: list[dict], key: str) -> dict:
    """Get a single context entry of a given key from a command response.

    Args:
        res (list[dict]): The response of demisto.executeCommand.
        key (str): The context key to extract.
    Returns:
        The context entry as a dict, or an empty dict.
    """
    if not res:
        return {}
    context = get_relevant_context(res[0].get("EntryContext", {}), key)
    if isinstance(context, list):
        return context[0] if context else {}
    return context


def check_value_exist_in_context(value: str, context: list | dict, key: str) -> bool:
    """Verify if a specific value of a specific key is present in the context.

    Args:
        value (str): The value whose existence is checked.
        context (list | dict): The command context.
        key (str): The key to extract from the context.
    Returns:
        Whether the value is present.
    """
    items = [context] if isinstance(context, dict) else context
    for item in items or []:
        if _text(item.get(key)) == value:
            demisto.debug(f"BU: the {value=} was found.")
            return True
    demisto.debug(f"BU: the {value=} isn't in the context with the {key=}")
    return False


def is_polling_resume() -> bool:
    """Whether the current run is a polling round that resumes an earlier run.

    Returns:
        True when a commit or a push job is already in flight.
    """
    incident_context = demisto.context()
    return bool(demisto.get(incident_context, "commit_job_id") or demisto.get(incident_context, "push_job_id"))


def update_brands_to_run(brands_to_run: list) -> tuple[list, set]:
    """Delete the brands that were already executed from the list of brands to run.

    Used when at least one brand finished its execution before the polling of another brand is over.
    Args:
        brands_to_run (list): The list of brands that should be executed.
    Returns:
        The list of brands executed in previous runs, and the set of brands to execute now.
    """
    if PAN_OS_BRAND not in brands_to_run:
        return [], set(brands_to_run)
    incident_context = demisto.context()
    executed_brands = (incident_context.get("executed_brands", "[]")).replace("'", '"')
    try:
        executed_brands = json.loads(executed_brands)
    except json.JSONDecodeError:
        demisto.debug("BU: there was a failure in the json.loads for the executed_brands.")
        executed_brands = []
    updated_brands_to_run = {brand for brand in brands_to_run if brand not in executed_brands}
    demisto.debug(f"BU: removed {executed_brands=} from {brands_to_run=}")
    return executed_brands, updated_brands_to_run


def run_execute_command(command_name: str, args: dict[str, Any]) -> list[dict]:
    """Execute a command and return its raw results.

    Args:
        command_name (str): The name of the command to execute.
        args (dict[str, Any]): The arguments to pass to the command.
    Returns:
        A list of the command result entries.
    """
    demisto.debug(f"BU: Executing command: {command_name} with {args=}")
    res = demisto.executeCommand(command_name, args)
    demisto.debug(f"BU: The response of {command_name} is {res}")
    return res


""" CLIENT CLASS """


class PanOs:
    def __init__(self, args: dict) -> None:
        self.args = args
        self.responses: list = []
        self.is_panorama: bool = False
        self.device_group: str = ""
        self.already_present_urls: list[str] = []
        self.failure_message: str = ""

    """ TOPOLOGY """

    def detect_topology(self) -> None:
        """Detect whether the configured instance is a Panorama or a plain firewall.

        Panorama requires pre_post on every rule command and scopes objects by device group.
        """
        res_pan_os = run_execute_command("pan-os", {"cmd": "<show><system><info></info></system></show>", "type": "op"})
        self.responses.append(res_pan_os)
        raise_on_command_error(res_pan_os, "PAN-OS system information")
        context = get_relevant_context(res_pan_os[0].get("EntryContext", {}), "Panorama.Command")
        model = context.get("response", {}).get("result", {}).get("system", {}).get("model", "")  # type: ignore[union-attr]
        self.is_panorama = model == PAN_OS_BRAND
        demisto.debug(f"BU: detected {model=}, {self.is_panorama=}")

    def rule_scope_args(self) -> dict[str, Any]:
        """The scoping arguments every rule command needs on Panorama and must not get on a firewall.

        Returns:
            The extra arguments for the rule commands.
        """
        return {"pre_post": "pre-rulebase"} if self.is_panorama else {}

    def capture_device_group(self, context: dict) -> None:
        """Remember the device group PAN-OS echoed back, for the commit, the push and the xpath.

        Args:
            context (dict): A PAN-OS command context entry.
        """
        device_group = _text(context.get("DeviceGroup")) if isinstance(context, dict) else ""
        if device_group:
            self.device_group = device_group
            demisto.debug(f"BU: captured {self.device_group=}")

    """ CUSTOM URL CATEGORY """

    def get_custom_url_category(self) -> dict:
        """Read the custom URL category, treating "Object not present" as missing rather than failed.

        Returns:
            The category context entry, or an empty dict when the category does not exist.
        Raises:
            BlockUrlError: When the command failed for any other reason.
        """
        category = self.args["url_category"]
        res = run_execute_command("pan-os-get-custom-url-category", {"name": category})
        if error_message := get_error_message(res):
            if OBJECT_NOT_FOUND in error_message:
                demisto.debug(f"BU: the custom URL category {category=} does not exist yet.")
                return {}
            raise BlockUrlError(error_message)
        self.responses.append(res)
        context = get_context_entry(res, "Panorama.CustomURLCategory")
        self.capture_device_group(context)
        return context

    def ensure_url_category(self, existing: dict, urls: list[str]) -> list[str]:
        """Create the custom URL category, or append only the URLs it does not hold yet.

        Args:
            existing (dict): The existing category context, or an empty dict.
            urls (list[str]): The normalized URLs to block.
        Returns:
            The URLs that were already present in the category.
        Raises:
            BlockUrlError: When the category exists with a type other than "URL List", or on failure.
        """
        category = self.args["url_category"]
        if not existing:
            return self.create_url_category(urls)
        category_type = _text(existing.get("Type"))
        if category_type != URL_LIST_TYPE:
            # PAN-OS silently converts a foreign-type category to a URL List and merges its members
            # into the site list, destroying the object. There is no server-side protection.
            raise BlockUrlError(
                f"Won't modify a user-managed category '{category}' of type '{category_type}'. "
                f"Only categories of type '{URL_LIST_TYPE}' are managed by this script. "
                f"Use the url_category argument to point to a different category."
            )
        existing_sites = _text_list(existing.get("Sites"))
        missing_urls = [url for url in urls if url not in existing_sites]
        already_present = [url for url in urls if url in existing_sites]
        if not missing_urls:
            demisto.debug(f"BU: every URL is already present in the category {category=}, skipping the edit.")
            return already_present
        res = run_execute_command("pan-os-edit-custom-url-category", {"name": category, "action": "add", "sites": missing_urls})
        self.responses.append(res)
        raise_on_command_error(res, f"custom URL category '{category}'")
        return already_present

    def create_url_category(self, urls: list[str]) -> list[str]:
        """Create the custom URL category with the requested URLs.

        Args:
            urls (list[str]): The normalized URLs to block.
        Returns:
            An empty list, since a new category holds none of the URLs yet.
        Raises:
            BlockUrlError: When the creation failed.
        """
        category = self.args["url_category"]
        res = run_execute_command(
            "pan-os-create-custom-url-category",
            {"name": category, "type": URL_LIST_TYPE, "sites": urls, "description": OBJECT_DESCRIPTION},
        )
        self.responses.append(res)
        raise_on_command_error(res, f"custom URL category '{category}'")
        self.capture_device_group(get_context_entry(res, "Panorama.CustomURLCategory"))
        return []

    """ URL FILTERING PROFILE """

    def ensure_url_filtering_profile(self) -> None:
        """Create the URL filtering profile, or attach the category to the existing one.

        Raises:
            BlockUrlError: When the profile could not be read, created or edited.
        """
        profile = self.args["url_filtering_profile"]
        res = run_execute_command("pan-os-get-url-filter", {"name": profile})
        error_message = get_error_message(res)
        if error_message and OBJECT_NOT_FOUND not in error_message:
            raise BlockUrlError(error_message)
        if error_message:
            demisto.debug(f"BU: the URL filtering profile {profile=} does not exist yet.")
            self.create_url_filtering_profile()
            return
        self.responses.append(res)
        context = get_context_entry(res, "Panorama.URLFilter")
        self.capture_device_group(context)
        self.attach_category_to_profile(context)

    def create_url_filtering_profile(self) -> None:
        """Create the URL filtering profile with the category blocked for Site Access.

        Raises:
            BlockUrlError: When the creation failed.
        """
        profile = self.args["url_filtering_profile"]
        res = run_execute_command(
            "pan-os-create-url-filter",
            {
                "name": profile,
                "url_category": self.args["url_category"],
                "action": "block",
                "description": OBJECT_DESCRIPTION,
            },
        )
        self.responses.append(res)
        raise_on_command_error(res, f"URL filtering profile '{profile}'")
        self.capture_device_group(get_context_entry(res, "Panorama.URLFilter"))

    def attach_category_to_profile(self, context: dict) -> None:
        """Add the category to the profile block list when it is not attached yet.

        Args:
            context (dict): The existing profile context.
        Raises:
            BlockUrlError: When the edit failed.
        """
        profile = self.args["url_filtering_profile"]
        category = self.args["url_category"]
        if self.is_category_attached(context, category):
            demisto.debug(f"BU: the category {category=} is already blocked by the profile {profile=}.")
            return
        res = run_execute_command(
            "pan-os-edit-url-filter",
            {
                "name": profile,
                "element_to_change": "block_categories",
                "element_value": category,
                "add_remove_element": "add",
            },
        )
        self.responses.append(res)
        raise_on_command_error(res, f"URL filtering profile '{profile}'")

    @staticmethod
    def is_category_attached(context: dict, category: str) -> bool:
        """Whether the category is already in the block list of the profile.

        Args:
            context (dict): The profile context.
            category (str): The custom URL category name.
        Returns:
            Whether the category is attached.
        """
        if category in _text_list(context.get("block_categories")):
            return True
        categories = context.get("Category") or []
        if isinstance(categories, dict):
            categories = [categories]
        return any(_text(item.get("Name")) == category for item in categories)

    """ TAG AND SECURITY RULE """

    def ensure_tag(self) -> None:
        """Create the tag object before any rule references it.

        pan-os-create-rule fails with "tag '<name>' is not a valid reference" when the tag object
        does not exist. Re-creating an existing tag succeeds, so this call is idempotent. A failure
        here is tolerated rather than aborting the whole flow.
        """
        tag = self.args.get("tag", "")
        if not tag:
            return
        res = run_execute_command("pan-os-create-tag", {"name": tag})
        if error_message := get_error_message(res):
            demisto.debug(f"BU: could not create the tag {tag=}, continuing without it. {error_message=}")
            return
        self.responses.append(res)

    def ensure_security_rule(self) -> None:
        """Create the security rule when it is missing, then attach the profile and move it to the top.

        Raises:
            BlockUrlError: When the rulebase could not be read or the rule could not be created.
        """
        rule_name = self.args["rule_name"]
        res_list_rules = run_execute_command("pan-os-list-rules", self.rule_scope_args())
        self.responses.append(res_list_rules)
        raise_on_command_error(res_list_rules, f"security rule '{rule_name}'")
        context = get_relevant_context(res_list_rules[0].get("EntryContext", {}), "Panorama.SecurityRule")
        if check_value_exist_in_context(rule_name, context, "Name"):
            demisto.debug(f"BU: reusing the existing security rule {rule_name=}.")
            self.add_tag_to_rule()
        else:
            self.create_security_rule()
        self.apply_profile_to_rule()
        self.move_rule_to_top()

    def add_tag_to_rule(self) -> None:
        """Add the configured tag to an existing rule unconditionally.

        Uses behaviour=add so the rule's existing tags are preserved rather than replaced. The edit
        is issued every run because the rule may have been changed outside this script (for example
        through the PAN-OS UI), so the fetched tag list can be stale. Adding an already-present tag
        is a no-op on the device, so this stays idempotent.
        Raises:
            BlockUrlError: When the edit failed.
        """
        tag = self.args.get("tag", "")
        if not tag:
            return
        rule_name = self.args["rule_name"]
        edit_args: dict[str, Any] = {
            "rulename": rule_name,
            "element_to_change": "tag",
            "element_value": tag,
            "behaviour": "add",
        }
        edit_args |= self.rule_scope_args()
        res = run_execute_command("pan-os-edit-rule", edit_args)
        self.responses.append(res)
        raise_on_command_error(res, f"security rule '{rule_name}'")

    def create_security_rule(self) -> None:
        """Create the security rule that carries the URL filtering profile.

        Raises:
            BlockUrlError: When the creation failed.
        """
        rule_name = self.args["rule_name"]
        create_rule_args: dict[str, Any] = {
            "rulename": rule_name,
            # The action is ALLOW by design. The URL filtering profile attached to this rule performs
            # the blocking, and PAN-OS only inspects traffic with a profile when the rule allows it.
            # A "deny" rule would drop the traffic before the profile runs, so do not change this.
            "action": "allow",
            "source": "any",
            "destination": "any",
            "application": "any",
            "description": OBJECT_DESCRIPTION,
        }
        if tag := self.args.get("tag", ""):
            create_rule_args["tags"] = tag
        if log_forwarding_name := self.args.get("log_forwarding_name", ""):
            create_rule_args["log_forwarding"] = log_forwarding_name
        create_rule_args |= self.rule_scope_args()
        res = run_execute_command("pan-os-create-rule", create_rule_args)
        self.responses.append(res)
        raise_on_command_error(res, f"security rule '{rule_name}'")

    def apply_profile_to_rule(self) -> None:
        """Attach the URL filtering profile to the security rule.

        Raises:
            BlockUrlError: When the command failed.
        """
        rule_name = self.args["rule_name"]
        apply_args: dict[str, Any] = {
            "profile_type": "url-filtering",
            "rule_name": rule_name,
            "profile_name": self.args["url_filtering_profile"],
        }
        apply_args |= self.rule_scope_args()
        res = run_execute_command("pan-os-apply-security-profile", apply_args)
        self.responses.append(res)
        raise_on_command_error(res, f"security rule '{rule_name}'")

    def move_rule_to_top(self) -> None:
        """Move the security rule to the top of the rulebase.

        pan-os-create-rule appends the rule at the bottom, where an earlier allow rule would defeat
        the block, so the move is mandatory. It is idempotent ("Rule already at the top"), therefore
        it runs on every execution.
        Raises:
            BlockUrlError: When the command failed.
        """
        rule_name = self.args["rule_name"]
        move_args: dict[str, Any] = {"rulename": rule_name, "where": "top"}
        move_args |= self.rule_scope_args()
        res = run_execute_command("pan-os-move-rule", move_args)
        self.responses.append(res)
        raise_on_command_error(res, f"security rule '{rule_name}'")

    """ FLOW """

    def reduce_pan_os_responses(self) -> list[list[dict]]:
        """Reduce the stored responses to the parts the later polling rounds need.

        Returns:
            A list containing the relevant parts of the command responses.
        """
        demisto.debug("BU: updating the responses in reduce_pan_os_responses.")
        reduced_responses = []
        for res in self.responses:
            current_new_res = []
            for entry in res:
                current_new_res.append(
                    {
                        "HumanReadable": entry.get("HumanReadable"),
                        "Contents": entry.get("Contents"),
                        "Type": entry.get("Type"),
                        "Metadata": entry.get("Metadata"),
                    }
                )
            reduced_responses.append(current_new_res)
        demisto.debug(f"BU: {len(reduced_responses)=}, {len(self.responses)=}")
        return reduced_responses

    def save_state_to_context(self) -> None:
        """Persist the state the next polling round needs."""
        demisto.setContext("panorama_responses", str(self.reduce_pan_os_responses()))
        demisto.setContext("pan_os_device_group", self.device_group)

    def restore_state_from_context(self, incident_context: dict) -> None:
        """Restore the state saved by the previous polling round.

        Args:
            incident_context (dict): The incident context.
        """
        self.responses = ast.literal_eval(incident_context.get("panorama_responses", "") or "[]")
        self.device_group = demisto.get(incident_context, "pan_os_device_group") or ""

    def start_pan_os_flow(self) -> tuple[list, bool]:
        """Run the configuration part of the PAN-OS flow.

        Returns:
            A tuple of the command results, and whether the changes should be committed. The results
            are populated only when the flow failed and there is nothing left to commit.
        """
        try:
            self.detect_topology()
            existing_category = self.get_custom_url_category()
            self.already_present_urls = self.ensure_url_category(existing_category, self.submitted_urls())
            self.ensure_url_filtering_profile()
            self.ensure_tag()
            self.ensure_security_rule()
        except BlockUrlError as error:
            demisto.debug(f"BU: the PAN-OS flow failed. {error=}")
            self.failure_message = str(error)
            return self.pan_os_finish(), False
        return [], bool(self.args.get("auto_commit", True))

    def submitted_urls(self) -> list[str]:
        """The normalized URLs that are submitted to PAN-OS.

        Returns:
            The list of submitted URLs.
        """
        return [entry["SubmittedURL"] for entry in self.args["url_entries"]]

    def adopt_job_failure(self) -> bool:
        """Adopt a commit or push job failure reported by the polling functions.

        The polling functions run outside the class and communicate a terminal PAN-OS job failure
        through the JOB_FAILURE_MESSAGE global, since a failed job comes back as a type-1 success
        entry that the is_error sweep in prepare_context_and_hr_multiple_executions cannot detect.
        Returns:
            Whether a job failure was adopted.
        """
        global JOB_FAILURE_MESSAGE
        if not JOB_FAILURE_MESSAGE:
            return False
        demisto.debug(f"BU: adopting the job failure {JOB_FAILURE_MESSAGE=}")
        self.failure_message = JOB_FAILURE_MESSAGE
        JOB_FAILURE_MESSAGE = ""
        return True

    def pan_os_finish(self) -> list[CommandResults]:
        """Clear the polling state from the context and build the final results.

        Returns:
            The list of Command Results.
        """
        demisto.setContext("push_job_id", "")
        demisto.setContext("commit_job_id", "")
        demisto.setContext("panorama_responses", "")
        demisto.setContext("pan_os_device_group", "")
        details = {
            "brand": PAN_OS_BRAND,
            "rule_name": self.args.get("rule_name", ""),
            "url_category": self.args.get("url_category", ""),
            "job_id": self.args.get("commit_job_id") or "",
            "already_present": self.already_present_urls,
            "failure_message": self.failure_message,
        }
        return prepare_context_and_hr_multiple_executions(
            self.responses, bool(self.args.get("verbose", False)), self.args["url_entries"], details
        )

    def manage_pan_os_flow(self) -> CommandResults | list[CommandResults] | PollResult:
        """Manage the different states of the PAN-OS flow.

        1. The flow start: create or reuse the category, the profile, the tag and the rule.
        2. If auto_commit is true and there were changes, execute pan-os-commit.
        3. There is a commit job ID, check the status of the commit.
        4. The commit finished, on Panorama push the changes to the device group.
        5. There is a push job ID, check the status of the push.
        6. The push finished, build the final results.
        Returns:
            A PollResult while polling, otherwise a Command Result or a list of Command Results.
        """
        incident_context = demisto.context()
        auto_commit = self.args["auto_commit"]
        commit_job_id = self.args.get("commit_job_id")
        context_push_job_id = demisto.get(incident_context, "push_job_id")
        context_commit_job_id = demisto.get(incident_context, "commit_job_id")
        is_polling_reentry = bool(commit_job_id)
        if not is_polling_reentry and (context_commit_job_id or context_push_job_id):
            demisto.debug(
                f"BU: stale polling context on a fresh invocation "
                f"(commit={context_commit_job_id!r}, push={context_push_job_id!r}); clearing."
            )
            demisto.setContext("commit_job_id", "")
            demisto.setContext("push_job_id", "")
            demisto.setContext("panorama_responses", "")
            demisto.setContext("pan_os_device_group", "")
            context_push_job_id = None
        push_job_id = context_push_job_id if is_polling_reentry else None
        # state 5
        if push_job_id:
            demisto.debug(f"BU: has a {push_job_id=}")
            self.restore_state_from_context(incident_context)
            self.args["push_job_id"] = push_job_id
            res_push_status = pan_os_push_status(self.args, self.responses)
            # state 6
            if not POLLING:
                demisto.debug("BU: finished polling, finishing the flow.")
                self.adopt_job_failure()
                return self.pan_os_finish()
            self.save_state_to_context()
            return res_push_status
        # state 3
        if commit_job_id:
            demisto.debug(f"BU: has a {commit_job_id=}")
            self.args["commit_job_id"] = commit_job_id
            self.restore_state_from_context(incident_context)
            poll_commit_status = pan_os_commit_status(self.args, self.responses)
            if POLLING:
                self.save_state_to_context()
                return poll_commit_status
            # A commit that PAN-OS finished with a failure must not be pushed: the pushed candidate
            # config never passed validation, and reporting success here would tell the user the URLs
            # are blocked when they are not.
            if self.adopt_job_failure():
                demisto.debug("BU: the commit job failed, skipping the push.")
                return self.pan_os_finish()
            # state 4
            self.detect_topology()
            if not self.is_panorama:
                demisto.debug("BU: not a Panorama instance, not pushing to the device group.")
                return self.pan_os_finish()
            self.args["device_group"] = self.device_group
            poll_push_to_device = pan_os_push_to_device(self.args, self.responses)
            if not POLLING:
                demisto.debug("BU: nothing to push, finishing the flow.")
                self.adopt_job_failure()
                return self.pan_os_finish()
            self.save_state_to_context()
            return poll_push_to_device

        # state 1
        results, should_commit = self.start_pan_os_flow()
        if not should_commit:
            if results:
                return results
            not_committed = CommandResults(
                readable_output=f"Not committing the changes in PAN-OS, since {auto_commit=}. "
                f"Please do so manually for the changes to take effect."
            )
            final_results = self.pan_os_finish()
            final_results.append(not_committed)
            return final_results
        # state 2
        self.args["device_group"] = self.device_group
        self.args["is_panorama"] = self.is_panorama
        poll_result = pan_os_commit(self.args, self.responses)
        if not POLLING:
            return self.pan_os_finish()
        self.save_state_to_context()
        return poll_result


""" STANDALONE FUNCTION """


def job_details(job: dict) -> str:
    """Extract the human readable reason a PAN-OS job reports for its outcome.

    PAN-OS returns the reason either as a plain string or as a {"line": [...]} structure, and the
    lines may themselves be nested lists.
    Args:
        job (dict): The job element of a pan-os-commit-status response.
    Returns:
        The joined details, or a placeholder when PAN-OS reported none.
    """
    details = job.get("details")
    if isinstance(details, dict):
        details = details.get("line")
    if isinstance(details, list):
        flattened = [str(item) for line in details for item in (line if isinstance(line, list) else [line])]
        return "; ".join(flattened) or "none reported"
    return str(details) if details else "none reported"


def build_commit_args(args: dict) -> dict[str, Any]:
    """Build the arguments of pan-os-commit, scoped as narrowly as PAN-OS allows.

    PAN-OS has no per-object commit, so the device group is the finest available granularity.
    Args:
        args (dict): The flow arguments.
    Returns:
        The arguments for pan-os-commit.
    """
    url_count = len(args.get("url_entries", []))
    commit_args: dict[str, Any] = {
        "polling": True,
        "description": f"Block URL - {url_count} URL(s) - {args.get('incident_id', '')}",
        "exclude_device_network_configuration": True,
    }
    device_group = args.get("device_group", "")
    if args.get("is_panorama") and device_group:
        commit_args["device-group"] = device_group
        # Only safe when the objects live in the device group and not in /config/shared.
        commit_args["exclude_shared_objects"] = True
    return commit_args


def build_push_args(args: dict) -> dict[str, Any]:
    """Build the arguments of pan-os-push-to-device-group.

    Args:
        args (dict): The flow arguments.
    Returns:
        The arguments for pan-os-push-to-device-group.
    """
    push_args: dict[str, Any] = {
        "polling": True,
        "description": f"Block URL - {args.get('incident_id', '')}",
    }
    if device_group := args.get("device_group", ""):
        push_args["device-group"] = device_group
    return push_args


def create_final_human_readable(failure_message: str, context: list[dict]) -> str:
    """Create the human readable summary of the script.

    Args:
        failure_message (str): A failure message if relevant.
        context (list[dict]): The final context records.
    Returns:
        The human readable summary.
    """
    headers = ["URL", "SubmittedURL", "Result", "Brand", "RuleName", "URLCategory", "JobID", "Message"]
    name = "Failed to block the URL/s" if failure_message else "URL/s blocking summary"
    demisto.debug(f"BU: creating the final human readable for {failure_message=}")
    return tableToMarkdown(name=name, t=context, headers=headers, removeNull=True)


def create_final_context(used_integration: str, url_entries: list[dict], details: dict) -> list[dict]:
    """Create the context records of the script, one per URL.

    Args:
        used_integration (str): The integration that was used.
        url_entries (list[dict]): The accepted URL entries, holding URL and SubmittedURL.
        details (dict): The flow details, holding the rule name, the category, the job ID, the URLs
            that were already present and the failure message.
    Returns:
        The list of context records.
    """
    failure_message = details.get("failure_message", "")
    already_present = details.get("already_present", [])
    context = []
    for entry in url_entries:
        submitted_url = entry.get("SubmittedURL", "")
        if failure_message:
            result, message = "Failed", failure_message
        elif submitted_url in already_present:
            result, message = "Skipped", "URL already present in the category."
        else:
            result, message = "Success", "URL was blocked successfully."
        context.append(
            {
                "URL": entry.get("URL") or None,
                "SubmittedURL": submitted_url or None,
                "Brand": used_integration or None,
                "Result": result or None,
                "Message": message or None,
                "RuleName": details.get("rule_name") or None,
                "URLCategory": details.get("url_category") or None,
                "JobID": details.get("job_id") or None,
            }
        )
    return context


def create_rejected_results(rejected: list[dict]) -> CommandResults:
    """Create the results of the URLs that were rejected before any brand was contacted.

    Args:
        rejected (list[dict]): The rejected URL entries.
    Returns:
        A Command Results holding the rejected records.
    """
    context = [
        {
            "URL": entry.get("URL") or None,
            "SubmittedURL": None,
            "Brand": None,
            "Result": "Failed",
            "Message": entry.get("Message") or None,
            "RuleName": None,
            "URLCategory": None,
            "JobID": None,
        }
        for entry in rejected
    ]
    headers = ["URL", "SubmittedURL", "Result", "Message"]
    return CommandResults(
        readable_output=tableToMarkdown(name="URL/s that were not submitted", t=context, headers=headers, removeNull=True),
        outputs_prefix="BlockURLResults",
        outputs=context,
        raw_response=context,
    )


def prepare_context_and_hr_multiple_executions(
    responses: list[list[dict]], verbose: bool, url_entries: list[dict], details: dict
) -> list[CommandResults]:
    """Create the context and the human readable of a flow made of multiple command executions.

    Args:
        responses (list[list[dict]]): The responses returned from the command executions.
        verbose (bool): Whether to return a human readable entry per command or only the summary.
        url_entries (list[dict]): The accepted URL entries.
        details (dict): The flow details.
    Returns:
        A list containing the relevant Command Results.
    """
    demisto.debug(f"BU: in prepare_context_and_hr_multiple_executions, {len(responses)=}")
    results = []
    failed_messages = []
    used_integration = details.get("brand", "")
    if responses and responses[0]:
        used_integration = responses[0][0].get("Metadata", {}).get("brand") or used_integration

    for res in responses:
        for entry in res:
            command_hr = entry.get("HumanReadable")
            message = f"{used_integration}: {entry.get('Contents', '')}"
            if is_error(entry):
                demisto.debug(f"BU: a failure was found {message=}")
                failed_messages.append(message)
            elif command_hr and command_hr != str(None):
                results.append(CommandResults(readable_output=f"{used_integration}:\n{command_hr}"))
            elif message and isinstance(entry.get("Contents"), str):
                results.append(CommandResults(readable_output=message))
    if explicit_failure := details.get("failure_message", ""):
        failed_messages.append(explicit_failure)
    details = details | {"failure_message": ", ".join(failed_messages)}

    final_context = create_final_context(used_integration, url_entries, details)
    final_cr = CommandResults(
        readable_output=create_final_human_readable(details["failure_message"], final_context),
        outputs_prefix="BlockURLResults",
        outputs=final_context,
        raw_response=final_context,
    )
    if verbose:
        results.append(final_cr)
    else:
        results = [final_cr]
    return results


""" COMMAND FUNCTION """


@polling_function(
    name="block-url",
    interval=POLLING_INTERVAL,
    timeout=POLLING_TIMEOUT,
)
def pan_os_commit(args: dict, responses: list) -> PollResult:
    """Execute pan-os-commit.

    Args:
        args (dict): The arguments of the flow.
        responses (list): The responses of the command executions so far.
    Returns:
        A PollResult object.
    """
    res_commit = run_execute_command("pan-os-commit", build_commit_args(args))
    responses.append(res_commit)
    polling_args = res_commit[0].get("Metadata", {}).get("pollingArgs", {})
    job_id = polling_args.get("commit_job_id")
    if job_id:
        context_output = {"JobID": job_id, "Status": "Pending"}
        continue_to_poll = True
        commit_output = CommandResults(
            outputs=context_output, readable_output=tableToMarkdown("Commit Status:", context_output, removeNull=True)
        )
        demisto.debug(f"BU: initiated a commit execution {job_id=}")
        demisto.setContext("commit_job_id", job_id)
    else:  # nothing to commit in PAN-OS, no reason to poll.
        commit_output = res_commit[0].get("Contents") or "There are no changes to commit."  # type: ignore[assignment]
        demisto.debug(f"BU: no job_id, {commit_output}")
        continue_to_poll = False
    global POLLING
    POLLING = continue_to_poll

    args_for_next_run = args | {
        "commit_job_id": job_id,
        "interval_in_seconds": arg_to_number(args.get("interval_in_seconds", POLLING_INTERVAL)),
        "timeout": arg_to_number(args.get("timeout", POLLING_TIMEOUT)),
        "polling": True,
    }
    return PollResult(
        response=commit_output,
        continue_to_poll=continue_to_poll,
        args_for_next_run=args_for_next_run,
        partial_result=CommandResults(readable_output=f"Waiting for commit job ID {job_id} to finish..."),
    )


@polling_function(
    name="block-url",
    interval=POLLING_INTERVAL,
    timeout=POLLING_TIMEOUT,
)
def pan_os_commit_status(args: dict, responses: list) -> PollResult:
    """Check the status of the commit in PAN-OS.

    A commit that finishes with warnings is a success: the lab returns warnings on every commit. A
    commit that finishes with any result other than "OK" is a failure, and PAN-OS reports it as a
    successful command entry carrying a failed job, so the failure is published through the
    JOB_FAILURE_MESSAGE global for manage_pan_os_flow to skip the push and report it.
    Args:
        args (dict): The arguments of the flow.
        responses (list): The responses of the command executions so far.
    Returns:
        A PollResult object.
    """
    commit_job_id = args["commit_job_id"]
    res_commit_status = run_execute_command("pan-os-commit-status", {"job_id": commit_job_id})
    responses.append(res_commit_status)
    global POLLING, JOB_FAILURE_MESSAGE
    raw_contents = res_commit_status[0].get("Contents") if res_commit_status else None
    if is_error(res_commit_status) or not isinstance(raw_contents, dict):
        POLLING = False
        error_reason = get_error_message(res_commit_status) or str(raw_contents)
        JOB_FAILURE_MESSAGE = (
            f"The PAN-OS commit job {commit_job_id} status could not be read, so the changes were not "
            f"pushed and the URLs are not blocked. PAN-OS reason: {error_reason}"
        )
        demisto.debug(f"BU: the commit status returned an error entry. {JOB_FAILURE_MESSAGE=}")
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
    job = raw_contents.get("response", {}).get("result", {}).get("job", {})
    job_result = job.get("result")
    continue_to_poll = job.get("status") != COMMIT_JOB_FINISHED_STATUS
    job_failed = not continue_to_poll and job_result != COMMIT_JOB_SUCCESS_RESULT
    commit_output = {"JobID": commit_job_id, "Status": "Failure" if job_failed else "Success"}
    POLLING = continue_to_poll
    if job_failed:
        JOB_FAILURE_MESSAGE = (
            f"The PAN-OS commit job {commit_job_id} failed with the result '{job_result}', so the changes were "
            f"not pushed and the URLs are not blocked. PAN-OS details: {job_details(job)}"
        )
        demisto.debug(f"BU: the commit job failed. {JOB_FAILURE_MESSAGE=}")
    demisto.debug(f"BU: after pan-os-commit-status {continue_to_poll=} {commit_job_id=} {job_result=}")
    return PollResult(
        response=CommandResults(
            outputs=commit_output,
            outputs_key_field="JobID",
            readable_output=tableToMarkdown("Commit Status:", commit_output, removeNull=True),
        ),
        args_for_next_run=args,
        continue_to_poll=continue_to_poll,
    )


@polling_function(
    name="block-url",
    interval=POLLING_INTERVAL,
    timeout=POLLING_TIMEOUT,
)
def pan_os_push_to_device(args: dict, responses: list) -> PollResult:
    """Execute pan-os-push-to-device-group.

    Args:
        args (dict): The arguments of the flow.
        responses (list): The responses of the command executions so far.
    Returns:
        A PollResult object.
    """
    res_push_to_device = run_execute_command("pan-os-push-to-device-group", build_push_args(args))
    responses.append(res_push_to_device)
    polling_args = res_push_to_device[0].get("Metadata", {}).get("pollingArgs", {})
    job_id = polling_args.get("push_job_id")
    device_group = polling_args.get("device-group")
    demisto.debug(f"BU: the polling args are {job_id=} {device_group=}")
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
    name="block-url",
    interval=POLLING_INTERVAL,
    timeout=POLLING_TIMEOUT,
)
def pan_os_push_status(args: dict, responses: list) -> PollResult:
    """Check the status of the push in PAN-OS.

    The status is read from the context, since the human readable output of pan-os-push-status is
    nearly empty while the job is still settling.
    Args:
        args (dict): The arguments of the flow.
        responses (list): The responses of the command executions so far.
    Returns:
        A PollResult object.
    """
    push_job_id = args["push_job_id"]
    res_push_status = run_execute_command("pan-os-push-status", {"job_id": push_job_id})
    responses.append(res_push_status)
    global POLLING, JOB_FAILURE_MESSAGE
    if is_error(res_push_status):
        POLLING = False
        error_reason = get_error_message(res_push_status)
        JOB_FAILURE_MESSAGE = (
            f"The PAN-OS push job {push_job_id} status could not be read, so the committed changes were "
            f"not confirmed as applied and the URLs may not be blocked. PAN-OS reason: {error_reason}"
        )
        demisto.debug(f"BU: the push status returned an error entry. {JOB_FAILURE_MESSAGE=}")
        push_output = {"JobID": push_job_id, "Status": "Failure"}
        return PollResult(
            response=CommandResults(
                outputs=push_output,
                outputs_key_field="JobID",
                readable_output=tableToMarkdown("Push to Device Group:", push_output, ["JobID", "Status"], removeNull=True),
            ),
            continue_to_poll=False,
        )
    push_context = get_context_entry(res_push_status, "Panorama.Push")
    push_status = _text(push_context.get("Status"))
    push_failed = push_status in PUSH_FAILURE_STATUSES
    # An empty status means the job is still settling, not that it succeeded. Treating it as done
    # would report a full success for a push that never finished. The polling decorator timeout is
    # the safety net for a status that never resolves.
    continue_to_poll = not push_failed and push_status != PUSH_COMPLETED_STATUS
    demisto.debug(f"BU: after pan-os-push-status {push_status=} {continue_to_poll=} {push_failed=}")
    context_output = {"Status": push_status, "JobID": push_job_id}
    push_cr = CommandResults(
        outputs_key_field="JobID",
        outputs=context_output,
        readable_output=tableToMarkdown("Push to Device Group:", context_output, ["JobID", "Status"], removeNull=True),
    )
    POLLING = continue_to_poll
    if push_failed:
        details = _text(push_context.get("Details")) or _text(push_context.get("Errors"))
        JOB_FAILURE_MESSAGE = (
            f"The PAN-OS push job {push_job_id} failed with the status '{push_status}', so the committed changes "
            f"were not applied to the managed firewalls and the URLs are not blocked. PAN-OS details: "
            f"{details or 'none reported'}"
        )
        demisto.debug(f"BU: the push job failed. {JOB_FAILURE_MESSAGE=}")
    return PollResult(
        response=push_cr,
        continue_to_poll=continue_to_poll,
        partial_result=CommandResults(readable_output=f"Waiting for Job-ID {push_job_id} to finish pushing the changes..."),
    )


""" MAIN FUNCTION """


def main():  # pragma: no cover
    try:
        args = demisto.args()
        demisto.debug(f"BU: the script block-url was called with the arguments {args=}")
        url_list = argToList(args.get("url_list", []))
        brands_to_run = argToList(args.get("brands", ",".join(SUPPORTED_BRANDS)))
        verbose = argToBoolean(args.get("verbose", False))
        modules = demisto.getModules()
        enabled_brands = {module.get("brand") for module in modules.values() if module.get("state") == "active"}
        demisto.debug(f"BU: the enabled modules are: {enabled_brands=}, {brands_to_run=}")

        executed_brands, updated_brands_to_run = update_brands_to_run(brands_to_run)
        accepted_urls, rejected_urls = partition_urls(url_list)

        results: list = []
        if rejected_urls and not is_polling_resume():
            results.append(create_rejected_results(rejected_urls))

        for brand in updated_brands_to_run:
            demisto.debug(f"BU: the current brand is {brand}")
            if brand not in enabled_brands:
                results.append(CommandResults(readable_output=f"The brand {brand} isn't enabled."))
                executed_brands.append(brand)
                continue
            if brand != PAN_OS_BRAND:
                return_error(
                    f"The brand {brand} isn't a part of the supported integrations for 'block-url'. "
                    f"The supported integrations are: {', '.join(SUPPORTED_BRANDS)}."
                )
            if not accepted_urls:
                results.append(CommandResults(readable_output="There are no valid URLs to block."))
                executed_brands.append(brand)
                continue
            brand_args = {
                "url_list": [entry["SubmittedURL"] for entry in accepted_urls],
                "url_entries": accepted_urls,
                "rule_name": args.get("rule_name", "Cortex - Block URLs"),
                "url_category": args.get("url_category", "Blocked URLs - Cortex"),
                "url_filtering_profile": args.get("url_filtering_profile", "Cortex - Block URL profile"),
                "log_forwarding_name": args.get("log_forwarding_name", ""),
                "tag": args.get("tag", "cortex-blocked-urls"),
                "auto_commit": argToBoolean(args.get("auto_commit", True)),
                "verbose": verbose,
                "brands": brands_to_run,
                "commit_job_id": args.get("commit_job_id"),
                "incident_id": demisto.incident().get("id", ""),
                "polling": True,
            }
            results.append(PanOs(brand_args).manage_pan_os_flow())
            if not POLLING:
                demisto.debug("BU: not in a polling mode, adding Panorama to the executed_brands.")
                executed_brands.append(brand)

        if POLLING:
            demisto.debug(f"BU: updating the executed_brands {executed_brands=}")
            demisto.setContext("executed_brands", str(executed_brands))
        elif PAN_OS_BRAND in brands_to_run:
            demisto.debug("BU: not in a polling mode, initializing the executed_brands.")
            demisto.setContext("executed_brands", "")
        return_results(results)

    except Exception as ex:
        return_error(f"Failed to execute block-url. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
