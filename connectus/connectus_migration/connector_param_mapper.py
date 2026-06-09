import json
import logging
from pathlib import Path
from typing import Any

import typer
import yaml

logger = logging.getLogger(__name__)

main = typer.Typer()

FETCH_ASSETS_CAPABILITIES = "Fetch Assets and Vulnerabilities"
FETCH_ISSUES_CAPABILITIES = "Fetch Issues"
FETCH_EVENTS_CAPABILITIES = "Log Collection"
FETCH_SECRETS_CAPABILITIES = "Fetch Secrets"
FETCH_INDICATORS_CAPABILITIES = "Threat Intelligence & Enrichment"
AUTOMATION_CAPABILITY = "Automation"

COMMAND_TO_CAPABILITY: dict[str, str] = {
    "fetch-incidents": FETCH_ISSUES_CAPABILITIES,
    "fetch-events": FETCH_EVENTS_CAPABILITIES,
    "fetch-credentials": FETCH_SECRETS_CAPABILITIES,
    "fetch-indicators": FETCH_INDICATORS_CAPABILITIES,
    "fetch-assets": FETCH_ASSETS_CAPABILITIES,
}

# Source of truth for routing the long-running parameter (longRunningPort) and the
# `long-running-execution` command (plus its params from command_params) to the
# correct capability. Keys are the integration's ``commonfields.id`` (the exact
# id field inside the YML — NOT the folder name). Sourced from
# long_running_capability_mapping.csv and verified against each YML's actual id.
# Integration ids missing from this dict fall through to the existing routing
# rules (likely landing in Automation).
#
# Note: SlackV3 and SlackV3v2 both have ``commonfields.id: SlackV3``, so a single
# entry covers both. Both map to AUTOMATION_CAPABILITY anyway, so the dedup is
# semantically lossless.
INTEGRATION_TO_LONGRUNNING_CAPABILITY: dict[str, str] = {
    "Akamai WAF SIEM": FETCH_EVENTS_CAPABILITIES,
    "AWS-SNS-Listener": AUTOMATION_CAPABILITY,
    "EDL": AUTOMATION_CAPABILITY,
    "LookoutMobileEndpointSecurity": FETCH_EVENTS_CAPABILITIES,
    "MattermostV2": AUTOMATION_CAPABILITY,
    "Microsoft Teams": AUTOMATION_CAPABILITY,
    "Proofpoint Email Security Event Collector": FETCH_EVENTS_CAPABILITIES,
    "QRadar v3": FETCH_ISSUES_CAPABILITIES,
    "Retarus Secure Email Gateway": FETCH_EVENTS_CAPABILITIES,
    "SlackV3": AUTOMATION_CAPABILITY,  # Also covers SlackV3v2 (same commonfields.id)
    "Symantec Cloud Secure Web Gateway Event Collector": FETCH_EVENTS_CAPABILITIES,
    "Symantec Endpoint Security": FETCH_EVENTS_CAPABILITIES,
    "Syslog v2": FETCH_ISSUES_CAPABILITIES,
    "TAXII2 Server": AUTOMATION_CAPABILITY,
    "TAXII Server": AUTOMATION_CAPABILITY,
    "Workday_IAM_Event_Generator": AUTOMATION_CAPABILITY,
    "WorkdaySignonEventGenerator": AUTOMATION_CAPABILITY,
    "Zoom": AUTOMATION_CAPABILITY,
}

LONG_RUNNING_EXECUTION_COMMAND = "long-running-execution"
LONG_RUNNING_PORT_PARAM = "longRunningPort"
LONG_RUNNING_FLAG_PARAM = "longRunning"

# Params that must be routed ONLY to the long-running suggested capability
# (per INTEGRATION_TO_LONGRUNNING_CAPABILITY). They are placed by Rule 7 in
# `decide_capabilities` and are guarded against the rest of the pipeline:
#   - `_handle_test_module`, `_single_capability_shortcut`,
#     `_multi_capability_mapping` skip them (won't re-add them anywhere else)
#   - `_deduplicate` exempts them (won't move them to `general_configurations`
#     even if they appear elsewhere — Rule 7 is authoritative)
PINNED_LONG_RUNNING_PARAMS: frozenset[str] = frozenset({LONG_RUNNING_FLAG_PARAM})

EXCLUDED_AUTOMATION_PATTERNS: list[str] = [
    "get-indicators",
    "get-events",
    "fetch-incidents",
    "fetch-events",
    "fetch-credentials",
    "fetch-indicators",
]


# ---------------------------------------------------------------------------
# Step 1: Decide capabilities
# ---------------------------------------------------------------------------
def _is_pure_event_collector(integration_yml: dict, command_names: list[str]) -> bool:
    """Check whether the integration qualifies as a 'pure' event collector for Rule 2's early-exit.

    Returns True only if ALL of the following hold:
      - No other fetch flags are set: ``isfetch``, ``isfetch:platform``, ``feed``,
        ``isfetchassets``.
      - No configuration param named ``isFetchCredentials`` exists.
      - The integration has at least ONE command that is NOT a ``get-events``-style
        command (i.e., ``len(command_names) - get_events_count > 0``). An integration
        whose ONLY commands are get-events is NOT considered pure — the early-exit
        is suppressed for that edge case.

    Used to gate Rule 2's early-exit so multi-purpose collectors don't drop their
    other capabilities.
    """
    script = integration_yml.get("script", {}) or {}
    if script.get("isfetch"):
        return False
    if script.get("isfetch:platform"):
        return False
    if script.get("feed"):
        return False
    if script.get("isfetchassets"):
        return False
    # Check for isFetchCredentials param
    for param in integration_yml.get("configuration", []) or []:
        if param.get("name") == "isFetchCredentials":
            return False
    get_events_cmd_count = sum(1 for n in command_names if "get-events" in n)
    if len(command_names) - get_events_cmd_count > 0:
        return False
    return True


def decide_capabilities(integration_yml: dict) -> dict[str, list[str]]:
    """Decide which capabilities should be created from the integration YML.

    Implements the rules listed in the task description. The function may
    early-exit returning a minimal mapping when one of the early-exit
    conditions for ``Log Collection`` or ``Threat Intelligence & Enrichment``
    is met.
    """
    result: dict[str, list[str]] = {"general_configurations": []}

    integration_name: str = (integration_yml.get("name") or "").lower()
    script: dict = integration_yml.get("script") or {}
    configuration: list[dict] = integration_yml.get("configuration") or []
    commands: list[dict] = script.get("commands") or []
    command_names: list[str] = [c.get("name", "") for c in commands]

    # Rule 1 - Fetch Secrets
    if any(p.get("name") == "isFetchCredentials" for p in configuration):
        result[FETCH_SECRETS_CAPABILITIES] = []

    # Rule 2 - Log Collection (with possible early exit)
    if script.get("isfetchevents") is True:
        result[FETCH_EVENTS_CAPABILITIES] = []
        if "event collector" in integration_name and _is_pure_event_collector(
            integration_yml, command_names
        ):
            # Pure event collector — short-circuit to keep the result minimal
            return {"general_configurations": [], FETCH_EVENTS_CAPABILITIES: []}

    # Rule 3 - Fetch Issues
    if script.get("isfetch") is True and script.get("isfetch:platform") is not False:
        result[FETCH_ISSUES_CAPABILITIES] = []

    # Rule 4 - Threat Intelligence & Enrichment (with possible early exit)
    if script.get("feed") is True:
        result[FETCH_INDICATORS_CAPABILITIES] = []
        get_indicators_cmd_count = sum(
            1 for n in command_names if "get-indicators" in n
        )
        if "feed" in integration_name and (
            len(command_names) - get_indicators_cmd_count == 0
        ):
            return {
                "general_configurations": [],
                FETCH_INDICATORS_CAPABILITIES: [],
            }

    # Rule 5 - Fetch Assets and Vulnerabilities
    if script.get("isfetchassets") is True:
        result[FETCH_ASSETS_CAPABILITIES] = []

    # Rule 6 - Automation
    # An integration gets the Automation capability when it has at least one
    # command that is NOT a fetch command (i.e., not matching any pattern in
    # EXCLUDED_AUTOMATION_PATTERNS: issues/secrets/events/incidents/assets/
    # indicators fetches).
    #
    # Event-collector sub-rule: when the integration is an event collector
    # (``script.isfetchevents is True``), Automation is added ONLY when the
    # integration exposes enough commands — total command count >= 3 — in
    # addition to having a non-fetch command. Pure/light event collectors
    # (1-2 commands) do not get Automation.
    has_non_fetch_command = any(
        not any(pattern in command_name for pattern in EXCLUDED_AUTOMATION_PATTERNS)
        for command_name in command_names
    )
    is_event_collector = script.get("isfetchevents") is True
    if has_non_fetch_command and (
        not is_event_collector or len(command_names) >= 3
    ):
        result[AUTOMATION_CAPABILITY] = []

    # Rule 7 - Long-running suggested capability
    # If the integration declares longRunning AND its id is in the
    # INTEGRATION_TO_LONGRUNNING_CAPABILITY override dict, ensure the suggested
    # capability key exists in result so Step 2 has a target to route to.
    if script.get("longRunning") is True:
        integration_id: str = (integration_yml.get("commonfields") or {}).get("id", "")
        suggested = INTEGRATION_TO_LONGRUNNING_CAPABILITY.get(integration_id, "")
        if suggested not in result:
            result[suggested] = ["longRunning"]
        elif "longRunning" not in result[suggested]:
            result[suggested].append("longRunning")

    capabilities = list(result.keys())
    capabilities.remove("general_configurations")
    if len(capabilities) < 1:
        raise Exception(f"No capabilities were created for integration {integration_name}")
    return result


# ---------------------------------------------------------------------------
# Step 2: Map params to capabilities
# ---------------------------------------------------------------------------
def _required_param_names(integration_yml: dict | None) -> set[str]:
    """Return the set of YML config param names marked ``required: true``.

    A param is "required" only when its YML ``configuration[]`` entry has
    ``required`` set to the JSON boolean ``true``. Missing / ``false`` /
    any non-``True`` value is treated as NOT required.
    """
    required: set[str] = set()
    if integration_yml is None:
        return required
    for param in integration_yml.get("configuration", []) or []:
        if param.get("required") is True:
            name = param.get("name")
            if name:
                required.add(name)
    return required


def _handle_test_module(
    result: dict[str, list[str]],
    command_params: dict,
    param_defaults: dict,
    integration_yml: dict | None = None,
) -> list[str]:
    """Step 2.1 - Elevate REQUIRED ``test-module`` params (without a default)
    to the connection (``other_connection`` in Auth Details) instead of
    routing them into ``general_configurations``.

    Two-correction behavior (vs. the historical "every test-module param
    without a default → general_configurations" rule):

    1. **Required test-module params are elevated to the connection, not
       general.** A REQUIRED ``test-module`` param that has no default
       belongs on the connection (the integration needs it to even
       authenticate / run the connection test), so it must NOT land in
       ``general_configurations``. It is returned in the elevation list so
       the caller (Step 3b) can inject it into the integration's
       ``Auth Details.other_connection`` via ``set-auth``. It is also kept
       out of every capability bucket so it never appears in the persisted
       ``Params to Capabilities`` cell (whose closed enum has no
       ``other_connection`` key anyway).
    2. **Required-only elevation; non-required keep the old behavior.** Only
       params whose YML ``configuration`` entry is ``required: true`` are
       elevated. A NON-required ``test-module`` param (no default) keeps the
       historical behavior — it is added to ``general_configurations`` —
       because a param that appears only under ``test-module`` is never
       placed by the downstream command-routing "other decisions", so
       dropping it would lose it entirely.

    Params already supplied with a default (``param_defaults``) and pinned
    long-running params are neither elevated nor added to general.

    Returns the sorted list of param names elevated to ``other_connection``
    (may be empty). The caller uses it to drive the Auth Details injection.
    """
    commands_section: dict = command_params.get("commands") or {}
    test_module_params: list[str] = commands_section.get("test-module", []) or []
    required_names: set[str] = _required_param_names(integration_yml)
    general_set: set = set(result["general_configurations"])
    elevated: set[str] = set()
    for param in test_module_params:
        if param in PINNED_LONG_RUNNING_PARAMS:
            # Pinned params are owned by Rule 7 — never touched here.
            continue
        if param in param_defaults:
            # Has a code/test default — not a connection-required param.
            continue
        if param in required_names:
            # Correction 1: required test-module params elevate to the
            # connection (other_connection), never into a capability bucket.
            elevated.add(param)
        elif param not in general_set:
            # Correction 2: non-required test-module params keep the old
            # general_configurations behavior.
            result["general_configurations"].append(param)
            general_set.add(param)

    if elevated:
        # Make sure no elevated param lingers in any capability bucket
        # (e.g. if it was seeded there before this step ran).
        for capability in list(result.keys()):
            result[capability] = [p for p in result[capability] if p not in elevated]

    return sorted(elevated)


def _apply_manual_mapping(
    result: dict[str, list[str]],
    command_params: dict,
    manual_command_to_capability: dict[str, list[str]],
) -> set:
    """
    manual_command_to_capability - mapping command name -> list of capability names.
    Step 2.1.5 — Apply manual command-to-capability overrides.

    Manual mapping is the source of truth for any listed command. For each entry:
      1. Ensure each listed capability exists in the result dict (create with []).
      2. Add the command's params (from command_params['commands'][cmd]) to each
         listed capability.

    Returns the set of command names that were handled here, so subsequent steps
    (2.2 / 2.3) can skip them and avoid double-routing.

    Uses a ``placed_per_cap`` dict-of-sets for O(1) per-capability dedup
    instead of scanning ``result[cap]`` linearly on every check.

    No-op when ``manual_command_to_capability`` is empty.
    """
    handled_commands: set = set()
    if not manual_command_to_capability:
        return handled_commands

    commands_section: dict = command_params.get("commands") or {}
    for cmd_name, capability_list in manual_command_to_capability.items():
        # Ensure each capability exists.
        for cap in capability_list:
            if cap not in result:
                result[cap] = []
            else:
                result[cap].append(cmd_name)
        # Route this command's params to each listed capability.
        for cmd_params in commands_section.values():
            if cmd_name in cmd_params:
                cmd_params.remove(cmd_name)
    return handled_commands


def _single_capability_shortcut(
    result: dict[str, list[str]],
    command_params: dict,
    handled_commands: set | None = None,
) -> None:
    """Step 2.2 - When only a single (non-general) capability exists, dump all
    unique command params (excluding those already placed in
    ``general_configurations`` and those handled by manual mapping) into that
    capability."""
    handled_commands = handled_commands or set()
    target_capability = next(
        cap for cap in result if cap != "general_configurations"
    )
    already_placed = set(result["general_configurations"])
    # Pinned long-running params are routed by Rule 7 only — exclude them from
    # the target capability list (they are already placed in the suggested
    # capability, which may or may not be the same as target_capability).
    already_placed |= PINNED_LONG_RUNNING_PARAMS
    seen: set = set()
    commands_section: dict = command_params.get("commands") or {}
    for cmd_name, params in commands_section.items():
        if cmd_name in handled_commands:
            continue
        for param in params or []:
            if param in already_placed or param in seen:
                continue
            seen.add(param)
            result[target_capability].append(param)


def _resolve_target_capability(
    cmd_name: str,
    result: dict[str, list[str]],
    integration_id: str = "",
) -> str:
    """Decide which capability a command's params should be routed to.

    Resolution order:
    1. Long-running override: if ``cmd_name == "long-running-execution"`` AND
       ``integration_id`` is in ``INTEGRATION_TO_LONGRUNNING_CAPABILITY`` →
       return the suggested capability from the dict.
    2. Exact match in ``COMMAND_TO_CAPABILITY`` (e.g. ``"fetch-events"`` →
       ``"Log Collection"``).
    3. Substring routing:
       - If ``"get-events"`` in command name AND ``"Log Collection"`` exists
         in the capabilities → ``"Log Collection"``.
       - If ``"get-indicators"`` in command name AND
         ``"Threat Intelligence & Enrichment"`` exists in the capabilities →
         ``"Threat Intelligence & Enrichment"``.
    4. Fallback: ``"Automation"``.
    """
    if cmd_name == LONG_RUNNING_EXECUTION_COMMAND:
        suggested = INTEGRATION_TO_LONGRUNNING_CAPABILITY.get(integration_id)
        if suggested:
            return suggested
    if cmd_name in COMMAND_TO_CAPABILITY:
        return COMMAND_TO_CAPABILITY[cmd_name]
    if "get-events" in cmd_name and FETCH_EVENTS_CAPABILITIES in result:
        return FETCH_EVENTS_CAPABILITIES
    if "get-indicators" in cmd_name and FETCH_INDICATORS_CAPABILITIES in result:
        return FETCH_INDICATORS_CAPABILITIES
    return AUTOMATION_CAPABILITY


def _multi_capability_mapping(
    result: dict[str, list[str]],
    command_params: dict,
    handled_commands: set | None = None,
    integration_id: str = "",
) -> None:
    """
    command_params structure- {integration: '', commands: {command: [params]}}
    Step 2.3 - For each command, map its params to the matching capability
    (or ``Automation``).  Skips test-module (handled in 2.1) and any command
    already routed by manual mapping (Step 2.1.5).  Warns if the target
    capability is missing from the result mapping.

    ``integration_id`` is forwarded to ``_resolve_target_capability`` so the
    long-running override can take effect for ``long-running-execution``.

    Uses a ``placed_per_cap`` dict-of-sets for O(1) per-capability dedup
    instead of scanning ``result[target]`` linearly on every check.
    """
    handled_commands = handled_commands or set()
    commands_section: dict = command_params.get("commands") or {}
    placed_per_cap: dict[str, set] = {}
    for cmd_name, params in commands_section.items():
        if cmd_name == "test-module" or cmd_name in handled_commands:
            continue
        target = _resolve_target_capability(cmd_name, result, integration_id)
        if target in result:
            cap_set = placed_per_cap.setdefault(target, set(result[target]))
            for param in params or []:
                if param in PINNED_LONG_RUNNING_PARAMS:
                    # Pinned params are owned by Rule 7 — never auto-routed here.
                    continue
                if param not in cap_set:
                    result[target].append(param)
                    cap_set.add(param)
        else:
            for param in params or []:
                logger.warning(
                    f"{param} failed to add to {target} because it doesn't "
                    f"exist although it's a part of {cmd_name}."
                )


def _deduplicate(result: dict[str, list[str]]) -> None:
    """Step 2.4 - Move any param appearing in two or more capabilities (or in
    ``general_configurations`` plus another capability) into
    ``general_configurations`` exactly once.

    Pinned long-running params (``PINNED_LONG_RUNNING_PARAMS``) are EXEMPT:
    they are owned by Rule 7 and must remain only in the suggested long-running
    capability. If they accidentally appear elsewhere, they are stripped from
    every other capability rather than moved to ``general_configurations``.

    Uses a snapshot ``general_set`` for O(1) membership lookup at the final
    insertion step instead of an O(n) list scan per duplicate.
    """
    # Pin-correction pass: ensure pinned params live in exactly one capability
    # (the long-running suggested capability), never in general_configurations
    # or other capabilities they may have ended up in.
    for capability in list(result.keys()):
        if capability == "general_configurations":
            result[capability] = [
                p for p in result[capability] if p not in PINNED_LONG_RUNNING_PARAMS
            ]

    # Count occurrences of every param across all keys.
    occurrences: dict[str, int] = {}
    for params in result.values():
        for param in params:
            occurrences[param] = occurrences.get(param, 0) + 1

    duplicated = {
        p
        for p, count in occurrences.items()
        if count >= 2 and p not in PINNED_LONG_RUNNING_PARAMS
    }
    if not duplicated:
        return

    if "general_configurations" not in result:
        result["general_configurations"] = []

    for capability in list(result.keys()):
        result[capability] = [p for p in result[capability] if p not in duplicated]

    general_set: set = set(result["general_configurations"])
    for param in duplicated:
        if param not in general_set:
            result["general_configurations"].append(param)
            general_set.add(param)


_MISSING = object()


def _collect_hidden_params(
    integration_yml: dict, param_defaults: dict
) -> tuple[set, set]:
    """Step 2.6 helper — Collect names of params to remove because they're
    hidden on the Cortex Platform, plus any hidden params kept by the carve-out.

    A param is considered hidden on the platform if EITHER:
      - Its ``hidden`` field is ``True`` (boolean — hidden in all marketplaces)
      - Its ``hidden`` field is a list that contains the string ``"platform"``

    Carve-out: a hidden param is KEPT (not added to the removal set) if ALL
    THREE of the following hold:
      1. Its name is NOT a key in ``param_defaults`` (no external override)
      2. It is hidden in the platform (the trigger above)
      3. It HAS a ``defaultvalue`` field in the YAML (any non-``None`` value;
         empty string ``""`` counts)

    Returns a 2-tuple:
      - ``to_remove``: set of param names that should be filtered out
      - ``kept_by_carveout``: set of hidden param names that were KEPT due to
        the carve-out (used by the caller for INFO logging)
    """
    to_remove: set = set()
    kept_by_carveout: set = set()
    for param in integration_yml.get("configuration", []) or []:
        name = param.get("name", "")
        hidden_value = param.get("hidden")
        is_hidden_on_platform = hidden_value is True or (
            isinstance(hidden_value, list) and "platform" in hidden_value
        )
        if not is_hidden_on_platform:
            continue
        # Hidden on platform — apply the carve-out check
        not_in_param_defaults = name not in param_defaults
        # Sentinel distinguishes "key absent" from "key present with value None"
        defaultvalue = param.get("defaultvalue", _MISSING)
        has_yml_defaultvalue = defaultvalue is not _MISSING and defaultvalue is not None
        if not_in_param_defaults and has_yml_defaultvalue:
            kept_by_carveout.add(name)
        else:
            to_remove.add(name)
    return to_remove, kept_by_carveout


def _filter_hidden_params(
    result: dict[str, list[str]],
    hidden_params: set,
    kept_by_carveout: set | None = None,
) -> None:
    """Step 2.6 — Remove hidden params from every capability list and log them.

    Mutates ``result`` in place. Two log messages may be emitted:
      - ``"Removed the following params..."`` if any params were stripped
      - ``"Kept the following hidden params because they have a YAML
        defaultvalue and no override in param_defaults..."`` if any were
        kept by the carve-out
    """
    kept_by_carveout = kept_by_carveout or set()
    if not hidden_params and not kept_by_carveout:
        return
    if hidden_params:
        removed: set = set()
        for capability, params in result.items():
            filtered = [p for p in params if p not in hidden_params]
            if len(filtered) != len(params):
                removed.update(p for p in params if p in hidden_params)
                result[capability] = filtered
        if removed:
            logger.info(
                f"Removed the following params from the final result because "
                f"they're hidden in the platform/all marketplaces: "
                f"{sorted(removed)}"
            )
    if kept_by_carveout:
        logger.info(
            f"Kept the following hidden params because they have a YAML "
            f"defaultvalue and no override in param_defaults: "
            f"{sorted(kept_by_carveout)}"
        )


def _route_long_running_param(
    result: dict[str, list[str]],
    integration_yml: dict | None,
    param_defaults: dict,
    integration_id: str,
) -> None:
    """Step 2.0 — Route the literal ``longRunningPort`` config param to the
    suggested long-running capability for this integration.

    Pre-conditions for routing:
      - ``integration_yml`` is provided and declares ``script.longRunning: true``
      - ``integration_id`` is present in ``INTEGRATION_TO_LONGRUNNING_CAPABILITY``
      - The integration's YAML configuration contains a param named
        ``longRunningPort`` that is NOT in ``param_defaults`` (defaults override
        keeps general-configurations behavior).

    The suggested capability key is expected to already exist in ``result``
    (created by ``decide_capabilities``'s Rule 7); a defensive check creates it
    if missing. The append is dedup-safe.

    All other long-running-related config params (listener URL, certificate,
    etc.) intentionally fall through to the standard flow.
    """
    if integration_yml is None or not integration_id:
        return
    script: dict = integration_yml.get("script") or {}
    if script.get("longRunning") is not True:
        return
    suggested = INTEGRATION_TO_LONGRUNNING_CAPABILITY.get(integration_id)
    if not suggested:
        return
    has_long_running_port = any(
        p.get("name") == LONG_RUNNING_PORT_PARAM
        for p in (integration_yml.get("configuration") or [])
    )
    if not has_long_running_port:
        return
    if suggested not in result:
        result[suggested] = []
    if LONG_RUNNING_PORT_PARAM not in result[suggested]:
        result[suggested].append(LONG_RUNNING_PORT_PARAM)


def is_single_capability(results):
    return len(results) == 2


def map_params_to_capabilities(
    capabilities: dict[str, list[str]],
    command_params: dict,
    param_defaults: dict,
    manual_command_to_capability: dict[str, list[str]] | None = None,
    integration_yml: dict | None = None,
    elevated_out: list[str] | None = None,
) -> dict[str, list[str]]:
    """Apply Step 2 - populate the capabilities mapping with parameter names
    derived from the supplied ``command_params`` and ``param_defaults`` JSON
    inputs. ``manual_command_to_capability`` (optional) overrides automatic
    routing for any listed commands. ``integration_yml`` (optional) enables
    Step 2.0 (long-running param routing), Step 2.1 elevation of required
    test-module params to the connection, and Step 2.6 (filtering out params
    hidden on the Cortex Platform).

    If ``elevated_out`` is provided, the sorted list of REQUIRED test-module
    params elevated to the connection (``other_connection`` in Auth Details)
    is written into it. These params are also guaranteed NOT to appear in any
    capability bucket of the returned dict (see ``_handle_test_module``)."""
    manual_command_to_capability = manual_command_to_capability or {}
    integration_id: str = ""
    if integration_yml is not None:
        integration_id = (integration_yml.get("commonfields") or {}).get("id", "")

    # Work on a fresh dict so the caller's data is untouched.
    result: dict[str, list[str]] = {k: list(v) for k, v in capabilities.items()}

    # Step 2.0 (NEW) - route the longRunningPort config param to the suggested
    # long-running capability (if applicable).
    _route_long_running_param(result, integration_yml, param_defaults, integration_id)

    # Step 2.1 - elevate REQUIRED test-module params (no default) to the
    # connection (other_connection). They are stripped from `result` and
    # returned so the caller can inject them into Auth Details.
    elevated: list[str] = _handle_test_module(
        result, command_params, param_defaults, integration_yml
    )

    # Step 2.1.5 - manual override (source of truth for listed commands)
    handled_commands = _apply_manual_mapping(
        result, command_params, manual_command_to_capability
    )

    if is_single_capability(results=result):
        # Step 2.2 - single-capability shortcut (skip 2.3)
        _single_capability_shortcut(result, command_params, handled_commands)
    else:
        # Step 2.3 - multi-capability mapping (forwards integration_id so the
        # long-running-execution command is routed by the override dict)
        _multi_capability_mapping(
            result, command_params, handled_commands, integration_id
        )

    # Step 2.4 - deduplicate
    _deduplicate(result)

    # Step 2.6 (NEW) - filter hidden params
    if integration_yml is not None:
        to_remove, kept_by_carveout = _collect_hidden_params(
            integration_yml, param_defaults
        )
        _filter_hidden_params(result, to_remove, kept_by_carveout)

    # Final elevation strip: routing (2.2/2.3) may have re-added an elevated
    # param that also appears under a non-test-module command. Elevated params
    # live on the connection ONLY, so strip them from every capability bucket
    # one more time after all routing is done.
    if elevated:
        elevated_set = set(elevated)
        for capability in list(result.keys()):
            result[capability] = [
                p for p in result[capability] if p not in elevated_set
            ]
        logger.info(
            f"Elevated required test-module params to the connection "
            f"(other_connection in Auth Details), excluded from "
            f"Params to Capabilities: {elevated}"
        )

    if elevated_out is not None:
        elevated_out[:] = elevated

    # NOTE: empty capability buckets (including general_configurations) are
    # intentionally preserved in the final result — no cleanup pass is run.

    return result


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------
@main.command()
def generate_param_mapping(
    command_params_json: str = typer.Argument(
        ...,
        help="JSON string with the {integration: '', commands: {command: [params]}} structure that map commands to their params.",
    ),
    param_defaults_json: str = typer.Argument(
        ..., help="JSON string mapping param names to their default values."
    ),
    integration_yml_path: Path = typer.Argument(
        ..., exists=True, help="Path to the integration YML file."
    ),
    manual_command_to_capability_json: str = typer.Argument(
        "{}",
        help=(
            "JSON string mapping command name -> list of capability names. "
            "Acts as source of truth, overriding automatic routing. "
            "Pass '{}' or omit to disable."
        ),
    ),
    output_path: Path = typer.Option(
        Path("./param_mapping_output.json"),
        "-o",
        "--output",
        help="Output JSON file path.",
    ),
) -> None:
    """Generate the connector parameter mapping from the integration YML and
    the supplied command/defaults JSON inputs (with optional manual overrides)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    command_params: dict[str, Any] = json.loads(command_params_json)
    param_defaults: dict[str, Any] = json.loads(param_defaults_json)
    manual_command_to_capability: dict[str, list[str]] = json.loads(
        manual_command_to_capability_json
    )
    with open(integration_yml_path) as f:
        integration_yml: dict = yaml.safe_load(f)

    capabilities = decide_capabilities(integration_yml)
    elevated: list[str] = []
    result = map_params_to_capabilities(
        capabilities,
        command_params,
        param_defaults,
        manual_command_to_capability,
        integration_yml=integration_yml,  # enables Step 2.1 elevation + Step 2.6
        elevated_out=elevated,
    )

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    logger.info(f"Param mapping written to {output_path}")

    # Surface the required test-module params that must be elevated to the
    # connection (other_connection in Auth Details). Step 3b reads this
    # sidecar, injects them into the integration's Auth Details, and re-applies
    # via set-auth (which resets the workflow back to the Auth Details step;
    # the capability mapping survives because Params to Capabilities is
    # preserve_on_reset=true).
    elevated_path = output_path.with_suffix(output_path.suffix + ".elevated.json")
    with open(elevated_path, "w") as f:
        json.dump(elevated, f, indent=2)
    if elevated:
        logger.info(
            f"{len(elevated)} param(s) must be elevated to other_connection "
            f"in Auth Details: {elevated}. Elevation list written to "
            f"{elevated_path}."
        )
    else:
        logger.info(
            f"No required test-module params to elevate. Empty elevation list "
            f"written to {elevated_path}."
        )


if __name__ == "__main__":
    main()
