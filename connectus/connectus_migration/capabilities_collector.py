import json
import logging
import sys
from pathlib import Path

import typer
import yaml

logger = logging.getLogger(__name__)

main = typer.Typer()

# Make sibling connectus modules (workflow_state) importable regardless of CWD.
# capabilities_collector.py lives in connectus/connectus_migration/, so the
# connectus/ dir is one level up.
_CONNECTUS_DIR = Path(__file__).resolve().parent.parent
if str(_CONNECTUS_DIR) not in sys.path:
    sys.path.insert(0, str(_CONNECTUS_DIR))

_REPO_ROOT = _CONNECTUS_DIR.parent

# Exit codes — mirror the reference analyzers (check_param_defaults.py etc.).
EXIT_OK = 0
EXIT_USAGE = 2

FETCH_ASSETS_CAPABILITIES = "Fetch Assets and Vulnerabilities"
FETCH_ISSUES_CAPABILITIES = "Fetch Issues"
FETCH_EVENTS_CAPABILITIES = "Log Collection"
FETCH_SECRETS_CAPABILITIES = "Fetch Secrets"
FETCH_INDICATORS_CAPABILITIES = "Threat Intelligence & Enrichment"
AUTOMATION_CAPABILITY = "Automation"

# Command-name substrings that identify a fetch command (issues/secrets/events/
# incidents/assets/indicators). A command that matches none of these is a
# "non-fetch" command and therefore qualifies the integration for Automation.
EXCLUDED_AUTOMATION_PATTERNS: list[str] = [
    "get-indicators",
    "get-events",
    "fetch-incidents",
    "fetch-events",
    "fetch-credentials",
    "fetch-indicators",
]

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

def _is_pure_event_collector(integration_yml: dict, command_names: list[str]) -> bool:
    """Return True only if the integration is a 'pure' event collector.

    Pure means: ``isfetchevents`` is the only fetch flag, there is no
    ``isFetchCredentials`` config param, and every command is a get-events
    command (i.e., there is no non-get-events command). Used to gate the
    Log Collection early-exit so multi-purpose collectors keep their other
    capabilities.
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
    for param in integration_yml.get("configuration", []) or []:
        if param.get("name") == "isFetchCredentials":
            return False
    get_events_cmd_count = sum(1 for n in command_names if "get-events" in n)
    if len(command_names) - get_events_cmd_count > 0:
        return False
    return True


def collect_capabilities(integration_yml: dict) -> list[str]:
    """Collect the list of expected capability names for an integration YML.

    Mirrors the capability-decision rules but returns a flat, de-duplicated
    list of capability names (``general_configurations`` is never included).
    The order is deterministic, following the order the rules are evaluated.
    """
    capabilities: list[str] = []

    def add(capability: str) -> None:
        if capability and capability not in capabilities:
            capabilities.append(capability)

    integration_name: str = (integration_yml.get("name") or "").lower()
    integration_id: str = (integration_yml.get("commonfields", {}).get("id") or "")
    script: dict = integration_yml.get("script") or {}
    configuration: list[dict] = integration_yml.get("configuration") or []
    commands: list[dict] = script.get("commands") or []
    command_names: list[str] = [c.get("name", "") for c in commands]
    is_event_collector = ("event collector" in integration_name or "eventcollector" in integration_name)

    # Rule 1 - Fetch Secrets
    if any(p.get("name") == "isFetchCredentials" for p in configuration):
        add(FETCH_SECRETS_CAPABILITIES)

    # Rule 2 - Log Collection (with possible early exit)
    if script.get("isfetchevents") is True:
        add(FETCH_EVENTS_CAPABILITIES)
        if is_event_collector and _is_pure_event_collector(
            integration_yml, command_names
        ):
            return [FETCH_EVENTS_CAPABILITIES]

    # Rule 3 - Fetch Issues
    if script.get("isfetch") is True and script.get("isfetch:platform") is not False:
        add(FETCH_ISSUES_CAPABILITIES)

    # Rule 4 - Threat Intelligence & Enrichment (with possible early exit)
    if script.get("feed") is True:
        add(FETCH_INDICATORS_CAPABILITIES)
        get_indicators_cmd_count = sum(
            1 for n in command_names if "get-indicators" in n
        )
        if "feed" in integration_name and (
            len(command_names) - get_indicators_cmd_count == 0
        ):
            return [FETCH_INDICATORS_CAPABILITIES]

    # Rule 5 - Fetch Assets and Vulnerabilities
    if script.get("isfetchassets") is True:
        add(FETCH_ASSETS_CAPABILITIES)

    # Rule 6 - Use hard-coded predefined long-running to capability mapper        
    if integration_id in INTEGRATION_TO_LONGRUNNING_CAPABILITY:
        add(INTEGRATION_TO_LONGRUNNING_CAPABILITY[integration_id])

    # Rule 7 - Automation
    # Added when the integration has at least one non-fetch command. For event
    # collectors (isfetchevents True) the integration must additionally expose
    # >= 3 commands.
    has_non_fetch_command = any(
        not any(pattern in command_name for pattern in EXCLUDED_AUTOMATION_PATTERNS)
        for command_name in command_names
    )
    if has_non_fetch_command:
        add(AUTOMATION_CAPABILITY)

    return capabilities


def _resolve_integration_yml(integration_id: str) -> Path:
    """Resolve an integration's YML path from its workflow-CSV id.

    Mirrors the reference analyzers' ``--integration-id`` resolution
    (e.g. :func:`check_param_defaults._resolve_integration_path`): it goes
    through :func:`workflow_state.get_integration_files`, the single source
    of truth for an integration's on-disk files. Raises ``ValueError`` on
    any resolution failure so the CLI can surface a clean usage error.
    """
    try:
        from workflow_state import get_integration_files  # type: ignore

        files = get_integration_files(integration_id)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(
            f"could not resolve --integration-id {integration_id!r}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if "error" in files:
        raise ValueError(f"--integration-id {integration_id!r}: {files['error']}")
    yml_rel = files.get("yml")
    if not yml_rel:
        raise ValueError(
            f"--integration-id {integration_id!r}: workflow row has no YML path."
        )
    return (_REPO_ROOT / yml_rel).resolve()


def _load_yml(yml_path: Path) -> dict:
    with open(yml_path) as f:
        return yaml.safe_load(f) or {}


def build_report(integration_yml: dict) -> dict:
    """Build the stdout JSON envelope (reference-analyzer shape).

    Shape mirrors :mod:`check_param_defaults` / :mod:`check_auth_parity`:
    a top-level ``integration`` name, a ``pass`` boolean, and the
    payload (``capabilities``). ``pass`` is ``True`` whenever the
    collection succeeded — capability collection is deterministic and
    never "fails" structurally, so the flag exists purely for a uniform
    exit-code contract across the analyzer family.
    """
    capabilities = collect_capabilities(integration_yml)
    return {
        "integration": integration_yml.get("name") or "<unknown>",
        "pass": True,
        "capabilities": capabilities,
    }


@main.command()
def generate_capabilities_list(
    integration_yml_path: Path = typer.Argument(
        None,
        exists=True,
        help=(
            "Path to the integration YML file (legacy positional form). "
            "Omit when using --integration-id."
        ),
    ),
    integration_id: str = typer.Option(
        None,
        "--integration-id",
        help="Resolve the integration YML from the workflow CSV id (preferred).",
    ),
    output_path: Path = typer.Option(
        Path("./capabilities_output.json"),
        "-o",
        "--output",
        help="Output JSON file path (also written when --report is used).",
    ),
    report: bool = typer.Option(
        False,
        "--report",
        help=(
            "Emit the reference-aligned JSON envelope "
            "({integration, pass, capabilities}) to stdout."
        ),
    ),
    human: bool = typer.Option(
        False, "--human", help="Also print a human-readable summary to stderr."
    ),
) -> None:
    """Collect the expected capability names from an integration YML.

    Two input modes (back-compatible):

    * **Legacy** — positional ``<yml>`` + ``-o <path>``: writes the bare
      capability JSON array to the ``-o`` file (unchanged behavior).
    * **Reference-aligned** — ``--integration-id <id>`` resolves the YML via
      ``workflow_state`` (the single source of truth for integration files),
      mirroring ``check_param_defaults`` / ``check_auth_parity`` /
      ``check_command_params``.

    With ``--report`` the analyzer ALSO emits a JSON envelope
    (``{"integration", "pass", "capabilities"}``) on stdout — the same shape
    the other analyzers use. ``--report`` + ``--human`` adds a stderr summary.
    Exit 0 on success, 2 on a usage / resolution error.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not integration_yml_path and not integration_id:
        print(
            "error: provide a positional <yml> path or --integration-id",
            file=sys.stderr,
        )
        raise typer.Exit(EXIT_USAGE)

    try:
        yml_path = (
            integration_yml_path.resolve()
            if integration_yml_path
            else _resolve_integration_yml(integration_id)
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise typer.Exit(EXIT_USAGE)

    if not yml_path.is_file():
        print(f"error: not a file: {yml_path}", file=sys.stderr)
        raise typer.Exit(EXIT_USAGE)

    integration_yml = _load_yml(yml_path)
    capabilities = collect_capabilities(integration_yml)

    with open(output_path, "w") as f:
        json.dump(capabilities, f, indent=2)
    logger.info(f"Capabilities list written to {output_path}: {capabilities}")

    if report:
        envelope = build_report(integration_yml)
        print(json.dumps(envelope, indent=2, sort_keys=True))
        if human:
            summary = ", ".join(capabilities) if capabilities else "(none)"
            print(
                f"Integration: {envelope['integration']}\n"
                f"  capabilities: {summary}",
                file=sys.stderr,
            )

    raise typer.Exit(EXIT_OK)


if __name__ == "__main__":
    main()
