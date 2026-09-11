"""Mute a Google Cloud SCC finding from the incident layout action button."""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401
from typing import Any

MUTE_COMMAND = "google-cloud-scc-finding-mute"

SET_INCIDENT_COMMAND = "setIncident"

FINDING_NAME_INCIDENT_FIELD = "googlecloudsccfindingname"

MUTE_STATE_INCIDENT_FIELD = "googlecloudsccfindingmutestatus"

ERROR_MESSAGES = {
    "MISSING_FINDING_NAME": 'The "finding_name" argument is required. It was not provided and the incident field '
    '"GoogleCloudSCC Finding Name" is empty.',
    "MUTE_FAILED": "Failed to mute the finding {}.\n{}",
    "SET_INCIDENT_FAILED": "The finding {} was muted, "
    'but the incident field "GoogleCloudSCC Finding Mute Status" could not be updated.\n{}',
}


def get_finding_name_from_incident() -> str:
    """
    Get the finding name from the "GoogleCloudSCC Finding Name" field of the current incident.

    :return: The finding name, or an empty string when the field is not populated.
    """
    incident = demisto.incident() or {}
    custom_fields = incident.get("CustomFields") or {}

    return str(custom_fields.get(FINDING_NAME_INCIDENT_FIELD) or "").strip()


def get_finding_name(args: dict[str, Any]) -> str:
    """
    Resolve the finding name to mute, preferring the script argument over the incident field.

    :param args: Script argument(s).
    :return: The relative resource name of the finding.
    :raises DemistoException: When the finding name is neither provided nor available on the incident.
    """
    finding_name = str(args.get("finding_name") or "").strip() or get_finding_name_from_incident()
    if not finding_name:
        raise DemistoException(ERROR_MESSAGES["MISSING_FINDING_NAME"])

    return finding_name


def get_mute_state(entries: list[dict[str, Any]]) -> str:
    """
    Get the mute state of the finding from the entries returned by the mute command.

    :param entries: The entries returned by the mute command.
    :return: The mute state of the finding, or "MUTED" when the state is not present in the response.
    """
    for entry in entries:
        contents = entry.get("Contents")
        if isinstance(contents, dict) and contents.get("mute"):
            return str(contents["mute"])

    return ""


def get_error_message(result: Any) -> str:
    """
    Extract the readable error text from a failed command result.

    :param result: The error returned by the command, either an error message or the raw entry(s).
    :return: The extracted error text.
    """
    if isinstance(result, str):
        return result.strip()

    entries = result if isinstance(result, list) else [result]

    messages = [str(entry.get("Contents") or "").strip() for entry in entries if isinstance(entry, dict)]

    return "\n".join(message for message in messages if message) or str(result)


def set_mute_state_on_incident(finding_name: str, mute_state: str) -> None:
    """
    Set the mute state of the finding on the "GoogleCloudSCC Finding Mute Status" field of the current incident.

    :param finding_name: The relative resource name of the muted finding.
    :param mute_state: The mute state to set on the incident field.
    :raises DemistoException: When the incident field could not be updated.
    """
    is_successful, entries = execute_command(
        SET_INCIDENT_COMMAND,
        {"customFields": {MUTE_STATE_INCIDENT_FIELD: mute_state}},
        extract_contents=False,
        fail_on_error=False,
    )
    if not is_successful:
        raise DemistoException(ERROR_MESSAGES["SET_INCIDENT_FAILED"].format(finding_name, get_error_message(entries)))


def mute_finding(args: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Mute the finding by executing the "google-cloud-scc-finding-mute" command and update the incident mute field.

    :param args: Script argument(s).
    :return: The entries returned by the command.
    :raises DemistoException: When the command execution fails.
    """
    finding_name = get_finding_name(args)

    command_args = {"name": finding_name}

    demisto.debug(f'Executing "{MUTE_COMMAND}" for the finding {finding_name}.')

    is_successful, entries = execute_command(MUTE_COMMAND, command_args, extract_contents=False, fail_on_error=False)
    if not is_successful:
        raise DemistoException(ERROR_MESSAGES["MUTE_FAILED"].format(finding_name, get_error_message(entries)))

    entries = entries if isinstance(entries, list) else [entries]

    mute_state = get_mute_state(entries)

    demisto.debug(f'Setting the mute state "{mute_state}" on the incident for the finding {finding_name}.')

    set_mute_state_on_incident(finding_name, mute_state)

    return entries


def main():  # pragma: no cover
    try:
        return_results(mute_finding(demisto.args()))
    except Exception as exception:
        return_error(f"Failed to execute GoogleCloudSCCMuteFinding script. Error: {exception}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
