"""Unmute a Google Cloud SCC finding from the incident layout action button."""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401
from typing import Any

UNMUTE_COMMAND = "google-cloud-scc-finding-unmute"

SET_INCIDENT_COMMAND = "setIncident"

FINDING_NAME_INCIDENT_FIELD = "googlecloudsccfindingname"

MUTE_STATE_INCIDENT_FIELD = "googlecloudsccfindingmutestatus"

ERROR_MESSAGES = {
    "MISSING_FINDING_NAME": 'The "finding_name" argument is required. It was not provided and the incident field '
    '"GoogleCloudSCC Finding Name" is empty.',
    "UNMUTE_FAILED": "Failed to unmute the finding {}.\n{}",
    "SET_INCIDENT_FAILED": "The finding {} was unmuted, "
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
    Resolve the finding name to unmute, preferring the script argument over the incident field.

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
    Get the mute state of the finding from the entries returned by the unmute command.

    :param entries: The entries returned by the unmute command.
    :return: The mute state of the finding, or "UNMUTED" when the state is not present in the response.
    """
    for entry in entries:
        contents = entry.get("Contents")
        if isinstance(contents, dict) and contents.get("mute"):
            return str(contents["mute"])

    return ""


def set_mute_state_on_incident(finding_name: str, mute_state: str) -> None:
    """
    Set the mute state of the finding on the "GoogleCloudSCC Finding Mute Status" field of the current incident.

    :param finding_name: The relative resource name of the unmuted finding.
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
        raise DemistoException(ERROR_MESSAGES["SET_INCIDENT_FAILED"].format(finding_name, entries))


def unmute_finding(args: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Unmute the finding by executing the "google-cloud-scc-finding-unmute" command and update the incident mute field.

    :param args: Script argument(s).
    :return: The entries returned by the command.
    :raises DemistoException: When the command execution fails.
    """
    finding_name = get_finding_name(args)

    command_args = {"name": finding_name}

    is_successful, entries = execute_command(UNMUTE_COMMAND, command_args, extract_contents=False, fail_on_error=False)
    if not is_successful:
        raise DemistoException(ERROR_MESSAGES["UNMUTE_FAILED"].format(finding_name, entries))

    entries = entries if isinstance(entries, list) else [entries]

    set_mute_state_on_incident(finding_name, get_mute_state(entries))

    return entries


def main():  # pragma: no cover
    try:
        return_results(unmute_finding(demisto.args()))
    except Exception as exception:
        return_error(f"Failed to execute GoogleCloudSCCUnmuteFinding script. Error: {exception}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
