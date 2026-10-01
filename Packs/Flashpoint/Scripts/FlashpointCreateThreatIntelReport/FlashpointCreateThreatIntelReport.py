import demistomock as demisto
from CommonServerPython import *
from markdownify import markdownify as md

REPORT_GET_COMMAND = "flashpoint-ignite-intelligence-report-get"
CREATE_XSOAR_THREAT_INTEL_REPORT_COMMAND = "createThreatIntelReport"

REPORT_TYPE = "Executive Brief"

PUBLISHED_STATUS = "Published"
DRAFT_STATUS = "Draft"

EMPTY_REPORT_BODY = "No report body available."

ERROR_MESSAGES = {
    "MISSING_ARGUMENT": "Please provide correct input for '{}' argument.",
    "FAILED_COMMAND": "Failed to execute '{}' command. Error: {}",
    "NO_REPORT": "No report found for the given ID: '{}'.",
}

""" HELPER FUNCTIONS """


def html_to_markdown(html: str) -> str:
    """
    Convert an HTML report body into markdown.

    :type html: str
    :param html: Raw HTML body returned by Ignite.

    :return: Markdown representation of the body, or an empty string when the input is empty.
    :rtype: str
    """
    if not html:
        return ""
    return md(str(html), heading_style="ATX")


def trim_spaces_from_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Trim leading and trailing whitespace from all string argument values.

    :type args: dict[str, Any]
    :param args: Command arguments dictionary.

    :return: Arguments dictionary with string values stripped.
    :rtype: dict[str, Any]
    """
    for key, value in args.items():
        if isinstance(value, str):
            args[key] = value.strip()
    return args


def get_command_result(command_results: list) -> dict:
    """
    Return the first non-error result from an executeCommand output list.

    :type command_results: list
    :param command_results: Raw list returned by demisto.executeCommand.

    :return: First successful result entry, or an empty dict if all entries are errors.
    :rtype: dict
    """
    for result in command_results:
        if not isError(result):
            return result
    return {}


def execute_command_safe(command: str, args: dict) -> tuple[dict, Any]:
    """
    Execute a demisto command and return a (result, error) tuple.

    :type command: str
    :param command: Name of the demisto command to execute.

    :type args: dict
    :param args: Arguments to pass to the command.

    :return: (result_dict, None) on success; ({}, error_contents) on failure.
             The error value is the raw Contents field from the error entry, which may be str, dict, or list.
    :rtype: tuple[dict, Any]
    """
    raw = demisto.executeCommand(command, args)
    if not isinstance(raw, list):
        raw = [raw]
    result = get_command_result(raw)
    if not result:
        error = raw[0].get("Contents", "Unknown error") if raw and isinstance(raw[0], dict) else "Unknown error"
        return {}, error
    return result, None


def build_body(report: dict) -> str:
    """
    Build the Threat Intel Report body from an Ignite report.

    The Executive Brief layout does not render 'summary', 'id', 'platform_url', 'ingested_at'
    or 'actors', so these are prepended to the body as a metadata header to keep them visible.

    :type report: dict
    :param report: Raw Ignite report.

    :return: Markdown body consisting of a metadata header followed by the converted report body under a
        'Report Body' heading.
    :rtype: str
    """
    platform_url = report.get("platform_url")
    entries = {
        "Summary": report.get("summary"),
        "Report ID": report.get("id"),
        "Source": f"[Flashpoint Ignite]({platform_url})" if platform_url else None,
        "Ingested": report.get("ingested_at"),
        "Actors": ", ".join(actor for actor in report.get("actors") or [] if actor),
    }
    header = "\n\n".join(f"**{label}:** {value}" for label, value in entries.items() if value)

    body = html_to_markdown(report.get("body") or "") or EMPTY_REPORT_BODY
    body = f"**Report Body**\n\n---\n\n{body}"
    return f"{header}\n\n{body}" if header else body


def build_payload(report: dict) -> dict:
    """
    Map an Ignite report onto the arguments of the createThreatIntelReport command.

    :type report: dict
    :param report: Raw Ignite report.

    :return: Arguments for the createThreatIntelReport command, with empty values removed.
    :rtype: dict
    """
    published_status = report.get("published_status") or ""
    payload = {
        "type": REPORT_TYPE,
        "name": report.get("title"),
        "bodyexecutivebrief": build_body(report),
        "description": report.get("summary"),
        "published": report.get("posted_at"),
        "modified": report.get("updated_at") or report.get("version_posted_at"),
        "tags": report.get("tags"),
        "reportstatus": PUBLISHED_STATUS if published_status.lower() == "published" else DRAFT_STATUS,
        "value": report.get("id"),
    }
    remove_nulls_from_dictionary(payload)
    return payload


""" COMMAND FUNCTION """


def create_threat_intel_report(args: dict[str, Any]) -> list:
    """
    Retrieve an Ignite report and create the corresponding Executive Brief Threat Intel Report.

    :type args: dict[str, Any]
    :param args: Script arguments.
        - report_id (str): ID of the Ignite report.

    :return: The entry returned by the createThreatIntelReport command, followed by a result holding a summary
        of the created Threat Intel Report.
    :rtype: list

    :raises ValueError: If report_id is not provided, the report is not found, or either of the
        executed commands fails.
    """
    remove_nulls_from_dictionary(args)

    report_id = args.get("report_id")
    if not report_id:
        raise ValueError(ERROR_MESSAGES["MISSING_ARGUMENT"].format("report_id"))

    result, err = execute_command_safe(REPORT_GET_COMMAND, {"report_id": report_id})
    if err:
        raise ValueError(ERROR_MESSAGES["FAILED_COMMAND"].format(REPORT_GET_COMMAND, err))

    report = result.get("Contents") or {}
    if not isinstance(report, dict) or not report.get("id"):
        raise ValueError(ERROR_MESSAGES["NO_REPORT"].format(report_id))

    payload = build_payload(report)

    report_result, err = execute_command_safe(CREATE_XSOAR_THREAT_INTEL_REPORT_COMMAND, payload)
    if err:
        raise ValueError(ERROR_MESSAGES["FAILED_COMMAND"].format(CREATE_XSOAR_THREAT_INTEL_REPORT_COMMAND, err))

    readable_output = tableToMarkdown(
        "Created Threat Intel Report",
        {
            "Name": payload.get("name"),
            "Type": REPORT_TYPE,
            "Report ID": payload.get("value"),
            "Report Status": payload.get("reportstatus"),
            "Published": payload.get("published"),
            "Tags": ", ".join(report.get("tags") or []),
        },
        ["Name", "Type", "Report ID", "Report Status", "Published", "Tags"],
        removeNull=True,
    )

    return [report_result, CommandResults(readable_output=readable_output)]


""" MAIN FUNCTION """


def main():
    """
    Entry point. Reads script arguments, executes create_threat_intel_report,
    and returns results. Catches all exceptions and surfaces them via return_error.
    """
    try:
        return_results(create_threat_intel_report(trim_spaces_from_args(demisto.args())))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute FlashpointCreateThreatIntelReport. Error: {ex!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
