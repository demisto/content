import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

UNSUPPORTED_COMMAND_MSG = "Unsupported Command : getEntriesByIDs"


def get_errors(entries: List) -> List[str]:
    """Extracts error entry contents

    The entries argument should be a list of demisto entries

    Args:
        entries (List[List[Dict]]): multiples entries of results of demisto.executeCommand()

    Returns:
        (List[str]): Error messages extracted from error entries
    """
    error_messages = []
    for entry in entries:
        if isinstance(entry, list):
            assert len(entry) == 1
            entry_details = entry[0]
        else:
            entry_details = entry
        is_error_entry = isinstance(entry_details, dict) and entry_details["Type"] == entryTypes["error"]
        if is_error_entry:
            error_messages.append(entry_details["Contents"])

    return error_messages


def get_entries(entry_ids: list) -> list:
    entries = []

    if is_xsiam_or_xsoar_saas():
        entry_ids_str = ",".join(entry_ids)
        entries = demisto.executeCommand("getEntriesByIDs", {"entryIDs": entry_ids_str})
        if is_error(entries) and UNSUPPORTED_COMMAND_MSG in get_error(entries):
            entries = []  # unsupported, try again using getEntry

    if not entries:
        entries = [demisto.executeCommand("getEntry", {"id": entry_id}) for entry_id in entry_ids]
    return entries


def main():
    try:
        args = demisto.args()
        # the entry_id argument can be a list of entry ids or a single entry id
        entry_ids = args.get("entry_id", demisto.get(demisto.context(), "lastCompletedTaskEntries"))
        entry_ids = argToList(entry_ids)

        entries = get_entries(entry_ids)
        error_messages = get_errors(entries)

        # Set yes or no based on the presence of errors
        error_status = "yes" if error_messages else "no"

        # If errors found, set them in the context
        if error_messages:
            demisto.setContext("OnError.Message", error_messages)

        # Directly return yes or no
        return_results(error_status)

    except Exception as e:
        return_error(f"Failed to fetch errors for the given entry id(s). Problem: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
