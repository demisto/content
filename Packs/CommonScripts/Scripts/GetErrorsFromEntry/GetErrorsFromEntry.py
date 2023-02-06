import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


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
        assert len(entry) == 1
        entry_details = entry[0]
        is_error_entry = isinstance(entry_details, dict) and entry_details['Type'] == entryTypes['error']
        if is_error_entry:
            demisto.debug(f'error entry contents: "{entry_details["Contents"]}"')
            error_messages.append(entry_details['Contents'])

    return error_messages


def main():
    try:
        args = demisto.args()
        # the entry_id argument can be a list of entry ids or a single entry id
        entry_ids = args.get('entry_id', demisto.get(demisto.context(), 'lastCompletedTaskEntries'))
        entry_ids = argToList(entry_ids)

        entries = [demisto.executeCommand('getEntry', {'id': entry_id}) for entry_id in entry_ids]
        error_messages = get_errors(entries)

        return_results(CommandResults(
            readable_output='\n'.join(error_messages),
            outputs_prefix='ErrorEntries',
            outputs=error_messages,
            raw_response=error_messages,
        ))
    except Exception as e:
        return_error(f'Failed to fetch errors for the given entry id(s). Problem: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
