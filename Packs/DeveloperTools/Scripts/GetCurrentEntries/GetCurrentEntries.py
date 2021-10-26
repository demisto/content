import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def fetch_entries(incident_id: str):
    entries: dict = {}
    try:
        response = demisto.internalHttpRequest('POST', f'investigation/{incident_id}', body={"pageSize": 200})
        body = json.loads(response.get('body'))
        entries = body.get('entries')
    except Exception as e:
        return_error(f"Failed to retrieve entries from server. {e}")
    return entries


''' MAIN FUNCTION '''


def main():
    incident_id = demisto.args().get('incident_id')
    entries = fetch_entries(incident_id)
    entry_contents: dict = {}
    if len(entries) > 0:
        for entry in entries:
            if entry.get('contents'):
                context_safe_key = re.sub(r'\W+', '', entry.get('contents'))
                if context_safe_key not in entry_contents:
                    entry_contents[context_safe_key] = 1
                else:
                    entry_contents[context_safe_key] = entry_contents.get(context_safe_key, 0) + 1
        contents: str = "Entries successfully added to context."
        entry_context: dict = entry_contents
    else:
        contents: str = "No entries were returned"
        entry_context: dict = {}
    return CommandResults(
        outputs_prefix='LatestEntries',
        outputs_key_field='ID',
        outputs=entry_context,
        readable_output=contents
    )


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(main())
