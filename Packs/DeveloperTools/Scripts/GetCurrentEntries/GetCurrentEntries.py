import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' MAIN FUNCTION '''


def main():
    incident_id = demisto.args().get('incident_id')
    response = demisto.internalHttpRequest('POST', f'investigation/{incident_id}', body={"pageSize": 200})
    body = json.loads(response.get('body'))
    entries = body.get('entries')
    entry_contents = {}
    for entry in entries:
        if entry.get('contents'):
            dict_safe_key = re.sub(r'\W+', '', entry.get('contents'))
            if not dict_safe_key in entry_contents:
                entry_contents[dict_safe_key] = 1
            else:
                entry_contents[dict_safe_key] = entry_contents.get(dict_safe_key) + 1

    demisto.results(
        {
            'EntryContext': {
                "LatestEntries": entry_contents
            },
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': "Success"
        }
    )


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
