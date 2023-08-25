import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' COMMAND FUNCTION '''


def CamelCaseToDotCase(key):
    dot_format = ""
    for char in key:
        if char.isupper():
            dot_format += "." + char.lower()
        else:
            dot_format += char

    return dot_format


def display_metas():
    incident = demisto.incident()

    if (
        not isinstance(incident, dict)
        or 'CustomFields' not in incident
        or 'metasevents' not in incident['CustomFields']
        or not len(incident['CustomFields']['metasevents'])
    ):
        return {'Type': entryTypes['note'], 'ContentsFormat': formats['markdown'], 'Contents': 'No event available for this incident.'}

    metasevents = incident['CustomFields']['metasevents'][0]

    markdown = tableToMarkdown('', metasevents, headers=metasevents.keys(), headerTransform=CamelCaseToDotCase)

    return {'Type': entryTypes['note'], 'ContentsFormat': formats['markdown'], 'Contents': markdown}


''' MAIN FUNCTION '''


def main():

    content = display_metas()
    return_results(content)


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

