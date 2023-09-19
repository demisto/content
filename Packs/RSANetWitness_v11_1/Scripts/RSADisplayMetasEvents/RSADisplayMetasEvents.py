import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' COMMAND FUNCTION '''


def CamelCaseToDotCase(key: str) -> str:
    '''
    Convert camel case string to dot case string.
    ex: eventSource => event.source
    '''
    dot_format = ""
    for char in key:
        if char.isupper():
            dot_format += "." + char.lower()
        else:
            dot_format += char

    return dot_format


def display_metas() -> dict:
    '''
    Return metas event alert markdown to display it in dynamic section.
    '''
    incident = demisto.incident()

    if (
        not isinstance(incident, dict)
        or 'CustomFields' not in incident
        or 'rsametasevents' not in incident['CustomFields']
        or not len(incident['CustomFields']['rsametasevents'])
    ):
        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': 'No event available for this incident.'
        }

    rsametasevents = incident.get('CustomFields', {}).get('rsametasevents', [])[0]
    markdown = tableToMarkdown('', rsametasevents, headers=rsametasevents.keys(), headerTransform=CamelCaseToDotCase)
    return {'Type': entryTypes['note'], 'ContentsFormat': formats['markdown'], 'Contents': markdown}


''' MAIN FUNCTION '''


def main():

    content = display_metas()
    return_results(content)


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
