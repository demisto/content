import demistomock as demisto
from CommonServerPython import *

from FormatURLApiModule import *  # noqa: E402


def main():
    raw_urls = argToList(demisto.args().get('input'), separator='|')
    try:
        formatted_urls = format_urls(raw_urls)
        output = [{
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': [urls.replace("==", "\\==")],  # This is used to escape MD in XSOAR
            'EntryContext': {'URL': urls},
        } for urls in formatted_urls]

        for url in output:
            demisto.results(url)

    except Exception as e:
        return_error(
            f'Failed to execute the automation. Error: \n{str(e)}'
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no-cover
    main()
