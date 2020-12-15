import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


def main():
    url_list = argToList(demisto.args().get('input'))
    entry_list = []

    for url in url_list:
        entry_list.append({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': 2,
            'EntryContext': {
                'DBotScore': {
                    'Indicator': url,
                    'Type': 'Onion URL',
                    'Score': 2,  # suspicious
                    'Vendor': 'DBot'
                }
            }
        })

    demisto.results(entry_list)


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
