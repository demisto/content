import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from time import sleep


def get_entry_id():
    entry_id = ''
    files = []

    for index in range(1, 4):
        try:
            context = demisto.context()
            files = context['InfoFile']
            break

        except KeyError:
            sleep(index * 2)

    try:
        for file in files:
            if file['Name'].startswith('suspicious'):
                entry_id = file['EntryID']
                break

    except TypeError:
        if files['Name'].startswith('suspicious'):
            entry_id = files['Name']

    return entry_id


def main():

    entry_id = get_entry_id()

    server_url = demisto.executeCommand('GetServerURL', {})[0].get('Contents')

    link = f'{server_url}/entry/download/{entry_id}'

    if entry_id:
        html = f'<-:->![pic]({link})\n[Download]({link})'

    else:
        html = '<-:->No Image'

    demisto.results({
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': html,
    })


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
