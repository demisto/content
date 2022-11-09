import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incident()

entries = demisto.executeCommand('getEntries', {})


def get_user_display_name(username):
    return demisto.executeCommand('getUserByUsername', {'username': username})[0]['Contents'].get('name')


def make_fancy_time(timestamp):
    params = {'value': timestamp, 'include_raw': False}
    return demisto.executeCommand('fancy-email-make-timestring', params)[0]['Contents']['html']


def extract_entry(entry):
    user = get_user_display_name(entry.get('Metadata').get('user')),
    modified = make_fancy_time(entry.get('Metadata').get('modified'))
    contents = demisto.executeCommand("mdToHtml", {'text': entry.get("Contents")})[0]['Contents']

    return {
        'Notes': f'<br/><b>{user[0]}</b><br/>{modified}<hr/>{contents}',
    }


def convert_to_fancy_table(notes):
    return demisto.executeCommand('fancy-email-make-table', {'items': notes, 'name':
                                                             'Notes',
                                                             'include_raw': False,
                                                             'headers': ['Notes']
                                                             })


def get_note(entry):
    return extract_entry(entry) if entry.get('Note') else None


def filter_out_none(note):
    if note:
        return True
    else:
        return False


entries = list(filter(filter_out_none, map(get_note, entries)))
if entries:
    return_results(convert_to_fancy_table(entries))
else:
    return_results('')
