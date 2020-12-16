import os

from CommonServerPython import *


def parse_attachment_entries(entries):
    # list -> list
    """Parse the attachments entries.

    Args:
        entries: entries of attachments.

    Returns:
        List of entry context dict containing the attachments metadata.
    """
    entry_context = []
    for entry in entries:
        if entry.get('File') and entry.get('FileMetadata'):
            name, ext = os.path.splitext(entry['File'])
            entry_context.append({
                'Name': entry['File'],
                'MD5': entry['FileMetadata'].get('md5'),
                'SHA1': entry['FileMetadata'].get('sha1'),
                'SHA256': entry['FileMetadata'].get('sha256'),
                'SSDeep': entry['FileMetadata'].get('ssdeep'),
                'Size': entry['FileMetadata'].get('size'),
                'Info': entry['FileMetadata'].get('info'),
                'Type': entry['FileMetadata'].get('type'),
                'Extension': ext[1:] if ext else '',
                'EntryID': entry['ID']
            })
    return entry_context


def main():
    """Repopulate the incident context with the attachments metadata.

    Returns:
        Demisto entry.
    """
    entries = demisto.executeCommand('getEntries', {'filter': {'categories': ['attachments']}})
    if isinstance(entries, list):
        entry_context = parse_attachment_entries(entries)
        return_outputs('Done', {outputPaths['file']: entry_context}, entry_context)
    else:
        return_outputs('No attachments were found.')


if __name__ in ["__builtin__", "builtins"]:
    main()
