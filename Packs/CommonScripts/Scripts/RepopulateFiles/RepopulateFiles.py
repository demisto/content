import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import os
import hashlib
from typing import List, Dict, Optional, Any


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
            entry_context.append(assign_params(
                Name=entry['File'],
                MD5=entry['FileMetadata'].get('md5'),
                SHA1=entry['FileMetadata'].get('sha1'),
                SHA256=entry['FileMetadata'].get('sha256'),
                SHA512=entry['FileMetadata'].get('sha512'),
                SSDeep=entry['FileMetadata'].get('ssdeep'),
                Size=entry['FileMetadata'].get('size'),
                Info=entry['FileMetadata'].get('info'),
                Type=entry['FileMetadata'].get('type'),
                Extension=ext[1:] if ext else '',
                EntryID=entry['ID']
            ))
    return entry_context


def find_attachment_entry(file_ents: List[Dict[str, Any]], attachment_ent: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Find an incident attachment entry

    :param file_ents: A list of file entries
    :param attachment_ent: An entry of an incident attachment file
    :return: An file entry to which the attachment is correspond.
    """
    # Extract the File ID
    path = attachment_ent.get('path')
    if not path:
        demisto.debug('Key not found: path')
        return None

    m = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', path)
    if not m:
        demisto.debug(f'Failed to get file ID for {path}')
        return None

    # Compute hash values
    try:
        hash_table = {}
        file = demisto.getFilePath(m.group())
        for alg in ['SHA512', 'SHA256', 'SHA1', 'MD5']:
            with open(file['path'], 'rb') as f:
                hobj = hashlib.new(alg)
                for chunk in iter(lambda: f.read(hobj.block_size * 4096), b''):
                    hobj.update(chunk)
                hash_table[alg] = hobj.hexdigest().lower()
    except Exception as e:
        demisto.debug(str(e))
        return None

    # Find the attachment entry
    for file_ent in file_ents:
        for alg, hval in hash_table.items():
            if file_ent.get(alg, '').lower() == hval:
                # Update hash entries
                file_ent.update(hash_table)
                return file_ent
    return None


def main():
    """Repopulate the incident context with the attachments metadata.

    Returns:
        Demisto entry.
    """
    entries = demisto.executeCommand(
        'getEntries',
        {
            'filter': {
                'categories': ['attachments']
            }
        }
    )
    if is_error(entries):
        return_error(get_error(entries))
    if isinstance(entries, list):
        war_attachment_ents = parse_attachment_entries(entries)
        inc_attachment_ents = []
        for ent in demisto.incident().get('attachment') or []:
            inc_attachment_ent = find_attachment_entry(war_attachment_ents, ent)
            if inc_attachment_ent:
                inc_attachment_ents.append(dict(inc_attachment_ent, Attachment=ent))

        entry_context = {outputPaths['file']: war_attachment_ents}
        if inc_attachment_ents:
            entry_context['AttachmentFile(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || '
                          'val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || '
                          'val.SSDeep && val.SSDeep == obj.SSDeep)'] = inc_attachment_ents

        return_outputs('Done', entry_context, war_attachment_ents)
    else:
        return_outputs('No attachments were found.')


if __name__ in ["__builtin__", "builtins"]:
    main()
