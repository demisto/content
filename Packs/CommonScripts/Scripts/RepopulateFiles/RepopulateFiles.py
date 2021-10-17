import hashlib
import os
import re
from typing import Any, Dict, Iterator, List, Optional

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def make_file_entry_context(ent: Dict[str, Any], data: bytes) -> Dict[str, Any]:
    """
    Create an File entry context for an attachment

    :param ent: An attachment entry
    :param data: The payload to the entry
    :return: An File entry context
    """
    name, ext = os.path.splitext(ent['File'])
    fmeta = ent['FileMetadata']
    return {
        'Name': ent['File'],
        'MD5': fmeta.get('md5') or hashlib.md5(data).hexdigest(),
        'SHA1': fmeta.get('sha1') or hashlib.sha1(data).hexdigest(),
        'SHA256': fmeta.get('sha256') or hashlib.sha256(data).hexdigest(),
        'SSDeep': fmeta.get('ssdeep'),
        'Size': fmeta.get('size') or len(data),
        'Info': fmeta.get('info'),
        'Type': fmeta.get('type'),
        'Extension': ext[1:] if ext else '',
        'EntryID': ent['ID']
    }


def find_attachment_entry(ents: List[Dict[str, Any]], data: bytes, name: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Find an attachment entry matches to the payload.

    :param ents: The entries
    :param data: The file data
    :param name: The file name
    :return: An entry which the file data is correspond to.
    """
    alternate = None
    for ent in ents:
        fmeta = ent.get('FileMetadata')
        fname = ent.get('File')
        if fname and fmeta:
            for alg in ['sha512', 'sha256', 'sha1', 'md5']:
                h = fmeta.get(alg)
                if h:
                    hobj = hashlib.new(alg)
                    hobj.update(data)
                    if h.lower() == hobj.hexdigest().lower():
                        return ent
                    break
            if name and name == fname:
                alternate = ent
    return alternate


def iterate_entries(incident_id: Optional[str], query_filter: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    """
    Iterate war room entries

    :param incident_id: The incident ID to search entries from.
    :param query_filter: Filters to search entries.
    :return: An iterator to retrieve entries.
    """
    query_filter = dict(**query_filter)
    first_id = 1
    while True:
        query_filter['firstId'] = str(first_id)

        ents = demisto.executeCommand('getEntries', assign_params(
            id=incident_id,
            filter=query_filter
        ))
        if not ents:
            break

        if is_error(ents[0]):
            if first_id == 1:
                return_error('Unable to retrieve entries')
            break

        for ent in ents:
            yield ent

        # Set the next ID
        last_id = ent['ID']
        m = re.match('([0-9]+)', last_id)
        if not m:
            raise ValueError('Invalid entry ID: {last_id}')
        next_id = int(m[1]) + 1
        if next_id <= first_id:
            break
        first_id = next_id


def collect_file_infos(incident_id: Optional[str], file_fields: List[str]) -> List[Dict[str, Any]]:
    """
    Get list of file information

    :param incident_id: The incident ID to search entries from.
    :param file_fields: List of field name which to extract attachment files from.
    :return: Get list of file information.
    """
    incident = demisto.incident()
    file_infos = []
    for file_field in file_fields:
        files = incident.get(file_field)
        if files is None:
            files = demisto.get(incident, f'CustomFields.{file_field}') or []
        if files:
            attachment_ents = [ent for ent in iterate_entries(None, {'categories': ['attachments']})]
            for file in files:
                # Extract the File ID
                apath = file['path']
                m = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', apath)
                if not m:
                    raise ValueError(f'Failed to get file ID for {apath}')
                else:
                    # Read the file contents
                    fpath = demisto.getFilePath(m.group())
                    with open(fpath['path'], 'rb') as f:
                        data = f.read()

                    # Find the attachment entry
                    attachment_ent = find_attachment_entry(attachment_ents, data, file.get('name'))
                    if not attachment_ent:
                        raise RuntimeError('No attachment entry found in the war room')
                    else:
                        file_infos.append({
                            'Attachment': file,
                            'AttachmentEntry': attachment_ent,
                            'File': make_file_entry_context(attachment_ent, data)
                        })
    return file_infos


def main():
    args = demisto.args()
    file_fields = argToList(args.get('fields', 'attachment'))
    try:
        file_infos = collect_file_infos(None, file_fields)
    except Exception as e:
        return_error(str(e))

    if not file_infos:
        return_outputs('No files were found.')
    else:
        return_outputs(
            'Done',
            {
                outputPaths['file']: [a['File'] for a in file_infos],
                'AttachmentFile': [dict(a['File'], **{'Attachment': a['Attachment']}) for a in file_infos]
            },
            file_infos)


if __name__ in ('__builtin__', 'builtins'):
    main()
