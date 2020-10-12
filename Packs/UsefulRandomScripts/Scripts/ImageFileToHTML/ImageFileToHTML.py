import base64

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

supported_types = [
    'image/png',
    'image/jpeg',
    'image/gif',
    'image/bmp',
    'image/svg+xml',
    'image/tiff',
    'image/webp'
]

entry_id = demisto.args().get('entryId')
res = demisto.getFilePath(entry_id)
if not res:
    return_error(f"Entry {entry_id} not found")

file_entry = demisto.executeCommand("getEntry", {"id": entry_id})[0]
file_name = file_entry.get('File')
file_type = file_entry.get('FileMetadata').get('type')
file_path = res.get('path')

if file_type not in supported_types:
    return_error(f"'{file_type}' is not a supported file type. Supported types include '{','.join(supported_types)}'")
else:
    with open(file_path, 'rb') as f:
        encoded_file = base64.b64encode(f.read())

    data = encoded_file.decode('ascii')
    html = f'<img src="data:{file_type};base64,{data}" alt="image from xsoar">'

    demisto.results({
        'Contents': html,
        'ContentsFormat': formats['text'],
        'EntryContext': {'ImageFileToHTML': [html]}
    })
