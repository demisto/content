import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import tarfile
import io

# arguments
action = demisto.args().get('action')
entry_id = demisto.args().get('entry_id')
file_names = demisto.args().get('file_names')

# handle single file export by ensuring it's still a list
if not isinstance(file_names, list):
    file_names = [file_names]

# check if the content bundle exists
res = demisto.getFilePath(entry_id)
if not res:
    return_error(f"Entry {entry_id} not found")

file_path = res.get('path')

# Return a list of custom content in the content bundle
if action == 'listfiles':
    files = []
    with open(file_path, 'rb') as f:
        data = f.read()
        tar = tarfile.open(fileobj=io.BytesIO(data))
        files = tar.getnames()

    files = [file[1:] for file in files]
    readable = f"Got {len(files)} file names from custom content bundle"
    results = CommandResults(
        readable_output=readable,
        outputs_prefix='CustomContent',
        outputs=files
    )

    return_results(results)

# Return the selected files to the war room
if action == "exportfiles":
    files = [f"/{file}" for file in file_names]
    exported_files = []
    with open(file_path, 'rb') as f:
        data = f.read()
        tar = tarfile.open(fileobj=io.BytesIO(data))

        for member in tar.getmembers():
            path = member.name
            if path in files:
                data = tar.extractfile(member)  # type:ignore
                f = data.read()  # type:ignore
                exported_files.append(member.name[1:])
                demisto.results(fileResult(member.name[1:], f))

    demisto.results(f"Added the following files to Context: {exported_files}")
