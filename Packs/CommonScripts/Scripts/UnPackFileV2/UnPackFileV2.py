import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import traceback
import rarfile
import os


def extract(file_entry_id: str) -> CommandResults:

    file_base_names = []
    contents = []
    if not file_entry_id:
        raise Exception('You must set the entry_id when executing UnPackFile script.')

    archive_path = demisto.getFilePath(file_entry_id).get('path')
    rf = rarfile.RarFile(archive_path)
    for f in rf.infolist():
        file_path = f.filename
        if f.is_file():
            file_base_name = os.path.basename(file_path)
            file_base_names.append(file_base_name)
            contents.append({
                'Name': file_base_name,
                'Path': file_path
            })
            with rf.open(file_path) as file_:
                demisto.results(fileResult(file_base_name, file_.read()))

    return CommandResults(
        outputs_prefix='ExtractedFiles',
        outputs=file_base_names,
        readable_output=tableToMarkdown('Extracted Files', contents)
    )


''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        file_entry_id = args.get('entry_id')
        return_results(extract(file_entry_id))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute UnPackFileV2. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
