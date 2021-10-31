import tempfile
from typing import Tuple

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import traceback
import rarfile
import os


def extract(rf: rarfile.RarFile, dir_path=None, password=None) -> Tuple[CommandResults, list]:

    file_base_names = []
    contents = []
    file_list = []

    for file_path in rf.namelist():
        if file_name := os.path.basename(file_path):
            contents.append({
                'Name': file_name,
                'Path': file_path
            })

    rf.extractall(path=dir_path, pwd=password)
    for root, _, files in os.walk(dir_path):
        for file_ in files:
            file_base_name = os.path.basename(file_)
            file_base_names.append(file_base_name)
            file_path = os.path.join(root, file_)

            file_list.append(file_path)

    return CommandResults(
        outputs_prefix='ExtractedFiles',
        outputs=file_base_names,
        readable_output=tableToMarkdown('Extracted Files', contents)
    ), file_list


''' MAIN FUNCTION '''


def main():
    with tempfile.TemporaryDirectory() as dir_path:
        try:
            args = demisto.args()
            file_entry_id = args.get('entry_id')
            password = args.get('password')
            archive_path = demisto.getFilePath(file_entry_id).get('path')
            rf = rarfile.RarFile(archive_path)
            results, files = extract(rf, dir_path, password)
            for file_ in files:
                file_base_name = os.path.basename(file_)
                demisto.results(fileResult(file_base_name, open(file_).read()))
            return_results(results)
        except Exception as ex:
            demisto.error(traceback.format_exc())  # print the traceback
            return_error(f'Failed to execute UnPackFileV2. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
