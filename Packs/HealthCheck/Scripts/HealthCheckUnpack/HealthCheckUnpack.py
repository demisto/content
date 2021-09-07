import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import tarfile
import re


def extract_files(path, action):
    extracted_files = []
    try:
        with tarfile.open(path, action) as tar:
            for tar_file in tar.getnames():
                extracted_file = tar.extractfile(tar_file)
                if not extracted_file:
                    continue

                data = extracted_file.read()
                tar_file = tar_file.rsplit('/', 1)[1]

                return_results(fileResult(tar_file, data))
                extracted_files.append(tar_file)

        return_results(CommandResults(
            readable_output=tableToMarkdown('', extracted_files, headers='Extracted Files'),
            outputs_prefix='ExtractedFiles',
            outputs=extracted_files,
        ))
        return 'yes'

    except UnicodeDecodeError:
        return "Could not read file"
    except IndexError:
        return "Could not extract files"


def main(args):
    entry_id = args['entryID']

    try:
        res = demisto.getFilePath(entry_id)
        file_path = res['path']
        file_name = res['name']
        file_suffix = re.findall(r"re:|tar|gz", file_name)

        if "gz" in file_suffix and "tar" in file_suffix:
            tar_action = "r:gz"
        elif "tar" in file_suffix:
            tar_action = "r:"
        else:
            return 'no'

        return extract_files(file_path, tar_action)

    except Exception:
        return 'File not found'


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    return_results(main(demisto.args()))
