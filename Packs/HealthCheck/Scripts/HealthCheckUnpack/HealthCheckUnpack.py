import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import tarfile
import re

ExtractedFiles = []
ec = []

entryID = demisto.args()['entryID']

res = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})
file_path = res[0]['Contents']['path']
file_name = res[0]['Contents']['name']
file_suffix = re.findall(r"re:|tar|gz", file_name)


def extractFiles(path, action):
    try:
        tar = tarfile.open(path, action)

        for tar_file in tar.getnames():
            extracted_file = tar.extractfile(tar_file)
            if not extracted_file:
                continue

            data = extracted_file.read()
            tar_file = tar_file.rsplit('/', 1)[1]

            demisto.results(fileResult(tar_file, data))
            ExtractedFiles.append(tar_file)

        # To display table in war room
        for e in ExtractedFiles:
            ec.append({'ExtractedFiles': e})

        entry = {'Type': entryTypes['note'],
                 'Contents': ec,
                 'ContentsFormat': formats['table'],
                 'EntryContext': {'ExtractedFiles': ExtractedFiles}}

        demisto.results(entry)
        demisto.results('yes')
    except UnicodeDecodeError:
        demisto.results("Could not read file")
    except IndexError:
        demisto.results("Could not extract files")
        tar = res[0]['Contents']['path']


if "gz" in file_suffix and "tar" in file_suffix:
    tar_action = "r:gz"
elif "tar" in file_suffix:
    tar_action = "r:"
else:
    demisto.results('no')

if res[0]['Type'] == entryTypes['error']:
    demisto.results('File not found')
else:
    extractFiles(file_path, tar_action)
