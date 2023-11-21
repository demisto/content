import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import os
from os.path import isdir, isfile

from pyunpack import Archive

filePath = None
fileEntryID = ''
if 'fileName' in demisto.args() or 'lastPackedFileInWarroom' in demisto.args():
    entries = demisto.executeCommand('getEntries', {})
    for entry in entries:
        fn = demisto.get(entry, 'File')

        is_text = type(fn) in [unicode, str]
        is_correct_file = demisto.args().get('fileName', '').lower() == fn.lower()

        if is_text:
            if 'fileName' in demisto.args() and is_correct_file:
                fileEntryID = entry['ID']
                break
            if 'lastPackedFileInWarroom' in demisto.args() and fn.lower().endswith(demisto.args().get(
                    'lastPackedFileInWarroom', '').lower()):
                fileEntryID = entry['ID']

    if fileEntryID == '':
        errorMessage = ''
        if 'fileName' in demisto.args():
            demisto.results({
                'Type': entryTypes['error'],
                'ContentsFormat': formats['text'],
                'Contents': '"' + demisto.args().get('fileName') + '" no such file in the war room'
            })
        if 'lastPackedFileInWarroom' in demisto.args():
            demisto.results({
                'Type': entryTypes['error'],
                'ContentsFormat': formats['text'],
                'Contents': 'Could not find "' + demisto.args().get('lastPackedFileInWarroom',
                                                                    '') + '" file in war room'
            })

        sys.exit(0)

if 'entryID' in demisto.args():
    fileEntryID = demisto.args().get('entryID')

if not fileEntryID:
    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': 'You must set entryID or fileName or lastPackedFileInWarroom=i.e.(zip) when executing Unpack script'
    })
    sys.exit(0)

res = demisto.executeCommand('getFilePath', {'id': fileEntryID})
if res[0]['Type'] == entryTypes['error']:
    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': 'Failed to get the file path for entry: ' + fileEntryID
    })
    sys.exit(0)

filePath = res[0]['Contents']['path']

filenames = []
# remembering which files and dirs we currently have so we add them later as newly extracted files.
excludedFiles = [f for f in os.listdir('.') if isfile(f)]
excludedDirs = [d for d in os.listdir('.') if isdir(d)]

# extracting the archive file
Archive(filePath).extractall_patool('.', None)
# recursing over the file system top down
for root, directories, files in os.walk('.'):
    # removing the previously existing dirs from the search
    directories[:] = [d for d in directories if d not in excludedDirs]
    for f in files:
        # skipping previously existing files and verifying that the current file is a file and then adding it
        # to the extracted files list
        if f not in excludedFiles and isfile(os.path.join(root, f)):
            filenames.append(os.path.join(root, f))
if len(filenames) == 0:
    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': 'Could not find files in archive'
    })
else:
    results = []
    # extracted files can be in sub directories so we save the base names of the files and also the full path of
    # the file
    files_base_names = [os.path.basename(file_path) for file_path in filenames]
    files_dic = {file_path: os.path.basename(file_path) for file_path in filenames}
    for file_path, file_name in files_dic.items():
        demisto.results(file_result_existing_file(file_path, file_name))
    results.append(
        {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {'extractedFiles': files_base_names},
            'EntryContext': {'ExtractedFiles': files_base_names,
                             'File(val.EntryID=="' + fileEntryID + '").Unpacked': True},
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Extracted Files',
                                             [{'name': file_name, 'path': file_path} for file_path, file_name in
                                              files_dic.items()])
        })
    demisto.results(results)
