from typing import Dict, Union

import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from tempfile import mkdtemp
import shutil
import subprocess
import hashlib


def get_pcap_path(args: Dict) -> str:
    """

    Args:
        args: argument from demisto

    Returns: path of pcap file

    """
    file_entry_id = args.get('entry_id', '')

    res = demisto.executeCommand('getFilePath', {'id': file_entry_id})
    if is_error(res):
        raise Exception(f'Failed to get the file path for entry: {file_entry_id} - {get_error(res)}')

    return res[0]['Contents']['path']


def upload_files(dir_path: str, file_path: str) -> Union[CommandResults, str]:
    """

    Args:
        dir_path: dir path for the files
        file_path: the path to the pcap file

    Returns:
        Extracted files to download

    """

    process = subprocess.Popen(['tshark', '-r', f'{file_path}', '--export-objects', f'http,{dir_path}',
                                '--export-objects', f'smb,{dir_path}', '--export-objects', f'imf,{dir_path}',
                                '--export-objects', f'tftp,{dir_path}', '--export-objects', f'dicom,{dir_path}'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.communicate()

    context = []

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    for root, _, files in os.walk(dir_path):
        if len(files) == 0:
            return 'No files found.'

        for f in files:
            file_path = os.path.join(root, f)
            file_name = os.path.join(f)

            with open(file_path, 'rb') as file:
                data = file.read()
                demisto.results(fileResult(file_name, data))

                md5.update(data)
                sha1.update(data)
                sha256.update(data)

            context.append({
                'FileMD5': md5.hexdigest(),
                'FileSHA1': sha1.hexdigest(),
                'FileSHA256': sha256.hexdigest(),
                'FileName': file_name,
                'FileSize': os.path.getsize(file_path),
                'FileExtension': os.path.splitext(file_name)[1]
            })

        readable_output = tableToMarkdown('Pcap Extracted Files', [{'name': file_name} for file_name in files])

        results = CommandResults(
            outputs_prefix='PcapExtractedFiles',
            outputs_key_field='FileMD5',
            outputs=context,
            readable_output=readable_output
        )

    return results


def main():
    dir_path = mkdtemp()
    try:
        args = demisto.args()
        file_path = get_pcap_path(args)
        return_results(upload_files(dir_path, file_path))

    except Exception as e:
        return_error(f'Failed to execute PcapFileExtracor. Error: {str(e)}')
    finally:
        if dir_path:
            shutil.rmtree(dir_path)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
