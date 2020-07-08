import hashlib
import subprocess
import tempfile
from typing import Dict, Union, Set, Optional

import magic

from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


class InclusiveExclusive:
    INCLUSIVE = 'inclusive'
    EXCLUSIVE = 'exclusive'


def get_file_path_from_id(entry_id: Optional[str] = None):
    if entry_id:
        return demisto.getFilePath(entry_id).get('path')
    else:
        return None


def run_process(args: list, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    """Running a process

    Args:
        args: args as will be passed to Popen
        stdout: STDOUT pipe
        stderr: STDERR pipe

    Raises:
        DemistoException if returncode is different than 0
    """
    demisto.results(f'running command {args}')
    process = subprocess.Popen(args, stdout=stdout, stderr=stderr)
    process.wait()
    stdout_data, stderr_data = process.communicate()
    if process.returncode != 0:
        raise DemistoException(f'Error returned from tshark command: {process.returncode=} {stderr_data}')


def upload_files(
        file_path: str, dir_path: str, /,
        types: Optional[Set[str]] = None, extensions: Optional[Set[str]] = None,
        types_inclusive_or_exclusive: Optional[str] = None,
        extensions_inclusive_or_exclusive: Optional[str] = None,
        limit: int = 5
) -> Union[CommandResults, str]:
    """

    Args:
        file_path: the path to the PCAP file
        dir_path: dir path for the files
        types:
        extensions:
        types_inclusive_or_exclusive:
        extensions_inclusive_or_exclusive:
        limit:

    Returns:
        Extracted files to download

    """
    run_process(['tshark', '-r', f'{file_path}', '--export-objects', f'http,{dir_path}',
                 '--export-objects', f'smb,{dir_path}', '--export-objects', f'imf,{dir_path}',
                 '--export-objects', f'tftp,{dir_path}', '--export-objects', f'dicom,{dir_path}'])

    context = []
    magic_mime = magic.Magic(mime=True)
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    # strip `.` from extension
    if extensions:
        extensions = [extension.split(".")[-1] for extension in extensions]
    for root, _, files in os.walk(dir_path):
        # Limit the files list to minimum
        files = files[: limit]
        if not files:
            return 'No files found.'
        # Filter files
        for file in files:
            # types list supplied,
            if types:
                mime_type = magic_mime.from_file(os.path.join(root, file))
                # Inclusive types, take only the types in the list.
                if types_inclusive_or_exclusive == InclusiveExclusive.INCLUSIVE and mime_type not in types:
                    continue
                # Exclusive types, don't take those files.
                elif types_inclusive_or_exclusive == InclusiveExclusive.EXCLUSIVE and mime_type not in types:
                    continue
            if extensions:
                # Get file extension without a leading point.
                f_ext = os.path.splitext(file)[1].split('.')[-1]
                # Inclusive extensions, take only the types in the list.
                if extensions_inclusive_or_exclusive == InclusiveExclusive.INCLUSIVE and f_ext in extensions:
                    continue
                # Exclude extensions, don't take those files.
                elif extensions_inclusive_or_exclusive == InclusiveExclusive.EXCLUSIVE and f_ext not in extensions:
                    continue

            file_path = os.path.join(root, file)
            file_name = os.path.join(file)

            with open(file_path, 'rb') as file_stream:
                data = file_stream.read()
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
    else:
        raise DemistoException('No files found in path.')


def decrypt(
        file_path: str,
        password: Optional[str] = None,
        rsa_key_path: Optional[str] = None
) -> str:
    if not password and not rsa_key_path:
        return file_path
    file_extension = os.path.splitext(file_path)[1]
    with tempfile.NamedTemporaryFile(suffix=file_extension) as temp_file:
        command = ['tshark', '-r', file_path, '-w', temp_file.name]

        if password:
            command.extend([
                '-o', 'wlan.enable_decryption:TRUE',
                '-o', f'uat:80211_keys:"wpa-pwd","{password}"'
            ])

        if rsa_key_path:
            command.extend(['-o', f'uat:rsa_keys:"{rsa_key_path}",""'])
        run_process(command)
        return temp_file.name


def main():
    with tempfile.TemporaryDirectory() as dir_path:
        try:
            kwargs = demisto.args()
            file_path = get_file_path_from_id(kwargs.get('entry_id'))
            file_path = decrypt(
                file_path, kwargs.get('wpa_password'), get_file_path_from_id(kwargs.get('rsa_decrypt_key_entry_id'))
            )
            return_results(upload_files(
                file_path, dir_path,
                types=set(argToList(kwargs.get('types'))),
                extensions=set(argToList(kwargs.get('extensions'))),
                types_inclusive_or_exclusive=kwargs.get('types_inclusive_or_exclusive'),
                extensions_inclusive_or_exclusive=kwargs.get('extensions_inclusive_or_exclusive'),
                limit=int(kwargs.get('limit', 5))
            ))

        except Exception as e:
            return_error(f'Failed to execute PcapFileExtracor. Error: {str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
