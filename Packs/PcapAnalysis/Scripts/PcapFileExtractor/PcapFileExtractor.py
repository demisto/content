import hashlib
import subprocess
import tempfile

import magic

from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

INCLUSIVE: str = 'inclusive'
EXCLUSIVE: str = 'exclusive'


class HashCalculator:
    """Class to calculate hashes.

    """
    @staticmethod
    def _calculate_by_chunks(hash_calculator, file_path: str) -> str:
        """Calculates hashes by chunks

        Args:
            hash_calculator: A hashlib object
            file_path: File path to calculate hashes

        Returns:
            Hash string.
        """
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_calculator.update(chunk)
        return hash_calculator.hexdigest()

    @classmethod
    def md5(cls, file_path: str) -> str:
        """Calculate MD5 hash of file.

        Args:
            file_path: A path of file to calculate.

        Returns:
            A MD5 hash
        """
        return cls._calculate_by_chunks(hashlib.md5(), file_path)   # nosec

    @classmethod
    def sha1(cls, file_path: str) -> str:
        """Calculate SHA1 hash of file.

        Args:
            file_path: A path of file to calculate.

        Returns:
            A SHA1 hash
        """
        return cls._calculate_by_chunks(hashlib.sha1(), file_path)  # nosec

    @classmethod
    def sha256(cls, file_path: str) -> str:
        """Calculate SHA256 hash of file.

        Args:
            file_path: A path of file to calculate.

        Returns:
            A SHA256 hash
        """
        return cls._calculate_by_chunks(hashlib.sha256(), file_path)


def get_file_path_from_id(entry_id: str) -> tuple[str, str]:
    """Gets a file path and name from entry_id.

    Args:
        entry_id: ID of the file from context.

    Returns:
        file path, name of file
    """
    file_obj = demisto.getFilePath(entry_id)
    return file_obj.get('path'), file_obj.get('name')


def run_command(args: list, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    """Running a process

    Args:
        args: args as will be passed to Popen
        stdout: STDOUT pipe
        stderr: STDERR pipe

    Raises:
        DemistoException if returncode is different than 0
    """
    process = subprocess.Popen(args, stdout=stdout, stderr=stderr)
    stdout_data, stderr_data = process.communicate()
    if process.returncode != 0:
        raise DemistoException(f'Error returned from tshark command: {process.returncode}\n {stderr_data!r}')


def filter_files(
        root: str, files: list[str],
        types: set[str] | None = None,
        extensions: set[str] | None = None,
        inclusive_or_exclusive: str | None = None,
) -> list[str]:
    """Filtering files by its MIME type and file extension.

    Args:
        root: file's root
        files: files to filter
        types: types to filter by.
        extensions: extensions to filter by.
        inclusive_or_exclusive: should extensions/types set be inclusive or exclusive

    Returns:
        Filtered file list.
    """
    # strip `.` from extension
    if extensions is not None:
        extensions = set([extension.split('.')[-1] for extension in extensions])
    else:
        extensions = set()
    if types is None:
        types = set()
    magic_mime = magic.Magic(mime=True)
    new_files = files.copy()
    # MIME Types
    if types:
        for file in files:
            # types list supplied,
            mime_type = magic_mime.from_file(os.path.join(root, file))
            # Inclusive types, take only the types in the list.
            if inclusive_or_exclusive == INCLUSIVE and mime_type not in types:
                new_files.remove(file)
            # Exclusive types, don't take those files.
            elif inclusive_or_exclusive == EXCLUSIVE and mime_type in types:
                new_files.remove(file)
    # Extensions
    if extensions:
        for file in files:
            # Get file extension without a leading point.
            f_ext = os.path.splitext(file)[1].split('.')[-1]
            # Inclusive extensions, take only the types in the list.
            if inclusive_or_exclusive == INCLUSIVE and f_ext not in extensions:
                new_files.remove(file)
            # Exclude extensions, don't take those files.
            elif inclusive_or_exclusive == EXCLUSIVE and f_ext in extensions:
                new_files.remove(file)
    return new_files


def upload_files(
        file_path: str, dir_path: str,
        types: set[str] | None = None, extensions: set[str] | None = None,
        inclusive_or_exclusive: str | None = None,
        wpa_pwd: str | None = None,
        rsa_path: str | None = None,
        limit: int = 5
) -> CommandResults | str:
    """Extracts files and delivers it to CortexSOAR

    Args:
        file_path: the path to the PCAP file
        dir_path: dir path for the files
        types: types to filter by.
        extensions: extensions to filter by.
        inclusive_or_exclusive: should types/extensions set be inclusive or exclusive
        wpa_pwd: password to the file (if WPA-PWD protected)
        rsa_path: path to a private key file (if TLS encrypted)
        limit: maximum files to extract (default 5)

    Returns:
        Extracted files to download

    """
    assert not (types and extensions), 'Provide only types or extensions, not both.'
    command = ['tshark', '-2', '-r', f'{file_path}', '--export-objects', f'http,{dir_path}',
               '--export-objects', f'smb,{dir_path}', '--export-objects', f'imf,{dir_path}',
               '--export-objects', f'tftp,{dir_path}', '--export-objects', f'dicom,{dir_path}']
    # If WPA-PWD protected
    if wpa_pwd:
        command.extend([
            '-o', 'wlan.enable_decryption:TRUE',
            '-o', f'uat:80211_keys:"wpa-pwd","{wpa_pwd}"'
        ])
    # If need to decrypt the file using a RSA key
    if rsa_path:
        command.extend(['-o', f'uat:rsa_keys:"{rsa_path}",""'])

    run_command(command)

    context = []
    for root, _, files in os.walk(dir_path):
        # Limit the files list to the limit provided by the user
        files = files[: limit]
        if not files:
            return 'No files found.'
        # Filter files
        files = filter_files(root, files,
                             types=types,
                             extensions=extensions,
                             inclusive_or_exclusive=inclusive_or_exclusive
                             )
        for file in files:
            file_path = os.path.join(root, file)
            file_name = os.path.join(file)

            with open(file_path, 'rb') as file_stream:
                data = file_stream.read()
                demisto.results(fileResult(file_name, data))

            context.append({
                'FileMD5': HashCalculator.md5(file_path),
                'FileSHA1': HashCalculator.sha1(file_path),
                'FileSHA256': HashCalculator.sha256(file_path),
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
    return 'No files found in path.'


def main(
        entry_id: str,
        wpa_password: str | None = None,
        rsa_decrypt_key_entry_id: str | None = None,
        types: str | None = None,
        inclusive_or_exclusive: str | None = 'inclusive',
        extensions: str | None = None,
        limit: str = '5',
):
    """Exports a PCAP file and returns them to the context.

    Args:
        entry_id: Entry ID of the PCAP file
        wpa_password: password for WPA-PWD protected files. <password> or <host>:<password>
        rsa_decrypt_key_entry_id: Entry ID of a RSA key.
        types: A CSV list of types.
        extensions: A CSV list of extensions.
        inclusive_or_exclusive: Should types/extensions be inclusive or exclusive
        limit: Maximum of files to export from PCAP file

    Raises:
        SystemExit if error occurred.
    """
    with tempfile.TemporaryDirectory() as dir_path:
        try:
            file_path, file_name = get_file_path_from_id(entry_id)
            cert_path, _ = get_file_path_from_id(rsa_decrypt_key_entry_id) if rsa_decrypt_key_entry_id else (None, None)
            return_results(upload_files(
                file_path, dir_path,
                types=set(argToList(types)),
                extensions=set(argToList(extensions)),
                inclusive_or_exclusive=inclusive_or_exclusive,
                wpa_pwd=wpa_password,
                rsa_path=cert_path,
                limit=int(limit) if limit else 5
            ))
        except Exception as e:
            return_error(f'Failed to execute PcapFileExtractor. Error: {str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main(**demisto.args())
