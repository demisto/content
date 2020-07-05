import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from tempfile import mkdtemp
import shutil
import subprocess
import hashlib


def get_pcap_path(args):
    """

    Args:
        args: argument from demisto

    Returns: path of pcap file

    """
    file_entry_id = args.get('entry_id')  # type: ignore

    if not file_entry_id:
        return_error('You must set entry_id')

    res = demisto.executeCommand('getFilePath', {'id': file_entry_id})
    if isError(res):
        raise Exception(f'Failed to get the file path for entry: {file_entry_id}')

    return res[0]['Contents']['path']


def find_files_packets(file_path):
    """

    Args:
        file_path: the pcap file path

    Returns:
        protocol: the protocol to use while extracting the files
        data_list: the relevant packets for the files.

    """
    protocol = ''
    data_list = []
    process = subprocess.Popen(['tshark', '-r', f'{file_path}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = process.communicate()
    stdout = str(stdout).split('\\n')
    for line in stdout:
        if line.endswith(')') and 'HTTP' in line:
            data_list.append(line)
            protocol = 'http'

        if line.endswith(')') and 'IMF' in line:
            data_list.append(line)
            protocol = 'imf'

        if line.endswith(')') and 'SMB' in line or 'DCERPC' in line:
            data_list.append(line)
            protocol = 'smb'

        if line.endswith(')') and 'DICOM' in line:
            data_list.append(line)
            protocol = 'dicom'

        if line.endswith(')') and 'TFTP' in line:
            data_list.append(line)
            protocol = 'tftp'

    return protocol, data_list


def upload_files(dir_path, file_path):
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
    protocol, packet_data = find_files_packets(file_path)

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    for root, directories, files in os.walk(dir_path):
        if len(files) == 0:
            raise Exception('Could not find files')

        for f in files:
            file_path = os.path.join(root, f)
            file_name = os.path.join(f)

            for data in packet_data:
                packet = data.split()
                try:
                    source_ip = packet[2]
                    dest_ip = packet[4]
                except Exception:
                    pass

            with open(file_path, 'rb') as file:
                demisto.results(fileResult(file_name, file.read()))

                data = file.read()
                md5.update(data)
                sha1.update(data)
                sha256.update(data)

            context.append({
                'FileMD5': md5.hexdigest(),
                'FileSHA1': sha1.hexdigest(),
                'FileSHA256': sha256.hexdigest(),
                'FileName': file_name,
                'FileSize': os.path.getsize(file_path),
                'DetectedInProtocol': protocol,
                'FileExtension': os.path.splitext(file_name)[1],
                'SourceIP': source_ip,
                'DestinationIP': dest_ip
            })

        readable_output = tableToMarkdown('Pcap Extracted Files', [{'name': file_name} for file_name in files])

        results = CommandResults(
            outputs_prefix='PcapExtractedFiles',
            outputs_key_field='FileName',
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
