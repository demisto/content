import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from os.path import isfile
from tempfile import mkdtemp
import shutil
import glob
import subprocess
import hashlib
import shlex


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


def find_files_protocol(file_path):
    """

    Args:
        file_path: the pcap file path

    Returns:
        protocol: the protocol to use while extracting the files
        data_list: the relevant packets for the files.

    """
    protocol = ''
    data_list = []
    command_ = f'tshark -r {file_path}'
    process = subprocess.Popen(shlex.split(command_), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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


def extract_files(file_path, dir_path):
    """

    Args:
        file_path: the pcap file path.
        dir_path: directory for the files will be extract to

    Returns: excluded_files: the excludedfiles which are in dir_path

    """
    protocol, _ = find_files_protocol(file_path)
    if not protocol:
        return_error('Could not find a valid protocol for extracting the files')

    if protocol == 'http':
        command_ = f'tshark -r {file_path} --export-objects http,{dir_path}'

    elif protocol == 'smb':
        command_ = f'tshark -r {file_path} --export-objects smb,{dir_path}'

    elif protocol == 'imf':
        command_ = f'tshark -r {file_path} --export-objects imf,{dir_path}'

    elif protocol == 'tftp':
        command_ = f'tshark -r {file_path} --export-objects tftp,{dir_path}'

    elif protocol == 'dicom':
        command_ = f'tshark -r {file_path} --export-objects dicom,{dir_path}'

    process = subprocess.Popen(shlex.split(command_), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.communicate()
    excluded_files = [f for f in glob.glob(dir_path + '/*')]

    return excluded_files


def upload_files(excluded_files, dir_path, file_path):
    """

    Args:
        excluded_files: excluded files
        dir_path: dir path for the files
        file_path: the path to the pcap file

    Returns:
        Extracted files to download

    """
    filenames = []
    # recursive call over the file system top down
    for root, directories, files in os.walk(dir_path):
        for f in files:
            # skipping previously existing files
            # adding it to the extracted pcap files list
            if f not in excluded_files and isfile(os.path.join(root, f)):
                filenames.append(os.path.join(root, f))

    if len(filenames) == 0:
        return_error('Could not find files')

    else:
        context = []
        protocol, packet_data = find_files_protocol(file_path)

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        files_dic = {file_path: os.path.basename(file_path) for file_path in filenames}

        for file_path, file_name in files_dic.items():
            for data in packet_data:
                packet_number = data.split()[0]
                for packet_number in packet_data:
                    data = packet_number.split()
                    try:
                        source_ip = data[2]
                        dest_ip = data[4]
                    except:
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

        readable_output = tableToMarkdown('Pcap Extracted Files', [{'name': file_name} for file_name in
                                                                   files_dic.values()])
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
        excluded_files = extract_files(file_path=file_path, dir_path=dir_path)
        return_results(upload_files(excluded_files, dir_path, file_path))

    except Exception as e:
        return_error(f'Failed to execute PcapFileExtracor. Error: {str(e)}')
    finally:
        if dir_path:
            shutil.rmtree(dir_path)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
