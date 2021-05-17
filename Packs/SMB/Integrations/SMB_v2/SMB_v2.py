from CommonServerPython import *
import demistomock as demisto

''' IMPORTS '''

import smbclient
from smbclient import (
    open_file,
    register_session,
    scandir,
    remove,
    mkdir,
    rmdir
)


def get_file_name(path):
    delimiter = '/' if '/' in path else '\\'
    return path.split(delimiter)[-1]


def handle_path(path):
    """
    Stripping the '\\' and '/' characters from a given path.
    Examples:
        \\Shared\\123.txt\\ ---> Shared\\123.txt
        /Shared/123.txt/ ---> Shared/123.txt
        \\Shared\\123.txt/\\ ---> Shared\\123.txt
    """
    return path.strip('\\/')


class SMBClient:
    def __init__(self, hostname, user, password, encrypt, port):
        self.hostname = hostname
        self._user = user
        self._password = password
        self._encrypt = encrypt
        self._port = port

    def create_session(self, hostname: str = None, user: str = None, password: str = None, encrypt: bool = False,
                       port: int = None):
        register_session(
            server=hostname or self.hostname,
            username=user or self._user,
            password=password or self._password,
            port=port or self._port,
            encrypt=encrypt or self._encrypt)


def test_module(client: SMBClient):
    client.create_session()
    return "ok"


def smb_upload(client: SMBClient, args: dict):
    hostname = args.get('hostname')
    path = handle_path(args.get('file_path'))
    path = os.path.join(hostname or client.hostname, path)
    username = args.get('username')
    password = args.get('password')
    entryID = args.get('entryID')
    content = args.get('content')

    if not entryID and not content:
        raise DemistoException(
            "You must provide a content to upload using one of the following arguments: content, entryID.")

    client.create_session(hostname, username, password)

    # For the content argument - the input is text.
    writing_mode = 'w'
    if entryID:
        file = demisto.getFilePath(entryID)
        filePath = file['path']
        writing_mode = 'wb'

        with open(filePath, mode='rb') as f:
            content = f.read()

    with open_file(fr'{path}', mode=writing_mode) as file_obj:
        file_obj.write(content)
    return f'File {get_file_name(path)} was uploaded successfully'


def smb_download(client: SMBClient, args: dict):
    hostname = args.get('hostname')
    path = handle_path(args.get('file_path'))
    path = os.path.join(hostname or client.hostname, path)
    username = args.get('username')
    password = args.get('password')

    client.create_session(hostname, username, password)

    with open_file(fr'{path}', mode="rb") as fd:
        file_contents = fd.read()
        file_name = get_file_name(path)
        return fileResult(file_name, file_contents)


def smb_remove_file(client: SMBClient, args: dict):
    hostname = args.get('hostname')
    path = handle_path(args.get('file_path'))
    path = os.path.join(hostname or client.hostname, path)
    username = args.get('username')
    password = args.get('password')

    client.create_session(hostname, username, password)
    remove(path)
    file_name = get_file_name(path)
    return f'File {file_name} was deleted successfully'


def list_dir(client: SMBClient, args: dict):
    hostname = args.get('hostname')
    username = args.get('username')
    password = args.get('password')
    path = handle_path(args.get('path'))
    path = os.path.join(hostname or client.hostname, path)

    client.create_session(hostname, username, password)
    entries = list(scandir(path))

    files = []
    dirs = []

    for entry in entries:
        if entry.is_file():
            files.append(entry.name)
        if entry.is_dir():
            dirs.append(entry.name)

    context = {
        'SharedFolder': path,
        'Files': files,
        'Directories': dirs,
    }
    return CommandResults(
        outputs_prefix='SMB.Path',
        outputs_key_field='SharedFolder',
        outputs=context,
        readable_output=tableToMarkdown(f'List Of Entries for {path}', context),
    )


def smb_mkdir(client: SMBClient, args: dict):
    hostname = args.get('hostname')
    username = args.get('username')
    password = args.get('password')
    path = handle_path(args.get('path'))
    path = os.path.join(hostname or client.hostname, path)

    client.create_session(hostname, username, password)

    mkdir(path)

    return f"Directory: {path} was created successfully"


def smb_rmdir(client: SMBClient, args: dict):
    hostname = args.get('hostname')
    username = args.get('username')
    password = args.get('password')
    path = handle_path(args.get('path'))
    path = os.path.join(hostname or client.hostname, path)

    client.create_session(hostname, username, password)
    rmdir(path)

    return f"Directory: {path} was removed successfully"


def main():
    params = demisto.params()
    hostname = params['hostname']
    port = int(params.get('port', '445'))
    user = params['credentials']['identifier']
    password = params['credentials']['password']
    encrypt = params.get('encrypt', False)
    dc = params.get('dc', None)
    verify = params.get('require_secure_negotiate', True)
    client_guid = params.get('client_guid', None)
    smbclient.ClientConfig(username=user, password=password, require_secure_negotiate=verify, domain_controller=dc,
                           client_guid=client_guid)

    client = SMBClient(hostname=hostname,
                       user=user,
                       password=password,
                       encrypt=encrypt,
                       port=port)

    demisto.info(f'Command being called is {demisto.command()}')

    try:
        if demisto.command() == 'test-module':
            return_results(test_module(client))
        elif demisto.command() == 'smb-download':
            return_results(smb_download(client, demisto.args()))
        elif demisto.command() == 'smb-upload':
            return_results(smb_upload(client, demisto.args()))
        elif demisto.command() == 'smb-directory-list':
            return_results(list_dir(client, demisto.args()))
        elif demisto.command() == 'smb-file-remove':
            return_results(smb_remove_file(client, demisto.args()))
        elif demisto.command() == 'smb-directory-create':
            return_results(smb_mkdir(client, demisto.args()))
        elif demisto.command() == 'smb-directory-remove':
            return_results(smb_rmdir(client, demisto.args()))
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')
    finally:
        smbclient.reset_connection_cache()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
