import uuid
from pathlib import Path, PurePosixPath, PureWindowsPath

from CommonServerPython import *
import demistomock as demisto

import smbclient


def generate_pathlib_object(hostname: str, path: str, os_type: str) -> PurePosixPath | PureWindowsPath:
    if os_type.casefold() == "Unix".casefold():
        return PurePosixPath(hostname, path)

    elif os_type.casefold() == "Windows".casefold():
        return PureWindowsPath(hostname, path)

    else:
        raise ValueError(f"\"{os_type}\" is an invalid OSType value.\nOnly \"Unix\" or \"Windows\" can be used.")


class SMBClient:
    def __init__(self, hostname, port, os_type, user, password, encrypt):
        self.hostname = hostname
        self.os_type = os_type
        self._port = port
        self._user = user
        self._password = password
        self._encrypt = encrypt

    def create_session(self, hostname: str = None, user: str = None, password: str = None, encrypt: bool = False,
                       port: int = None):
        smbclient.register_session(
            server=hostname or self.hostname,
            username=user or self._user,
            password=password or self._password,
            port=port or self._port,
            encrypt=encrypt or self._encrypt,
            auth_protocol='ntlm',
        )


def test_module(client: SMBClient):
    client.create_session()
    return "ok"


def smb_upload(client: SMBClient, args: dict):
    hostname = args.get('hostname')
    os_type = args.get('os_type') or client.os_type
    username = args.get('username')
    password = args.get('password')
    entry_id = args.get('entryID')
    content = args.get('content')  # The input is text.
    path_input = args['file_path']
    path = generate_pathlib_object(hostname, path_input, os_type)

    if not entry_id and not content:
        raise DemistoException(
            "You must provide a content to upload using one of the following arguments: content, entryID.")

    client.create_session(hostname, username, password)

    writing_mode = 'w'

    if entry_id:
        file = demisto.getFilePath(entry_id)
        file_path = Path(file['path'])
        writing_mode = 'wb'

        with open(file_path, mode='rb') as f:
            content = f.read()

    demisto.debug(f"Uploading file: {path}")
    with smbclient.open_file(str(path), mode=writing_mode) as file_obj:
        file_obj.write(content)

    return f'File {path.name} was uploaded successfully'


def smb_download(client: SMBClient, args: dict):
    hostname = args.get('hostname')
    os_type = args.get('os_type') or client.os_type
    username = args.get('username')
    password = args.get('password')
    path_input = args['file_path']
    path = generate_pathlib_object(hostname, path_input, os_type)

    client.create_session(hostname, username, password)

    demisto.debug(f"Downloading file: {path}")
    with smbclient.open_file(str(path), mode="rb") as fd:
        file_contents = fd.read()
        file_name = path.name

    return fileResult(file_name, file_contents)


def smb_remove_file(client: SMBClient, args: dict):
    hostname = args.get('hostname')
    os_type = args.get('os_type') or client.os_type
    username = args.get('username')
    password = args.get('password')
    path_input = args['file_path']
    path = generate_pathlib_object(hostname, path_input, os_type)

    client.create_session(hostname, username, password)

    demisto.debug(f"Removing file: {path}")
    smbclient.remove(str(path))

    return f'File {path.name} has been deleted successfully.'


def list_dir(client: SMBClient, args: dict):
    hostname = args.get('hostname')
    os_type = args.get('os_type') or client.os_type
    username = args.get('username')
    password = args.get('password')
    path_input = args['path']
    path = generate_pathlib_object(hostname, path_input, os_type)

    client.create_session(hostname, username, password)

    demisto.debug(f"Listing directory: {path}")
    entries = list(smbclient.scandir(str(path)))

    files = []
    dirs = []

    for entry in entries:
        if entry.is_file():
            files.append(entry.name)
        if entry.is_dir():
            dirs.append(entry.name)

    context = {
        'SharedFolder': str(path),
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
    os_type = args.get('os_type') or client.os_type
    username = args.get('username')
    password = args.get('password')
    path_input = args['path']
    path = generate_pathlib_object(hostname, path_input, os_type)

    client.create_session(hostname, username, password)

    demisto.debug(f"Creating directory: {path}")
    smbclient.mkdir(str(path))
    return f"Directory: {path} was created successfully"


def smb_rmdir(client: SMBClient, args: dict):
    hostname = args.get('hostname')
    os_type = args.get('os_type') or client.os_type
    username = args.get('username')
    password = args.get('password')
    path_input = args['path']
    path = generate_pathlib_object(hostname, path_input, os_type)

    client.create_session(hostname, username, password)

    demisto.debug(f"Removing directory: {path}")
    smbclient.rmdir(str(path))

    return f"Directory: {path} was removed successfully"


def main():
    params = demisto.params()
    hostname = params['hostname']
    port = int(params.get('port', '445'))
    os_type = params.get('os_type', 'Unix')
    user = params['credentials']['identifier']
    password = params['credentials']['password']
    encrypt = params.get('encrypt', False)
    dc = params.get('dc', None)
    verify = params.get('require_secure_negotiate', True)
    client_guid = params.get('client_guid', None)

    # Temporary workaround to an issue in the smbprotocol package.
    # GitHub issue: https://github.com/jborean93/smbprotocol/issues/109
    config = smbclient.ClientConfig(username=user, password=password, require_secure_negotiate=verify)
    config.domain_controller = dc

    if client_guid:
        try:
            client_guid = uuid.UUID(client_guid)
            config.client_guid = client_guid
        except ValueError:
            demisto.info(
                f'Failed to convert {client_guid} to a valid UUID string. Using a random generated UUID instead')

    client = SMBClient(hostname=hostname,
                       os_type=os_type,
                       user=user,
                       password=password,
                       encrypt=encrypt,
                       port=port)

    demisto.info(f'Command used: {demisto.command()}')

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
        else:
            raise NotImplementedError(f'Command {demisto.command()} does not exist.')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')

    finally:
        smbclient.reset_connection_cache()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
