import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import uuid


""" IMPORTS """


import os
import smbclient
from smbclient import (
    mkdir,
    open_file,
    register_session,
    remove,
    rmdir,
    scandir,
    rename,
    stat as smb_stat,  # SMB version for metadata
)
import fnmatch
import stat as py_stat  # Built-in Python module for S_ISDIR


def get_file_name(path):
    delimiter = "/" if "/" in path else "\\"
    return path.split(delimiter)[-1]


def handle_path(path):
    """
    Stripping the '\\' and '/' characters from a given path.
    Examples:
        \\Shared\\123.txt\\ ---> Shared\\123.txt
        /Shared/123.txt/ ---> Shared/123.txt
        \\Shared\\123.txt/\\ ---> Shared\\123.txt
    """
    return path.strip("\\/")


def create_share_path(hostname, path):
    r"""
    Create a path to the shared folder according to the smbprotocol convention: '\\server\share'.
    For reference see https://github.com/jborean93/smbprotocol/blob/master/examples/high-level/directory-management.py
    """
    return rf"\\{hostname}\{path}"


class SMBClient:
    def __init__(self, hostname, user, password, encrypt, port):
        self.hostname = hostname
        self._user = user
        self._password = password
        self._encrypt = encrypt
        self._port = port

    def create_session(
        self, hostname: str = None, user: str = None, password: str = None, encrypt: bool = False, port: int = None
    ):
        register_session(
            server=hostname or self.hostname,
            username=user or self._user,
            password=password or self._password,
            port=port or self._port,
            encrypt=encrypt or self._encrypt,
            auth_protocol="ntlm",
        )


def test_module(client: SMBClient):
    client.create_session()
    return "ok"


def smb_upload(client: SMBClient, args: dict):
    hostname = args.get("hostname")
    path = handle_path(args.get("file_path"))
    path = create_share_path(hostname or client.hostname, path)
    username = args.get("username")
    password = args.get("password")
    entryID = args.get("entryID")
    content = args.get("content")

    if not entryID and not content:
        raise DemistoException("You must provide a content to upload using one of the following arguments: content, entryID.")

    client.create_session(hostname, username, password)

    # For the content argument - the input is text.
    writing_mode = "w"
    if entryID:
        file = demisto.getFilePath(entryID)
        filePath = file["path"]
        writing_mode = "wb"

        with open(filePath, mode="rb") as f:
            content = f.read()

    with open_file(rf"{path}", mode=writing_mode) as file_obj:
        file_obj.write(content)
    return f"File {get_file_name(path)} was uploaded successfully"


def smb_download(client: SMBClient, args: dict):
    hostname = args.get("hostname")
    path = handle_path(args.get("file_path"))
    path = create_share_path(hostname or client.hostname, path)
    username = args.get("username")
    password = args.get("password")

    client.create_session(hostname, username, password)

    with open_file(rf"{path}", mode="rb") as fd:
        file_contents = fd.read()
        file_name = get_file_name(path)
        return fileResult(file_name, file_contents)


def smb_remove_file(client: SMBClient, args: dict):
    hostname = args.get("hostname")
    path = handle_path(args.get("file_path"))
    path = create_share_path(hostname or client.hostname, path)
    username = args.get("username")
    password = args.get("password")

    client.create_session(hostname, username, password)
    remove(path)
    file_name = get_file_name(path)
    return f"File {file_name} was deleted successfully"


def exist_dir(client: SMBClient, args: dict):
    network_folder = r"\\nade02dsv12\USAFRICOM_CIFS_User_Profile_Data"

    if os.path.exists(network_folder):
        print("Folder exists")
    else:
        print("Folder does not exist")


def list_dir(client: SMBClient, args: dict):
    hostname = args.get("hostname")
    username = args.get("username")
    password = args.get("password")
    path = handle_path(args.get("path"))
    path = create_share_path(hostname or client.hostname, path)

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
        "SharedFolder": path,
        "Files": files,
        "Directories": dirs,
    }
    return CommandResults(
        outputs_prefix="SMB.Path",
        outputs_key_field="SharedFolder",
        outputs=context,
        readable_output=tableToMarkdown(f"List Of Entries for {path}", context),
    )


def smb_mkdir(client: SMBClient, args: dict):
    hostname = args.get("hostname")
    username = args.get("username")
    password = args.get("password")
    path = handle_path(args.get("path"))
    path = create_share_path(hostname or client.hostname, path)

    client.create_session(hostname, username, password)

    mkdir(path)

    return f"Directory: {path} was created successfully"


def smb_rmdir(client: SMBClient, args: dict):
    hostname = args.get("hostname")
    username = args.get("username")
    password = args.get("password")
    path = handle_path(args.get("path"))
    path = create_share_path(hostname or client.hostname, path)

    client.create_session(hostname, username, password)
    rmdir(path)

    return f"Directory: {path} was removed successfully"


def smb_path_rename(client: SMBClient, args: dict):
    """
    Renames a file or directory on an SMB server.

    Args:
        client (SMBClient): An instance of the SMBClient class.
        args (dict): Dictionary containing 'hostname', 'username', 'password', 'src_path', 'dest_path', and optional 'overwrite'.

    Returns:
        CommandResults: Result object with context and readable output.
    """
    hostname = args.get("hostname")
    username = args.get("username")
    password = args.get("password")
    overwrite = args.get("overwrite", "no").lower()

    source_path = handle_path(args.get("src_path"))
    destination_path = handle_path(args.get("dest_path"))

    source_path = create_share_path(hostname or client.hostname, source_path)
    destination_path = create_share_path(hostname or client.hostname, destination_path)

    client.create_session(hostname, username, password)

    # Check if destination exists
    dest_exists = False
    try:
        smb_stat(destination_path)
        dest_exists = True
    except Exception:
        pass

    if dest_exists and overwrite != "yes":
        return CommandResults(
            readable_output=f"Skipped rename: '{destination_path}' already exists and overwrite=no.",
            outputs={
                "SMBRename": {
                    "OriginalPath": source_path,
                    "NewPath": destination_path,
                    "Renamed": False,
                    "Reason": "Destination already exists and overwrite is disabled"
                }
            },
            outputs_prefix="SMBRename",
            outputs_key_field="OriginalPath"
        )

    # Perform rename
    rename(source_path, destination_path)

    return CommandResults(
        readable_output=f"Successfully renamed '{source_path}' to '{destination_path}'",
        outputs={
            "SMBRename": {
                "OriginalPath": source_path,
                "NewPath": destination_path,
                "Renamed": True
            }
        },
        outputs_prefix="SMBRename",
        outputs_key_field="OriginalPath"
    )


def smb_rename_dir(client: SMBClient, args: dict):
    """
    Renames a directory on an SMB server.

    Args:
        client (SMBClient): An instance of the SMBClient class.
        args (dict): Dictionary containing 'hostname', 'username', 'password', 'src_path', and 'dest_path'.

    Returns:
        str: Success message indicating the directory was renamed.
    """

    hostname = args.get("hostname")
    username = args.get("username")
    password = args.get("password")
    source_path = handle_path(args.get("src_path"))  # Ensuring clean paths
    destination_path = handle_path(args.get("dest_path"))

    # Construct the full SMB paths
    source_path = create_share_path(hostname or client.hostname, source_path)
    destination_path = create_share_path(hostname or client.hostname, destination_path)

    # Establish session with the SMB server
    client.create_session(hostname, username, password)

    # Rename the directory
    rename(source_path, destination_path)

    return f"Directory '{source_path}' was successfully renamed to '{destination_path}'"


def smb_copy(client: SMBClient, args: dict):
    import fnmatch

    source_host = args.get("source_host")
    destination_host = args.get("destination_host", source_host)
    username = args.get("username")
    password = args.get("password")
    src_path = handle_path(args.get("source_path"))
    dst_path = handle_path(args.get("destination_path"))
    overwrite = args.get("overwrite", "no")

    src_path = create_share_path(source_host or client.hostname, src_path)
    dst_path = create_share_path(destination_host or client.hostname, dst_path)

    client.create_session(source_host, username, password)
    if destination_host != source_host:
        client.create_session(destination_host, username, password)

    def copy_file(src, dst):
        dst_stat = None
        try:
            dst_stat = smb_stat(dst)
        except Exception:
            pass

        if dst_stat and py_stat.S_ISDIR(dst_stat.st_mode):
            filename = src.split("\\")[-1]
            dst = f"{dst}\\{filename}"

        if overwrite.lower() != "yes":
            try:
                smb_stat(dst)
                demisto.info(f"Skipped (exists): {dst}")
                return None
            except Exception:
                pass

        with open_file(src, mode="rb") as src_file:
            content = src_file.read()
        with open_file(dst, mode="wb") as dst_file:
            dst_file.write(content)

        demisto.info(f"Copied file: {src} → {dst}")
        return dst

    def copy_directory(src_dir, dst_dir):
        copied_files = []
        skipped_files = []
        copied_dirs = []
        skipped_dirs = []

        try:
            dst_stat = smb_stat(dst_dir)
            if py_stat.S_ISDIR(dst_stat.st_mode):
                demisto.info(f"Destination directory already exists: {dst_dir}")
                if overwrite.lower() == "yes":
                    copied_dirs.append(dst_dir)
            else:
                raise Exception("Destination exists but is not a directory")
        except Exception:
            mkdir(dst_dir)
            demisto.info(f"Created destination directory: {dst_dir}")
            copied_dirs.append(dst_dir)

        for entry in scandir(src_dir):
            src_entry = f"{src_dir}\\{entry.name}"
            dst_entry = f"{dst_dir}\\{entry.name}"

            if entry.is_file():
                if overwrite.lower() != "yes":
                    try:
                        smb_stat(dst_entry)
                        demisto.info(f"Skipped file (exists): {dst_entry}")
                        skipped_files.append(dst_entry)
                        continue
                    except Exception:
                        pass
                result = copy_file(src_entry, dst_entry)
                if result:
                    copied_files.append(result)

            elif entry.is_dir():
                sub_files_copied, sub_files_skipped, sub_dirs_copied, sub_dirs_skipped = copy_directory(src_entry, dst_entry)
                copied_files.extend(sub_files_copied)
                skipped_files.extend(sub_files_skipped)
                copied_dirs.extend(sub_dirs_copied)
                skipped_dirs.extend(sub_dirs_skipped)

        return copied_files, skipped_files, copied_dirs, skipped_dirs

    try:
        if "*" in src_path or "?" in src_path:
            src_dir = "\\".join(src_path.split("\\")[:-1])
            pattern = src_path.split("\\")[-1]

            copied_files = []
            skipped_files = []

            for entry in scandir(src_dir):
                if entry.is_file() and fnmatch.fnmatch(entry.name.lower(), pattern.lower()):
                    src_file_path = f"{src_dir}\\{entry.name}"

                    dst_stat = None
                    try:
                        dst_stat = smb_stat(dst_path)
                    except Exception:
                        pass

                    dst_is_dir = dst_stat and py_stat.S_ISDIR(dst_stat.st_mode)
                    dst_file_path = f"{dst_path}\\{entry.name}" if dst_is_dir else dst_path

                    try:
                        if overwrite.lower() != "yes":
                            smb_stat(dst_file_path)
                            demisto.info(f"Skipped (exists): {dst_file_path}")
                            skipped_files.append(dst_file_path)
                            continue
                    except Exception:
                        pass

                    result = copy_file(src_file_path, dst_path)
                    if result:
                        copied_files.append(result)

            summary = f"{len(copied_files)} file(s) copied from {src_dir} to {dst_path} matching '{pattern}'"
            if skipped_files:
                summary += f". {len(skipped_files)} file(s) were skipped due to overwrite=no."

            context = {
                "SMBCopy": {
                    "SourcePath": src_dir,
                    "DestinationPath": dst_path,
                    "FilesCopied": copied_files,
                    "FoldersCopied": []
                }
            }

            return CommandResults(
                readable_output=summary,
                outputs=context,
                outputs_prefix="SMBCopy",
                outputs_key_field="SourcePath"
            )

        src_stat = smb_stat(src_path)
        if py_stat.S_ISDIR(src_stat.st_mode):
            copied_files, skipped_files, copied_dirs, skipped_dirs = copy_directory(src_path, dst_path)
            total_copied = len(copied_files) + len(copied_dirs)
            total_skipped = len(skipped_files) + len(skipped_dirs)

            summary = f"{total_copied} item(s) copied from {src_path} to {dst_path}"
            if total_skipped:
                summary += f". {total_skipped} item(s) were skipped due to overwrite=no."

            context = {
                "SMBCopy": {
                    "SourcePath": src_path,
                    "DestinationPath": dst_path,
                    "FilesCopied": copied_files,
                    "FoldersCopied": copied_dirs
                }
            }

            return CommandResults(
                readable_output=summary,
                outputs=context,
                outputs_prefix="SMBCopy",
                outputs_key_field="SourcePath"
            )

        else:
            result = copy_file(src_path, dst_path)
            summary = f"File copied from {src_path} to {dst_path} successfully" if result else f"File skipped: {src_path} already exists and overwrite=no"

            context = {
                "SMBCopy": {
                    "SourcePath": src_path,
                    "DestinationPath": dst_path,
                    "FilesCopied": [result] if result else [],
                    "FoldersCopied": []
                }
            }

            return CommandResults(
                readable_output=summary,
                outputs=context,
                outputs_prefix="SMBCopy",
                outputs_key_field="SourcePath"
            )

    except Exception as e:
        raise DemistoException(f"Failed to copy from {src_path} to {dst_path}. Error: {e}")


def main():
    params = demisto.params()
    hostname = params["hostname"]
    port = int(params.get("port", "445"))
    user = params["credentials"]["identifier"]
    password = params["credentials"]["password"]
    encrypt = params.get("encrypt", False)
    dc = params.get("dc", None)
    verify = params.get("require_secure_negotiate", True)
    client_guid = params.get("client_guid", None)

    # Temporary workaround to an issue in the smbprotocol package.
    # Git issue: https://github.com/jborean93/smbprotocol/issues/109
    config = smbclient.ClientConfig(username=user, password=password, require_secure_negotiate=verify)
    config.domain_controller = dc

    if client_guid:
        try:
            client_guid = uuid.UUID(client_guid)
            config.client_guid = client_guid
        except ValueError:
            demisto.info(f"Failed to convert {client_guid} to a valid UUID string. Using a random generated UUID instead")

    client = SMBClient(hostname=hostname, user=user, password=password, encrypt=encrypt, port=port)

    demisto.info(f"Command being called is {demisto.command()}")

    try:
        if demisto.command() == "test-module":
            return_results(test_module(client))
        elif demisto.command() == "smb-download":
            return_results(smb_download(client, demisto.args()))
        elif demisto.command() == "smb-upload":
            return_results(smb_upload(client, demisto.args()))
        elif demisto.command() == "smb-directory-list":
            return_results(list_dir(client, demisto.args()))
        elif demisto.command() == "smb-file-remove":
            return_results(smb_remove_file(client, demisto.args()))
        elif demisto.command() == "smb-directory-create":
            return_results(smb_mkdir(client, demisto.args()))
        elif demisto.command() == "smb-directory-remove":
            return_results(smb_rmdir(client, demisto.args()))
        elif demisto.command() == "smb-copy":
            return_results(smb_copy(client, demisto.args()))
        elif demisto.command() == "smb-path-rename":
            return_results(smb_path_rename(client, demisto.args()))

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {e!s}")
    finally:
        smbclient.reset_connection_cache()


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
