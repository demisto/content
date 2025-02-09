import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import re
import time
import urllib3
import base64
import hashlib

# Disable insecure warnings
urllib3.disable_warnings()


''' CLIENT CLASS '''


class Client(BaseClient):
    def upload_file(self, incident_id: str,
                    file_content,
                    file_name: str,
                    as_incident_attachment: bool = True):
        """Upload file
        Arguments:
            client: (Client) The client class.
            incident_id {str} -- incident id to upload the file to
            file_content -- content of the file to upload
            file_name {str} -- name of the file in the dest incident
            as_incident_attachment {bool} -- upload the file as an attachment or an entry
        Returns:
            json -- return of the API
        """

        service_name = 'incident' if as_incident_attachment else 'entry'
        response = self._http_request(
            method='POST',
            url_suffix=f'/{service_name}/upload/{incident_id}',
            files={
                "file": (file_name, file_content, 'application/octet-stream')
            }
        )
        return response

    def delete_context(self, incident_id: str, key_to_delete: str):
        """Send the command "DeleteContext" to a specific incident
        Arguments:
            client: (Client) The client class.
            incident_id {str} -- incident id to upload the file to
            key_to_delete {str} -- context data incident key to delete
        Returns:
            json -- return of the API
        """
        body_content = {
            "id": "",
            "version": 0,
            "investigationId": incident_id,
            "data": f"!DeleteContext key={key_to_delete}",
            "args": None,
            "markdown": False
        }
        response = self._http_request(
            method='POST',
            url_suffix='/entry',
            json_data=body_content
        )
        return response

    def delete_file(self, incident_id, entry_id: str, delete_artifact=True):
        """Delete file by entry ID
        Arguments:
            client: (Client) The client class.
            entry_id {str} -- entry ID of the file to delete
            delete_artifact {bool} -- delete the artifact
        Returns:
            json -- return of the API
        """
        body_content = {
            "id": entry_id,
            "deleteArtifact": delete_artifact,
            "version": 0,
            "investigationId": incident_id
        }
        response = self._http_request(
            method='POST',
            url_suffix='/entry/delete/v2',
            json_data=body_content
        )
        return response

    def create_attachment_data_json(self, file_path: str, field_name: str):
        """Structure to delete attachments
        Arguments:
            client: (Client) The client class.
            file_path {str} -- Path of the file to delete
            field_name {str} -- Name of the field containing the attachment
        Returns:
            json -- structure for the API
        """
        # full structure in comment in case the API change the requirement
        # attachment_name = attachment['name']
        attachment_path = file_path  # attachment['path']
        # attachment_type = attachment['type']
        # attachment_media_file = attachment['showMediaFile']
        # attachment_description = attachment['description']
        file_data = {
            "fieldName": field_name,
            "files": {
                attachment_path: {
                    # "description": "",
                    # "name": attachment_name,
                    "path": attachment_path,
                    # "showMediaFile": attachment_media_file,
                    # "type": attachment_type
                }
            },
            "originalAttachments": [
                {
                    # "description": attachment_description,
                    # "name": attachment_name,
                    "path": attachment_path,
                    # "showMediaFile": attachment_media_file,
                    # "type": attachment_type
                }
            ]}
        return file_data

    def delete_attachment(self, incident_id: str, file_path: str, field_name: str = "attachment"):
        """Delete attachments by path
        Arguments:
            client: (Client) The client class.
            incident_id {str} -- incident id to upload the file to
            file_path {str} -- Path of the file to delete
            field_name {str} -- Name of the field containing the attachment
        Returns:
            json -- return of the API
        """
        response = self._http_request(
            method='POST',
            url_suffix=f'/incident/remove/{incident_id}',
            json_data=self.create_attachment_data_json(file_path, field_name)
        )
        return response

    def get_entry_file(self, entry_id: str):
        """Get the content of the file
        Arguments:
            client: (Client) The client class.
            entry_id {str} -- entry ID of the file
        Returns:
            json -- return of the API
        """
        response = self._http_request(
            method='GET',
            url_suffix=f'/entry/download/{entry_id}',
        )
        return response

    def get_markdown_file(self, entry_id: str):
        """Get the content of the file
        Arguments:
            client: (Client) The client class.
            entry_id {str} -- entry ID of the file
        Returns:
            json -- return of the API
        """
        response = requests.get(f'{self._base_url}/markdown/image/{entry_id}', headers=self._headers, verify=self._verify)
        return response

    def get_current_user(self):
        """Get current user
        Arguments:
            client: (Client) The client class.
        Returns:
            json -- return of the API
        """
        self._http_request(
            method='GET',
            url_suffix='/user'
        )


def test_module(client: Client) -> str:
    """Test module command
    Arguments:
        client: (Client) The client class.
    Returns:
        str -- ok or the error
    """
    try:
        client.get_current_user()
        return 'ok'
    except DemistoException as error:
        if 'Forbidden' in str(error):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise error


def get_incident_id(entry_id: str) -> str:
    """Parse the entryID to get the incident id
    Arguments:
        entryID {str} -- entry ID of the file
    Returns:
        str -- incident id
    """
    res = re.findall("(.*?)@(\d+)", entry_id)
    if len(res) <= 0:
        return_error("EntryID unknow or malformatted !")
    return res[0][1]


def rename_file_command(client: Client, args: dict) -> CommandResults:
    """Check if a file exist on the disk
    Arguments:
        entryID {str} -- entry ID of the file
        newFileName {str} -- new name of the file
    Returns:
        CommandResults -- Readable output
    Note:
        This command should not be use in loop, I/O consumming
    """
    entry_id = args.get('entryID', '')
    file_name = args.get('newFileName', '')

    res_path, res_name = get_entry_file_path_name(entry_id)
    # read file
    file_binary = open(res_path, 'rb')
    # create new file new name
    incident_id = get_incident_id(entry_id)
    response = client.upload_file(incident_id, file_binary, file_name, False)
    file_binary.close()
    # create data for the key file
    nfu = struct_file_upload(response)
    # delete old file
    new_files = delete_file(client, entry_id)
    new_files.append(nfu)
    return CommandResults(readable_output=f'File {res_name} was renamed to {file_name} under the new entry id {nfu["EntryID"]}',
                          outputs=new_files,
                          outputs_prefix="File")


def check_file_command(client: Client, args: dict) -> CommandResults:
    """Check if a file exist on the disk
    Arguments:
        entryID {str} -- entry ID of the file
    Returns:
        CommandResults -- Readable output
    """
    entry_id = args.get('entryID')
    output_content = demisto.context().get('IsFileExists', {})
    if len(output_content) > 0:
        client.delete_context(demisto.incident()["id"], "IsFileExists")
        time.sleep(1)  # to let the API execute the request
    try:
        path_res = demisto.getFilePath(entry_id)
        # file_path = path_res.get("path")
        file_name = path_res.get('name')
        output_tmp = {entry_id: True}
        output_content = {**output_content, **output_tmp}
        return CommandResults(readable_output=f"File {entry_id} exist under the name {file_name} !",
                              outputs_prefix="IsFileExists",
                              outputs=output_content)
    except Exception as err:
        output_tmp = {entry_id: False}
        output_content = {**output_content, **output_tmp}
        return CommandResults(readable_output=f"File {entry_id} does not exist ! {err}",
                              outputs_prefix="IsFileExists",
                              outputs=output_content)


def delete_attachment_command(client: Client, args: dict) -> CommandResults:
    """Delete an attachment
    Arguments:
        incidentID {str} -- incident number where the file will be deleted
        filePath {str} -- path of the file
        fieldName {str} -- name of the field (type attachment) you want to remove the attachment.
                           By default it's the incident attachment (incident.attachment) field
    Returns:
        CommandResults -- Readable output
    Note:
        This command delete file on the disk
    """
    inc = demisto.incident()
    incident_id = args.get('incidentID', inc.get("investigationId") if not inc.get("id") else inc.get("id"))
    file_path = args.get('filePath', "")
    field_name = args.get('fieldName', "attachment")

    if not incident_id:
        return_error("Please provide an incident id")
    if not file_path:
        return_error("Argument file_path is empty.")
    try:
        client.delete_attachment(incident_id, file_path, field_name)
    except DemistoException as error:
        return_error(f"File already deleted or not found !\n{str(error)}")
    return CommandResults(readable_output=f"Attachment {file_path} deleted !")


def delete_file(client: Client, entry_id: str):
    files = demisto.context().get('File', [])
    files = [files] if not isinstance(files, list) else files
    incident_id = get_incident_id(entry_id)
    # delete old file
    try:
        client.delete_file(incident_id, entry_id)
    except DemistoException as error:
        return_error(f"File already deleted or not found !\n{str(error)}")
    # output
    client.delete_context(incident_id, "File")
    time.sleep(1)  # to let the API execute the request
    new_files = [file for file in files if file.get("EntryID") != entry_id]
    return new_files


def delete_file_command(client: Client, args: dict) -> CommandResults:
    """Delete a file
    Arguments:
        entryID {str} -- entry ID of the file
    Returns:
        CommandResults -- Readable output
    Note:
        This command delete file on the disk
    """
    entry_id = args.get('entryID', "")

    if not entry_id:
        return_error("Argument entry_id is empty.")
    new_files = delete_file(client, entry_id)
    return CommandResults(readable_output=f"File {entry_id} deleted !", outputs=new_files, outputs_prefix="File")


def get_entry_file_path_name(file_input: str) -> tuple[str, str]:
    """Get the path and the name of a file
    Arguments:
        file_input {str} -- can be an entryID or a path under the key incident.attachments.path
    Returns:
        Tuple -- first element is the path and second the name of the file
    Note:
        getFilePath does not react the same in preprocessing and playground so we use try catch
    """
    try:
        path_res = demisto.getFilePath(file_input)
        file_path = path_res.get("path")
        file_name = path_res.get('name')
        return file_path, file_name
    except Exception:
        res = re.findall("_(.*)_(.*)", file_input)
        if len(res) <= 0:
            return_error("File not found... entryID or path invalid !")
        path_res = demisto.getFilePath(res[0][0])
        file_path = path_res.get("path")
        file_name = res[0][1]
        return file_path, file_name


def upload_file_command(client: Client, args: dict) -> CommandResults:
    """Upload a new file
    Arguments:
        incidentID {str} -- incident id to upload the file to
        fileContent -- content of the file to upload
        fileName {str} -- name of the file in the dest incident
        entryID {str} -- entry ID of the file
        filePath {str} -- path of the file
        target {bool} -- upload the file as an attachment or an war room entry
    Returns:
        CommandResults -- Readable output
    Note:
        You can give either the entryID, the filePath or the fileContent.
        fileName have to contain the extension if you want one
    """
    inc = demisto.incident()
    incident_id = args.get('incidentID', inc.get("investigationId") if not inc.get("id") else inc.get("id"))
    file_content = args.get('fileContent', '')
    file_content_b64 = args.get('fileContentB64', '')
    entry_id = args.get('entryID', '')
    file_path = args.get('filePath', '')
    file_name = args.get('fileName', '')
    target = args.get('target', 'war room entry')

    if not incident_id:
        return_error("Please provide an incident id")
    # check if some content is given and not too many
    if len(list(filter(None, [file_content, file_content_b64, entry_id, file_path]))) != 1:
        return_error("You have to give either the content of the file using the arg 'fileContent'"
                     "or 'fileContentB64' or an entryID or a file path !")
    # if file_name is not set when using content of the file
    if (file_content or file_content_b64) and not file_name:
        return_error("You have to choose a name for your file !")

    response = {}
    if file_content:
        response = client.upload_file(incident_id,
                                      file_content,
                                      file_name,
                                      target == 'incident attachment')
    elif file_content_b64:
        file_content_tmp = base64.b64decode(file_content_b64)
        response = client.upload_file(incident_id,
                                      file_content_tmp,
                                      file_name,
                                      target == 'incident attachment')
    else:
        arg_path: str = list(filter(None, [entry_id, file_path]))[0]
        res_path, res_name = get_entry_file_path_name(arg_path)
        # file name override by user
        file_name = file_name if file_name else res_name
        if not file_name:
            return_error("Impossible to detect a filename in the path, "
                         "use the argument 'fileName' to set one !")
        file_binary = open(res_path, 'rb')
        response = client.upload_file(incident_id,
                                      file_binary,
                                      file_name,
                                      target == 'incident attachment')
        file_binary.close()
    # create output
    readable = f'File {file_name} uploaded successfully to incident {incident_id}.'
    # in case the file uploaded as war room entry
    if target == 'war room entry':
        readable += f' Entry ID is {response["entries"][0]["id"]}'

    return CommandResults(readable_output=readable)


def struct_file_upload(response):
    nfu = {
        "Size": response["entries"][0]["fileMetadata"]["size"],
        "SHA1": response["entries"][0]["fileMetadata"]["sha1"],
        "SHA256": response["entries"][0]["fileMetadata"]["sha256"],
        "SHA512": response["entries"][0]["fileMetadata"]["sha512"],
        "Name": response["entries"][0]["file"],
        "SSDeep": response["entries"][0]["fileMetadata"]["ssdeep"],
        "EntryID": response["entries"][0]["id"],
        "Info": response["entries"][0]["fileMetadata"]["type"],
        "Type": response["entries"][0]["fileMetadata"]["info"],
        "MD5": response["entries"][0]["fileMetadata"]["md5"],
        "Extension": response["entries"][0]["file"]
    }
    res = nfu.get("Name", "").split(".")
    if len(res) > 1:
        nfu["Extension"] = res[-1]
    return nfu


def download_file_command(client: Client, args: dict) -> CommandResults:
    """Download a file and upload it
    Arguments:
        incidentID {str} -- incident id to upload the file to
        fileName {str} -- name of the file in the dest incident
        fileURI {str} -- URI of the file
        target {bool} -- upload the file as an attachment or an war room entry
    Returns:
        CommandResults -- Readable output
    """
    inc = demisto.incident()
    incident_id = args.get('incidentID', inc.get("investigationId") if not inc.get("id") else inc.get("id"))
    file_name = args.get("fileName", "")
    file_uri = re.sub(".*\/markdown\/image\/", "", args.get("fileURI", ""))
    target = args.get('target', 'war room entry')

    if not incident_id:
        return_error("Please provide an incident id")
    if not file_uri:
        return_error("Please provide file URI")
    # download file
    response = client.get_markdown_file(file_uri)
    if response.status_code != 200:
        return_error(f"HTTP error {response.status_code}")
    # extract file_name from URL or reponse header
    if not file_name:
        headers = response.headers
        if "Content-Disposition" in headers.keys():
            file_name = re.findall("filename=(.+)", headers["Content-Disposition"])[0]
        else:
            file_name = file_uri.split("/")[-1]
    if not file_name:
        return_error("Please provide file name")
    response = client.upload_file(incident_id, response.content, file_name, target == 'incident attachment')

    # create output
    readable = f'File {file_name} uploaded successfully to incident {incident_id}.'
    # in case the file uploaded as war room entry
    if target == 'war room entry':
        readable += f' Entry ID is {response["entries"][0]["id"]}'
    return CommandResults(readable_output=readable,
                          outputs=struct_file_upload(response),
                          outputs_prefix="File")


def get_file_hash_command(client: Client, args: dict) -> CommandResults:
    """Get the file hash
    Arguments:
        fileURI {str} -- URI of the file
    Returns:
        CommandResults -- Readable output
    """
    file_uri = re.sub(".*\/markdown\/image\/", "", args.get("fileURI", ""))
    if not file_uri:
        return_error("Please provide file URI")
    # download file
    response = client.get_markdown_file(file_uri)
    if response.status_code != 200:
        return_error(f"HTTP error {response.status_code}")
    file_name = ""
    if "Content-Disposition" in response.headers.keys():
        file_name = re.findall("filename=(.+)", response.headers["Content-Disposition"])[0]

    # structure to return
    nfu = {
        "Size": response.headers['Content-length'],
        "SHA1": hashlib.sha1(response.content, usedforsecurity=False).hexdigest(),
        "SHA256": hashlib.sha256(response.content, usedforsecurity=False).hexdigest(),
        "SHA512": hashlib.sha512(response.content, usedforsecurity=False).hexdigest(),
        "Name": file_name,
        "MD5": hashlib.md5(response.content, usedforsecurity=False).hexdigest()
    }
    res = nfu.get("Name", "").split(".")
    if len(res) > 1:
        nfu["Extension"] = res[-1]

    return CommandResults(readable_output="Hash save under the key 'File_Hash'.",
                          outputs=nfu,
                          outputs_prefix="File_Hash")


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = demisto.get(demisto.params(), 'creds_apikey.password')
    api_key_id = demisto.params().get("creds_apikey_id", {}).get("password")
    server_url = demisto.demistoUrls()["server"]
    base_url = params.get('url', server_url)
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    try:
        headers = {
            'Authorization': api_key,
            'x-xdr-auth-id': api_key_id
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'file-management-upload-file-to-incident':
            return_results(upload_file_command(client, args))
        elif command == 'file-management-delete-file':
            return_results(delete_file_command(client, args))
        elif command == 'file-management-delete-attachment':
            return_results(delete_attachment_command(client, args))
        elif command == 'file-management-delete-custom-attachment':
            if args.get('fieldName', "") != "attachment":
                return_results(delete_attachment_command(client, args))
            else:
                return_error("Use command file-management-delete-attachment instead")
        elif command == 'file-management-check-file':
            return_results(check_file_command(client, args))
        elif command == 'file-management-rename-file':
            return_results(rename_file_command(client, args))
        elif command == 'file-management-download-file':
            return_results(download_file_command(client, args))
        elif command == 'file-management-get-file-hash':
            return_results(get_file_hash_command(client, args))
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as error:
        return_error(f'Failed to execute {command} command.\nError:\n{str(error)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
