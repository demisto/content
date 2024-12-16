import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import copy
import shutil
import urllib3
from collections.abc import Callable

from requests import Response

import defusedxml.ElementTree as defused_ET

GENERAL_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
DATE_FORMAT = "%a, %d %b %Y %H:%M:%S GMT"
account_sas_token = ''
storage_account_name = ''


class Client:
    """
    API Client
    """

    def __init__(self, server_url, verify, proxy, account_sas_token, storage_account_name, api_version):
        self.ms_client = MicrosoftStorageClient(server_url, verify, proxy, account_sas_token, storage_account_name,
                                                api_version)

    def create_share_request(self, share_name: str) -> Response:
        """
        Create a new Azure file share under the specified account.
        Args:
            share_name (str): Share name.

        Returns:
            Response: API response from Azure.

        """
        params = assign_params(restype="share")

        response = self.ms_client.http_request(method='PUT', url_suffix=f'{share_name}',
                                               params=params, return_empty_response=True)

        return response

    def delete_share_request(self, share_name: str) -> Response:
        """
        Delete file share under the specified account.
        Args:
            share_name (str): Share name.

        Returns:
            Response: API response from Azure.

        """
        params = assign_params(restype="share")

        response = self.ms_client.http_request(method='DELETE', url_suffix=f'{share_name}',
                                               params=params, return_empty_response=True)

        return response

    def list_shares_request(self, limit: str = None, prefix: str = None, marker: str = None) -> str:
        """
        list Azure file shares under the specified account.
        Args:
            limit (str): Number of shares to retrieve.
            prefix (str): Filters the results to return only shares whose name begins with the specified prefix.
            marker (str): Identifies the portion of the list to be returned.
        Returns:
            str: API response from Azure.

        """
        params = assign_params(comp="list", maxresults=limit, prefix=prefix, marker=marker)

        response = self.ms_client.http_request(method='GET', url_suffix='',
                                               params=params, resp_type="text")

        return response

    def list_directories_and_files_request(self, share_name: str, directory_path: str = None, prefix: str = None,
                                           limit: str = None, marker: str = None) -> str:
        """
        List files and directories under the specified share or directory.

        Args:
            share_name (str): Share name.
            directory_path (str): The path to the directory.
            prefix (str): Filters the results to return only files and directories whose name begins with the specified prefix.
            limit (str): Number of directories and files to retrieve.
            marker (str): Identifies the portion of the list to be returned.

        Returns:
            str: API response from Azure.

        """
        params = assign_params(restype="directory", comp="list", include="Timestamps",
                               prefix=prefix, maxresults=limit, marker=marker)

        url_suffix = f'{share_name}/{directory_path}' if directory_path else f'{share_name}'

        response = self.ms_client.http_request(method='GET', url_suffix=url_suffix,
                                               params=params, resp_type="text")

        return response

    def create_directory_request(self, share_name: str, directory_name: str, directory_path: str = None) -> Response:
        """
        Create a new directory under the specified share or parent directory.
        Args:
            share_name (str): Share name.
            directory_name (str): New directory name.
            directory_path (str): The path to the directory.

        Returns:
            Response: API response from Azure.

        """
        params = assign_params(restype="directory")

        headers = {'x-ms-file-permission': 'inherit ',
                   'x-ms-file-attributes': 'None',
                   'x-ms-file-creation-time': 'now',
                   'x-ms-file-last-write-time': 'now'}

        url_suffix = f'{share_name}/{directory_path}/{directory_name}' if directory_path else f'{share_name}/{directory_name}'

        response = self.ms_client.http_request(method='PUT', url_suffix=url_suffix,
                                               params=params, headers=headers, return_empty_response=True)

        return response

    def delete_directory_request(self, share_name: str, directory_name: str, directory_path: str) -> Response:
        """
        Delete the specified empty directory.
        Args:
            share_name (str): Share name.
            directory_name (str): Directory name.
            directory_path (str): The path to the directory.

        Returns:
            Response: API response from Azure.

        """
        params = assign_params(restype="directory")

        url_suffix = f'{share_name}/{directory_path}/{directory_name}' if directory_path else f'{share_name}/{directory_name}'

        response = self.ms_client.http_request(method='DELETE', url_suffix=url_suffix,
                                               params=params, return_empty_response=True)

        return response

    def create_file_request(self, share_name: str, file_entry_id: str, file_name: str,
                            directory_path: str = None) -> Response:
        """
        Create a New empty file in Share from War room file Entry ID.
        Note that this operation only initializes the file. To add content to a file, we have to call the Put Range operation.
        Args:
            share_name (str): Share name.
            file_entry_id (str): File War room Entry ID.
            file_name (str): File name. Default is XSOAR file name.
            directory_path (str): The path to the directory where the file should be created.

        Returns:
            Response: API response from Azure.


        """
        xsoar_file_data = demisto.getFilePath(
            file_entry_id)  # Retrieve XSOAR system file path and name, given file entry ID.
        xsoar_system_file_path = xsoar_file_data['path']
        new_file_name = file_name if file_name else xsoar_file_data['name']

        create_file_headers = {'x-ms-type': 'file',
                               'x-ms-file-permission': 'Inherit',
                               'x-ms-file-attributes': 'None',
                               'x-ms-file-creation-time': 'now',
                               'x-ms-file-last-write-time': 'now'
                               }

        create_file_url = f'{share_name}/{directory_path}/{new_file_name}' if directory_path else f'{share_name}/{new_file_name}'

        try:
            shutil.copy(xsoar_system_file_path, new_file_name)
        except FileNotFoundError:
            raise Exception(
                'Failed to prepare file for upload. '
                'The process of importing and copying the file data from XSOAR failed.')

        try:
            with open(new_file_name, 'rb') as file:
                file.seek(0, 2)
                content_length = file.tell()
                create_file_headers['x-ms-content-length'] = str(content_length)

                create_file_response = self.ms_client.http_request(method='PUT', url_suffix=create_file_url,
                                                                   headers=create_file_headers,
                                                                   return_empty_response=True)

        finally:
            shutil.rmtree(new_file_name, ignore_errors=True)

        return create_file_response

    def add_file_content_request(self, share_name: str, file_entry_id: str, file_name: str,
                                 directory_path: str = None) -> Response:
        """
        Write a range of bytes to a file.
        Note that this operation not initializes the file, but add content to a file.
        Args:
            share_name (str): Share name.
            file_entry_id (str): File War room Entry ID.
            file_name (str): File name. Default is XSOAR file name.
            directory_path (str): The path to the directory where the file should be created.

        Returns:
            Response: API response from Azure.

        """
        xsoar_file_data = demisto.getFilePath(
            file_entry_id)  # Retrieve XSOAR system file path and name, given file entry ID.
        xsoar_system_file_path = xsoar_file_data['path']
        new_file_name = file_name if file_name else xsoar_file_data['name']

        try:
            shutil.copy(xsoar_system_file_path, new_file_name)
        except FileNotFoundError:
            raise Exception('Failed to prepare file for upload. '
                            'The process of importing and copying the file data from XSOAR failed.')

        try:
            with open(new_file_name, 'rb') as file:
                file.seek(0, 2)
                content_length = file.tell()
                file.seek(0)

                max_range = int(content_length) - 1
                bytes_range = f'bytes=0-{max_range}'

                put_rang_headers = {
                    'x-ms-write': 'update',
                    'x-ms-range': bytes_range,
                    'Content-Length': str(content_length),
                    'x-ms-type': 'file',
                }

                params = {'comp': 'range'}

                put_range_url = f'{share_name}/{directory_path}/{new_file_name}' if directory_path else \
                    f'{share_name}/{new_file_name}'

                put_range_response = self.ms_client.http_request(method='PUT', url_suffix=put_range_url,
                                                                 headers=put_rang_headers, params=params,
                                                                 return_empty_response=True, data=file)

        finally:
            shutil.rmtree(new_file_name, ignore_errors=True)

        return put_range_response

    def get_file_request(self, share_name: str, file_name: str, directory_path: str = None) -> Response:
        """
        Get file from Share.
        Args:
            share_name (str): Share name.
            file_name (str): File name.
            directory_path (str): The path to the file directory.

        Returns:
            Response: API response from Azure.


        """
        url_suffix = f'{share_name}/{directory_path}/{file_name}' if directory_path else f'{share_name}/{file_name}'

        response = self.ms_client.http_request(method='GET', url_suffix=url_suffix, resp_type="response")

        return response

    def delete_file_request(self, share_name, file_name, directory_path):
        """
        Delete file from Share.
        Args:
            share_name (str): Share name.
            file_name (str): File name.
            directory_path (str): The path to the file directory.

        Returns:
            Response: API response from Azure.

        """
        url_suffix = f'{share_name}/{directory_path}/{file_name}' if directory_path else f'{share_name}/{file_name}'

        response = self.ms_client.http_request(method='DELETE', url_suffix=url_suffix, return_empty_response=True)

        return response


def create_share_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create a new Azure file share under the specified account.
    Args:
        client (Client): Azure FileShares Storage API client.
        args (dict): Command arguments from XSOAR.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    share_name = args['share_name']

    share_name_regex = "^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$"
    # Rules for naming shares can be found here:
    # https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-shares--directories--files--and-metadata

    if not re.search(share_name_regex, share_name):
        raise Exception('The specified share name is invalid.')

    client.create_share_request(share_name)

    command_results = CommandResults(
        readable_output=f'Share {share_name} successfully created.',
    )

    return command_results


def delete_share_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete file share under the specified account.
    Args:
        client (Client): Azure FileShares Storage API client.
        args (dict): Command arguments from XSOAR.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    share_name = args['share_name']

    client.delete_share_request(share_name)
    command_results = CommandResults(
        readable_output=f'Share {share_name} successfully deleted.',
    )

    return command_results


def get_pagination_next_marker_element(limit: str, page: int, client_request: Callable, params: dict) -> str:
    """
    Get next marker element for request pagination.
    'marker' is a string value that identifies the portion of the list to be returned with the next list operation.
    The operation returns a NextMarker element within the response body if the list returned was not complete.
    This value may then be used as a query parameter in a subsequent call to request the next portion of the list items.
    Args:
        limit (str): Number of elements to retrieve.
        page (str): Page number.
        client_request (Callable): Client request function.
        params (dict): Request params.

    Returns:
        str: Next marker.

    """
    offset = int(limit) * (page - 1)
    response = client_request(limit=str(offset), **params)
    tree = ET.ElementTree(defused_ET.fromstring(response))
    root = tree.getroot()

    return root.findtext('NextMarker')  # type: ignore


def list_shares_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    list Azure file shares under the specified account.
    Args:
        client (Client): Azure FileShares Storage API client.
        args (dict): Command arguments from XSOAR.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    limit = args.get('limit') or '50'
    prefix = args.get('prefix')
    page = arg_to_number(args.get('page') or '1')
    marker = ''
    readable_message = f'Shares List:\n Current page size: {limit}\n Showing page {page} out others that may exist'

    if page > 1:  # type: ignore
        marker = get_pagination_next_marker_element(limit=limit, page=page,  # type: ignore
                                                    client_request=client.list_shares_request,
                                                    params={"prefix": prefix})
        if not marker:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='AzureStorageFileShare.Share',
                outputs=[],
                raw_response=[]
            )

    response = client.list_shares_request(limit, prefix, marker=marker)

    tree = ET.ElementTree(defused_ET.fromstring(response))
    root = tree.getroot()

    raw_response = []
    outputs = []

    for element in root.iter('Share'):
        data = handle_content_properties_information(element)
        raw_response.append(data)
        outputs.append({'Name': element.findtext('Name')})

    readable_output = tableToMarkdown(
        readable_message,
        outputs,
        headers=['Name'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageFileShare.Share',
        outputs_key_field='Name',
        outputs=outputs,
        raw_response=raw_response
    )

    return command_results


def handle_content_properties_information(element: object) -> dict:
    """
    Handle API response 'properties' information.
    Args:
        element (object): An XML element hierarchy data.

    Returns:
        dict: Transformed dictionary of properties information.

    """

    data = {'Name': element.findtext('Name')}  # type: ignore
    properties = {}
    for share_property in element.findall('Properties'):  # type: ignore
        for attribute in share_property:
            properties[attribute.tag] = attribute.text
    data['Properties'] = properties  # type: ignore

    return data


def handle_directory_content_response(response: str) -> dict:
    """
    Convert XML schema directory content to dictionary data structure.
    Args:
        response (str): XML schema string response.

    Returns:
        dict: Raw response.

    """
    tree = ET.ElementTree(defused_ET.fromstring(response))
    root = tree.getroot()

    xml_path = ['Directory', 'File']
    raw_response = {'Directory': [], 'File': [], 'DirectoryId': root.findtext('DirectoryId')}  # type: ignore

    for path in xml_path:
        for element in root.iter(path):
            data = handle_content_properties_information(element)
            data['FileId'] = element.findtext('FileId')
            raw_response[path].append(data)  # type: ignore

    return raw_response


def create_directory_content_output(share_name: str, raw_response: dict, directory_path: str = "") -> dict:
    """
    Create XSOAR context output for list directory command.
    Args:
        share_name (str): Share name.
        raw_response (dict): Request raw response.
        directory_path (str): Source directory path.

    Returns:
        dict: XSOAR command context output.

    """

    xml_path = ['Directory', 'File']

    outputs = {"Name": share_name, "Content": {"Path": directory_path, "DirectoryId": raw_response['DirectoryId']}}

    time_headers = ['CreationTime', 'LastAccessTime', 'LastWriteTime', 'ChangeTime']

    for path in xml_path:
        for element in raw_response.get(path):  # type: ignore
            for header in time_headers:
                str_time = element['Properties'].get(header)  # type: ignore
                str_time = str_time[:-2] + 'Z'
                element['Properties'][header] = FormatIso8601(  # type: ignore
                    datetime.strptime(str_time, GENERAL_DATE_FORMAT))  # type: ignore

            element['Properties']['Last-Modified'] = FormatIso8601(  # type: ignore
                datetime.strptime(element['Properties']['Last-Modified'], DATE_FORMAT))  # type: ignore

            element['Property'] = element.pop('Properties')  # type: ignore

    outputs["Content"].update(raw_response)  # type: ignore

    return outputs


def create_content_readable_output(outputs: dict, prefix: str = '') -> str:
    """
    Create readable output for list directory content command.
    Args:
        outputs (dict): Command outputs.
        prefix (str): Readable output prefix.

    Returns:
        str: Command readable output.

    """
    directories_outputs = tableToMarkdown(
        'Directories:',
        outputs["Content"]["Directory"],
        headers=['Name', 'FileId'],
        headerTransform=pascalToSpace
    )

    files_outputs = tableToMarkdown(
        'Files:',
        outputs["Content"]["File"],
        headers=['Name', 'FileId'],
        headerTransform=pascalToSpace
    )

    return prefix + "\n" + directories_outputs + "\n" + files_outputs


def list_directories_and_files_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List files and directories under the specified share or directory.
    Args:
        client (Client): Azure FileShares Storage API client.
        args (dict): Command arguments from XSOAR.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    prefix = args.get('prefix')
    limit = args.get('limit') or '50'
    share_name = args['share_name']
    directory_path = args.get('directory_path', '')

    page = arg_to_number(args.get('page') or '1')
    marker = ''
    readable_message = f'Directories and Files List:\n Current page size: {limit}\n Showing page {page} out others that may exist'

    if page > 1:  # type: ignore
        marker = get_pagination_next_marker_element(limit=limit, page=page,  # type: ignore
                                                    client_request=client.list_directories_and_files_request,
                                                    params={"prefix": prefix, "share_name": share_name,
                                                            "directory_path": directory_path})

        if not marker:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='AzureStorageFileShare.Share',
                outputs=[],
                raw_response=[]
            )

    response = client.list_directories_and_files_request(share_name, directory_path, prefix, limit, marker)

    raw_response = handle_directory_content_response(response)

    response_copy = copy.deepcopy(raw_response)
    outputs = create_directory_content_output(share_name, response_copy, directory_path)

    readable_output = create_content_readable_output(outputs, readable_message)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_key_field='Name',
        outputs_prefix='AzureStorageFileShare.Share',
        outputs=outputs,
        raw_response=raw_response
    )

    return command_results


def validate_characters(string: str, invalid_characters: str) -> bool:
    """
    Validate that string does not contain invalid characters.
    Args:
        string (str): String validate.
        invalid_characters (str): Characters to validate.

    Returns:
        bool: True if the string is valid , otherwise False.

    """
    return all(character not in string for character in invalid_characters)


def create_directory_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create a new directory under the specified share or parent directory.
    Args:
        client (Client): Azure FileShares Storage API client.
        args (dict): Command arguments from XSOAR.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    share_name = args['share_name']
    directory_name = args['directory_name']
    directory_path = args.get('directory_path')

    if not validate_characters(directory_name, "\"\/:|<>*?"):
        raise Exception('The specified directory name is invalid.')

    client.create_directory_request(share_name, directory_name, directory_path)

    command_results = CommandResults(
        readable_output=f'{directory_name} Directory successfully created in {share_name}.',
    )

    return command_results


def delete_directory_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete the specified empty directory.
    Args:
        client (Client): Azure FileShares Storage API client.
        args (dict): Command arguments from XSOAR.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    share_name = args['share_name']
    directory_name = args['directory_name']
    directory_path = args.get('directory_path')

    client.delete_directory_request(share_name, directory_name, directory_path)  # type: ignore
    command_results = CommandResults(
        readable_output=f'{directory_name} Directory successfully deleted from {share_name}.'
    )

    return command_results


def create_file_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create a file in Share from War room file Entry ID.
    Args:
        client (Client): Azure FileShares Storage API client.
        args (dict): Command arguments from XSOAR.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    share_name = args['share_name']
    file_entry_id = args['file_entry_id']
    directory_path = args.get('directory_path')
    file_name = args.get('file_name')

    client.create_file_request(share_name, file_entry_id, file_name, directory_path)  # type: ignore
    client.add_file_content_request(share_name, file_entry_id, file_name, directory_path)  # type: ignore

    command_results = CommandResults(
        readable_output=f'File successfully created in {share_name}.'
    )

    return command_results


def get_file_command(client: Client, args: Dict[str, Any]) -> fileResult:  # type: ignore
    """
    Get file from Share.
    Args:
        client (Client): Azure FileShares Storage API client.
        args (dict): Command arguments from XSOAR.
    Returns:
        fileResult: XSOAR File Result.

    """
    share_name = args['share_name']
    file_name = args['file_name']
    directory_path = args.get('directory_path')

    response = client.get_file_request(share_name, file_name, directory_path)

    return fileResult(filename=file_name, data=response.content)


def delete_file_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete file from Share.
    Args:
        client (Client): Azure FileShares Storage API client.
        args (dict): Command arguments from XSOAR.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    share_name = args['share_name']
    file_name = args['file_name']
    directory_path = args.get('directory_path')

    client.delete_file_request(share_name, file_name, directory_path)
    command_results = CommandResults(
        readable_output=f'File {file_name} successfully deleted from {share_name}.',
    )

    return command_results


def test_module(client: Client) -> None:
    """
    Tests API connectivity and authentication.
    Args:
        client (Client): Azure FileShares Storage API client.
    Returns:
        str : 'ok' if test passed, anything else will fail the test.
    """
    try:
        client.list_shares_request()
    except Exception as exception:
        if 'Error in API call' in str(exception):
            return return_results('Authorization Error: make sure API Credentials are correctly set')

        if 'Error Type' in str(exception):
            return return_results(
                'Verify that the storage account name is correct and that you have access to the server from your host.')

        raise exception

    return_results('ok')
    return None


def main() -> None:
    """
    Main function
    """
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    global account_sas_token
    global storage_account_name
    account_sas_token = params['credentials']['password']
    storage_account_name = params['credentials']['identifier']
    api_version = "2020-10-02"
    base_url = f'https://{storage_account_name}.file.core.windows.net/'

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client: Client = Client(base_url, verify_certificate, proxy, account_sas_token, storage_account_name,
                                api_version)

        commands = {
            'azure-storage-fileshare-create': create_share_command,
            'azure-storage-fileshare-delete': delete_share_command,
            'azure-storage-fileshare-list': list_shares_command,
            'azure-storage-fileshare-content-list': list_directories_and_files_command,
            'azure-storage-fileshare-directory-create': create_directory_command,
            'azure-storage-fileshare-directory-delete': delete_directory_command,
            'azure-storage-fileshare-file-create': create_file_command,
            'azure-storage-fileshare-file-get': get_file_command,
            'azure-storage-fileshare-file-delete': delete_file_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


from MicrosoftAzureStorageApiModule import *  # noqa: E402

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
