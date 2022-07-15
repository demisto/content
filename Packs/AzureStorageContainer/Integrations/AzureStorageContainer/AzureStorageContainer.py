import shutil
from typing import Callable

from requests import Response

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
account_sas_token = ""
storage_account_name = ""


class Client:
    """
    API Client
    """

    def __init__(self, server_url, verify, proxy, account_sas_token, storage_account_name, api_version):
        self.ms_client = MicrosoftStorageClient(server_url, verify, proxy, account_sas_token, storage_account_name,
                                                api_version)

    def list_containers_request(self, limit: str = None, prefix: str = None, marker: str = None) -> str:
        """
        List Containers under the specified storage account.

        Args:
            limit (str): Number of Containers to retrieve.
            prefix (str): Filters the results to return only Containers whose name begins with the specified prefix.
            marker (str): Identifies the portion of the list to be returned.

        Returns:
            str: API response from Azure.

        """
        params = assign_params(maxresults=limit, prefix=prefix, comp='list', marker=marker)

        response = self.ms_client.http_request(method='GET', url_suffix='', params=params, resp_type="text")

        return response

    def create_container_request(self, container_name: str) -> Response:
        """
        Create a new Container under the specified account.

        Args:
            container_name (str): Container name.

        Returns:
            Response: API response from Azure.

        """
        params = assign_params(restype="container")

        response = self.ms_client.http_request(method='PUT', url_suffix=f'{container_name}', params=params,
                                               return_empty_response=True)

        return response

    def get_container_properties_request(self, container_name: str) -> Response:
        """
        Retrieve properties for the specified Container.

        Args:
            container_name (str): Container name.

        Returns:
            Response: API response from Azure.

        """
        params = assign_params(restype="container")

        response = self.ms_client.http_request(method='GET', url_suffix=f'{container_name}', params=params,
                                               return_empty_response=True)

        return response

    def delete_container_request(self, container_name: str) -> Response:
        """
        Delete Container under the specified account.

        Args:
            container_name (str): Container name.

        Returns:
            Response: API response from Azure.

        """
        params = assign_params(restype="container")

        response = self.ms_client.http_request(method='DELETE', url_suffix=f'{container_name}', params=params,
                                               return_empty_response=True)

        return response

    def list_blobs_request(self, container_name: str, limit: str = None, prefix: str = None, marker: str = None) -> str:
        """
        List Blobs under the specified container.

        Args:
            container_name (str): Container name.
            limit (str): Number of Blob to retrieve.
            prefix (str): Filters the results to return only Blob whose name begins with the specified prefix.
            marker (str): Identifies the portion of the list to be returned.

        Returns:
            str: API response from Azure.

        """
        params = assign_params(container_name=container_name, maxresults=limit,
                               prefix=prefix, restype='container', comp='list', marker=marker)

        response = self.ms_client.http_request(method='GET', url_suffix=f'{container_name}', params=params,
                                               resp_type="text")

        return response

    def put_blob_request(self, container_name: str, file_entry_id: str, file_name: str = None) -> Response:
        """
        Create or update Blob under the specified Container.

        Args:
            container_name (str): Container name.
            file_entry_id (str): File War room Entry ID.
            file_name (str): File name. Default is XSOAR file name.

        Returns:
            Response: API response from Azure.

        """

        xsoar_file_data = demisto.getFilePath(
            file_entry_id)  # Retrieve XSOAR system file path and name, given file entry ID.
        xsoar_system_file_path = xsoar_file_data['path']
        blob_name = file_name if file_name else xsoar_file_data['name']

        headers = {'x-ms-blob-type': 'BlockBlob'}

        try:
            shutil.copy(xsoar_system_file_path, blob_name)
        except FileNotFoundError:
            raise Exception('Failed to prepare file for upload. '
                            'The process of importing and copying the file data from XSOAR failed.')

        try:
            with open(blob_name, 'rb') as file:
                response = self.ms_client.http_request(method='PUT',
                                                       url_suffix=f'{container_name}/{blob_name}',
                                                       headers=headers,
                                                       return_empty_response=True,
                                                       data=file)

        finally:
            shutil.rmtree(blob_name, ignore_errors=True)

        return response

    def get_blob_request(self, container_name: str, blob_name: str) -> Response:
        """
        Retrieve Blob from Container.

        Args:
            container_name (str): Container name.
            blob_name (str): Blob name.

        Returns:
            Response: API response from Azure.

        """
        response = self.ms_client.http_request(method='GET', url_suffix=f'{container_name}/{blob_name}',
                                               resp_type="response")

        return response

    def get_blob_tags_request(self, container_name: str, blob_name: str) -> str:
        """
        Retrieve the tags of the specified Blob.

        Args:
            container_name (str): Container name.
            blob_name (str): Blob name.

        Returns:
            str: API response from Azure.

        """
        params = assign_params(comp="tags")

        response = self.ms_client.http_request(method='GET', url_suffix=f'{container_name}/{blob_name}', params=params,
                                               resp_type="text")

        return response

    def set_blob_tags_request(self, container_name: str, blob_name: str, tags: str) -> Response:
        """
        Set the tags for the specified Blob.

        Args:
            container_name (str): Container name.
            blob_name (str): Blob name.
            tags (str): XML tags data.

        Returns:
            Response: API response from Azure.

        """
        params = assign_params(comp="tags")

        response = self.ms_client.http_request(method='PUT', url_suffix=f'{container_name}/{blob_name}',
                                               params=params, return_empty_response=True, data=tags)

        return response

    def delete_blob_request(self, container_name: str, blob_name: str) -> Response:
        """
        Delete Blob from Container.

        Args:
            container_name (str): Container name.
            blob_name (str): Blob name.

        Returns:
            Response: API response from Azure.

        """

        response = self.ms_client.http_request(method='DELETE', url_suffix=f'{container_name}/{blob_name}',
                                               return_empty_response=True)

        return response

    def get_blob_properties_request(self, container_name: str, blob_name: str) -> Response:
        """
        Retrieve Blob properties.

        Args:
            container_name (str): Container name.
            blob_name (str): Blob name.

        Returns:
            Response: API response from Azure.

        """

        response = self.ms_client.http_request(method='HEAD', url_suffix=f'{container_name}/{blob_name}',
                                               resp_type="response")

        return response

    def set_blob_properties_request(self, container_name: str, blob_name: str, headers: dict) -> Response:
        """
        Set Blob properties.

        Args:
            container_name (str): Container name.
            blob_name (str): Blob name.
            headers (dict): Request Headers.

        Returns:
            Response: API response from Azure.

        """

        params = assign_params(comp='properties')
        response = self.ms_client.http_request(method='PUT', url_suffix=f'{container_name}/{blob_name}',
                                               params=params, headers=headers, return_empty_response=True)

        return response


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
    tree = ET.ElementTree(ET.fromstring(response))
    root = tree.getroot()

    return root.findtext('NextMarker')  # type: ignore


def list_containers_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List Containers under the specified storage account.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    limit = args.get('limit') or '50'
    prefix = args.get('prefix')
    page = arg_to_number(args.get('page') or '1')

    marker = ''
    readable_message = f'Containers List:\n Current page size: {limit}\n Showing page {page} out others that may exist'

    if page > 1:  # type: ignore
        marker = get_pagination_next_marker_element(limit=limit, page=page,  # type: ignore
                                                    client_request=client.list_containers_request,
                                                    params={"prefix": prefix})

        if not marker:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='AzureStorageContainer.Container',
                outputs=[],
                raw_response=[]
            )

    response = client.list_containers_request(limit, prefix, marker)

    tree = ET.ElementTree(ET.fromstring(response))
    root = tree.getroot()

    raw_response = []
    outputs = []

    for element in root.iter('Container'):
        outputs.append({'name': element.findtext('Name')})
        data = {'Name': element.findtext('Name')}
        properties = {}
        for container_property in element.findall('Properties'):
            for attribute in container_property:
                properties[attribute.tag] = attribute.text

        data['Property'] = properties  # type: ignore
        raw_response.append(data)

    readable_output = tableToMarkdown(
        readable_message,
        outputs,
        headers=['name'],
        headerTransform=string_to_table_header
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageContainer.Container',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=raw_response
    )

    return command_results


def create_container_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create a new Container under the specified account.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    container_name = args['container_name']

    container_name_regex = "^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$"
    # Rules for naming containers can be found here:
    # https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata

    if not re.search(container_name_regex, container_name):
        raise Exception('The specified container name is invalid.')

    client.create_container_request(container_name)

    command_results = CommandResults(
        readable_output=f'Container {container_name} successfully created.',
    )

    return command_results


def convert_dict_time_format(data: dict, keys: list):
    """
    Convert dictionary data values time format.
    Args:
        data (dict): Data.
        keys (list): Keys list to convert

    """
    for key in keys:
        if data.get(key):
            time_value = datetime.strptime(data.get(key), DATE_FORMAT)  # type: ignore
            iso_time = FormatIso8601(time_value)
            data[key] = iso_time


def get_container_properties_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve properties for the specified Container.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    container_name = args['container_name']

    response = client.get_container_properties_request(container_name)

    raw_response = response.headers
    raw_response = dict(raw_response)  # Convert raw_response from 'CaseInsensitiveDict' to 'dict'

    response_headers = list(raw_response.keys())
    outputs = {}

    properties = transform_response_to_context_format(raw_response, response_headers)

    outputs['name'] = container_name
    outputs['Property'] = properties

    convert_dict_time_format(outputs['Property'], ['last_modified', 'date'])

    readable_output = tableToMarkdown(
        f'Container {container_name} Properties:',
        outputs.get('Property'),
        headers=['last_modified', 'etag', 'lease_status', 'lease_state', 'has_immutability_policy', 'has_legal_hold'],
        headerTransform=string_to_table_header
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageContainer.Container',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=raw_response
    )


def delete_container_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete Container under the specified account.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    container_name = args['container_name']

    client.delete_container_request(container_name)

    command_results = CommandResults(
        readable_output=f'Container {container_name} successfully deleted.',
    )

    return command_results


def list_blobs_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List Blobs under the specified container.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    container_name = args['container_name']
    limit = args.get('limit') or '50'
    prefix = args.get('prefix')
    page = arg_to_number(args.get('page') or '1')

    marker = ''
    readable_message = f'{container_name} Container Blobs List:\n Current page size: {limit}\n ' \
                       f'Showing page {page} out others that may exist'
    if page > 1:  # type: ignore
        marker = get_pagination_next_marker_element(limit=limit, page=page,  # type: ignore
                                                    client_request=client.list_blobs_request,
                                                    params={"container_name": container_name,
                                                            "prefix": prefix})  # type: ignore

        if not marker:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='AzureStorageContainer.Container',
                outputs=[],
                raw_response=[]
            )

    response = client.list_blobs_request(container_name, limit, prefix, marker)

    tree = ET.ElementTree(ET.fromstring(response))
    root = tree.getroot()

    raw_response = []
    blobs = []

    for element in root.iter('Blob'):
        data = {'name': element.findtext('Name')}
        blobs.append(dict(data))
        properties = {}
        for blob_property in element.findall('Properties'):
            for attribute in blob_property:
                properties[attribute.tag] = attribute.text

        data['Property'] = properties  # type: ignore
        raw_response.append(data)

    outputs = {"name": container_name, "Blob": blobs}
    readable_output = tableToMarkdown(
        readable_message,
        outputs.get('Blob'),
        headers='name',
        headerTransform=string_to_table_header
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageContainer.Container',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=raw_response

    )

    return command_results


def create_blob_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create a new Blob under the specified Container.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    container_name = args['container_name']
    file_entry_id = args['file_entry_id']
    blob_name = args.get('blob_name')

    client.put_blob_request(container_name, file_entry_id, blob_name)

    command_results = CommandResults(
        readable_output='Blob successfully created.',
    )

    return command_results


def update_blob_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update Blob under the specified Container.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    container_name = args['container_name']
    file_entry_id = args['file_entry_id']
    blob_name = args['blob_name']

    client.put_blob_request(container_name, file_entry_id, blob_name)

    command_results = CommandResults(
        readable_output=f'Blob {blob_name} successfully updated.',
    )

    return command_results


def get_blob_command(client: Client, args: Dict[str, Any]) -> fileResult:  # type: ignore
    """
    Retrieve Blob from Container.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        fileResult: XSOAR File Result.

    """
    container_name = args['container_name']
    blob_name = args['blob_name']

    response = client.get_blob_request(container_name, blob_name)

    return fileResult(filename=blob_name, data=response.content)


def get_blob_tags_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the tags of the specified Blob.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    container_name = args['container_name']
    blob_name = args['blob_name']

    response = client.get_blob_tags_request(container_name, blob_name)

    tree = ET.ElementTree(ET.fromstring(response))
    root = tree.getroot()

    raw_response = []
    outputs = {'name': container_name, 'Blob': {'name': blob_name}}

    for element in root.iter('Tag'):
        tag = {'Key': element.findtext('Key'), 'Value': element.findtext('Value')}
        raw_response.append(dict(tag))

    outputs['Blob']['Tag'] = raw_response

    readable_output = tableToMarkdown(
        f'Blob {blob_name} Tags:',
        outputs['Blob']['Tag'],
        headers=['Key', 'Value'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageContainer.Container',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=raw_response
    )

    return command_results


def create_set_tags_request_body(tags: dict) -> str:
    """
    Create XML request body for set blob tags.
    Args:
        tags (dict): Tags data. Key represents tag name , and value represents tag Value.

    Returns:
        str: Set tags request body.

    """
    top = ET.Element('Tags')

    tag_set = ET.SubElement(top, 'TagSet')

    for key, value in tags.items():
        tag = ET.SubElement(tag_set, 'Tag')
        tag_key = ET.SubElement(tag, 'Key')
        tag_key.text = key

        tag_value = ET.SubElement(tag, 'Value')
        tag_value.text = value

    return ET.tostring(top, encoding='unicode')


def set_blob_tags_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Sets the tags for the specified Blob.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    container_name = args['container_name']
    blob_name = args['blob_name']
    tags = args['tags']

    try:
        tags = json.loads(tags)
    except ValueError:
        raise ValueError('Failed to parse tags argument. Please provide valid JSON format tags data.')

    xml_data = create_set_tags_request_body(tags)

    client.set_blob_tags_request(container_name, blob_name, xml_data)

    command_results = CommandResults(
        readable_output=f'{blob_name} Tags successfully updated.',
    )

    return command_results


def delete_blob_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete Blob from Container.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    container_name = args['container_name']
    blob_name = args['blob_name']

    client.delete_blob_request(container_name, blob_name)

    command_results = CommandResults(
        readable_output=f'Blob {blob_name} successfully deleted.',
    )

    return command_results


def transform_response_to_context_format(data: dict, keys: list) -> dict:
    """
    Transform API response data to suitable XSOAR context data.
    Remove 'x-ms' prefix and replace '-' to '_' for more readable and conventional variables.
    Args:
        data (dict): Data to exchange.
        keys (list): Keys to filter.

    Returns:
        dict: Processed data.

    """
    return {key.replace('x-ms-', '').replace('-', '_').lower(): value
            for key, value in data.items() if key in keys}


def get_blob_properties_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve Blob properties.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    container_name = args['container_name']
    blob_name = args['blob_name']

    response = client.get_blob_properties_request(container_name, blob_name)

    raw_response = response.headers
    raw_response = dict(raw_response)  # Convert raw_response from 'CaseInsensitiveDict' to 'dict'

    response_headers = list(raw_response.keys())
    outputs = {}

    properties = transform_response_to_context_format(raw_response, response_headers)

    outputs['name'] = container_name
    outputs['Blob'] = {'name': blob_name, 'Property': properties}

    convert_dict_time_format(outputs['Blob']['Property'], ['creation_time', 'last_modified', 'date'])

    readable_output = tableToMarkdown(
        f'Blob {blob_name} Properties:',
        outputs.get('Blob').get('Property'),  # type: ignore
        headers=['creation_time', 'last_modified', 'content_length', 'content_type', 'etag'],
        headerTransform=string_to_table_header
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageContainer.Container',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=raw_response
    )


def set_blob_properties_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Set Blob properties.

    Args:
        client (Client): Azure Blob Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    container_name = args['container_name']
    blob_name = args['blob_name']
    content_type = args.get('content_type')
    content_md5 = args.get('content_md5')
    content_encoding = args.get('content_encoding')
    content_language = args.get('content_language')
    content_disposition = args.get('content_disposition')
    cache_control = args.get('cache_control')
    request_id = args.get('request_id')
    lease_id = args.get('lease_id')

    headers = remove_empty_elements({
        'x-ms-blob-cache-control': cache_control,
        'x-ms-blob-content-type': content_type,
        'x-ms-blob-content-md5': content_md5,
        'x-ms-blob-content-encoding': content_encoding,
        'x-ms-blob-content-language': content_language,
        'x-ms-blob-content-disposition': content_disposition,
        'x-ms-client-request-id': request_id,
        'x-ms-lease-id': lease_id,
    })

    client.set_blob_properties_request(container_name, blob_name, headers)

    command_results = CommandResults(
        readable_output=f'Blob {blob_name} properties successfully updated.',
    )

    return command_results


def test_module(client: Client) -> None:
    """
    Tests API connectivity and authentication.
    Args:
        client (Client): Azure Blob Storage API client.
    Returns:
        str : 'ok' if test passed, anything else will fail the test.
    """
    try:
        client.list_containers_request()
    except Exception as exception:
        if 'Error in API call' in str(exception):
            return return_results('Authorization Error: make sure API Credentials are correctly set')

        if 'Error Type' in str(exception):
            return return_results(
                'Verify that the storage account name is correct and that you have access to the server from your host.')

        raise exception

    return_results('ok')


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
    base_url = f'https://{storage_account_name}.blob.core.windows.net/'

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(base_url, verify_certificate, proxy, account_sas_token, storage_account_name,
                                api_version)

        commands = {
            'azure-storage-container-list': list_containers_command,
            'azure-storage-container-create': create_container_command,
            'azure-storage-container-property-get': get_container_properties_command,
            'azure-storage-container-delete': delete_container_command,
            'azure-storage-container-blob-list': list_blobs_command,
            'azure-storage-container-blob-create': create_blob_command,
            'azure-storage-container-blob-update': update_blob_command,
            'azure-storage-container-blob-get': get_blob_command,
            'azure-storage-container-blob-tag-get': get_blob_tags_command,
            'azure-storage-container-blob-tag-set': set_blob_tags_command,
            'azure-storage-container-blob-delete': delete_blob_command,
            'azure-storage-container-blob-property-get': get_blob_properties_command,
            'azure-storage-container-blob-property-set': set_blob_properties_command,
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
