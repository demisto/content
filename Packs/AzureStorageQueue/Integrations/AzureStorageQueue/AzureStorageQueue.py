import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections.abc import Callable


import base64
import copy
import defusedxml.ElementTree as defused_ET
from requests import Response
import urllib3

DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
account_sas_token = ""
storage_account_name = ""


class Client:
    """
    API Client
    """

    def __init__(self, server_url, verify, proxy, account_sas_token, storage_account_name,
                 api_version, managed_identities_client_id: Optional[str] = None):
        self.ms_client = MicrosoftStorageClient(server_url, verify, proxy, account_sas_token, storage_account_name,
                                                api_version, managed_identities_client_id)

    def list_queues_request(self, limit: str = None, prefix: str = None, marker: str = None) -> str:
        """
        List queues in Azure storage account.

        Args:
            limit (str): Number of queues to retrieve.
            prefix (str): Filters the results to return only queues with names that begin with the specified prefix.
            marker (str): Identifies the portion of the list to be returned.

        Returns:
            str: API xml response from Azure.

        """
        params = assign_params(comp='list', maxresults=limit, prefix=prefix, marker=marker)

        response = self.ms_client.http_request(method="GET", url_suffix='', params=params, resp_type="text")

        return response

    def create_queue_request(self, queue_name: str) -> Response:
        """
        Create queue in storage account.

        Args:
            queue_name (str): New queue name.

        Returns:
            Response: API response from Azure.

        """

        response = self.ms_client.http_request(method="PUT", url_suffix=f'/{queue_name}', return_empty_response=True)

        return response

    def delete_queue_request(self, queue_name: str) -> Response:
        """
        Delete queue from storage account.

        Args:
            queue_name (str): New queue name.

        Returns:
            Response: API response from Azure.

        """

        response = self.ms_client.http_request(method="DELETE", url_suffix=f'/{queue_name}', return_empty_response=True)

        return response

    def create_message_request(self, queue_name: str, xml_data: str,
                               visibility_time_out: int = None, expiration: int = None) -> str:
        """
        Add a new message to the back of the message queue.

        Args:
            queue_name (str): Queue name.
            xml_data (str): Request XML data.
            visibility_time_out (int): Specifies the new visibility timeout value.
            expiration (int): Specifies the time-to-live interval for the message, in seconds.

        Returns:
            str: API response from Azure.

        """

        params = assign_params(messagettl=expiration, visibilitytimeout=visibility_time_out)

        response = self.ms_client.http_request(method="POST", url_suffix=f'/{queue_name}/messages', params=params,
                                               resp_type="text", data=xml_data)

        return response

    def get_messages_request(self, queue_name: str, limit: str = "1", visibility_time_out: int = 30) -> str:
        """
        Retrieves messages from the front of the queue.
        Retrieved messages will move to the end of the queue,and will be visible after 'visibility_time_out' argument.

        Args:
            limit (str): Number of messages to retrieve.
            queue_name (str): Queue name.
            visibility_time_out (int): Specifies the new visibility timeout value.

        Returns:
            str: API response from Azure.

        """
        params = assign_params(numofmessages=limit, visibilitytimeout=visibility_time_out)

        response = self.ms_client.http_request(method="GET", url_suffix=f'/{queue_name}/messages',
                                               resp_type="text", params=params)

        return response

    def peek_messages_request(self, limit: str, queue_name: str) -> str:
        """
        Retrieves messages from the front of the queue.

        Args:
            limit (str): Number of messages to retrieve
            queue_name (str): Queue name.

        Returns:
            str: API response from Azure.

        """
        params = assign_params(numofmessages=limit, peekonly="true")

        response = self.ms_client.http_request(method="GET", url_suffix=f'/{queue_name}/messages',
                                               resp_type="text", params=params)

        return response

    def delete_message_request(self, queue_name: str, message_id: str, pop_receipt: str) -> Response:
        """
        Delete message from the queue.

        Args:
            queue_name (str): Queue name.
            message_id (str): Message ID.
            pop_receipt (str): Message ID pop-receipt.

        Returns:
            Response: API response from Azure.

        """
        params = assign_params(popreceipt=pop_receipt.replace("+", "%2b"))

        url_suffix = f'/{queue_name}/messages/{message_id}'

        response = self.ms_client.http_request(method="DELETE", url_suffix=url_suffix,
                                               params=params, return_empty_response=True)

        return response

    def update_message_request(self, queue_name: str, xml_data: str, message_id: str, pop_receipt: str,
                               visibility_time_out: str) -> Response:
        """
        Update message in the queue.

        Args:
            queue_name (str): Queue name.
            xml_data (str): Request XML data.
            message_id (str): Updated message ID.
            pop_receipt (str): Updated message ID pop-receipt.
            visibility_time_out (str): Specifies the new visibility timeout value.

        Returns:
            Response: API response text from Azure.

        """

        params = assign_params(popreceipt=pop_receipt.replace("+", "%2b"),
                               visibilitytimeout=visibility_time_out)

        url_suffix = f'/{queue_name}/messages/{message_id}'

        response = self.ms_client.http_request(method="PUT", url_suffix=url_suffix, params=params, data=xml_data,
                                               return_empty_response=True)

        return response

    def clear_messages_request(self, queue_name: str) -> Response:
        """
        Delete all messages from the queue.

        Args:
            queue_name (str): Queue name.

        Returns:
            Response: API response text from Azure.

        """
        url_suffix = f'/{queue_name}/messages'

        response = self.ms_client.http_request(method="DELETE", url_suffix=url_suffix, return_empty_response=True)

        return response


def parse_xml_response(xml_string_response: str, tag_path: str = "", find_tag: bool = False) -> list:
    """
    Parse Azure XML response.
    Convert XML schema string to iterable list.
    For example:
    xml_string_response = Integration log: <?xml version="1.0" encoding="utf-8"?><QueueMessagesList>
                                            <QueueMessage><MessageId>e90f5f60-7a02-4b0b-a522-04ca8f3a00b9</MessageId>
                                            <InsertionTime>Thu, 14 Oct 2021 08:17:14 GMT</InsertionTime>
                                            <ExpirationTime>Thu, 21 Oct 2021 08:17:14 GMT</ExpirationTime>
                                            <DequeueCount>0</DequeueCount><MessageText>demo content</MessageText>
                                            </QueueMessage>
                                            </QueueMessagesList>

    The return value will be:
    [{'MessageId': 'e90f5f60-7a02-4b0b-a522-04ca8f3a00b9', 'InsertionTime': 'Thu, 14 Oct 2021 08:17:14 GMT',
    'ExpirationTime': 'Thu, 21 Oct 2021 08:17:14 GMT', 'DequeueCount': '0', 'MessageText': 'demo content'}]
    Args:
        xml_string_response (str): XML response.
        tag_path (str): XML target Tag.
        find_tag (bool): Indicates parse operation type.

    Returns:
        list: XML iterable element.

    """

    tree = ET.ElementTree(defused_ET.fromstring(xml_string_response))

    root = tree.getroot()

    raw_response = []

    if find_tag:
        return root.findall(tag_path)

    for message in root.iter(tag_path):
        message_data = {}
        for attribute in message:
            message_data[attribute.tag] = attribute.text

        raw_response.append(message_data)

    return raw_response


def is_base_64(string: str) -> bool:
    """
    Validate if string is base 64 encoded.
    Args:
        string (str): String to validate.

    Returns:
        bool: True if the string is base 64 encoded ,  else False.

    """
    try:
        if isinstance(string, str):
            # If there's any unicode here, an exception will be thrown and the function will return false
            string_bytes = bytes(string, 'ascii')
        elif isinstance(string, bytes):
            string_bytes = string
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(string_bytes)) == string_bytes
    except Exception:
        return False


def decode_message(string: str) -> str:
    """
    Decode string if it is encoded in base64.
    Args:
        string (str): String to decode.

    Returns:
        str : Decoded / origin string.

    """
    if is_base_64(string):
        try:
            return base64.b64decode(string).decode("utf-8")
        except Exception:
            return string

    return string


def encode_message(string: str) -> str:
    """
    Encode string in base64.
    Args:
        string (str): String to decode.

    Returns:
        str: Encoded string.

    """
    message_bytes = string.encode('utf-8')

    return base64.b64encode(message_bytes).decode("utf-8")


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


def list_queues_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     List queues in Azure storage account.
    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    limit = args.get('limit') or '50'
    prefix = args.get('prefix')

    page = arg_to_number(args.get('page') or '1')
    marker = ''
    readable_message = f'Queues List:\n Current page size: {limit}\n Showing page {page} out others that may exist'

    if page > 1:  # type: ignore
        marker = get_pagination_next_marker_element(limit=limit, page=page,  # type: ignore
                                                    client_request=client.list_queues_request,
                                                    params={"prefix": prefix})

        if not marker:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='AzureStorageQueue.Queue',
                outputs=[],
                raw_response=[]
            )

    response = client.list_queues_request(limit, prefix, marker)

    xml_response = parse_xml_response(xml_string_response=response, tag_path="./Queues/Queue/Name", find_tag=True)

    raw_response = [{"name": element.text} for element in xml_response]

    readable_output = tableToMarkdown(
        readable_message,
        raw_response,
        headers='name',
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageQueue.Queue',
        outputs_key_field='name',
        outputs=raw_response,
        raw_response=raw_response
    )

    return command_results


def create_queue_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create queue in storage account.
    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: readable output for XSOAR.

    """
    queue_name = args["queue_name"]

    queue_name_regex = "^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$"
    # Rules for naming queues can be found here:
    # https://docs.microsoft.com/en-us/rest/api/storageservices/naming-queues-and-metadata

    if not re.search(queue_name_regex, queue_name):
        raise Exception('The specified queue name is invalid.')

    response = client.create_queue_request(queue_name)

    readable_output = f'Queue {queue_name} successfully created.' if response.status_code == 201 \
        else f'Queue {queue_name} already exists.'

    command_results = CommandResults(
        readable_output=readable_output
    )

    return command_results


def delete_queue_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete queue from storage account.
    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: readable output for XSOAR.

    """
    queue_name = args["queue_name"]
    client.delete_queue_request(queue_name)

    readable_output = f'Queue {queue_name} successfully deleted.'

    command_results = CommandResults(
        readable_output=readable_output
    )

    return command_results


def date_values_to_iso(data: dict, keys: list):
    """
    Convert time data values to ISO 8601 time format.
    input example: keys = ['InsertionTime','ExpirationTime'] , data = {
                            'InsertionTime': 'Wed, 13 Oct 2021 09:11:32 GMT',
                            'ExpirationTime': 'Wed, 20 Oct 2021 09:11:32 GMT',
                            }

    the method will convert the data to:
    {
        'InsertionTime': '2021-10-13T09:11:32',
        'ExpirationTime': '2021-10-20T09:11:32'
    }

    Args:
        data (dict): Data.
        keys (list): Keys list to convert.

    """
    for key in keys:
        if data.get(key):
            time_value = datetime.strptime(data.get(key), DATE_FORMAT)  # type: ignore
            iso_time = FormatIso8601(time_value)
            data[key] = iso_time


def create_message_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add a new message to the back of the message queue.
    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    message_content = args["message_content"]
    queue_name = args["queue_name"]
    visibility_time_out = arg_to_number(args.get("visibility_time_out"))
    expiration = arg_to_number(args.get("expiration"))
    encode = argToBoolean(args.get("base64_encoding", False))

    message_content = encode_message(message_content) if encode else message_content

    top = ET.Element('QueueMessage')

    child = ET.SubElement(top, 'MessageText')
    child.text = message_content

    xml_data = ET.tostring(top, encoding='unicode')

    response = client.create_message_request(queue_name, xml_data, visibility_time_out, expiration)

    raw_response = parse_xml_response(xml_string_response=response, tag_path="QueueMessage")

    message_outputs = copy.deepcopy(raw_response)[0]

    date_values_to_iso(message_outputs, ['ExpirationTime', 'InsertionTime', 'TimeNextVisible'])

    outputs = {'name': queue_name, 'Message': message_outputs}

    readable_output = tableToMarkdown(f'{queue_name} Queue message:',
                                      message_outputs,
                                      headers=['MessageId', 'ExpirationTime',
                                               'InsertionTime', 'TimeNextVisible', 'PopReceipt'],
                                      headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageQueue.Queue',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=raw_response
    )

    return command_results


def get_messages_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves messages from the front of the queue.
    Retrieved messages will move to the end of the queue,
    and will be visible after the amount of time specified in the 'TimeNextVisible' param.
    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    limit = args.get('limit') or '1'
    queue_name = args["queue_name"]
    visibility_time_out = arg_to_number(args.get("visibility_time_out"))

    if int(limit) < 1 or int(limit) > 32:
        raise Exception('Invalid limit value. Minimum value is 1, maximum value is 32')

    response = client.get_messages_request(queue_name, limit, visibility_time_out)  # type: ignore

    raw_response = parse_xml_response(xml_string_response=response, tag_path="QueueMessage")

    message_outputs = copy.deepcopy(raw_response)

    for message in message_outputs:
        message['MessageText'] = decode_message(message['MessageText'])
        date_values_to_iso(message, ['ExpirationTime', 'InsertionTime', 'TimeNextVisible'])

    outputs = {'name': queue_name, 'Message': message_outputs}

    readable_output = tableToMarkdown(f'{queue_name} Queue messages:',
                                      message_outputs,
                                      headers=['MessageText', 'MessageId', 'PopReceipt', 'DequeueCount',
                                               'ExpirationTime', 'InsertionTime', 'TimeNextVisible'],
                                      headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageQueue.Queue',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=raw_response
    )

    return command_results


def peek_messages_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves messages from the front of the queue.
    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    limit = args.get('limit') or '1'
    queue_name = args["queue_name"]

    if int(limit) < 1 or int(limit) > 32:
        raise Exception('Invalid limit value. Minimum value is 1, maximum value is 32')

    response = client.peek_messages_request(limit, queue_name)

    raw_response = parse_xml_response(xml_string_response=response, tag_path="QueueMessage")

    message_outputs = copy.deepcopy(raw_response)

    for message in message_outputs:
        message['MessageText'] = decode_message(message['MessageText'])
        date_values_to_iso(message, ['ExpirationTime', 'InsertionTime'])

    outputs = {'name': queue_name, 'Message': message_outputs}

    readable_output = tableToMarkdown(f'{queue_name} Queue messages:',
                                      message_outputs,
                                      headers=['MessageText', 'MessageId', 'DequeueCount',
                                               'ExpirationTime', 'InsertionTime'],
                                      headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageQueue.Queue',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=raw_response
    )

    return command_results


def dequeue_message_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Dequeue message from the front of the queue.
    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: Readable output for XSOAR.
    """
    queue_name = args["queue_name"]

    response = client.get_messages_request(queue_name=queue_name)

    message_response = parse_xml_response(xml_string_response=response, tag_path="QueueMessage")

    if len(message_response) == 0:
        return CommandResults(readable_output=f'There are no messages in {queue_name} queue.')

    message_id = message_response[0]["MessageId"]
    pop_receipt = message_response[0]["PopReceipt"]

    client.delete_message_request(queue_name=queue_name, message_id=message_id, pop_receipt=pop_receipt)

    readable_output = f'Message in {queue_name} successfully deleted.'

    command_results = CommandResults(
        readable_output=readable_output
    )

    return command_results


def delete_message_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete message from the queue.
    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: Readable output for XSOAR.
    """
    queue_name = args["queue_name"]

    message_id = args["message_id"]
    pop_receipt = args["pop_receipt"]

    client.delete_message_request(queue_name=queue_name, message_id=message_id, pop_receipt=pop_receipt)

    readable_output = f'Message in {queue_name} successfully deleted.'

    command_results = CommandResults(
        readable_output=readable_output
    )

    return command_results


def update_message_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update message in the the queue.

    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: readable output for XSOAR.

    """
    message_content = args["message_content"]
    queue_name = args["queue_name"]
    message_id = args["message_id"]
    pop_receipt = args["pop_receipt"]
    encode = argToBoolean(args.get("base64_encoding", False))
    visibility_time_out = args["visibility_time_out"]

    message_content = encode_message(message_content) if encode else message_content

    top = ET.Element('QueueMessage')

    child = ET.SubElement(top, 'MessageText')
    child.text = message_content

    xml_data = ET.tostring(top, encoding='unicode')

    client.update_message_request(queue_name, xml_data, message_id, pop_receipt, visibility_time_out)

    readable_output = f'The message in {queue_name} successfully updated.'

    command_results = CommandResults(
        readable_output=readable_output
    )

    return command_results


def clear_messages_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete all messages from the queue.
    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: Readable output for XSOAR.
    """
    queue_name = args["queue_name"]

    client.clear_messages_request(queue_name=queue_name)

    readable_output = f'{queue_name} was cleared of messages successfully.'

    command_results = CommandResults(
        readable_output=readable_output
    )

    return command_results


def parse_incident(message: dict) -> dict:
    """
    Parse message to XSOAR Incident.
    Args:
        message (dict): Message item.

    Returns:
        dict: XSOAR Incident

    """
    time_headers = ['ExpirationTime', 'InsertionTime', 'TimeNextVisible']

    message['MessageText'] = decode_message(message['MessageText'])
    for header in time_headers:
        time_value = datetime.strptime(message.get(header), DATE_FORMAT)  # type: ignore
        iso_time = FormatIso8601(time_value) + 'Z'
        message[header] = iso_time

    incident = {}
    incident['name'] = "Azure Storage - Queue MessageId: " + message["MessageId"]
    incident['rawJSON'] = json.dumps(message)

    return incident


def fetch_incidents(client: Client, queue_name: str, max_fetch: str) -> None:
    """
    Fetch messages from the Queue.

    Args:
        client (Client): Azure Queue Storage API client.
        queue_name (str): Queue name.
        max_fetch (str): Maximum incidents for one fetch.

    """

    response = client.get_messages_request(queue_name=queue_name, limit=max_fetch)

    raw_response = parse_xml_response(xml_string_response=response, tag_path="QueueMessage")

    incidents = []

    for message in raw_response:
        message['queue_name'] = queue_name
        incidents.append(parse_incident(message))

    demisto.incidents(incidents)

    for message in raw_response:
        client.delete_message_request(queue_name=queue_name, message_id=message["MessageId"],
                                      pop_receipt=message["PopReceipt"])


def test_module(client: Client, max_fetch: str) -> None:
    """
    Tests API connectivity and authentication.
    Args:
        client (Client): Azure Queue Storage API client.
        max_fetch (str): Maximum incidents for one fetch.

    Returns:
        str : 'ok' if test passed, anything else will fail the test.

    """
    try:
        client.list_queues_request()
        max_fetch_int = int(max_fetch)
    except Exception as exception:
        if 'Error in API call' in str(exception):
            return return_results('Authorization Error: make sure API Credentials are correctly set')

        if 'Error Type' in str(exception):
            return return_results(
                'Verify that the storage account name is correct and that you have access to the server from your host.')

        if type(exception).__name__ == 'ValueError':
            return return_results('Invalid Maximum fetch value.')

        raise exception

    if max_fetch_int <= 0 or max_fetch_int > 32:
        return return_results('Invalid Maximum fetch value. Minimum value is 1, maximum value is 32')

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
    account_sas_token = params.get('credentials', {}).get('password')
    storage_account_name = params['credentials']['identifier']
    api_version = "2020-10-02"
    base_url = f'https://{storage_account_name}.queue.core.windows.net'
    managed_identities_client_id = get_azure_managed_identities_client_id(params)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client: Client = Client(base_url, verify_certificate, proxy, account_sas_token, storage_account_name,
                                api_version,
                                managed_identities_client_id)

        commands = {
            'azure-storage-queue-list': list_queues_command,
            'azure-storage-queue-create': create_queue_command,
            'azure-storage-queue-delete': delete_queue_command,
            'azure-storage-queue-message-create': create_message_command,
            'azure-storage-queue-message-get': get_messages_command,
            'azure-storage-queue-message-peek': peek_messages_command,
            'azure-storage-queue-message-dequeue': dequeue_message_command,
            'azure-storage-queue-message-update': update_message_command,
            'azure-storage-queue-message-delete': delete_message_command,
            'azure-storage-queue-message-clear': clear_messages_command
        }

        if command == 'test-module':
            test_module(client, params.get('max_fetch'))  # type: ignore
        elif command == 'fetch-incidents':
            fetch_incidents(client, params.get('queue_name'), params.get('max_fetch'))  # type: ignore
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


from MicrosoftAzureStorageApiModule import *  # noqa: E402

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
