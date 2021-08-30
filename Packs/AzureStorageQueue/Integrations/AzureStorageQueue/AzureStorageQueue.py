import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import base64
import copy
from requests import Response

DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'


class Client:
    """
    API Client
    """

    def __init__(self, server_url, verify, proxy, account_sas_token, storage_account_name, api_version):
        self.ms_client = MicrosoftStorageClient(server_url, verify, proxy, account_sas_token, storage_account_name,
                                                api_version)

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
                               visibility_time_out: int = None, time_to_live: int = None) -> str:
        """
        Add a new message to the back of the message queue.

        Args:
            queue_name (str): Queue name.
            xml_data (str): Request XML data.
            visibility_time_out (int): Specifies the new visibility timeout value.
            time_to_live (int): Specifies the time-to-live interval for the message, in seconds.

        Returns:
            str: API response from Azure.

        """

        params = assign_params(messagettl=time_to_live, visibilitytimeout=visibility_time_out)

        print(params)

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

    def peek_messages_request(self, limit: str, queue_name: str) -> Response:
        """
        Retrieves messages from the front of the queue.

        Args:
            limit (str): Number of messages to retrieve
            queue_name (str): Queue name.

        Returns:
            Response: API response from Azure.

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
    Args:
        xml_string_response (str): XML response.
        tag_path (str): XML target Tag.
        find_tag (bool): Indicates parse operation type.

    Returns:
        list: XML iterable element.

    """

    tree = ET.ElementTree(ET.fromstring(xml_string_response))

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
        except Exception as e:
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


def list_queues_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     List queues in Azure storage account.
    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    limit = args.get('limit', '50')
    prefix = args.get('prefix')

    page = arg_to_number(args.get('page', '1'))
    marker = ''
    readable_message = f'Queues List:\n Current page size: {limit}\n Showing page {page} out others that may exist'

    if page > 1:
        offset = int(limit) * (page - 1)
        response = client.list_queues_request(str(offset), prefix)
        tree = ET.ElementTree(ET.fromstring(response))
        root = tree.getroot()
        marker = root.findtext('NextMarker')

        if not marker:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='AzureStorageQueue.Queue',
                outputs=[],
                raw_response=[]
            )

    response = client.list_queues_request(limit, prefix, marker)

    xml_response = parse_xml_response(xml_string_response=response, tag_path="./Queues/Queue/Name", find_tag=True)

    raw_response = [{"Name": element.text} for element in xml_response]

    readable_output = tableToMarkdown(
        readable_message,
        raw_response,
        headers='Name'
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageQueue.Queue',
        outputs_key_field='Name',
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
    response = client.create_queue_request(queue_name)

    readable_output = f'Queue {queue_name} successfully created.' if response.status_code == 201 else f'Queue {queue_name} already exists.'

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
    time_to_live = arg_to_number(args.get("time_to_live"))
    encode = argToBoolean(args.get("base64_encoding", False))

    message_content = encode_message(message_content) if encode else message_content

    top = ET.Element('QueueMessage')

    child = ET.SubElement(top, 'MessageText')
    child.text = message_content

    xml_data = ET.tostring(top, encoding='unicode')

    response = client.create_message_request(queue_name, xml_data, visibility_time_out, time_to_live)

    raw_response = parse_xml_response(xml_string_response=response, tag_path="QueueMessage")

    outputs = copy.deepcopy(raw_response)[0]
    outputs['queue_name'] = queue_name

    time_headers = ['ExpirationTime', 'InsertionTime', 'TimeNextVisible']
    for header in time_headers:
        time_value = datetime.strptime(outputs.get(header), DATE_FORMAT)
        iso_time = FormatIso8601(time_value)
        outputs[header] = iso_time

    readable_output = tableToMarkdown(f'{queue_name} Queue message:',
                                      outputs,
                                      headers=['MessageId', 'ExpirationTime',
                                               'InsertionTime', 'TimeNextVisible', 'PopReceipt'],
                                      headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageQueue.Message',
        outputs_key_field=['queue_name', 'MessageId'],
        outputs=outputs,
        raw_response=raw_response
    )

    return command_results


def get_messages_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves messages from the front of the queue.
    Retrieved messages will move to the end of the queue,and will be visible after 'TimeNextVisible' param.
    Args:
        client (Client): Azure Queue Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    limit = args.get('limit', '1')
    queue_name = args["queue_name"]
    visibility_time_out = arg_to_number(args.get("visibility_time_out"))

    response = client.get_messages_request(queue_name, limit, visibility_time_out)

    raw_response = parse_xml_response(xml_string_response=response, tag_path="QueueMessage")

    outputs = copy.deepcopy(raw_response)

    time_headers = ['ExpirationTime', 'InsertionTime', 'TimeNextVisible']
    for message in outputs:
        message['queue_name'] = queue_name
        message['MessageText'] = decode_message(message['MessageText'])
        for header in time_headers:
            time_value = datetime.strptime(message.get(header), DATE_FORMAT)
            iso_time = FormatIso8601(time_value)
            message[header] = iso_time

    readable_output = tableToMarkdown(f'{queue_name} Queue messages:',
                                      outputs,
                                      headers=['MessageText', 'MessageId', 'PopReceipt', 'DequeueCount',
                                               'ExpirationTime', 'InsertionTime', 'TimeNextVisible'],
                                      headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageQueue.Message',
        outputs_key_field=['queue_name', 'MessageId'],
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
    limit = args.get('limit', '1')
    queue_name = args["queue_name"]

    response = client.peek_messages_request(limit, queue_name)

    raw_response = parse_xml_response(xml_string_response=response, tag_path="QueueMessage")

    outputs = copy.deepcopy(raw_response)

    time_headers = ['ExpirationTime', 'InsertionTime']
    for message in outputs:
        message['queue_name'] = queue_name
        message['MessageText'] = decode_message(message['MessageText'])
        for header in time_headers:
            time_value = datetime.strptime(message.get(header), DATE_FORMAT)
            iso_time = FormatIso8601(time_value)
            message[header] = iso_time

    readable_output = tableToMarkdown(f'{queue_name} Queue messages:',
                                      outputs,
                                      headers=['MessageText', 'MessageId', 'DequeueCount',
                                               'ExpirationTime', 'InsertionTime'],
                                      headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageQueue.Message',
        outputs_key_field=['queue_name', 'MessageId'],
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
        time_value = datetime.strptime(message.get(header), DATE_FORMAT)
        iso_time = FormatIso8601(time_value)
        message[header] = iso_time

    incident = {}
    incident['name'] = "Azure Storage - Queue MessageId: " + message["MessageId"]
    incident['rawJSON'] = json.dumps(message)

    return incident


def fetch_incidents(client: Client, queue_name: str, max_fetch: str) -> None:
    """
    Fetch messaged from the Queue.

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
        client.delete_message_request(queue_name=queue_name, message_id=message.get("MessageId"),
                                      pop_receipt=message.get("PopReceipt"))


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


def main() -> None:
    """
    Main function
    """
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    account_sas_token = params.get('account_sas_token')
    storage_account_name = params.get('storage_account_name')
    api_version = "2020-10-02"
    base_url = f'https://{storage_account_name}.queue.core.windows.net'

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(base_url, verify_certificate, proxy, account_sas_token, storage_account_name,
                                api_version)

        commands = {
            'azure-storage-queue-queue-list': list_queues_command,
            'azure-storage-queue-queue-create': create_queue_command,
            'azure-storage-queue-queue-delete': delete_queue_command,
            'azure-storage-queue-message-create': create_message_command,
            'azure-storage-queue-message-get': get_messages_command,
            'azure-storage-queue-message-peek': peek_messages_command,
            'azure-storage-queue-message-dequeue': dequeue_message_command,
            'azure-storage-queue-message-update': update_message_command,
            'azure-storage-queue-message-delete': delete_message_command,
            'azure-storage-queue-message-clear': clear_messages_command
        }

        if command == 'test-module':
            test_module(client, params.get('max_fetch'))
        if command == 'fetch-incidents':
            fetch_incidents(client, params.get('queue_name'), params.get('max_fetch'))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


from MicrosoftAzureStorageApiModule import *  # noqa: E402

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
