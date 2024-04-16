import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
import urllib3
from typing import Dict
from enum import Enum

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class Roles:
    ASSISTANT = 'assistant'
    USER = 'user'


''' CLIENT CLASS '''


class OpenAiClient(BaseClient):
    CHAT_COMPLETIONS_URL = 'https://api.openai.com/v1/chat/completions'
    DEFAULT_TEMPERATURE = 1
    DEFAULT_TOP_P = 1

    def __init__(self, api_key: str, model: str, proxy: bool, verify: bool):
        super().__init__(base_url=OpenAiClient.CHAT_COMPLETIONS_URL, proxy=proxy, verify=verify)
        self.api_key = api_key
        self.model = model
        self.headers = {'Authorization': f'Bearer {self.api_key}', 'Content-Type': 'application/json'}

    def get_chat_completions(self,
                             chat_context: List[Dict[str, str]],
                             completion_params: Dict[str, str | None]) -> Dict[str, any]:
        """ """
        options = {'model': self.model}
        max_tokens = completion_params.get('max_tokens', None)
        if max_tokens:
            options['max_tokens'] = int(max_tokens)

        temperature = completion_params.get('temperature', None)
        if temperature:
            options['temperature'] = float(temperature)

        top_p = completion_params.get('top_p', None)
        if top_p:
            options['top_p'] = float(top_p)

        options['messages'] = chat_context
        demisto.debug(f"openai-gpt Using options for chat completion: {options=}")
        return self._http_request(method='POST',
                                  full_url=OpenAiClient.CHAT_COMPLETIONS_URL,
                                  json_data=options,
                                  headers=self.headers)


''' HELPER FUNCTIONS '''


def get_updated_conversation(reset_conversation_history: bool, message: str) -> List[Dict[str, str]]:
    """
    Retrieve and update the chat conversation history.

    This function retrieves the existing chat conversation history from the incident context.
    If `reset_conversation_history` is True, or if no conversation history exists, it initializes a new conversation list.
    The function then appends the new message to this conversation history. It is important to note that this
    function does not write the updated conversation history back to the incident context; it only returns it.

    Parameters:
        reset_conversation_history (bool): Flag to determine whether to reset the existing conversation history.
        message (str): The new message to be added to the conversation.

    Returns:
        List[Dict[str, str]]: The updated conversation history with the new message appended.
    """
    # Retrieve or initialize conversation history based on the context and reset flag
    conversation = demisto.context().get('OpenAIGPT', {}).get('Conversation')
    demisto.debug(
        f'openai-gpt send_message using conversation history from context: [type(conversation)={type(conversation)}]{conversation=}')

    if reset_conversation_history or not conversation:
        conversation = []
        demisto.debug('openai-gpt send_message - Conversation history reset or initialized as empty.')

    # Append the new user message to the conversation history
    conversation.append({"role": Roles.USER, "content": message})
    demisto.debug(f'Updated conversation with new message: {conversation=}')

    return conversation


def extract_assistant_message(response: Dict[str, Any], conversation: List[Dict[str, str]]) -> str:
    """Extracts the assistant message from a response and updates the conversation history.
        Returns:
        The assistant message as a string.
    """

    choices: list = response.get('choices', [])
    if not choices:
        return_error("Could not retrieve message from response.")

    message = choices[0].get('message', {})
    if not message:
        return_error("Could not retrieve message from response.")

    # Updating the conversation with the structured assistant message.
    conversation.append(message)

    response_content = message.get('content', '')
    if not response_content:
        return_error("Could not retrieve message from response.")

    return response_content


def get_email_parts(entry_id: str) -> Tuple[Dict[str, str], str]:
    if not entry_id:
        return_error("Provide an entryId of an uploaded '.eml' file.")

    file_name, file_content = get_file_by_entry_id(entry_id)
    file_content: str
    file_name: str

    if not file_name.endswith(EML_FILE_PREFIX):
        return_error("Provided 'entryId' does not point to a valid '.eml' file.")

    return parse_email(file_content)


def construct_prompt(new_message: str, conversation_context=None, rag_data=""):
    if not conversation_context:
        conversation_context = []
    # TODO - implement this


''' COMMAND FUNCTIONS '''


def test_module(client: OpenAiClient) -> str:
    """Tests API connectivity and authentication along with model compatability with 'Chat Completions' endpoint.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``OpenAiClient``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    message = ''
    try:
        chat_message = {"role": "user", "content": ""}
        client.get_chat_completions(chat_context=[chat_message], completion_params={})
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def send_message_command(client: OpenAiClient, args: Dict[str, Any]) -> CommandResults:
    message = args.get('message', "")
    if not message:
        raise ValueError('Message not provided')

    reset_conversation_history = args.get('reset_conversation_history', False)
    conversation = get_updated_conversation(reset_conversation_history, message)

    completion_params = {
        'max_tokens': args.get('max_tokens', None),
        'temperature': args.get('temperature', None),
        'top_p': args.get('top_p', None)
    }
    demisto.debug(f'openai-gpt getting chat completions for: {conversation=} and {completion_params=}')

    response = client.get_chat_completions(chat_context=conversation, completion_params=completion_params)
    # Also updating the conversation history with the extracted message from the response.
    assistant_message = extract_assistant_message(response, conversation)
    return CommandResults(
        outputs_prefix='OpenAIGPT.Conversation',
        outputs=conversation,
        readable_output=assistant_message
    )


def check_email_header_command(client: OpenAiClient, args: Dict[str, Any]) -> CommandResults:
    entry_id: str | None = args.get('entryId', None)
    email_headers, _ = get_email_parts(entry_id)
    demisto.debug(f'openai-gpt checking email headers: {email_headers=}')
    return CommandResults(
        outputs_prefix='OpenAIGPT.Email.Headers',
        outputs=email_headers,
        readable_output=str(email_headers)
    )
    # # 3 - Construct the prompt
    # prompt = ""
    # # Starting a new conversation as of a new topic discussed.
    # args.update({'reset_conversation_history': True, 'message': prompt})
    # return send_message_command(client, args)


def check_email_body_command(client: OpenAiClient, args: Dict[str, Any]) -> CommandResults:
    entry_id: str | None = args.get('entryId', None)
    _, email_body = get_email_parts(entry_id)
    demisto.debug(f'openai-gpt checking email body: {email_body=}')
    return CommandResults(
        outputs_prefix='OpenAIGPT.Email.Body',
        outputs=email_body,
        readable_output=email_body
    )
    # # 3 - Construct the prompt
    # prompt = ""
    # # Starting a new conversation as of a new topic discussed.
    # args.update({'reset_conversation_history': True, 'message': prompt})
    # return send_message_command(client, args)


# def get_cve_info_command(client: OpenAiClient, args: Dict[str, Any]) -> CommandResults:
#     cve = args.get('CVE', None)
#     if not cve:
#         raise ValueError('CVE not specified')
#
#     # TODO - RAG CVE Data
#     # TODO - construct prompt
#     # TODO - client.getChatCompletion(prompt)
#     # TODO - conversation =
#     # TODO - answer =
#
#     return CommandResults(
#         outputs_prefix='OpenAIGPT',
#         outputs_key_field='Conversation',
#         outputs=result,
#     )
#
#
# def check_email_header(client: OpenAiClient, args: Dict[str, Any]) -> CommandResults:
#     pass
#
#
# def check_email_body(client: OpenAiClient, args: Dict[str, Any]) -> CommandResults:
#     pass


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('api_key')
    # If a model name was provided within the free text box, it will override the selected one from the model selection box.
    # The provided model will be tested for compatability within the test module.
    model = params.get('model-freetext') if params.get('model-freetext') else params.get('model-select')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    try:
        client = OpenAiClient(
            api_key=api_key,
            model=model,
            verify=verify,
            proxy=proxy
        )

        if command == 'test-module':
            return_results(test_module(client))

        elif command == "gpt-send-message":
            return_results(send_message_command(client=client, args=args))

        # elif command == "gpt-get-cve-info":
        #     return_results(get_cve_info_command(client=client, args=args))
        #
        elif command == "gpt-check-email-header":
            return_results(check_email_header_command(client=client, args=args))

        elif command == "gpt-check-email-body":
            return_results(check_email_body_command(client=client, args=args))

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
