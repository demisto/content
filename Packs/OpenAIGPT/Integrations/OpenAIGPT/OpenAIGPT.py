import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
import urllib3
from typing import Dict
import parse_emails
# from Packs.CIRCL.Integrations.CirclCVESearch.CirclCVESearch import Client as CveSearchClient, valid_cve_id_format

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

CIRCLCVE_BASE_URL = 'https://cve.circl.lu/api'

EML_FILE_PREFIX = '.eml'

CHECK_EMAIL_HEADERS_PROMPT = """
I have a set of email headers.
Analyze these headers for any potential security issues such as spoofing, phishing attempts, or other malicious activity.
Please identify any suspicious fields, explain why they might be concerning, and suggest any further actions that could be taken \
to investigate or mitigate these issues.
Additional instructions: {}

'''
{}
'''

Please, review each header, highlighting any red flags and explaining the potential risks associated with them.
Make you answer very concise and easily readable, with references to the email headers if there are, otherwise do not refer to \
hypothetical problems.
"""

CHECK_EMAIL_BODY_PROMPT = """
I have this email body that I suspect may contain security risks such as phishing links, suspicious attachments,
or signs of social engineering. Please analyze the content of this email body, identify any elements that may pose security 
threats, and explain why these elements are concerning. Also, suggest any steps that could be taken to further verify these risks
or protect against these threats. 
Additional instructions: {}

'''
{}
'''

Highlight potential security risks, and explain the implications of such risks.
Make you answer very concise and easily readable, with references to the email body if there are, otherwise do not refer to \
hypothetical problems.
"""


class Roles:
    ASSISTANT = 'assistant'
    USER = 'user'


class EmailParts:
    HEADERS = 'headers'
    BODY = 'body'


''' CLIENT CLASS '''


class OpenAiClient(BaseClient):
    CHAT_COMPLETIONS_URL = 'https://api.openai.com/v1/chat/completions'

    def __init__(self, api_key: str, model: str, proxy: bool, verify: bool):
        super().__init__(base_url=OpenAiClient.CHAT_COMPLETIONS_URL, proxy=proxy, verify=verify)
        self.api_key = api_key
        self.model = model
        self.headers = {'Authorization': f'Bearer {self.api_key}', 'Content-Type': 'application/json'}

    def get_chat_completions(self,
                             chat_context: List[Dict[str, str]],
                             completion_params: Dict[str, str | None]) -> Dict[str, any]:
        """ Gets the response to a chat_completions request using the OpenAI API. """

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
    Retrieves the existing chat conversation history from the incident context, if exists.
    If `reset_conversation_history` is True, or if no conversation history exists, it initializes a new conversation list
    with the given message and returns it.

    Args:
        reset_conversation_history (bool): Flag to determine whether to reset the existing conversation history.
        message (str): The new message to be added to the conversation.

    Returns:
        List[Dict[str, str]]: The updated conversation history with the new message appended.
    """
    # Retrieve or initialize conversation history based on the context and reset flag
    conversation = demisto.context().get('OpenAIGPT', {}).get('Conversation')
    if reset_conversation_history or not conversation:
        conversation = []
        demisto.debug('openai-gpt send_message - conversation history reset or initialized as empty.')
    else:
        demisto.debug(f'openai-gpt send_message using conversation history from context:'
                      f' [type(conversation)={type(conversation)}]{conversation=}')

    # Append the new user message to the conversation history
    conversation.append({"role": Roles.USER, "content": message})
    demisto.debug(f'Updated conversation with new message: {conversation=}')

    return conversation


def extract_assistant_message(response: Dict[str, Any], conversation: List[Dict[str, str]]) -> str:
    """
        Extracts the assistant message from a response and updates the conversation history.
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


def get_email_parts(entry_id: str) -> tuple[List[Dict[str, str]] | None, str | None, str | None]:
    """
        Extracts and parses the headers, text body, and HTML body from an .eml file identified by a given entry ID.

        Args:
        - entry_id (str): The unique identifier for the uploaded .eml file in the war room.

        Returns:
        - tuple[List[Dict[str, str]] | None, str | None, str | None]: A tuple containing three elements:
            - headers (List[Dict[str, str]] | None): A list of dictionaries where each dictionary represents an email header.
            - text_body (str | None): The plain text body of the email, if available.
            - html_body (str | None): The HTML body of the email, if available.
    """
    if not entry_id:
        return_error("Provide an entryId of an uploaded '.eml' file.")

    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    file_name = get_file_path_res["name"]

    if not file_name.endswith(EML_FILE_PREFIX):
        return_error("Provided 'entryId' does not point to a valid '.eml' file.")

    email_parser = parse_emails.EmailParser(file_path=file_path)
    email_parser.parse()

    headers, text_body, html_body = (email_parser.parsed_email.get('Headers', None),
                                     email_parser.parsed_email.get('Text', None),
                                     email_parser.parsed_email.get('HTML', None))
    return headers, text_body, html_body


def check_email_part(email_part: str, client: OpenAiClient, args: Dict[str, Any]) -> CommandResults:
    """
        Checks email parts (headers/body) for potential security issues using predefined prompts
        ('CHECK_EMAIL_HEADERS_PROMPT', 'CHECK_EMAIL_BODY_PROMPT') that are sent to the GPT model.
    """
    entry_id: str | None = args.get('entryId', None)
    email_headers, email_text_body, email_html_body = get_email_parts(entry_id)
    additional_instructions = args.get('additionalInstructions', '')

    if email_part == EmailParts.HEADERS:
        demisto.debug(f'openai-gpt checking email headers: {email_headers=}')
        if email_headers:
            email_headers_formatted = []
            for header in email_headers:
                # Each header is represented as follows: {'name': 'From', 'value': 'Example <example@example.com>'},
                # therefore we want to combine them into a formatted string in order to reduce token's usage in prompts.
                header_formatted = ': '.join(header.values())
                email_headers_formatted.append(header_formatted)

            readable_input = '\n'.join(email_headers_formatted)
            check_email_part_message = CHECK_EMAIL_HEADERS_PROMPT.format(additional_instructions, readable_input)

        else:
            raise DemistoException("'parse_emails' did not extract any email headers from the provided file..")
    elif email_part == EmailParts.BODY:
        demisto.debug(f'openai-gpt checking email body: {email_text_body=} {email_html_body=}')

        if not email_text_body and not email_html_body:
            raise DemistoException("'email_parser' did not extract any email body from the provided file.")

        email_text_body = f'Body/Text: {email_text_body}' if email_text_body else ''
        email_html_body = f'HTML/Text: {email_html_body}' if email_html_body else ''

        readable_input = '\n'.join([email_text_body, email_html_body])
        check_email_part_message = CHECK_EMAIL_BODY_PROMPT.format(additional_instructions, readable_input)
    else:
        raise DemistoException("Invalid email part to check provided.")

    # Starting a new conversation as of a new topic discussed.
    args.update({'reset_conversation_history': True, 'message': check_email_part_message})

    # Displaying the analyzed email part to the war room.
    return_results(readable_input)
    return send_message_command(client, args)


''' COMMAND FUNCTIONS '''


def test_module(client: OpenAiClient, params: dict) -> str:
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
        completion_params = {
            'max_tokens': params.get('max_tokens', None),
            'temperature': params.get('temperature', None),
            'top_p': params.get('top_p', None)
        }
        client.get_chat_completions(chat_context=[chat_message], completion_params=completion_params)
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def send_message_command(client: OpenAiClient, args: Dict[str, Any]) -> CommandResults:
    """
        Sending a message with conversation context to an OpenAI GPT model and retrieves the generated response.
    """
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
    demisto.debug(f'openai-gpt get_chat_completions for: {conversation=} and {completion_params=}')

    response = client.get_chat_completions(chat_context=conversation, completion_params=completion_params)
    demisto.debug(f'openai-gpt get_chat_completions {response=}')
    # Also updating the conversation history with the extracted message from the response.
    assistant_message = extract_assistant_message(response, conversation)

    usage = response.get('usage', {})
    verbose_message = (f"Model: {response.get('model', '')} "
                       f"Usage: prompt-tokens={usage.get('prompt_tokens', '')}, "
                       f"completion-tokens={usage.get('completion_tokens', '')}, "
                       f"total-tokens={usage.get('total_tokens', '')}")

    readable_output = assistant_message
    readable_output += f"\n\n{verbose_message}" if args.get('verbose', False) else ''
    return CommandResults(
        outputs_prefix='OpenAIGPT.Conversation',
        outputs=conversation,
        replace_existing=True,
        readable_output=readable_output
    )


def check_email_headers_command(client: OpenAiClient, args: Dict[str, Any]) -> CommandResults:
    return check_email_part(EmailParts.HEADERS, client, args)


def check_email_body_command(client: OpenAiClient, args: Dict[str, Any]) -> CommandResults:
    return check_email_part(EmailParts.BODY, client, args)


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
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

    # Using instance params for model configuration, if command args were not provided.
    if not args.get('max_tokens', None) and params.get('max_tokens', None):
        args['max_tokens'] = params.get('max_tokens')
    if not args.get('temperature', None) and params.get('temperature', None):
        args['temperature'] = params.get('temperature')
    if not args.get('top_p', None) and params.get('top_p', False):
        args['top_p'] = params.get('top_p')

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
            return_results(test_module(client=client, params=params))

        elif command == "gpt-send-message":
            return_results(send_message_command(client=client, args=args))

        elif command == "gpt-check-email-header":
            results = check_email_headers_command(client=client, args=args)
            return_results(results)

        elif command == "gpt-check-email-body":
            return_results(check_email_body_command(client=client, args=args))

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
