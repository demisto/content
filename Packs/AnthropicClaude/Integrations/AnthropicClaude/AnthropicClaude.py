import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import urllib3
import parse_emails

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
ANTHROPIC_VERSION = '2023-06-01'
EML_FILE_SUFFIX = '.eml'

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
{}
'''
{}
'''

Highlight potential security risks, and explain the implications of such risks.
Make you answer very concise and easily readable, with references to the email body if there are, otherwise do not refer to \
hypothetical problems.
"""

CREATE_SOC_EMAIL_TEMPLATE_PROMPT = """
Based on the details provided in our conversation and any specific instructions you have been given,
create a professional email template suitable for a Security Operations Center (SOC).
The template should be adaptable, clearly structured, and include placeholders for specific incident details,
recommendations for action, and any necessary escalation points.
Please ensure the tone is appropriate for communication within a cybersecurity context.
{}
"""


class ArgAndParamNames:
    MODEL = "model"
    MESSAGE = "message"
    RESET_CONVERSATION_HISTORY = "reset_conversation_history"
    ENTRY_ID = "entry_id"
    ADDITIONAL_INSTRUCTIONS = "additional_instructions"
    MAX_TOKENS = "max_tokens"
    TEMPERATURE = "temperature"
    TOP_P = "top_p"


class Roles:
    ASSISTANT = 'assistant'
    USER = 'user'


class EmailParts:
    HEADERS = 'headers'
    BODY = 'body'


''' CLIENT CLASS '''


class AnthropicClient(BaseClient):
    MESSAGES_ENDPOINT = 'v1/messages'

    def __init__(self, url: str, api_key: str, model: str, proxy: bool, verify: bool):
        super().__init__(base_url=url, proxy=proxy, verify=verify)

        self.api_key = api_key
        self.model = model
        self.headers = {
            'x-api-key': self.api_key,
            'anthropic-version': ANTHROPIC_VERSION,
            'Content-Type': 'application/json'
        }

    def get_messages(self,
                     chat_context: List[dict[str, str]],
                     completion_params: dict[str, str | None]) -> dict[str, Any]:
        """ Gets the response to a messages request using the Anthropic API. """

        # Convert chat context to Anthropic format
        messages = []
        for msg in chat_context:
            if msg['role'] in [Roles.USER, Roles.ASSISTANT]:
                messages.append({
                    'role': msg['role'],
                    'content': msg['content']
                })

        options: Dict[str, Any] = {
            ArgAndParamNames.MODEL: self.model,
            'messages': messages,
            # Anthropic API requires max_tokens to be specified, default to 1024 if not provided
            ArgAndParamNames.MAX_TOKENS: 1024
        }

        max_tokens = completion_params.get(ArgAndParamNames.MAX_TOKENS, None)
        if max_tokens:
            try:
                # Ensure max_tokens is a valid integer
                options[ArgAndParamNames.MAX_TOKENS] = int(max_tokens)
            except (ValueError, TypeError):
                # Use default if conversion fails
                demisto.debug(f"Could not convert max_tokens value '{max_tokens}' to integer, using default value 1024")
                options[ArgAndParamNames.MAX_TOKENS] = 1024

        temperature = completion_params.get(ArgAndParamNames.TEMPERATURE, None)
        if temperature:
            options[ArgAndParamNames.TEMPERATURE] = float(temperature)

        top_p = completion_params.get(ArgAndParamNames.TOP_P, None)
        if top_p:
            options[ArgAndParamNames.TOP_P] = float(top_p)

        demisto.debug(f"anthropic-claude Using options for message: {options=}")
        return self._http_request(method='POST',
                                  url_suffix=AnthropicClient.MESSAGES_ENDPOINT,
                                  json_data=options,
                                  headers=self.headers)


''' HELPER FUNCTIONS '''


def conversation_to_chat_context(conversation: List[dict[str, str]]) -> List[dict[str, str]]:
    """ A 'Conversation' list that was retrieved from 'demisto.context()' is formatted to be more intuitive for XSOAR users
    and is formatted as: [
                            {'user': '<USER_MESSAGE_0>', 'assistant': '<ASSISTANT_MESSAGE_0>'},
                            {'user': '<USER_MESSAGE_1>', 'assistant': '<ASSISTANT_MESSAGE_1>'},
                             ...
                        ].

    The conversational format that is supported by the Anthropic Messages API is a sequence of messages,
     labeled with roles:
        [
            {'role': 'user', 'content': '<USER_MESSAGE_0>'},
            {'role': 'assistant', 'content': '<ASSISTANT_MESSAGE_0>'},
            {'role': 'user', 'content': '<USER_MESSAGE_1>'},
            {'role': 'assistant', 'content': '<ASSISTANT_MESSAGE_1>'},
            ...
        ]

    Therefore, it has to be transformed.
     """

    chat_context = []
    for element in conversation:
        demisto.debug(f'anthropic-claude conversation_to_chat_context reading {element=} from conversation')
        chat_context.append({'role': Roles.USER, 'content': element.get(Roles.USER, '')})
        chat_context.append({'role': Roles.ASSISTANT, 'content': element.get(Roles.ASSISTANT, '')})

    return chat_context


def get_chat_context(reset_conversation_history: bool, message: str) -> List[dict[str, str]]:
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
    conversation = demisto.context().get('AnthropicClaude', {}).get('Conversation')

    if reset_conversation_history or not conversation:
        conversation = []
        demisto.debug('anthropic-claude get_chat_context conversation history reset or initialized as empty.')
    else:
        demisto.debug(f'anthropic-claude get_chat_context using conversation history from context:'
                      f' [type(conversation)={type(conversation)}]{conversation=}')

    # Create the chat context which is suitable with the required format for a 'messages' request.
    chat_context = conversation_to_chat_context(conversation)
    chat_context.append({"role": Roles.USER, "content": message})
    demisto.debug(f'anthropic-claude get_chat_context updated chat_context with new message: {chat_context=}')
    return chat_context


def extract_assistant_message(response: dict[str, Any]) -> str:
    """
        Extracts the assistant message from a response.
        Returns:
        The assistant message as a string.
    """
    if not response:
        return_error("Could not retrieve message from response.")

    content = response.get('content', [])
    if not content:
        return_error("Could not retrieve content from response.")

    message_content = ""
    for item in content:
        if item.get('type') == 'text':
            message_content += item.get('text', '')

    if not message_content:
        return_error("Could not retrieve text from response content.")

    return message_content


def get_email_parts(entry_id: str) -> tuple[List[dict[str, str]] | None, str | None, str | None, str | None]:
    """
        Extracts and parses the headers, text body, and HTML body from an .eml file identified by a given entry ID.

        Args:
        - entry_id (str): The unique identifier for the uploaded .eml file in the war room.

        Returns:
        - tuple[List[Dict[str, str]] | None, str | None, str | None]: A tuple containing three elements:
            - headers (List[Dict[str, str]] | None): A list of dictionaries where each dictionary represents an email header.
            - text_body (str | None): The plain text body of the email, if available.
            - html_body (str | None): The HTML body of the email, if available.
            - file_name (str | None): The name of the .eml file in the war room.
    """
    if not entry_id:
        DemistoException("Provide an entryId of an uploaded '.eml' file.")

    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    file_name = get_file_path_res["name"]

    if not file_name.endswith(EML_FILE_PREFIX):
        DemistoException("Provided 'entry_id' does not point to a valid '.eml' file.")

    email_parser = parse_emails.EmailParser(file_path=file_path)
    email_parser.parse()

    headers, text_body, html_body = (email_parser.parsed_email.get('Headers', None),
                                     email_parser.parsed_email.get('Text', None),
                                     email_parser.parsed_email.get('HTML', None))
    return headers, text_body, html_body, file_name


def check_email_part(email_part: str, client: AnthropicClient, args: dict[str, Any]) -> CommandResults:
    """
        Checks email parts (headers/body) for potential security issues using predefined prompts
        ('CHECK_EMAIL_HEADERS_PROMPT', 'CHECK_EMAIL_BODY_PROMPT') that are sent to the Claude model.
    """
    entry_id: str = args.get(ArgAndParamNames.ENTRY_ID, '')
    email_headers, email_text_body, email_html_body, file_name = get_email_parts(entry_id)
    additional_instructions = (f'anthropic-claude check_email_part '
                               f'Additional instructions: {ArgAndParamNames.ADDITIONAL_INSTRUCTIONS}\n') \
        if args.get(ArgAndParamNames.ADDITIONAL_INSTRUCTIONS, "") else ''

    if email_part == EmailParts.HEADERS:
        demisto.debug(f'anthropic-claude checking email headers: {email_headers=}')
        if email_headers:
            email_headers_formatted = {
                header['name']: header['value']
                for header in email_headers
                if 'name' in header and 'value' in header
            }
            readable_input = tableToMarkdown(name=f'{file_name} headers:', t=email_headers_formatted, sort_headers=False)
            check_email_part_message = CHECK_EMAIL_HEADERS_PROMPT.format(additional_instructions, readable_input)

        else:
            raise DemistoException("'parse_emails' did not extract any email headers from the provided file..")
    elif email_part == EmailParts.BODY:
        demisto.debug(f'anthropic-claude checking email body: {email_text_body=} {email_html_body=}')

        if not email_text_body and not email_html_body:
            raise DemistoException("'email_parser' did not extract any email body from the provided file.")

        email_text_body = email_text_body if email_text_body else ''
        email_html_body = email_html_body if email_html_body else ''

        email_body = {'Body/Text': email_text_body, 'HTML/Text': email_html_body}

        readable_input = tableToMarkdown(name=f'{file_name} body:', t=email_body, sort_headers=False)
        check_email_part_message = CHECK_EMAIL_BODY_PROMPT.format(additional_instructions, readable_input)
    else:
        raise DemistoException("Invalid email part to check provided.")

    demisto.debug(f'anthropic-claude check_email_part {check_email_part_message=}')

    # Starting a new conversation as of a new topic discussed.
    args.update({ArgAndParamNames.RESET_CONVERSATION_HISTORY: 'yes', ArgAndParamNames.MESSAGE: check_email_part_message})
    send_message_command_results, response = send_message_command(client, args)

    # Displaying the analyzed email part to the war room and setting the context for the email checking response
    # prior to returning the 'send-message-command' results and the entire conversation to the context.
    return_results(
        CommandResults(readable_output=readable_input,
                       outputs_prefix='AnthropicClaude.Email' + email_part.capitalize(),
                       outputs={
                           'Email' + email_part.capitalize(): readable_input,
                           'Response': response
                       },
                       replace_existing=True
                       )
    )
    return send_message_command_results


''' COMMAND FUNCTIONS '''


def test_module(client: AnthropicClient, params: dict) -> str:
    """Tests API connectivity and authentication along with model compatability with 'Messages' endpoint.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``AnthropicClient``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    message = ''
    try:
        chat_message = {"role": "user", "content": "test"}
        completion_params = {
            ArgAndParamNames.MAX_TOKENS: int(params.get("max_tokens", 1024)),
            ArgAndParamNames.TEMPERATURE: params.get(ArgAndParamNames.TEMPERATURE, None),
            ArgAndParamNames.TOP_P: params.get(ArgAndParamNames.TOP_P, None)
        }
        client.get_messages(chat_context=[chat_message], completion_params=completion_params)
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def send_message_command(client: AnthropicClient,
                         args: dict[str, Any]) -> tuple[CommandResults, dict[str, Any]]:
    """
        Sending a message with conversation context to an Anthropic Claude model and retrieving the generated response.
    """
    message = args.get(ArgAndParamNames.MESSAGE, "")
    if not message:
        raise ValueError('Message not provided')

    completion_params = {
        ArgAndParamNames.MAX_TOKENS: int(args.get(ArgAndParamNames.MAX_TOKENS, 1024)),
        ArgAndParamNames.TEMPERATURE: args.get(ArgAndParamNames.TEMPERATURE, None),
        ArgAndParamNames.TOP_P: args.get(ArgAndParamNames.TOP_P, None)
    }

    reset_conversation_history = args.get(ArgAndParamNames.RESET_CONVERSATION_HISTORY, '') == 'yes'
    chat_context = get_chat_context(reset_conversation_history, message)
    demisto.debug(f'anthropic-claude send_message_command {chat_context=}, {completion_params=}')

    response = client.get_messages(chat_context=chat_context, completion_params=completion_params)
    demisto.debug(f'anthropic-claude send_message_command {response=}')

    assistant_message = extract_assistant_message(response)
    conversation_step = [{Roles.USER: message, Roles.ASSISTANT: assistant_message}]

    usage: dict[str, str] = response.get('usage', {})

    readable_output = assistant_message + '\n' + tableToMarkdown(name=f'{response.get(ArgAndParamNames.MODEL, "")} response:',
                                                                 sort_headers=False,
                                                                 t={
                                                                     'Input tokens': usage.get('input_tokens', ''),
                                                                     'Output tokens': usage.get('output_tokens', ''),
                                                                     'Context messages': str(len(chat_context))
                                                                 }
                                                                 )
    return CommandResults(
        outputs_prefix='AnthropicClaude.Conversation',
        outputs=conversation_step,
        replace_existing=reset_conversation_history,
        readable_output=readable_output
    ), response


def check_email_headers_command(client: AnthropicClient, args: dict[str, Any]) -> CommandResults:
    return check_email_part(EmailParts.HEADERS, client, args)


def check_email_body_command(client: AnthropicClient, args: dict[str, Any]) -> CommandResults:
    return check_email_part(EmailParts.BODY, client, args)


def create_soc_email_template_command(client: AnthropicClient, args: dict[str, Any]) -> CommandResults:
    additional_instructions = f'Additional instructions: {args.get(ArgAndParamNames.ADDITIONAL_INSTRUCTIONS)}\n'\
        if args.get(ArgAndParamNames.ADDITIONAL_INSTRUCTIONS, "") else ''
    create_soc_email_template_message = CREATE_SOC_EMAIL_TEMPLATE_PROMPT.format(additional_instructions)
    args.update({ArgAndParamNames.MESSAGE: create_soc_email_template_message})
    send_message_command_results, response = send_message_command(client, args)
    # Setting the SOCEmailTemplate context prior to returning the 'send-message-command' results
    # and setting the entire conversation in the context.
    return_results(
        CommandResults(
            outputs_prefix='AnthropicClaude.SocEmailTemplate',
            outputs={'Response': response},
            replace_existing=True
        )
    )
    return send_message_command_results


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('apikey', {}).get('password')
    # If a model name was provided within the free text box, it will override the selected one from the model selection box.
    # The provided model will be tested for compatability within the test module.
    model = params.get('model-freetext') if params.get('model-freetext') else params.get('model-select')

    args.update({key: value for key, value in params.items() if key not in args and value is not None})

    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    try:
        client = AnthropicClient(
            url=params.get('url'),
            api_key=api_key,
            model=model,
            verify=verify,
            proxy=proxy
        )

        if command == 'test-module':
            return_results(test_module(client=client, params=params))

        elif command == "claude-send-message":
            return_results(send_message_command(client=client, args=args)[0])

        elif command == "claude-check-email-header":
            return_results(check_email_headers_command(client=client, args=args))

        elif command == "claude-check-email-body":
            return_results(check_email_body_command(client=client, args=args))

        elif command == "claude-create-soc-email-template":
            return_results(create_soc_email_template_command(client=client, args=args))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
