import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401



import json
import urllib3


urllib3.disable_warnings()


''' CLIENT CLASS '''

MAX_TOKEN = 20

class Client(BaseClient):
    """ Client class to interact with the OpenAI ChatGPT
    """

    def __init__(self, api_key: str, base_url: str, url_suffix: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_key = api_key
        self.base_url = base_url
        self.url_suffix = url_suffix
        self.headers = {'Authorization': f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def chatgpt(self, options):
        return self._http_request(method='POST', url_suffix=self.url_suffix, json_data=options, headers=self.headers)


''' COMMAND FUNCTIONS '''


def test_module(client: Client, options: dict) -> str:
    """
    Tests API connectivity and authentication'
    Returning 'ok' indicates that connection to the service is successful.
    Raises exceptions if something goes wrong.
    """
    response = client.chatgpt(options)
    status = ''
    try:
        if response:
            status = 'ok'
            return status
    except Exception as e:
        exception_text = str(e).lower()
        if 'forbidden' in exception_text or 'authorization' in exception_text:
            status = 'Authorization Error: make sure API Key is correctly set'
            return status
        else:
            raise e

    return status


def chatgpt_send_prompt_command(client: Client, options: dict) -> CommandResults:
    """
    Command to send prompts to OpenAI ChatGPT API
    and receive a response converted into json then
    returned to Output function to convert it to markdown table

    :type client: ``Client``
    """

    chatgpt_response = client.chatgpt(options)

    return chatgpt_output(chatgpt_response)


def chatgpt_output(response) -> CommandResults:
    """
    Convert response from ChatGPT to a human readable format in markdown table

    :return: CommandResults return output of ChatGPT response
    :rtype: ``CommandResults``
    """
    if response and isinstance(response, dict):
        rep = json.dumps(response)
        repJSON = json.loads(rep)
        model = repJSON.get('model')
        createdTime = repJSON.get('created')
        id = repJSON.get('id')
        promptTokens = repJSON.get('usage', {}).get('prompt_tokens')
        completionTokens = repJSON.get('usage', {}).get('completion_tokens')
        totalTokens = repJSON.get('usage', {}).get('total_tokens')
        if "gpt-4" in model or "gpt-3" in model:
            choices = repJSON.get('choices', [])[0].get('message', {}).get('content', "").strip('\n')
        else:
            choices = repJSON.get('choices', [])[0].get('text', {}).strip('\n')

        context = [{'ID': id, 'Model': model,
                    'ChatGPT Response': choices, 'Created Time': createdTime,
                    'Number of Prompt Tokens': promptTokens,
                    'Number of Completion Tokens': completionTokens,
                    'Number of Total Tokens': totalTokens
                    }]

        markdown = tableToMarkdown(
            'ChatGPT API Response',
            context,
            date_fields=['Created Time'],
        )

        results = CommandResults(
            readable_output=markdown,
            outputs_prefix='ChatGPTResponse',
            outputs_key_field='id',
            outputs=context
        )


        return results
    else:
        raise DemistoException('Error in results')


''' MAIN FUNCTION '''


def main() -> None:
    """main function, runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('apikey', {}).get('password')
    base_url = params.get('url', '')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    apiVersion = params.get('apiversion')
    prompt = demisto.getArg('prompt')

    if apiVersion == 'gpt-4' or apiVersion == 'gpt-3.5-turbo':
        url_suffix='v1/chat/completions'
        options = {"max_tokens": MAX_TOKEN, "model": apiVersion, "messages": [{"role": "user", "content": prompt}]}
    else:
        options = {
            "model": apiVersion,
            "prompt": prompt,
            "temperature": 0.7,
            "max_tokens": MAX_TOKEN,
            "top_p": 1,
            "frequency_penalty": 0,
            "presence_penalty": 0
        }
        url_suffix='v1/completions'

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(api_key=api_key, base_url=base_url, url_suffix=url_suffix, verify=verify, proxy=proxy)

        if command == 'test-module':
            # This is the call made when clicking the integration Test button.
            return_results(test_module(client, options))

        elif command == 'chatgpt-send-prompt':
            if not prompt:
                raise DemistoException('the prompt argument cannot be empty.')
            return_results(chatgpt_send_prompt_command(client, options))

        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error("\n".join(("Failed to execute {command} command.",
                                "Error:",
                                str(e))))


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

