import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback

import requests


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]  # pylint: disable=no-member


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the OpenAI API
    """

    def __init__(self, base_url: str, api_key: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_key = api_key
        self.headers = {'Authorization': f'Bearer {self.api_key}',
                        'Content-Type': 'application/json'}

    def completions(self, prompt: str, model: str = "text-davinci-003", temperature: float = 0.7,
                    max_tokens: int = 256, top_p: float = 1, frequency_penalty: int = 0,
                    presence_penalty: int = 0) -> dict:
        """Enter an instruction and watch the OpenAI API respond with a completion that attempts to match the context
        or pattern you provided.

        :type prompt: ``str``
        :param prompt: Instruction
        :type model: ``str``
        :param model: The model which will generate the completion.
        :type temperature: ``float``
        :param temperature: Controls randomness: Lowering results in less random completions.
        :type max_tokens: ``int``
        :param max_tokens: The maximum number of tokens to generate.
        :type top_p: ``float``
        :param top_p: Controls Diversity via nucleus sampling
        :type frequency_penalty: ``int``
        :param frequency_penalty: How much to penalize new tokens based on their existing frequency in the text so far.
        :type presence_penalty: ``int``
        :param presence_penalty: How much to penalize new tokens based on whether they appear in the text so far.

        :return: response of the OpenAI Completion API
        :rtype: ``dict``
        """

        data = {
            "model": model,
            "prompt": prompt,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p": top_p,
            "frequency_penalty": frequency_penalty,
            "presence_penalty": presence_penalty
        }

        return self._http_request(method='POST', url_suffix='v1/completions', json_data=data, headers=self.headers,
                                  resp_type='json', ok_codes=(200,), )


''' COMMAND FUNCTIONS '''


def test_module_command(client):
    """
    Tests OpenAPI connectivity
    """
    result = client.completions(prompt="Can I connect to the OpenAI api?")
    if result:
        return 'ok'
    else:
        return 'Did not receive a response from OpenAI API'


def reputations_command(client: Client, args: dict) -> CommandResults:
    """Enter an instruction and watch the OpenAI API respond with a completion that attempts to match the context
    or pattern you provided.

    :type client: ``Client``
    :param client: instance of Client class to interact with OpenAI API
    :type args: ``dict``
    :param args:  arguments

    :return: CommandResults instance of the OpenAI Completion API response
    :rtype: ``CommandResults``
    """

    prompt = args.get('prompt', False)

    if not prompt:
        raise ValueError('No prompt argument was provided')

    model = args.get('model', 'text-davinci-003')
    temperature = args.get('temperature') or 0.7
    max_tokens = args.get('max_tokens') or 256
    top_p = args.get('top_p') or 1
    frequency_penalty = args.get('frequency_penalty') or 0
    presence_penalty = args.get('presence_penalty') or 0

    response = client.completions(prompt=prompt, model=model, temperature=float(temperature),
                                  max_tokens=int(max_tokens), top_p=int(top_p),
                                  frequency_penalty=int(frequency_penalty), presence_penalty=int(presence_penalty))

    meta = None
    context = None

    if response and isinstance(response, dict):
        model = response.get('model')
        id = response.get('id')
        choices = response.get('choices', [])
        meta = f"Model {response.get('model')} generated {len(choices)} possible text completion(s)."
        context = [{'id': id, 'model': model, 'text': choice.get('text')} for choice in choices]

    return CommandResults(
        readable_output=tableToMarkdown('OpenAI - Completions', context, metadata=meta, removeNull=True),
        outputs_prefix='OpenAI.Completions',
        outputs_key_field='id',
        outputs=context,
        raw_response=response
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get('url')
    api_key = params.get('apikey')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify,
            proxy=proxy
        )

        if command == 'test-module':
            return_results(test_module_command(client))
        elif command == 'openai-completions':
            return_results(reputations_command(client=client, args=args))
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
