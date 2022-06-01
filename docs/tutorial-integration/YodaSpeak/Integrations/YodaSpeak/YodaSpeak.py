# uncomment the import statements for debugging in PyCharm, VS Code or other IDEs.
# import demistomock as demisto
# from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
# from CommonServerUserPython import *  # noqa

TRANSLATE_OUTPUT_PREFIX = 'Phrase'

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


class Client(BaseClient):
    def __init__(self, api_key: str, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_key = api_key

        if self.api_key:
            self._headers = {'X-Funtranslations-Api-Secret': self.api_key}

    def translate(self, text: str):
        return self._http_request(method='POST', url_suffix='yoda', data={'text': text}, resp_type='json',
                                  ok_codes=(200,))


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'

    Returning 'ok' indicates that connection to the service is successful.
    Raises exceptions if something goes wrong.
    """

    try:
        response = client.translate('I have the high ground!')

        success = demisto.get(response, 'success.total')  # Safe access to response['success']['total']
        if success != 1:
            return f'Unexpected result from the service: success={success} (expected success=1)'

        return 'ok'

    except Exception as e:
        exception_text = str(e).lower()
        if 'forbidden' in exception_text or 'authorization' in exception_text:
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e


def translate_command(client: Client, text: str) -> CommandResults:
    if not text:
        raise DemistoException('the text argument cannot be empty.')

    response = client.translate(text)
    translated = demisto.get(response, 'contents.translated')

    if translated is None:
        raise DemistoException('Translation failed: the response from server did not include `translated`.',
                               res=response)

    output = {'Original': text, 'Translation': translated}

    return CommandResults(outputs_prefix='YodaSpeak',
                          outputs_key_field=f'{TRANSLATE_OUTPUT_PREFIX}.Original',
                          outputs={TRANSLATE_OUTPUT_PREFIX: output},
                          raw_response=response,
                          readable_output=tableToMarkdown(name='Yoda Says...', t=output))


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('apikey', {}).get('password')
    base_url = params.get('url', '')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(api_key=api_key, base_url=base_url, verify=verify, proxy=proxy)

        if command == 'test-module':
            # This is the call made when clicking the integration Test button.
            return_results(test_module(client))

        elif command == 'yoda-speak-translate':
            return_results(translate_command(client, **args))

        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error("\n".join(("Failed to execute {command} command.",
                                "Error:",
                                str(e))))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
