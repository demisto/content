import io
import json

import pytest

from CommonServerPython import (CommandResults, DemistoException,
                                tableToMarkdown, urljoin)
from YodaSpeak import TRANSLATE_OUTPUT_PREFIX


def util_load_json(path: str):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


BASE_URL = 'https://yoda.example.com'
YODA_ENDPOINT = 'yoda'
ENDPOINT_URL = urljoin(BASE_URL, YODA_ENDPOINT)


def test_translate(requests_mock):
    """
    Given
            An API key, and text to translate
    When
            Calling translate
    Then
            Test the command result structure
    """
    from YodaSpeak import Client, translate_command
    client = Client(base_url=BASE_URL, verify=False, api_key='foo', proxy=False)
    args = {'text': 'this is some sentence for translation'}

    raw_response = util_load_json('test_data/translate.json')
    requests_mock.post(ENDPOINT_URL, json=raw_response)
    command_result = translate_command(client, **args)

    output = {'Original': 'this is some sentence for translation',
              'Translation': 'Some sentence for translation, this is.'}

    expected_result = CommandResults(outputs_prefix='YodaSpeak',
                                     outputs_key_field=f'{TRANSLATE_OUTPUT_PREFIX}.Original',
                                     outputs={TRANSLATE_OUTPUT_PREFIX: output},
                                     raw_response=raw_response,
                                     readable_output=tableToMarkdown(name='Yoda Says...', t=output))

    assert command_result.to_context() == expected_result.to_context()


def test_translate_invalid(requests_mock):
    """
    Given
            An API key, and text to translate
    When
            Calling test-module
    Then
            Make sure that invalid responses (lacking `translated`) trigger an exception
    """
    from YodaSpeak import Client, translate_command
    client = Client(base_url=BASE_URL, verify=False, api_key='my api key', proxy=False)
    args = {'text': 'this is some sentence for translation'}

    requests_mock.post(ENDPOINT_URL, json=util_load_json('test_data/translate-fail-no-translation.json'))
    with pytest.raises(DemistoException) as e:
        translate_command(client, **args)
    assert 'did not include `translated`' in str(e)


@pytest.mark.parametrize('file', ('test_data/test-module-fail-zero-success.json',
                                  'test_data/test-module-fail-no-success.json'))
def test_test_module_failure(requests_mock, file: str):
    """
    Given
            An API key
    When
            Calling test-module
    Then
            Make sure that invalid `success` values cause the test to fail
    """
    from YodaSpeak import Client, test_module
    client = Client(base_url=BASE_URL, verify=False, api_key='some api key', proxy=False)

    json_response = util_load_json(file)
    requests_mock.post(ENDPOINT_URL, json=json_response)
    response = test_module(client)
    assert f'Unexpected result from the service: success=' in response
