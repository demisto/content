import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import hashlib
import traceback
from google.cloud import translate_v3  # type: ignore[attr-defined]


class Client:
    """Wrapper around the Google Cloud Translate API Client implementing the code
    to handle credentials and proxy under Demisto and a translation between
    the Google Cloud Python library typing system and Python serializable
    dictionaries/lists

    Returns:
        service_account(dict): The desarialized contents of the Service Account Private
            Key JSON file
        project(str): The GCP project ID. If None, the project id is read from the
            service_account. Default: None
        verify(bool): Enable certificate verification. Default: True
        proxy(bool): Enable proxy. Default: False
    """

    def __init__(self, service_account=None, project=None, verify=True):
        self.service_account = service_account
        self.project = project
        self.verify = verify

        self.client = self._get_client()
        self.project_id = self._get_project_id()

    def get_supported_languages(self):
        """Returns languages supported by Google Cloud Translation API

        Returns:
            list: List of supported languages. Each entry is a dictionary
                representing a supported language: language_code is the
                2 letter ISO language code, support_source is a bool
                indicating if the language is a supported source,
                support_target is a bool indicating if the language is
                a supported target for the translation.
        """
        parent = f"projects/{self.project_id}/locations/global"
        result = self.client.get_supported_languages(parent=parent)

        return [
            {
                "language_code": language.language_code,
                "support_source": language.support_source,
                "support_target": language.support_target
            }
            for language in result.languages
        ]

    def translate_text(self, text, target, source=None):
        """Translates a text from source language to target language.

        Args:
            text (str): The text to be translated
            target (str): ISO 2 letter code of the target language. Default: en
            source (str, optional): ISO 2 letter code of the source language. If
                None, Google Cloud Translate will try to detect the source
                language. Default: None

        Returns:
            dict: Result of translation. The translated_text key is the result
                of the translation, detected_language_code is the ISO 2 letter
                code of the detected language or None if the source language
                was specified.
        """
        parent = f"projects/{self.project_id}/locations/global"
        result = self.client.translate_text(
            request={
                'contents': [text],
                'target_language_code': target,
                'parent': parent,
                'source_language_code': source
            }
        )

        return {
            'detected_language_code': result.translations[0].detected_language_code,
            'translated_text': result.translations[0].translated_text
        }

    def _get_project_id(self):
        return self.project if self.project is not None else self.service_account['project_id']

    def _get_client(self):
        handle_proxy()

        cur_directory_path = os.getcwd()
        credentials_file_name = demisto.uniqueFile() + '.json'
        credentials_file_path = os.path.join(cur_directory_path, credentials_file_name)

        with open(credentials_file_path, 'w') as creds_file:
            json.dump(self.service_account, creds_file)

        return translate_v3.TranslationServiceClient.from_service_account_json(  # type: ignore[call-arg]
            filename=credentials_file_path
        )


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client (Client): instance of the Client class

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    try:
        client.get_supported_languages()
        return 'ok'

    except Exception as e:
        return f'Test failed: {str(e)}'


def supported_languages(client):
    """Returns the list of supported languages

    Args:
        client (Client): instance of the Client class

    Returns:
        The list of supported languages

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs for other tasks in the
                 playbook
        raw_response (dict): Used for debugging/troubleshooting purposes - will be shown only if the command executed with
                      raw-response=true
    """
    result = client.get_supported_languages()

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = 'Languages: {}'.format(', '.join([language['language_code'] for language in result]))
    outputs = {
        'GoogleCloudTranslate': {
            'SupportedLanguages': result
        }
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def translate_text(client, args):
    """Translates text

    Args:
        client (Client): instance of the Client class
        args (dict): dictionary of arguments. The argument text is the text to
            be translated, target is the ISO 2 letter code of the target language
            (default: en), source is the ISO 2 letter code of the source language
            (default: auto detect)

    Returns:
        The list of supported languages

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs for other tasks in the
                 playbook
        raw_response (dict): Used for debugging/troubleshooting purposes - will be shown only if the command executed with
                      raw-response=true
    """
    text = args.get('text', '')
    target = args.get('target', 'en')
    source = args.get('source', None)

    result = client.translate_text(
        text,
        target,
        source=source
    )

    readable_output = 'Translation: {}\nSource Language Detected: {}'.format(
        result['translated_text'],
        result['detected_language_code']
    )

    id_ = hashlib.md5(f'{target}-{source}-{text}'.encode()).hexdigest()  # nosec

    outputs = {
        'GoogleCloudTranslate.TranslateText(val.ID && val.ID==obj.ID)': {
            'ID': id_,
            'text': text,
            'translated_text': result['translated_text'],
            'source_language_code': source,
            'detected_language_code': result['detected_language_code'],
            'target_language_code': target
        }
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    service_account_json = demisto.params().get('project_creds', {}).get('password')\
        or demisto.params().get('service_account_json')
    try:
        service_account = json.loads(service_account_json)
    except Exception:
        return_error('Invalid JSON provided')

    project = demisto.params().get('project_creds', {}).get('identifier') or demisto.params().get('project', None)

    verify_certificate = not demisto.params().get('insecure', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            service_account=service_account,
            project=project,
            verify=verify_certificate,
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'gct-supported-languages':
            return_outputs(*supported_languages(client))

        elif demisto.command() == 'gct-translate-text':
            return_outputs(*translate_text(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        LOG(traceback.format_exc())
        return_error(
            f'Failed to execute {demisto.command()} command. Error: {str(e)}'
        )

    finally:
        LOG.print_log()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
