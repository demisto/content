import mimetypes
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict

INTEGRATION_COMMAND_NAME = "lastline"
INTEGRATION_NAME = "Lastline_v2"


class Client(BaseClient):
    MD5_LEN = 32
    SHA1_LEN = 40
    SHA256_LEN = 64
    DEFAULT_THRESHOLD = 70

    def __init__(self, base_url: str, api_params: Dict, verify=True, proxy=False):
        self.command_params = api_params
        super(Client, self).__init__(base_url, verify, proxy)

    def file(self):
        hash_type = help_hash_type_checker(self.command_params.get('file'))
        self.command_params[hash_type] = self.command_params.get('file')
        result = self.request_in_path('/analysis/submit/file')
        context_entry: Dict = {
            'File': {
                'MD5': "",
                'SHA1': "",
                'SHA256': "",
                'Type': "",
                'Malicious': {
                    'Vendor': "",
                    'Description': "",
                    'Score': ""
                }
            },
            'DBotScore': {
                'Indicator': self.command_params.get('file'),
                'Type': hash_type,
                'Vendor': "Lastline v2",
                'Score': 0
            }
        }
        human_readable = tableToMarkdown(name=INTEGRATION_NAME, t=context_entry)
        return human_readable, context_entry, result

    def check_status(self):
        result = self.request_in_path('/analysis/get')
        context_entry: Dict = {
            'Lastline': {
                'Submission': {
                    'UUID': "",
                    'Status': ""
                }
            }
        }
        help_upload_and_status(result, context_entry)
        human_readable = tableToMarkdown(name=INTEGRATION_COMMAND_NAME, t=context_entry.get('Lastline'))
        return human_readable, context_entry, result

    def get_report(self):
        result = self.request_in_path('/analysis/get')
        context_entry: Dict = help_get_report_context(result, self.command_params.get('threshold'))
        human_readable = tableToMarkdown(name=INTEGRATION_NAME, t=context_entry)
        return human_readable, context_entry, result

    def get_task_list(self):
        result = self.request_in_path('/analysis/get_completed')
        context_entry: Dict = {
            'key': [],
            'uuid': []
        }
        human_readable = tableToMarkdown(name=INTEGRATION_NAME, t=context_entry)
        return human_readable, context_entry, result

    def upload_file(self):
        entry_id = self.command_params.get('EntryID')
        self.command_params['push_to_portal'] = True
        file_params = demisto.getFilePath(entry_id)
        file_params['mime_type'] = mimetypes.guess_type(file_params.get('name'))
        with open(file_params.get('path'), 'rb') as file:
            result = self.request_in_path('/analysis/submit/file', files={file_params['mime_type']: file.read()})
        context_entry: Dict = {
            'Lastline': {
                'Submission': {
                    'Filename': file_params.get('name'),
                    'UUID': "",
                    'Status': ""
                }
            }
        }
        help_upload_and_status(result, context_entry)
        human_readable = tableToMarkdown(INTEGRATION_COMMAND_NAME, t=context_entry)

        return human_readable, context_entry, result

    def upload_url(self):
        result = self.request_in_path('/analysis/submit/url')
        demisto.info(result)
        context_entry: Dict = {
            'Lastline': {
                'Submission': {
                    'URL': self.command_params.get('url'),
                    'UUID': "",
                    'Status': ""
                }
            }
        }
        help_upload_and_status(result, context_entry)
        human_readable = tableToMarkdown(name=INTEGRATION_COMMAND_NAME, t=context_entry)
        return human_readable, context_entry, result

    def test_module_command(self):
        self.command_params['url'] = 'https://www.google.com'
        self.upload_url()
        return 'ok'

    def request_in_path(self, path: str, files=None) -> Dict:
        result: Dict = self._http_request('POST', path, data=self.command_params, files=files)
        help_lastline_exception_handler(result)
        return result


def help_lastline_exception_handler(result: Dict):
    if not result.get("success"):
        error_msg = "error "
        if 'error_code' in result:
            error_msg += "(" + str(result['error_code']) + ") "
        if 'error' in result:
            error_msg += result['error']
        raise DemistoException(error_msg)


def help_hash_type_checker(hash_file: str) -> str:
    if len(hash_file) == Client.MD5_LEN:
        return 'md5'
    if len(hash_file) == Client.SHA1_LEN:
        return 'sha1'
    if len(hash_file) == Client.SHA256_LEN:
        return 'sha256'
    raise DemistoException(f'{INTEGRATION_NAME} File command support md5/ sha1/ sha256 only')


def help_upload_and_status(result: Dict, context_entry: Dict):
    if 'data' in result:
        context_entry['Lastline']['Submission']['UUID'] = result['data'].get('task_uuid')
        if 'score' in result['data']:
            context_entry['Lastline']['Submission']['Status'] = 'Completed'
        else:
            context_entry['Lastline']['Submission']['Status'] = 'Analyzing'


def help_get_report_context(result: Dict, threshold=None) -> Dict:
    context_entry: Dict = {
        'URL': {
            'Data': "",
            'Malicious': {
                'Vendor': "",
                'Description': "",
                'Score': ""
            }
        },
        'File': {
            'MD5': "",
            'SHA1': "",
            'SHA256': "",
            'Malicious': {
                'Vendor': "",
                'Description': "",
                'Score': ""
            }
        },
        'DBotScore': {
            'Indicator': "",
            'Type': "",
            'Vendor': 'Lastline',
            'Score': 0
        },
        'Lastline': {
            'Submission': {
                'Status': "",
                'YaraSignatures': {
                    'name': "",
                    'score': "",
                    'internal': ""
                },
                'DNSqueries': "",
                'NetworksConnection': "",
                'DownloadedFiles': "",
                'Process': {
                    'arguments': "",
                    'executable': {
                        'abs_path': "",
                        'filename': "",
                        'yara_signature_hits': "",
                        'ext_info': "",
                        'process_id': ""
                    },
                }
            }
        }
    }
    if 'data' in result:
        if 'score' in result['data']:
            if 'analysis_subject' in result['data']:
                context_entry['Lastline']['Submission']['Status'] = 'Completed'
                context_entry['DBotScore']['type'] = 'url'
                context_entry['DBotScore']['Indicator'] = result['data']['analysis_subject'].get('url')
                if threshold is None:
                    threshold = Client.DEFAULT_THRESHOLD
                if result['data']['score'] > threshold:
                    if 'url' in result['data']['analysis_subject']:
                        key = 'URL'
                        context_entry[key]['Data'] = result['data']['analysis_subject'].get('url')
                        context_entry['DBotScore']['Indicator'] = context_entry[key]['Data']
                    else:
                        key = 'File'
                        context_entry[key]['md5'] = result['data']['analysis_subject'].get('md5')
                        context_entry[key]['sha1'] = result['data']['analysis_subject'].get('sha1')
                        context_entry[key]['sha256'] = result['data']['analysis_subject'].get('sha256')
                        context_entry['DBotScore']['Indicator'] = 'md5-' + context_entry[key]['md5']
                    context_entry['DBotScore']['Type'] = key
                    context_entry[key]['Malicious']['Vendor'] = 'Lastline'
                    context_entry[key]['Malicious']['score'] = result['data'].get('score')
                    context_entry[key]['Malicious']['Description'] = 'Score above ' + str(threshold)

        else:
            context_entry['Lastline']['Submission']['Status'] = 'Analyzing'
    return context_entry


def main():
    params = demisto.params()
    base_url = params.get('url')
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    api_params = {
        'key': params.get('api_key'),
        'api_token': params.get('api_token')
    }
    api_params.update(demisto.args())
    client = Client(base_url, api_params, verify=verify_ssl, proxy=proxy)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    # Switch case
    commands = {
        'test-module': Client.test_module_command,
        'file': Client.file,
        f'{INTEGRATION_COMMAND_NAME}-check-status': Client.check_status,
        f'{INTEGRATION_COMMAND_NAME}-get-report': Client.get_report,
        f'{INTEGRATION_COMMAND_NAME}-get-task-list': Client.get_task_list,
        f'{INTEGRATION_COMMAND_NAME}-upload-file': Client.upload_file,
        f'{INTEGRATION_COMMAND_NAME}-upload-url': Client.upload_url
    }
    try:
        demisto.info(command)
        if command in commands:
            readable_output, outputs, raw_response = commands[command](client)
            return_outputs(readable_output, outputs, raw_response)
    # Log exceptions
    except Exception as every_error:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{every_error}]'
        return_error(err_msg, error=every_error)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
