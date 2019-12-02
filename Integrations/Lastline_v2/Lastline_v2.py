import hashlib
from typing import Dict
import urllib3
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


INTEGRATION_COMMAND_NAME = "lastline"
INTEGRATION_NAME = "Lastline_v2"
urllib3.disable_warnings()


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
        context_entry: Dict = help_context_entry(demisto.command())
        context_entry['DBotScore']['Indicator'] = self.command_params.get('file')
        context_entry['DBotScore']['Type'] = hash_type
        human_readable = tableToMarkdown(name=INTEGRATION_NAME, t=context_entry, removeNull=True)
        return human_readable, context_entry, result

    def check_status(self):
        result = self.request_in_path('/analysis/get')
        context_entry: Dict = help_context_entry(demisto.command())
        help_upload_and_status(result, context_entry)
        human_readable = tableToMarkdown(name=INTEGRATION_COMMAND_NAME, t=context_entry.get('Lastline'), removeNull=True)
        return human_readable, context_entry, result

    def get_report(self):
        result = self.request_in_path('/analysis/get')
        context_entry: Dict = help_get_report_context(result, self.command_params.get('threshold'))
        human_readable = tableToMarkdown(name=INTEGRATION_NAME, t=context_entry, removeNull=True)
        return human_readable, context_entry, result

    def get_task_list(self):
        result = self.request_in_path('/analysis/get_completed')
        context_entry: Dict = help_context_entry(demisto.command())
        if 'data' in result:
            context_entry['uuid'] = result['data'].get('tasks')
        human_readable = tableToMarkdown(name=INTEGRATION_NAME, t=context_entry, removeNull=True)
        return human_readable, context_entry, result

    def upload_file(self):
        entry_id = self.command_params.get('EntryID')
        self.command_params['push_to_portal'] = True
        file_params = demisto.getFilePath(entry_id)
        self.command_params['md5'] = help_file_hash(file_params.get('path'))
        result = self.request_in_path('/analysis/submit/file',
                                      headers={'Content-Type': 'multipart/form-data'},
                                      files={'file': file_params.get('path')})
        context_entry: Dict = help_context_entry(demisto.command())
        context_entry['Lastline']['Submission']['Filename'] = self.command_params.get('name')
        help_upload_and_status(result, context_entry)

        human_readable = tableToMarkdown(INTEGRATION_COMMAND_NAME, t=context_entry, removeNull=True)
        return human_readable, context_entry, result

    def upload_url(self):
        result = self.request_in_path('/analysis/submit/url')
        demisto.info(result)
        context_entry: Dict = help_context_entry(demisto.command())
        context_entry['Lastline']['Submission']['URL'] = self.command_params.get('url')
        help_upload_and_status(result, context_entry)
        human_readable = tableToMarkdown(name=INTEGRATION_COMMAND_NAME, t=context_entry, removeNull=True)
        return human_readable, context_entry, result

    def test_module_command(self):
        self.command_params['url'] = 'https://www.google.com'
        self.upload_url()
        return 'ok'

    def request_in_path(self, path: str, headers=None, files=None) -> Dict:
        result: Dict = self._http_request('POST', path, params=self.command_params, headers=headers, files=files)
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
    context_entry: Dict = help_context_entry(f'{INTEGRATION_COMMAND_NAME}-get-report')
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


def help_context_entry(command: str):
    commands: Dict = {
        'file': {
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
                'Indicator': '',
                'Type': '',
                'Vendor': "Lastline v2",
                'Score': 0
            }
        },
        f'{INTEGRATION_COMMAND_NAME}-check-status': {
            'Lastline': {
                'Submission': {
                    'UUID': "",
                    'Status': ""
                }
            }
        },
        f'{INTEGRATION_COMMAND_NAME}-get-report': {
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
        },
        f'{INTEGRATION_COMMAND_NAME}-get-task-list': {
            'key': [],
            'uuid': []
        },
        f'{INTEGRATION_COMMAND_NAME}-upload-file': {
            'Lastline': {
                'Submission': {
                    'Filename': '',
                    'UUID': "",
                    'Status': ""
                }
            }
        },
        f'{INTEGRATION_COMMAND_NAME}-upload-url': {
            'Lastline': {
                'Submission': {
                    'URL': '',
                    'UUID': "",
                    'Status': ""
                }
            }
        }
    }
    return commands.get(command)


def help_file_hash(path: str) -> str:
    block_size = 65536
    file_hash = hashlib.md5()
    with open(path, 'rb') as file:
        buf = file.read(block_size)
        while len(buf) > 0:
            file_hash.update(buf)
            buf = file.read(block_size)
    return file_hash.hexdigest()


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
        # 'file': Client.file,
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


if __name__ in ("__builtin__", "builtins"):
    main()
