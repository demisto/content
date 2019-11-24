# import demistomock as demisto
from CommonServerPython import *
# from CommonServerUserPython import *

INTEGRATION_COMMAND_NAME = "lastline"
INTEGRATION_NAME = "Lastline_v2"


class Client(BaseClient):
    MD5_LEN = 32
    SHA1_LEN = 40
    SHA256_LEN = 64

    def __init__(self, base_url: str, api_params: dict, verify=True, proxy=False):
        self.command_params = api_params
        super(Client, self).__init__(base_url, verify, proxy)

    def file(self):
        self.command_params[help_hash_type_checker(self.command_params.get('file'))] = self.command_params.get('file')
        # del self.command_params['file']
        result = self.request_in_path('/analysis/submit/file')
        context_entry = {
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
                'Indicator': "",
                'Type': "",
                'Vendor': "",
                'Score': ""
            }
        }
        human_readable = tableToMarkdown(name=INTEGRATION_NAME, t=context_entry)
        return human_readable, context_entry, result

    def check_status(self):
        result = self.request_in_path('/analysis/get')
        context_entry = {
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
        context_entry = help_get_report_context(result)
        human_readable = tableToMarkdown(name=INTEGRATION_NAME, t=context_entry)
        return human_readable, context_entry, result

    def get_task_list(self):
        result = self.request_in_path('/analysis/get_completed')
        context_entry = {
            'key': [],
            'uuid': []
        }
        human_readable = tableToMarkdown(name=INTEGRATION_NAME, t=context_entry)
        return human_readable, context_entry, result

    def upload_file(self):
        entry_id = self.command_params.get('EntryID')
        self.command_params['push_to_portal'] = True
        file_params = demisto.getFilePath(entry_id)
        with open(file_params.get('path'), 'rb') as file:
            result = self.request_in_path('/analysis/submit/file', files={'file': file.read()})
            # result = {"success": 0, "error_code": 115, "error": "Submission limit exceeded"}
        demisto.info("open success")
        demisto.info(result)
        context_entry = {
            'Lastline': {
                'Submission': {
                    'Filename': file_params.get('name'),
                    'UUID': "",
                    'Status': ""
                }
            }
        }
        help_upload_and_status(result, context_entry)
        human_readable = tableToMarkdown(INTEGRATION_COMMAND_NAME, t=context_entry.get('Lastline'))
        return human_readable, context_entry, result

    def upload_url(self):
        result = self.request_in_path('/analysis/submit/url')
        demisto.info(result)
        context_entry = {
            'Lastline': {
                'Submission': {
                    'URL': "",
                    'UUID': "",
                    'Status': ""
                }
            }
        }
        help_upload_and_status(dict, context_entry)
        human_readable = tableToMarkdown(INTEGRATION_COMMAND_NAME, t=context_entry['Lastline'])
        return human_readable, context_entry.get('Lastline'), result

    def test_module_command(self):
        self.command_params['uuid'] = '64081e5251ae0010058d480cc8c1b68b'
        self.get_report()
        return 'ok'

    def request_in_path(self, path: str, files=None) -> dict:
        result = self._http_request('POST', path, data=self.command_params, files=files)
        help_lastline_exception_handler(result)
        return result


def help_lastline_exception_handler(result: dict):
    if not result.get("success"):
        error_msg = "error "
        if 'error_code' in result:
            error_msg += "(" + str(result.get("error_code")) + ") "
        error_msg += result.get("error")
        raise DemistoException(error_msg)


def help_hash_type_checker(hash_file: str) -> str:
    if len(hash_file) == Client.MD5_LEN:
        return 'md5'
    if len(hash_file) == Client.SHA1_LEN:
        return 'sha1'
    if len(hash_file) == Client.SHA256_LEN:
        return 'sha256'
    raise DemistoException(f'{INTEGRATION_NAME} File command support md5/ sha1/ sha256 only')


def help_upload_and_status(result: dict, context_entry: dict):
    if 'data' in result:
        context_entry['Lastline']['Submission']['UUID'] = result['data'].get('task_uuid')
        if 'score' in result['data']:
            context_entry['Lastline']['Submission']['Status'] = 'Completed'
        else:
            context_entry['Lastline']['Submission']['Status'] = 'Analyzing'
        if 'analysis_subject' in result['data']:
            if 'Filename' in result['data']['analysis_subject'] and \
                    'Filename' in context_entry['Lastline']['Submission']:
                context_entry['Lastline']['Submission']['Filename'] = result['data']['analysis_subject']['Filename']
            elif 'url' in result['data']['analysis_subject'] and 'url' in context_entry['Lastline']['Submission']:
                context_entry['Lastline']['Submission']['URL'] = result['data']['analysis_subject']['url']


def help_get_report_context(result) -> dict:
    context_entry = {
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
                if 'url' in result['data']['analysis_subject']:
                    key = 'URL'
                    context_entry[key]['Data'] = result['data']['analysis_subject'].get('url')

                else:
                    # context_entry['URL']['Data'] = result['data']['analysis_subject'].get('url')
                    key = 'File'
                context_entry['key']['Data']['Malicious']['Vendor'] = 'Lastline'
                context_entry['key']['Data']['Malicious']['Description'] = 'Score above '
                context_entry['key']['Data']['Malicious']['score'] = result['data'].get('score')
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
        # 'fetch-incidents': fetch_incidents_command,
        'file': Client.file,
        f'{INTEGRATION_COMMAND_NAME}-check-status':  Client.check_status,
        f'{INTEGRATION_COMMAND_NAME}-get-report':  Client.get_report,
        f'{INTEGRATION_COMMAND_NAME}-get-task-list':  Client.get_task_list,
        f'{INTEGRATION_COMMAND_NAME}-upload-file':  Client.upload_file,
        f'{INTEGRATION_COMMAND_NAME}-upload-url':  Client.upload_url
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
# main()


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
