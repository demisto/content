import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Dict, Tuple, List

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
BPA_HOST = 'https://bpa.paloaltonetworks.com'
BPA_VERSION = 'v1'
BPA_URL = BPA_HOST + '/api/' + BPA_VERSION + '/'
DOWNLOADED_REPORT_NAME_SUFFIX = '_BPA-report.zip'


class LightPanoramaClient(BaseClient):
    '''
    This is a client for Panorama API, used by integration commands to issue requests to Panorama API,
     not the BPA service.
    '''
    def __init__(self, server, port, api_key, verify, proxy):
        if port is None:
            super().__init__(server + '/', verify)
        else:
            super().__init__(server.rstrip('/:') + ':' + port + '/', verify)
        self.api_key = api_key
        if proxy:
            self.proxies = handle_proxy()

        else:
            self.proxies = {}

    def simple_op_request(self, cmd):
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': self.api_key
        }

        result = self._http_request(
            'POST',
            'api',
            params=params,
            resp_type='text',
            proxies=self.proxies
        )

        return result

    @logger
    def get_system_time(self):
        return self.simple_op_request('<show><clock></clock></show>')

    @logger
    def get_license(self):
        return self.simple_op_request('<request><license><info></info></license></request>')

    @logger
    def get_system_info(self):
        return self.simple_op_request('<show><system><info></info></system></show>')

    @logger
    def get_running_config(self):
        params = {
            'type': 'config',
            'action': 'show',
            'key': self.api_key
        }

        result = self._http_request(
            'POST',
            'api',
            params=params,
            resp_type='text',
            proxies=self.proxies
        )

        return result


class Client(BaseClient):
    """
    Client to use in the BPA integration. This client issues requests to the BPA service, and not Panorama.
    """

    def __init__(self, bpa_token: str, verify: bool, proxy: bool):
        headers = {'Authorization': f'Token {bpa_token}'}
        super().__init__(base_url=BPA_URL, verify=verify, headers=headers)
        self.token = bpa_token
        if proxy:
            self.proxies = handle_proxy()

        else:
            self.proxies = {}

    def get_documentation_request(self):
        response = self._http_request('GET', 'documentation/', proxies=self.proxies)
        return response

    def submit_task_request(self, running_config, system_info, license_info, system_time, generate_zip_bundle) -> Dict:
        data = {
            'xml': running_config,
            'system_info': system_info,
            'license_info': license_info,
            'system_time': system_time,
            'generate_zip_bundle': generate_zip_bundle
        }

        response = self._http_request('POST', 'create/', data=data, proxies=self.proxies)
        return response

    def get_results_request(self, task_id: str):
        response = self._http_request('GET', f'results/{task_id}/', proxies=self.proxies)
        return response

    def get_download_results_request(self, task_id: str) -> bytes:
        response = self._http_request('GET', f'results/{task_id}/download', resp_type='content', proxies=self.proxies)
        return response


def create_output(doc: dict):
    doc_output = {}
    for key in doc.keys():
        doc_output[string_to_context_key(key)] = doc.get(key)
    return doc_output


def get_documentation_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    raw = client.get_documentation_request()
    if not raw:
        raise Exception('Failed getting documentation from BPA')
    filter_by_ids = args.get('ids')
    if filter_by_ids:
        output = []
        old_output = []  # keep old output format in order to not break backwards compatibility
        id_list = filter_by_ids.split(',')
        for doc in raw:
            if str(doc.get('doc_id')) in id_list:
                output.append(create_output(doc))
                old_output.append(doc)
    else:
        output = [create_output(doc) for doc in raw]
        old_output = raw
    entry_context = {
        'PAN-OS-BPA.Documentation.Document': output,
        'PAN-OS-BPA.Documentation': old_output  # Keep old output path in order to not break backwards compatibility.
    }
    human_readable = tableToMarkdown('BPA documentation', output)
    # print(f'DOCUMENTATION CONTEXT: {entry_context}')

    return human_readable, entry_context, raw


def submit_task_command(client: Client, panorama: LightPanoramaClient, args: Dict) -> Tuple[str, Dict, Dict]:
    try:
        running_config = panorama.get_running_config()
        system_info = panorama.get_system_info()
        license_info = panorama.get_license()
        system_time = panorama.get_system_time()
    except Exception:
        raise Exception('Failed getting response from Panorama')

    generate_zip_bundle = args.get('generate_zip_bundle')
    raw = client.submit_task_request(running_config, system_info, license_info, system_time, generate_zip_bundle)
    task_id = raw.get('task_id', '')

    human_readable = f'Submitted BPA job ID: {task_id}'
    entry_context = {'PAN-OS-BPA.SubmittedJob(val.JobID && val.JobID === obj.JobID)': {'JobID': task_id}}

    return human_readable, entry_context, raw


def transform_check(check, feature, category):
    # safe to shallow clone since it is a shallow object
    transformed_check = check.copy()
    transformed_check['check_category'] = category
    transformed_check['check_feature'] = feature
    return transformed_check


def get_checks_from_feature(feature, feature_name, category):
    notes_checks = feature.get('notes', [])
    warnings_checks = feature.get('warnings', [])
    return [transform_check(c, feature_name, category) for c in notes_checks + warnings_checks]


def get_results_command(client: Client, args: Dict):
    task_id = args.get('task_id', '')
    filter_by_check_id = args.get('check_id', '').split(',') if args.get('check_id') else []
    filter_by_check_name = args.get('check_name', '').split(',') if args.get('check_name') else []
    raw: Dict = client.get_results_request(task_id)
    status = raw.get('status')
    results = raw.get('results', {})
    exclude_passed_checks = args.get('exclude_passed_checks') == "true"

    if not status:
        raise Exception("Invalid response from BPA")

    job_checks: List[Dict] = []

    if status == 'invalid':
        raise Exception("Job ID not valid or doesn't exist")

    if status == 'complete':
        bpa = results.get('bpa', {})
        if not bpa:
            raise Exception("Invalid response from BPA")

        for category_name, features in bpa.items():
            for feature_name, feature_contents in features.items():
                if not feature_contents:
                    # Empty list, no checks
                    continue
                checks = get_checks_from_feature(feature_contents[0], feature_name, category_name)
                if exclude_passed_checks:
                    job_checks.extend([check for check in checks if not check.get('check_passed')])
                elif filter_by_check_id or filter_by_check_name:
                    job_checks.extend([check for check in checks if str(check.get('check_id')) in filter_by_check_id
                                       or check.get('check_name') in filter_by_check_name])
                else:
                    job_checks.extend(checks)

    download_url = results.get('download_url')

    # check that a report was generated, and can be downloaded
    if download_url:
        download_report_handler(client, task_id)

    context = {'PAN-OS-BPA.JobResults(val.JobID && val.JobID === obj.JobID)': {
        'JobID': task_id,
        'Checks': job_checks,
        'Status': status
    }}
    human_readable = tableToMarkdown('BPA Results', job_checks)

    return human_readable, context, results


def download_report_handler(client: Client, task_id):
    downloaded_report = client.get_download_results_request(task_id)
    demisto.results(
        fileResult(task_id + DOWNLOADED_REPORT_NAME_SUFFIX, downloaded_report, entryTypes['entryInfoFile']))


def test_module(client, panorama):
    client.get_documentation_request()
    panorama.get_system_time()

    demisto.results('ok')
    return '', None, None


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    panorama_server = demisto.params().get('server')
    panorama_port = demisto.params().get('port', None)
    panorama_api_key = demisto.params().get('key')
    bpa_token = demisto.params().get('token')
    verify = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy')

    try:
        client = Client(bpa_token, verify, proxy)
        panorama = LightPanoramaClient(panorama_server, panorama_port, panorama_api_key, verify, proxy)
        command = demisto.command()
        LOG(f'Command being called is {command}.')
        if command == 'pan-os-bpa-submit-job':
            return_outputs(*submit_task_command(client, panorama, demisto.args()))
        elif command == 'pan-os-bpa-get-job-results':
            return_outputs(*get_results_command(client, demisto.args()))
        elif command == 'pan-os-get-documentation':
            return_outputs(*get_documentation_command(client, demisto.args()))
        elif command == 'test-module':
            return_outputs(*test_module(client, panorama))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
