from typing import Dict, Callable, Tuple, Any

from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client to use in the Securonix integration. Overrides BaseClient
    """
    def __init__(self, server_url: str, org_key: str, auth_token: str, verify: bool, proxy: bool):
        super().__init__(base_url=server_url, verify=verify)
        self.org_key = org_key
        self._cb_time_format = '%Y-%m-%dT%H:%M:%SZ'
        self._proxies = handle_proxy() if proxy else None
        self._headers = {
            'X-Auth-Token': auth_token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    @staticmethod
    def get_respective_date(time_window: int, cb_time_format: str) -> str:
        now = datetime.now()
        start_time = now - timedelta(days=int(time_window))
        return str(start_time.strftime(cb_time_format))

    @staticmethod
    def delete_unnecessary_fields(response: dict) -> dict:
        if 'crossproc' in response:
            del response['crossproc']
        if 'crossproc_target_complete' in response:
            del response['crossproc_target_complete']
        if 'modload_complete' in response:
            del response['modload_complete']
        if 'modload_name' in response:
            del response['modload_name']
        if 'modload_hash' in response:
            del response['modload_hash']
        if 'hash' in response:
            del response['hash']
        if 'process_complete' in response:
            del response['process_complete']
        if 'regmod_complete' in response:
            del response['regmod_complete']

    def http_request(self, method: str, url_suffix: str, version: str, params: str = None, data: dict = None,
                     safe: bool = False, parse_json: bool = True):
        url = f'{self._base_url}{version}{url_suffix}'
        try:
            result = requests.request(
                method,
                url,
                verify=self._verify,
                params=params,
                json=data,
                headers=self._headers,
            )
        except requests.exceptions.RequestException as err:
            raise Exception(f'Error in connection to the server. '
                            f'Please make sure you entered the URL correctly. {str(err)}')
        # Handle error responses gracefully
        if result.status_code not in {200, 201}:
            if safe:
                return None
            if result.status_code == 401:
                raise Exception('Unauthorized. Please check your API token')
            try:
                reason = result.json()
            except ValueError:
                reason = result.reason
            raise Exception(f'Error in API call. status code: {result.status_code}, reason: {reason}')

        if parse_json:
            return result.json()
        return result.content

    def search_jobs(self, payload: dict, query_type: str, version: str):
        result = self.http_request('POST', url_suffix=f'/orgs/{self.org_key}/{query_type}/search_jobs',
                                   version=version, payload=payload)
        if ('job_id' not in result) and ('query_id' not in result):
            raise Exception("An error occurred while running the query")

        return result

    def get_job_results(self, job_id, query_type, max_rows):
        result = self.http_request('GET', url_suffix=f'/orgs/{self.org_key}/{query_type}/search_jobs/{job_id}/results',
                                   version='v2', params=f'start=0&rows={max_rows}')
        return result

    def cb_query_request(self, query: str, query_type: str, time_window: int):
        result = self.http_request('GET', url_suffix=f'/orgs/{self.org_key}/processes/search_validation',
                                   version='v1', params=f'q=({query})')
        if not result('valid', False):
            raise Exception('Error in CarbonBlack ThreatHunter query')

        start_time = self.get_respective_date(time_window, self._cb_time_format)
        payload = {
            "query": query,
            "fields": ["*", "document_guid"],
            "rows": 50,
            "time_range": {
                "start": start_time
            },
            "sort": [{
                "field": "device_timestamp",
                "order": "DESC"
            }]
        }

        job_id = self.search_jobs(payload, query_type, 'v2').get('job_id', {})
        return self.get_job_results(job_id, query_type, '50')

    def cb_get_process_details_request(self, process_guid: str, document_guid: str, query_type: str = 'processes'):
        if document_guid:
            query = f"process_guid:{process_guid} AND document_guid:{document_guid}"
        else:
            query = f"process_guid:{process_guid}"
        payload = {
            "search_params": {
                "q": query,
                "cb.full_docs": True,
                "cb.all_fields": False,
                "cb.min_device_timestamp": 0,
                "rows": 500,
                "facet": False,
                "fl": "*,document_guid",
                "sort": "device_timestamp desc",
                "fq": "{!collapse field=process_collapse_id sort='max(0,legacy) asc,device_timestamp desc'}"
            }
        }

        query_id = self.search_jobs(payload, query_type, '1').get('query_id', {})
        response = self.get_job_results(query_id, query_type, '1').get('results', [])[0]
        self.delete_unnecessary_fields(response)  # Remove all unnecessary fields from result

        return response


def test_module(client: Client) -> Tuple[str, Dict, Dict]:
    """
    Performs basic get request to get item samples
    """
    result = client.http_request('GET', url_suffix=f'/orgs/{client.org_key}/processes/'
                                                   f'search_validation?q=(netconn_ipv4%3A8.8.8.8)', version='1')
    if result.get('valid', False):
        'ok', {}, {}
    raise Exception(f'CarbonBlack ThreatHunter test-module failed with: {dir(result)}')  # TODO find real reason


def cb_query(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    query = f"({str(args.get('query', ''))})"
    query_type = str(args.get('type', ''))
    time_window = int(args.get('timeWindow', 1))

    response = client.cn_query_request(client, query, query_type, time_window)
    if response.get('results'):
        md_ = tableToMarkdown('Carbon Black Threat Hunter Query Result', response['results'])
    else:
        md_ = "No result found for the given query."
    entry_context = {
        'CB.ThreatHunter.Query.Result(val["Event ID"] && val["Event ID"] == obj["Event ID"])': response['results']
    }
    return md_, entry_context, response


def cb_get_process_details(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    process_guid = str(args.get('process_guid', ''))
    document_guid = str(args.get('document_guid', ''))

    response = client.cb_get_process_details_request(client, process_guid, document_guid)

    entry_context = {'CB.ThreatHunter.Process.Details(val["Event ID"] && val["Event ID"] == obj["Event ID"])': response}

    return f'Process details for: {process_guid} retrieved successfully,', entry_context, response


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()

    org_key = str(params.get('org_key', ''))  # TODO - check origins. do not keep this secret!!
    serverurl = str(params.get('serverurl', ''))
    server = serverurl[:-1] if serverurl.endswith('/') else serverurl
    server_url = f'{server}/api/investigate/'
    token = params.get('api_token')
    app_id = params.get('app_id')
    auth_token = f'{token}/{app_id}'
    verify = not params.get('insecure', False)
    proxy = demisto.params().get('proxy') is True

    command = demisto.command()
    LOG(f'Command being called in CarbonBlack ThreatHunter is: {command}')

    try:
        client = Client(server_url=server_url, org_key=org_key, auth_token=auth_token, verify=verify, proxy=proxy)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
            'test-module': test_module,
            'cb-query': cb_query,
            'cb-get-process-details': cb_get_process_details
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
