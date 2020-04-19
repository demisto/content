from typing import Dict, Callable, Tuple, Any, Optional

import urllib3

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client to use in the Carbon Black Threat Hunter integration. Overrides BaseClient
    """
    def __init__(self, server_url: str, org_key: str, auth_token: str, verify: bool, proxy: bool):
        """

        Args:
            server_url: server url
            org_key: organization key
            auth_token: auth token, as derived from the app id and the API token.
            verify: whether to trust any certificate
            proxy: whether to run the request over a proxy
        """
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
    def calculate_respective_date(time_window: int, cb_time_format: str) -> str:
        """Calculate the respective date.

        Args:
            time_window: time window in days
            cb_time_format: CarbonBlack time format
        Returns:
            The time difference in CarbonBlack time format.
        """
        now = datetime.now()
        start_time = now - timedelta(days=int(time_window))
        return str(start_time.strftime(cb_time_format))

    def http_request(self, method: str, url_suffix: str, version: str, params: str = None, data: dict = None):
        """
        Generic request to Carbon Black Threat Hunter
        """
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
            if result.status_code == 401:
                raise Exception('Unauthorized. Please check your API token')
            try:
                reason = result.json()
            except ValueError:
                reason = result.reason
            raise Exception(f'Error in API call. status code: {result.status_code}, reason: {reason}')

        return result.json()

    def post_query_job(self, payload: dict, query_type: str, version: str) -> dict:
        """Post a query job in Threat Hunter.

        Args:
            payload: payload
            query_type: query type
            version: API version

        Returns:
            Response from API.
        """
        result = self.http_request('POST', url_suffix=f'/orgs/{self.org_key}/{query_type}/search_jobs',
                                   version=version, data=payload)
        if ('job_id' not in result) and ('query_id' not in result):
            raise Exception("An error occurred while running the query in CarbonBlack ThreatHunter.")

        return result

    def get_job_results(self, job_id: str, query_type: str, max_rows: str):
        """Get Threat Hunter job results.

        Args:
            job_id: job ID
            query_type: query type
            max_rows: max rows of the job to return

        Returns:
            Response from API.
        """
        return self.http_request('GET', url_suffix=f'/orgs/{self.org_key}/{query_type}/search_jobs/{job_id}/results',
                                 version='v2', params=f'start=0&rows={max_rows}')

    def cb_query_request(self, query: str, query_type: str, time_window: int) -> dict:
        """Query Threat Hunter.

        Args:
            query: query string
            query_type: query type
            time_window: time span for the query
        Returns:
            Response from API.
        """
        result = self.http_request('GET', url_suffix=f'/orgs/{self.org_key}/processes/search_validation',
                                   version='v1', params=f'q=({query})')
        if not result.get('valid', False):
            raise Exception('Error in CarbonBlack ThreatHunter query')

        start_time = self.calculate_respective_date(time_window, self._cb_time_format)
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

        job_id = self.post_query_job(payload, query_type, 'v2').get('job_id', {})
        return job_id

    def cb_query_status_request(self, job_id: str, query_type: str, max_rows: Optional[str] = '50') -> str:
        """Check query status.

        Args:
            job_id: job ID
            query_type: query type
            max_rows: max rows
        Returns:
            Response from API.
        """
        return self.get_job_results(job_id, query_type, max_rows)

    def cb_query_process_details_request(self, process_guid: str, document_guid: str) -> dict:
        """Query process details.

        Args:
            process_guid: process ID
            document_guid: document ID
        Returns:
            Response from API.
        """
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

        return self.post_query_job(payload, 'processes', 'v1').get('query_id', {})

    def cb_query_process_analysis_request(self, process_guid: str) -> dict:
        """Query process analysis.

        Args:
            process_guid: process ID
        Returns:
            Response from API.
        """
        payload = {
            "search_params": {
                "q": f"process_guid:{process_guid} -(legacy:true OR enriched:true)",
                "cb.full_docs": False,
                "cb.all_fields": True,
                "cb.min_device_timestamp": 0,
                "rows": 500,
                "facet": True,
                "facet.field": [],
                "facet.mincount": 1,
                "fl": "*,document_guid",
                "sort": "device_timestamp desc",
                "fq": "{!collapse field=process_collapse_id sort='max(0,legacy) asc,device_timestamp desc'}"
            }
        }

        return self.post_query_job(payload, 'processes', 'v1').get('query_id', {})

    def cb_get_watchlists_request(self) -> dict:
        """Get watchlists reports.

        Returns:
            Response from API.
        """
        self._base_url.replace('investigate', 'watchlistmgr')
        return self.http_request('GET', url_suffix='/watchlist', version='v1')

    def cb_get_watchlist_report_by_id(self, report_id: str) -> dict:
        """Get watchlists reports.

        Returns:
            Response from API.
        """
        self._base_url.replace('investigate', 'watchlistmgr')
        return self.http_request('GET', url_suffix='/report', version='v1')


def test_module(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """
    Performs basic get request to test the instance configuration.
    """
    result = client.http_request('GET', url_suffix=f'/orgs/{client.org_key}/processes/'
                                                   f'search_validation?q=(netconn_ipv4%3A8.8.8.8)', version='v1')
    if result.get('valid', False):
        return 'ok', {}, {}
    raise Exception(f'CarbonBlack ThreatHunter test-module failed with: {dir(result)}')  # TODO find real reason


def cb_query(client: Client, args: dict) -> Tuple[Any, Dict, Dict]:
    """Query Threat Hunter.

    Args:
        client: Client object with request.
        args: Usually demisto.args()
    Returns:
        Demisto Outputs.
    """
    query = f"({str(args.get('query', ''))})"
    query_type = str(args.get('type', ''))
    try:
        time_window = int(args.get('time_window', 1))
    except ValueError:
        raise Exception('time_window argument must receive an integer, e.g: 4.')

    job_id = client.cb_query_request(query, query_type, time_window)

    md_ = f'Query for: {query_type} with Job ID: {job_id} was submitted to Carbon Black Threat Hunter successfully.'
    ec_ = {'JobID': job_id, 'Status': 'Pending'}
    entry_context = {'CB.ThreatHunter.Query(val.JobID == obj.JobID)': ec_}

    return md_, entry_context, job_id


def cb_check_query_status(client: Client, args: dict) -> Tuple[Any, Dict, Dict]:
    """Check query status.

    Args:
        client: Client object with request.
        args: Usually demisto.args()
    Returns:
        Demisto Outputs.
    """
    job_id = str(args.get('job_id', ''))
    query_type = str(args.get('type', ''))

    response = client.cb_query_status_request(job_id, query_type)

    if 'contacted' not in response or 'completed' not in response:
        raise Exception("An error occurred with job result query.")
    contacted = int(response.get('contacted', 0))
    completed = int(response.get('completed', 0))
    if contacted and completed and contacted == completed:
        status = 'Completed'
    else:
        status = 'Pending'

    md_ = f'Query status for: {query_type} with Job ID: {job_id} is: {status}.'
    ec_ = {'JobID': job_id, 'Status': status}
    entry_context = {'CB.ThreatHunter.Query(val.JobID == obj.JobID)': ec_}

    return md_, entry_context, job_id


def cb_get_query_results(client: Client, args: dict) -> Tuple[Any, Dict, Dict]:
    """Get query results.

    Args:
        client: Client object with request.
        args: Usually demisto.args()
    Returns:
        Demisto Outputs.
    """
    job_id = str(args.get('job_id', ''))
    query_type = str(args.get('type', ''))

    response = client.cb_query_status_request(job_id, query_type)
    if 'contacted' not in response or 'completed' not in response:
        raise Exception("An error occurred with job result query.")
    contacted = int(response.get('contacted', 0))
    completed = int(response.get('completed', 0))
    if contacted and completed and contacted == completed:
        status = 'Completed'
    else:
        status = 'Pending'

    if status == 'Pending':
        md_ = f'Results for query with Job ID: {job_id} are not available yet.'
        ec_ = {'JobID': job_id, 'Status': status}
        entry_context = {'CB.ThreatHunter.Query(val.JobID == obj.JobID)': ec_}
    else:
        if response.get('results'):
            results = response.get('results', {})
            md_ = tableToMarkdown('Carbon Black Threat Hunter Query Results:', t=results)
            # TODO - add a prettify for the ec obj
            entry_context = {'CB.ThreatHunter.Query(val.JobID == obj.JobID)': results}
        else:
            md_ = f'No results found for the given query: {job_id}.'
            entry_context = {'CB.ThreatHunter.Query(val.JobID == obj.JobID)': response}

    return md_, entry_context, response


def cb_query_process_details(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Get process details.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    process_guid = str(args.get('process_guid', ''))
    document_guid = str(args.get('document_guid', ''))

    query_id = client.cb_query_process_details_request(process_guid, document_guid)

    md_ = f'Query for process details with Query ID: {query_id} ' \
          f'was submitted to Carbon Black Threat Hunter successfully.'
    ec_ = {'QueryID': query_id, 'Status': 'Pending'}
    entry_context = {'CB.ThreatHunter.Process(val.QueryID == obj.QueryID)': ec_}

    return md_, entry_context, query_id


def cb_query_process_analysis(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Get process analysis.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    process_guid = str(args.get('process_guid', ''))

    query_id = client.cb_query_process_analysis_request(process_guid)

    md_ = f'Query for process analysis with Query ID: {query_id} ' \
          f'was submitted to Carbon Black Threat Hunter successfully.'
    ec_ = {'QueryID': query_id, 'Status': 'Pending'}
    entry_context = {'CB.ThreatHunter.Process(val.QueryID == obj.QueryID)': ec_}

    return md_, entry_context, query_id


def cb_check_query_process_status(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Check process query status.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    query_id = str(args.get('query_id', ''))

    response = client.cb_query_status_request(query_id, 'processes', '1')

    if 'contacted' not in response or 'completed' not in response:
        raise Exception("An error occurred with job result query.")
    contacted = int(response.get('contacted', 0))
    completed = int(response.get('completed', 0))
    if contacted and completed and contacted == completed:
        status = 'Completed'
    else:
        status = 'Pending'

    md_ = f'Query status for process with Query ID: {query_id} is: {status}.'
    ec_ = {'QueryID': query_id, 'Status': status}
    entry_context = {'CB.ThreatHunter.Process(val.QueryID == obj.QueryID)': ec_}

    return md_, entry_context, query_id


def cb_get_query_process_results(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Get process query results.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    query_id = str(args.get('query_id', ''))

    response = client.cb_query_status_request(query_id, 'processes')

    if 'contacted' not in response or 'completed' not in response:
        raise Exception("An error occurred with job result query.")
    contacted = int(response.get('contacted', 0))
    completed = int(response.get('completed', 0))
    if contacted and completed and contacted == completed:
        status = 'Completed'
    else:
        status = 'Pending'

    if status == 'Pending':
        md_ = f'Results for query with Query ID: {query_id} are not available yet.'
        ec_ = {'QueryID': query_id, 'Status': status}
        entry_context = {'CB.ThreatHunter.Query(val.QueryID == obj.QueryID)': ec_}
    else:
        if response.get('results'):
            if isinstance(response.get('results'), list):
                results = response.get('results', [])[0]
            else:
                results = response.get('results')
            delete_unnecessary_fields(results)  # Remove all unnecessary fields from result
            md_ = tableToMarkdown('Carbon Black Threat Hunter Process Query Results:', t=results)
            # TODO - add a prettify for the ec obj
            entry_context = {'CB.ThreatHunter.Process(val.QueryID == obj.QueryID)': results}
        else:
            md_ = f'No results where retrieved from Carbon Black Threat Hunter for the given process query: {query_id}.'
            entry_context = {'CB.ThreatHunter.Process(val.QueryID == obj.QueryID)': response}

    return md_, entry_context, response


def delete_unnecessary_fields(response: dict):
    """Delete unnecessary fields from the response.

    Args:
        response: the response dictionary.
    """
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


def cb_get_watchlist_reports(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """Get watchlists reports.

    Args:
        client: Client object with request.

    Returns:
        Demisto Outputs.
    """
    response = client.cb_get_watchlists_request()

    if 'results' not in response:
        raise Exception('Watchlists reports are not available')

    result = []
    watchlists = response.get('results', {})
    for watchlist in watchlists:
        temp_dict = {}
        report = watchlist.get('report', {})
        if report:
            temp_dict['WatchlistName'] = report.get('name')
            report_ids = report.get('report_ids')
            temp_dict['Reports'] = []
            for report_id in report_ids:
                report = client.cb_get_watchlist_report_by_id(report_id)
                temp_dict['Reports'].append(report)
            result.append(temp_dict)

    md_ = tableToMarkdown('Carbon Black Threat Hunter Watchlists:', t=result)
    entry_context = {'CB.ThreatHunter.Watchlists': result}

    return md_, entry_context, response


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
            'cb-check-query-status': cb_check_query_status,
            'cb-get-query-results': cb_get_query_results,
            'cb-query-process-details': cb_query_process_details,
            'cb-query-process-analysis': cb_query_process_analysis,
            'cb-check-query-process-status': cb_check_query_process_status,
            'cb-get-query-process-results': cb_get_query_process_results,
            'cb-get-watchlist-reports': cb_get_watchlist_reports,
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
