import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Any, Dict, Tuple
import json
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
# Setting global params, initiation in main() function
TOKEN: str = ''
SERVER: str = ''
USE_SSL: bool = False
BASE_URL: str = ''
HEADERS: dict = dict()
PROXIES: dict or None = None

''' HELPER FUNCTIONS '''
FILE_HASHES: tuple = ('md5', 'ssdeep', 'sha1', 'sha256')  # hashes as described in API


def http_request(method: str, url_suffix: str, params: dict = None, data: dict = None, proxies: list = None,
                 headers: dict = None, file_obj: Tuple = None):
    """Basic HTTP Request wrapper

    Args:
        method: Method to use: ['GET', 'POST', 'PUT', 'DELETE']
        url_suffix: suffix to add to SERVER param
        params: dict to use in url query
        data: body of request
        proxies: list of proxies to use
        headers: dict of headers
        file_obj: Tuple of (`file name`. file_obj)

    Returns:
        Response.json: Response from API
    """
    # A wrapper for requests lib to send our requests and handle requests and responses better
    err_msg = 'Error in API call to DataEnrichmentThreatIntelligence Integration [{}] - {}'
    if proxies is None:
        proxies = PROXIES
    if headers is None:
        headers = HEADERS

    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=headers,
        proxies=proxies,
        file=file_obj
    )
    # Handle error responses gracefully
    if res.status_code not in {200}:
        return_error(err_msg.format(res.status_code, res.reason))
    try:
        return res.json()
    except ValueError as e:
        return_error(err_msg.format(res.status_code, res.reason), error=str(e))


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('GET', 'analysis')


def upload_file_request(file_name: str, file_path: str, is_public: bool) -> Dict:
    """Uploads file

    Args:
        file_path: path to file
        file_name: name of file
        is_public: is public flag

    Returns:
        Dict: response data
    """
    # The service endpoint to request from
    suffix: str = 'upload'
    # Dictionary of params for the request
    params = {
        'publish': is_public
    }
    # Send a request using our http_request wrapper
    response = http_request('POST', suffix, params, file_obj=(file_name, file_path))
    # Return results
    return response.get('results')


def upload_file_command():
    """
    Gets details about a raw_response using IDs or some other filters
    """
    # Initialize main vars
    context: dict = dict()
    # Get arguments from user
    entry_id: str = demisto.args().get('entry_id')
    is_public: bool = demisto.args().get('is_public') == 'true'
    # Get file from entry
    file_obj = demisto.getFilePath(entry_id)
    file_path = file_obj['path']
    file_name = file_obj['name']
    # Make request and get raw response
    raw_response: Dict = upload_file_request(file_name, file_path, is_public)
    # Parse response into context & content entries
    if raw_response:
        title = f'DataEnrichmentThreatIntelligence - Uploading file: {file_name}'

        context_entries = {
            'ID': raw_response.get('id'),  # ID of job,
            'IsFinished': raw_response.get('is_finished'),
            'CreatedDate': raw_response.get('createdDate'),
            'Analysis': raw_response.get('analysis')
        }

        context['DataEnrichmentThreatIntelligence.Job(val.ID && val.ID === obj.ID)'] = context_entries
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entries, removeNull=True)
        # Return data to Demisto
        return_outputs(human_readable, context, raw_response)
    else:
        err_msg = f'DataEnrichmentThreatIntelligence: Could not upload file with entry ID: {entry_id}'
        return_error(err_msg)


def get_job_request(job_id: str) -> Dict:
    suffix = 'job'
    params = {
        'job_id': job_id
    }
    return http_request('GET', suffix, params=params).get('results')


def get_job_command():
    """Gets job from API. Used mostly for polling playbook

    """
    job_id: str = demisto.args().get('job_id')
    raw_response = get_job_request(job_id)
    if raw_response:
        title = f'DataEnrichmentThreatIntelligence - Job results for job ID: {job_id}'
        context_entry = {
            'ID': raw_response.get('job_id'),
            'IsFinished': raw_response.get('is_finished')
        }
        context = {
            'DataEnrichmentThreatIntelligence.Job(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry, removeNull=True)
        return_outputs(human_readable, context, raw_response)
    else:
        return_error(f'DataEnrichmentThreatIntelligence: Could not get job from job ID: {job_id}')


def get_analysis_request(analysis_id: str):
    suffix: str = 'analysis'
    params = {
        'analysis_id': analysis_id
    }
    return http_request('GET', suffix, params=params).get('results')


def get_analysis_command():
    analysis_id = demisto.args().get('analysis_id')
    raw_response = get_analysis_request(analysis_id)
    if raw_response:
        title = f'DataEnrichmentThreatIntelligence - Analysis results for analysis ID: {analysis_id}'
        context_entry = {
            'ID': raw_response.get('id'),
            'Severity': raw_response.get('severity'),
            'MD5': raw_response.get('md5'),
            'SHA1': raw_response.get('sha1'),
            'SHA256': raw_response.get('sha256'),
            'SSDeep': raw_response.get('ssdeep')
        }
        # Building a score for DBot
        dbot_score = [
            {
                'Indicator': raw_response.get(hash_name),
                'Type': 'hash',
                'Vendor': 'DataEnrichmentThreatIntelligence',
                'Score': raw_response.get('Severity', 0),  # If severity is equal to out DBotScore
            } for hash_name in FILE_HASHES if raw_response.get(hash_name)
        ]
        context = {
            outputPaths['dbotscore']: dbot_score,
            'DataEnrichmentThreatIntelligence.Analysis(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry, removeNull=True)
        return_outputs(human_readable, context, raw_response)
    else:
        return_error(f'DataEnrichmentThreatIntelligence: Could not get analysis ID: {analysis_id}')


def close_event_command():
    pass


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))


def main():
    # Declare global parameters
    global TOKEN, SERVER, USE_SSL, BASE_URL, HEADERS, PROXIES
    TOKEN = demisto.params().get('api_key')
    # Remove trailing slash to prevent wrong URL path to service
    SERVER = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
    # Should we use SSL
    USE_SSL = not demisto.params().get('insecure', False)
    # Service base URL
    BASE_URL = SERVER + '/api/v2.0/'
    # Headers to be sent in requests
    HEADERS = {
        'Authorization': f'Bearer {TOKEN}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    # Remove proxy if not set to true in params
    PROXIES = handle_proxy()
    command: str = demisto.command()
    try:
        if command == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
            demisto.results('ok')
        elif command == 'data-enrichment-threat-intelligence-upload-file':
            upload_file_command()
        elif command == 'data-enrichment-threat-intelligence-get-job':
            get_job_command()
        elif command == 'data-enrichment-threat-intelligence-get-analysis':
            get_analysis_command()
        elif command == 'data-enrichment-threat-intelligence-close-event':
            close_event_command()
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in DataEnrichmentThreatIntelligence Integration [{e}]'
        return_error(err_msg, error=str(e))


if __name__ == '__builtin__':
    main()
