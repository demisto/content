import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import io
import os
import urllib3

from zipfile import ZipFile

''' GLOBAL PARAMS test test'''
API_KEY = demisto.params().get('api_key') or demisto.params().get('credentials', {}).get('password')
if not API_KEY:
    raise ValueError('The API Key parameter is required.')
SERVER = (
    demisto.params()['server'][:-1]
    if (demisto.params()['server'] and demisto.params()['server'].endswith('/'))
    else demisto.params()['server']
)
RETRY_ON_RATE_LIMIT = demisto.params().get("retry_on_rate_limit", True)
SERVER += '/rest/'
USE_SSL = not demisto.params().get('insecure', False)
PROXY = demisto.params().get("proxy", True)
HEADERS = {'Authorization': f'api_key {API_KEY}', 'User-Agent': 'Cortex XSOAR/1.1.11'}
ERROR_FORMAT = 'Error in API call to VMRay [{}] - {}'
RELIABILITY = demisto.params().get('integrationReliability', DBotScoreReliability.C) or DBotScoreReliability.C
INDEX_LOG_DELIMITER = '|'
INDEX_LOG_FILENAME_POSITION = 3

# Disable insecure warnings
urllib3.disable_warnings()

''' HELPER DICTS '''
SEVERITY_DICT = {
    'malicious': 'Malicious',
    'suspicious': 'Suspicious',
    'not_suspicious': 'Good',
    'blacklisted': 'Blacklisted',
    'whitelisted': 'Whitelisted',
    'unknown': 'Unknown',
    None: 'Unknown',
}

VERDICT_DICT = {
    'malicious': 'Malicious',
    'suspicious': 'Suspicious',
    'clean': 'Clean',
    'not_available': 'Not Available',
    None: 'Not Available',
}

DBOTSCORE = {
    'Malicious': 3,
    'Suspicious': 2,
    'Clean': 1,
    'Not Available': 0,
}

RATE_LIMIT_REACHED = 429
MAX_RETRIES = 10

''' HELPER FUNCTIONS '''


def is_json(response):
    """Checks if response is jsonable

    Args:
        response (requests.Response):

    Returns:
        bool: true if object is jsonable
    """
    try:
        response.json()
    except ValueError:
        return False
    return True


def check_id(id_to_check: int | str) -> bool:
    """Checks if parameter id_to_check is a number

    Args:
        id_to_check (int or str):

    Returns:
        bool: True if is a number, else returns error
    """
    if isinstance(id_to_check, int) or isinstance(id_to_check, str) and id_to_check.isdigit():
        return True
    raise ValueError(f"Invalid ID `{id_to_check}` provided.")


def get_billing_type(analysis_id: int) -> str | None:
    """Try to read the billing type from the analysis."""

    response = http_request("GET", f"analysis/{analysis_id}")
    if (analysis_data := response.get("data")) is not None:
        return analysis_data.get("analysis_billing_type")

    return None


def build_errors_string(errors):
    """

    Args:
        errors (list, dict or unicode):

    Returns:
        str: error message
    """
    if isinstance(errors, str):
        return str(errors)
    elif isinstance(errors, list):
        err_str = ''
        for error in errors:
            err_str += error.get('error_msg') + '.\n'
    else:
        err_str = errors.get('error_msg')
    return err_str


def http_request(method, url_suffix, params=None, files=None, get_raw=False, ignore_errors=False):
    """ General HTTP request.
    Args:
        ignore_errors (bool):
        method: (str) 'GET', 'POST', 'DELETE' 'PUT'
        url_suffix: (str)
        params: (dict)
        files: (dict)
        get_raw: (bool) return raw data instead of dict

    Returns:
        dict: response json
    """

    def find_error(may_be_error_inside):
        """Function will search for dict with 'errors' or 'error_msg' key

        Args:
            may_be_error_inside: object, any object

        Returns:
            None if no error presents
            Errors list/string if errors inside.
        """
        if isinstance(may_be_error_inside, list):
            for obj in may_be_error_inside:
                ans = find_error(obj)
                if ans:
                    return ans
            return None
        if isinstance(may_be_error_inside, dict):
            if 'error_msg' in may_be_error_inside:
                return may_be_error_inside['error_msg']
            if 'errors' in may_be_error_inside and may_be_error_inside.get('errors'):
                return may_be_error_inside['errors']
            for value in may_be_error_inside.values():
                err_r = find_error(value)
                if err_r:
                    return err_r
        return None

    def error_handler(res):  # pragma: no cover
        if res.status_code == RATE_LIMIT_REACHED and "Retry-After" in res.headers:
            return_error(f"Rate limit exceeded! Please wait {res.headers.get('Retry-After', 0)} seconds and re-run.")
        if res.status_code in {405, 401}:
            return_error(ERROR_FORMAT.format(res.status_code, 'Token may be invalid'))

    try:
        res = generic_http_request(method=method,
                                   server_url=SERVER,
                                   verify=USE_SSL,
                                   proxy=PROXY,
                                   client_headers=HEADERS,
                                   url_suffix=url_suffix,
                                   files=files,
                                   params=params,
                                   retries=MAX_RETRIES,
                                   error_handler=error_handler,
                                   resp_type='response',
                                   ok_codes=(200, 201, 202, 204),
                                   status_list_to_retry=[429])

        if not get_raw and not is_json(res):
            raise ValueError
        response = res.json() if not get_raw else res.content
        if res.status_code not in {200, 201, 202, 204} and not ignore_errors:
            if get_raw and isinstance(response, str):
                # this might be json even if get_raw is True because the API will return errors as json
                try:
                    response = json.loads(response)
                except ValueError:
                    pass
            err = find_error(response)
            if not err:
                err = res.text
            return_error(ERROR_FORMAT.format(res.status_code, err))

        err = find_error(response)
        if err:
            if "no jobs were created" in build_errors_string(err):
                err_message = err[0].get("error_msg") + '. There is a possibility this file has been analyzed ' \
                                                        'before. Please change the Analysis Caching mode for this ' \
                                                        'API key to something other than "Legacy" in the VMRay ' \
                                                        'Web Interface.'
                err[0]['error_msg'] = err_message
            return_error(ERROR_FORMAT.format(res.status_code, err))

        return response
    except ValueError:
        # If no JSON is present, must be an error that can't be ignored
        return_error(ERROR_FORMAT.format(res.status_code, res.text))
    except Exception as e:
        return_error(str(e))


def dbot_score_by_hash(data):
    """Gets a dict containing MD5/SHA1/SHA256/SSDeep and return dbotscore

    Args:
        data: (dict)

    Returns:
        list: dbot scores
    """
    hashes = ['MD5', 'SHA256', 'SHA1', 'SSDeep']
    scores = []
    for hash_type in hashes:
        if hash_type in data:
            scores.append(
                {
                    'Indicator': data.get(hash_type),
                    'Type': 'hash',
                    'Vendor': 'VMRay',
                    'Score': DBOTSCORE.get(data.get('Verdict', 0)),
                    'Reliability': RELIABILITY
                }
            )
    return scores


def build_job_data(data):
    """

    Args:
        data: any kind of object.

    Returns:
        list: list of jobs
    """

    def build_entry(entry_data):
        entry = {}
        entry['JobID'] = entry_data.get('job_id')
        entry['SampleID'] = entry_data.get('job_sample_id')
        entry['SubmissionID'] = entry_data.get('job_submission_id')
        entry['MD5'] = entry_data.get('job_sample_md5')
        entry['SHA1'] = entry_data.get('job_sample_sha1')
        entry['SHA256'] = entry_data.get('job_sample_sha256')
        entry['SSDeep'] = entry_data.get('job_sample_ssdeep')
        entry['VMName'] = entry_data.get('job_vm_name')
        entry['VMID'] = entry_data.get('job_vm_id')
        entry['Status'] = entry_data.get('job_status')
        return entry

    jobs_list = []
    if isinstance(data, list):
        for item in data:
            jobs_list.append(build_entry(item))
    elif isinstance(data, dict):
        jobs_list = build_entry(data)
    return jobs_list


def build_finished_job(job_id, sample_id):
    entry = {}
    entry['JobID'] = job_id
    entry['SampleID'] = sample_id
    entry['Status'] = 'Finished/NotExists'
    return entry


def build_analysis_data(analyses):
    """

    Args:
        analyses: (dict) of analysis

    Returns:
        dict: formatted entry context
    """
    entry_context = {}
    entry_context['VMRay.Analysis(val.AnalysisID === obj.AnalysisID)'] = [
        {
            'AnalysisID': analysis.get('analysis_id'),
            'AnalysisURL': analysis.get('analysis_webif_url'),
            'SampleID': analysis.get('analysis_sample_id'),
            'Verdict': VERDICT_DICT.get(analysis.get('analysis_verdict')),
            'VerdictReason': analysis.get('analysis_verdict_reason_description'),
            'Severity': SEVERITY_DICT.get(analysis.get('analysis_severity')),
            'JobCreated': analysis.get('analysis_job_started'),
            'SHA1': analysis.get('analysis_sample_sha1'),
            'MD5': analysis.get('analysis_sample_md5'),
            'SHA256': analysis.get('analysis_sample_sha256'),
        }
        for analysis in analyses
    ]

    scores = []  # type: list
    for analysis in entry_context:
        scores.extend(dbot_score_by_hash(analysis))
    entry_context[outputPaths['dbotscore']] = scores

    return entry_context


def build_upload_params():
    """Builds params for upload_file

    Returns:
        dict: params
    """
    # additional params
    doc_pass = demisto.args().get('document_password')
    arch_pass = demisto.args().get('archive_password')
    sample_type = demisto.args().get('sample_type')
    shareable = demisto.args().get('shareable')
    max_jobs = demisto.args().get('max_jobs')
    tags = demisto.args().get('tags')
    net_scheme_name = demisto.args().get('net_scheme_name')

    params = {}
    if doc_pass:
        params['document_password'] = doc_pass
    if arch_pass:
        params['archive_password'] = arch_pass
    if sample_type:
        params['sample_type'] = sample_type

    params['shareable'] = shareable == 'true'

    if max_jobs:
        if isinstance(max_jobs, str) and max_jobs.isdigit() or isinstance(max_jobs, int):
            params['max_jobs'] = int(max_jobs)
        else:
            raise ValueError('max_jobs arguments isn\'t a number')
    if tags:
        params['tags'] = tags
    if net_scheme_name:
        params['user_config'] = "{\"net_scheme_name\": \"" + str(net_scheme_name) + "\"}"
    return params


def test_module():
    """Simple get request to see if connected"""
    response = http_request('GET', 'analysis?_limit=1')
    if response.get('result'):
        demisto.results('ok')
    else:
        raise ValueError(f'Can\'t authenticate: {response}')


def submit(params, files=None):
    """Submit a file/URL to VMRay Platform

    Args:
        params: (dict)
        files: (dict)

    Returns:
        dict: response
    """

    suffix = 'sample/submit'
    results = http_request('POST', url_suffix=suffix, params=params, files=files)
    return results


def build_submission_data(raw_response, type_):
    """Process a submission response from VMRay Platform

    Args:
        raw_response: (dict)
        type_: (str)
    """

    data = raw_response.get('data')

    jobs_list = []
    jobs = data.get('jobs', [])
    for job in jobs:
        if isinstance(job, dict):
            job_entry = {}
            job_entry['JobID'] = job.get('job_id')
            job_entry['Created'] = job.get('job_created')
            job_entry['SampleID'] = job.get('job_sample_id')
            job_entry['VMName'] = job.get('job_vm_name')
            job_entry['VMID'] = job.get('job_vm_id')
            job_entry['JobRuleSampleType'] = job.get('job_jobrule_sampletype')
            jobs_list.append(job_entry)

    samples_list = []
    samples = data.get('samples', [])
    for sample in samples:
        if isinstance(sample, dict):
            sample_entry = {}
            sample_entry['SampleID'] = sample.get('sample_id')
            sample_entry['SampleURL'] = sample.get('sample_webif_url')
            sample_entry['Created'] = sample.get('sample_created')
            sample_entry['FileName'] = sample.get('submission_filename')
            sample_entry['FileSize'] = sample.get('sample_filesize')
            sample_entry['SSDeep'] = sample.get('sample_ssdeephash')
            sample_entry['SHA1'] = sample.get('sample_sha1hash')
            samples_list.append(sample_entry)

    submissions_list = []
    submissions = data.get('submissions', [])
    for submission in submissions:
        if isinstance(submission, dict):
            submission_entry = {}
            submission_entry['SubmissionID'] = submission.get('submission_id')
            submission_entry['SubmissionURL'] = submission.get('submission_webif_url')
            submission_entry['SampleID'] = submission.get('submission_sample_id')
            submissions_list.append(submission_entry)

    entry_context = {}
    entry_context['VMRay.Job(val.JobID === obj.JobID)'] = jobs_list
    entry_context['VMRay.Sample(val.SampleID === obj.SampleID)'] = samples_list
    entry_context[
        'VMRay.Submission(val.SubmissionID === obj.SubmissionID)'
    ] = submissions_list

    table = {
        'Jobs ID': [job.get('JobID') for job in jobs_list],
        'Samples ID': [sample.get('SampleID') for sample in samples_list],
        'Submissions ID': [
            submission.get('SubmissionID') for submission in submissions_list
        ],
        'Sample URL': [sample.get('SampleURL') for sample in samples_list],
    }
    human_readable = tableToMarkdown(
        type_ + ' submitted to VMRay',
        t=table,
        headers=['Jobs ID', 'Samples ID', 'Submissions ID', 'Sample URL'],
    )

    return_outputs(
        readable_output=human_readable, outputs=entry_context, raw_response=raw_response
    )


def encode_file_name(file_name):
    """
    encodes the file name - i.e ignoring invalid chars and removing backslashes
    Args:
        file_name (str): name of the file
    Returns: encoded file name
    """
    file_name = file_name.translate(dict.fromkeys(map(ord, "<>:\"/\\|?*")))
    return file_name.encode('utf-8', 'ignore')


def upload_sample_command():
    """Uploads a file to vmray
    """
    # Preserve BC
    file_id = (
        demisto.args().get('entry_id')
        if demisto.args().get('entry_id')
        else demisto.args().get('file_id')
    )
    params = build_upload_params()

    file_obj = demisto.getFilePath(file_id)
    # Ignoring non ASCII
    file_name = encode_file_name(file_obj['name'])
    file_path = file_obj['path']
    with open(file_path, 'rb') as f:
        files = {'sample_file': (file_name, f)}
        # Request call
        raw_response = submit(params, files=files)
        return build_submission_data(raw_response, "File")


def upload_url_command():
    """upload a URL to VMRay
    """
    args = demisto.args()
    url = args.get('url')

    if isinstance(url, str):
        url = str(url)

    params = build_upload_params()
    params['sample_url'] = url
    raw_response = submit(params)

    return build_submission_data(raw_response, "URL")


def get_analysis(sample, params=None):
    """Uploading sample to vmray

    Args:
        sample (str): sample id
        params (dict): dict of params

    Returns:
        dict: response
    """
    suffix = f'analysis/sample/{sample}'
    response = http_request('GET', suffix, params=params)
    return response


def get_analysis_command():
    sample_id = demisto.args().get('sample_id')
    check_id(sample_id)
    limit = demisto.args().get('limit')
    params = {'_limit': limit}
    raw_response = get_analysis(sample_id, params)
    data = raw_response.get('data')
    if data:
        entry_context = build_analysis_data(data)
        human_readable = tableToMarkdown(
            f'Analysis results from VMRay for ID {sample_id}:',
            entry_context.get('VMRay.Analysis(val.AnalysisID === obj.AnalysisID)'),
            headers=['AnalysisID', 'SampleID', 'Verdict', 'AnalysisURL']
        )
        return_outputs(human_readable, entry_context, raw_response=raw_response)
    else:
        return_outputs(f'#### No analysis found for sample id {sample_id}', None)


def get_submission(submission_id):
    """

    Args:
        submission_id (str): if of submission

    Returns:
        dict: response
    """
    suffix = f'submission/{submission_id}'
    response = http_request('GET', url_suffix=suffix)
    return response


def get_submission_command():
    submission_id = demisto.args().get('submission_id')
    check_id(submission_id)
    demisto.info(f"Getting submission for {submission_id}")

    try:
        raw_response = get_submission(submission_id)
    except Exception as err:
        demisto.error(str(err))
        raise err

    data = raw_response.get('data')
    if data:
        # Build entry
        entry = {}
        entry['IsFinished'] = data.get('submission_finished')
        entry['HasErrors'] = data.get('submission_has_errors')
        entry['SubmissionID'] = data.get('submission_id')
        entry['SubmissionURL'] = data.get('submission_webif_url')
        entry['MD5'] = data.get('submission_sample_md5')
        entry['SHA1'] = data.get('submission_sample_sha1')
        entry['SHA256'] = data.get('submission_sample_sha256')
        entry['SSDeep'] = data.get('submission_sample_ssdeep')
        entry['Verdict'] = VERDICT_DICT.get(data.get('submission_verdict'))
        entry['VerdictReason'] = data.get('submission_verdict_reason_description')
        entry['Severity'] = SEVERITY_DICT.get(data.get('submission_severity'))
        entry['SampleID'] = data.get('submission_sample_id')
        scores = dbot_score_by_hash(entry)

        entry_context = {
            'VMRay.Submission(val.SubmissionID === obj.SubmissionID)': entry,
            outputPaths.get('dbotscore'): scores,
        }

        human_readable = tableToMarkdown(
            'Submission results from VMRay for ID {} with verdict of {}'.format(
                submission_id, entry.get('Verdict', 'Unknown')
            ),
            entry,
            headers=[
                'IsFinished',
                'Verdict',
                'HasErrors',
                'MD5',
                'SHA1',
                'SHA256',
                'SSDeep',
                'SubmissionURL',
            ],
        )

        return_outputs(human_readable, entry_context, raw_response=raw_response)
    else:
        return_outputs(
            f'No submission found in VMRay for submission id: {submission_id}',
            {},
        )


def get_sample(sample_id):
    """building http request for get_sample_command

    Args:
        sample_id (str, int):

    Returns:
        dict: data from response
    """
    suffix = f'sample/{sample_id}'
    response = http_request('GET', suffix)
    return response


def create_sample_entry(data):
    """Construct output dict from api response data

    Args:
        data (dict):

    Returns:
        dict: entry

    """
    entry = {}
    entry['SampleID'] = data.get('sample_id')
    entry['SampleURL'] = data.get('sample_webif_url')
    entry['FileName'] = data.get('sample_filename')
    entry['MD5'] = data.get('sample_md5hash')
    entry['SHA1'] = data.get('sample_sha1hash')
    entry['SHA256'] = data.get('sample_sha256hash')
    entry['SSDeep'] = data.get('sample_ssdeephash')
    entry['Verdict'] = VERDICT_DICT.get(data.get('sample_verdict'))
    entry['VerdictReason'] = data.get('sample_verdict_reason_description')
    entry['Severity'] = SEVERITY_DICT.get(data.get('sample_severity'))
    entry['Type'] = data.get('sample_type')
    entry['Created'] = data.get('sample_created')
    entry['Classification'] = data.get('sample_classifications')
    entry['ChildSampleIDs'] = data.get('sample_child_sample_ids')
    entry['ParentSampleIDs'] = data.get('sample_parent_sample_ids')

    return entry


def get_sample_command():
    sample_id = demisto.args().get('sample_id')
    check_id(sample_id)

    # query API
    raw_response = get_sample(sample_id)

    # build response dict
    data = raw_response.get('data')
    entry = create_sample_entry(data)
    scores = dbot_score_by_hash(entry)
    entry_context = {
        'VMRay.Sample(val.SampleID === obj.SampleID)': entry,
        outputPaths.get('dbotscore'): scores,
    }

    human_readable = tableToMarkdown(
        'Results for sample id: {} with verdict {}'.format(
            entry.get('SampleID'), entry.get('Verdict', 'Unknown')
        ),
        entry,
        headers=['FileName', 'Type', 'MD5', 'SHA1', 'SHA256', 'SSDeep', 'SampleURL'],
    )
    return_outputs(human_readable, entry_context, raw_response=raw_response)


def get_sample_by_hash(hash_type, hash):
    """building http request for get_sample_by_hash_command

    Args:
        hash_type (str)
        hash (str)

    Returns:
        list[dict]: list of matching samples
    """
    suffix = f'sample/{hash_type}/{hash}'
    response = http_request('GET', suffix)
    return response


def get_sample_by_hash_command():
    hash = demisto.args().get('hash').strip()

    hash_type_lookup = {
        32: "md5",
        40: "sha1",
        64: "sha256"
    }
    hash_type = hash_type_lookup.get(len(hash))
    if hash_type is None:
        error_string = " or ".join(f"{len_} ({type_})" for len_, type_ in hash_type_lookup.items())
        raise ValueError(
            f'Invalid hash provided, must be of length {error_string}. '
            f'Provided hash had a length of {len(hash)}.'
        )

    # query API
    raw_response = get_sample_by_hash(hash_type, hash)

    # build response dict
    samples = raw_response.get('data')

    if samples:
        # VMRay outputs
        entry_context = {}
        context_key = f'VMRay.Sample(val.{hash.upper()} === obj.{hash.upper()})'
        entry_context[context_key] = [
            create_sample_entry(sample)
            for sample in samples
        ]

        # DBotScore output
        scores = []  # type: list
        for sample in entry_context[context_key]:
            scores += dbot_score_by_hash(sample)
        entry_context[outputPaths['dbotscore']] = scores

        # Indicator output
        # just use the first sample that is returned by the API for now
        entry = entry_context[context_key][0]
        file = Common.File(
            None,
            md5=entry['MD5'],
            sha1=entry['SHA1'],
            sha256=entry['SHA256'],
            ssdeep=entry['SSDeep'],
            name=entry['FileName']
        )
        entry_context.update(file.to_context())

        human_readable = tableToMarkdown(
            f'Results for {hash_type} hash {hash}:',
            entry_context[context_key],
            headers=['SampleID', 'FileName', 'Type', 'Verdict', 'SampleURL'],
        )
        return_outputs(human_readable, entry_context, raw_response=raw_response)
    else:
        return_outputs(
            f'No samples found for {hash_type} hash {hash}',
            {},
        )


def get_job(job_id, sample_id):
    """
    Args:
        sample_id (str):
        job_id (str):
    Returns:
        dict of response, if not exists returns:
        {
            'error_msg': 'No such element'
            'result': 'error'
        }
    """
    suffix = (
        f'job/{job_id}'
        if job_id
        else f'job/sample/{sample_id}'
    )
    response = http_request('GET', suffix, ignore_errors=True)
    return response


def get_job_command():
    job_id = demisto.args().get('job_id')
    sample_id = demisto.args().get('sample_id')
    if sample_id:
        check_id(sample_id)
    else:
        check_id(job_id)

    vmray_id = job_id if job_id else sample_id
    title = 'job' if job_id else 'sample'

    raw_response = get_job(job_id=job_id, sample_id=sample_id)
    data = raw_response.get('data')
    if not data or raw_response.get('result') == 'error':
        entry = build_finished_job(job_id=job_id, sample_id=sample_id)
        human_readable = '#### Couldn\'t find a job for the {}: {}. Either the job completed, or does not exist.' \
            .format(title, vmray_id)
    else:
        entry = build_job_data(data)
        sample = entry[0] if isinstance(entry, list) else entry
        human_readable = tableToMarkdown(
            f'Job results for {title} id: {vmray_id}',
            sample,
            headers=['JobID', 'SampleID', 'VMName', 'VMID'],
        )

    entry_context = {
        'VMRay.Job(val.JobID === obj.JobID && val.SampleID === obj.SampleID)': entry
    }
    return_outputs(human_readable, entry_context, raw_response=raw_response)


def get_threat_indicators(sample_id):
    """

    Args:
        sample_id (str):

    Returns:
        dict: response
    """
    suffix = f'sample/{sample_id}/threat_indicators'
    response = http_request('GET', suffix).get('data')
    return response


def get_threat_indicators_command():
    sample_id = demisto.args().get('sample_id')
    check_id(sample_id)
    raw_response = get_threat_indicators(sample_id)
    data = raw_response.get('threat_indicators')

    # Build Entry Context
    if data and isinstance(data, list):
        entry_context_list = []
        for indicator in data:
            entry = {}
            entry['AnalysisID'] = indicator.get('analysis_ids')
            entry['Category'] = indicator.get('category')
            entry['Classification'] = indicator.get('classifications')
            entry['ID'] = indicator.get('id')
            entry['Operation'] = indicator.get('operation')
            entry_context_list.append(entry)

        human_readable = tableToMarkdown(
            'Threat indicators for sample ID: {}:'.format(
                sample_id
            ),
            entry_context_list,
            headers=['ID', 'AnalysisID', 'Category', 'Classification', 'Operation'],
        )

        entry_context = {'VMRay.ThreatIndicator(obj.ID === val.ID)': entry_context_list}
        return_outputs(
            human_readable, entry_context, raw_response={'threat_indicators': data}
        )
    else:
        return_outputs(
            f'No threat indicators for sample ID: {sample_id}',
            {},
            raw_response=raw_response,
        )


def post_tags_to_analysis(analysis_id, tag):
    """

    Args:
        analysis_id (str):
        tag (str):

    Returns:
        dict:
    """
    suffix = f'analysis/{analysis_id}/tag/{tag}'
    response = http_request('POST', suffix)
    return response


def post_tags_to_submission(submission_id, tag):
    """

    Args:
        submission_id (str):
        tag (str):

    Returns:
        dict:

    """
    suffix = f'submission/{submission_id}/tag/{tag}'
    response = http_request('POST', suffix)
    return response


def post_tags():
    analysis_id = demisto.args().get('analysis_id')
    submission_id = demisto.args().get('submission_id')
    tag = demisto.args().get('tag')
    if not submission_id and not analysis_id:
        raise ValueError('No submission ID or analysis ID has been provided')
    if analysis_id:
        analysis_status = post_tags_to_analysis(analysis_id, tag)
        if analysis_status.get('result') == 'ok':
            return_outputs(
                f'Tags: {tag} has been added to analysis: {analysis_id}',
                {},
                raw_response=analysis_status,
            )
    if submission_id:
        submission_status = post_tags_to_submission(submission_id, tag)
        if submission_status.get('result') == 'ok':
            return_outputs(
                f'Tags: {tag} has been added to submission: {submission_id}',
                {},
                raw_response=submission_status,
            )


def delete_tags_from_analysis(analysis_id, tag):
    suffix = f'analysis/{analysis_id}/tag/{tag}'
    response = http_request('DELETE', suffix)
    return response


def delete_tags_from_submission(submission_id, tag):
    suffix = f'submission/{submission_id}/tag/{tag}'
    response = http_request('DELETE', suffix)
    return response


def delete_tags():
    analysis_id = demisto.args().get('analysis_id')
    submission_id = demisto.args().get('submission_id')
    tag = demisto.args().get('tag')
    if not submission_id and not analysis_id:
        raise ValueError('No submission ID or analysis ID has been provided')
    if submission_id:
        submission_status = delete_tags_from_submission(submission_id, tag)
        if submission_status.get('result') == 'ok':
            return_outputs(
                f'Tags: {tag} has been removed from submission: {submission_id}',
                {},
                raw_response=submission_status,
            )
    if analysis_id:
        analysis_status = delete_tags_from_analysis(analysis_id, tag)
        if analysis_status.get('result') == 'ok':
            return_outputs(
                f'Tags: {tag} has been removed from analysis: {analysis_id}',
                {},
                raw_response=analysis_status,
            )


def get_iocs(sample_id, all_artifacts):
    """

    Args:
        sample_id (str):

    Returns:
        dict: response
    """
    suffix = f'sample/{sample_id}/iocs'
    if all_artifacts:
        suffix += '?all_artifacts=true'
    response = http_request('GET', suffix)
    return response


def get_iocs_command():  # pragma: no cover
    def get_hashed(lst):
        """

        Args:
            lst (List[dict]): list of hashes attributes

        Returns:
            List[dict]:list of hashes attributes in demisto's favor
        """
        hashes_dict = {
            'MD5': 'md5_hash',
            'SHA1': 'sha1_hash',
            'SHA256': 'sha256_hash',
            'SSDeep': 'ssdeep_hash'
        }
        return [
            {k: hashes.get(v) for k, v in hashes_dict.items()}
            for hashes in lst
        ]

    sample_id = demisto.args().get('sample_id')
    check_id(sample_id)
    all_artifacts = demisto.args().get('all_artifacts', 'false').lower() == 'true'
    raw_response = get_iocs(sample_id, all_artifacts)
    data = raw_response.get('data', {}).get('iocs', {})

    command_results_list = []

    indicator_types = {
        # mapping of
        # VMRay artifact type -> XSOAR score type,      Indicator class, Main value key, Headers
        'Domain': (DBotScoreType.DOMAIN, Common.Domain, 'Domain', ['OriginalDomains', 'Countries']),  # noqa: E241, E501
        'EmailAddress': (DBotScoreType.EMAIL, Common.EMAIL, 'EmailAddress', ['IsRecipient', 'IsSender', 'Subjects']),
        # noqa: E241, E501
        'Email': (None, None, 'Subject', ['Subject', 'Sender', 'Recipients',  # noqa: E241, E501
                                          'NrAttachments', 'NrLinks']),
        'Filename': (None, None, 'Filename', ['Operations']),  # noqa: E241
        'File': (DBotScoreType.FILE, None, 'Filename', ['Filenames', 'MD5', 'SHA1', 'SHA256',  # noqa: E241, E501
                                                        'Operations']),
        'IP': (DBotScoreType.IP, Common.IP, 'IP', ['Domains', 'Countries', 'Protocols']),  # noqa: E241, E501
        'Mutex': (None, None, 'Name', ['Operations', 'ParentProcessesNames']),  # noqa: E241, E501
        'Process': (None, None, 'ProcessNames', ['CmdLine']),  # noqa: E241
        'Registry': (None, None, 'Name', ['ValueTypes', 'Operations',  # noqa: E241, E501
                                          'ParentProcessesNames']),
        'URL': (DBotScoreType.URL, Common.URL, 'URL', ['OriginalURLs', 'Categories',  # noqa: E241, E501
                                                       'Countries', 'Methods', 'IPAddresses',
                                                       'ParentProcessesNames']),
    }

    # this will be extended with every call to generate_results
    # we need to keep the state and always add new items to it, so that new results don't replace information from
    # older ones
    context_output = {
        'SampleID': sample_id,
        'IOC': {}
    }
    artifact_type = 'artifact' if all_artifacts else 'IOC'

    # helper function to generate the CommandResults objects from the IOC information
    def generate_results(vmray_type, objects):
        res = []
        dbot_score_type, indicator_class, key_field, headers = indicator_types[vmray_type]
        for object in objects:
            key_value = object[key_field]
            indicator = None
            if dbot_score_type == DBotScoreType.FILE:
                # special handing for File indicators since they need a hash as the indicator...
                hashes = object.get('Hashes', [{}])[0]
                dbot_score = Common.DBotScore(
                    indicator=hashes.get('MD5'),
                    indicator_type=dbot_score_type,
                    integration_name='VMRay',
                    score=DBOTSCORE.get(object['Verdict'], 0)
                )
                # ... and have multiple parameters
                indicator = Common.File(
                    dbot_score,
                    path=key_value,
                    size=object.get('FileSize'),
                    md5=hashes.get('MD5'),
                    sha1=hashes.get('SHA1'),
                    sha256=hashes.get('SHA256'),
                    ssdeep=hashes.get('SSDeep'),
                    file_type=object.get('MIMEType')
                )
            elif dbot_score_type is not None and indicator_class:
                # Generic handling for IOCs which have a corresponding Indicator type in XSOAR
                dbot_score = Common.DBotScore(
                    indicator=key_value,
                    indicator_type=dbot_score_type,
                    integration_name='VMRay',
                    score=DBOTSCORE.get(object['Verdict'], 0)
                )
                # first argument must always be the "main" value and second arg the score
                indicator = indicator_class(key_value, dbot_score)

            # fields that should be shown in human-readable output
            table_headers = [key_field, 'IsIOC'] + headers + ['Verdict', 'VerdictReason']

            # add IOC to the final context output
            if vmray_type in context_output['IOC']:
                context_output['IOC'][vmray_type].append(object)
            else:
                context_output['IOC'][vmray_type] = [object]

            if dbot_score_type == DBotScoreType.FILE:
                # for files we put the hashes manually in the readable output
                info = object.copy()
                info.update(info.get('Hashes', [{}])[0])
            else:
                info = object

            try:
                # tableToMarkdown sometimes chokes on unicode input
                readable_output = tableToMarkdown(vmray_type + " " + artifact_type, info, headers=table_headers,
                                                  removeNull=True)
            except UnicodeEncodeError:
                readable_output = " "

            res.append(CommandResults(
                outputs_prefix='VMRay.Sample',
                outputs_key_field='SampleID',
                outputs=context_output,
                readable_output=readable_output,
                indicator=indicator
            ))
        return res

    domains = data.get('domains', [])
    command_results_list.append(generate_results('Domain', [{
        'AnalysisID': domain.get('analysis_ids'),
        'Countries': domain.get('countries'),
        'CountryCodes': domain.get('country_codes'),
        'Domain': domain.get('domain'),
        'ID': 0,  # deprecated
        'IsIOC': domain.get('ioc'),
        'IOCType': domain.get('ioc_type'),
        'IpAddresses': domain.get('ip_addresses'),
        'OriginalDomains': domain.get('original_domains'),
        'ParentProcesses': domain.get('parent_processes'),
        'ParentProcessesNames': domain.get('parent_processes_names'),
        'Protocols': domain.get('protocols'),
        'Sources': domain.get('sources'),
        'Type': domain.get('type'),
        'Verdict': VERDICT_DICT.get(domain.get('verdict')),
        'VerdictReason': domain.get('verdict_reason'),
    } for domain in domains if domain.get('domain')]))

    email_addresses = data.get('email_addresses', [])
    command_results_list.append(generate_results('EmailAddress', [{
        'AnalysisID': email_address.get('analysis_ids'),
        'Classifications': email_address.get('classifications'),
        'EmailAddress': email_address.get('email_address'),
        'IsIOC': email_address.get('ioc'),
        'IsRecipient': email_address.get('recipient'),
        'IsSender': email_address.get('sender'),
        'IOCType': email_address.get('ioc_type'),
        'Subjects': email_address.get('subjects'),
        'ThreatNames': email_address.get('threat_names'),
        'Type': email_address.get('type'),
        'Verdict': VERDICT_DICT.get(email_address.get('verdict')),
        'VerdictReason': email_address.get('verdict_reason'),
    } for email_address in email_addresses if email_address.get('email_address')]))

    emails = data.get('emails', [])
    command_results_list.append(generate_results('Email', [{
        'AnalysisID': email.get('analysis_ids'),
        'AttachmentTypes': email.get('attachment_types'),
        'Classifications': email.get('classifications'),
        'Hashes': get_hashed(email.get('hashes')),
        'IsIOC': email.get('ioc'),
        'IOCType': email.get('ioc_type'),
        'NrAttachments': email.get('nr_attachments'),
        'NrLinks': email.get('nr_links'),
        'Recipients': email.get('recipients'),
        'Sender': email.get('sender'),
        'Subject': email.get('subject'),
        'ThreatNames': email.get('threat_names'),
        'Type': email.get('type'),
        'Verdict': VERDICT_DICT.get(email.get('verdict')),
        'VerdictReason': email.get('verdict_reason'),
    } for email in emails]))

    filenames = data.get('filenames', [])
    command_results_list.append(generate_results('Filename', [{
        'AnalysisID': filename.get('analysis_ids'),
        'Categories': filename.get('categories'),
        'Classifications': filename.get('classifications'),
        'Filename': filename.get('filename'),
        'IsIOC': filename.get('ioc'),
        'IOCType': filename.get('ioc_type'),
        'Operations': filename.get('operations'),
        'ThreatNames': filename.get('threat_names'),
        'Type': filename.get('type'),
        'Verdict': VERDICT_DICT.get(filename.get('verdict')),
        'VerdictReason': filename.get('verdict_reason'),
    } for filename in filenames if filename.get('filename')]))

    files = data.get('files', [])
    command_results_list.append(generate_results('File', [{
        'AnalysisID': file.get('analysis_ids'),
        'Categories': file.get('categories'),
        'Classifications': file.get('classifications'),
        'FileSize': file.get('file_size'),
        'Filename': file.get('filename'),
        'Filenames': file.get('filenames'),
        'Hashes': get_hashed(file.get('hashes')),
        'ID': 0,  # deprecated
        'IsIOC': file.get('ioc'),
        'IOCType': file.get('ioc_type'),
        'MIMEType': file.get('mime_type'),
        'Name': file.get('filename'),  # for backwards compatibility
        'NormFilename': file.get('norm_filename'),
        'Operation': file.get('operations'),  # typo
        'Operations': file.get('operations'),
        'ParentFiles': file.get('parent_files'),
        'ParentProcesses': file.get('parent_processes'),
        'ParentProcessesNames': file.get('parent_processes_names'),
        'ResourceURL': file.get('resource_url'),
        'ThreatNames': file.get('threat_names'),
        'Type': file.get('type'),
        'Verdict': VERDICT_DICT.get(file.get('verdict')),
        'VerdictReason': file.get('verdict_reason'),
    } for file in files]))

    ips = data.get('ips', [])
    command_results_list.append(generate_results('IP', [{
        'AnalysisID': ip.get('analysis_ids'),
        'Country': ip.get('country'),
        'CountryCode': ip.get('country_code'),
        'Domains': ip.get('domains'),
        'IP': ip.get('ip_address'),
        'ID': 0,  # deprecated
        'IsIOC': ip.get('ioc'),
        'IOCType': ip.get('ioc_type'),
        'Operation': None,  # deprecated
        'ParentProcesses': ip.get('parent_processes'),
        'ParentProcessesNames': ip.get('parent_processes_names'),
        'Protocols': ip.get('protocols'),
        'Sources': ip.get('sources'),
        'Type': ip.get('type'),
        'Verdict': VERDICT_DICT.get(ip.get('verdict')),
        'VerdictReason': ip.get('verdict_reason'),
    } for ip in ips if ip.get('ip_address')]))

    mutexes = data.get('mutexes', [])
    command_results_list.append(generate_results('Mutex', [{
        'AnalysisID': mutex.get('analysis_ids'),
        'Classifications': mutex.get('classifications'),
        'ID': 0,  # deprecated
        'IsIOC': mutex.get('ioc'),
        'IOCType': mutex.get('ioc_type'),
        'Name': mutex.get('mutex_name'),
        'Operation': mutex.get('operations'),  # typo
        'Operations': mutex.get('operations'),
        'ParentProcesses': mutex.get('parent_processes'),
        'ParentProcessesNames': mutex.get('parent_processes_names'),
        'ThreatNames': mutex.get('threat_names'),
        'Type': mutex.get('type'),
        'Verdict': VERDICT_DICT.get(mutex.get('verdict')),
        'VerdictReason': mutex.get('verdict_reason'),
    } for mutex in mutexes if mutex.get('mutex_name')]))

    processes = data.get('processes', [])
    command_results_list.append(generate_results('Process', [{
        'AnalysisID': process.get('analysis_ids'),
        'Classifications': process.get('classifications'),
        'CmdLine': process.get('cmd_line'),
        'ImageNames': process.get('image_names'),
        'IsIOC': process.get('ioc'),
        'IOCType': process.get('ioc_type'),
        'ParentProcesses': process.get('parent_processes'),
        'ParentProcessesNames': process.get('parent_processes_names'),
        'ProcessNames': process.get('process_names'),
        'ThreatNames': process.get('threat_names'),
        'Type': process.get('type'),
        'Verdict': VERDICT_DICT.get(process.get('verdict')),
        'VerdictReason': process.get('verdict_reason'),
    } for process in processes if process.get('process_names')]))

    registry = data.get('registry', [])
    command_results_list.append(generate_results('Registry', [{
        'AnalysisID': reg.get('analysis_ids'),
        'Classifications': reg.get('classifications'),
        'ID': 0,  # deprecated
        'IsIOC': reg.get('ioc'),
        'IOCType': reg.get('ioc_type'),
        'Name': reg.get('reg_key_name'),
        'Operation': reg.get('operations'),  # typo
        'Operations': reg.get('operations'),
        'ParentProcesses': reg.get('parent_processes'),
        'ParentProcessesNames': reg.get('parent_processes_names'),
        'ThreatNames': reg.get('threat_names'),
        'Type': reg.get('type'),
        'ValueTypes': reg.get('reg_key_value_types'),
        'Verdict': VERDICT_DICT.get(reg.get('verdict')),
        'VerdictReason': reg.get('verdict_reason'),
    } for reg in registry if reg.get('reg_key_name')]))

    urls = data.get('urls', [])
    command_results_list.append(generate_results('URL', [{
        'AnalysisID': url.get('analysis_ids'),
        'Categories': url.get('categories'),
        'ContentTypes': url.get('content_types'),
        'Countries': url.get('countries'),
        'CountryCodes': url.get('country_codes'),
        'ID': 0,  # deprecated
        'IPAddresses': url.get('ip_addresses'),
        'Methods': url.get('methods'),
        'Operation': None,  # deprecated
        'OriginalURLs': url.get('original_urls'),
        'ParentFiles': url.get('parent_files'),
        'ParentProcesses': url.get('parent_processes'),
        'ParentProcessesNames': url.get('parent_processes_names'),
        'Referrers': url.get('referrers'),
        'Source': url.get('sources'),
        'Type': url.get('type'),
        'URL': url.get('url'),
        'UserAgents': url.get('user_agents'),
        'Verdict': VERDICT_DICT.get(url.get('verdict')),
        'VerdictReason': url.get('verdict_reason'),
    } for url in urls if url.get('url')]))

    return_results(command_results_list)


def get_summary(analysis_id):
    """

    Args:
        analysis_id (str):

    Returns:
        str: response
    """
    suffix = f'analysis/{analysis_id}/archive/logs/summary_v2.json'
    response = http_request('GET', suffix, get_raw=True)
    return response


def get_screenshots(analysis_id):
    """

    Args:
        analysis_id (str):

    Returns:
        str: response
    """
    suffix = f'analysis/{analysis_id}/archive?filenames=screenshots/*'
    response = http_request('GET', suffix, get_raw=True)
    return response


def get_summary_command():
    analysis_id = demisto.args().get('analysis_id')
    check_id(analysis_id)

    billing_type = get_billing_type(analysis_id)
    if billing_type == "detector":
        raise ValueError(
            "The current billing plan has no permissions to generate or download reports. "
            "If you want more information about the sample, use "
            "`vmray-get-threat-indicators` or `vmray-get-iocs` instead."
        )

    summary_data = get_summary(analysis_id)

    file_entry = fileResult(
        filename='summary_v2.json',
        data=summary_data,
        file_type=EntryType.ENTRY_INFO_FILE
    )
    return_results(file_entry)


def get_screenshots_command():
    analysis_id = demisto.args().get('analysis_id')
    check_id(analysis_id)

    screenshots_data = get_screenshots(analysis_id)

    file_results = []
    screenshot_counter = 0
    try:
        with ZipFile(io.BytesIO(screenshots_data), 'r') as screenshots_zip:
            index_log_data = screenshots_zip.read('screenshots/index.log')
            for line in index_log_data.splitlines():
                filename = line.decode('utf-8').split(INDEX_LOG_DELIMITER)[INDEX_LOG_FILENAME_POSITION].strip()
                extension = os.path.splitext(filename)[1]
                screenshot_data = screenshots_zip.read(f'screenshots/{filename}')
                file_results.append(
                    fileResult(
                        filename=f'analysis_{analysis_id}_screenshot_{screenshot_counter}{extension}',
                        data=screenshot_data,
                        file_type=EntryType.IMAGE
                    )
                )
                screenshot_counter += 1
    except Exception as exc:  # noqa
        demisto.error(f'Failed to read screenshots.zip, error: {exc}')
        raise exc
    else:
        demisto.debug(f'Successfully read screenshots.zip, found {screenshot_counter} screenshots')

    return_results(file_results)


def vmray_get_license_usage_verdicts_command():  # pragma: no cover
    """

    Returns:
        dict: response
    """
    suffix = 'billing_info'
    raw_response = http_request('GET', suffix)
    data = raw_response.get('data')

    entry = {}
    entry['VerdictsQuota'] = data.get('verdict_quota')
    entry['VerdictsRemaining'] = data.get('verdict_remaining')
    entry['VerdictsUsage'] = round((100 / float(data.get('verdict_quota')))
                                   * (float(data.get('verdict_quota')) - float(data.get('verdict_remaining'))), 2)
    entry['PeriodEndDate'] = data.get('end_date')

    markdown = tableToMarkdown('VMRay Verdicts Quota Information', entry, headers=[
        'VerdictsQuota', 'VerdictsRemaining', 'VerdictsUsage', 'PeriodEndDate'])

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='VMRay.VerdicsQuota',
        outputs_key_field='PeriodEndDate',
        outputs=entry
    )

    return_results(results)


def vmray_get_license_usage_reports_command():  # pragma: no cover
    """

    Returns:
        dict: response
    """
    suffix = 'billing_info'
    raw_response = http_request('GET', suffix)
    data = raw_response.get('data')

    entry = {}
    entry['ReportQuota'] = data.get('report_quota')
    entry['ReportRemaining'] = data.get('report_remaining')
    entry['ReportUsage'] = round((100 / float(data.get('report_quota')))
                                 * (float(data.get('report_quota')) - float(data.get('report_remaining'))), 2)
    entry['PeriodEndDate'] = data.get('end_date')

    markdown = tableToMarkdown('VMRay Reports Quota Information', entry, headers=[
        'ReportQuota', 'ReportRemaining', 'ReportUsage', 'PeriodEndDate'])

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='VMRay.ReportsQuota',
        outputs_key_field='PeriodEndDate',
        outputs=entry
    )

    return_results(results)


def main():  # pragma: no cover
    try:
        command = demisto.command()
        if command == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
        elif command in ('upload_sample', 'vmray-upload-sample', 'file'):
            upload_sample_command()
        elif command == 'vmray-upload-url':
            upload_url_command()
        elif command == 'vmray-get-submission':
            get_submission_command()
        elif command in ('get_results', 'vmray-get-analysis-by-sample'):
            get_analysis_command()
        elif command == 'vmray-get-sample':
            get_sample_command()
        elif command == 'vmray-get-sample-by-hash':
            get_sample_by_hash_command()
        elif command in (
            'vmray-get-job-by-sample',
            'get_job_sample',
            'vmray-get-job-by-id',
        ):
            get_job_command()
        elif command == 'vmray-get-threat-indicators':
            get_threat_indicators_command()
        elif command == 'vmray-add-tag':
            post_tags()
        elif command == 'vmray-delete-tag':
            delete_tags()
        elif command == 'vmray-get-iocs':
            get_iocs_command()
        elif command == 'vmray-get-summary':
            get_summary_command()
        elif command == 'vmray-get-screenshots':
            get_screenshots_command()
        elif command == 'vmray-get-license-usage-verdicts':
            vmray_get_license_usage_verdicts_command()
        elif command == 'vmray-get-license-usage-reports':
            vmray_get_license_usage_reports_command()
    except Exception as exc:
        return_error(f"Failed to execute `{demisto.command()}` command. Error: {str(exc)}")


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
