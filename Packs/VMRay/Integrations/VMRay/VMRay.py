import requests
from CommonServerPython import *

''' GLOBAL PARAMS '''
API_KEY = demisto.params()['api_key']
SERVER = (
    demisto.params()['server'][:-1]
    if (demisto.params()['server'] and demisto.params()['server'].endswith('/'))
    else demisto.params()['server']
)
SERVER += '/rest/'
USE_SSL = not demisto.params().get('insecure', False)
HEADERS = {'Authorization': 'api_key ' + API_KEY}
ERROR_FORMAT = 'Error in API call to VMRay [{}] - {}'

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

# Remove proxy
PROXIES = handle_proxy()

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

DBOTSCORE = {
    'Malicious': 3,
    'Suspicious': 2,
    'Good': 1,
    'Blacklisted': 3,
    'Whitelisted': 1,
    'Unknown': 0,
}

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


def check_id(id_to_check):
    """Checks if parameter id_to_check is a number

    Args:
        id_to_check (int or str or unicode):

    Returns:
        bool: True if is a number, else returns error
    """
    if isinstance(id_to_check, int) or isinstance(id_to_check, (str, unicode)) and id_to_check.isdigit():
        return True
    return_error(ERROR_FORMAT.format(404, 'No such element'))


def build_errors_string(errors):
    """

    Args:
        errors (list or dict):

    Returns:
        str: error message
    """
    if isinstance(errors, list):
        err_str = str()
        for error in errors:
            err_str += error.get('error_msg') + '.\n'
    else:
        err_str = errors.get('error_msg')
    return err_str


def http_request(method, url_suffix, params=None, files=None, ignore_errors=False):
    """ General HTTP request.
    Args:
        ignore_errors (bool):
        method: (str) 'GET', 'POST', 'DELETE' 'PUT'
        url_suffix: (str)
        params: (dict)
        files: (tuple, dict)

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

    url = SERVER + url_suffix
    r = requests.request(
        method, url, params=params, headers=HEADERS, files=files, verify=USE_SSL, proxies=PROXIES
    )
    # Handle errors
    try:
        if r.status_code in {405, 401}:
            return_error(ERROR_FORMAT.format(r.status_code, 'Token may be invalid'))
        elif not is_json(r):
            raise ValueError
        response = r.json()
        if r.status_code not in {200, 201, 202, 204} and not ignore_errors:
            err = find_error(response)
            if not err:
                err = r.text
            return_error(ERROR_FORMAT.format(r.status_code, err))

        err = find_error(response)
        if err:
            if "no jobs were created" in build_errors_string(err):
                err_message = err[0].get("error_msg") + ' \nThere is a possibility this file has been analyzed ' \
                                                        'before. Please try using the command with the argument: ' \
                                                        'reanalyze=true.'
                err[0]['error_msg'] = err_message
            return_error(ERROR_FORMAT.format(r.status_code, err))
        return response
    except ValueError:
        # If no JSON is present, must be an error that can't be ignored
        return_error(ERROR_FORMAT.format(r.status_code, r.text))


def dbot_score_by_hash(analysis):
    """Gets a dict containing MD5/SHA1/SHA256/SSDeep and return dbotscore

    Args:
        analysis: (dict)

    Returns:
        dict: dbot score
    """
    hashes = ['MD5', 'SHA256', 'SHA1', 'SSDeep']
    scores = list()
    for hash_type in hashes:
        if hash_type in analysis:
            scores.append(
                {
                    'Indicator': analysis.get(hash_type),
                    'Type': 'hash',
                    'Vendor': 'VMRay',
                    'Score': DBOTSCORE.get(analysis.get('Severity', 0)),
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
        entry = dict()
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

    jobs_list = list()
    if isinstance(data, list):
        for item in data:
            jobs_list.append(build_entry(item))
    elif isinstance(data, dict):
        jobs_list = build_entry(data)
    return jobs_list


def build_finished_job(job_id, sample_id):
    entry = dict()
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
    entry_context = dict()
    entry_context['VMRay.Analysis(val.AnalysisID === obj.AnalysisID)'] = [
        {
            'AnalysisID': analysis.get('analysis_id'),
            'SampleID': analysis.get('analysis_sample_id'),
            'Severity': SEVERITY_DICT.get(analysis.get('analysis_severity')),
            'JobCreated': analysis.get('analysis_job_started'),
            'SHA1': analysis.get('analysis_sample_sha1'),
            'MD5': analysis.get('analysis_sample_md5'),
            'SHA256': analysis.get('analysis_sample_sha256'),
        }
        for analysis in analyses
    ]

    scores = list()  # type: list
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
    reanalyze = demisto.args().get('reanalyze')
    max_jobs = demisto.args().get('max_jobs')
    tags = demisto.args().get('tags')

    params = dict()
    if doc_pass:
        params['document_password'] = doc_pass
    if arch_pass:
        params['archive_password'] = arch_pass
    if sample_type:
        params['sample_type'] = sample_type

    params['shareable'] = shareable == 'true'
    params['reanalyze'] = reanalyze == 'true'

    if max_jobs:
        if isinstance(max_jobs, (str, unicode)) and max_jobs.isdigit() or isinstance(max_jobs, int):
            params['max_jobs'] = int(max_jobs)
        else:
            return_error('max_jobs arguments isn\'t a number')
    if tags:
        params['tags'] = tags
    return params


def test_module():
    """Simple get request to see if connected
    """
    response = http_request('GET', 'analysis?_limit=1')
    demisto.results('ok') if response.get('result') == 'ok' else return_error(
        'Can\'t authenticate: {}'.format(response)
    )


def upload_sample(file_id, params):
    """Uploading sample to VMRay

    Args:
        file_id (str): entry_id
        params (dict): dict of params

    Returns:
        dict: response
    """
    suffix = 'sample/submit'
    file_obj = demisto.getFilePath(file_id)
    # Ignoring non ASCII
    file_name = file_obj['name'].encode('ascii', 'ignore')
    file_path = file_obj['path']
    with open(file_path, 'rb') as f:
        files = {'sample_file': (file_name, f)}
        results = http_request('POST', url_suffix=suffix, params=params, files=files)
        return results


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

    # Request call
    raw_response = upload_sample(file_id, params=params)
    data = raw_response.get('data')
    jobs_list = list()
    jobs = data.get('jobs')
    if jobs:
        for job in jobs:
            if isinstance(job, dict):
                job_entry = dict()
                job_entry['JobID'] = job.get('job_id')
                job_entry['Created'] = job.get('job_created')
                job_entry['SampleID'] = job.get('job_sample_id')
                job_entry['VMName'] = job.get('job_vm_name')
                job_entry['VMID'] = job.get('job_vm_id')
                job_entry['JobRuleSampleType'] = job.get('job_jobrule_sampletype')
                jobs_list.append(job_entry)

    samples_list = list()
    samples = data.get('samples')
    if samples:
        for sample in samples:
            if isinstance(sample, dict):
                sample_entry = dict()
                sample_entry['SampleID'] = sample.get('sample_id')
                sample_entry['Created'] = sample.get('sample_created')
                sample_entry['FileName'] = sample.get('submission_filename')
                sample_entry['FileSize'] = sample.get('sample_filesize')
                sample_entry['SSDeep'] = sample.get('sample_ssdeephash')
                sample_entry['SHA1'] = sample.get('sample_sha1hash')
                samples_list.append(sample_entry)

    submissions_list = list()
    submissions = data.get('submissions')
    if submissions:
        for submission in submissions:
            if isinstance(submission, dict):
                submission_entry = dict()
                submission_entry['SubmissionID'] = submission.get('submission_id')
                submission_entry['SampleID'] = submission.get('submission_sample_id')
                submissions_list.append(submission_entry)

    entry_context = dict()
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
    }
    human_readable = tableToMarkdown(
        'File submitted to VMRay',
        t=table,
        headers=['Jobs ID', 'Samples ID', 'Submissions ID'],
    )

    return_outputs(
        readable_output=human_readable, outputs=entry_context, raw_response=raw_response
    )


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
            'Analysis results from VMRay for ID {}:'.format(sample_id),
            entry_context.get('VMRay.Analysis(val.AnalysisID === obj.AnalysisID)'),
            headers=['AnalysisID', 'SampleID', 'Severity']
        )
        return_outputs(human_readable, entry_context, raw_response=raw_response)
    else:
        return_outputs('#### No analysis found for sample id {}'.format(sample_id), None)


def get_analysis(sample, params=None):
    """Uploading sample to vmray

    Args:
        sample (str): sample id
        params (dict): dict of params

    Returns:
        dict: response
    """
    suffix = 'analysis/sample/{}'.format(sample)
    response = http_request('GET', suffix, params=params)
    return response


def get_submission_command():
    submission_id = demisto.args().get('submission_id')
    check_id(submission_id)
    raw_response = get_submission(submission_id)
    data = raw_response.get('data')
    if data:
        # Build entry
        entry = dict()
        entry['IsFinished'] = data.get('submission_finished')
        entry['HasErrors'] = data.get('submission_has_errors')
        entry['SubmissionID'] = data.get('submission_id')
        entry['MD5'] = data.get('submission_sample_md5')
        entry['SHA1'] = data.get('submission_sample_sha1')
        entry['SHA256'] = data.get('submission_sample_sha256')
        entry['SSDeep'] = data.get('submission_sample_ssdeep')
        entry['Severity'] = SEVERITY_DICT.get(data.get('submission_severity'))
        entry['SampleID'] = data.get('submission_sample_id')
        scores = dbot_score_by_hash(entry)

        entry_context = {
            'VMRay.Submission(val.SubmissionID === obj.SubmissionID)': entry,
            outputPaths.get('dbotscore'): scores,
        }

        human_readable = tableToMarkdown(
            'Submission results from VMRay for ID {} with severity of {}'.format(
                submission_id, entry.get('Severity', 'Unknown')
            ),
            entry,
            headers=[
                'IsFinished',
                'Severity',
                'HasErrors',
                'MD5',
                'SHA1',
                'SHA256',
                'SSDeep',
            ],
        )

        return_outputs(human_readable, entry_context, raw_response=raw_response)
    else:
        return_outputs(
            'No submission found in VMRay for submission id: {}'.format(submission_id),
            {},
        )


def get_submission(submission_id):
    """

    Args:
        submission_id (str): if of submission

    Returns:
        dict: response
    """
    suffix = 'submission/{}'.format(submission_id)
    response = http_request('GET', url_suffix=suffix)
    return response


def get_sample_command():
    sample_id = demisto.args().get('sample_id')
    check_id(sample_id)
    raw_response = get_sample(sample_id)
    data = raw_response.get('data')

    entry = dict()
    entry['SampleID'] = data.get('sample_id')
    entry['FileName'] = data.get('sample_filename')
    entry['MD5'] = data.get('sample_md5hash')
    entry['SHA1'] = data.get('sample_sha1hash')
    entry['SHA256'] = data.get('sample_sha256hash')
    entry['SSDeep'] = data.get('sample_ssdeephash')
    entry['Severity'] = SEVERITY_DICT.get(data.get('sample_severity'))
    entry['Type'] = data.get('sample_type')
    entry['Created'] = data.get('sample_created')
    entry['Classification'] = data.get('sample_classifications')
    scores = dbot_score_by_hash(entry)

    entry_context = {
        'VMRay.Sample(var.SampleID === obj.SampleID)': entry,
        outputPaths.get('dbotscore'): scores,
    }

    human_readable = tableToMarkdown(
        'Results for sample id: {} with severity {}'.format(
            entry.get('SampleID'), entry.get('Severity')
        ),
        entry,
        headers=['Type', 'MD5', 'SHA1', 'SHA256', 'SSDeep'],
    )
    return_outputs(human_readable, entry_context, raw_response=raw_response)


def get_sample(sample_id):
    """building http request for get_sample_command

    Args:
        sample_id (str, int):

    Returns:
        dict: data from response
    """
    suffix = 'sample/{}'.format(sample_id)
    response = http_request('GET', suffix)
    return response


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
        'job/{}'.format(job_id)
        if job_id
        else 'job/sample/{}'.format(sample_id)
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
    if raw_response.get('result') == 'error' or not data:
        entry = build_finished_job(job_id=job_id, sample_id=sample_id)
        human_readable = '#### Couldn\'t find a job for the {}: {}. Either the job completed, or does not exist.' \
            .format(title, vmray_id)
    else:
        entry = build_job_data(data)
        sample = entry[0] if isinstance(entry, list) else entry
        human_readable = tableToMarkdown(
            'Job results for {} id: {}'.format(title, vmray_id),
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
    suffix = 'sample/{}/threat_indicators'.format(sample_id)
    response = http_request('GET', suffix).get('data')
    return response


def get_threat_indicators_command():
    sample_id = demisto.args().get('sample_id')
    check_id(sample_id)
    raw_response = get_threat_indicators(sample_id)
    data = raw_response.get('threat_indicators')

    # Build Entry Context
    if data and isinstance(data, list):
        entry_context_list = list()
        for indicator in data:
            entry = dict()
            entry['AnalysisID'] = indicator.get('analysis_ids')
            entry['Category'] = indicator.get('category')
            entry['Classification'] = indicator.get('classifications')
            entry['ID'] = indicator.get('id')
            entry['Operation'] = indicator.get('operation')
            entry_context_list.append(entry)

        human_readable = tableToMarkdown(
            'Threat indicators for sample ID: {}. Showing first indicator:'.format(
                sample_id
            ),
            entry_context_list[0],
            headers=['AnalysisID', 'Category', 'Classification', 'Operation'],
        )

        entry_context = {'VMRay.ThreatIndicator(obj.ID === val.ID)': entry_context_list}
        return_outputs(
            human_readable, entry_context, raw_response={'threat_indicators': data}
        )
    else:
        return_outputs(
            'No threat indicators for sample ID: {}'.format(sample_id),
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
    suffix = 'analysis/{}/tag/{}'.format(analysis_id, tag)
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
    suffix = 'submission/{}/tag/{}'.format(submission_id, tag)
    response = http_request('POST', suffix)
    return response


def post_tags():
    analysis_id = demisto.args().get('analysis_id')
    submission_id = demisto.args().get('submission_id')
    tag = demisto.args().get('tag')
    if not submission_id and not analysis_id:
        return_error('No submission ID or analysis ID has been provided')
    if analysis_id:
        analysis_status = post_tags_to_analysis(analysis_id, tag)
        if analysis_status.get('result') == 'ok':
            return_outputs(
                'Tags: {} has been added to analysis: {}'.format(tag, analysis_id),
                {},
                raw_response=analysis_status,
            )
    if submission_id:
        submission_status = post_tags_to_submission(submission_id, tag)
        if submission_status.get('result') == 'ok':
            return_outputs(
                'Tags: {} has been added to submission: {}'.format(tag, submission_id),
                {},
                raw_response=submission_status,
            )


def delete_tags_from_analysis(analysis_id, tag):
    suffix = 'analysis/{}/tag/{}'.format(analysis_id, tag)
    response = http_request('DELETE', suffix)
    return response


def delete_tags_from_submission(submission_id, tag):
    suffix = 'submission/{}/tag/{}'.format(submission_id, tag)
    response = http_request('DELETE', suffix)
    return response


def delete_tags():
    analysis_id = demisto.args().get('analysis_id')
    submission_id = demisto.args().get('submission_id')
    tag = demisto.args().get('tag')
    if not submission_id and not analysis_id:
        return_error('No submission ID or analysis ID has been provided')
    if submission_id:
        submission_status = delete_tags_from_submission(submission_id, tag)
        if submission_status.get('result') == 'ok':
            return_outputs(
                'Tags: {} has been added to submission: {}'.format(tag, submission_id),
                {},
                raw_response=submission_status,
            )
    if analysis_id:
        analysis_status = delete_tags_from_analysis(analysis_id, tag)
        if analysis_status.get('result') == 'ok':
            return_outputs(
                'Tags: {} has been added to analysis: {}'.format(tag, analysis_id),
                {},
                raw_response=analysis_status,
            )


def get_iocs(sample_id):
    """

    Args:
        sample_id (str):

    Returns:
        dict: response
    """
    suffix = 'sample/{}/iocs'.format(sample_id)
    response = http_request('GET', suffix)
    return response


def get_iocs_command():
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
    raw_response = get_iocs(sample_id)
    data = raw_response.get('data', {}).get('iocs', {})

    # Initialize counters
    iocs_size = 0
    iocs_size_table = dict()
    iocs = dict()

    domains = data.get('domains')
    if domains:
        size = len(domains)
        iocs_size_table['Domain'] = size
        iocs_size += size
        iocs['Domain'] = [
            {
                'AnalysisID': domain.get('analysis_ids'),
                'Domain': domain.get('domain'),
                'ID': domain.get('id'),
                'Type': domain.get('type'),
            } for domain in domains
        ]

    ips = data.get('ips')
    if ips:
        size = len(ips)
        iocs_size_table['IP'] = size
        iocs_size += size
        iocs['IP'] = [
            {
                'AnalysisID': ip.get('analysis_ids'),
                'IP': ip.get('ip_address'),
                'ID': ip.get('id'),
                'Type': ip.get('type')
            } for ip in ips
        ]

    mutexes = data.get('mutexes')
    if mutexes:
        size = len(mutexes)
        iocs_size_table['Mutex'] = size
        iocs_size += size
        iocs['Mutex'] = [{
            'AnalysisID': mutex.get('analysis_ids'),
            'Name': mutex.get('mutex_name'),
            'Operation': mutex.get('operations'),
            'ID': mutex.get('id'),
            'Type': mutex.get('type')
        } for mutex in mutexes
        ]

    registry = data.get('registry')
    if registry:
        size = len(registry)
        iocs_size_table['Registry'] = size
        iocs_size += size
        iocs['Registry'] = [
            {
                'AnalysisID': reg.get('analysis_ids'),
                'Name': reg.get('reg_key_name'),
                'Operation': reg.get('operations'),
                'ID': reg.get('id'),
                'Type': reg.get('type'),
            } for reg in registry
        ]

    urls = data.get('urls')
    if urls:
        size = len(urls)
        iocs_size_table['URL'] = size
        iocs_size += size
        iocs['URL'] = [
            {
                'AnalysisID': url.get('analysis_ids'),
                'URL': url.get('url'),
                'Operation': url.get('operations'),
                'ID': url.get('id'),
                'Type': url.get('type'),
            } for url in urls
        ]

    files = data.get('files')
    if files:
        size = len(files)
        iocs_size_table['File'] = size
        iocs_size += size
        iocs['File'] = [
            {
                'AnalysisID': file_entry.get('analysis_ids'),
                'Filename': file_entry.get('filename'),
                'Operation': file_entry.get('operations'),
                'ID': file_entry.get('id'),
                'Type': file_entry.get('type'),
                'Hashes': get_hashed(file_entry.get('hashes'))
            } for file_entry in files
        ]

    entry_context = {'VMRay.Sample(val.SampleID === {}).IOC'.format(sample_id): iocs}
    if iocs_size:
        human_readable = tableToMarkdown(
            'Total of {} IOCs found in VMRay by sample {}'.format(iocs_size, sample_id),
            iocs_size_table,
            headers=['URLs', 'IPs', 'Domains', 'Mutexes', 'Registry', 'File'],
            removeNull=True
        )
    else:
        human_readable = '### No IOCs found in sample {}'.format(sample_id)
    return_outputs(human_readable, entry_context, raw_response=raw_response)


def main():
    try:
        COMMAND = demisto.command()
        if COMMAND == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
        elif COMMAND in ('upload_sample', 'vmray-upload-sample', 'file'):
            upload_sample_command()
        elif COMMAND == 'vmray-get-submission':
            get_submission_command()
        elif COMMAND in ('get_results', 'vmray-get-analysis-by-sample'):
            get_analysis_command()
        elif COMMAND == 'vmray-get-sample':
            get_sample_command()
        elif COMMAND in (
                'vmray-get-job-by-sample',
                'get_job_sample',
                'vmray-get-job-by-id',
        ):
            get_job_command()
        elif COMMAND == 'vmray-get-threat-indicators':
            get_threat_indicators_command()
        elif COMMAND == 'vmray-add-tag':
            post_tags()
        elif COMMAND == 'vmray-delete-tag':
            delete_tags()
        elif COMMAND == 'vmray-get-iocs':
            get_iocs_command()
    except Exception as exc:
        return_error(str(exc))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
