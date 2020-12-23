
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_HOST = "https://api.twinwave.io"
API_VERSION = "v1"
EXPIRE_SECONDS = 86400


class AuthenticationException(Exception):
    pass


class Client(BaseClient):
    """
        Client to connect to the API
    """

    def __init__(self, api_token, verify, proxy, host=API_HOST, version=API_VERSION):
        self.host = f"{host}/{version}"
        self.api_token = api_token
        self._verify = verify
        self._proxy = proxy

    def get_token(self):
        auth_url = f"{self.host}/accesstoken"
        resp = requests.get(auth_url, verify=self._verify, proxies=self._proxy)
        if resp.ok:
            return resp.json()
        else:
            raise AuthenticationException("Error getting access token, Please check the username and password")

    def get_header(self):
        return {'X-API-KEY': self.api_token}

    def get_recent_jobs(self, num_jobs=10, username=None, source=None, state=None):
        url = f"{self.host}/jobs/recent"
        params = {}
        params["count"] = num_jobs
        if username:
            params["username"] = username
        if source:
            params["source"] = source
        if state:
            params["state"] = state
        resp = requests.get(url, params=params, headers=self.get_header(), verify=self._verify,
                            proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def get_engines(self):
        url = f"{self.host}/engines"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def get_job(self, job_id):
        url = f"{self.host}/jobs/{job_id}"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def get_task_normalized_forensics(self, job_id, task_id):
        url = f"{self.host}/jobs/{job_id}/tasks/{task_id}/forensics"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def get_job_normalized_forensics(self, job_id):
        url = f"{self.host}/jobs/{job_id}/forensics"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def get_task_raw_forensics(self, job_id, task_id):
        url = f"{self.host}/jobs/{job_id}/tasks/{task_id}/rawforensics"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)

        # do not raise an exception for 404
        if resp.status_code == 404:
            return resp.json()
        resp.raise_for_status()
        return resp.json()

    def submit_url(self, scan_url, engine_list=[], parameters=None, priority=None, profile=None):
        url = f"{self.host}/jobs/urls"
        req = {"url": scan_url, "engines": engine_list, "parameters": parameters}
        if priority:
            req['priority'] = priority
        if profile:
            req['profile'] = profile

        resp = requests.post(url, json=req, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def submit_file(self, file_name, file_obj, engine_list=[], priority=None, profile=None):
        url = f"{self.host}/jobs/files"
        payload = {}
        file_dict = {"filedata": file_obj}
        payload["engines"] = (None, json.dumps(engine_list))
        payload['filename'] = (None, file_name)
        payload['priority'] = priority
        payload['profile'] = profile

        resp = requests.post(url, data=payload, files=file_dict, headers=self.get_header(), verify=self._verify,
                             proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def resubmit_job(self, job_id):
        url = f"{self.host}/jobs/{job_id}/reanalyze"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def download_submitted_resources(self, job_id, sha256):
        url = f"{self.host}/jobs/{job_id}/resources/{sha256}"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp

    def get_temp_artifact_url(self, path):
        url = f"{self.host}/jobs/artifact/url?path={path}"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def search_across_jobs_and_resources(self, term, field, count, shared_only, submitted_by, timeframe, page, type):
        query_params = {}
        if term:
            query_params['term'] = term
        if field:
            query_params['field'] = field
        if count:
            query_params['count'] = count
        if shared_only:
            query_params['shared_only'] = shared_only
        if submitted_by:
            query_params['submitted_by'] = submitted_by
        if timeframe:
            query_params['timeframe'] = timeframe
        if page:
            query_params['page'] = page
        if type:
            query_params['type'] = type
        url = f"{self.host}/jobs/search"
        resp = requests.get(url, headers=self.get_header(), params=query_params, verify=self._verify,
                            proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        header = get_engines(client)
        if header:
            return 'ok'
        else:
            return_error('Authentication failed! Please check the username and password before continuing.')
    except Exception:
        return_error('Authentication failed! Please check the username and password before continuing.')


def get_engines(client):
    """
        List of engines
    """
    result = client.get_engines()
    # readable output will be in markdown format
    readable_output = '## List of Engines\n'
    readable_output += tableToMarkdown('Twinwave Engines', result, headers=['Name', 'SupportedTypes', 'DefaultEnabled'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Twinwave.Engines",
        outputs_key_field='Name',
        outputs=result,
        raw_response=result  # raw response - the original response
    )


def validate_priority(priority):
    int_priority = 0
    validate_string = "Validation failed. Please make sure the priority is a numeric value within 1-225"
    if priority:
        if not priority.isnumeric():
            return_error(validate_string)
        else:
            try:
                int_priority = int(priority)
            except ValueError:
                return_error(validate_string)

            if int_priority <= 0 or int_priority >= 256:
                return_error(validate_string)
    else:
        return_error(validate_string)

    return int_priority


def submit_url(client, args):
    """
        Submit the URL
    """
    url = args.get('url')
    engines = args.get('engines')
    parameters = args.get('parameters')
    priority = args.get('priority', 10)
    profile = args.get('profile')

    # validation for priority
    priority = validate_priority(priority)

    # validate the url
    regex_matches = re.match(urlRegex, url)
    if regex_matches:
        # passing the validated url into the search
        result = client.submit_url(scan_url=regex_matches.group(0), engine_list=engines, parameters=parameters,
                                   priority=priority, profile=profile)

        # readable output will be in markdown format
        readable_output = '## Submitted URL\n'
        readable_output += tableToMarkdown('Twinwave Submissions', result, headers=['JobID'])
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="Twinwave.Submissions",
            outputs_key_field='JobID',
            outputs=result,
            raw_response=result  # raw response - the original response
        )

    return_error("Validation Failed. Please check the format of the submitted URL")


def submit_file(client, args):
    """
        Submit the URL
    """
    file_entry_id = args.get('entry_id')
    file_path = demisto.getFilePath(file_entry_id)['path']
    file_name = demisto.getFilePath(file_entry_id)['name']
    priority = args.get('priority', 10)
    profile = args.get('profile')

    # validation for priority
    priority = validate_priority(priority)

    with open(file_path, 'rb') as file:
        result = client.submit_file(file_name=file_name, file_obj=file.read(), priority=priority, profile=profile)

    readable_output = '## Submitted File\n'
    readable_output += tableToMarkdown('Twinwave Submissions', result,
                                       headers=['JobID'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Twinwave.Submissions",
        outputs_key_field='JobID',
        outputs=result,
        raw_response=result  # raw response - the original response
    )


def resubmit_job(client, args):
    """
        Re submit a job
    """
    job_id = args.get('job_id')

    result = client.resubmit_job(job_id=job_id)
    # readable output will be in markdown format
    readable_output = '## Resubmitted Job'
    readable_output += tableToMarkdown('Twinwave Submissions', result, headers=['JobID'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Twinwave.Submissions",
        outputs_key_field='JobID',
        outputs=result,
        raw_response=result  # raw response - the original response
    )


def list_recent_jobs(client, args):
    incidents = []
    last_run = demisto.getLastRun()
    jobs = []

    count = args.get('first_fetch', 10)
    state = args.get('state')
    username = args.get('username')
    source = args.get('source')
    if source == 'all':
        source = None

    # initial fetch
    if not last_run:
        jobs = client.get_recent_jobs(num_jobs=count, state=state, username=username, source=source)
    else:
        max_fetch = min(int(args.get('max_fetch', 50)), 200)
        # logic to fetch the incidents from the last run onwards
        # retrieving 50 incidents at a time assuming
        # there will not be 50 events submitted concurrently within a 1 min period
        retrieved_jobs = client.get_recent_jobs(num_jobs=max_fetch, state=state, username=username, source=source)
        for job in retrieved_jobs:
            # comparing the time to see if the last fetch time is less than or equal
            # to the incidents that are being fetched
            # if last fetch time is lower, will fetch the incidents
            if int(date_to_timestamp(job.get('CreatedAt'), date_format=DATE_FORMAT)) <= int(
                    last_run.get('last_created_at')):
                break
            else:
                jobs.append(job)

    for job in jobs:
        incident = {
            'name': job.get('ID'),
            'occurred': job['CreatedAt'],
            'rawJSON': json.dumps(job)
        }
        incidents.append(incident)
    # set the last run
    if jobs:
        # access the first of the array and set the start date and time to last run
        demisto.setLastRun({
            'last_created_at': date_to_timestamp(jobs[0].get('CreatedAt'), date_format=DATE_FORMAT)
        })

    # return the incidents
    return incidents


def search_across_jobs_and_resources(client, args):
    """
        Search across jobs and resources
    """
    term = args.get('term')
    field = args.get('field')
    type = args.get('type')
    count = args.get('count')
    shared_only = args.get('shared_only')
    submitted_by = args.get('submitted_by')
    timeframe = args.get('timeframe')
    page = args.get('page')
    result = client.search_across_jobs_and_resources(term=term, field=field, type=type, count=count,
                                                     shared_only=shared_only, submitted_by=submitted_by,
                                                     timeframe=timeframe, page=page)
    readable_output = '## Search Across Jobs and Resources \n'
    readable_output += tableToMarkdown('Jobs and Resources', result.get('Jobs'),
                                       headers=[])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Twinwave.JobsAndResources",
        outputs_key_field='Jobs.ID',
        outputs=result,
        raw_response=result  # raw response - the original response
    )


def get_job_summary(client, args):
    """
        Job Summary
    """
    job_id = args.get('job_id')
    result = client.get_job(job_id=job_id)
    command_results = []
    # Setting the DbotScore
    twinwave_score = round(float(result.get('Score')) * 100, 2)
    if twinwave_score >= 70:
        score = Common.DBotScore.BAD
    elif twinwave_score >= 30:
        score = Common.DBotScore.SUSPICIOUS
    else:
        score = Common.DBotScore.GOOD

    submission = result.get('Submission')
    resources = result.get('Resources')
    tasks = result.get('Tasks')
    # created_at = result.get('CreatedAt')

    readable_output = '## Job Summary\n'

    # check if the job is a file
    if submission.get('SHA256'):
        size = None

        # if Twinwave scan is not completed, don't set the DBotScore
        if result.get('State') == 'done':
            # extracting more information from the job
            if resources:
                for resource in resources:
                    file_metadata = resource.get('FileMetadata')
                    if file_metadata:
                        if file_metadata.get('SHA256') == submission.get('SHA256'):
                            size = file_metadata.get('Size')

            dbot_score = Common.DBotScore(
                indicator=submission.get('SHA256'),
                indicator_type=DBotScoreType.FILE,
                integration_name='Twinwave',
                score=score
            )

            file = Common.File(
                name=submission.get('Name'),
                md5=submission.get('MD5'),
                sha256=submission.get('SHA256'),
                size=size,
                dbot_score=dbot_score
            )
            command_results.append(CommandResults(
                readable_output=tableToMarkdown("New file indicator was added", file.to_context()),
                indicator=file
            ))
        # Adding the SHA256 to the Result
        result['SHA256'] = submission.get('SHA256')
        result['DisplayScore'] = twinwave_score
        readable_output += tableToMarkdown('Twinwave Job Summary', result,
                                           headers=['ID', 'SHA256', 'State', 'DisplayScore', 'ResourceCount',
                                                    'CreatedAt'])
    # check if the job is a URL
    else:
        # if Twinwave scan is not completed, don't set the DBotScore
        if result.get('State') == 'done':
            detection_engines = set()
            positive_engines = set()

            for task in tasks:
                detection_engines.add(task.get('Engine'))
                if task.get('Results') and task.get('Results').get('Score') > 0:
                    positive_engines.add(task.get('Engine'))

            dbot_score = Common.DBotScore(
                indicator=submission.get('Name'),
                indicator_type=DBotScoreType.URL,
                integration_name='Twinwave',
                score=score
            )

            url = Common.URL(
                url=submission.get('Name'),
                detection_engines=list(detection_engines),
                dbot_score=dbot_score
            )

            command_results.append(CommandResults(
                readable_output=tableToMarkdown("New URL indicator was added", url.to_context()),
                indicator=url
            ))
        # Adding the URL to the Result
        result['URL'] = submission.get('Name')
        # Adding the DisplayScore to the result
        result['DisplayScore'] = twinwave_score
        readable_output += tableToMarkdown('Twinwave Job Summary', result,
                                           headers=['ID', 'URL', 'State', 'DisplayScore',
                                                    'ResourceCount', 'CreatedAt'])
    command_results.append(CommandResults(
        readable_output=readable_output,
        outputs_prefix="Twinwave.JobSummary",
        outputs_key_field='ID',
        outputs=result,
        raw_response=result,  # raw response - the original response
    ))
    return command_results


def get_job_normalized_forensics(client, args):
    """
        Job Normalized Forensics
    """
    job_id = args.get('job_id')
    result = client.get_job_normalized_forensics(job_id=job_id)
    # adding the job id to the results
    if result and isinstance(result, dict):
        result['JobID'] = job_id
    # readable output will be in markdown format
    readable_output = '## Normalized Forensics\n'
    readable_output += tableToMarkdown('Twinwave Job Normalized Forensics', result,
                                       headers=['JobID', 'Version', 'Engine', 'DisplayScore', 'Verdict', 'StartTime',
                                                'EndTime'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Twinwave.JobNormalizedForensics",
        outputs_key_field='JobID',
        outputs=result,
        raw_response=result  # raw response - the original response
    )


def get_task_normalized_forensics(client, args):
    """
        Task Normalized Forensics
    """
    job_id = args.get('job_id')
    task_id = args.get('task_id')
    result = client.get_task_normalized_forensics(job_id=job_id, task_id=task_id)
    # adding the job id and task id to the results
    if result and isinstance(result, dict):
        result['TaskID'] = task_id
        result['JobID'] = job_id
    # readable output will be in markdown format
    readable_output = '## Normalized Forensics\n'
    readable_output += tableToMarkdown('Twinwave Task Normalized Forensics', result,
                                       headers=['JobID', 'TaskID', 'Version', 'Engine', 'DisplayScore', 'Verdict',
                                                'StartTime', 'EndTime'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Twinwave.TaskNormalizedForensics",
        outputs_key_field='TaskID',
        outputs=result,
        raw_response=result  # raw response - the original response
    )


def get_task_raw_forensics(client, args):
    """
        Task Raw Forensics
    """
    job_id = args.get('job_id')
    task_id = args.get('task_id')
    result = client.get_task_raw_forensics(job_id=job_id, task_id=task_id)
    # adding the job id and task id to the results
    if result and isinstance(result, dict):
        result['TaskID'] = task_id
        result['JobID'] = job_id
    # readable output will be in markdown format
    readable_output = '## Raw Forensics\n'
    readable_output += tableToMarkdown('Twinwave Task Raw Forensics', result,
                                       headers=[])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Twinwave.TaskRawForensics",
        outputs_key_field='TaskID',
        outputs=result,
        raw_response=result  # raw response - the original response
    )


def download_submitted_resource(client, args):
    """
        Download submitted resource
    """
    job_id = args.get('job_id')
    sha256 = args.get('sha256')
    result = client.download_submitted_resources(job_id=job_id, sha256=sha256)
    return fileResult("resources.zip", data=result.content)


def get_temp_artifact_url(client, args):
    """
        Get Temp Artifact URL
    """
    path = args.get('path')
    result = client.get_temp_artifact_url(path=path)
    # readable output will be in markdown format
    readable_output = '## Get Temp Artifact URL \n'
    readable_output += tableToMarkdown('Temp Artifact URL', result,
                                       headers=[])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Twinwave.TempArtifactURL",
        outputs_key_field='URL',
        outputs=result,
        raw_response=result  # raw response - the original response
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()

    api_token = params.get('api-token')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(api_token=api_token, verify=verify_certificate, proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            demisto.incidents(list_recent_jobs(client, params))

        elif demisto.command() == 'twinwave-get-engines':
            return_results(get_engines(client))

        elif demisto.command() == 'twinwave-submit-url':
            return_results(submit_url(client, demisto.args()))

        elif demisto.command() == 'twinwave-submit-file':
            return_results(submit_file(client, demisto.args()))

        elif demisto.command() == 'twinwave-resubmit-job':
            return_results(resubmit_job(client, demisto.args()))

        elif demisto.command() == 'twinwave-list-recent-jobs':
            return_results(list_recent_jobs(client, demisto.args()))

        elif demisto.command() == 'twinwave-get-job-summary':
            return_results(get_job_summary(client, demisto.args()))

        elif demisto.command() == 'twinwave-get-job-normalized-forensics':
            return_results(get_job_normalized_forensics(client, demisto.args()))

        elif demisto.command() == 'twinwave-get-task-normalized-forensics':
            return_results(get_task_normalized_forensics(client, demisto.args()))

        elif demisto.command() == 'twinwave-get-task-raw-forensics':
            return_results(get_task_raw_forensics(client, demisto.args()))

        elif demisto.command() == 'twinwave-download-submitted-resource':
            return_results(download_submitted_resource(client, demisto.args()))

        elif demisto.command() == 'twinwave-get-temp-artifact-url':
            return_results(get_temp_artifact_url(client, demisto.args()))

        elif demisto.command() == 'twinwave-search-across-jobs-and-resources':
            return_results(search_across_jobs_and_resources(client, demisto.args()))

            # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
