import requests

from CommonServerPython import *

""" GLOBAL PARAMS """
API_KEY = demisto.params()["api_key"]
SERVER = (
    demisto.params()["server"][:-1]
    if (demisto.params()["server"] and demisto.params()["server"].endswith("/"))
    else demisto.params()["server"]
)

SERVER += "/rest/"
USE_SSL = not demisto.params().get("insecure", False)
HEADERS = {"Authorization": "api_key " + API_KEY}

# Remove proxy
if not demisto.params().get("proxy"):
    del os.environ["HTTP_PROXY"]
    del os.environ["HTTPS_PROXY"]
    del os.environ["http_proxy"]
    del os.environ["https_proxy"]

""" HELPER DICTS """
SEVERITY_DICT = {
    "malicious": "Malicious",
    "suspicious": "Suspicious",
    "not_suspicious": "Good",
    "blacklisted": "Blacklisted",
    "whitelisted": "Whitelisted",
    "unknown": "Unknown",
    None: "Unknown"
}

DBOTSCORE = {
    "Malicious": 3,
    "Suspicious": 2,
    "Good": 1,
    "Blacklisted": 3,
    "Whitelisted": 1,
    "Unknown": 0,
}

""" HELPER FUNCTIONS """


def build_errors_string(errors):
    if isinstance(errors, list):
        err_str = str()
        for error in errors:
            err_str += error.get("error_msg") + ".\n"
    else:
        err_str = errors.get("error_msg")
    return err_str


def http_request(method, url_suffix, params=None, files=None, ignore_errors=False):
    def find_error(may_be_error_inside):
        """Function will search for dict with "errors" or "error_msg" key

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
            if "error_msg" in may_be_error_inside:
                return may_be_error_inside["error_msg"]
            if "errors" in may_be_error_inside and len(may_be_error_inside["errors"]):
                return may_be_error_inside["errors"]
            for v in may_be_error_inside.values():
                err = find_error(v)
                if err:
                    return err
        return None

    """ General HTTP request.
    Args:
        ignore_error:
        method: (str) "GET", "POST", "DELETE' "PUT"
        url_suffix: (str)
        params: (dict)
        files: (tuple, dict)

    Returns:
        dict: response json
    """
    error_format = "Error in API call to VMRay [{}] - {}"
    url = SERVER + url_suffix
    r = requests.request(
        method,
        url,
        params=params,
        headers=HEADERS,
        files=files,
        verify=USE_SSL,
    )

    status_code = r.status_code
    # Handle errors
    try:
        if status_code not in {200, 201, 202, 204} and not ignore_errors:
            raise ValueError

        response = r.json()
        err = find_error(response)
        if err:
            return_error(error_format.format(status_code, err))
        return response
    except ValueError:
        # If no JSON is present, must be an error that can't be ignored
        return_error(
            error_format.format(status_code, r.text)
        )


def score_by_hash(analysis):
    """Gets a dict containing MD5/SHA1/SHA256/SSDeep and return dbotscore

    Args:
        analysis: (dict)

    Returns:
        dict: dbot score
    """
    hashes = ["MD5", "SHA256", "SHA1", "SSDeep"]
    scores = list()
    for hash_type in hashes:
        if hash_type in analysis:
            scores.append(
                {
                    "Indicator": analysis.get(hash_type),
                    "Type": "hash",
                    "Vendor": "VMRay",
                    "Score": DBOTSCORE.get(analysis.get("Severity", 0)),
                }
            )
    return scores


def build_job_data(data):
    def build_entry(entry_data):
        entry = dict()
        entry["JobID"] = entry_data.get("job_id")
        entry["SampleID"] = entry_data.get("job_sample_id")
        entry["SubmissionID"] = entry_data.get("job_submission_id")
        entry["MD5"] = entry_data.get("job_sample_md5")
        entry["SHA1"] = entry_data.get("job_sample_sha1")
        entry["SHA256"] = entry_data.get("job_sample_sha256")
        entry["SSDeep"] = entry_data.get("job_sample_ssdeep")
        entry["VMName"] = entry_data.get("job_vm_name")
        entry["VMID"] = entry_data.get("job_vm_id")
        entry["Status"] = entry_data.get("job_status")
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
    entry["JobID"] = job_id
    entry["SampleID"] = sample_id
    entry["Status"] = "Finished/NotExists"
    return entry


def build_analysis_data(analyses):
    """

    Args:
        analyses: (dict) of analysis

    Returns:
        dict: formatted entry context
    """
    entry_context = dict()
    entry_context["VMRay.Analysis(val.AnalysisID === obj.AnalysisID)"] = [
        {
            "AnalysisID": analysis.get("analysis_id"),
            "SampleID": analysis.get("analysis_sample_id"),
            "Severity": SEVERITY_DICT.get(analysis.get("analysis_severity")),
            "JobCreated": analysis.get("analysis_job_started"),
            "SHA1": analysis.get("analysis_sample_sha1"),
            "MD5": analysis.get("analysis_sample_md5"),
            "SHA256": analysis.get("analysis_sample_sha25"),
        }
        for analysis in analyses
    ]

    scores = list()
    for analysis in entry_context:
        scores.extend(score_by_hash(analysis))
    entry_context[outputPaths.get("dbotscore")] = scores

    return entry_context


def test_module():
    """Simple get request to see if connected
    """
    response = http_request("GET", "analysis?_limit=1")
    demisto.results("ok") if response.get("result") == 'ok' else return_error("Can't authenticate! {}".format(response))


def upload_sample(path, params=None):
    suffix = "sample/submit"
    files = {"sample_file": open(path, "rb")}
    results = http_request("POST", url_suffix=suffix, params=params, files=files)
    return results


def upload_sample_command():
    """Uploads a file to vmray
    """
    # Preserve BC
    file_id = demisto.args().get("entry_id") if demisto.args().get("entry_id") else demisto.args().get("file_id")
    path = demisto.getFilePath(file_id).get("path")

    # additional params
    doc_pass = demisto.args().get("document_password")
    arch_pass = demisto.args().get("archive_password")
    sample_type = demisto.args().get("sample_type")
    shareable = demisto.args().get("shareable")
    reanalyze = demisto.args().get("reanalyze")
    max_jobs = demisto.args().get("max_jobs")
    tags = demisto.args().get("tags")

    params = dict()
    if doc_pass:
        params["document_password"] = doc_pass
    if arch_pass:
        params["archive_password"] = arch_pass
    if sample_type:
        params["sample_type"] = sample_type
    if shareable == "true":
        params["shareable"] = shareable
    if reanalyze == "true":
        params["reanalyze"] = reanalyze
    if max_jobs:
        if max_jobs.isdigit():
            params["max_jobs"] = int(max_jobs)
        else:
            return_error("max_jobs arguments isn't a number")
    if tags:
        params["tags"] = tags

    # Request call
    raw_response = upload_sample(path, params=params)
    data = raw_response.get("data")
    jobs_list = list()
    jobs = data.get("jobs")
    if jobs:
        for job in jobs:
            if isinstance(job, dict):
                job_entry = dict()
                job_entry["JobID"] = job.get("job_id")
                job_entry["Created"] = job.get("job_created")
                job_entry["SampleID"] = job.get("job_sample_id")
                job_entry["VMName"] = job.get("job_vm_name")
                job_entry["VMID"] = job.get("job_vm_id")
                job_entry["JobRuleSampleType"] = job.get("job_jobrule_sampletype")
                jobs_list.append(job_entry)

    samples_list = list()
    samples = data.get("samples")
    if samples:
        for sample in samples:
            if isinstance(sample, dict):
                sample_entry = dict()
                sample_entry["SampleID"] = sample.get("sample_id")
                sample_entry["Created"] = sample.get("sample_created")
                sample_entry["FileName"] = sample.get("submission_filename")
                sample_entry["FileSize"] = sample.get("sample_filesize")
                sample_entry["SSDeep"] = sample.get("sample_ssdeephash")
                sample_entry["SHA1"] = sample.get("sample_sha1hash")
                samples_list.append(sample_entry)

    submissions_list = list()
    submissions = data.get("submissions")
    if submissions:
        for submission in submissions:
            if isinstance(submission, dict):
                submission_entry = dict()
                submission_entry["SubmissionID"] = submission.get("submission_id")
                submission_entry["SampleID"] = submission.get("submission_sample_id")
                submissions_list.append(submission_entry)

    entry_context = dict()
    entry_context["VMRay.Job(val.JobID === obj.JobID)"] = jobs_list
    entry_context["VMRay.Sample(val.SampleID === obj.SampleID)"] = samples_list
    entry_context["VMRay.Submission(val.SubmissionID === obj.SubmissionID)"] = submissions_list

    table = {
        "Jobs ID": [job.get("JobID") for job in jobs_list],
        "Samples ID": [sample.get("SampleID") for sample in samples_list],
        "Submissions ID": [
            submission.get("SubmissionID") for submission in submissions_list
        ],
    }
    human_readable = tableToMarkdown(
        "File submitted to VMRay",
        t=table,
        headers=["Jobs ID", "Samples ID", "Submissions ID"],
    )

    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)


def get_analysis_command():
    sample_id = demisto.args().get("sample_id")
    limit = demisto.args().get("limit")

    params = {"_limit": limit}
    raw_response = get_analysis(sample_id, params)
    data = raw_response.get("data")
    entry_context = build_analysis_data(data)
    humam_readable = json.dumps(entry_context, indent=4)
    return_outputs(humam_readable, entry_context, raw_response=raw_response)


def get_analysis(sample, params=None):
    suffix = "analysis/sample/{}".format(sample)
    response = http_request("GET", suffix, params=params)
    return response


def get_submission_command():
    submission_id = demisto.args().get("submission_id")
    raw_response = get_submission(submission_id)
    data = raw_response.get("data")
    if data:
        # Build entry
        entry = dict()
        entry["IsFinished"] = data.get("submission_finished")
        entry["HasErrors"] = data.get("submission_has_errors")
        entry["SubmissionID"] = data.get("submission_id")
        entry["MD5"] = data.get("submission_sample_md5")
        entry["SHA1"] = data.get("submission_sample_sha1")
        entry["SHA256"] = data.get("submission_sample_sha256")
        entry["SSDeep"] = data.get("submission_sample_ssdeep")
        entry["Severity"] = SEVERITY_DICT.get(data.get("submission_severity"))
        entry["SampleID"] = data.get("submission_sample_id")
        scores = score_by_hash(entry)

        entry_context = {
            "VMRay.Submission(val.SubmissionID === obj.SubmissionID)": entry,
            outputPaths.get("dbotscore"): scores,
        }

        human_readable = tableToMarkdown(
            "Submission results from VMRay for ID {} with severity of {}".format(
                submission_id, entry.get("Severity", "Unknown")
            ),
            entry,
            headers=[
                "IsFinished",
                "Severity",
                "HasErrors",
                "MD5",
                "SHA1",
                "SHA256",
                "SSDeep",
            ],
        )

        return_outputs(human_readable, entry_context, raw_response=raw_response)
    else:
        return_outputs("No submission found in VMRay for submission id: {}".format(submission_id), {})


def get_submission(submission_id):
    """

    Args:
        submission_id: (str)

    Returns:
        dict: response.data
    """
    suffix = "submission/{}".format(submission_id)
    response = http_request("GET", url_suffix=suffix)
    return response


def get_sample_command():
    sample_id = demisto.args().get("sample_id")
    raw_response = get_sample(sample_id)
    data = raw_response.get("data")

    entry = dict()
    entry["SampleID"] = data.get("sample_id")
    entry["FileName"] = data.get("sample_filename")
    entry["MD5"] = data.get("sample_md5hash")
    entry["SHA1"] = data.get("sample_sha1hash")
    entry["SHA256"] = data.get("sample_sha256hash")
    entry["SSDeep"] = data.get("sample_ssdeephash")
    entry["Severity"] = SEVERITY_DICT.get(data.get("sample_severity"))
    entry["Type"] = data.get("sample_type")
    entry["Created"] = data.get("sample_created")
    entry["Classification"] = data.get("sample_classifications")
    scores = score_by_hash(entry)

    entry_context = {
        "VMRay.Sample(var.SampleID === obj.SampleID)": entry,
        outputPaths.get("dbotscore"): scores,
    }

    human_readable = tableToMarkdown(
        "Results for sample id: {} with severity {}".format(
            entry.get("SampleID"), entry.get("Severity")
        ),
        entry,
        headers=["Type", "MD5", "SHA1", "SHA256", "SSDeep"],
    )
    return_outputs(human_readable, entry_context, raw_response=raw_response)


def get_sample(sample_id):
    """building http request for get_sample_command

    Args:
        sample_id: (str, int)

    Returns:
        dict: data from response
    """
    suffix = "sample/{}".format(sample_id)
    response = http_request("GET", suffix)
    return response


def get_job(job_id=None, sample_id=None):
    """
    Args:
        sample_id:
        job_id:
    Returns:
        dict of response, if not exists returns:
        {
            "error_msg": "No such element"
            "result": "error"
        }
    """
    suffix = "job/{}".format(job_id) if isinstance(job_id, str) else "job/sample/{}".format(sample_id)
    response = http_request("GET", suffix, ignore_errors=True)
    return response


def get_job_command():
    job_id = demisto.args().get("job_id")
    sample_id = demisto.args().get("sample_id")

    vmray_id = job_id if job_id else sample_id
    title = "job" if job_id else "sample"

    raw_response = get_job(job_id=job_id, sample_id=sample_id)
    data = raw_response.get("data")
    if raw_response.get("result") == "error" or not data:
        entry = build_finished_job(job_id=job_id, sample_id=sample_id)
        human_readable = "#### Jobs for {} id {} is finished/not exists".format(title, vmray_id)
    else:
        entry = build_job_data(data)
        sample = entry[0] if isinstance(entry, list) else entry
        human_readable = tableToMarkdown(
            "Job results for {} id: {}".format(title, vmray_id),
            sample,
            headers=["JobID", "SampleID", "VMName", "VMID"],
        )

    entry_context = {"VMRay.Job(val.JobID === obj.JobID && val.SampleID === obj.SampleID)": entry}
    return_outputs(human_readable, entry_context, raw_response=raw_response)


def get_threat_indicators(sample_id):
    suffix = "sample/{}/threat_indicators".format(sample_id)
    response = http_request("GET", suffix).get("data")
    return response


def get_threat_indicators_command():
    sample_id = demisto.args().get("sample_id")
    raw_response = get_threat_indicators(sample_id)
    data = raw_response.get("threat_indicators")

    # Build Entry Context
    if data and isinstance(data, list):
        entry_context_list = list()
        for indicator in data:
            entry = dict()
            entry["AnalysisID"] = indicator.get("analysis_ids")
            entry["Category"] = indicator.get("category")
            entry["Classification"] = indicator.get("classifications")
            entry["ID"] = indicator.get("id")
            entry["Operation"] = indicator.get("operation")
            entry_context_list.append(entry)

        human_readable = tableToMarkdown(
            "Threat indicators for sample ID: {}. Showing first indicator:".format(
                sample_id
            ),
            entry_context_list[0],
            headers=["AnalysisID", "Category", "Classification", "Operation"],
        )

        entry_context = {"VMRay.ThreatIndicator(obj.ID === val.ID)": entry_context_list}
        return_outputs(
            human_readable,
            entry_context,
            raw_response={
                "threat_indicators": data
            }
        )
    return_outputs(
        "No threat indicators for sample ID: {}".format(sample_id),
        {},
        raw_response=raw_response
    )


def post_tags_to_analysis(analysis_id, tag):
    suffix = "analysis/{}/tag/{}".format(analysis_id, tag)
    response = http_request("POST", suffix)
    return response


def post_tags_to_submission(submission_id, tag):
    suffix = "submission/{}/tag/{}".format(submission_id, tag)
    response = http_request("POST", suffix)
    return response


def post_tags():
    analysis_id = demisto.args().get("analysis_id")
    submission_id = demisto.args().get("submission_id")
    tag = demisto.args().get("tag")
    if not submission_id and not analysis_id:
        return_error("No submission ID or analysis ID has been provided")
    if analysis_id:
        analysis_status = post_tags_to_analysis(analysis_id, tag)
        if analysis_status.get("result") == "ok":
            return_outputs(
                "Tags: {} has been added to analysis:".format(tag, analysis_id),
                {},
                raw_response=analysis_status,
            )
    if submission_id:
        submission_status = post_tags_to_submission(submission_id, tag)
        if submission_status.get("result") == "ok":
            return_outputs(
                "Tags: {} has been added to submission:".format(tag, submission_id),
                {},
                raw_response=submission_status,
            )


def delete_tags_from_analysis(analysis_id, tag):
    suffix = "analysis/{}/tag/{}".format(analysis_id, tag)
    response = http_request("DELETE", suffix)
    return response


def delete_tags_from_submission(submission_id, tag):
    suffix = "submission/{}/tag/{}".format(submission_id, tag)
    response = http_request("DELETE", suffix)
    return response


def delete_tags():
    analysis_id = demisto.args().get("analysis_id")
    submission_id = demisto.args().get("submission_id")
    tag = demisto.args().get("tags")
    if not submission_id and not analysis_id:
        return_error("No submission ID or analysis ID has been provided")
    if submission_id:
        submission_status = delete_tags_from_submission(submission_id, tag)
        if submission_status.get("result") == "ok":
            return_outputs(
                "Tags: {} has been added to submission:".format(tag, submission_id),
                {},
                raw_response=submission_status,
            )
    if analysis_id:
        analysis_status = delete_tags_from_analysis(analysis_id, tag)
        if analysis_status.get("result") == "ok":
            return_outputs(
                "Tags: {} has been added to analysis:".format(tag, analysis_id),
                {},
                raw_response=analysis_status,
            )


def get_iocs(sample_id):
    suffix = "sample/{}/iocs".format(sample_id)
    response = http_request("GET", suffix)
    return response


def get_iocs_command():
    sample_id = demisto.args().get("sample_id")
    raw_response = get_iocs(sample_id)
    data = raw_response.get("data", {}).get("iocs", {})

    # Initialize counters
    iocs_size = 0
    iocs_size_table = dict()

    domains = data.get("domains")
    domain_list = list()
    if domains:
        size = len(domains)
        iocs_size_table["Domain"] = size
        iocs_size += size

        for domain in domains:
            entry = dict()
            entry["AnalysisID"] = domain.get("analysis_ids")
            entry["Domain"] = domain.get("domain")
            entry["ID"] = domain.get("id")
            entry["Type"] = domain.get("type")
            domain_list.append(entry)

    ips = data.get("ips")
    ip_list = list()
    if ips:
        size = len(ips)
        iocs_size_table["IP"] = size
        iocs_size += size

        for ip in ips:
            entry = dict()
            entry["AnalysisID"] = ip.get("analysis_ids")
            entry["IP"] = ip.get("ip_address")
            entry["ID"] = ip.get("id")
            entry["Type"] = ip.get("type")
            ip_list.append(entry)

    mutexes = data.get("mutexes")
    mutex_list = list()
    if mutexes:
        size = len(mutexes)
        iocs_size_table["Mutex"] = size
        iocs_size += size

        for mutex in mutexes:
            entry = dict()
            entry["AnalysisID"] = mutex.get("analysis_ids")
            entry["Name"] = mutex.get("mutex_name")
            entry["Operation"] = mutex.get("operations")
            entry["ID"] = mutex.get("id")
            entry["Type"] = mutex.get("type")
            mutex_list.append(entry)

    registry = data.get("registry")
    registry_list = list()
    if registry:
        size = len(registry)
        iocs_size_table["Registry"] = size
        iocs_size += size

        for reg in registry:
            entry = dict()
            entry["AnalysisID"] = reg.get("analysis_ids")
            entry["Name"] = reg.get("reg_key_name")
            entry["Operation"] = reg.get("operations")
            entry["ID"] = reg.get("id")
            entry["Type"] = reg.get("type")
            registry_list.append(entry)

    urls = data.get("urls")
    urls_list = list()
    if urls:
        size = len(urls)
        iocs_size_table["URL"] = size
        iocs_size += size
        for url in urls:
            entry = dict()
            entry["AnalysisID"] = url.get("analysis_ids")
            entry["URL"] = url.get("url")
            entry["Operation"] = url.get("operations")
            entry["ID"] = url.get("id")
            entry["Type"] = url.get("type")
            urls_list.append(entry)

    iocs = {
        "URL": urls_list,
        "Mutex": mutex_list,
        "Domain": domain_list,
        "Registry": registry_list,
        "IP": ip_list
    }

    entry_context = {
        "VMRay.Sample(val.SampleID === {}).IOC".format(sample_id): iocs,
    }

    human_readable = tableToMarkdown(
        "Total of {} IOCs found in VMRay by sample {}".format(iocs_size, sample_id),
        iocs_size_table,
        headers=["URLs", "IPs", "Domains", "Mutexes", "Registry"]
    )
    return_outputs(human_readable, entry_context, raw_response=raw_response)


try:
    COMMAND = demisto.command()
    if COMMAND == "test-module":
        # This is the call made when pressing the integration test button.
        # demisto.results('ok')
        test_module()
    elif COMMAND in ("upload_sample", "vmray-upload-sample", "file"):
        upload_sample_command()
    elif COMMAND == "vmray-get-submission":
        get_submission_command()
    elif COMMAND in ("get_results", "vmray-get-analysis-by-sample"):
        get_analysis_command()
    elif COMMAND == "vmray-get-sample":
        get_sample_command()
    elif COMMAND in ("vmray-get-job-by-sample", "get_job_sample", "vmray-get-job-by-id"):
        get_job_command()
    elif COMMAND == "vmray-get-threat-indicators":
        get_threat_indicators_command()
    elif COMMAND == "vmray-add-tag":
        post_tags()
    elif COMMAND == "vmray-delete-tag":
        delete_tags()
    elif COMMAND == "vmray-get-iocs":
        get_iocs_command()
except Exception as exc:
    return_error(exc.message)
