import requests

from CommonServerPython import *

""" GLOBAL PARAMS """
API_KEY = demisto.params()["api_key"]
SERVER = (
    demisto.params()["server"][:-1]
    if (demisto.params().get("server") and demisto.params()["server"].endswith("/"))
    else demisto.params()["server"]
)

SERVER = SERVER + "/rest/"
USE_SSL = not demisto.params().get("insecure", False)

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


def http_request(method, url_suffix, body=None, params=None, files=None):
    """

    Args:
        method: (str) "GET", "POST", "DELETE' "PUT"
        url_suffix: (str)
        body: (dict)
        params: (dict)
        files: (tuple, dict)

    Returns:
        dict: response json
    """
    headers = {"Authorization": "api_key " + API_KEY}

    url = SERVER + url_suffix
    r = requests.request(
        method,
        url,
        json=body,
        params=params,
        headers=headers,
        files=files,
        verify=USE_SSL,
    )
    if r.status_code not in {200, 201, 202, 204}:
        return_error(
            "Error in API call to VMRay [{}] - {}".format(r.status_code, r.text)
        )
    return r.json()


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
                    "Score": DBOTSCORE[analysis.get("Severity")],
                }
            )
    return scores


def test_module():
    """Simple get request to see if connected
    """
    http_request("GET", "analysis?_limit=1")
    demisto.results("ok")


def upload_sample(path):
    suffix = "sample/submit"
    files = {"sample_file": open(path, "rb")}
    results = http_request("POST", url_suffix=suffix, files=files)
    return results


def upload_sample_command():
    """Uploads a file to vmray
    """
    file_id = demisto.args().get("file_id")
    path = demisto.getFilePath(file_id).get("path")

    raw_response = upload_sample(path).get("data")

    jobs_list = list()
    jobs = raw_response.get("jobs")
    if jobs:
        for job in jobs:
            if isinstance(job, dict):
                job_entry = dict()
                job_entry["JobID"] = job.get("job_id")
                job_entry["Created"] = job.get("job_created")
                job_entry["SampleID"] = job.get("job_sample_id")
                job_entry["VMName"] = job.get("job_vm_name")
                job_entry["VMID"] = job.get("job_vm_id")
                jobs_list.append(job_entry)

    samples_list = list()
    samples = raw_response.get("samples")
    if samples:
        for sample in samples:
            if isinstance(sample, dict):
                sample_entry = dict()
                sample_entry["SampleID"] = sample.get("sample_id")
                sample_entry["Created"] = sample.get("sample_created")
                samples_list.append(sample_entry)

    submissions_list = list()
    submissions = raw_response.get("submissions")
    if submissions:
        for submission in submissions:
            if isinstance(submission, dict):
                submission_entry = dict()
                submission_entry["SubmissionID"] = submission.get("submission_id")
                submission_entry["SampleID"] = submission.get("submission_sample_id")
                submissions_list.append(submission_entry)

    ec = dict()
    ec["VMRay.Jobs(val.JobID === obj.JobID)"] = jobs_list
    ec["VMRay.Samples(val.SampleID === obj.SampleID)"] = samples_list
    ec["VMRay.Submissions(val.SubmissionID === obj.SubmissionID)"] = submissions_list

    table = {
        "Jobs ID": [job.get("JobID") for job in jobs_list],
        "Samples ID": [sample.get("SampleID") for sample in samples_list],
        "Submissions ID": [
            submission.get("SubmissionID") for submission in submissions_list
        ],
    }
    md = tableToMarkdown(
        "File submitted to VMRay",
        t=table,
        headers=["Jobs ID", "Samples ID", "Submissions ID"],
    )

    return_outputs(readable_output=md, outputs=ec, raw_response=raw_response)


def build_analysis_data(analyses):
    """

    Args:
        analyses: (dict) of analysis

    Returns:
        dict: formatted entry context
    """
    ec = dict()
    ec["VMRay.Analysis(val.AnalysisID === obj.AnalysisID)"] = [
        {
            "AnalysisID": analysis.get("analysis_id"),
            "AnalysisSampleID": analysis.get("analysis_sample_id"),
            "Severity": SEVERITY_DICT.get(analysis.get("analysis_severity")),
            "Created": analysis.get("analysis_job_started"),
            "SHA1": analysis.get("analysis_sample_sha1"),
            "MD5": analysis.get("analysis_sample_md5"),
            "SHA256": analysis.get("analysis_sample_sha25"),
        }
        for analysis in analyses
    ]

    scores = list()
    for analysis in ec:
        scores.extend(score_by_hash(analysis))
    ec[outputPaths.get("dbotscore")] = scores

    return ec


def get_analysis_command():
    sample_id = demisto.args().get("sample_id")
    limit = demisto.args().get("limit")

    params = {"_limit": limit}

    raw_response = get_analysis(sample_id, params)
    ec = build_analysis_data(raw_response)
    md = json.dumps(ec, indent=4)
    return_outputs(md, ec, raw_response=raw_response)


def get_analysis(sample, params=None):
    suffix = "analysis/sample/{}".format(sample)
    response = http_request("GET", suffix, params=params)
    return response.get("data")


def get_submission_command():
    submission_id = demisto.args().get("submission_id")
    raw_response = get_submission(submission_id)

    # Build entry
    entry = dict()
    entry["IsFinished"] = raw_response.get("submission_finished")
    entry["HasErrors"] = raw_response.get("submission_has_errors")
    entry["SubmissionID"] = raw_response.get("submission_id")
    entry["MD5"] = raw_response.get("submission_sample_md5")
    entry["SHA1"] = raw_response.get("submission_sample_sha1")
    entry["SHA256"] = raw_response.get("submission_sample_sha256")
    entry["SSDeep"] = raw_response.get("submission_sample_ssdeep")
    entry["Severity"] = SEVERITY_DICT.get(raw_response.get("submission_severity"))
    scores = score_by_hash(entry)

    ec = {
        "VMRay.Submission(val.SubmissionID === obj.SubmissionID)": entry,
        outputPaths.get("dbotscore"): scores,
    }

    md = tableToMarkdown(
        "Submission results from VMRay for ID {} with severity of {}".format(
            submission_id, entry.get("Severity")
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

    return_outputs(md, ec, raw_response=raw_response)


def get_submission(submission_id):
    """

    Args:
        submission_id: (str)

    Returns:
        dict: response.data
    """
    suffix = "submission/{}".format(submission_id)
    response = http_request("GET", url_suffix=suffix)
    return response.get("data")


def get_sample_command():
    sample_id = demisto.args().get("sample_id")
    raw_response = get_sample(sample_id)

    entry = dict()
    entry["SampleID"] = raw_response.get("sample_id")
    entry["FileName"] = raw_response.get("sample_filename")
    entry["MD5"] = raw_response.get("sample_md5hash")
    entry["SHA1"] = raw_response.get("sample_sha1hash")
    entry["SHA256"] = raw_response.get("sample_sha256hash")
    entry["SSDeep"] = raw_response.get("sample_ssdeephash")
    entry["Severity"] = SEVERITY_DICT.get(raw_response.get("sample_severity"))
    entry["Type"] = raw_response.get("sample_type")
    entry["Created"] = raw_response.get("sample_created")
    entry["Classifications"] = raw_response.get("sample_classifications")
    scores = score_by_hash(entry)

    ec = {
        "VMRay.Samples(var.SampleID === obj.SampleID)": entry,
        outputPaths.get("dbotscore"): scores,
    }

    md = tableToMarkdown(
        "Results for sample id: {} with severity {}".format(
            entry.get("SampleID"), entry.get("Severity")
        ),
        entry,
        headers=["Type", "MD5", "SHA1", "SHA256", "SSDeep"],
    )
    return_outputs(md, ec, raw_response=raw_response)


def get_sample(sample_id):
    """building http request for get_sample_command

    Args:
        sample_id: (str, int)

    Returns:
        dict: data from response
    """
    suffix = "sample/{}".format(sample_id)
    return http_request("GET", suffix).get("data")


def get_job_sample(sample_id):
    suffix = "job/sample/{}".format(sample_id)
    response = http_request("GET", suffix)
    return response.get("data")


def get_job_sample_command():
    sample_id = demisto.args().get("sample_id")
    raw_response = get_job_sample(sample_id)

    entry = dict()
    entry["JobID"] = raw_response.get("job_id")
    entry["SampleID"] = raw_response.get("job_sample_id")
    entry["SubmissionID"] = raw_response.get("job_submission_id")
    entry["MD5"] = raw_response.get("job_sample_md5")
    entry["SHA1"] = raw_response.get("job_sample_sha1")
    entry["SHA256"] = raw_response.get("job_sample_sha256")
    entry["SSDeep"] = raw_response.get("job_sample_ssdeep")
    entry["JobVMName"] = raw_response.get("job_vm_name")
    entry["JobVMID"] = raw_response.get("job_vm_id")

    ec = {"VMRay.Jobs(val.JobID === obj.JobID)": entry}

    md = tableToMarkdown(
        "Results for job sample id: {}".format(sample_id),
        entry,
        headers=["JobID", "SampleID", "JobVMName", "JobVMID"],
    )
    return_outputs(md, ec, raw_response=raw_response)


try:
    COMMAND = demisto.command()
    # The command demisto.command() holds the command sent from the user.
    if COMMAND == "test-module":
        # This is the call made when pressing the integration test button.
        # demisto.results('ok')
        test_module()
    elif COMMAND in ("upload_sample", "vmray-upload-sample"):
        upload_sample_command()
    elif COMMAND == "vmray-get-submission":
        get_submission_command()
    elif COMMAND in ("get_results", "vmray-get-analysis-by-sample"):
        get_analysis_command()
    elif COMMAND == "vmray-get-sample":
        get_sample_command()
    elif COMMAND in ("vmray-get-job-sample", "get_job_sample"):
        get_job_sample_command()
except Exception as exc:
    return_error(exc.message)
