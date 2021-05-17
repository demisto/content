<!-- HTML_DOC -->
<div class="cl-preview-section">
</div>
<div class="cl-preview-section">
<h2 id="vmray-playbook">VMRay Playbook</h2>
</div>
<div class="cl-preview-section">
<p>Detonate File - VMRay</p>
</div>
<div class="cl-preview-section">
<h2 id="configure-vmray-on-demisto">Configure VMRay on Demisto</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for VMRay.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g.,<span> </span>https://cloud.vmray.com)</strong></li>
<li><strong>API Key</strong></li>
<li><strong>Use system proxy</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="known-limitations">Known Limitations</h2>
</div>
<div class="cl-preview-section">
<ul>
<li>Non-ASCII characters in file names will be ignored when uploading.</li>
</ul>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#submit-a-sample-for-analysis" target="_self">Submit a sample for analysis: vmray-upload-sample</a></li>
<li><a href="#get-analysis-details-for-a-sample" target="_self">Get analysis details for a sample: vmray-get-analysis-by-sample</a></li>
<li><a href="#get-job-details-for-a-sample" target="_self">Get job details for a sample: vmray-get-job-by-sample</a></li>
<li><a href="#get-submission-results" target="_self">Get submission results: vmray-get-submission</a></li>
<li><a href="#get-information-for-a-sample" target="_self">Get information for a sample: vmray-get-sample</a></li>
<li><a href="#get-threat-indicators" target="_self">Get threat indicators: vmray-get-threat-indicators</a></li>
<li><a href="#add-a-tag-to-an-analysis-or-submission" target="_self">Add a tag to an analysis or submission: vmray-add-tag</a></li>
<li><a href="#delete-a-tag-from-an-analysis-or-submission" target="_self">Delete a tag from an analysis or submission: vmray-delete-tag</a></li>
<li><a href="#get-iocs-for-a-sample" target="_self">Get IOCs for a sample: vmray-get-iocs</a></li>
<li><a href="#get-information-for-a-job" target="_self">Get information for a job: vmray-get-job-by-id</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="submit-a-sample-for-analysis">1. Submit a sample for analysis</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Submits a sample to VMRay for analysis.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vmray-upload-sample</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 201px;"><strong>Argument Name</strong></th>
<th style="width: 441px;"><strong>Description</strong></th>
<th style="width: 98px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 201px;">entry_id</td>
<td style="width: 441px;">Entry ID of the file to submit.</td>
<td style="width: 98px;">Required</td>
</tr>
<tr>
<td style="width: 201px;">document_password</td>
<td style="width: 441px;">Password of the document.</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 201px;">archive_password</td>
<td style="width: 441px;">Password of an archive.</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 201px;">sample_type</td>
<td style="width: 441px;">Force type of the file.</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 201px;">shareable</td>
<td style="width: 441px;">Whether the file is shareable.</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 201px;">reanalyze</td>
<td style="width: 441px;">Analyze even if analyses already exist.</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 201px;">max_jobs</td>
<td style="width: 441px;">Maximum number of jobs to create (number).</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 201px;">tags</td>
<td style="width: 441px;">A CSV list of tags to add to the sample.</td>
<td style="width: 98px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 334px;"><strong>Path</strong></th>
<th style="width: 87px;"><strong>Type</strong></th>
<th style="width: 319px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334px;">VMRay.Job.JobID</td>
<td style="width: 87px;">Number</td>
<td style="width: 319px;">ID of a new job</td>
</tr>
<tr>
<td style="width: 334px;">VMRay.Job.Created</td>
<td style="width: 87px;">Date</td>
<td style="width: 319px;">Timestamp of job creation.</td>
</tr>
<tr>
<td style="width: 334px;">VMRay.Job.SampleID</td>
<td style="width: 87px;">Number</td>
<td style="width: 319px;">ID of the sample.</td>
</tr>
<tr>
<td style="width: 334px;">VMRay.Job.VMName</td>
<td style="width: 87px;">String</td>
<td style="width: 319px;">Name of the virtual machine.</td>
</tr>
<tr>
<td style="width: 334px;">VMRay.Job.VMID</td>
<td style="width: 87px;">Number</td>
<td style="width: 319px;">ID of the virtual machine.</td>
</tr>
<tr>
<td style="width: 334px;">VMRay.Sample.SampleID</td>
<td style="width: 87px;">Number</td>
<td style="width: 319px;">ID of the sample.</td>
</tr>
<tr>
<td style="width: 334px;">VMRay.Sample.Created</td>
<td style="width: 87px;">Date</td>
<td style="width: 319px;">Timestamp of sample creation.</td>
</tr>
<tr>
<td style="width: 334px;">VMRay.Submission.SubmissionID</td>
<td style="width: 87px;">Number</td>
<td style="width: 319px;">Submission ID.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>vmray-upload-sample entry_id=79@4 max_jobs=1
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "VMRay.Sample": [
        {
            "SHA1": "69df095557346b3c136db4378afd5ee7a4839dcc", 
            "Created": "2019-05-27T07:48:11", 
            "SampleID": 3902285, 
            "FileName": "KeePass-2.41-Setup.exe", 
            "FileSize": 3301376, 
            "SSDeep": "98304:rk/6KPcsSO9iShSf0UTsj+te5NrYWM+40n3vGJyc:rkCK0UhSfHsKw5z4OvGJL"
        }
    ], 
    "VMRay.Submission": [
        {
            "SampleID": 3902285, 
            "SubmissionID": 4569315
        }
    ], 
    "VMRay.Job": [
        {
            "Created": "2019-05-27T07:48:11", 
            "JobRuleSampleType": "Windows PE (x86)", 
            "VMID": 20, 
            "SampleID": 3902285, 
            "JobID": 3908304, 
            "VMName": "win10_64_th2"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="file-submitted-to-vmray">File submitted to VMRay</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Jobs ID</th>
<th>Samples ID</th>
<th>Submissions ID</th>
</tr>
</thead>
<tbody>
<tr>
<td>3908304</td>
<td>3902285</td>
<td>4569315</td>
</tr>
</tbody>
</table>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-analysis-details-for-a-sample">2. Get analysis details for a sample</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves all analysis details for a specified sample.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vmray-get-analysis-by-sample</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 180px;"><strong>Argument Name</strong></th>
<th style="width: 462px;"><strong>Description</strong></th>
<th style="width: 98px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">sample_id</td>
<td style="width: 462px;">Analysis sample ID.</td>
<td style="width: 98px;">Required</td>
</tr>
<tr>
<td style="width: 180px;">limit</td>
<td style="width: 462px;">Maximum number of results to return (number).</td>
<td style="width: 98px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 193px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 488px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 193px;">VMRay.Analysis.AnalysisID</td>
<td style="width: 59px;">Number</td>
<td style="width: 488px;">Analysis ID.</td>
</tr>
<tr>
<td style="width: 193px;">VMRay.Analysis.SampleID</td>
<td style="width: 59px;">Number</td>
<td style="width: 488px;">Sample ID in the analysis.</td>
</tr>
<tr>
<td style="width: 193px;">VMRay.Analysis.Severity</td>
<td style="width: 59px;">String</td>
<td style="width: 488px;">Severity of the sample (Malicious, Suspicious, Good, Blacklisted, Whitelisted, Unknown).</td>
</tr>
<tr>
<td style="width: 193px;">VMRay.Analysis.JobCreated</td>
<td style="width: 59px;">Date</td>
<td style="width: 488px;">Date when the analysis job started.</td>
</tr>
<tr>
<td style="width: 193px;">VMRay.Analysis.MD5</td>
<td style="width: 59px;">String</td>
<td style="width: 488px;">MD5 hash of the sample.</td>
</tr>
<tr>
<td style="width: 193px;">VMRay.Analysis.SHA1</td>
<td style="width: 59px;">String</td>
<td style="width: 488px;">SHA1 hash of the sample.</td>
</tr>
<tr>
<td style="width: 193px;">VMRay.Analysis.SHA256</td>
<td style="width: 59px;">String</td>
<td style="width: 488px;">SHA256 hash of the sample.</td>
</tr>
<tr>
<td style="width: 193px;">VMRay.Analysis.SSDeep</td>
<td style="width: 59px;">String</td>
<td style="width: 488px;">ssdeep hash of the sample.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>vmray-get-analysis-by-sample sample_id=3902238
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h4 id="no-analysis-found-for-sample-id-3902238">No analysis found for sample id 3902238</h4>
</div>
<div class="cl-preview-section">
<h3 id="get-job-details-for-a-sample">3. Get job details for a sample</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves details for all jobs for a specified sample.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vmray-get-job-by-sample</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 306px;"><strong>Argument Name</strong></th>
<th style="width: 260px;"><strong>Description</strong></th>
<th style="width: 174px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 306px;">sample_id</td>
<td style="width: 260px;">Job sample ID.</td>
<td style="width: 174px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 253px;"><strong>Path</strong></th>
<th style="width: 87px;"><strong>Type</strong></th>
<th style="width: 400px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 253px;">VMRay.Job.JobID</td>
<td style="width: 87px;">Number</td>
<td style="width: 400px;">ID of the job.</td>
</tr>
<tr>
<td style="width: 253px;">VMRay.Job.SampleID</td>
<td style="width: 87px;">Number</td>
<td style="width: 400px;">Sample ID of the job.</td>
</tr>
<tr>
<td style="width: 253px;">VMRay.Job.SubmissionID</td>
<td style="width: 87px;">Number</td>
<td style="width: 400px;">ID of the submission.</td>
</tr>
<tr>
<td style="width: 253px;">VMRay.Job.MD5</td>
<td style="width: 87px;">String</td>
<td style="width: 400px;">MD5 hash of the sample in the job.</td>
</tr>
<tr>
<td style="width: 253px;">VMRay.Job.SHA1</td>
<td style="width: 87px;">String</td>
<td style="width: 400px;">SHA1 hash of the sample in the job.</td>
</tr>
<tr>
<td style="width: 253px;">VMRay.Job.SHA256</td>
<td style="width: 87px;">String</td>
<td style="width: 400px;">SHA256 hash of the sample in the job.</td>
</tr>
<tr>
<td style="width: 253px;">VMRay.Job.SSDeep</td>
<td style="width: 87px;">String</td>
<td style="width: 400px;">ssdeep hash of the sample in the job.</td>
</tr>
<tr>
<td style="width: 253px;">VMRay.Job.VMName</td>
<td style="width: 87px;">String</td>
<td style="width: 400px;">Name of the virtual machine.</td>
</tr>
<tr>
<td style="width: 253px;">VMRay.Job.VMID</td>
<td style="width: 87px;">Number</td>
<td style="width: 400px;">ID of the virtual machine.</td>
</tr>
<tr>
<td style="width: 253px;">VMRay.Job.Status</td>
<td style="width: 87px;">String</td>
<td style="width: 400px;">Status of the job.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!vmray-get-job-by-sample sample_id=3902238
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "VMRay.Job": {
        "JobID": 365547,
        "SampleID": 3902238,
        "SubmissionID": 4569262,
        "SHA1": "b94951a9dde256624289abe8b9744d0f61fab8bb", 
        "SSDeep": "192:sv28pU/UDVCavCAIl20otWzFtyTI619lKoFt333esXPDOljpcS+oOKzHg4/IOSCS:sv23/eogCPzFcTIaaljXSKbUJiB", 
        "SHA256": "543da75d434d172533411bb4a23577d54e2c63d959974c91b5a3098aaa0cad07", 
        "MD5": "e24992f83bb3d0ed12b3e8cd7c35888f"
        "VMName": "windows8.1-x64 sp1",
        "VMID": 747112,
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="get-submission-results">4. Get submission results</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves the results of a submission.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vmray-get-submission</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 141px;"><strong>Argument Name</strong></th>
<th style="width: 528px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">submission_id</td>
<td style="width: 528px;">ID of the submission. Can be obtained by running the <a href="#submit-a-sample-for-analysis" target="_self">vmray-upload-sample</a> command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 237px;"><strong>Path</strong></th>
<th style="width: 54px;"><strong>Type</strong></th>
<th style="width: 449px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 237px;">VMRay.Submission.IsFinished</td>
<td style="width: 54px;">Boolean</td>
<td style="width: 449px;">Whether the submission is finished (true or false).</td>
</tr>
<tr>
<td style="width: 237px;">VMRay.Submission.HasErrors</td>
<td style="width: 54px;">Boolean</td>
<td style="width: 449px;">Whether there are any errors in the submission (true or false).</td>
</tr>
<tr>
<td style="width: 237px;">VMRay.Submission.SubmissionID</td>
<td style="width: 54px;">Number</td>
<td style="width: 449px;">ID of the sample in the submission.</td>
</tr>
<tr>
<td style="width: 237px;">VMRay.Submission.MD5</td>
<td style="width: 54px;">String</td>
<td style="width: 449px;">MD5 hash of the sample in the submission.</td>
</tr>
<tr>
<td style="width: 237px;">VMRay.Submission.SHA1</td>
<td style="width: 54px;">String</td>
<td style="width: 449px;">SHA1 hash of the sample in the submission.</td>
</tr>
<tr>
<td style="width: 237px;">VMRay.Submission.SHA256</td>
<td style="width: 54px;">String</td>
<td style="width: 449px;">SHA256 hash of the sample in the submission.</td>
</tr>
<tr>
<td style="width: 237px;">VMRay.Submission.SSDeep</td>
<td style="width: 54px;">String</td>
<td style="width: 449px;">ssdeep hash of the sample in the submission.</td>
</tr>
<tr>
<td style="width: 237px;">VMRay.Submission.Severity</td>
<td style="width: 54px;">String</td>
<td style="width: 449px;">Severity of the sample in the submission (Malicious, Suspicious, Good, Blacklisted, Whitelisted, Unknown).</td>
</tr>
<tr>
<td style="width: 237px;">VMRay.Submission.SampleID</td>
<td style="width: 54px;">Number</td>
<td style="width: 449px;">ID of the sample in the submission.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>vmray-get-submission submission_id=4569262
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "DBotScore": [
        {
            "Vendor": "VMRay", 
            "Indicator": "e24992f83bb3d0ed12b3e8cd7c35888f", 
            "Score": 0, 
            "Type": "hash"
        }, 
        {
            "Vendor": "VMRay", 
            "Indicator": "543da75d434d172533411bb4a23577d54e2c63d959974c91b5a3098aaa0cad07", 
            "Score": 0, 
            "Type": "hash"
        }, 
        {
            "Vendor": "VMRay", 
            "Indicator": "b94951a9dde256624289abe8b9744d0f61fab8bb", 
            "Score": 0, 
            "Type": "hash"
        }, 
        {
            "Vendor": "VMRay", 
            "Indicator": "192:sv28pU/UDVCavCAIl20otWzFtyTI619lKoFt333esXPDOljpcS+oOKzHg4/IOSCS:sv23/eogCPzFcTIaaljXSKbUJiB", 
            "Score": 0, 
            "Type": "hash"
        }
    ], 
    "VMRay.Submission": {
        "SHA1": "b94951a9dde256624289abe8b9744d0f61fab8bb", 
        "HasErrors": false, 
        "Severity": "Unknown", 
        "IsFinished": true, 
        "SampleID": 3902238, 
        "SubmissionID": 4569262, 
        "SSDeep": "192:sv28pU/UDVCavCAIl20otWzFtyTI619lKoFt333esXPDOljpcS+oOKzHg4/IOSCS:sv23/eogCPzFcTIaaljXSKbUJiB", 
        "SHA256": "543da75d434d172533411bb4a23577d54e2c63d959974c91b5a3098aaa0cad07", 
        "MD5": "e24992f83bb3d0ed12b3e8cd7c35888f"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="submission-results-from-vmray-for-id-4569262-with-severity-of-unknown">Submission results from VMRay for ID 4569262 with severity of Unknown</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>IsFinished</th>
<th>Severity</th>
<th>HasErrors</th>
<th>MD5</th>
<th>SHA1</th>
<th>SHA256</th>
<th>SSDeep</th>
</tr>
</thead>
<tbody>
<tr>
<td>true</td>
<td>Unknown</td>
<td>false</td>
<td>e24992f83bb3d0ed12b3e8cd7c35888f</td>
<td>b94951a9dde256624289abe8b9744d0f61fab8bb</td>
<td>543da75d434d172533411bb4a23577d54e2c63d959974c91b5a3098aaa0cad07</td>
<td>192:sv28pU/UDVCavCAIl20otWzFtyTI619lKoFt333esXPDOljpcS+oOKzHg4/IOSCS:sv23/eogCPzFcTIaaljXSKbUJiB</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-information-for-a-sample">5. Get information for a sample</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves a sample using the sample ID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vmray-get-sample</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 286px;"><strong>Argument Name</strong></th>
<th style="width: 289px;"><strong>Description</strong></th>
<th style="width: 165px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 286px;">sample_id</td>
<td style="width: 289px;">ID of the sample.</td>
<td style="width: 165px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 208px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 469px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 208px;">VMRay.Sample.SampleID</td>
<td style="width: 63px;">Number</td>
<td style="width: 469px;">ID of the sample.</td>
</tr>
<tr>
<td style="width: 208px;">VMRay.Sample.FileName</td>
<td style="width: 63px;">String</td>
<td style="width: 469px;">File name of the sample.</td>
</tr>
<tr>
<td style="width: 208px;">VMRay.Sample.MD5</td>
<td style="width: 63px;">String</td>
<td style="width: 469px;">MD5 hash of the sample.</td>
</tr>
<tr>
<td style="width: 208px;">VMRay.Sample.SHA1</td>
<td style="width: 63px;">String</td>
<td style="width: 469px;">SHA1 hash of the sample.</td>
</tr>
<tr>
<td style="width: 208px;">VMRay.Sample.SHA256</td>
<td style="width: 63px;">String</td>
<td style="width: 469px;">SHA256 hash of the sample.</td>
</tr>
<tr>
<td style="width: 208px;">VMRay.Sample.SSDeep</td>
<td style="width: 63px;">String</td>
<td style="width: 469px;">ssdeep hash of the sample.</td>
</tr>
<tr>
<td style="width: 208px;">VMRay.Sample.Severity</td>
<td style="width: 63px;">String</td>
<td style="width: 469px;">Severity of the sample in the submission (Malicious, Suspicious, Good, Blacklisted, Whitelisted, Unknown).</td>
</tr>
<tr>
<td style="width: 208px;">VMRay.Sample.Type</td>
<td style="width: 63px;">String</td>
<td style="width: 469px;">File type.</td>
</tr>
<tr>
<td style="width: 208px;">VMRay.Sample.Created</td>
<td style="width: 63px;">Date</td>
<td style="width: 469px;">Timestamp of sample creation.</td>
</tr>
<tr>
<td style="width: 208px;">VMRay.Sample.Classifications</td>
<td style="width: 63px;">String</td>
<td style="width: 469px;">Classifications of the sample.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>vmray-get-sample sample_id=3902238
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "DBotScore": [
        {
            "Vendor": "VMRay", 
            "Indicator": "e24992f83bb3d0ed12b3e8cd7c35888f", 
            "Score": 0, 
            "Type": "hash"
        }, 
        {
            "Vendor": "VMRay", 
            "Indicator": "543da75d434d172533411bb4a23577d54e2c63d959974c91b5a3098aaa0cad07", 
            "Score": 0, 
            "Type": "hash"
        }, 
        {
            "Vendor": "VMRay", 
            "Indicator": "b94951a9dde256624289abe8b9744d0f61fab8bb", 
            "Score": 0, 
            "Type": "hash"
        }, 
        {
            "Vendor": "VMRay", 
            "Indicator": "192:sv28pU/UDVCavCAIl20otWzFtyTI619lKoFt333esXPDOljpcS+oOKzHg4/IOSCS:sv23/eogCPzFcTIaaljXSKbUJiB", 
            "Score": 0, 
            "Type": "hash"
        }
    ], 
    "VMRay.Sample": {
        "SHA1": "b94951a9dde256624289abe8b9744d0f61fab8bb", 
        "Severity": "Unknown", 
        "Classification": [], 
        "Created": "2019-05-27T07:28:08", 
        "SampleID": 3902238, 
        "FileName": "[TEST][COFENCE]_CASO_1_EMAIL_DA_SISTEMA_COFENCE__ZIP PASSWORD.msg", 
        "SSDeep": "192:sv28pU/UDVCavCAIl20otWzFtyTI619lKoFt333esXPDOljpcS+oOKzHg4/IOSCS:sv23/eogCPzFcTIaaljXSKbUJiB", 
        "SHA256": "543da75d434d172533411bb4a23577d54e2c63d959974c91b5a3098aaa0cad07", 
        "Type": "CDFV2 Microsoft Outlook Message", 
        "MD5": "e24992f83bb3d0ed12b3e8cd7c35888f"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="results-for-sample-id-3902238-with-severity-unknown">Results for sample id: 3902238 with severity Unknown</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Type</th>
<th>MD5</th>
<th>SHA1</th>
<th>SHA256</th>
<th>SSDeep</th>
</tr>
</thead>
<tbody>
<tr>
<td>CDFV2 Microsoft Outlook Message</td>
<td>e24992f83bb3d0ed12b3e8cd7c35888f</td>
<td>b94951a9dde256624289abe8b9744d0f61fab8bb</td>
<td>543da75d434d172533411bb4a23577d54e2c63d959974c91b5a3098aaa0cad07</td>
<td>192:sv28pU/UDVCavCAIl20otWzFtyTI619lKoFt333esXPDOljpcS+oOKzHg4/IOSCS:sv23/eogCPzFcTIaaljXSKbUJiB</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-threat-indicators">6. Get threat indicators</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves threat indicators (VTI).</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vmray-get-threat-indicators</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 523px;"><strong>Description</strong></th>
<th style="width: 80px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">sample_id</td>
<td style="width: 523px;">ID of the sample. Can be obtained from the VMRay.Sample.ID output.</td>
<td style="width: 80px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 334px;"><strong>Path</strong></th>
<th style="width: 76px;"><strong>Type</strong></th>
<th style="width: 330px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334px;">VMRay.ThreatIndicator.AnalysisID</td>
<td style="width: 76px;">Number</td>
<td style="width: 330px;">List of connected analysis IDs.</td>
</tr>
<tr>
<td style="width: 334px;">VMRay.ThreatIndicator.Category</td>
<td style="width: 76px;">String</td>
<td style="width: 330px;">Category of threat indicators.</td>
</tr>
<tr>
<td style="width: 334px;">VMRay.ThreatIndicator.Classification</td>
<td style="width: 76px;">String</td>
<td style="width: 330px;">Classifications of threat indicators.</td>
</tr>
<tr>
<td style="width: 334px;">VMRay.ThreatIndicator.ID</td>
<td style="width: 76px;">Number</td>
<td style="width: 330px;">ID of a threat indicator.</td>
</tr>
<tr>
<td style="width: 334px;">VMRay.ThreatIndicator.Operation</td>
<td style="width: 76px;">String</td>
<td style="width: 330px;">Operation the indicators caused.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>vmray-get-threat-indicators sample_id=3902238
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>No threat indicators for sample ID: 3902238</p>
</div>
<div class="cl-preview-section">
<h3 id="add-a-tag-to-an-analysis-or-submission">7. Add a tag to an analysis or submission</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds a tag to an analysis and/or a submission.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vmray-add-tag</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 180px;"><strong>Argument Name</strong></th>
<th style="width: 457px;"><strong>Description</strong></th>
<th style="width: 103px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">submission_id</td>
<td style="width: 457px;">ID of the submission to which to add tags.</td>
<td style="width: 103px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">analysis_id</td>
<td style="width: 457px;">ID of the analysis from which to delete tags.</td>
<td style="width: 103px;">Optional</td>
</tr>
<tr>
<td style="width: 180px;">tag</td>
<td style="width: 457px;">Tag to add.</td>
<td style="width: 103px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-6">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-6">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>vmray-add-tag submission_id=4569262 tag=faulty
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Tags: faulty has been added to submission: 4569262</p>
</div>
<div class="cl-preview-section">
<h3 id="delete-a-tag-from-an-analysis-or-submission">8. Delete a tag from an analysis or submission</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes tags from an analysis and/or a submission.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vmray-delete-tag</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 172px;"><strong>Argument Name</strong></th>
<th style="width: 470px;"><strong>Description</strong></th>
<th style="width: 98px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 172px;">analysis_id</td>
<td style="width: 470px;">ID of the analysis from which to delete a tag.</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">submission_id</td>
<td style="width: 470px;">ID of the submission from which to delete a tag.</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">tag</td>
<td style="width: 470px;">Tag to delete.</td>
<td style="width: 98px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-7">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-7">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>vmray-delete-tag submission_id=4569262 tag=faulty
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-7">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Tags: faulty has been added to submission: 4569262</p>
</div>
<div class="cl-preview-section">
<h3 id="get-iocs-for-a-sample">9. Get IOCs for a sample</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves indicators of compropmise for a specified sample.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-8">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vmray-get-iocs</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-8">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 286px;"><strong>Argument Name</strong></th>
<th style="width: 289px;"><strong>Description</strong></th>
<th style="width: 165px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 286px;">sample_id</td>
<td style="width: 289px;">ID of the sample.</td>
<td style="width: 165px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-8">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 274px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 404px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.URL.AnalysisID</td>
<td style="width: 62px;">Number</td>
<td style="width: 404px;">IDs of other analyses that contain the given URL.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.URL.URL</td>
<td style="width: 62px;">String</td>
<td style="width: 404px;">URL.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.URL.Operation</td>
<td style="width: 62px;">String</td>
<td style="width: 404px;">Operation of the specified URL.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.URL.ID</td>
<td style="width: 62px;">Number</td>
<td style="width: 404px;">ID of the URL.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.URL.Type</td>
<td style="width: 62px;">String</td>
<td style="width: 404px;">Type of URL.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.Domain.AnalysisID</td>
<td style="width: 62px;">Number</td>
<td style="width: 404px;">IDs of other analyses that contain the given domain.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.Domain.Domain</td>
<td style="width: 62px;">String</td>
<td style="width: 404px;">Domain.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.Domain.ID</td>
<td style="width: 62px;">Number</td>
<td style="width: 404px;">ID of the domain.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.Domain.Type</td>
<td style="width: 62px;">String</td>
<td style="width: 404px;">Type of domain.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.IP.AnalysisID</td>
<td style="width: 62px;">Number</td>
<td style="width: 404px;">IDs of other analyses that contain the given IP address.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.IP.IP</td>
<td style="width: 62px;">String</td>
<td style="width: 404px;">IP address.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.IP.Operation</td>
<td style="width: 62px;">String</td>
<td style="width: 404px;">Operation of the given IP.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.IP.ID</td>
<td style="width: 62px;">Number</td>
<td style="width: 404px;">ID of the IP address.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.IP.Type</td>
<td style="width: 62px;">String</td>
<td style="width: 404px;">Type of IP address.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.Mutex.AnalysisID</td>
<td style="width: 62px;">Number</td>
<td style="width: 404px;">IDs of other analyses that contains the given IP.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.Mutex.Name</td>
<td style="width: 62px;">String</td>
<td style="width: 404px;">Name of the mutex.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.Mutex.Operation</td>
<td style="width: 62px;">String</td>
<td style="width: 404px;">Operation of given mutex</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.Mutex.ID</td>
<td style="width: 62px;">Number</td>
<td style="width: 404px;">ID of the mutex.</td>
</tr>
<tr>
<td style="width: 274px;">VMRay.Sample.IOC.Mutex.Type</td>
<td style="width: 62px;">String</td>
<td style="width: 404px;">Type of mutex.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-8">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>vmray-get-iocs sample_id=3902238
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-4">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "VMRay.Sample": {
        "URL": [], 
        "IP": [], 
        "Domain": [], 
        "Mutex": [], 
        "Registry": []
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-8">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="no-iocs-found-in-sample-3902238">No IOCs found in sample 3902238</h3>
</div>
<div class="cl-preview-section">
<h3 id="get-information-for-a-job">10. Get information for a job</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves a job by job ID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-9">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vmray-get-job-by-id</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-9">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 321px;"><strong>Argument Name</strong></th>
<th style="width: 236px;"><strong>Description</strong></th>
<th style="width: 183px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 321px;">job_id</td>
<td style="width: 236px;">ID of a job.</td>
<td style="width: 183px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-9">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 256px;"><strong>Path</strong></th>
<th style="width: 84px;"><strong>Type</strong></th>
<th style="width: 400px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 256px;">VMRay.Job.JobID</td>
<td style="width: 84px;">Number</td>
<td style="width: 400px;">ID of the job.</td>
</tr>
<tr>
<td style="width: 256px;">VMRay.Job.SampleID</td>
<td style="width: 84px;">Number</td>
<td style="width: 400px;">Sample ID of the job.</td>
</tr>
<tr>
<td style="width: 256px;">VMRay.Job.SubmissionID</td>
<td style="width: 84px;">Number</td>
<td style="width: 400px;">ID of the submission.</td>
</tr>
<tr>
<td style="width: 256px;">VMRay.Job.MD5</td>
<td style="width: 84px;">String</td>
<td style="width: 400px;">MD5 hash of the sample in the job.</td>
</tr>
<tr>
<td style="width: 256px;">VMRay.Job.SHA1</td>
<td style="width: 84px;">String</td>
<td style="width: 400px;">SHA1 hash of the sample in the job.</td>
</tr>
<tr>
<td style="width: 256px;">VMRay.Job.SHA256</td>
<td style="width: 84px;">String</td>
<td style="width: 400px;">SHA256 hash of the sample in the job.</td>
</tr>
<tr>
<td style="width: 256px;">VMRay.Job.SSDeep</td>
<td style="width: 84px;">String</td>
<td style="width: 400px;">ssdeep hash of the sample in the job.</td>
</tr>
<tr>
<td style="width: 256px;">VMRay.Job.VMName</td>
<td style="width: 84px;">String</td>
<td style="width: 400px;">Name of the virtual machine.</td>
</tr>
<tr>
<td style="width: 256px;">VMRay.Job.VMID</td>
<td style="width: 84px;">Number</td>
<td style="width: 400px;">ID of the virtual machine.</td>
</tr>
<tr>
<td style="width: 256px;">VMRay.Job.Status</td>
<td style="width: 84px;">String</td>
<td style="width: 400px;">Status of the job.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-9">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!vmray-get-job-by-id job_id=365547
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-5">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "VMRay.Job": {
        "JobID": 365547,
        "SampleID": 3902238,
        "SubmissionID": 4569262,
        "SHA1": "b94951a9dde256624289abe8b9744d0f61fab8bb", 
        "SSDeep": "192:sv28pU/UDVCavCAIl20otWzFtyTI619lKoFt333esXPDOljpcS+oOKzHg4/IOSCS:sv23/eogCPzFcTIaaljXSKbUJiB", 
        "SHA256": "543da75d434d172533411bb4a23577d54e2c63d959974c91b5a3098aaa0cad07", 
        "MD5": "e24992f83bb3d0ed12b3e8cd7c35888f"
        "VMName": "windows8.1-x64 sp1",
        "VMID": 747112,
    }
}</pre>
</div>