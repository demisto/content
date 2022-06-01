<p>
    This integration was integrated and tested with <a href="https://caseapi.phishlabs.com/idapi/v1/docs/">V1.0 of
    PhishLabs IOC EIR api</a>
</p>
<h2>Use Cases</h2>
<ul>
    <li>Get live EIR from PhishLabs</li>
    <li>Get EIR by filters from PhishLabs</li>
</ul>
<h2>Detailed Description</h2>
<p>
    <a href="https://www.phishlabs.com/email-incident-response/">Phishlabs Email Incident Response (EIR)</a> is a
    solution that protects against threats that make it past your email security stack and into your employee inboxes.
    With Email Incident Response, enterprises can detect, prevent, and respond to these threats.
</p>
<ul>
    <li>Suspicious Email Analysis</li>
    <li>Email Threat Intelligence</li>
</ul>

<h2>Configure PhishLabs IOC EIR on Cortex XSOAR</h2>
<ol>
    <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
        &nbsp;<strong>Servers &amp; Services</strong>.
    </li>
    <li>Search for PhishLabs IOC EIR.</li>
    <li>
        Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
        <ul>
            <li><strong>Name</strong>: a textual name for the integration instance.</li>
            <li><strong>Server URL (e.g. https://example.net)</strong></li>
            <li><strong>User</strong></li>
            <li><strong>Source Reliability.</strong> Reliability of the source providing the intelligence data. (The default value is B - Usually reliable)</li>
            <li><strong>Fetch incidents</strong></li>
            <li><strong>First fetch timestamp ( e.g., 12 hours, 7 days)</strong></li>
            <li><strong>Fetch limit</strong></li>
            <li><strong>Trust any certificate (not secure)</strong></li>
            <li><strong>Use system proxy settings</strong></li>
        </ul>
    </li>
    <li>
        Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
    </li>
</ol>
<h2>Fetch Incidents</h2>
<p>Fetch incidents done by the following configuration:</p>
<ul>
    <li>Fetch limit - limit amount of incidents by fetch</li>
    <li>First fetch timestamp - date for starting collecting incidents (1 days ago, 1 hours ago etc)</li>
    <li>Incident type</li>
</ul>
<pre>
[
  {
    "name": "PhishLabs IOC - EIR: INC0528925",
    "occurred": "2019-10-15T16:31:09Z",
    "rawJSON": {
            "id": "INC0528925",
            "service": "EIR",
            "title": "Deploymentliste release 10.0 in PROD am 15.10.2019",
            "description": "",
            "status": "Closed",
            "details": {
                "caseType": "Response",
                "classification": "No Threat Detected",
                "subClassification": "No Threat Detected",
                "severity": null,
                "emailReportedBy": "johnnydepp@gmail.com",
                "submissionMethod": "Attachment",
                "sender": "johnnydepp@gmail.com",
                "emailBody": "Test",
                "urls": [
                    {
                        "url": "google.com",
                        "malicious": false,
                        "maliciousDomain": false
                    }
                ],
                "attachments": [],
                "furtherReviewReason": null,
                "offlineUponReview": false
            },
            "created": "2019-10-15T16:31:08Z",
            "modified": "2019-10-15T16:31:09Z",
            "closed": "2019-10-15T16:31:09Z",
            "duration": 0
        }
  }
]
</pre>

<h2>Commands</h2>
<p>
    You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
    After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
    <li>phishlabs-ioc-eir-get-incidents</li>
    <li>phishlabs-ioc-eir-get-incident-by-id</li>
</ol>
<h3>1. phishlabs-ioc-eir-get-incidents</h3>
<hr>
<p>Get EIR incidents from PhishLabs-IOC EIR service (dafault limit 25 incidents)</p>
<h5>Base Command</h5>
<p>
    <code>phishlabs-ioc-eir-get-incidents</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Argument Name</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
        <th>
            <strong>Required</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>status</td>
        <td>Filter incidents that are opened or closed.</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>created_after</td>
        <td>Return Incidents created on or after the given timestamp
            Timestamp is in RFC3339 format(2019-04-12T23:20:50Z)
        </td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>created_before</td>
        <td>Return Incidents created on or before the given timestamp
            Timestamp is in RFC3339 format(2019-04-12T23:20:50Z)
        </td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>closed_after</td>
        <td>Return Incidents closed on or after the given timestamp
            Timestamp is in RFC3339 format(2019-04-12T23:20:50Z)
        </td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>closed_before</td>
        <td>Return Incidents closed on or before the given timestamp
            Timestamp is in RFC3339 format(2019-04-12T23:20:50Z)
        </td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>sort</td>
        <td>Return Incidents sorted by the given column.</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>direction</td>
        <td>Return Incidents sorted by the given order. This will be applied to the given sort parameter.</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>limit</td>
        <td>Limit amounts of incidents (0-50, default 25)</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>offset</td>
        <td>Offset from last incident</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>period</td>
        <td>Period to query on 1 days, 2 hours</td>
        <td>Optional</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Path</strong>
        </th>
        <th>
            <strong>Type</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>PhishLabsIOC.EIR.CaseType</td>
        <td>String</td>
        <td>Incident reason type</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Classification</td>
        <td>String</td>
        <td>Incident classification</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.SubClassification</td>
        <td>String</td>
        <td>Detailed classification</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Severity</td>
        <td>String</td>
        <td>Incident severity</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.SubmissionMethod</td>
        <td>String</td>
        <td>Email submission method</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.FurtherReviewReason</td>
        <td>String</td>
        <td>Incident further review reason</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.ID</td>
        <td>String</td>
        <td>Id of incident</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Title</td>
        <td>String</td>
        <td>Title of reported incident</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Description</td>
        <td>String</td>
        <td>Description of reporeted incident</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Status</td>
        <td>Boolean</td>
        <td>Status of reported incident</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Created</td>
        <td>Date</td>
        <td>Date of incident creation</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Modified</td>
        <td>Date</td>
        <td>Date of incident last modified</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Closed</td>
        <td>Date</td>
        <td>Date of incident closing</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Duration</td>
        <td>Number</td>
        <td>Duration until closing incident in seconds</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.EmailReportedBy</td>
        <td>String</td>
        <td>User who reported the incident</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.EmailBody</td>
        <td>String</td>
        <td>Email body</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Sender</td>
        <td>String</td>
        <td>Email sender</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.URL.URL</td>
        <td>String</td>
        <td>Url found in body</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.URL.Malicious</td>
        <td>Boolean</td>
        <td>Is the url malicious?</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.URL.MaliciousDomain</td>
        <td>Boolean</td>
        <td>Is the url domain malicious?</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Attachment.FileName</td>
        <td>String</td>
        <td>Name of the attached file</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Attachment.MimeType</td>
        <td>String</td>
        <td>Attachemt mime type</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Attachment.MD5</td>
        <td>String</td>
        <td>Attachemt md5 hash</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Attachment.SHA256</td>
        <td>String</td>
        <td>Attachemt sha256 hash</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Attachment.Malicious</td>
        <td>Boolean</td>
        <td>Is the file malicious?</td>
    </tr>
    <tr>
        <td>Email.To</td>
        <td>String</td>
        <td>The recipient of the email.</td>
    </tr>
    <tr>
        <td>Email.From</td>
        <td>String</td>
        <td>The sender of the email.</td>
    </tr>
    <tr>
        <td>Email.Body/HTML</td>
        <td>String</td>
        <td>The plain-text version of the email.</td>
    </tr>
    <tr>
        <td>File.Name</td>
        <td>String</td>
        <td>The full file name (including file extension).</td>
    </tr>
    <tr>
        <td>File.SHA256</td>
        <td>Unknown</td>
        <td>The SHA256 hash of the file.</td>
    </tr>
    <tr>
        <td>File.MD5</td>
        <td>String</td>
        <td>The MD5 hash of the file.</td>
    </tr>
    <tr>
        <td>File.Malicious.Vendor</td>
        <td>String</td>
        <td>The vendor that reported the file as malicious.</td>
    </tr>
    <tr>
        <td>File.Malicious.Description</td>
        <td>String</td>
        <td>A description explaining why the file was determined to be malicious.</td>
    </tr>
    <tr>
        <td>URL.Data</td>
        <td>String</td>
        <td>The URL</td>
    </tr>
    <tr>
        <td>URL.Malicious.Vendor</td>
        <td>String</td>
        <td>The vendor reporting the URL as malicious.</td>
    </tr>
    <tr>
        <td>URL.Malicious.Description</td>
        <td>String</td>
        <td>A description of the malicious URL.</td>
    </tr>
    <tr>
        <td>DBotScore.Indicator</td>
        <td>String</td>
        <td>The indicator that was tested.</td>
    </tr>
    <tr>
        <td>DBotScore.Type</td>
        <td>String</td>
        <td>The indicator type.</td>
    </tr>
    <tr>
        <td>DBotScore.Vendor</td>
        <td>String</td>
        <td>The vendor used to calculate the score.</td>
    </tr>
    <tr>
        <td>DBotScore.Score</td>
        <td>String</td>
        <td>The actual score.</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
    <code>!phishlabs-ioc-eir-get-incidents limit=3</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": [
        {
            "Indicator": "https://google.com",
            "Score": 1,
            "Type": "URL",
            "Vendor": "PhishLabs IOC - EIR"
        }
    ],
    "Email": [
        {
            "Body/HTML": "Example body",
            "From": "LinkedIn Sales Navigator  not@domain.com",
            "To": "Michael Mammele not@domain.com"
        },
        {
            "Body/HTML": "Example body",
            "From": "Tony Prince not@domain.com",
            "To": "Tony Prince not@domain.com"
        },
        {
            "Body/HTML": "Example body",
            "From": "FileDoc2 not@domain.com",
            "To": "John LaCour not@domain.com"
        }
    ],
    "File": [],
    "PhishLabsIOC": {
        "EIR": [
            {
                "CaseType": "Link",
                "Classification": "No Threat Detected",
                "Closed": "2019-11-05T23:23:06Z",
                "Created": "2019-11-05T22:05:52Z",
                "Description": "",
                "Duration": 4635,
                "Email": {
                    "Attachment": [],
                    "EmailBody": "Example body",
                    "Sender": "LinkedIn Sales Navigator  not@domain.com",
                    "URL": [
                        {
                            "Malicious": false,
                            "MaliciousDomain": false,
                            "URL": "https://google.com"
                        }
                    ]
                },
                "EmailReportedBy": "Michael Mammele not@domain.com",
                "FurtherReviewReason": null,
                "ID": "INC0682881",
                "Modified": "2019-11-05T23:23:06Z",
                "Severity": null,
                "Status": "Closed",
                "SubClassification": "No Threat Detected",
                "SubmissionMethod": "Attachment",
                "Title": "See who else can influence your deals"
            }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>PhishLabs IOC - EIR - incidents</h3>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th><strong>ID</strong></th>
        <th><strong>Title</strong></th>
        <th><strong>Status</strong></th>
        <th><strong>Created</strong></th>
        <th><strong>Classification</strong></th>
        <th><strong>SubClassification</strong></th>
        <th><strong>EmailReportedBy</strong></th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> INC0682881</td>
        <td> See who else can influence your deals</td>
        <td> Closed</td>
        <td> 2019-11-05T22:05:52Z</td>
        <td> No Threat Detected</td>
        <td> No Threat Detected</td>
        <td> Michael Mammele not@domain.com</td>
    </tr>
    <tr>
        <td> INC0682040</td>
        <td> FW: Tuesday, November 5, 2019</td>
        <td> Closed</td>
        <td> 2019-11-05T20:30:48Z</td>
        <td> Malicious</td>
        <td> Link - Phishing</td>
        <td> Tony Prince not@domain.com</td>
    </tr>
    <tr>
        <td> INC0681982</td>
        <td> Tuesday, November 5, 2019</td>
        <td> Closed</td>
        <td> 2019-11-05T20:25:22Z</td>
        <td> Malicious</td>
        <td> Link - Phishing</td>
        <td> John LaCour not@domain.com</td>
    </tr>
    </tbody>
</table>
</p>

<h3>2. phishlabs-ioc-eir-get-incident-by-id</h3>
<hr>
<p>Returns a single Incident based on the given ID.</p>
<h5>Base Command</h5>
<p>
    <code>phishlabs-ioc-eir-get-incident-by-id</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Argument Name</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
        <th>
            <strong>Required</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>incident_id</td>
        <td>ID of Incident, Get it from previous command</td>
        <td>Required</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th>
            <strong>Path</strong>
        </th>
        <th>
            <strong>Type</strong>
        </th>
        <th>
            <strong>Description</strong>
        </th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>PhishLabsIOC.EIR.CaseType</td>
        <td>String</td>
        <td>Incident reason type</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Classification</td>
        <td>String</td>
        <td>Incident classification</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.SubClassification</td>
        <td>String</td>
        <td>Detailed classification</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Severity</td>
        <td>String</td>
        <td>Incident severity</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.SubmissionMethod</td>
        <td>String</td>
        <td>Email submission method</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.FurtherReviewReason</td>
        <td>String</td>
        <td>Incident further review reason</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.ID</td>
        <td>String</td>
        <td>Id of incident</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Title</td>
        <td>String</td>
        <td>Title of reported incident</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Description</td>
        <td>String</td>
        <td>Description of reporeted incident</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Status</td>
        <td>Boolean</td>
        <td>Status of reported incident</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Created</td>
        <td>Date</td>
        <td>Date of incident creation</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Modified</td>
        <td>Date</td>
        <td>Date of incident last modified</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Closed</td>
        <td>Date</td>
        <td>Date of incident closing</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Duration</td>
        <td>Number</td>
        <td>Duration until closing incident in seconds</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.EmailReportedBy</td>
        <td>String</td>
        <td>User who reported the incident</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.EmailBody</td>
        <td>String</td>
        <td>Email body</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Sender</td>
        <td>String</td>
        <td>Email sender</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.URL.URL</td>
        <td>String</td>
        <td>Url found in body</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.URL.Malicious</td>
        <td>Boolean</td>
        <td>Is the url malicious?</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.URL.MaliciousDomain</td>
        <td>Boolean</td>
        <td>Is the url domain malicious?</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Attachment.FileName</td>
        <td>String</td>
        <td>Name of the attached file</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Attachment.MimeType</td>
        <td>String</td>
        <td>Attachemt mime type</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Attachment.MD5</td>
        <td>String</td>
        <td>Attachemt md5 hash</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Attachment.SHA256</td>
        <td>String</td>
        <td>Attachemt sha256 hash</td>
    </tr>
    <tr>
        <td>PhishLabsIOC.EIR.Email.Attachment.Malicious</td>
        <td>Boolean</td>
        <td>Is the file malicious?</td>
    </tr>
    <tr>
        <td>Email.To</td>
        <td>String</td>
        <td>The recipient of the email.</td>
    </tr>
    <tr>
        <td>Email.From</td>
        <td>String</td>
        <td>The sender of the email.</td>
    </tr>
    <tr>
        <td>Email.Body/HTML</td>
        <td>String</td>
        <td>The plain-text version of the email.</td>
    </tr>
    <tr>
        <td>File.Name</td>
        <td>String</td>
        <td>The full file name (including file extension).</td>
    </tr>
    <tr>
        <td>File.SHA256</td>
        <td>Unknown</td>
        <td>The SHA256 hash of the file.</td>
    </tr>
    <tr>
        <td>File.MD5</td>
        <td>String</td>
        <td>The MD5 hash of the file.</td>
    </tr>
    <tr>
        <td>File.Malicious.Vendor</td>
        <td>String</td>
        <td>The vendor that reported the file as malicious.</td>
    </tr>
    <tr>
        <td>File.Malicious.Description</td>
        <td>String</td>
        <td>A description explaining why the file was determined to be malicious.</td>
    </tr>
    <tr>
        <td>URL.Data</td>
        <td>String</td>
        <td>The URL</td>
    </tr>
    <tr>
        <td>URL.Malicious.Vendor</td>
        <td>String</td>
        <td>The vendor reporting the URL as malicious.</td>
    </tr>
    <tr>
        <td>URL.Malicious.Description</td>
        <td>String</td>
        <td>A description of the malicious URL.</td>
    </tr>
    <tr>
        <td>DBotScore.Indicator</td>
        <td>String</td>
        <td>The indicator that was tested.</td>
    </tr>
    <tr>
        <td>DBotScore.Type</td>
        <td>String</td>
        <td>The indicator type.</td>
    </tr>
    <tr>
        <td>DBotScore.Vendor</td>
        <td>String</td>
        <td>The vendor used to calculate the score.</td>
    </tr>
    <tr>
        <td>DBotScore.Score</td>
        <td>String</td>
        <td>The actual score.</td>
    </tr>
    </tbody>
</table>
<h5>Command Example</h5>
<p>
    <code>!phishlabs-ioc-eir-get-incident-by-id incident_id=INC0671150</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "DBotScore": [
        {
            "Indicator": "https://google.com",
            "Score": 1,
            "Type": "URL",
            "Vendor": "PhishLabs IOC - EIR"
        }
    ],
    "Email": [
        {
            "Body/HTML": "Example body",
            "From": "LinkedIn Sales Navigator  not@domain.com",
            "To": "Michael Mammele not@domain.com"
        }
    ],
    "File": [],
    "PhishLabsIOC": {
        "EIR": [
            {
                "CaseType": "Link",
                "Classification": "No Threat Detected",
                "Closed": "2019-11-05T23:23:06Z",
                "Created": "2019-11-05T22:05:52Z",
                "Description": "",
                "Duration": 4635,
                "Email": {
                    "Attachment": [],
                    "EmailBody": "Example body",
                    "Sender": "LinkedIn Sales Navigator  not@domain.com",
                    "URL": [
                        {
                            "Malicious": false,
                            "MaliciousDomain": false,
                            "URL": "https://google.com"
                        }
                    ]
                },
                "EmailReportedBy": "Michael Mammele not@domain.com",
                "FurtherReviewReason": null,
                "ID": "INC0682881",
                "Modified": "2019-11-05T23:23:06Z",
                "Severity": null,
                "Status": "Closed",
                "SubClassification": "No Threat Detected",
                "SubmissionMethod": "Attachment",
                "Title": "See who else can influence your deals"
            }
    ]
}
</pre>
