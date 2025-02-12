<!-- HTML_DOC -->
<p>Deprecated. Use the Cofense Triage v2 integration instead.</p>
<h2>Configure Cofense Triage on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Cofense Triage.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g.,<span> </span><a href="https://192.168.0.1/" rel="nofollow">https://192.168.0.1</a>)</strong></li>
<li><strong>User</strong></li>
<li><strong>API Token</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>First fetch time ( , e.g., 12 hours, 7 days, 3 months, 1 year)</strong></li>
<li><strong>Category ID to fetch - corresponds to the ranking that determines the Cofense Triage prioritization (1-5)</strong></li>
<li><strong>Match Priority - the highest match priority based on rule hits for the report</strong></li>
<li><strong>Tags - CSV list of tags of processed reports by which to filter</strong></li>
<li><strong>Maximum number of incidents to fetch each time</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<p>Test of mirroring! 1. 2. 3. 4.</p>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_e926473e-cece-4f98-8645-503850ed1aee" target="_self">Search reports: cofense-search-reports</a></li>
<li><a href="#h_f9f3b2c2-2432-48d5-adb5-8b6313bd8232" target="_self">Get an attachment: cofense-get-attachment</a></li>
<li><a href="#h_9381632d-4537-49d0-9e54-9187ae336bdf" target="_self">Get the reporter email address: cofense-get-reporter</a></li>
<li><a href="#h_dfc3649c-7e94-4d21-b1b2-629b5832ef9f" target="_self">Get a report: cofense-get-report-by-id</a></li>
</ol>
<h3 id="h_e926473e-cece-4f98-8645-503850ed1aee">1. Search reports</h3>
<hr>
<p>Runs a query for reports.</p>
<h5>Base Command</h5>
<p><code>cofense-search-reports</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">file_hash</td>
<td style="width: 526px;">File hash, MD5 or SHA256.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">url</td>
<td style="width: 526px;">The reported URLs.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">subject</td>
<td style="width: 526px;">Report subject.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">reported_at</td>
<td style="width: 526px;">Retrieve reports that were reported after this time, for example: "2 hours, 4 minutes, 6 month, 1 day".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">created_at</td>
<td style="width: 526px;">Retrieve reports that were created after this time, for example: "2 hours, 4 minutes, 6 month, 1 day".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">reporter</td>
<td style="width: 526px;">Name or ID of the reporter.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">max_matches</td>
<td style="width: 526px;">Maximum number of matches to fetch. Default is 30.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">verbose</td>
<td style="width: 526px;">Returns all fields of a report.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 214px;"><strong>Path</strong></th>
<th style="width: 70px;"><strong>Type</strong></th>
<th style="width: 456px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 214px;">Report.ID</td>
<td style="width: 70px;">unknown</td>
<td style="width: 456px;">ID number of the report.</td>
</tr>
<tr>
<td style="width: 214px;">Report.EmailAttachments</td>
<td style="width: 70px;">unknown</td>
<td style="width: 456px;">Email attachments.</td>
</tr>
<tr>
<td style="width: 214px;">Report.EmailAttachments.id</td>
<td style="width: 70px;">unknown</td>
<td style="width: 456px;">Email attachment ID.</td>
</tr>
<tr>
<td style="width: 214px;">Report.Tags</td>
<td style="width: 70px;">string</td>
<td style="width: 456px;">Report tags.</td>
</tr>
<tr>
<td style="width: 214px;">Report.ClusterId</td>
<td style="width: 70px;">number</td>
<td style="width: 456px;">Cluster ID number.</td>
</tr>
<tr>
<td style="width: 214px;">Report.CategoryId</td>
<td style="width: 70px;">number</td>
<td style="width: 456px;">Report category.</td>
</tr>
<tr>
<td style="width: 214px;">Report.CreatedAt</td>
<td style="width: 70px;">date</td>
<td style="width: 456px;">Report creation date.</td>
</tr>
<tr>
<td style="width: 214px;">Report.ReportedAt</td>
<td style="width: 70px;">string</td>
<td style="width: 456px;">Reporting time.</td>
</tr>
<tr>
<td style="width: 214px;">Report.MatchPriority</td>
<td style="width: 70px;">number</td>
<td style="width: 456px;">The highest match priority based on rule hits for the report.</td>
</tr>
<tr>
<td style="width: 214px;">Report.ReporterId</td>
<td style="width: 70px;">number</td>
<td style="width: 456px;">Reporter ID.</td>
</tr>
<tr>
<td style="width: 214px;">Report.Location</td>
<td style="width: 70px;">string</td>
<td style="width: 456px;">Location of the report.</td>
</tr>
<tr>
<td style="width: 214px;">Report.Reporter</td>
<td style="width: 70px;">string</td>
<td style="width: 456px;">Reporter email address.</td>
</tr>
<tr>
<td style="width: 214px;">Report.SuspectFromAddress</td>
<td style="width: 70px;">string</td>
<td style="width: 456px;">Suspect from address.</td>
</tr>
<tr>
<td style="width: 214px;">Report.ReportSubject</td>
<td style="width: 70px;">string</td>
<td style="width: 456px;">Report subject.</td>
</tr>
<tr>
<td style="width: 214px;">Report.ReportBody</td>
<td style="width: 70px;">string</td>
<td style="width: 456px;">Report body.</td>
</tr>
<tr>
<td style="width: 214px;">Report.Md5</td>
<td style="width: 70px;">number</td>
<td style="width: 456px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 214px;">Report.Sha256</td>
<td style="width: 70px;">unknown</td>
<td style="width: 456px;">SHA256 hash of the file.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>cofense-search-reports max_matches=30 created_at="60 days" reported_at="60 days" reporter=5328</pre>
<h5>Context Example</h5>
<pre>{
    "Cofense.Report": [
        {
            "ReportBody": "Good day\n\n\nPlease arrange to provide the best offer for below attached Purchase Order\nThe requirement for our green field project in Berghofen,Dortmund.\nKindly get back to us\n\n \n\n\n1) Proforma invoice with bank details\n\n2) Delivery date \n\n3) FOB/CIF Port\n\n \n\n \n \nRegards,\n\nkahn Gotze\nSales &amp; Services Assistant\n", 
            "ReportedAt": "2019-05-17T11:37:52.000Z", 
            "ReporterId": 5328, 
            "Tags": [], 
            "ClusterId": null, 
            "ID": 13232, 
            "Location": "Processed", 
            "EmailAttachments": [
                {
                    "content_type": "application/octet-stream; name=ORDER#t571BA80.rar", 
                    "size_in_bytes": 219777, 
                    "decoded_filename": "ORDER#t571BA80.rar", 
                    "email_attachment_payload": {
                        "sha256": "1e2c4ac7be08888c72c953adaeb79254e7e9b821988bfdad5d75d75b2467def1", 
                        "id": 7037, 
                        "mime_type": "application/x-rar; charset=binary", 
                        "md5": "e74c45a697651f3942f86fc5fce009df"
                    }, 
                    "id": 17831, 
                    "report_id": 13232
                }
            ], 
            "ReportSubject": "NEW ORDER", 
            "MatchPriority": 5, 
            "Sha256": "ca2579c53bd4ff0fa70fe38ae09a893c9332b8dfeab6ca7a13b89a709d54c0bb", 
            "CategoryId": 3, 
            "CreatedAt": "2019-05-17T16:57:16.343Z", 
            "Md5": "f5a1766371c063414d8b6a616b19bad0"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Reports:</h3>
<table class="" style="width: 2208px;" border="2">
<thead>
<tr>
<th style="width: 79px;">Category Id</th>
<th style="width: 553px;">Email Attachments</th>
<th style="width: 535px;">Sha256</th>
<th style="width: 134px;">Created At</th>
<th style="width: 45px;">Id</th>
<th style="width: 59px;">Match Priority</th>
<th style="width: 71px;">Location</th>
<th style="width: 154px;">Report Body</th>
<th style="width: 60px;">Report Subject</th>
<th style="width: 134px;">Reported At</th>
<th style="width: 70px;">Reporter Id</th>
<th style="width: 277px;">Md5</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 79px;">3</td>
<td style="width: 553px;">{'id': 17831, 'report_id': 13232, 'decoded_filename': 'ORDER#t571BA80.rar', 'content_type': 'application/octet-stream; name=ORDER#t571BA80.rar', 'size_in_bytes': 219777, 'email_attachment_payload': {'id': 7037, 'md5': 'e74c45a697651f3942f86fc5fce009df', 'sha256': '1e2c4ac7be08888c72c953adaeb79254e7e9b821988bfdad5d75d75b2467def1', 'mime_type': 'application/x-rar; charset=binary'}}</td>
<td style="width: 535px;">ca2579c53bd4ff0fa70fe38ae09a893c9332b8dfeab6ca7a13b89a709d54c0bb</td>
<td style="width: 134px;">2019-05-17T16:57:16.343Z</td>
<td style="width: 45px;">13232</td>
<td style="width: 59px;">5</td>
<td style="width: 71px;">Processed</td>
<td style="width: 154px;">Good day<br> <br> <br> Please arrange to provide the best offer for below attached Purchase Order<br> The requirement for our green field project in Berghofen,Dortmund.<br> Kindly get back to us<br> <br> <br> <br> <br> 1) Proforma invoice with bank details<br> <br> 2) Delivery date<span> </span><br> <br> 3) FOB/CIF Port<br> <br> <br> <br> <br> <br> Regards,<br> <br> kahn Gotze<br> Sales &amp; Services Assistant</td>
<td style="width: 60px;">NEW ORDER</td>
<td style="width: 134px;">2019-05-17T11:37:52.000Z</td>
<td style="width: 70px;">5328</td>
<td style="width: 277px;">f5a1766371c063414d8b6a616b19bad0</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_f9f3b2c2-2432-48d5-adb5-8b6313bd8232">2. Get an attachment</h3>
<hr>
<p>Retrieves an attachment by the attachment ID number.</p>
<h5>Base Command</h5>
<p><code>cofense-get-attachment</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 261px;"><strong>Argument Name</strong></th>
<th style="width: 329px;"><strong>Description</strong></th>
<th style="width: 150px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 261px;">attachment_id</td>
<td style="width: 329px;">ID of the attachment.</td>
<td style="width: 150px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 116px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 571px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 116px;">Attachment.ID</td>
<td style="width: 53px;">string</td>
<td style="width: 571px;">The ID number of the report that contains the attachment.</td>
</tr>
<tr>
<td style="width: 116px;">File.Size</td>
<td style="width: 53px;">string</td>
<td style="width: 571px;">The date and time (in UTC) when the threat was found on the device.</td>
</tr>
<tr>
<td style="width: 116px;">File.EntryID</td>
<td style="width: 53px;">string</td>
<td style="width: 571px;">The file path where the threat was found on the device.</td>
</tr>
<tr>
<td style="width: 116px;">File.Name</td>
<td style="width: 53px;">string</td>
<td style="width: 571px;">The name of the threat.</td>
</tr>
<tr>
<td style="width: 116px;">File.SHA1</td>
<td style="width: 53px;">string</td>
<td style="width: 571px;">The SHA1 hash of the threat.</td>
</tr>
<tr>
<td style="width: 116px;">File.SHA256</td>
<td style="width: 53px;">string</td>
<td style="width: 571px;">The SHA256 hash of the threat.</td>
</tr>
<tr>
<td style="width: 116px;">File.MD5</td>
<td style="width: 53px;">string</td>
<td style="width: 571px;">The MD5 hash of the threat.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>cofense-get-attachment attachment_id=8195</pre>
<h5>Context Example</h5>
<pre>{
    "Cofense.Attachment": {
        "ID": "8195"
    }
}
</pre>
<h3 id="h_9381632d-4537-49d0-9e54-9187ae336bdf">3. Get the reporter email address</h3>
<hr>
<p>Retrieves the email address of the reporter, by reporter ID.</p>
<h5>Base Command</h5>
<p><code>cofense-get-reporter</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 283px;"><strong>Argument Name</strong></th>
<th style="width: 295px;"><strong>Description</strong></th>
<th style="width: 162px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 283px;">reporter_id</td>
<td style="width: 295px;">ID of the reporter.</td>
<td style="width: 162px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 218px;"><strong>Path</strong></th>
<th style="width: 137px;"><strong>Type</strong></th>
<th style="width: 385px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 218px;">Report.ID</td>
<td style="width: 137px;">unknown</td>
<td style="width: 385px;">ID of the reporter.</td>
</tr>
<tr>
<td style="width: 218px;">Report.Email</td>
<td style="width: 137px;">unknown</td>
<td style="width: 385px;">Reporter email address.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>cofense-get-reporter reporter_id=5328</pre>
<h5>Context Example</h5>
<pre>{
    "Cofense.Reporter": {
        "Email": "vishnuetp16@gmail.com", 
        "ID": "5328"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>Reporter:<span> </span><a href="mailto:vishnuetp16@gmail.com">vishnuetp16@gmail.com</a></p>
<h3 id="h_dfc3649c-7e94-4d21-b1b2-629b5832ef9f">4. Get a report</h3>
<hr>
<p>Retrieves a report by the report ID.</p>
<h5>Base Command</h5>
<p><code>cofense-get-report-by-id</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 296px;"><strong>Argument Name</strong></th>
<th style="width: 276px;"><strong>Description</strong></th>
<th style="width: 168px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 296px;">report_id</td>
<td style="width: 276px;">ID of the report.</td>
<td style="width: 168px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 210px;"><strong>Path</strong></th>
<th style="width: 74px;"><strong>Type</strong></th>
<th style="width: 456px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 210px;">Report.ID</td>
<td style="width: 74px;">unknown</td>
<td style="width: 456px;">ID number of the report.</td>
</tr>
<tr>
<td style="width: 210px;">Report.EmailAttachments</td>
<td style="width: 74px;">unknown</td>
<td style="width: 456px;">Email attachments.</td>
</tr>
<tr>
<td style="width: 210px;">Report.EmailAttachments.id</td>
<td style="width: 74px;">unknown</td>
<td style="width: 456px;">Email attachment ID.</td>
</tr>
<tr>
<td style="width: 210px;">Report.Tags</td>
<td style="width: 74px;">string</td>
<td style="width: 456px;">Report tags.</td>
</tr>
<tr>
<td style="width: 210px;">Report.ClusterId</td>
<td style="width: 74px;">number</td>
<td style="width: 456px;">Cluster ID number.</td>
</tr>
<tr>
<td style="width: 210px;">Report.CategoryId</td>
<td style="width: 74px;">number</td>
<td style="width: 456px;">Report category.</td>
</tr>
<tr>
<td style="width: 210px;">Report.CreatedAt</td>
<td style="width: 74px;">date</td>
<td style="width: 456px;">Report creation date.</td>
</tr>
<tr>
<td style="width: 210px;">Report.ReportedAt</td>
<td style="width: 74px;">string</td>
<td style="width: 456px;">Reporting time.</td>
</tr>
<tr>
<td style="width: 210px;">Report.MatchPriority</td>
<td style="width: 74px;">number</td>
<td style="width: 456px;">The highest match priority based on rule hits for the report.</td>
</tr>
<tr>
<td style="width: 210px;">Report.ReporterId</td>
<td style="width: 74px;">number</td>
<td style="width: 456px;">Reporter ID.</td>
</tr>
<tr>
<td style="width: 210px;">Report.Location</td>
<td style="width: 74px;">string</td>
<td style="width: 456px;">Location of the report.</td>
</tr>
<tr>
<td style="width: 210px;">Report.Reporter</td>
<td style="width: 74px;">string</td>
<td style="width: 456px;">Reporter email address.</td>
</tr>
<tr>
<td style="width: 210px;">Report.SuspectFromAddress</td>
<td style="width: 74px;">string</td>
<td style="width: 456px;">Suspect from address.</td>
</tr>
<tr>
<td style="width: 210px;">Report.ReportSubject</td>
<td style="width: 74px;">string</td>
<td style="width: 456px;">Report subject.</td>
</tr>
<tr>
<td style="width: 210px;">Report.ReportBody</td>
<td style="width: 74px;">string</td>
<td style="width: 456px;">Report body.</td>
</tr>
<tr>
<td style="width: 210px;">Report.Md5</td>
<td style="width: 74px;">number</td>
<td style="width: 456px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 210px;">Report.Sha256</td>
<td style="width: 74px;">unknown</td>
<td style="width: 456px;">SHA256 hash of the file.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>cofense-get-report-by-id report_id=5760</pre>
<h5>Context Example</h5>
<pre>{
    "Cofense.Report": [
        {
            "ReportedAt": "2019-04-17T16:54:57.000Z", 
            "ReporterId": 3280, 
            "Reporter": "no-reply@server.com", 
            "Tags": [], 
            "ClusterId": null, 
            "ID": 5760, 
            "Location": "Processed", 
            "EmailAttachments": [], 
            "ReportSubject": "example.gmail.com Reset password instruction", 
            "MatchPriority": 0, 
            "Sha256": "4f6bc0d9c1217a2a6f327423e16b7a6e9294c68cfb33864541bd805fe4ab2d72", 
            "CategoryId": 4, 
            "CreatedAt": "2019-04-17T20:53:02.090Z", 
            "Md5": "f13bbc172fe7d394828ccabb25c3c99e"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Cofense HTML Report:</h3>
<p>HTML report download request has been completed</p>
<h3>Report Summary:</h3>
<table class="" style="width: 1360px;" border="2">
<thead>
<tr>
<th style="width: 77px;">Category Id</th>
<th style="width: 549px;">Sha256</th>
<th style="width: 122px;">Created At</th>
<th style="width: 36px;">Id</th>
<th style="width: 59px;">Match Priority</th>
<th style="width: 71px;">Location</th>
<th style="width: 165px;">Report Subject</th>
<th style="width: 73px;">Reported At</th>
<th style="width: 70px;">Reporter Id</th>
<th style="width: 34px;">Md5</th>
<th style="width: 70px;">Reporter</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 77px;">4</td>
<td style="width: 549px;">4f6bc0d9c1217a2a6f327423e16b7a6e9294c68cfb33864541bd805fe4ab2d72</td>
<td style="width: 122px;">2019-04-17T20:53:02.090Z</td>
<td style="width: 36px;">5760</td>
<td style="width: 59px;">0</td>
<td style="width: 71px;">Processed</td>
<td style="width: 165px;">example.gmail.com password i</td>
</tr>
</tbody>
</table>
