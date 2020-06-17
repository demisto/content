<!-- HTML_DOC -->
<p>Use the TruSTAR v2 integration to manage reports, indicators and phishing submissions.</p>
<p>This integration was integrated and tested with TruSTAR v1.3. (TruSTAR Python SDK.)</p>
<h2>Use Cases</h2>
<ul>
<li>Search for indicators.</li>
<li>Retrieve indicators metadata.</li>
<li>Search for premium intel indicator summaries.</li>
<li>Add and remove indicators to the whitelist.</li>
<li>Filter reports using indicators.</li>
<li>Submit, update, delete, search, and get reports.</li>
<li>Get Phishing Indicadors and Phishing submissions.</li>
</ul>
<h2>Prerequisites</h2>
<p>Access your TruSTAR environment to obtain an API key and an API secret.</p>
<p>Navigate to <strong>Settings </strong>&gt; <strong>API </strong>&gt; <strong>API Credentials</strong>.</p>
<h2>Configure TruSTAR v2 on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for TruSTAR.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name:</strong> a textual name for the integration instance</li>
<li>
<strong>Server URL</strong> (example: https://192.168.0.1)</li>
<li><strong>TruSTAR API Key</strong></li>
<li><strong>TruSTAR API Secret</strong></li>
<li>Do not validate server certificate (not secure)</li>
<li>Use system proxy settings</li>
</ul>
</li>
<li>Click <strong>Test </strong>to validate connectivity and credentials.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_3942468361528291405689">Return a list of related indicators: trustar-related-indicators</a></li>
<li><a href="#h_151383312491528291448872">Trending indicators: trustar-trending-indicators</a></li>
<li><a href="#h_601442914901528291466003">Find an indicator: trustar-search-indicators</a></li>
<li><a href="#h_4295260251301528291478809">Submit a report: trustar-submit-report</a></li>
<li><a href="#h_2390523201661528291493621">Update a report: trustar-update-report</a></li>
<li><a href="#h_7239594532001528291506505">Return report details: trustar-report-details</a></li>
<li><a href="#h_8744143842331528291518588">Delete a report: trustar-delete-report</a></li>
<li><a href="#h_9223074962651528291535977">Generate a report: trustar-get-reports</a></li>
<li><a href="#h_6987239092961528291550310">Return correlated reports: trustar-correlated-reports</a></li>
<li><a href="#h_1950779103291528291565200">Search reports: trustar-search-reports</a></li>
<li><a href="#h_185400428431528626499848">Add indicators to whitelist: trustar-add-to-whitelist</a></li>
<li><a href="#h_2965863533601528291579105">Remove indicators from whitelist: trustar-remove-from-whitelist</a></li>
<li><a href="#h_564840413901528291593360">Get all enclaves: trustar-get-enclaves</a></li>
<li><a href="#h_trustar_indicators_metadata">Get indicators metadata: trustar-indicators-metadata</a></li>
<li><a href="#h_trustar_indicator_summaries">Get indicator summaries: 
trustar-indicator-summaries</a></li>
<li><a href="#h_trustar_phishing_indicators">Get phishing indicators: trustar-get-phishing-indicators</a></li>
<li><a href="#h_trustar_phishing_submissions">Get phishing submissions: trustar-get-phishing-submissions</a></li>

</ol>
<h3 id="h_3942468361528291405689">1. Return a list of related indicators</h3>
<hr>
<p>Returns a list of indicators related to a specified indicator.</p>
<h5>Command Example</h5>
<p><code>!trustar-related-indicators indicators=wannacry.exe</code></p>
<h5>Inputs</h5>
<table style="height: 141px; width: 653px;">
<thead>
<tr>
<td style="width: 148px;"><strong>Argument Name</strong></td>
<td style="width: 505px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">indicators</td>
<td style="width: 505px;">
<p>Example indicator types: IP address, email address, URL, MD5, SHA-1, SHA-256, registry key, malware name, and so on</p>
</td>
</tr>
<tr>
<td style="width: 148px;">enclave-ids</td>
<td style="width: 505px;">
<p>CSV of enclave IDs. Returns indicators found in reports from these enclaves only (default - all enclaves you have READ access to)</p>
</td>
</tr>
<tr>
<td style="width: 148px;">limit</td>
<td style="width: 505px;">Limit of results to return. Max value possible is 1000.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 147px; width: 663px;">
<thead>
<tr>
<td style="width: 300px;"><strong>Path</strong></td>
<td style="width: 345px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 300px;">File.Name</td>
<td style="width: 345px;">File name</td>
</tr>
<tr>
<td style="width: 300px;">File.MD5</td>
<td style="width: 345px;">File MD5</td>
</tr>
<tr>
<td style="width: 300px;">File.SHA1</td>
<td style="width: 345px;">File SHA-1</td>
</tr>
<tr>
<td style="width: 300px;">File.SHA256</td>
<td style="width: 345px;">File SHA-256</td>
</tr>
<tr>
<td style="width: 300px;">URL.Address</td>
<td style="width: 345px;">URL address</td>
</tr>
<tr>
<td style="width: 300px;">IP.Address</td>
<td style="width: 345px;">IP address</td>
</tr>
<tr>
<td style="width: 300px;">Account.Email.Address</td>
<td style="width: 345px;">Email address</td>
</tr>
<tr>
<td style="width: 300px;">RegistryKey.Path</td>
<td style="width: 345px;">Registry key path</td>
</tr>
<tr>
<td style="width: 300px;">CVE.ID</td>
<td style="width: 345px;">CVE ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre> [
    {
       "indicatorType": "SOFTWARE",
       "value": "00000000.res"
    }
 ]
</pre>
<h3 id="h_151383312491528291448872">2. Trending indicators</h3>
<hr>
<p>Returns trending indicators.</p>
<h5>Command Example</h5>
<p><code>!trustar-trending-indicators type=MALWARE raw-response=true</code></p>
<h5>Inputs</h5>
<table style="height: 172px; width: 750px;">
<thead>
<tr>
<td style="width: 161px;"><strong>Argument Name</strong></td>
<td style="width: 492px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 161px;">type</td>
<td style="width: 492px;">
<p>Types of indicators to return (by default, all indicator types except for CVE and MALWARE will be returned)</p>
</td>
</tr>
<tr>
<td style="width: 161px;">days-back</td>
<td style="width: 492px;">
<p>Number of days to count correlations for</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 86px; width: 750px;">
<thead>
<tr>
<td style="width: 306px;"><strong>Path</strong></td>
<td style="width: 361px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 306px;">File.Name</td>
<td style="width: 361px;">File name</td>
</tr>
<tr>
<td style="width: 306px;">File.MD5</td>
<td style="width: 361px;">File MD5</td>
</tr>
<tr>
<td style="width: 306px;">File.SHA1</td>
<td style="width: 361px;">File SHA-1</td>
</tr>
<tr>
<td style="width: 306px;">File.SHA256</td>
<td style="width: 361px;">File SHA-256</td>
</tr>
<tr>
<td style="width: 306px;">URL.Address</td>
<td style="width: 361px;">URL address</td>
</tr>
<tr>
<td style="width: 306px;">IP.Address</td>
<td style="width: 361px;">IP address</td>
</tr>
<tr>
<td style="width: 306px;">Account.Email.Address</td>
<td style="width: 361px;">Email address</td>
</tr>
<tr>
<td style="width: 306px;">RegistryKey.Path</td>
<td style="width: 361px;">Registry key path</td>
</tr>
<tr>
<td style="width: 306px;">CVE.ID</td>
<td style="width: 361px;">CVE ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>Formatted JSON Data
[  
   {  
      "correlationCount":109,
      "indicatorType":"MALWARE",
      "value":"IEXPLORE"
   }
]
</pre>
<h3 id="h_601442914901528291466003">3. Find an indicator</h3>
<hr>
<p>Search for a specific indicator.</p>
<h5>Command Example</h5>
<p><code>!trustar-search-indicators search-term=IEXPLORE</code></p>
<h5>Inputs</h5>
<table style="height: 177px; width: 750px;">
<thead>
<tr>
<td style="width: 142px;"><strong>Argument Name</strong></td>
<td style="width: 511px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142px;">search-term</td>
<td style="width: 511px;">
<p>Term to search for</p>
</td>
</tr>
<tr>
<td style="width: 142px;">enclave-ids</td>
<td style="width: 511px;">
<p>CSV of enclave IDs. Returns indicators found in reports from these enclaves only (default - all enclaves you have READ access to).</p>
</td>
</tr>
<tr>
<td style="width: 142px;">limit</td>
<td style="width: 511px;">Limit of results to return. Max value possible is 1000.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 86px; width: 750px;">
<thead>
<tr>
<td style="width: 282px;"><strong>Path</strong></td>
<td style="width: 380px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 282px;">File.Name</td>
<td style="width: 380px;">File name</td>
</tr>
<tr>
<td style="width: 282px;">File.MD5</td>
<td style="width: 380px;">File MD5</td>
</tr>
<tr>
<td style="width: 282px;">File.SHA1</td>
<td style="width: 380px;">File SHA-1</td>
</tr>
<tr>
<td style="width: 282px;">File.SHA256</td>
<td style="width: 380px;">File SHA-256</td>
</tr>
<tr>
<td style="width: 282px;">URL.Address</td>
<td style="width: 380px;">URL address</td>
</tr>
<tr>
<td style="width: 282px;">IP.Address</td>
<td style="width: 380px;">IP address</td>
</tr>
<tr>
<td style="width: 282px;">Account.Email.Address</td>
<td style="width: 380px;">Email address</td>
</tr>
<tr>
<td style="width: 282px;">RegistryKey.Path</td>
<td style="width: 380px;">Registry key path</td>
</tr>
<tr>
<td style="width: 282px;">CVE.ID</td>
<td style="width: 380px;">CVE ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "indicatorType":"SOFTWARE",
      "priorityLevel":"HIGH",
      "value":"iexplore.exe",
      "whitelisted":false
   }
]
</pre>
<h3 id="h_4295260251301528291478809">4. Submit a report</h3>
<hr>
<p>Creates a new report. This command does not generate content.</p>
<h5>Command Example</h5>
<p><code>!trustar-submit-report report-body=1.2.3.4,domain.com title=DailyReport distribution-type=ENCLAVE enclave-ids=3435626a-d0d6-4ba5-a229-1dd645d34da5</code></p>
<h5>Inputs</h5>
<table style="height: 177px; width: 750px;">
<thead>
<tr>
<td style="width: 158px;"><strong>Argument Name</strong></td>
<td style="width: 505px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 158px;">title</td>
<td style="width: 505px;">
<p>Title of the report</p>
</td>
</tr>
<tr>
<td style="width: 158px;">report-body</td>
<td style="width: 505px;">
<p>Text content of report</p>
</td>
</tr>
<tr>
<td style="width: 158px;">enclave-ids</td>
<td style="width: 505px;">
<p>CSV of TruSTAR-generated enclave IDs. Mandatory if the distribution type is ENCLAVE.</p>
<p><strong>NOTE: </strong>Use the enclave ID, not the enclave name.</p>
</td>
</tr>
<tr>
<td style="width: 158px;">distribution-type</td>
<td style="width: 505px;">Distribution type of the report</td>
</tr>
<tr>
<td style="width: 158px;">external-url</td>
<td style="width: 505px;">
<p>URL for the external report that this originated from, if one exists. Limited to 500 alphanumeric characters. Each company must have a unique URL for all of its reports.</p>
</td>
</tr>
<tr>
<td style="width: 158px;">time-began</td>
<td style="width: 505px;">
<p>ISO-8601 formatted incident time with timezone (for example: 2016-09-22T11:38:35+00:00) (default is current time)</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 86px; width: 750px;">
<thead>
<tr>
<td style="width: 293px;"><strong>Path</strong></td>
<td style="width: 364px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 293px;">TruSTAR.Report.title</td>
<td style="width: 364px;">Title of the report</td>
</tr>
<tr>
<td style="width: 293px;">TruSTAR.Report.reportBody</td>
<td style="width: 364px;">Body of the report</td>
</tr>
<tr>
<td style="width: 293px;">TruSTAR.Report.id</td>
<td style="width: 364px;">ID of the report</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "id":"ddda0c95-0b87-44b3-b38c-591f387f1be7",
   "reportBody":"1.2.3.4,domain.com",
   "title":"DailyReport"
}
</pre>
<h3 id="h_2390523201661528291493621">5. Update a report</h3>
<hr>
<p>Modifies an existing report.</p>
<h5>Inputs</h5>
<table style="height: 177px; width: 750px;">
<thead>
<tr>
<td style="width: 156px;"><strong>Argument Name</strong></td>
<td style="width: 511px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 156px;">report-id</td>
<td style="width: 511px;">
<p>TruSTAR report ID or external tracking ID</p>
</td>
</tr>
<tr>
<td style="width: 156px;">title</td>
<td style="width: 511px;">
<p>Title of the report</p>
</td>
</tr>
<tr>
<td style="width: 156px;">report-body</td>
<td style="width: 511px;">
<p>Text content of report</p>
</td>
</tr>
<tr>
<td style="width: 156px;">enclave-ids</td>
<td style="width: 511px;">
<p>CSV of TruSTAR-generated enclave IDs. Mandatory if the distribution type is ENCLAVE</p>
<p><strong>NOTE: </strong>Use the enclave ID, not the enclave name</p>
</td>
</tr>
<tr>
<td style="width: 156px;">external-url</td>
<td style="width: 511px;">
<p>URL for the external report that this originated from, if one exists. Limit 500 alphanumeric characters. Each company must have a unique URL for all of its reports.</p>
</td>
</tr>
<tr>
<td style="width: 156px;">distribution-type</td>
<td style="width: 511px;">
<p>Distribution type of the report</p>
</td>
</tr>
<tr>
<td style="width: 156px;">time-began</td>
<td style="width: 511px;">
<p>ISO-8601 formatted incident time with timezone (for example: 2016-09-22T11:38:35+00:00) Default is current time.</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 86px; width: 750px;">
<thead>
<tr>
<td style="width: 295px;"><strong>Path</strong></td>
<td style="width: 373px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 295px;">TruSTAR.Report.title</td>
<td style="width: 373px;">Title of the report</td>
</tr>
<tr>
<td style="width: 295px;">TruSTAR.Report.reportBody</td>
<td style="width: 373px;">Body of the report</td>
</tr>
<tr>
<td style="width: 295px;">TruSTAR.Report.id</td>
<td style="width: 373px;">
<p>ID of the report</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "id":"ddda0c95-0b87-44b3-b38c-591f387f1be7",
   "reportBody":"email@gmail.com",
   "title":"UpdateDailyReport"
}
</pre>
<h3 id="h_7239594532001528291506505">6. Return report details</h3>
<hr>
<p>Returns report metadata.</p>
<table style="height: 177px; width: 750px;">
<thead>
<tr>
<td style="width: 155px;"><strong>Argument Name</strong></td>
<td style="width: 509px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">report-id</td>
<td style="width: 509px;">
<p>TruSTAR report ID or external tracking ID</p>
</td>
</tr>
<tr>
<td style="width: 155px;">id-type</td>
<td style="width: 509px;">
<p>Type of report ID</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 119px; width: 750px;">
<thead>
<tr>
<td style="width: 284px;"><strong>Path</strong></td>
<td style="width: 382px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 284px;">TruSTAR.Report.title</td>
<td style="width: 382px;">Title of the report</td>
</tr>
<tr>
<td style="width: 284px;">TruSTAR.Report.reportBody</td>
<td style="width: 382px;">Body of the report</td>
</tr>
<tr>
<td style="width: 284px;">TruSTAR.Report.id</td>
<td style="width: 382px;">ID of the report</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "created":"2018-04-04 08:09:05",
   "distributionType":"ENCLAVE",
   "enclaveIds":"3435626a-d0d6-4ba5-a229-1dd645d34da5",
   "id":"ddda0c95-0b87-44b3-b38c-591f387f1be7",
   "reportBody":"email@gmail.com",
   "timeBegan":"2018-04-04 08:12:13",
   "title":"UpdateDailyReport",
   "updated":"2018-04-04 08:12:07"
}
</pre>
<h3 id="h_8744143842331528291518588">7. Delete a report</h3>
<hr>
<p>Deletes specified report.</p>
<h5>Input</h5>
<table style="height: 177px; width: 750px;">
<thead>
<tr>
<td style="width: 141px;"><strong>Argument Name</strong></td>
<td style="width: 467px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">report-id</td>
<td style="width: 467px;">
<p>TruSTAR report ID or external tracking ID</p>
</td>
</tr>
<tr>
<td style="width: 141px;">id-type</td>
<td style="width: 467px;">
<p>Type of report ID</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Raw output</h5>
<pre>Report ddda0c95-0b87-44b3-b38c-591f387f1be7 was successfully deleted
</pre>
<h3 id="h_9223074962651528291535977">8. Generate a report</h3>
<hr>
<p>Generates a report.</p>
<h5>Command Example</h5>
<p><code>!trustar-get-reports enclave-ids=3435626a-d0d6-4ba5-a229-1dd645d34da5:</code></p>
<h5>Input</h5>
<table style="height: 177px; width: 750px;">
<thead>
<tr>
<td style="width: 168px;"><strong>Argument Name</strong></td>
<td style="width: 440px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168px;">from</td>
<td style="width: 440px;">
<p>Start of time window.</p>
<p>Format is YY-MM-DD HH:MM:SS (example: 2018-01-01 10:30:00)</p>
<p>Based on updated time, not created time.</p>
<p>(Default is 1 day ago)</p>
</td>
</tr>
<tr>
<td style="width: 168px;">to</td>
<td style="width: 440px;">
<p>End of time window</p>
<p>Format is YY-MM-DD HH:MM:SS (example: 2018-01-01 10:30:00)</p>
<p>Based on updated time, not created time.</p>
<p>(Default is current time)</p>
</td>
</tr>
<tr>
<td style="width: 168px;">distribution-type</td>
<td style="width: 440px;">
<p>Whether to search for reports only in enclaves, or in the COMMUNITY too</p>
</td>
</tr>
<tr>
<td style="width: 168px;">enclave-ids</td>
<td style="width: 440px;">
<p>CSV of enclave IDs to search for reports in. Even if distribution-type is COMMUNITY, these enclaves will still be searched as well (default: all enclaves the user has READ access to)</p>
</td>
</tr>
<tr>
<td style="width: 168px;">tags</td>
<td style="width: 440px;">
<p>Names of tags to filter by</p>
<p><strong>NOTE: </strong>only reports containing ALL of these tags are returned</p>
</td>
</tr>
<tr>
<td style="width: 168px;">excluded-tags</td>
<td style="width: 440px;">
<p>Tags excluded from the report</p>
<p><strong>NOTE: </strong>Reports containing ANY of these tags are excluded from the results.</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 119px; width: 750px;">
<thead>
<tr>
<td style="width: 283px;"><strong>Path</strong></td>
<td style="width: 299px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 283px;">TruSTAR.Report.title</td>
<td style="width: 299px;">Title of the report</td>
</tr>
<tr>
<td style="width: 283px;">TruSTAR.Report.reportBody</td>
<td style="width: 299px;">Body of the report</td>
</tr>
<tr>
<td style="width: 283px;">TruSTAR.Report.id</td>
<td style="width: 299px;">ID of the report</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "created":"2018-04-04 08:23:05",
      "distributionType":"ENCLAVE",
      "enclaveIds":"3435626a-d0d6-4ba5-a229-1dd645d34da5",
      "id":"d445c743-8cd8-4c38-bcf4-7879f31ca6bf",
      "reportBody":"1.2.3.4,domain.com",
      "timeBegan":"2018-04-04 08:23:12",
      "title":"DailyReport",
      "updated":"2018-04-04 08:23:05"
   }
]
</pre>
<h3 id="h_6987239092961528291550310">9. Return correlated reports</h3>
<hr>
<p>Returns reports correlating to specified indicators.</p>
<h5>Command Example</h5>
<p><code>!trustar-correlated-reports indicators=NANOCORE:</code></p>
<h5>Inputs</h5>
<table style="height: 177px; width: 750px;">
<thead>
<tr>
<td style="width: 155px;"><strong>Argument Name</strong></td>
<td style="width: 453px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">indicators</td>
<td style="width: 453px;">
<p>Indicator value of any type (for example: an IP address, email address, URL, MD5, SHA-1, SHA-256, Registry Key, Malware name)</p>
</td>
</tr>
<tr>
<td style="width: 155px;">enclave-ids</td>
<td style="width: 453px;">
<p>CSV of enclave IDs. returns indicators found in reports from these enclaves only (default: all enclaves the user has READ access to)</p>
</td>
<tr>
<td style="width: 155px;">limit</td>
<td style="width: 453px;">
<p>Limit of results to return. Max value possible is 1000.</p>
</td>
</tr>
<tr>
<td style="width: 155px;">distribution-type</td>
<td style="width: 453px;">
<p>Distribution type of the report</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Raw Output</h5>
<pre>{  
   "created":"2018-04-04 12:14:31",
   "distributionType":"ENCLAVE",
   "enclaveIds":[  

   ],
   "id":"c7343c52-13d8-4125-8693-e0d4648a2e49",
   "reportBody":"",
   "timeBegan":"2018-04-04 12:14:27",
   "title":"hybridanalysispublicfeed-11a5d43169626282dd899a1bb0f96fe0-2018-04-04 11:24:52",
   "updated":"2018-04-04 12:14:31"
}
</pre>
<h3 id="h_1950779103291528291565200">10. Search reports</h3>
<hr>
<p>Returns reports based on search terms.</p>
<h5>Command Example</h5>
<p><code>!trustar-search-reports search-term=CVE</code></p>
<h5>Inputs</h5>
<table style="height: 177px; width: 750px;" cellpadding="6">
<thead>
<tr>
<td style="width: 130px;"><strong>Argument Name</strong></td>
<td style="width: 478px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 130px;">search-term</td>
<td style="width: 478px;">
<p>Term to search for</p>
</td>
</tr>
<tr>
<td style="width: 130px;">enclave-ids</td>
<td style="width: 478px;">
<p>CSV of enclave IDs. Returns indicators found in reports from these enclaves only (defaults to all of the user’s enclaves)</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "created":"2018-01-31 20:04:34",
      "distributionType":"ENCLAVE",
      "enclaveIds":[  

      ],
      "id":"57bffb4b-bcf7-44c8-9e14-4116a46fcb95",
      "timeBegan":"2018-04-04T14:00:05.636840+00:00",
      "title":"CVE-2018-2714",
      "updated":"2018-01-31 20:04:34"
   }
]
</pre>
<h3 id="h_185400428431528626499848">11. Add indicators to whitelist</h3>
<hr>
<p>Adds indicators to your whitelist.</p>
<h5>Inputs</h5>
<table style="height: 177px; width: 750px;">
<thead>
<tr>
<td style="width: 120px;"><strong>Argument Name</strong></td>
<td style="width: 488px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 120px;">indicators</td>
<td style="width: 488px;">
<p>CSV of indicators to whitelist (example: evil.com,101.43.52.224)</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Raw output:</h5>
<pre>Added to the whitelist successfully
</pre>
<h3 id="h_2965863533601528291579105">12. Remove indicators from whitelist</h3>
<hr>
<p>Remove indicator from your whitelist.</p>
<h5>Inputs</h5>
<table style="height: 177px; width: 750px;">
<thead>
<tr>
<td style="width: 138px;"><strong>Argument Name</strong></td>
<td style="width: 470px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">indicator</td>
<td style="width: 470px;">
<p>Value of the indicator to delete</p>
</td>
</tr>
<tr>
<td style="width: 138px;">indicator-type</td>
<td style="width: 470px;">
<p>Type of indicator to delete</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Raw Output</h5>
<pre>Removed from the whitelist successfully
</pre>
<h3 id="h_564840413901528291593360">13. Get all enclaves</h3>
<hr>
<p>Returns all enclaves.</p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Raw output:</h5>
<pre>[  
   {  
      "create":false,
      "id":"0e4443fc-2b50-4756-b5e0-4ea30030bcb3",
      "name":"Broadanalysis",
      "read":true,
      "type":"OPEN",
      "updated":false
   }
]
</pre>
<p> </p>

<h3 id="h_trustar_indicators_metadata">14. Get indicators metadata</h3>
<hr>
<p>Provide metadata associated with a list of indicators, including value, indicatorType, noteCount, enclaves the user making the request has READ access to.</p>
<h5>Command Example</h5>
<p><code>!trustar-indicators-metadata indicators=185.220.101.141</code></p>
<h5>Inputs</h5>
<table style="height: 141px; width: 653px;">
<thead>
<tr>
<td style="width: 148px;"><strong>Argument Name</strong></td>
<td style="width: 505px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">indicators</td>
<td style="width: 505px;">
<p>Comma separated indicator values. Values can be any of the following types; 
        i.e. an IP address, email address, URL, MD5, SHA1, SHA256, Registry Key, Malware name, etc.</p>
</td>
</tr>
<tr>
<td style="width: 148px;">enclave-ids</td>
<td style="width: 505px;">
<p>a list of enclave IDs to restrict to. By default, uses all of the user’s enclaves.</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 147px; width: 663px;">
<thead>
<tr>
<td style="width: 300px;"><strong>Path</strong></td>
<td style="width: 345px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 300px;">File.Name</td>
<td style="width: 345px;">File name</td>
</tr>
<tr>
<td style="width: 300px;">File.MD5</td>
<td style="width: 345px;">File MD5</td>
</tr>
<tr>
<td style="width: 300px;">File.SHA1</td>
<td style="width: 345px;">File SHA-1</td>
</tr>
<tr>
<td style="width: 300px;">File.SHA256</td>
<td style="width: 345px;">File SHA-256</td>
</tr>
<tr>
<td style="width: 300px;">URL.Address</td>
<td style="width: 345px;">URL address</td>
</tr>
<tr>
<td style="width: 300px;">IP.Address</td>
<td style="width: 345px;">IP address</td>
</tr>
<tr>
<td style="width: 300px;">Account.Email.Address</td>
<td style="width: 345px;">Email address</td>
</tr>
<tr>
<td style="width: 300px;">RegistryKey.Path</td>
<td style="width: 345px;">Registry key path</td>
</tr>
<tr>
<td style="width: 300px;">CVE.ID</td>
<td style="width: 345px;">CVE ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre> [
    {
        "correlationCount": 0,
        "enclaveIds": [
            "71f337a0-9696-4331-988a-5679271656a0",
            "011ad71b-fd7d-44c2-834a-0d751299fb1f",
            "080234eb-d818-4507-a676-dae5c5927d94",
            "d915e45a-d0c8-4a75-987a-775649020c96",
            "ed35f85a-d6bf-4e74-a0f8-61651abf705e"
        ],
        "firstSeen": "2020-05-07 20:49:36",
        "indicatorType": "IP",
        "lastSeen": "2020-06-13 02:06:01",
        "notes": [],
        "tags": [],
        "value": "185.220.101.141"
    }
]
</pre>
<p> </p>



<h3 id="h_trustar_indicator_summaries">15. Get indicator Summaries</h3>
<hr>
<p>Provides structured summaries about indicators, which are derived from intelligence sources on the TruSTAR Marketplace.</p>
<h5>Command Example</h5>
<p><code>!trustar-indicator-summaries indicators=185.220.101.141</code></p>
<h5>Inputs</h5>
<table style="height: 141px; width: 653px;">
<thead>
<tr>
<td style="width: 148px;"><strong>Argument Name</strong></td>
<td style="width: 505px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">values</td>
<td style="width: 505px;">
<p>Comma separated indicator values. Values can be any of the following types; 
i.e. an IP address, email address, URL, MD5, SHA1, SHA256, Registry Key, Malware name, etc.</p>
</td>
</tr>
<tr>
<td style="width: 148px;">enclave-ids</td>
<td style="width: 505px;">
<p>a list of enclave IDs to restrict to. By default, uses all of the user’s enclaves.</p>
</td>
</tr>
<tr>
<td style="width: 148px;">limit</td>
<td style="width: 505px;">Limit of results to return. Max value possible is 1000.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 147px; width: 663px;">
<thead>
<tr>
<td style="width: 300px;"><strong>Path</strong></td>
<td style="width: 345px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 300px;">File.Name</td>
<td style="width: 345px;">File name</td>
</tr>
<tr>
<td style="width: 300px;">File.MD5</td>
<td style="width: 345px;">File MD5</td>
</tr>
<tr>
<td style="width: 300px;">File.SHA1</td>
<td style="width: 345px;">File SHA-1</td>
</tr>
<tr>
<td style="width: 300px;">File.SHA256</td>
<td style="width: 345px;">File SHA-256</td>
</tr>
<tr>
<td style="width: 300px;">URL.Address</td>
<td style="width: 345px;">URL address</td>
</tr>
<tr>
<td style="width: 300px;">IP.Address</td>
<td style="width: 345px;">IP address</td>
</tr>
<tr>
<td style="width: 300px;">Account.Email.Address</td>
<td style="width: 345px;">Email address</td>
</tr>
<tr>
<td style="width: 300px;">RegistryKey.Path</td>
<td style="width: 345px;">Registry key path</td>
</tr>
<tr>
<td style="width: 300px;">CVE.ID</td>
<td style="width: 345px;">CVE ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre> JSON Containing Indicator Premium intel summaries.
</pre>

<p></p>

<h3 id="h_trustar_phishing_indicators">16. Get Phishing Indicators</h3>
<hr>
<p> Get phishing indicators that match the given criteria.</p>
<h5>Command Example</h5>
<p><code>!trustar-get-phishing-indicators</code></p>
<h5>Inputs</h5>
<table style="height: 141px; width: 653px;">
<thead>
<tr>
<td style="width: 148px;"><strong>Argument Name</strong></td>
<td style="width: 505px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">normalized_indicator_score</td>
<td style="width: 505px;">
<p>List of Intel scores to restrict the query. Possible values are -1, 0, 1, 2, 3. </p>
</td>
</tr>
<tr>
<td style="width: 148px;">priority_event_score</td>
<td style="width: 505px;">
<p>List of email submissions scores to restrict the query. Possible values are -1, 0, 1, 2, 3. </p>
</td>
</tr>
<tr>
<td style="width: 148px;">from_time</td>
<td style="width: 505px;">
<p>Start of time window (defaults to 24 hours ago) (YYYY-MM-DD HH:MM:SS)</p>
</td>
</tr>
<tr>
<td style="width: 148px;">to_time</td>
<td style="width: 505px;">
<p>End of time window (defaults to 24 hours ago) (YYYY-MM-DD HH:MM:SS)</p>
</td>
</tr>
<tr>
<td style="width: 148px;">status</td>
<td style="width: 505px;">A list of triage statuses for submissions; only email submissions marked with at least one of these statuses will be returned. Options are 'UNRESOLVED', 'CONFIRMED', 'IGNORED'</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 147px; width: 663px;">
<thead>
<tr>
<td style="width: 300px;"><strong>Path</strong></td>
<td style="width: 345px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 300px;">File.Name</td>
<td style="width: 345px;">File name</td>
</tr>
<tr>
<td style="width: 300px;">File.MD5</td>
<td style="width: 345px;">File MD5</td>
</tr>
<tr>
<td style="width: 300px;">File.SHA1</td>
<td style="width: 345px;">File SHA-1</td>
</tr>
<tr>
<td style="width: 300px;">File.SHA256</td>
<td style="width: 345px;">File SHA-256</td>
</tr>
<tr>
<td style="width: 300px;">URL.Address</td>
<td style="width: 345px;">URL address</td>
</tr>
<tr>
<td style="width: 300px;">IP.Address</td>
<td style="width: 345px;">IP address</td>
</tr>
<tr>
<td style="width: 300px;">Account.Email.Address</td>
<td style="width: 345px;">Email address</td>
</tr>
<tr>
<td style="width: 300px;">RegistryKey.Path</td>
<td style="width: 345px;">Registry key path</td>
</tr>
<tr>
<td style="width: 300px;">CVE.ID</td>
<td style="width: 345px;">CVE ID</td>
</tr>
</tbody>
</table>

<p> </p>


<h3 id="h_trustar_phishing_submissions">17. Get Phishing Submissions</h3>
<hr>
<p> Fetches all phishing submissions that fit the given criteria.</p>
<h5>Command Example</h5>
<p><code>!trustar-get-phishing-submissions</code></p>
<h5>Inputs</h5>
<table style="height: 141px; width: 653px;">
<thead>
<tr>
<td style="width: 148px;"><strong>Argument Name</strong></td>
<td style="width: 505px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">priority_event_score</td>
<td style="width: 505px;">
<p>List of email submissions scores to restrict the query. Possible values are -1, 0, 1, 2, 3. </p>
</td>
</tr>
<tr>
<td style="width: 148px;">from_time</td>
<td style="width: 505px;">
<p>Start of time window (defaults to 24 hours ago) (YYYY-MM-DD HH:MM:SS)</p>
</td>
</tr>
<tr>
<td style="width: 148px;">to_time</td>
<td style="width: 505px;">
<p>End of time window (defaults to 24 hours ago) (YYYY-MM-DD HH:MM:SS)</p>
</td>
</tr>
<tr>
<td style="width: 148px;">status</td>
<td style="width: 505px;">A list of triage statuses for submissions; only email submissions marked with at least one of these statuses will be returned. Options are 'UNRESOLVED', 'CONFIRMED', 'IGNORED'</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 147px; width: 663px;">
<thead>
<tr>
<td style="width: 300px;"><strong>Path</strong></td>
<td style="width: 345px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 300px;">TruSTAR.PhishingSubmission.submissionId</td>
<td style="width: 345px;">Submission ID</td>
</tr>
<tr>
<td style="width: 300px;">TruSTAR.PhishingSubmission.title</td>
<td style="width: 345px;">Submission title</td>
</tr>
<tr>
<td style="width: 300px;">TruSTAR.PhishingSubmission.normalizedTriageScore</td>
<td style="width: 345px;">Submission Triage Score</td>
</tr>
<tr>
<td style="width: 300px;">TruSTAR.PhishingSubmission.context.indicatorType</td>
<td style="width: 345px;">Indicator Type</td>
</tr>
<tr>
<td style="width: 300px;">TruSTAR.PhishingSubmission.context.sourceKey</td>
<td style="width: 345px;">Indicator Source</td>
</tr>
<tr>
<td style="width: 300px;">TruSTAR.PhishingSubmission.context.normalizedSourceScore</td>
<td style="width: 345px;">Indicator Score</td>
</tr>
<tr>
<td style="width: 300px;">TruSTAR.PhishingSubmission.context.originalIndicatorScore.name</td>
<td style="width: 345px;">Original Indicator score name</td>
</tr>
<tr>
<td style="width: 300px;">TruSTAR.PhishingSubmission.context.originalIndicatorScore.value</td>
<td style="width: 345px;">Original Indicator score value</td>
</tr>
</tbody>
</table>
<p> </p>