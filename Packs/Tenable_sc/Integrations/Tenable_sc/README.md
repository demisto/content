<!-- HTML_DOC -->
<p>Use the Tenable.sc integration to get a real-time, continuous assessment of your security posture so you can find and fix vulnerabilities faster.</p>
<p>All data in Tenable.sc is managed using group level permissions. If you have several groups, data (scans, scan results, assets, etc) can be viewable but not manageable. Users with Security Manager role  can manage everything. These permissions come into play when multiple groups are in use.</p>
<p>It is important to know what data is manageable for the user in order to work with the integration.</p>
<p>This integration was integrated and tested with Tenable.sc v5.7.0.</p>
<h2>Use cases</h2>
<ul>
<li>Create and run scans.</li>
<li>Launch and manage scan results and the found vulnerabilities.</li>
<li>Create and view assets.</li>
<li>View policies, repositories, credentials, users and more system information.</li>
<li>View and real-time receiving of alerts.</li>
</ul>
<h2>Tenable.sc Playbook</h2>
<p>Tenable.sc - Launch scan</p>
<p><br> <a href="https://user-images.githubusercontent.com/35098543/49026814-73d56f00-f1a7-11e8-8a19-4de81e5f6ed4.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49026814-73d56f00-f1a7-11e8-8a19-4de81e5f6ed4.png" alt="image" width="751" height="1335"></a></p>
<h2>Configure tenable.sc on Cortex XSOAR</h2>
<p>To use the Tenable.sc integration in Cortex XSOAR, a user with administrative privileges is recommended.</p>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Tenable.sc.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. https://192.168.0.1)</strong></li>
<li><strong>Username</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year):</strong></li>
<li><strong>Incident type</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Fetched Incidents Data</h2>
<p>For the first fetch, you can specify the time range to return alerts for. Subsequent fetches return alerts from Tenable.sc according to their last triggered time.</p>
<pre>[
            {
                "id": "1",
                "name": "bwu_alert1",
                "description": "",
                "lastTriggered": "1485891841",
                "triggerName": "sumip",
                "triggerOperator": "&gt;=",
                "triggerValue": "5",
                "action": [
                    {
                        "id": "1",
                        "type": "ticket",
                        "definition": {
                            "assignee": {
                                "id": "4",
                                "username": "API17",
                                "firstname": "API17",
                                "lastname": ""
                            },
                            "name": "Ticket opened by alert",
                            "description": "",
                            "notes": ""
                        },
                        "status": "0",
                        "users": [],
                        "objectID": null
                    }
                ],
                "query": {
                    "id": "1648",
                    "name": "Query for alert 'bwu_alert1' at 1463283903",
                    "description": ""
                },
                "owner": {
                    "id": "4",
                    "username": "API17",
                    "firstname": "API17",
                    "lastname": ""
                }
            },
            {
                "id": "2",
                "name": "Test Alert",
                "description": "Maya test alert",
                "lastTriggered": "1543248911",
                "triggerName": "sumip",
                "triggerOperator": "&gt;=",
                "triggerValue": "0",
                "action": [
                    {
                        "id": "10",
                        "type": "notification",
                        "definition": {
                            "message": "Event!",
                            "users": [
                                {
                                    "id": "53",
                                    "username": "API55",
                                    "firstname": "API55",
                                    "lastname": ""
                                }
                            ]
                        },
                        "status": "0",
                        "users": [
                            {
                                "id": "53",
                                "username": "API55",
                                "firstname": "API55",
                                "lastname": ""
                            }
                        ],
                        "objectID": null
                    },
                    {
                        "id": "11",
                        "type": "ticket",
                        "definition": {
                            "assignee": {
                                "id": "53",
                                "username": "API55",
                                "firstname": "API55",
                                "lastname": ""
                            },
                            "name": "Ticket opened by alert",
                            "description": "",
                            "notes": ""
                        },
                        "status": "0",
                        "users": [],
                        "objectID": null
                    }
                ],
                "query": {
                    "id": "12669",
                    "name": "IP Summary",
                    "description": ""
                },
                "owner": {
                    "id": "53",
                    "username": "API55",
                    "firstname": "API55",
                    "lastname": ""
                }
            },
            {
                "id": "3",
                "name": "Test fetch",
                "description": "",
                "lastTriggered": "0",
                "triggerName": "sumport",
                "triggerOperator": "&gt;=",
                "triggerValue": "1",
                "action": [
                    {
                        "id": "5",
                        "type": "ticket",
                        "definition": {
                            "assignee": {
                                "id": "53",
                                "username": "API55",
                                "firstname": "API55",
                                "lastname": ""
                            },
                            "name": "Ticket opened by alert",
                            "description": "",
                            "notes": ""
                        },
                        "status": "0",
                        "users": [],
                        "objectID": null
                    }
                ],
                "query": {
                    "id": "13177",
                    "name": "IPv4 Fixed Address: 11.0.0.2",
                    "description": ""
                },
                "owner": {
                    "id": "53",
                    "username": "API55",
                    "firstname": "API55",
                    "lastname": ""
                }
            }
        ]
</pre>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_33160870171543312761635">Get a list of scans: tenable-sc-list-scans</a></li>
<li><a href="#h_4066330872101543312766482">Initiate a scan: tenable-sc-launch-scan</a></li>
<li><a href="#h_9119778454121543312823365">Get vulnerability information for a scan: tenable-sc-get-vulnerability</a></li>
<li><a href="#h_8074541816131543312858886">Get the status of a scan: tenable-sc-get-scan-status</a></li>
<li><a href="#h_3345675088131543312902125">Get a report with scan results: tenable-sc-get-scan-report</a></li>
<li><a href="#h_84903194610121543312987425">Get a list of credentials: tenable-sc-list-credentials</a></li>
<li><a href="#h_45087102513991543313089428">Get a list of scan policies: tenable-sc-list-policies</a></li>
<li><a href="#h_73757213415961543313284753">Get a list of report definitions: tenable-sc-list-report-definitions</a></li>
<li><a href="#h_15731006419791543313350353">Get a list of scan repositories: tenable-sc-list-repositories</a></li>
<li><a href="#h_81875088221731543313376351">Get a list of scan zones: tenable-sc-list-zones</a></li>
<li><a href="#h_84471925432911543313482493">Create a scan: tenable-sc-create-scan</a></li>
<li><a href="#h_76467577134841543313487972">Delete a scan: tenable-sc-delete-scan</a></li>
<li><a href="#h_1815092436741543313492172">List all assets: tenable-sc-list-assets</a></li>
<li><a href="#h_692212738651543313496932">Create an asset: tenable-sc-create-asset</a></li>
<li><a href="#h_6996025840551543313501384">Get asset information: tenable-sc-get-asset</a></li>
<li><a href="#h_99298134042441543313506447">Delete an asset: tenable-sc-delete-asset</a></li>
<li><a href="#h_57421034944301543313511177">Get a list of alerts: tenable-sc-list-alerts</a></li>
<li><a href="#h_37606516346171543313517428">Get alert information: tenable-sc-get-alert</a></li>
<li><a href="#h_9307079148031543313522519">Get device information for a user: tenable-sc-get-device</a></li>
<li><a href="#h_85286374749881543313528453">Get a list of users: tenable-sc-list-users</a></li>
<li><a href="#h_11515143551721543313534950">Get licensing information: tenable-sc-get-system-licensing</a></li>
<li><a href="#h_90698695955281543313539949">Get system information and diagnostics: tenable-sc-get-system-information</a></li>
<li><a href="#h_88414951045411544018729183">Get device information: tenable-sc-get-device</a></li>
<li><a href="#h_4cbe5353-4319-44ef-b7ed-06628baf46a0" target="_self">Get all scan results: tenable-sc-get-all-scan-results</a></li>
</ol>
<h3 id="h_33160870171543312761635">1. Get a list of scans</h3>
<hr>
<p>Returns a list of existing Tenable.sc scans.</p>
<h5><span class="wysiwyg-underline"><strong>Base Command</strong></span></h5>
<p><code>tenable-sc-list-scans</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 132px;"><strong>Argument Name</strong></th>
<th style="width: 505px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 132px;">manageable</td>
<td style="width: 505px;">Whether to return only manageable scans. By default, returns both usable and manageable scans.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 285px;"><strong>Path</strong></th>
<th style="width: 96px;"><strong>Type</strong></th>
<th style="width: 327px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 285px;">TenableSC.Scan.Name</td>
<td style="width: 96px;">string</td>
<td style="width: 327px;">Scan name.</td>
</tr>
<tr>
<td style="width: 285px;">TenableSC.Scan.ID</td>
<td style="width: 96px;">number</td>
<td style="width: 327px;">Scan ID.</td>
</tr>
<tr>
<td style="width: 285px;">TenableSC.Scan.Description</td>
<td style="width: 96px;">string</td>
<td style="width: 327px;">Scan description.</td>
</tr>
<tr>
<td style="width: 285px;">TenableSC.Scan.Policy</td>
<td style="width: 96px;">string</td>
<td style="width: 327px;">Scan policy name.</td>
</tr>
<tr>
<td style="width: 285px;">TenableSC.Scan.Group</td>
<td style="width: 96px;">string</td>
<td style="width: 327px;">Scan policy owner group name.</td>
</tr>
<tr>
<td style="width: 285px;">TenableSC.Scan.Owner</td>
<td style="width: 96px;">string</td>
<td style="width: 327px;">Scan policy owner user name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !tenable-sc-list-scans manageable=true</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "Scan": [
            {
                "Group": "Full Access",
                "ID": "701",
                "Name": "Test55",
                "Owner": "API55",
                "Policy": "Basic Discovery Scan"
            },
            {
                "Group": "Full Access",
                "ID": "702",
                "Name": "Test55_2",
                "Owner": "API55",
                "Policy": "Full Scan"
            },
            {
                "Group": "Full Access",
                "ID": "703",
                "Name": "test55_3",
                "Owner": "API55",
                "Policy": "Full Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1266",
                "Name": "my_test",
                "Owner": "API55",
                "Policy": "Basic Discovery Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1267",
                "Name": "my_test",
                "Owner": "API55",
                "Policy": "Basic Discovery Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1270",
                "Name": "test5",
                "Owner": "API55",
                "Policy": "Basic Discovery Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1271",
                "Name": "my_test",
                "Owner": "API55",
                "Policy": "Basic Discovery Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1274",
                "Name": "sfsa",
                "Owner": "API55",
                "Policy": "Basic_Disc"
            },
            {
                "Description": "desc",
                "Group": "Full Access",
                "ID": "1275",
                "Name": "my_test_scan",
                "Owner": "API55",
                "Policy": "Basic Discovery Scan"
            },
            {
                "Description": "desc",
                "Group": "Full Access",
                "ID": "1276",
                "Name": "my_test_scan_plug",
                "Owner": "API55",
                "Policy": "Basic Network Scan"
            },
        
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49027810-b5ffb000-f1a9-11e8-8e89-7d5070668902.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49027810-b5ffb000-f1a9-11e8-8e89-7d5070668902.png" alt="image" width="749" height="430"></a></p>
<h3 id="h_4066330872101543312766482">2. Initiate a scan</h3>
<hr>
<p>Launches an existing scan from Tenable.sc.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-launch-scan</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 153px;"><strong>Argument Name</strong></th>
<th style="width: 484px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153px;">scan_id</td>
<td style="width: 484px;">Scan ID (can be retrieved from the <em>tenable-sc-list-scans</em> command).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">diagnostic_target</td>
<td style="width: 484px;">Valid IP/hostname of a specific target to scan. Must be provided with diagnosticPassword.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">diagnostic_password</td>
<td style="width: 484px;">Non empty string password.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 411px;"><strong>Path</strong></th>
<th style="width: 88px;"><strong>Type</strong></th>
<th style="width: 209px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 411px;">TenableSC.ScanResults.Name</td>
<td style="width: 88px;">string</td>
<td style="width: 209px;">Scan name.</td>
</tr>
<tr>
<td style="width: 411px;">TenableSC.ScanResults.ID</td>
<td style="width: 88px;">string</td>
<td style="width: 209px;">Scan Results ID.</td>
</tr>
<tr>
<td style="width: 411px;">TenableSC.ScanResults.OwnerID</td>
<td style="width: 88px;">string</td>
<td style="width: 209px;">Scan owner ID.</td>
</tr>
<tr>
<td style="width: 411px;">TenableSC.ScanResults.JobID</td>
<td style="width: 88px;">string</td>
<td style="width: 209px;">Job ID.</td>
</tr>
<tr>
<td style="width: 411px;">TenableSC.ScanResults.Status</td>
<td style="width: 88px;">string</td>
<td style="width: 209px;">Scan status.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-launch-scan scan_id=1275 diagnostic_target=10.0.0.1 diagnostic_password=mypass</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "ScanResults": {
            "ID": "3398",
            "JobID": "949739",
            "Name": "my_test_scan",
            "OwnerID": "53",
            "Status": "Queued"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49028016-1f7fbe80-f1aa-11e8-87ea-09863853058d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49028016-1f7fbe80-f1aa-11e8-87ea-09863853058d.png" alt="image" width="749" height="410"></a></p>
<h3 id="h_9119778454121543312823365">3. Get vulnerability information for a scan</h3>
<hr>
<p>Returns details about a vulnerability from a specified Tenable.sc scan.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-get-vulnerability</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 177px;"><strong>Argument Name</strong></th>
<th style="width: 434px;"><strong>Description</strong></th>
<th style="width: 97px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 177px;">vulnerability_id</td>
<td style="width: 434px;">Vulnerability ID from the scan-report command.</td>
<td style="width: 97px;">Required</td>
</tr>
<tr>
<td style="width: 177px;">scan_results_id</td>
<td style="width: 434px;">Scan results ID from the scan-report command.</td>
<td style="width: 97px;">Required</td>
</tr>
<tr>
<td style="width: 177px;">limit</td>
<td style="width: 434px;">The number of objects to return in one response (maximum limit is 200).</td>
<td style="width: 97px;">Optional</td>
</tr>
<tr>
<td style="width: 177px;">page</td>
<td style="width: 434px;">The page to return starting from 0.</td>
<td style="width: 97px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 399px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 242px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.ID</td>
<td style="width: 67px;">number</td>
<td style="width: 242px;">Scan results ID.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.ID</td>
<td style="width: 67px;">number</td>
<td style="width: 242px;">Vulnerability plugin ID.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.Name</td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability name.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.Description</td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability description.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.Type</td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability type.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.Severity</td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability Severity.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.Synopsis</td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability Synopsis.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.Solution</td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability Solution.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.Published</td>
<td style="width: 67px;">date</td>
<td style="width: 242px;">Vulnerability publish date.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.CPE</td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability CPE.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.CVE</td>
<td style="width: 67px;">unknown</td>
<td style="width: 242px;">Vulnerability CVE.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.ExploitAvailable</td>
<td style="width: 67px;">boolean</td>
<td style="width: 242px;">Vulnerability exploit available.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.ExploitEase</td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability exploit ease.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.RiskFactor</td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability risk factor.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.CVSSBaseScore</td>
<td style="width: 67px;">number</td>
<td style="width: 242px;">Vulnerability CVSS base score.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.CVSSTemporalScore</td>
<td style="width: 67px;">number</td>
<td style="width: 242px;">Vulnerability CVSS temporal score.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.CVSSVector</td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability CVSS vector.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Vulnerability.PluginDetails</td>
<td style="width: 67px;">unknown</td>
<td style="width: 242px;">Vulnerability plugin details.</td>
</tr>
<tr>
<td style="width: 399px;">CVE.ID</td>
<td style="width: 67px;">unknown</td>
<td style="width: 242px;">CVE ID.</td>
</tr>
<tr>
<td style="width: 399px;"><span>TenableSC.ScanResults.Vulnerability.Host.IP</span></td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability Host IP.</td>
</tr>
<tr>
<td style="width: 399px;"><span>TenableSC.ScanResults.Vulnerability.Host.MAC</span></td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability Host MAC.</td>
</tr>
<tr>
<td style="width: 399px;"><span>TenableSC.ScanResults.Vulnerability.Host.Port</span></td>
<td style="width: 67px;">number</td>
<td style="width: 242px;">Vulnerability Host Port.</td>
</tr>
<tr>
<td style="width: 399px;"><span>TenableSC.ScanResults.Vulnerability.Host.Protocol</span></td>
<td style="width: 67px;">string</td>
<td style="width: 242px;">Vulnerability Host Protocol.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-get-vulnerability scan_results_id=3331 vulnerability_id=117672</pre>
<h5>Context Example</h5>
<pre>{
    "CVE": [
        {
            "ID": "CVE-2018-7584"
        },
        {
            "ID": "CVE-2018-0737"
        },
        {
            "ID": "CVE-2018-10546"
        },
        {
            "ID": "CVE-2018-10547"
        },
        {
            "ID": "CVE-2018-10548"
        },
        {
            "ID": "CVE-2018-10549"
        },
        {
            "ID": "CVE-2018-10545"
        },
        {
            "ID": "CVE-2018-0732"
        },
        {
            "ID": "CVE-2018-14851"
        },
        {
            "ID": "CVE-2018-14883"
        },
        {
            "ID": "CVE-2018-15132"
        }
    ],
    "TenableSC": {
        "ScanResults": {
            "ID": "3331",
            "Vulnerability": {
                "CPE": "cpe:/a:tenable:securitycenter",
                "CVE": [
                    "CVE-2018-7584",
                    "CVE-2018-0737",
                    "CVE-2018-10546",
                    "CVE-2018-10547",
                    "CVE-2018-10548",
                    "CVE-2018-10549",
                    "CVE-2018-10545",
                    "CVE-2018-0732",
                    "CVE-2018-14851",
                    "CVE-2018-14883",
                    "CVE-2018-15132"
                ],
                "CVSSBaseScore": "7.5",
                "CVSSTemporalScore": null,
                "CVSSVector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "Description": "According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is prior to 5.7.1. It is, therefore, affected by multiple vulnerabilities.\n\nNote that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.",
                "ExploitAvailable": "false",
                "ExploitEase": "",
                "ID": "117672",
                "Name": "Tenable SecurityCenter \u003c 5.7.1 Multiple Vulnerabilities (TNS-2018-12)",
                "PluginDetails": {
                    "CheckType": "combined",
                    "Family": "Misc.",
                    "Modified": "2018-11-15T12:00:00Z",
                    "Published": "2018-09-24T12:00:00Z"
                },
                "Published": "2018-09-17T12:00:00Z",
                "RiskFactor": "High",
                "Severity": "High",
                "Solution": "Upgrade to Tenable SecurityCenter version 5.7.1 or later.",
                "Synopsis": "An application installed on the remote host is affected by multiple vulnerabilities.",
                "Type": "active"
            }
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/38749041/64108856-b0fa0d80-cd86-11e9-9b7d-163f9654c686.png"></p>
<h3 id="h_8074541816131543312858886">4. Get the status of a scan</h3>
<p>Returns the status of a specified scan in Tenable.sc.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-get-scan-status</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 167px;"><strong>Argument Name</strong></th>
<th style="width: 444px;"><strong>Description</strong></th>
<th style="width: 97px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 167px;">scan_results_id</td>
<td style="width: 444px;">Scan results ID from the <em>tenable-sc-launch-scan</em> command.</td>
<td style="width: 97px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 399px;"><strong>Path</strong></th>
<th style="width: 114px;"><strong>Type</strong></th>
<th style="width: 195px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Status</td>
<td style="width: 114px;">string</td>
<td style="width: 195px;">Scan status.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Name</td>
<td style="width: 114px;">string</td>
<td style="width: 195px;">Scan name.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.Description</td>
<td style="width: 114px;">unknown</td>
<td style="width: 195px;">Scan description.</td>
</tr>
<tr>
<td style="width: 399px;">TenableSC.ScanResults.ID</td>
<td style="width: 114px;">unknown</td>
<td style="width: 195px;">Scan results ID.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-get-scan-status scan_results_id=3331</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "ScanResults": {
            "ID": "3331",
            "Name": "中文scan",
            "Status": "Completed"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49030063-fd3c6f80-f1ae-11e8-8f6c-98f22fad3e2a.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49030063-fd3c6f80-f1ae-11e8-8f6c-98f22fad3e2a.png" alt="image" width="751" height="339"></a></p>
<h3 id="h_3345675088131543312902125">5. Get a report with scan results</h3>
<hr>
<p>Returns a single report with a Tenable.sc scan results.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-get-scan-report</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 490px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">scan_results_id</td>
<td style="width: 490px;">Scan results ID.</td>
<td style="width: 72px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">vulnerability_severity</td>
<td style="width: 490px;">Comma-separated list of severity values of vulnerabilities to retrieve.</td>
<td style="width: 72px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 385px;"><strong>Path</strong></th>
<th style="width: 71px;"><strong>Type</strong></th>
<th style="width: 252px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.ID</td>
<td style="width: 71px;">number</td>
<td style="width: 252px;">Scan results ID.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Name</td>
<td style="width: 71px;">string</td>
<td style="width: 252px;">Scan name.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Status</td>
<td style="width: 71px;">string</td>
<td style="width: 252px;">Scan status.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.ScannedIPs</td>
<td style="width: 71px;">number</td>
<td style="width: 252px;">Scan number of scanned IPs.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.StartTime</td>
<td style="width: 71px;">date</td>
<td style="width: 252px;">Scan start time.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.EndTime</td>
<td style="width: 71px;">date</td>
<td style="width: 252px;">Scan end time.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Checks</td>
<td style="width: 71px;">number</td>
<td style="width: 252px;">Scan completed checks.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.RepositoryName</td>
<td style="width: 71px;">string</td>
<td style="width: 252px;">Scan repository name.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Description</td>
<td style="width: 71px;">string</td>
<td style="width: 252px;">Scan description.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Vulnerability.ID</td>
<td style="width: 71px;">number</td>
<td style="width: 252px;">Scan vulnerability ID.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Vulnerability.Name</td>
<td style="width: 71px;">string</td>
<td style="width: 252px;">Scan vulnerability Name.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Vulnerability.Family</td>
<td style="width: 71px;">string</td>
<td style="width: 252px;">Scan vulnerability family.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Vulnerability.Severity</td>
<td style="width: 71px;">string</td>
<td style="width: 252px;">Scan vulnerability severity.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Vulnerability.Total</td>
<td style="width: 71px;">number</td>
<td style="width: 252px;">Scan vulnerability total hosts.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Policy</td>
<td style="width: 71px;">string</td>
<td style="width: 252px;">Scan policy.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Group</td>
<td style="width: 71px;">string</td>
<td style="width: 252px;">Scan owner group name.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Owner</td>
<td style="width: 71px;">string</td>
<td style="width: 252px;">Scan owner user name.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.Duration</td>
<td style="width: 71px;">number</td>
<td style="width: 252px;">Scan duration in minutes.</td>
</tr>
<tr>
<td style="width: 385px;">TenableSC.ScanResults.ImportTime</td>
<td style="width: 71px;">date</td>
<td style="width: 252px;">Scan import time.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !tenable-sc-get-scan-report scan_results_id=3331 vulnerability_severity=High
</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "ScanResults": {
            "Checks": "17155624",
            "Duration": 97.13333333333334,
            "EndTime": "2018-11-20T17:37:11Z",
            "Group": "Full Access",
            "ID": "3331",
            "ImportTime": "2018-11-20T17:37:15Z",
            "Name": "中文scan",
            "Owner": "API17",
            "Policy": "Basic Network Scan",
            "RepositoryName": "repo",
            "ScannedIPs": "172",
            "StartTime": "2018-11-20T16:00:03Z",
            "Status": "Completed",
            "Vulnerability": [
                {
                    "Description": "An update for bind is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Important. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe Berkeley Internet Name Domain (BIND) is an implementation of the Domain Name System (DNS) protocols. BIND includes a DNS server (named); a resolver library (routines for applications to use when interfacing with DNS); and tools for verifying that the DNS server is operating correctly.\n\nSecurity Fix(es) :\n\n* A use-after-free flaw leading to denial of service was found in the way BIND internally handled cleanup operations on upstream recursion fetch contexts. A remote attacker could potentially use this flaw to make named, acting as a DNSSEC validating resolver, exit unexpectedly with an assertion failure via a specially crafted DNS request.\n(CVE-2017-3145)\n\nRed Hat would like to thank ISC for reporting this issue. Upstream acknowledges Jayachandran Palanisamy (Cygate AB) as the original reporter.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "106234",
                    "Name": "CentOS 7 : bind (CESA-2018:0102)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for kernel is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Important. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe kernel packages contain the Linux kernel, the core of any Linux operating system.\n\nSecurity Fix(es) :\n\nAn industry-wide issue was found in the way many modern microprocessor designs have implemented speculative execution of instructions (a commonly used performance optimization). There are three primary variants of the issue which differ in the way the speculative execution can be exploited.\n\nNote: This issue is present in hardware and cannot be fully fixed via software update. The updated kernel packages provide software mitigation for this hardware issue at a cost of potential performance penalty. Please refer to References section for further information about this issue and the performance impact.\n\nIn this update initial mitigations for IBM Power (PowerPC) and IBM zSeries (S390) architectures are provided.\n\n* Variant CVE-2017-5715 triggers the speculative execution by utilizing branch target injection. It relies on the presence of a precisely-defined instruction sequence in the privileged code as well as the fact that memory accesses may cause allocation into the microprocessor's data cache even for speculatively executed instructions that never actually commit (retire). As a result, an unprivileged attacker could use this flaw to cross the syscall and guest/host boundaries and read privileged memory by conducting targeted cache side-channel attacks. This fix specifically addresses S390 processors. (CVE-2017-5715, Important)\n\n* Variant CVE-2017-5753 triggers the speculative execution by performing a bounds-check bypass. It relies on the presence of a precisely-defined instruction sequence in the privileged code as well as the fact that memory accesses may cause allocation into the microprocessor's data cache even for speculatively executed instructions that never actually commit (retire). As a result, an unprivileged attacker could use this flaw to cross the syscall boundary and read privileged memory by conducting targeted cache side-channel attacks. This fix specifically addresses S390 and PowerPC processors. (CVE-2017-5753, Important)\n\n* Variant CVE-2017-5754 relies on the fact that, on impacted microprocessors, during speculative execution of instruction permission faults, exception generation triggered by a faulting access is suppressed until the retirement of the whole instruction block. In a combination with the fact that memory accesses may populate the cache even when the block is being dropped and never committed (executed), an unprivileged local attacker could use this flaw to read privileged (kernel space) memory by conducting targeted cache side-channel attacks. Note: CVE-2017-5754 affects Intel x86-64 microprocessors. AMD x86-64 microprocessors are not affected by this issue. This fix specifically addresses PowerPC processors.\n(CVE-2017-5754, Important)\n\nRed Hat would like to thank Google Project Zero for reporting CVE-2017-5715, CVE-2017-5753, and CVE-2017-5754.\n\nThis update also fixes the following security issues and bugs :\n\nSpace precludes documenting all of the bug fixes and enhancements included in this advisory. To see the complete list of bug fixes and enhancements, refer to the following KnowledgeBase article:\nhttps://access.redhat.com/articles/ 3327131.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "106353",
                    "Name": "CentOS 7 : kernel (CESA-2018:0151) (Meltdown) (Spectre)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for dhcp is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Important. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe Dynamic Host Configuration Protocol (DHCP) is a protocol that allows individual devices on an IP network to get their own network configuration information, including an IP address, a subnet mask, and a broadcast address. The dhcp packages provide a relay agent and ISC DHCP service required to enable and administer DHCP on a network.\n\nSecurity Fix(es) :\n\n* dhcp: Buffer overflow in dhclient possibly allowing code execution triggered by malicious server (CVE-2018-5732)\n\n* dhcp: Reference count overflow in dhcpd allows denial of service (CVE-2018-5733)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nRed Hat would like to thank ISC for reporting these issues. Upstream acknowledges Felix Wilhelm (Google) as the original reporter of these issues.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "108338",
                    "Name": "CentOS 7 : dhcp (CESA-2018:0483)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for glibc is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Moderate. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe glibc packages provide the standard C libraries (libc), POSIX thread libraries (libpthread), standard math libraries (libm), and the name service cache daemon (nscd) used by multiple programs on the system. Without these libraries, the Linux system cannot function correctly.\n\nSecurity Fix(es) :\n\n* glibc: realpath() buffer underflow when getcwd() returns relative path allows privilege escalation (CVE-2018-1000001)\n\n* glibc: Buffer overflow in glob with GLOB_TILDE (CVE-2017-15670)\n\n* glibc: Buffer overflow during unescaping of user names with the ~ operator (CVE-2017-15804)\n\n* glibc: denial of service in getnetbyname function (CVE-2014-9402)\n\n* glibc: DNS resolver NULL pointer dereference with crafted record type (CVE-2015-5180)\n\n* glibc: Fragmentation attacks possible when EDNS0 is enabled (CVE-2017-12132)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nRed Hat would like to thank halfdog for reporting CVE-2018-1000001.\nThe CVE-2015-5180 issue was discovered by Florian Weimer (Red Hat Product Security).\n\nAdditional Changes :\n\nFor detailed information on changes in this release, see the Red Hat Enterprise Linux 7.5 Release Notes linked from the References section.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "109371",
                    "Name": "CentOS 7 : glibc (CESA-2018:0805)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for dhcp is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Critical. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe Dynamic Host Configuration Protocol (DHCP) is a protocol that allows individual devices on an IP network to get their own network configuration information, including an IP address, a subnet mask, and a broadcast address. The dhcp packages provide a relay agent and ISC DHCP service required to enable and administer DHCP on a network.\n\nSecurity Fix(es) :\n\n* A command injection flaw was found in the NetworkManager integration script included in the DHCP client packages in Red Hat Enterprise Linux. A malicious DHCP server, or an attacker on the local network able to spoof DHCP responses, could use this flaw to execute arbitrary commands with root privileges on systems using NetworkManager and configured to obtain network configuration using the DHCP protocol.\n(CVE-2018-1111)\n\nRed Hat would like to thank Felix Wilhelm (Google Security Team) for reporting this issue.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "109814",
                    "Name": "CentOS 7 : dhcp (CESA-2018:1453)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for procps-ng is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Important. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe procps-ng packages contain a set of system utilities that provide system information, including ps, free, skill, pkill, pgrep, snice, tload, top, uptime, vmstat, w, watch, and pwdx.\n\nSecurity Fix(es) :\n\n* procps-ng, procps: Integer overflows leading to heap overflow in file2strvec (CVE-2018-1124)\n\n* procps-ng, procps: incorrect integer size in proc/alloc.* leading to truncation / integer overflow issues (CVE-2018-1126)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nRed Hat would like to thank Qualys Research Labs for reporting these issues.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "110204",
                    "Name": "CentOS 7 : procps-ng (CESA-2018:1700)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for kernel is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Important. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe kernel packages contain the Linux kernel, the core of any Linux operating system.\n\nSecurity Fix(es) :\n\n* Kernel: KVM: error in exception handling leads to wrong debug stack value (CVE-2018-1087)\n\n* Kernel: error in exception handling leads to DoS (CVE-2018-8897)\n\n* Kernel: ipsec: xfrm: use-after-free leading to potential privilege escalation (CVE-2017-16939)\n\n* kernel: Out-of-bounds write via userland offsets in ebt_entry struct in netfilter/ebtables.c (CVE-2018-1068)\n\n* kernel: ptrace() incorrect error handling leads to corruption and DoS (CVE-2018-1000199)\n\n* kernel: guest kernel crash during core dump on POWER9 host (CVE-2018-1091)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nRed Hat would like to thank Andy Lutomirski for reporting CVE-2018-1087 and CVE-2018-1000199 and Nick Peterson (Everdox Tech LLC) and Andy Lutomirski for reporting CVE-2018-8897.\n\nBug Fix(es) :\n\nThese updated kernel packages include also numerous bug fixes. Space precludes documenting all of these bug fixes in this advisory. See the bug fix descriptions in the related Knowledge Article:\nhttps://access.redhat.com/ articles/3431641",
                    "Family": "CentOS Local Security Checks",
                    "ID": "110245",
                    "Name": "CentOS 7 : kernel (CESA-2018:1318)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for yum-utils is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Important. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe yum-utils packages provide a collection of utilities and examples for the yum package manager to make yum easier and more powerful to use.\n\nSecurity Fix(es) :\n\n* yum-utils: reposync: improper path validation may lead to directory traversal (CVE-2018-10897)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nRed Hat would like to thank Jay Grizzard (Clover Network) and Aaron Levy (Clover Network) for reporting this issue.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "111615",
                    "Name": "CentOS 7 : yum-utils (CESA-2018:2285)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for kernel is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Important. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe kernel packages contain the Linux kernel, the core of any Linux operating system.\n\nSecurity Fix(es) :\n\n* Modern operating systems implement virtualization of physical memory to efficiently use available system resources and provide inter-domain protection through access control and isolation. The L1TF issue was found in the way the x86 microprocessor designs have implemented speculative execution of instructions (a commonly used performance optimisation) in combination with handling of page-faults caused by terminated virtual to physical address resolving process. As a result, an unprivileged attacker could use this flaw to read privileged memory of the kernel or other processes and/or cross guest/host boundaries to read host memory by conducting targeted cache side-channel attacks.\n(CVE-2018-3620, CVE-2018-3646)\n\n* An industry-wide issue was found in the way many modern microprocessor designs have implemented speculative execution of instructions past bounds check. The flaw relies on the presence of a precisely-defined instruction sequence in the privileged code and the fact that memory writes occur to an address which depends on the untrusted value. Such writes cause an update into the microprocessor's data cache even for speculatively executed instructions that never actually commit (retire). As a result, an unprivileged attacker could use this flaw to influence speculative execution and/or read privileged memory by conducting targeted cache side-channel attacks.\n(CVE-2018-3693)\n\n* A flaw named SegmentSmack was found in the way the Linux kernel handled specially crafted TCP packets. A remote attacker could use this flaw to trigger time and calculation expensive calls to tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() functions by sending specially modified packets within ongoing TCP sessions which could lead to a CPU saturation and hence a denial of service on the system. Maintaining the denial of service condition requires continuous two-way TCP sessions to a reachable open port, thus the attacks cannot be performed using spoofed IP addresses.\n(CVE-2018-5390)\n\n* kernel: crypto: privilege escalation in skcipher_recvmsg function (CVE-2017-13215)\n\n* kernel: mm: use-after-free in do_get_mempolicy function allows local DoS or other unspecified impact (CVE-2018-10675)\n\n* kernel: race condition in snd_seq_write() may lead to UAF or OOB access (CVE-2018-7566)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nRed Hat would like to thank Intel OSSIRT (Intel.com) for reporting CVE-2018-3620 and CVE-2018-3646; Vladimir Kiriansky (MIT) and Carl Waldspurger (Carl Waldspurger Consulting) for reporting CVE-2018-3693;\nand Juha-Matti Tilli (Aalto University, Department of Communications and Networking and Nokia Bell Labs) for reporting CVE-2018-5390.\n\nBug Fix(es) :\n\nThese updated kernel packages include also numerous bug fixes. Space precludes documenting all of the bug fixes in this advisory. See the descriptions in the related Knowledge Article :\n\nhttps://access.redhat.com/articles/3527791",
                    "Family": "CentOS Local Security Checks",
                    "ID": "111703",
                    "Name": "CentOS 7 : kernel (CESA-2018:2384) (Foreshadow)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for mariadb is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Moderate. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nMariaDB is a multi-user, multi-threaded SQL database server that is binary compatible with MySQL.\n\nThe following packages have been upgraded to a later upstream version:\nmariadb (5.5.60). (BZ#1584668, BZ#1584671, BZ#1584674, BZ#1601085)\n\nSecurity Fix(es) :\n\n* mysql: Client programs unspecified vulnerability (CPU Jul 2017) (CVE-2017-3636)\n\n* mysql: Server: DML unspecified vulnerability (CPU Jul 2017) (CVE-2017-3641)\n\n* mysql: Client mysqldump unspecified vulnerability (CPU Jul 2017) (CVE-2017-3651)\n\n* mysql: Server: Replication unspecified vulnerability (CPU Oct 2017) (CVE-2017-10268)\n\n* mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2017) (CVE-2017-10378)\n\n* mysql: Client programs unspecified vulnerability (CPU Oct 2017) (CVE-2017-10379)\n\n* mysql: Server: DDL unspecified vulnerability (CPU Oct 2017) (CVE-2017-10384)\n\n* mysql: Server: Partition unspecified vulnerability (CPU Jan 2018) (CVE-2018-2562)\n\n* mysql: Server: DDL unspecified vulnerability (CPU Jan 2018) (CVE-2018-2622)\n\n* mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018) (CVE-2018-2640)\n\n* mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018) (CVE-2018-2665)\n\n* mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018) (CVE-2018-2668)\n\n* mysql: Server: Replication unspecified vulnerability (CPU Apr 2018) (CVE-2018-2755)\n\n* mysql: Client programs unspecified vulnerability (CPU Apr 2018) (CVE-2018-2761)\n\n* mysql: Server: Locking unspecified vulnerability (CPU Apr 2018) (CVE-2018-2771)\n\n* mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2018) (CVE-2018-2781)\n\n* mysql: Server: DDL unspecified vulnerability (CPU Apr 2018) (CVE-2018-2813)\n\n* mysql: Server: DDL unspecified vulnerability (CPU Apr 2018) (CVE-2018-2817)\n\n* mysql: InnoDB unspecified vulnerability (CPU Apr 2018) (CVE-2018-2819)\n\n* mysql: Server: DDL unspecified vulnerability (CPU Jul 2017) (CVE-2017-3653)\n\n* mysql: use of SSL/TLS not enforced in libmysqld (Return of BACKRONYM) (CVE-2018-2767)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nBug Fix(es) :\n\n* Previously, the mysqladmin tool waited for an inadequate length of time if the socket it listened on did not respond in a specific way.\nConsequently, when the socket was used while the MariaDB server was starting, the mariadb service became unresponsive for a long time.\nWith this update, the mysqladmin timeout has been shortened to 2 seconds. As a result, the mariadb service either starts or fails but no longer hangs in the described situation. (BZ#1584023)",
                    "Family": "CentOS Local Security Checks",
                    "ID": "112020",
                    "Name": "CentOS 7 : mariadb (CESA-2018:2439)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for bind is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Important. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe Berkeley Internet Name Domain (BIND) is an implementation of the Domain Name System (DNS) protocols. BIND includes a DNS server (named); a resolver library (routines for applications to use when interfacing with DNS); and tools for verifying that the DNS server is operating correctly.\n\nSecurity Fix(es) :\n\n* bind: processing of certain records when 'deny-answer-aliases' is in use may trigger an assert leading to a denial of service (CVE-2018-5740)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nRed Hat would like to thank ISC for reporting this issue. Upstream acknowledges Tony Finch (University of Cambridge) as the original reporter.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "112164",
                    "Name": "CentOS 7 : bind (CESA-2018:2570)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is prior to 5.7.1. It is, therefore, affected by multiple vulnerabilities.\n\nNote that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.",
                    "Family": "Misc.",
                    "ID": "117672",
                    "Name": "Tenable SecurityCenter \u003c 5.7.1 Multiple Vulnerabilities (TNS-2018-12)",
                    "Severity": "High",
                    "Total": "2"
                },
                {
                    "Description": "An update for kernel is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Important. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe kernel packages contain the Linux kernel, the core of any Linux operating system.\n\nSecurity Fix(es) :\n\n* kernel: Integer overflow in Linux's create_elf_tables function (CVE-2018-14634)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nRed Hat would like to thank Qualys Research Labs for reporting this issue.\n\nBug Fix(es) :\n\nThese updated kernel packages include also numerous bug fixes. Space precludes documenting all of the bug fixes in this advisory. See the descriptions in the related Knowledge Article :\n\nhttps://access.redhat.com/articles/3588731",
                    "Family": "CentOS Local Security Checks",
                    "ID": "117829",
                    "Name": "CentOS 7 : kernel (CESA-2018:2748)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "Updated X.org server and driver packages are now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Low. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link (s) in the References section.\n\nX.Org is an open source implementation of the X Window System. It provides the basic low-level functionality that full-fledged graphical user interfaces are designed upon.\n\nSecurity Fix(es) :\n\n* libxcursor: 1-byte heap-based overflow in _XcursorThemeInherits function in library.c (CVE-2015-9262)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nAdditional Changes :\n\nFor detailed information on changes in this release, see the Red Hat Enterprise Linux 7.6 Release Notes linked from the References section.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "118986",
                    "Name": "CentOS 7 : freeglut / libX11 / libXcursor / libXfont / libXfont2 / libXres / libdrm / libepoxy / etc (CESA-2018:3059)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for kernel is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Important. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe kernel packages contain the Linux kernel, the core of any Linux operating system.\n\nSecurity Fix(es) :\n\n* A flaw named FragmentSmack was found in the way the Linux kernel handled reassembly of fragmented IPv4 and IPv6 packets. A remote attacker could use this flaw to trigger time and calculation expensive fragment reassembly algorithm by sending specially crafted packets which could lead to a CPU saturation and hence a denial of service on the system. (CVE-2018-5391)\n\n* kernel: out-of-bounds access in the show_timer function in kernel/time/ posix-timers.c (CVE-2017-18344)\n\n* kernel: Integer overflow in udl_fb_mmap() can allow attackers to execute code in kernel space (CVE-2018-8781)\n\n* kernel: MIDI driver race condition leads to a double-free (CVE-2018-10902)\n\n* kernel: Missing check in inode_init_owner() does not clear SGID bit on non-directories for non-members (CVE-2018-13405)\n\n* kernel: AIO write triggers integer overflow in some protocols (CVE-2015-8830)\n\n* kernel: Use-after-free in snd_pcm_info function in ALSA subsystem potentially leads to privilege escalation (CVE-2017-0861)\n\n* kernel: Handling of might_cancel queueing is not properly pretected against race (CVE-2017-10661)\n\n* kernel: Salsa20 encryption algorithm does not correctly handle zero-length inputs allowing local attackers to cause denial of service (CVE-2017-17805)\n\n* kernel: Inifinite loop vulnerability in madvise_willneed() function allows local denial of service (CVE-2017-18208)\n\n* kernel: fuse-backed file mmap-ed onto process cmdline arguments causes denial of service (CVE-2018-1120)\n\n* kernel: a NULL pointer dereference in dccp_write_xmit() leads to a system crash (CVE-2018-1130)\n\n* kernel: drivers/block/loop.c mishandles lo_release serialization allowing denial of service (CVE-2018-5344)\n\n* kernel: Missing length check of payload in _sctp_make_chunk() function allows denial of service (CVE-2018-5803)\n\n* kernel: buffer overflow in drivers/net/wireless/ath/wil6210/ wmi.c:wmi_set_ie() may lead to memory corruption (CVE-2018-5848)\n\n* kernel: out-of-bound write in ext4_init_block_bitmap function with a crafted ext4 image (CVE-2018-10878)\n\n* kernel: Improper validation in bnx2x network card driver can allow for denial of service attacks via crafted packet (CVE-2018-1000026)\n\n* kernel: Information leak when handling NM entries containing NUL (CVE-2016-4913)\n\n* kernel: Mishandling mutex within libsas allowing local Denial of Service (CVE-2017-18232)\n\n* kernel: NULL pointer dereference in ext4_process_freed_data() when mounting crafted ext4 image (CVE-2018-1092)\n\n* kernel: NULL pointer dereference in ext4_xattr_inode_hash() causes crash with crafted ext4 image (CVE-2018-1094)\n\n* kernel: vhost: Information disclosure in vhost/vhost.c:vhost_new_msg() (CVE-2018-1118)\n\n* kernel: Denial of service in resv_map_release function in mm/hugetlb.c (CVE-2018-7740)\n\n* kernel: Memory leak in the sas_smp_get_phy_events function in drivers/scsi/ libsas/sas_expander.c (CVE-2018-7757)\n\n* kernel: Invalid pointer dereference in xfs_ilock_attr_map_shared() when mounting crafted xfs image allowing denial of service (CVE-2018-10322)\n\n* kernel: use-after-free detected in ext4_xattr_set_entry with a crafted file (CVE-2018-10879)\n\n* kernel: out-of-bound access in ext4_get_group_info() when mounting and operating a crafted ext4 image (CVE-2018-10881)\n\n* kernel: stack-out-of-bounds write in jbd2_journal_dirty_metadata function (CVE-2018-10883)\n\n* kernel: incorrect memory bounds check in drivers/cdrom/cdrom.c (CVE-2018-10940)\n\nRed Hat would like to thank Juha-Matti Tilli (Aalto University - Department of Communications and Networking and Nokia Bell Labs) for reporting CVE-2018-5391; Trend Micro Zero Day Initiative for reporting CVE-2018-10902; Qualys Research Labs for reporting CVE-2018-1120;\nEvgenii Shatokhin (Virtuozzo Team) for reporting CVE-2018-1130; and Wen Xu for reporting CVE-2018-1092 and CVE-2018-1094.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "118990",
                    "Name": "CentOS 7 : kernel (CESA-2018:3083)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for glibc is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Moderate. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe glibc packages provide the standard C libraries (libc), POSIX thread libraries (libpthread), standard math libraries (libm), and the name service cache daemon (nscd) used by multiple programs on the system. Without these libraries, the Linux system cannot function correctly.\n\nSecurity Fix(es) :\n\n* glibc: Incorrect handling of RPATH in elf/dl-load.c can be used to execute code loaded from arbitrary libraries (CVE-2017-16997)\n\n* glibc: Integer overflow in posix_memalign in memalign functions (CVE-2018-6485)\n\n* glibc: Integer overflow in stdlib/canonicalize.c on 32-bit architectures leading to stack-based buffer overflow (CVE-2018-11236)\n\n* glibc: Buffer overflow in __mempcpy_avx512_no_vzeroupper (CVE-2018-11237)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nAdditional Changes :\n\nFor detailed information on changes in this release, see the Red Hat Enterprise Linux 7.6 Release Notes linked from the References section.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "118992",
                    "Name": "CentOS 7 : glibc (CESA-2018:3092)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Moderate. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nGNOME is the default desktop environment of Red Hat Enterprise Linux.\n\nSecurity Fix(es) :\n\n* libsoup: Crash in soup_cookie_jar.c:get_cookies() on empty hostnames (CVE-2018-12910)\n\n* poppler: Infinite recursion in fofi/FoFiType1C.cc:FoFiType1C::cvtGlyph() function allows denial of service (CVE-2017-18267)\n\n* libgxps: heap based buffer over read in ft_font_face_hash function of gxps-fonts.c (CVE-2018-10733)\n\n* libgxps: Stack-based buffer overflow in calling glib in gxps_images_guess_content_type of gcontenttype.c (CVE-2018-10767)\n\n* poppler: NULL pointer dereference in Annot.h:AnnotPath::getCoordsLength() allows for denial of service via crafted PDF (CVE-2018-10768)\n\n* poppler: out of bounds read in pdfunite (CVE-2018-13988)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nRed Hat would like to thank chenyuan (NESA Lab) for reporting CVE-2018-10733 and CVE-2018-10767 and Hosein Askari for reporting CVE-2018-13988.\n\nAdditional Changes :\n\nFor detailed information on changes in this release, see the Red Hat Enterprise Linux 7.6 Release Notes linked from the References section.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "118995",
                    "Name": "CentOS 7 : PackageKit / accountsservice / adwaita-icon-theme / appstream-data / at-spi2-atk / etc (CESA-2018:3140)",
                    "Severity": "High",
                    "Total": "1"
                },
                {
                    "Description": "An update for curl and nss-pem is now available for Red Hat Enterprise Linux 7.\n\nRed Hat Product Security has rated this update as having a security impact of Moderate. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.\n\nThe curl packages provide the libcurl library and the curl utility for downloading files from servers using various protocols, including HTTP, FTP, and LDAP.\n\nThe nss-pem package provides the PEM file reader for Network Security Services (NSS) implemented as a PKCS#11 module.\n\nSecurity Fix(es) :\n\n* curl: HTTP authentication leak in redirects (CVE-2018-1000007)\n\n* curl: FTP path trickery leads to NIL byte out of bounds write (CVE-2018-1000120)\n\n* curl: RTSP RTP buffer over-read (CVE-2018-1000122)\n\n* curl: Out-of-bounds heap read when missing RTSP headers allows information leak of denial of service (CVE-2018-1000301)\n\n* curl: LDAP NULL pointer dereference (CVE-2018-1000121)\n\nFor more details about the security issue(s), including the impact, a CVSS score, and other related information, refer to the CVE page(s) listed in the References section.\n\nRed Hat would like to thank the Curl project for reporting these issues. Upstream acknowledges Craig de Stigter as the original reporter of CVE-2018-1000007; Duy Phan Thanh as the original reporter of CVE-2018-1000120; Max Dymond as the original reporter of CVE-2018-1000122; the OSS-fuzz project as the original reporter of CVE-2018-1000301; and Dario Weisser as the original reporter of CVE-2018-1000121.\n\nAdditional Changes :\n\nFor detailed information on changes in this release, see the Red Hat Enterprise Linux 7.6 Release Notes linked from the References section.",
                    "Family": "CentOS Local Security Checks",
                    "ID": "118996",
                    "Name": "CentOS 7 : curl / nss-pem (CESA-2018:3157)",
                    "Severity": "High",
                    "Total": "1"
                }
            ]
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49028753-cd3f9d00-f1ab-11e8-99ad-186696dfa8be.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49028753-cd3f9d00-f1ab-11e8-99ad-186696dfa8be.png" alt="image" width="751" height="322"></a><br> <a href="https://user-images.githubusercontent.com/35098543/49028775-da5c8c00-f1ab-11e8-9ec5-b1ee233662f9.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49028775-da5c8c00-f1ab-11e8-9ec5-b1ee233662f9.png" alt="image" width="750" height="439"></a></p>
<h3 id="h_84903194610121543312987425">6. Get a list of credentials</h3>
<hr>
<p>Returns a list of Tenable.sc credentials.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-list-credentials</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 494px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">manageable</td>
<td style="width: 494px;">Whether to return only manageable scan credentials. By default, returns both usable and manageable.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 329px;"><strong>Path</strong></th>
<th style="width: 83px;"><strong>Type</strong></th>
<th style="width: 296px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 329px;">TenableSC.Credential.Name</td>
<td style="width: 83px;">string</td>
<td style="width: 296px;">Credential name.</td>
</tr>
<tr>
<td style="width: 329px;">TenableSC.Credential.ID</td>
<td style="width: 83px;">number</td>
<td style="width: 296px;">Credential ID.</td>
</tr>
<tr>
<td style="width: 329px;">TenableSC.Credential.Description</td>
<td style="width: 83px;">string</td>
<td style="width: 296px;">Credential description.</td>
</tr>
<tr>
<td style="width: 329px;">TenableSC.Credential.Type</td>
<td style="width: 83px;">string</td>
<td style="width: 296px;">Credential type.</td>
</tr>
<tr>
<td style="width: 329px;">TenableSC.Credential.Tag</td>
<td style="width: 83px;">string</td>
<td style="width: 296px;">Credential tag.</td>
</tr>
<tr>
<td style="width: 329px;">TenableSC.Credential.Group</td>
<td style="width: 83px;">string</td>
<td style="width: 296px;">Credential owner group name.</td>
</tr>
<tr>
<td style="width: 329px;">TenableSC.Credential.Owner</td>
<td style="width: 83px;">string</td>
<td style="width: 296px;">Credential owner user name.</td>
</tr>
<tr>
<td style="width: 329px;">TenableSC.Credential.LastModified</td>
<td style="width: 83px;">date</td>
<td style="width: 296px;">Credential last modified time.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-list-credentials</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "Credential": [
            {
                "ID": "1",
                "LastModified": "2017-10-30T21:17:34Z",
                "Name": "asdfasdf",
                "Type": "windows"
            },
            {
                "Group": "Full Access",
                "ID": "1000001",
                "LastModified": "2016-06-23T14:59:38Z",
                "Name": "cloris_windows_p1",
                "Type": "windows"
            },
            {
                "Group": "Full Access",
                "ID": "1000002",
                "LastModified": "2017-04-06T10:32:54Z",
                "Name": "cred admin api30",
                "Type": "windows"
            },
            {
                "Group": "Full Access",
                "ID": "1000003",
                "LastModified": "2017-04-19T14:04:21Z",
                "Name": "151",
                "Type": "windows"
            },
            {
                "Group": "Full Access",
                "ID": "1000004",
                "LastModified": "2017-05-15T22:12:38Z",
                "Name": "TestSSH creds",
                "Type": "ssh"
            },
            {
                "Group": "Full Access",
                "ID": "1000005",
                "LastModified": "2017-11-17T15:42:11Z",
                "Name": "Thycotic Test",
                "Type": "windows"
            },
            {
                "Group": "Full Access",
                "ID": "1000006",
                "LastModified": "2018-05-10T20:11:27Z",
                "Name": "testAPI",
                "Tag": "testAPI",
                "Type": "windows"
            },
            {
                "Group": "Full Access",
                "ID": "1000007",
                "LastModified": "2018-05-30T16:22:02Z",
                "Name": "Test",
                "Type": "database"
            },
            {
                "Description": "asgasdg",
                "Group": "Full Access",
                "ID": "1000008",
                "LastModified": "2018-05-30T16:22:42Z",
                "Name": "awefawef",
                "Tag": "testAPI",
                "Type": "windows"
            },
            {
                "Group": "Full Access",
                "ID": "1000009",
                "LastModified": "2018-05-30T16:23:00Z",
                "Name": "oracle",
                "Type": "database"
            },
            {
                "Group": "Full Access",
                "ID": "1000010",
                "LastModified": "2018-05-30T16:23:18Z",
                "Name": "KerbTest",
                "Type": "windows"
            },
            {
                "Group": "Full Access",
                "ID": "1000011",
                "LastModified": "2018-05-30T16:23:28Z",
                "Name": "snmpTest",
                "Type": "snmp"
            },
            {
                "Group": "Full Access",
                "ID": "1000012",
                "LastModified": "2018-05-30T16:23:43Z",
                "Name": "lmhash",
                "Type": "windows"
            },
            {
                "Group": "Full Access",
                "ID": "1000013",
                "LastModified": "2018-05-30T16:24:00Z",
                "Name": "ntlmhash",
                "Type": "windows"
            },
            {
                "Group": "Full Access",
                "ID": "1000014",
                "LastModified": "2018-05-30T16:24:24Z",
                "Name": "thycoti_secret",
                "Type": "windows"
            },
            {
                "Group": "Full Access",
                "ID": "1000015",
                "LastModified": "2018-05-30T16:24:56Z",
                "Name": "sshcert",
                "Type": "ssh"
            },
            {
                "Group": "Full Access",
                "ID": "1000016",
                "LastModified": "2018-05-30T16:25:10Z",
                "Name": "sshpassword",
                "Type": "ssh"
            },
            {
                "Group": "Full Access",
                "ID": "1000017",
                "LastModified": "2018-05-30T17:34:43Z",
                "Name": "SSHPublic Key",
                "Type": "ssh"
            },
            {
                "Group": "Full Access",
                "ID": "1000018",
                "LastModified": "2018-11-06T19:34:13Z",
                "Name": "SymbolPassword Test",
                "Type": "windows"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49030220-69b76e80-f1af-11e8-9e2e-460865a99921.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49030220-69b76e80-f1af-11e8-9e2e-460865a99921.png" alt="image" width="751" height="288"></a></p>
<h3 id="h_45087102513991543313089428">7. Get a list of scan policies</h3>
<hr>
<p>Returns a list of Tenable.sc scan policies.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-list-policies</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 493px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">manageable</td>
<td style="width: 493px;">Whether to return only manageable scan policies. By default, returns both usable and manageable.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 330px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 298px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 330px;">TenableSC.ScanPolicy.Name</td>
<td style="width: 80px;">string</td>
<td style="width: 298px;">Scan policy name.</td>
</tr>
<tr>
<td style="width: 330px;">TenableSC.ScanPolicy.ID</td>
<td style="width: 80px;">number</td>
<td style="width: 298px;">Scan policy ID.</td>
</tr>
<tr>
<td style="width: 330px;">TenableSC.ScanPolicy.Description</td>
<td style="width: 80px;">string</td>
<td style="width: 298px;">Scan policy description.</td>
</tr>
<tr>
<td style="width: 330px;">TenableSC.ScanPolicy.Tag</td>
<td style="width: 80px;">string</td>
<td style="width: 298px;">Scan policy tag.</td>
</tr>
<tr>
<td style="width: 330px;">TenableSC.ScanPolicy.Group</td>
<td style="width: 80px;">string</td>
<td style="width: 298px;">Scan policy owner group name.</td>
</tr>
<tr>
<td style="width: 330px;">TenableSC.ScanPolicy.Owner</td>
<td style="width: 80px;">string</td>
<td style="width: 298px;">Scan policy owner user name.</td>
</tr>
<tr>
<td style="width: 330px;">TenableSC.ScanPolicy.LastModified</td>
<td style="width: 80px;">date</td>
<td style="width: 298px;">Scan policy last modified time.</td>
</tr>
<tr>
<td style="width: 330px;">TenableSC.ScanPolicy.Type</td>
<td style="width: 80px;">string</td>
<td style="width: 298px;">Scan policy type.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-list-policies</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "ScanPolicy": [
            {
                "Group": "Full Access",
                "ID": "1000001",
                "LastModified": "2016-05-04T11:35:27Z",
                "Name": "MV Scan Policy",
                "Owner": "API7",
                "Type": "Advanced Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000002",
                "LastModified": "2016-05-04T11:35:58Z",
                "Name": "Web Application Tests",
                "Owner": "API7",
                "Type": "Web Application Tests"
            },
            {
                "Group": "Full Access",
                "ID": "1000003",
                "LastModified": "2016-05-04T11:36:25Z",
                "Name": "Basic Network Scan",
                "Owner": "API7",
                "Type": "Basic Network Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000004",
                "LastModified": "2016-06-23T14:41:08Z",
                "Name": "Windows Malware Scan",
                "Owner": "API17",
                "Type": "Malware Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000005",
                "LastModified": "2017-03-25T03:28:13Z",
                "Name": "Compliance Test SC Host",
                "Owner": "tenable",
                "Type": "Policy Compliance Auditing"
            },
            {
                "Group": "Full Access",
                "ID": "1000006",
                "LastModified": "2017-04-04T13:05:25Z",
                "Name": "Maiware Scan",
                "Owner": "API30",
                "Type": "Malware Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000008",
                "LastModified": "2017-04-24T18:12:39Z",
                "Name": "Basic Discovery Scan",
                "Owner": "API33",
                "Type": "Host Discovery"
            },
            {
                "Group": "Full Access",
                "ID": "1000009",
                "LastModified": "2017-05-17T00:43:07Z",
                "Name": "Test Citrix",
                "Owner": "API34",
                "Type": "Advanced Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000010",
                "LastModified": "2017-05-17T00:44:20Z",
                "Name": "test juniper",
                "Owner": "API34",
                "Type": "Advanced Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000011",
                "LastModified": "2017-05-17T00:45:02Z",
                "Name": "test vmware",
                "Owner": "API34",
                "Type": "Advanced Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000012",
                "LastModified": "2017-05-17T23:49:02Z",
                "Name": "Test PaloAlto Template",
                "Owner": "API34",
                "Type": "Advanced Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000014",
                "LastModified": "2017-09-20T16:41:40Z",
                "Name": "Full Scan",
                "Owner": "tenable",
                "Type": "Basic Network Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000015",
                "LastModified": "2017-10-17T08:05:13Z",
                "Name": "cisco_compliance",
                "Owner": "API32",
                "Type": "Advanced Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000125",
                "LastModified": "2018-02-15T15:52:22Z",
                "Name": "test_9845771654157357",
                "Owner": "API61",
                "Type": "Basic Network Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000165",
                "LastModified": "2018-04-10T19:23:00Z",
                "Name": "Test CIS",
                "Owner": "example.gmail.com",
                "Type": "Policy Compliance Auditing"
            },
            {
                "Group": "Full Access",
                "ID": "1000568",
                "LastModified": "2018-08-27T06:37:46Z",
                "Name": "Basic_Disc",
                "Owner": "API25",
                "Type": "Basic Network Scan"
            },
            {
                "Group": "Full Access",
                "ID": "1000619",
                "LastModified": "2018-11-06T19:35:24Z",
                "Name": "Symbol Password tests",
                "Owner": "hammackj",
                "Type": "Advanced Scan"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49030406-e5192000-f1af-11e8-820a-2305edbe1c8f.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49030406-e5192000-f1af-11e8-820a-2305edbe1c8f.png" alt="image"></a></p>
<h3 id="h_73757213415961543313284753">8. Get a list of report definitions</h3>
<hr>
<p>Returns a list of Tenable.sc report definitions.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-list-report-definitions</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 139px;"><strong>Argument Name</strong></th>
<th style="width: 498px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">manageable</td>
<td style="width: 498px;">Whether to return only manageable reports. By default, returns both usable and manageable.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 328px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 308px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 328px;">TenableSC.ReportDefinition.Name</td>
<td style="width: 72px;">string</td>
<td style="width: 308px;">Report definition name.</td>
</tr>
<tr>
<td style="width: 328px;">TenableSC.ReportDefinition.ID</td>
<td style="width: 72px;">number</td>
<td style="width: 308px;">Report definition ID.</td>
</tr>
<tr>
<td style="width: 328px;">TenableSC.ReportDefinition.Description</td>
<td style="width: 72px;">string</td>
<td style="width: 308px;">Report definition description.</td>
</tr>
<tr>
<td style="width: 328px;">TenableSC.ReportDefinition.Type</td>
<td style="width: 72px;">string</td>
<td style="width: 308px;">Report definition type.</td>
</tr>
<tr>
<td style="width: 328px;">TenableSC.ReportDefinition.Group</td>
<td style="width: 72px;">string</td>
<td style="width: 308px;">Report definition owner group name.</td>
</tr>
<tr>
<td style="width: 328px;">TenableSC.ReportDefinition.Owner</td>
<td style="width: 72px;">string</td>
<td style="width: 308px;">Report definition owner user name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-list-report-definitions manageable=true</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "ReportDefinition": [
            {
                "Group": "Full Access",
                "ID": "439",
                "Name": "Monthly Executive Report",
                "Owner": "API55",
                "Type": "pdf"
            },
            {
                "Group": "Full Access",
                "ID": "440",
                "Name": "Remediation Instructions by Host Report",
                "Owner": "API55",
                "Type": "pdf"
            },
            {
                "Group": "Full Access",
                "ID": "438",
                "Name": "Critical and Exploitable Vulnerabilities Report",
                "Owner": "API55",
                "Type": "pdf"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49030557-52c54c00-f1b0-11e8-97a7-5bc80921e135.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49030557-52c54c00-f1b0-11e8-97a7-5bc80921e135.png" alt="image"></a></p>
<h3 id="h_15731006419791543313350353">9. Get a list of scan repositories</h3>
<hr>
<p>Returns a list of Tenable.sc scan repositories.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-list-repositories</code></p>
<h5>Input</h5>
<p>There is no input for this command. </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 388px;"><strong>Path</strong></th>
<th style="width: 87px;"><strong>Type</strong></th>
<th style="width: 233px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 388px;">TenableSC.ScanRepository.Name</td>
<td style="width: 87px;">string</td>
<td style="width: 233px;">Scan repository name.</td>
</tr>
<tr>
<td style="width: 388px;">TenableSC.ScanRepository.ID</td>
<td style="width: 87px;">number</td>
<td style="width: 233px;">Scan repository ID.</td>
</tr>
<tr>
<td style="width: 388px;">TenableSC.ScanRepository.Description</td>
<td style="width: 87px;">string</td>
<td style="width: 233px;">Scan repository.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-list-repositories</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "ScanRepository": [
            {
                "ID": "1",
                "Name": "repo"
            },
            {
                "ID": "2",
                "Name": "Offline Repo"
            },
            {
                "ID": "3",
                "Name": "agent_repo"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49030636-8b652580-f1b0-11e8-828d-3b940b8625d0.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49030636-8b652580-f1b0-11e8-828d-3b940b8625d0.png" alt="image"></a></p>
<h3 id="h_81875088221731543313376351">10. Get a list of scan zones</h3>
<hr>
<p>Returns a list of Tenable.sc scan zones.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-list-zones</code></p>
<h5>Input</h5>
<p>There is no input for this command. </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 349px;"><strong>Path</strong></th>
<th style="width: 98px;"><strong>Type</strong></th>
<th style="width: 261px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 349px;">TenableSC.ScanZone.Name</td>
<td style="width: 98px;">string</td>
<td style="width: 261px;">Scan zone name.</td>
</tr>
<tr>
<td style="width: 349px;">TenableSC.ScanZone.ID</td>
<td style="width: 98px;">number</td>
<td style="width: 261px;">Scan zone ID.</td>
</tr>
<tr>
<td style="width: 349px;">TenableSC.ScanZone.Description</td>
<td style="width: 98px;">string</td>
<td style="width: 261px;">Scan zone description.</td>
</tr>
<tr>
<td style="width: 349px;">TenableSC.ScanZone.IPList</td>
<td style="width: 98px;">unknown</td>
<td style="width: 261px;">Scan zone IP list.</td>
</tr>
<tr>
<td style="width: 349px;">TenableSC.ScanZone.ActiveScanners</td>
<td style="width: 98px;">number</td>
<td style="width: 261px;">Scan zone active scanners.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-list-zones</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "ScanZone": {
            "ID": 0,
            "Name": "All Zones"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49030764-ed258f80-f1b0-11e8-8277-fb72d010eaa2.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49030764-ed258f80-f1b0-11e8-8277-fb72d010eaa2.png" alt="image"></a></p>
<h3 id="h_84471925432911543313482493">11. Create a scan</h3>
<hr>
<p>Creates a scan on Tenable.sc.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-create-scan</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 129px;"><strong>Argument Name</strong></th>
<th style="width: 508px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 129px;">name</td>
<td style="width: 508px;">Scan name.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 129px;">policy_id</td>
<td style="width: 508px;">Policy ID (can be retrieved from the <em>tenable-sc-list-policies</em> command).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 129px;">description</td>
<td style="width: 508px;">Scan description.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">repository_id</td>
<td style="width: 508px;">Scan Repository ID (can be retrieved from the tenable-<em>sc-list-repositories</em> command).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 129px;">zone_id</td>
<td style="width: 508px;">Scan zone ID (default is all zones) (can be retrieved from the <em>tenable-sc-list-zones</em> command).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">schedule</td>
<td style="width: 508px;">Schedule for the scan.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">asset_ids</td>
<td style="width: 508px;">Either all assets or a comma-separated list of asset IDs to scan (can be retrieved from the <em>tenable-sc-list-assets</em> command).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">scan_virtual_hosts</td>
<td style="width: 508px;">Whether to include virtual hosts, default is false.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">ip_list</td>
<td style="width: 508px;">Comma-separated list of IPs to scan, e.g., 10.0.0.1,10.0.0.2.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">report_ids</td>
<td style="width: 508px;">Comma separated list of report definition IDs to create post-scan, can be retrieved from list-report-definitions command.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">credentials</td>
<td style="width: 508px;">Comma-separated credentials IDs to use (can be retrieved from the <em>tenable-sc-list-credentials</em> command).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">timeout_action</td>
<td style="width: 508px;">Scan timeout action, default is import.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">max_scan_time</td>
<td style="width: 508px;">Maximum scan run time in hours, default is 1.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">dhcp_tracking</td>
<td style="width: 508px;">Track hosts which have been issued new IP address, (e.g. DHCP).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">rollover_type</td>
<td style="width: 508px;">Scan rollover type.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 129px;">dependent_id</td>
<td style="width: 508px;">Dependent scan ID in case of a dependent schedule, can be retrieved from list-scans command.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 316px;"><strong>Path</strong></th>
<th style="width: 111px;"><strong>Type</strong></th>
<th style="width: 281px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 316px;">TenableSC.Scan.ID</td>
<td style="width: 111px;">string</td>
<td style="width: 281px;">Scan ID.</td>
</tr>
<tr>
<td style="width: 316px;">TenableSC.Scan.CreatorID</td>
<td style="width: 111px;">string</td>
<td style="width: 281px;">Scan's creator ID.</td>
</tr>
<tr>
<td style="width: 316px;">TenableSC.Scan.Name</td>
<td style="width: 111px;">string</td>
<td style="width: 281px;">Scan name.</td>
</tr>
<tr>
<td style="width: 316px;">TenableSC.Scan.Type</td>
<td style="width: 111px;">string</td>
<td style="width: 281px;">Scan type.</td>
</tr>
<tr>
<td style="width: 316px;">TenableSC.Scan.CreatedTime</td>
<td style="width: 111px;">date</td>
<td style="width: 281px;">Scan creation time.</td>
</tr>
<tr>
<td style="width: 316px;">TenableSC.Scan.OwnerName</td>
<td style="width: 111px;">string</td>
<td style="width: 281px;">Scan owner username.</td>
</tr>
<tr>
<td style="width: 316px;">TenableSC.Scan.Reports</td>
<td style="width: 111px;">unknown</td>
<td style="width: 281px;">Scan report definition IDs.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-create-scan name="test_scan_2018" policy_id="1000618" description="Test scan" repository_id="1" schedule="never" asset_ids=AllManageable scan_virtual_hosts="false" ip_list="10.0.0.1" report_ids="438" credentials="1000007" max_scan_time="2" dhcp_tracking="true"</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "Scan": {
            "CreationTime": "2018-11-26T17:29:02Z",
            "CreatorID": "53",
            "ID": "1286",
            "Name": "test_scan_2018",
            "Reports": [
                "438"
            ],
            "Type": "policy"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49031059-9f5d5700-f1b1-11e8-85d9-8950fccc4e92.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49031059-9f5d5700-f1b1-11e8-85d9-8950fccc4e92.png" alt="image"></a></p>
<h3 id="h_76467577134841543313487972">12. Delete a scan</h3>
<hr>
<p>Deletes a scan in Tenable.sc.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-delete-scan</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 78px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">scan_id</td>
<td style="width: 526px;">Scan ID (can be retrieved from the <em>tenable-sc-list-scans</em> command).</td>
<td style="width: 78px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!tenable-sc-delete-scan scan_id=1286</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49033298-6e802080-f1b7-11e8-854a-35df7a15ae1e.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49033298-6e802080-f1b7-11e8-854a-35df7a15ae1e.png" alt="image"></a></p>
<h3 id="h_1815092436741543313492172">13. Get a list of assets</h3>
<hr>
<p>Returns a list of Tenable.sc assets.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-list-assets</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 142px;"><strong>Argument Name</strong></th>
<th style="width: 495px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142px;">manageable</td>
<td style="width: 495px;">Whether to return only manageable assets.By default, returns both usable and manageable.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 334px;"><strong>Path</strong></th>
<th style="width: 97px;"><strong>Type</strong></th>
<th style="width: 277px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334px;">TenableSC.Asset.ID</td>
<td style="width: 97px;">string</td>
<td style="width: 277px;">Asset ID.</td>
</tr>
<tr>
<td style="width: 334px;">TenableSC.Asset.Name</td>
<td style="width: 97px;">string</td>
<td style="width: 277px;">Asset name.</td>
</tr>
<tr>
<td style="width: 334px;">TenableSC.Asset.HostCount</td>
<td style="width: 97px;">number</td>
<td style="width: 277px;">Asset host IPs count.</td>
</tr>
<tr>
<td style="width: 334px;">TenableSC.Asset.Type</td>
<td style="width: 97px;">string</td>
<td style="width: 277px;">Asset type.</td>
</tr>
<tr>
<td style="width: 334px;">TenableSC.Asset.Tag</td>
<td style="width: 97px;">string</td>
<td style="width: 277px;">Asset tag.</td>
</tr>
<tr>
<td style="width: 334px;">TenableSC.Asset.Owner</td>
<td style="width: 97px;">string</td>
<td style="width: 277px;">Asset owner username.</td>
</tr>
<tr>
<td style="width: 334px;">TenableSC.Asset.Group</td>
<td style="width: 97px;">string</td>
<td style="width: 277px;">Asset group.</td>
</tr>
<tr>
<td style="width: 334px;">TenableSC.Asset.LastModified</td>
<td style="width: 97px;">date</td>
<td style="width: 277px;">Asset last modified time.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-list-assets manageable=true</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "Asset": [
            {
                "HostCount": 0,
                "ID": "354",
                "LastModified": "2018-01-08T13:50:05Z",
                "Name": "Bad Credentials",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "355",
                "LastModified": "2018-01-08T13:50:08Z",
                "Name": "Bad Windows Account",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 5,
                "ID": "356",
                "LastModified": "2018-01-08T13:50:09Z",
                "Name": "Windows Hosts",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "357",
                "LastModified": "2018-01-08T13:50:11Z",
                "Name": "Windows 7",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "358",
                "LastModified": "2018-01-08T13:50:13Z",
                "Name": "Windows RDP or Terminal Services",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 2,
                "ID": "359",
                "LastModified": "2018-01-08T13:50:15Z",
                "Name": "WMI Login Authenticated",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "360",
                "LastModified": "2018-01-08T13:50:16Z",
                "Name": "Microsoft Office 2010",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "361",
                "LastModified": "2018-01-08T13:50:18Z",
                "Name": "Microsoft Office 2007",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "362",
                "LastModified": "2018-01-08T13:50:19Z",
                "Name": "Microsoft VPN Technology",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "363",
                "LastModified": "2018-01-08T13:50:21Z",
                "Name": "Microsoft Windows Server 2000",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 4,
                "ID": "364",
                "LastModified": "2018-01-08T13:50:23Z",
                "Name": "Microsoft Windows Server",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "365",
                "LastModified": "2018-01-08T13:50:24Z",
                "Name": "Microsoft Windows Server 2003",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 3,
                "ID": "366",
                "LastModified": "2018-01-08T13:50:26Z",
                "Name": "Microsoft Windows Server 2008",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 1,
                "ID": "367",
                "LastModified": "2018-01-08T13:50:28Z",
                "Name": "Microsoft Windows Server 2012",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 2,
                "ID": "368",
                "LastModified": "2018-01-08T13:50:29Z",
                "Name": "Microsoft Windows Server Datacenter",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "369",
                "LastModified": "2018-01-08T13:50:31Z",
                "Name": "Microsoft Windows Server Enterprise",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "370",
                "LastModified": "2018-01-08T13:50:33Z",
                "Name": "Microsoft Windows Server Standard",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "371",
                "LastModified": "2018-01-08T13:50:36Z",
                "Name": "Microsoft Windows Workstation Enterprise",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "372",
                "LastModified": "2018-01-08T13:50:37Z",
                "Name": "Microsoft Windows Workstation Home",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "373",
                "LastModified": "2018-01-08T13:50:39Z",
                "Name": "Microsoft Windows 8",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "374",
                "LastModified": "2018-01-08T13:50:40Z",
                "Name": "Microsoft Windows Workstation Ultimate",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "375",
                "LastModified": "2018-01-08T13:50:42Z",
                "Name": "Unsupported Windows Operating Systems",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "376",
                "LastModified": "2018-01-08T13:50:43Z",
                "Name": "Microsoft Windows Workstation Professional",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "377",
                "LastModified": "2018-01-08T13:50:45Z",
                "Name": "Microsoft Windows XP",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": 0,
                "ID": "392",
                "LastModified": "2018-06-11T16:45:26Z",
                "Name": "Malware or Malicious Processes",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": "1",
                "ID": "537",
                "LastModified": "2018-11-07T13:34:11Z",
                "Name": "Maya test Asset",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": 0,
                "ID": "538",
                "LastModified": "2018-11-07T13:35:12Z",
                "Name": "Malware or Malicious Processes(1)",
                "Owner": "API55",
                "Type": "dynamic"
            },
            {
                "HostCount": "1",
                "ID": "543",
                "LastModified": "2018-11-20T18:29:53Z",
                "Name": "test_asset",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "2",
                "ID": "544",
                "LastModified": "2018-11-20T18:31:51Z",
                "Name": "test_asset2",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "2",
                "ID": "545",
                "LastModified": "2018-11-20T18:32:21Z",
                "Name": "test_asset3",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "2",
                "ID": "546",
                "LastModified": "2018-11-20T18:35:28Z",
                "Name": "test_asset4",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "2",
                "ID": "547",
                "LastModified": "2018-11-20T18:36:07Z",
                "Name": "test_asset5",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "2",
                "ID": "548",
                "LastModified": "2018-11-21T15:40:52Z",
                "Name": "blah",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "1",
                "ID": "549",
                "LastModified": "2018-11-21T16:05:10Z",
                "Name": "test_asset9",
                "Owner": "API55",
                "Tag": "hmm,blob",
                "Type": "static"
            },
            {
                "HostCount": "2",
                "ID": "550",
                "LastModified": "2018-11-22T15:12:29Z",
                "Name": "yyyy",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "1",
                "ID": "551",
                "LastModified": "2018-11-25T16:06:39Z",
                "Name": "test_asset_Sun Nov 25 2018 18:06:35 GMT+0200 (IST)",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "1",
                "ID": "552",
                "LastModified": "2018-11-25T16:08:54Z",
                "Name": "test_asset_Sun Nov 25 2018 18:08:50 GMT+0200 (IST)",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "1",
                "ID": "556",
                "LastModified": "2018-11-25T16:18:56Z",
                "Name": "test_asset_Sun Nov 25 2018 18:18:52 GMT+0200 (IST)",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "1",
                "ID": "557",
                "LastModified": "2018-11-25T16:34:52Z",
                "Name": "test_asset_Sun Nov 25 2018 18:34:47 GMT+0200 (IST)",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "1",
                "ID": "558",
                "LastModified": "2018-11-26T08:20:09Z",
                "Name": "test_asset_Mon Nov 26 2018 10:20:05 GMT+0200 (IST)",
                "Owner": "API55",
                "Type": "static"
            },
            {
                "HostCount": "1",
                "ID": "690",
                "LastModified": "2018-11-26T16:10:08Z",
                "Name": "test_asset_Mon Nov 26 2018 18:10:02 GMT+0200 (IST)",
                "Owner": "API55",
                "Type": "static"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49033449-e8b0a500-f1b7-11e8-8789-555777f21481.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49033449-e8b0a500-f1b7-11e8-8789-555777f21481.png" alt="image"></a></p>
<h3 id="h_692212738651543313496932">14. Create an asset</h3>
<hr>
<p>Creates an asset in Tenable.sc with the specified IP addresses.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-create-asset</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">name</td>
<td style="width: 501px;">Asset name.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">description</td>
<td style="width: 501px;">Asset description.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">owner_id</td>
<td style="width: 501px;">Asset owner ID, default is the Session User ID (can be retrieved from the <em>tenable-sc-list-users</em> command).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">tag</td>
<td style="width: 501px;">Asset tag.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">ip_list</td>
<td style="width: 501px;">Comma-separated list of IPs to include in the asset, e.g., 10.0.0.2,10.0.0.4</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 374px;"><strong>Path</strong></th>
<th style="width: 89px;"><strong>Type</strong></th>
<th style="width: 245px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 374px;">TenableSC.Asset.Name</td>
<td style="width: 89px;">string</td>
<td style="width: 245px;">Asset name.</td>
</tr>
<tr>
<td style="width: 374px;">TenableSC.Asset.ID</td>
<td style="width: 89px;">string</td>
<td style="width: 245px;">Asset ID.</td>
</tr>
<tr>
<td style="width: 374px;">TenableSC.Asset.OwnerName</td>
<td style="width: 89px;">string</td>
<td style="width: 245px;">Asset owner name.</td>
</tr>
<tr>
<td style="width: 374px;">TenableSC.Asset.Tags</td>
<td style="width: 89px;">string</td>
<td style="width: 245px;">Asset tags.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-create-asset name="test_asset_2018" description="desc" owner_id="53" ip_list="10.0.0.1,10.0.0.2"</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "Asset": {
            "ID": "691",
            "Name": "test_asset_2018",
            "OwnerName": "API55"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49033673-75f3f980-f1b8-11e8-9b88-58c90b87255a.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49033673-75f3f980-f1b8-11e8-9b88-58c90b87255a.png" alt="image"></a></p>
<h3 id="h_6996025840551543313501384">15. Get asset information</h3>
<hr>
<p>Get details for a given asset in Tenable.sc</p>
<h5>Base Command</h5>
<p><code>tenable-sc-get-asset</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 80px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">asset_id</td>
<td style="width: 497px;">Asset ID (can be retrieved from the <em>tenable-sc-list-assets</em> command).</td>
<td style="width: 80px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 318px;"><strong>Path</strong></th>
<th style="width: 113px;"><strong>Type</strong></th>
<th style="width: 277px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 318px;">TenableSC.Asset.ID</td>
<td style="width: 113px;">number</td>
<td style="width: 277px;">Asset ID.</td>
</tr>
<tr>
<td style="width: 318px;">TenableSC.Asset.Name</td>
<td style="width: 113px;">string</td>
<td style="width: 277px;">Asset name.</td>
</tr>
<tr>
<td style="width: 318px;">TenableSC.Asset.Description</td>
<td style="width: 113px;">string</td>
<td style="width: 277px;">Asset description.</td>
</tr>
<tr>
<td style="width: 318px;">TenableSC.Asset.Tag</td>
<td style="width: 113px;">string</td>
<td style="width: 277px;">Asset tag.</td>
</tr>
<tr>
<td style="width: 318px;">TenableSC.Asset.Modified</td>
<td style="width: 113px;">date</td>
<td style="width: 277px;">Asset last modified time.</td>
</tr>
<tr>
<td style="width: 318px;">TenableSC.Asset.Owner</td>
<td style="width: 113px;">string</td>
<td style="width: 277px;">Asset owner user name.</td>
</tr>
<tr>
<td style="width: 318px;">TenableSC.Asset.Group</td>
<td style="width: 113px;">string</td>
<td style="width: 277px;">Asset owner group.</td>
</tr>
<tr>
<td style="width: 318px;">TenableSC.Asset.IPs</td>
<td style="width: 113px;">unknown</td>
<td style="width: 277px;">Asset viewable IPs.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-get-asset asset_id=691</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "Asset": {
            "Created": "2018-11-26T18:17:39Z",
            "Description": "desc",
            "Group": "Full Access",
            "ID": "691",
            "IPs": [
                "10.0.0.1",
                "10.0.0.2"
            ],
            "Modified": "2018-11-26T18:17:39Z",
            "Name": "test_asset_2018",
            "Owner": "API55"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49034417-97ee7b80-f1ba-11e8-8258-4b67b2099311.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49034417-97ee7b80-f1ba-11e8-8258-4b67b2099311.png" alt="image"></a></p>
<h3 id="h_99298134042441543313506447">16. Delete an asset</h3>
<hr>
<p>Deletes the asset with the specified asset ID from Tenable.sc.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-delete-asset</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 303px;"><strong>Argument Name</strong></th>
<th style="width: 225px;"><strong>Description</strong></th>
<th style="width: 180px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 303px;">asset_id</td>
<td style="width: 225px;">Asset ID.</td>
<td style="width: 180px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!tenable-sc-delete-asset asset_id=691</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49034467-ba809480-f1ba-11e8-9e17-df4fc0f5ae18.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49034467-ba809480-f1ba-11e8-9e17-df4fc0f5ae18.png" alt="image"></a></p>
<h3 id="h_57421034944301543313511177">17. Get a list of alerts</h3>
<hr>
<p>Returns a list alerts from Tenable.sc.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-list-alerts</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 150px;"><strong>Argument Name</strong></th>
<th style="width: 487px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 150px;">manageable</td>
<td style="width: 487px;">Whether to return only manageable alerts. By default, returns both usable and manageable.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 345px;"><strong>Path</strong></th>
<th style="width: 78px;"><strong>Type</strong></th>
<th style="width: 285px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 345px;">TenableSC.Alert.ID</td>
<td style="width: 78px;">string</td>
<td style="width: 285px;">Alert ID.</td>
</tr>
<tr>
<td style="width: 345px;">TenableSC.Alert.Name</td>
<td style="width: 78px;">string</td>
<td style="width: 285px;">Alert name.</td>
</tr>
<tr>
<td style="width: 345px;">TenableSC.Alert.Description</td>
<td style="width: 78px;">string</td>
<td style="width: 285px;">Alert description.</td>
</tr>
<tr>
<td style="width: 345px;">TenableSC.Alert.State</td>
<td style="width: 78px;">string</td>
<td style="width: 285px;">Alert state.</td>
</tr>
<tr>
<td style="width: 345px;">TenableSC.Alert.Actions</td>
<td style="width: 78px;">string</td>
<td style="width: 285px;">Alert actions.</td>
</tr>
<tr>
<td style="width: 345px;">TenableSC.Alert.LastTriggered</td>
<td style="width: 78px;">date</td>
<td style="width: 285px;">Alert last triggered time.</td>
</tr>
<tr>
<td style="width: 345px;">TenableSC.Alert.LastEvaluated</td>
<td style="width: 78px;">date</td>
<td style="width: 285px;">Alert last evaluated time.</td>
</tr>
<tr>
<td style="width: 345px;">TenableSC.Alert.Group</td>
<td style="width: 78px;">string</td>
<td style="width: 285px;">Alert owner group name.</td>
</tr>
<tr>
<td style="width: 345px;">TenableSC.Alert.Owner</td>
<td style="width: 78px;">string</td>
<td style="width: 285px;">Alert owner user name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-list-alerts</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "Alert": [
            {
                "Actions": [
                    "ticket"
                ],
                "Group": "Full Access",
                "ID": "1",
                "LastEvaluated": "2018-11-25T19:44:00Z",
                "LastTriggered": "2017-01-31T19:44:01Z",
                "Name": "bwu_alert1",
                "Owner": "API17",
                "State": "Triggered"
            },
            {
                "Actions": [
                    "notification",
                    "ticket"
                ],
                "Group": "Full Access",
                "ID": "2",
                "LastEvaluated": "2018-11-26T18:30:14Z",
                "LastTriggered": "2018-11-26T18:30:15Z",
                "Name": "Test Alert",
                "Owner": "API55",
                "State": "Triggered"
            },
            {
                "Actions": [
                    "ticket"
                ],
                "Group": "Full Access",
                "ID": "3",
                "LastEvaluated": "2018-11-26T18:30:04Z",
                "LastTriggered": "1970-01-01T00:00:00Z",
                "Name": "Test fetch",
                "Owner": "API55",
                "State": "Not Triggered"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49034682-527e7e00-f1bb-11e8-875a-edb94fac9452.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49034682-527e7e00-f1bb-11e8-875a-edb94fac9452.png" alt="image"></a></p>
<h3 id="h_37606516346171543313517428">18. Get alert information</h3>
<hr>
<p>Returns information about a specified alert in Tenabel.sc.</p>
<h5>Base Command</h5>
<pre>tenable-sc-get-alert</pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 129px;"><strong>Argument Name</strong></th>
<th style="width: 504px;"><strong>Description</strong></th>
<th style="width: 75px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 129px;">alert_id</td>
<td style="width: 504px;">Alert ID (can be retrieved from the <em>tenable-sc-list-alerts</em> command).</td>
<td style="width: 75px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 376px;"><strong>Path</strong></th>
<th style="width: 94px;"><strong>Type</strong></th>
<th style="width: 238px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 376px;">TenableSC.Alert.ID</td>
<td style="width: 94px;">string</td>
<td style="width: 238px;">Alert ID.</td>
</tr>
<tr>
<td style="width: 376px;">TenableSC.Alert.Name</td>
<td style="width: 94px;">string</td>
<td style="width: 238px;">Alert name.</td>
</tr>
<tr>
<td style="width: 376px;">TenableSC.Alert.Description</td>
<td style="width: 94px;">string</td>
<td style="width: 238px;">Alert description.</td>
</tr>
<tr>
<td style="width: 376px;">TenableSC.Alert.State</td>
<td style="width: 94px;">string</td>
<td style="width: 238px;">Alert state.</td>
</tr>
<tr>
<td style="width: 376px;">TenableSC.Alert.Condition.Trigger</td>
<td style="width: 94px;">string</td>
<td style="width: 238px;">Alert trigger.</td>
</tr>
<tr>
<td style="width: 376px;">TenableSC.Alert.LastTriggered</td>
<td style="width: 94px;">date</td>
<td style="width: 238px;">Alert last triggered time.</td>
</tr>
<tr>
<td style="width: 376px;">TenableSC.Alert.Action</td>
<td style="width: 94px;">string</td>
<td style="width: 238px;">Alert action type.</td>
</tr>
<tr>
<td style="width: 376px;">TenableSC.Alert.Action.Values</td>
<td style="width: 94px;">unknown</td>
<td style="width: 238px;">Alert action values.</td>
</tr>
<tr>
<td style="width: 376px;">TenableSC.Alert.Condition.Query</td>
<td style="width: 94px;">string</td>
<td style="width: 238px;">Alert query name.</td>
</tr>
<tr>
<td style="width: 376px;">TenableSC.Alert.Condition.Filter.Name</td>
<td style="width: 94px;">string</td>
<td style="width: 238px;">Alert query filter name.</td>
</tr>
<tr>
<td style="width: 376px;">TenableSC.Alert.Condition.Filter.Values</td>
<td style="width: 94px;">unknown</td>
<td style="width: 238px;">Alert query filter values.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-get-alert alert_id=3</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "Alert": {
            "Action": [
                "type": "ticket",
                "values": "API55"
            ],
            "Behavior": "Execute on every trigger ",
            "Condition": {
                "Filter": [
                    {
                        "Name": "ip",
                        "Values": "11.0.0.2"
                    }
                ],
                "Query": "IPv4 Fixed Address: 11.0.0.2",
                "Trigger": "sumport &gt;= 1"
            },
            "ID": "3",
            "LastTriggered": "Never",
            "Name": "Test fetch",
            "State": "Not Triggered"
        }
    }
}</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/35098543/49744048-b0739100-fca4-11e8-9815-ff730aa99284.png" alt="image"></p>
<h3 id="h_9307079148031543313522519">19. Get device information for a user</h3>
<hr>
<p>Returns device information from the current user in Tenable.sc.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-get-device</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 219px;"><strong>Argument Name</strong></th>
<th style="width: 360px;"><strong>Description</strong></th>
<th style="width: 129px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 219px;">ip</td>
<td style="width: 360px;">A valid IP address to filter by.</td>
<td style="width: 129px;">Optional</td>
</tr>
<tr>
<td style="width: 219px;">dnsName</td>
<td style="width: 360px;">DNS name for the IP address.</td>
<td style="width: 129px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 266px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 375px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 266px;">TenableSC.Device.IP</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device IP address.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.UUID</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device UUID.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.RepositoryID</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device repository ID.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.MacAddress</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device Mac address.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.NetbiosName</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device Netbios name.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.DNSName</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device DNS name.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.OS</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device operating system.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.OsCPE</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device Common Platform Enumeration.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.LastScan</td>
<td style="width: 67px;">date</td>
<td style="width: 375px;">Device's last scan time.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.RepositoryName</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device repository name.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.TotalScore</td>
<td style="width: 67px;">number</td>
<td style="width: 375px;">Device total threat score.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.LowSeverity</td>
<td style="width: 67px;">number</td>
<td style="width: 375px;">Device total threat scores with low severity.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.MediumSeverity</td>
<td style="width: 67px;">number</td>
<td style="width: 375px;">Device total threat scores with medium severity.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.HighSeverity</td>
<td style="width: 67px;">number</td>
<td style="width: 375px;">Device total threat scores with high severity.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.CriticalSeverity</td>
<td style="width: 67px;">number</td>
<td style="width: 375px;">Device total threat scores with critical severity.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-get-device</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "Device": {
            "CriticalSeverity": "0",
            "DNSName": "gateway",
            "HighSeverity": "0",
            "IP": "10.0.0.1",
            "LastScan": "2018-11-26T18:26:03Z",
            "LowSeverity": "0",
            "MacAddress": "12:34:56:78:9a:bc",
            "MediumSeverity": "0",
            "OS": "Linux Kernel 2.2 Linux Kernel 2.4 Linux Kernel 2.6",
            "RepositoryID": "1",
            "RepositoryName": "repo",
            "TotalScore": "4"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49035282-ffa5c600-f1bc-11e8-80de-5905697983d6.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49035282-ffa5c600-f1bc-11e8-80de-5905697983d6.png" alt="image"></a></p>
<h3 id="h_85286374749881543313528453">20. Get a list of users</h3>
<hr>
<p>List users in Tenable.sc.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-list-users</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 226px;"><strong>Argument Name</strong></th>
<th style="width: 349px;"><strong>Description</strong></th>
<th style="width: 133px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 226px;">id</td>
<td style="width: 349px;">Filter by user ID.</td>
<td style="width: 133px;">Optional</td>
</tr>
<tr>
<td style="width: 226px;">username</td>
<td style="width: 349px;">Filter by user name.</td>
<td style="width: 133px;">Optional</td>
</tr>
<tr>
<td style="width: 226px;">email</td>
<td style="width: 349px;">Filter by user email address.</td>
<td style="width: 133px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 271px;"><strong>Path</strong></th>
<th style="width: 76px;"><strong>Type</strong></th>
<th style="width: 361px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 271px;">TenableSC.User.ID</td>
<td style="width: 76px;">string</td>
<td style="width: 361px;">User ID.</td>
</tr>
<tr>
<td style="width: 271px;">TenableSC.User.Username</td>
<td style="width: 76px;">string</td>
<td style="width: 361px;">Username.</td>
</tr>
<tr>
<td style="width: 271px;">TenableSC.User.FirstName</td>
<td style="width: 76px;">string</td>
<td style="width: 361px;">User first name.</td>
</tr>
<tr>
<td style="width: 271px;">TenableSC.User.LastName</td>
<td style="width: 76px;">string</td>
<td style="width: 361px;">User last name.</td>
</tr>
<tr>
<td style="width: 271px;">TenableSC.User.Title</td>
<td style="width: 76px;">string</td>
<td style="width: 361px;">User title.</td>
</tr>
<tr>
<td style="width: 271px;">TenableSC.User.Email</td>
<td style="width: 76px;">string</td>
<td style="width: 361px;">User email address.</td>
</tr>
<tr>
<td style="width: 271px;">TenableSC.User.Created</td>
<td style="width: 76px;">date</td>
<td style="width: 361px;">The creation time of the user.</td>
</tr>
<tr>
<td style="width: 271px;">TenableSC.User.Modified</td>
<td style="width: 76px;">date</td>
<td style="width: 361px;">Last modification time of the user.</td>
</tr>
<tr>
<td style="width: 271px;">TenableSC.User.Login</td>
<td style="width: 76px;">date</td>
<td style="width: 361px;">User last login.</td>
</tr>
<tr>
<td style="width: 271px;">TenableSC.User.Role</td>
<td style="width: 76px;">string</td>
<td style="width: 361px;">User role name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-list-users username=API55</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "User": {
            "Created": "2017-12-13T20:59:54Z",
            "FirstName": "API55",
            "ID": "53",
            "LastLogin": "2018-11-26T18:52:10Z",
            "Modified": "2017-12-13T20:59:54Z",
            "Role": "Security Manager",
            "Username": "API55"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49035509-ac804300-f1bd-11e8-92ce-d92592fa4b47.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49035509-ac804300-f1bd-11e8-92ce-d92592fa4b47.png" alt="image"></a></p>
<h3 id="h_11515143551721543313534950">21. Get licensing information</h3>
<hr>
<p>Retrieves licensing information from Tenable.sc.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-get-system-licensing</code></p>
<h5>Input</h5>
<p>There is no input for this command. </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 294px;"><strong>Path</strong></th>
<th style="width: 93px;"><strong>Type</strong></th>
<th style="width: 321px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 294px;">TenableSC.Status.ActiveIPS</td>
<td style="width: 93px;">number</td>
<td style="width: 321px;">Number of active IP addresses.</td>
</tr>
<tr>
<td style="width: 294px;">TenableSC.Status.LicensedIPS</td>
<td style="width: 93px;">unknown</td>
<td style="width: 321px;">Number of licensed IP addresses.</td>
</tr>
<tr>
<td style="width: 294px;">TenableSC.Status.License</td>
<td style="width: 93px;">unknown</td>
<td style="width: 321px;">License status.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-get-system-licensing</pre>
<h5>Context Example</h5>
<pre>{
    "TenableSC": {
        "Status": {
            "ActiveIPS": "150",
            "License": "Valid",
            "LicensedIPS": "1024"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49035672-2284aa00-f1be-11e8-8d20-8ede4ef5cb79.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49035672-2284aa00-f1be-11e8-8d20-8ede4ef5cb79.png" alt="image"></a></p>
<h3 id="h_90698695955281543313539949">22. Get system information and diagnostics</h3>
<hr>
<p>Returns the system information and diagnostics from Tenable.sc.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-get-system-information</code></p>
<h5>Input</h5>
<p>There is no input for this command. </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 346px;"><strong>Path</strong></th>
<th style="width: 90px;"><strong>Type</strong></th>
<th style="width: 272px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 346px;">TenableSC.System.Version</td>
<td style="width: 90px;">string</td>
<td style="width: 272px;">System version.</td>
</tr>
<tr>
<td style="width: 346px;">TenableSC.System.BuildID</td>
<td style="width: 90px;">string</td>
<td style="width: 272px;">System build ID.</td>
</tr>
<tr>
<td style="width: 346px;">TenableSC.System.ReleaseID</td>
<td style="width: 90px;">string</td>
<td style="width: 272px;">System release ID.</td>
</tr>
<tr>
<td style="width: 346px;">TenableSC.System.License</td>
<td style="width: 90px;">string</td>
<td style="width: 272px;">System license status.</td>
</tr>
<tr>
<td style="width: 346px;">TenableSC.System.JavaStatus</td>
<td style="width: 90px;">boolean</td>
<td style="width: 272px;">Server Java status.</td>
</tr>
<tr>
<td style="width: 346px;">TenableSC.System.RPMStatus</td>
<td style="width: 90px;">boolean</td>
<td style="width: 272px;">Server RPM status.</td>
</tr>
<tr>
<td style="width: 346px;">TenableSC.System.DiskStatus</td>
<td style="width: 90px;">boolean</td>
<td style="width: 272px;">Server disk status.</td>
</tr>
<tr>
<td style="width: 346px;">TenableSC.System.DiskThreshold</td>
<td style="width: 90px;">number</td>
<td style="width: 272px;">System space left on disk.</td>
</tr>
<tr>
<td style="width: 346px;">TenableSC.System.LastCheck</td>
<td style="width: 90px;">date</td>
<td style="width: 272px;">System last check time.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-get-system-information</pre>
<h3 id="h_88414951045411544018729183">23. Get device information</h3>
<hr>
<p>Retrieves information for the specified device.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-get-device</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 142px;"><strong>Argument Name</strong></th>
<th style="width: 495px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142px;">ip</td>
<td style="width: 495px;">A valid IP address of a device.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">dns_name</td>
<td style="width: 495px;">DNS name of a device.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">repository_id</td>
<td style="width: 495px;">Repository ID to get the device from, can be retrieved from the <a href="#h_15731006419791543313350353">list-repositories</a> command.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 266px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 375px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 266px;">TenableSC.Device.IP</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device IP address.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.UUID</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device UUID.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.RepositoryID</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device repository ID.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.MacAddress</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device Mac address.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.NetbiosName</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device Netbios name.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.DNSName</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device DNS name.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.OS</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device operating system.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.OsCPE</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device Common Platform Enumeration.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.LastScan</td>
<td style="width: 67px;">date</td>
<td style="width: 375px;">Device's last scan time.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.RepositoryName</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Device repository name.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.TotalScore</td>
<td style="width: 67px;">number</td>
<td style="width: 375px;">Device total threat score.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.LowSeverity</td>
<td style="width: 67px;">number</td>
<td style="width: 375px;">Device total threat scores with low severity.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.MediumSeverity</td>
<td style="width: 67px;">number</td>
<td style="width: 375px;">Device total threat scores with medium severity.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.HighSeverity</td>
<td style="width: 67px;">number</td>
<td style="width: 375px;">Device total threat scores with high severity.</td>
</tr>
<tr>
<td style="width: 266px;">TenableSC.Device.CriticalSeverity</td>
<td style="width: 67px;">number</td>
<td style="width: 375px;">Device total threat scores with critical severity.</td>
</tr>
<tr>
<td style="width: 266px;">Endpoint.IPAddress</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Endpoint IP address.</td>
</tr>
<tr>
<td style="width: 266px;">Endpoint.Hostname</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Endpoint DNS name.</td>
</tr>
<tr>
<td style="width: 266px;">Endpoint.MACAddress</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Endpoint Mac address.</td>
</tr>
<tr>
<td style="width: 266px;">Endpoint.OS</td>
<td style="width: 67px;">string</td>
<td style="width: 375px;">Endpoint operating system.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tenable-sc-get-device ip=213.35.2.109
!tenable-sc-get-device dns_name=213-35-2-109.navisite.net</pre>
<h5>Context Example</h5>
<pre>{
    "Endpoint": {
        "Hostname": "213-35-2-109.navisite.net",
        "IPAddress": "213.35.2.109",
        "OS": "Microsoft Windows Server 2012 R2"
    },
    "TenableSC": {
        "Device": {
            "CriticalSeverity": "0",
            "DNSName": "213-35-2-109.navisite.net",
            "HighSeverity": "0",
            "IP": "213.35.2.109",
            "LastScan": "2018-12-04T06:27:32Z",
            "LowSeverity": "0",
            "MediumSeverity": "0",
            "OS": "Microsoft Windows Server 2012 R2",
            "OsCPE": "cpe:/o:microsoft:windows_server_2012:r2",
            "RepositoryID": "1",
            "RepositoryName": "repo",
            "TotalScore": "34"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/49429690-d46d3900-f7b1-11e8-84a4-fe6494912e58.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/49429690-d46d3900-f7b1-11e8-84a4-fe6494912e58.png" alt="image"></a></p>
<h3 id="h_4cbe5353-4319-44ef-b7ed-06628baf46a0">24. Get all scan results</h3>
<hr>
<p>Returns all scan results in Tenable.sc.</p>
<h5>Base Command</h5>
<p><code>tenable-sc-get-all-scan-results</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 76px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">manageable</td>
<td style="width: 497px;">Filter only manageable alerts. By default, returns both usable and manageable alerts.</td>
<td style="width: 76px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">page</td>
<td style="width: 497px;">The page to return, starting from 0.</td>
<td style="width: 76px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">limit</td>
<td style="width: 497px;">The number of objects to return in one response (maximum limit is 200).</td>
<td style="width: 76px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 331.667px;"><strong>Path</strong></th>
<th style="width: 77.3333px;"><strong>Type</strong></th>
<th style="width: 298px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.ID</td>
<td style="width: 77.3333px;">Number</td>
<td style="width: 298px;">Scan ID.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.Name</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 298px;">Scan name.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.Status</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 298px;">Scan status.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.Description</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 298px;">Scan description.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.Policy</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 298px;">Scan policy.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.Group</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 298px;">Scan group name.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.Checks</td>
<td style="width: 77.3333px;">number</td>
<td style="width: 298px;">Scan completed number of checks.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.StartTime</td>
<td style="width: 77.3333px;">date</td>
<td style="width: 298px;">Scan results start time.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.EndTime</td>
<td style="width: 77.3333px;">date</td>
<td style="width: 298px;">Scan results end time.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.Duration</td>
<td style="width: 77.3333px;">number</td>
<td style="width: 298px;">Scan duration in minutes.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.ImportTime</td>
<td style="width: 77.3333px;">date</td>
<td style="width: 298px;">Scan import time.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.ScannedIPs</td>
<td style="width: 77.3333px;">number</td>
<td style="width: 298px;">Number of scanned IPs.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.Owner</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 298px;">Scan owner name.</td>
</tr>
<tr>
<td style="width: 331.667px;">TenableSC.ScanResults.RepositoryName</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 298px;">Scan repository name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !tenable-sc-get-all-scan-results page=10 limit=30</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/38749041/64108828-99bb2000-cd86-11e9-9f45-d8984d719241.png"></p>
<h2>Troubleshooting</h2>
<hr>
<p>For errors within Tenable.sc, the cause is generally specified, e.g., <code>The currently logged in used is not an administrator</code>, <code>Unable to retrieve Asset #2412. Asset #2412 does not exist</code> or <code>Invalid login credentials</code>. However there might be connection errors, for example when the server URL provided is incorrect.</p>
