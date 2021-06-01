<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Use the Tenable.io integration to manage scans and asset vulnerabilities.</p>
<p>This integration was integrated and tested with the November 2018 release of Tenable.io.</p>
<p> </p>
<h2>Configure Tenable.io on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Tenable.io.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>URL</strong></li>
<li><strong>Access Key</strong></li>
<li><strong>Secret Key</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br>After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_48852000951542101617984">Get a list of scans: tenable-io-list-scans</a></li>
<li><a href="#h_666906711891542101622823">Launch a scan: tenable-io-launch-scan</a></li>
<li><a href="#h_1339855721701542101627361">Get a scan report: tenable-io-get-scan-report</a></li>
<li><a href="#h_8236768922581542101631669">Get information for a vulnerability: tenable-io-get-vulnerability-details</a></li>
<li><a href="#h_4110535863371542101635494">Get a list of vulnerabilities for an asset: tenable-io-get-vulnerabilities-by-asset</a></li>
<li><a href="#h_3361940724151542101639987">Check the status of a scan: tenable-io-get-scan-status</a></li>
<li><a href="#h_3361940724151542101639988">Pause a scan: tenable-io-pause-scan</a></li>
<li><a href="#h_3361940724151542101639989">Resume a scan: tenable-io-resume-scan</a></li>

</ol>
<h3 id="h_48852000951542101617984">1. Get a list of scans</h3>
<hr>
<p>Retrieves a list of scans from the Tenable platform.</p>
<h5>Base Command</h5>
<pre><code>tenable-io-list-scans</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 488px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">folderId</td>
<td style="width: 488px;">The ID of the folder whose scans should be listed. Scans are stored in specific folders on Tenable, e.g.: folderId=8.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">lastModificationDate</td>
<td style="width: 488px;">Limit the results to those that have only changed since this time. Format: YYYY-MM-DD</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 257px;"><strong>Path</strong></th>
<th style="width: 60px;"><strong>Type</strong></th>
<th style="width: 391px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 257px;">TenableIO.Scan.Id</td>
<td style="width: 60px;">number</td>
<td style="width: 391px;">The unique ID of the scan.</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.Name</td>
<td style="width: 60px;">string</td>
<td style="width: 391px;">The name of the scan.</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.Target</td>
<td style="width: 60px;">string</td>
<td style="width: 391px;">The targets to scan.</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.Status</td>
<td style="width: 60px;">string</td>
<td style="width: 391px;">The status of the scan ("completed", "aborted", "imported", "pending", "running", "resuming", "canceling", "cancelled", "pausing", "paused", "stopping", "stopped)".</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.StartTime</td>
<td style="width: 60px;">date</td>
<td style="width: 391px;">The scheduled start time for the scan.</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.EndTime</td>
<td style="width: 60px;">date</td>
<td style="width: 391px;">The scheduled end time for the scan.</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.Enabled</td>
<td style="width: 60px;">boolean</td>
<td style="width: 391px;">If true, the schedule for the scan is enabled.</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.Type</td>
<td style="width: 60px;">string</td>
<td style="width: 391px;">The type of scan ("local", "remote", or "agent").</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.Owner</td>
<td style="width: 60px;">string</td>
<td style="width: 391px;">The owner of the scan.</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.Scanner</td>
<td style="width: 60px;">string</td>
<td style="width: 391px;">The scanner assigned for the scan.</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.Policy</td>
<td style="width: 60px;">string</td>
<td style="width: 391px;">The policy assigned for the scan.</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.CreationDate</td>
<td style="width: 60px;">date</td>
<td style="width: 391px;">The creation date for the scan in Unix time.</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.LastModificationDate</td>
<td style="width: 60px;">date</td>
<td style="width: 391px;">The last modification date for the scan in Unix time.</td>
</tr>
<tr>
<td style="width: 257px;">TenableIO.Scan.FolderId</td>
<td style="width: 60px;">number</td>
<td style="width: 391px;">The unique ID of the folder where the scan has been stored.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!tenable-io-list-scans</pre>
<h5>Human Readable Output</h5>
<h3>Tenable.io - List of Scans</h3>
<table border="2">
<thead>
<tr>
<th>FolderId</th>
<th>Id</th>
<th>Name</th>
<th>Targets</th>
<th>Status</th>
<th>StartTime</th>
<th>EndTime</th>
<th>Enabled</th>
<th>Type</th>
<th>Owner</th>
<th>Scanner</th>
<th>Policy</th>
<th>CreationDate</th>
<th>LastModificationDate</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center; vertical-align: middle;">8</td>
<td>20</td>
<td>artTest</td>
<td>anorton.ddns.net</td>
<td>completed</td>
<td>Tue Sep 18 15:12:47 2018</td>
<td>Tue Sep 18 15:23:53 2018</td>
<td>false</td>
<td>ps</td>
<td><a href="mailto:neelima@demisto.com">owner@demisto.com</a></td>
<td>US Cloud Scanner</td>
<td>Basic Network Scan</td>
<td>Tue Sep 18 15:12:47 2018</td>
<td>Tue Sep 18 15:23:53 2018</td>
</tr>
<tr>
<td style="text-align: center; vertical-align: middle;">15</td>
<td>13</td>
<td>Test 2</td>
<td><a href="http://www.google.com/" rel="nofollow">www.google.com</a></td>
<td>completed</td>
<td>Wed Oct 31 14:36:45 2018</td>
<td>Wed Oct 31 16:41:45 2018</td>
<td>true</td>
<td>ps</td>
<td><a href="mailto:neelima@demisto.com">owner@demisto.com</a></td>
<td>US Cloud Scanner</td>
<td>PCI Quarterly External Scan</td>
<td>Wed Oct 31 14:36:45 2018</td>
<td>Wed Oct 31 16:41:45 2018</td>
</tr>
<tr>
<td style="text-align: center; vertical-align: middle;">8</td>
<td>10</td>
<td>Test Scan - 1</td>
<td>216.75.62.8, 80.82.77.139, 60.191.38.77</td>
<td>running</td>
<td>Mon Nov 12 12:31:17 2018</td>
<td> </td>
<td>false</td>
<td>ps</td>
<td><a href="mailto:neelima@demisto.com">owner@demisto.com</a></td>
<td>US Cloud Scanner</td>
<td>Advanced Network Scan</td>
<td>Mon Nov 12 12:31:17 2018</td>
<td>Mon Nov 12 12:31:47 2018</td>
</tr>
<tr>
<td style="text-align: center; vertical-align: middle;">7</td>
<td>15</td>
<td>Test 3 - Prasen</td>
<td>192.168.1.1-192.168.1.255,www.google.com,93.174.93.1-93.174.93.255, 82.211.30.0/24, <a href="http://www.google.com/" rel="nofollow">www.google.com</a>
</td>
<td>completed</td>
<td>Tue Jul 3 23:00:36 2018</td>
<td>Wed Jul 4 01:59:44 2018</td>
<td>true</td>
<td>ps</td>
<td><a href="mailto:neelima@demisto.com">owner@demisto.com</a></td>
<td>US Cloud Scanner</td>
<td>Advanced Network Scan</td>
<td>Tue Jul 3 23:00:36 2018</td>
<td>Wed Jul 4 01:59:44 2018</td>
</tr>
<tr>
<td style="text-align: center; vertical-align: middle;">-</td>
<td>22</td>
<td>z</td>
<td> </td>
<td>empty</td>
<td> </td>
<td> </td>
<td>false</td>
<td> </td>
<td><a href="mailto:neelima@demisto.com">owner@demisto.com</a></td>
<td>US Cloud Scanner</td>
<td>Advanced Network Scan</td>
<td> </td>
<td> </td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>Inactive Web Applications Scans - Renew WAS license to use these scans</h3>
<table border="2">
<thead>
<tr>
<th>Id</th>
<th>Name</th>
<th>Status</th>
<th>Enabled</th>
<th>Type</th>
<th>Owner</th>
<th>CreationDate</th>
<th>LastModificationDate</th>
</tr>
</thead>
<tbody>
<tr>
<td>18</td>
<td>Test - Web</td>
<td>canceled</td>
<td>false</td>
<td>webapp</td>
<td><a href="mailto:neelima@demisto.com">owner@demisto.com</a></td>
<td>Thu Jul 19 11:13:03 2018</td>
<td>Thu Jul 19 11:17:51 2018</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_666906711891542101622823">2. Launch a scan</h3>
<hr>
<p>Launches a scan with existing or custom targets. You can specify custom targets in the command arguments.</p>
<h5>Base Command</h5>
<pre><code>tenable-io-launch-scan</code></pre>
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
<td style="width: 142px;">scanId</td>
<td style="width: 495px;">The ID of the scan to launch.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 142px;">scanTargets</td>
<td style="width: 495px;">If specified, targets to be scanned instead of the default. This value can be an array where each index is a target, or an array with a single index of comma-separated targets.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 164px;"><strong>Path</strong></th>
<th style="width: 57px;"><strong>Type</strong></th>
<th style="width: 487px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 164px;">TenableIO.Scan.Id</td>
<td style="width: 57px;">number</td>
<td style="width: 487px;">The unique ID of the scan.</td>
</tr>
<tr>
<td style="width: 164px;">TenableIO.Scan.Targets</td>
<td style="width: 57px;">string</td>
<td style="width: 487px;">The targets to scan.</td>
</tr>
<tr>
<td style="width: 164px;">TenableIO.Scan.Status</td>
<td style="width: 57px;">string</td>
<td style="width: 487px;">The status of the scan ("completed", "aborted", "imported", "pending", "running", "resuming", "canceling", "cancelled", "pausing", "paused", "stopping", "stopped").</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!tenable-io-launch-scan scan-id="10" scan-targets="216.75.62.8, 80.82.77.139, 60.191.38.77"</code></pre>
<h5>Human Readable Output</h5>
<h3>The requested scan was launched successfully</h3>
<table style="width: 446px;" border="2">
<thead>
<tr>
<th style="width: 25px;">Id</th>
<th style="width: 322px;">Targets</th>
<th style="width: 99px;">Status</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 25px;">10</td>
<td style="width: 322px;">216.75.62.8, 80.82.77.139, 60.191.38.77</td>
<td style="width: 99px;">pending</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_1339855721701542101627361">3. Get a scan report</h3>
<hr>
<p>Retrieves a scan report for the specified scan.</p>
<h5>Base Command</h5>
<pre><code>tenable-io-get-scan-report</code></pre>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 140px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 140px;">scanId</td>
<td style="width: 497px;">The ID of the scan to retrieve.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 140px;">detailed</td>
<td style="width: 497px;">If true, the report will contain remediation and host information for the specified scan. Otherwise, the report will only contain vulnerabilities.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">info</td>
<td style="width: 497px;">Whether to return the basic details of the specified scan.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 345px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 304px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 345px;">TenableIO.Scan.Id</td>
<td style="width: 59px;">number</td>
<td style="width: 304px;">The unique ID of the scan.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Scan.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The name of the scan.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Scan.Targets</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The targets to scan.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Scan.Status</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The status of the scan ("completed", "aborted", "imported", "pending", "running", "resuming", "canceling", "cancelled", "pausing", "paused", "stopping", "stopped").</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Scan.StartTime</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The scheduled start time for the scan.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Scan.EndTime</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The scheduled end time for the scan.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Scan.Scanner</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The scanner assigned to the scan.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Scan.Policy</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The policy assigned to the scan.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Vulnerabilities.Id</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The unique ID of the vulnerability.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Vulnerabilities.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The name of the vulnerability.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Vulnerabilities.Severity</td>
<td style="width: 59px;">number</td>
<td style="width: 304px;">The severity level of the vulnerability.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Vulnerabilities.Description</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The description of the vulnerability.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Vulnerabilities.Synopsis</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">A brief summary of the vulnerability.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Vulnerabilities.Solution</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">Information on how to fix the vulnerability.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Vulnerabilities.FirstSeen</td>
<td style="width: 59px;">date</td>
<td style="width: 304px;">When the vulnerability was first seen.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Vulnerabilities.LastSeen</td>
<td style="width: 59px;">date</td>
<td style="width: 304px;">When the vulnerability was last seen.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Vulnerabilities.VulnerabilityOccurences</td>
<td style="width: 59px;">number</td>
<td style="width: 304px;">A count of the vulnerability occurrences.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Assets.Hostname</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The name of the host.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Assets.Score</td>
<td style="width: 59px;">number</td>
<td style="width: 304px;">The overall score for the host.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Assets.Critical</td>
<td style="width: 59px;">number</td>
<td style="width: 304px;">The percentage of critical findings on the host.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Assets.High</td>
<td style="width: 59px;">number</td>
<td style="width: 304px;">The number of high findings on the host.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Assets.Medium</td>
<td style="width: 59px;">number</td>
<td style="width: 304px;">The number of medium findings on the host.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Assets.Low</td>
<td style="width: 59px;">number</td>
<td style="width: 304px;">The number of low findings on the host.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Remediations.Id</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The unique ID of the remediation.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Remediations.Description</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">Specific information related to the vulnerability and steps to remediate.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Remediations.AffectedHosts</td>
<td style="width: 59px;">number</td>
<td style="width: 304px;">The number of hosts affected.</td>
</tr>
<tr>
<td style="width: 345px;">TenableIO.Remediations.AssociatedVulnerabilities</td>
<td style="width: 59px;">number</td>
<td style="width: 304px;">The number of vulnerabilities associated with the remedy.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!tenable-io-get-scan-report scan-id="10" detailed="yes" info="yes"</code></pre>
<h5>Human Readable Output</h5>
<h3>Scan basic info</h3>
<table style="width: 651px;" border="2">
<thead>
<tr>
<th style="width: 18px;">Id</th>
<th style="width: 48px;">Name</th>
<th style="width: 157px;">Targets</th>
<th style="width: 73px;">Status</th>
<th style="width: 93px;">StartTime</th>
<th style="width: 93px;">EndTime</th>
<th style="width: 64px;">Scanner</th>
<th style="width: 80px;">Policy</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 18px;">10</td>
<td style="width: 48px;">Test Scan - 1</td>
<td style="width: 157px;">216.75.62.8, 80.82.77.139, 60.191.38.77</td>
<td style="width: 73px;">completed</td>
<td style="width: 93px;">Mon Nov 12 12:31:17 2018</td>
<td style="width: 93px;">Mon Nov 12 12:36:03 2018</td>
<td style="width: 64px;">US Cloud Scanner</td>
<td style="width: 80px;">Advanced Network Scan</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>Vulnerabilities</h3>
<table border="2">
<thead>
<tr>
<th>Id</th>
<th>Name</th>
<th>Severity</th>
<th>Description</th>
<th>Synopsis</th>
<th>Solution</th>
<th>FirstSeen</th>
<th>LastSeen</th>
<th>VulnerabilityOccurences</th>
</tr>
</thead>
<tbody>
<tr>
<td>10881</td>
<td>SSH Protocol Versions Supported</td>
<td>None</td>
<td>This plugin determines the versions of the SSH protocol supported by the remote SSH daemon.</td>
<td>A SSH server is running on the remote host.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>2</td>
</tr>
<tr>
<td>10114</td>
<td>ICMP Timestamp Request Remote Date Disclosure</td>
<td>None</td>
<td>The remote host answers to an ICMP timestamp request. This allows an attacker to know the date that is set on the targeted machine, which may assist an unauthenticated, remote attacker in defeating time-based authentication protocols.<br><br>Timestamps returned from machines running Windows Vista / 7 / 2008 / 2008 R2 are deliberately incorrect, but usually within 1000 seconds of the actual system time.</td>
<td>It is possible to determine the exact time set on the remote host.</td>
<td>Filter out the ICMP timestamp requests (13), and the outgoing ICMP timestamp replies (14).</td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>46</td>
</tr>
<tr>
<td>110723</td>
<td>No Credentials Provided</td>
<td>None</td>
<td>Nessus was unable to execute credentialed checks because no credentials were provided.</td>
<td>Nessus was able to find common ports used for local checks, however, no credentials were provided in the scan policy.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>8</td>
</tr>
<tr>
<td>25220</td>
<td>TCP/IP Timestamps Supported</td>
<td>None</td>
<td>The remote host implements TCP timestamps, as defined by RFC1323. A side effect of this feature is that the uptime of the remote host can sometimes be computed.</td>
<td>The remote service implements TCP timestamps.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>1</td>
</tr>
<tr>
<td>70657</td>
<td>SSH Algorithms and Languages Supported</td>
<td>None</td>
<td>This script detects which algorithms and languages are supported by the remote service for encrypting communications.</td>
<td>An SSH server is listening on this port.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>19</td>
</tr>
<tr>
<td>71049</td>
<td>SSH Weak MAC Algorithms Enabled</td>
<td>Low</td>
<td>The remote SSH server is configured to allow either MD5 or 96-bit MAC algorithms, both of which are considered weak.<br><br>Note that this plugin only checks for the options of the SSH server, and it does not check for vulnerable software versions.</td>
<td>The remote SSH server is configured to allow MD5 and 96-bit MAC algorithms.</td>
<td>Contact the vendor or consult product documentation to disable MD5 and 96-bit MAC algorithms.</td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>5</td>
</tr>
<tr>
<td>53335</td>
<td>RPC portmapper (TCP)</td>
<td>None</td>
<td>The RPC portmapper is running on this port. <br><br>The portmapper allows someone to get the port number of each RPC service running on the remote host by sending either multiple lookup requests or a DUMP request.</td>
<td>An ONC RPC portmapper is running on the remote host.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>1</td>
</tr>
<tr>
<td>70658</td>
<td>SSH Server CBC Mode Ciphers Enabled</td>
<td>Low</td>
<td>The SSH server is configured to support Cipher Block Chaining (CBC) encryption. This may allow an attacker to recover the plaintext message from the ciphertext. <br><br>Note that this plugin only checks for the options of the SSH server and does not check for vulnerable software versions.</td>
<td>The SSH server is configured to use Cipher Block Chaining.</td>
<td>Contact the vendor or consult product documentation to disable CBC mode cipher encryption, and enable CTR or GCM cipher mode encryption.</td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>5</td>
</tr>
<tr>
<td>11154</td>
<td>Unknown Service Detection: Banner Retrieval</td>
<td>None</td>
<td>Nessus was unable to identify a service on the remote host even though it returned a banner of some type.</td>
<td>There is an unknown service running on the remote host.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>75</td>
</tr>
<tr>
<td>12053</td>
<td>Host Fully Qualified Domain Name (FQDN) Resolution</td>
<td>None</td>
<td>Nessus was able to resolve the fully qualified domain name (FQDN) of the remote host.</td>
<td>It was possible to resolve the name of the remote host.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>98</td>
</tr>
<tr>
<td>45590</td>
<td>Common Platform Enumeration (CPE)</td>
<td>None</td>
<td>By using information obtained from a Nessus scan, this plugin reports CPE (Common Platform Enumeration) matches for various hardware and software products found on a host. <br><br>Note that if an official CPE is not available for the product, this plugin computes the best possible CPE based on the information available from the scan.</td>
<td>It was possible to enumerate CPE names that matched on the remote system.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>78</td>
</tr>
<tr>
<td>10884</td>
<td>Network Time Protocol (NTP) Server Detection</td>
<td>None</td>
<td>An NTP server is listening on port 123. If not securely configured, it may provide information about its version, current date, current time, and possibly system information.</td>
<td>An NTP server is listening on the remote host.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>1</td>
</tr>
<tr>
<td>10267</td>
<td>SSH Server Type and Version Information</td>
<td>None</td>
<td>It is possible to obtain information about the remote SSH server by sending an empty authentication request.</td>
<td>An SSH server is listening on this port.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>38</td>
</tr>
<tr>
<td>81052</td>
<td>Openswan &lt; 2.6.36 IKE Packet NULL Pointer Dereference Remote DoS</td>
<td>Medium</td>
<td>The remote host is running a version of Openswan prior to version 2.6.36. It is, therefore, affected by a remote denial of service vulnerability due to a NULL pointer dereference flaw. A remote attacker, using a specially crafted ISAKMP message with an invalid KEY_LENGTH attribute, can cause a denial of service.</td>
<td>The remote host is affected by a remote denial of service vulnerability.</td>
<td>Upgrade to Openswan 2.6.36 or later.</td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>1</td>
</tr>
<tr>
<td>81053</td>
<td>Openswan &lt; 2.6.37 Cryptographic Helper Use-After-Free Remote DoS</td>
<td>Medium</td>
<td>The remote host is running a version of Openswan prior to version 2.6.37. It is, therefore, affected by a remote denial of service vulnerability due to a use-after-free flaw in the cryptographic helper handler. A remote attacker can exploit this issue to cause a denial of service.</td>
<td>The remote host is affected by a remote denial of service vulnerability.</td>
<td>Upgrade to Openswan version 2.6.37 or later.</td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>1</td>
</tr>
<tr>
<td>66334</td>
<td>Patch Report</td>
<td>None</td>
<td>The remote host is missing one or more security patches. This plugin lists the newest version of each patch to install to make sure the remote host is up-to-date.</td>
<td>The remote host is missing several patches.</td>
<td>Install the patches listed below.</td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>18</td>
</tr>
<tr>
<td>11935</td>
<td>IPSEC Internet Key Exchange (IKE) Version 1 Detection</td>
<td>None</td>
<td>The remote host seems to be enabled to do Internet Key Exchange (IKE) version 1. This is typically indicative of a VPN server. VPN servers are used to connect remote hosts into internal resources. <br><br>Make sure that the use of this VPN endpoint is done in accordance with your corporate security policy. <br><br>Note that if the remote host is not configured to allow the Nessus host to perform IKE/IPSEC negotiations, Nessus won't be able to detect the IKE service. <br><br>Also note that this plugin does not run over IPv6.</td>
<td>A VPN server is listening on the remote port.</td>
<td>If this service is not needed, disable it or filter incoming traffic to this port.</td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>2</td>
</tr>
<tr>
<td>11936</td>
<td>OS Identification</td>
<td>None</td>
<td>Using a combination of remote probes (e.g., TCP/IP, SMB, HTTP, NTP, SNMP, etc.), it is possible to guess the name of the remote operating system in use. It is also possible sometimes to guess the version of the operating system.</td>
<td>It is possible to guess the remote operating system.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>56</td>
</tr>
<tr>
<td>46215</td>
<td>Inconsistent Hostname and IP Address</td>
<td>None</td>
<td>The name of this machine either does not resolve or resolves to a different IP address. <br><br>This may come from a badly configured reverse DNS or from a host file in use on the Nessus scanning host. <br><br>As a result, URLs in plugin output may not be directly usable in a web browser and some web tests may be incomplete.</td>
<td>The remote host's hostname is not consistent with DNS information.</td>
<td>Fix the reverse DNS or host file.</td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>58</td>
</tr>
<tr>
<td>19506</td>
<td>Nessus Scan Information</td>
<td>None</td>
<td>This plugin displays, for each tested host, information about the scan itself :<br><br>- The version of the plugin set.<br>- The type of scanner (Nessus or Nessus Home).<br>- The version of the Nessus Engine.<br>- The port scanner(s) used.<br>- The port range scanned.<br>- Whether credentialed or third-party patch management checks are possible.<br>- The date of the scan.<br>- The duration of the scan.<br>- The number of hosts scanned in parallel.<br>- The number of checks done in parallel.</td>
<td>This plugin displays information about the Nessus scan.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>187</td>
</tr>
<tr>
<td>22964</td>
<td>Service Detection</td>
<td>None</td>
<td>Nessus was able to identify the remote service by its banner or by looking at the error message it sends when it receives an HTTP request.</td>
<td>The remote service could be identified.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>30</td>
</tr>
<tr>
<td>90317</td>
<td>SSH Weak Algorithms Supported</td>
<td>Medium</td>
<td>Nessus has detected that the remote SSH server is configured to use the Arcfour stream cipher or no cipher at all. RFC 4253 advises against using Arcfour due to an issue with weak keys.</td>
<td>The remote SSH server is configured to allow weak encryption algorithms or no algorithm at all.</td>
<td>Contact the vendor or consult product documentation to remove the weak ciphers.</td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>1</td>
</tr>
<tr>
<td>11219</td>
<td>Nessus SYN scanner</td>
<td>None</td>
<td>This plugin is a SYN 'half-open' port scanner. It shall be reasonably quick even against a firewalled target. <br><br>Note that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded.</td>
<td>It is possible to determine which TCP ports are open.</td>
<td>Protect your target with an IP filter.</td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>324</td>
</tr>
<tr>
<td>54615</td>
<td>Device Type</td>
<td>None</td>
<td>Based on the remote operating system, it is possible to determine what the remote system type is (eg: a printer, router, general-purpose computer, etc).</td>
<td>It is possible to guess the remote device type.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>14</td>
</tr>
<tr>
<td>39520</td>
<td>Backported Security Patch Detection (SSH)</td>
<td>None</td>
<td>Security patches may have been 'backported' to the remote SSH server without changing its version number. <br><br>Banner-based checks have been disabled to avoid false positives. <br><br>Note that this test is informational only and does not denote any security problem.</td>
<td>Security patches are backported.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>1</td>
</tr>
<tr>
<td>11111</td>
<td>RPC Services Enumeration</td>
<td>None</td>
<td>By sending a DUMP request to the portmapper, it was possible to enumerate the ONC RPC services running on the remote port. Using this information, it is possible to connect and bind to each service by sending an RPC request to the remote port.</td>
<td>An ONC RPC service is running on the remote host.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>32</td>
</tr>
<tr>
<td>10223</td>
<td>RPC portmapper Service Detection</td>
<td>None</td>
<td>The RPC portmapper is running on this port.<br><br>The portmapper allows someone to get the port number of each RPC service running on the remote host by sending either multiple lookup requests or a DUMP request.</td>
<td>An ONC RPC portmapper is running on the remote host.</td>
<td> </td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>1</td>
</tr>
<tr>
<td>117886</td>
<td>Local Checks Not Enabled (info)</td>
<td>None</td>
<td>Nessus did not enable local checks on the remote host. This does not necessarily indicate a problem with the scan. Credentials may not have been provided, local checks may not be available for the target, the target may not have been identified, or another issue may have occurred that prevented local checks from being enabled. See plugin output for details.<br><br>This plugin reports informational findings related to local checks not being enabled. For failure information, see plugin 21745 :<br>'Authentication Failure - Local Checks Not Run'.</td>
<td>Local checks were not enabled.</td>
<td> </td>
<td>2018-10-25T12:51:05.830Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>1</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>Vulnerabilities - Missing From Workbench</h3>
<table border="2">
<thead>
<tr>
<th>Id</th>
<th>VulnerabilityOccurences</th>
<th>Severity</th>
</tr>
</thead>
<tbody>
<tr>
<td>27576</td>
<td>1</td>
<td>0</td>
</tr>
<tr>
<td>60020</td>
<td>1</td>
<td>0</td>
</tr>
<tr>
<td>33930</td>
<td>1</td>
<td>0</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>Assets</h3>
<table border="2">
<thead>
<tr>
<th>Hostname</th>
<th>Score</th>
<th>Critical</th>
<th>High</th>
<th>Medium</th>
<th>Low</th>
</tr>
</thead>
<tbody>
<tr>
<td>216.75.62.8</td>
<td>24</td>
<td>0</td>
<td>0</td>
<td>0</td>
<td>0</td>
</tr>
<tr>
<td>80.82.77.139</td>
<td>23</td>
<td>0</td>
<td>0</td>
<td>0</td>
<td>0</td>
</tr>
<tr>
<td>60.191.38.77</td>
<td>332</td>
<td>0</td>
<td>0</td>
<td>3</td>
<td>2</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>Remediations</h3>
<table border="2">
<thead>
<tr>
<th>Id</th>
<th>Description</th>
<th>AffectedHosts</th>
<th>AssociatedVulnerabilities</th>
</tr>
</thead>
<tbody>
<tr>
<td>68e52411b3ca69f756a5a7fc219a3d71</td>
<td>Openswan &lt; 2.6.37 Cryptographic Helper Use-After-Free Remote DoS: Upgrade to Openswan version 2.6.37 or later.</td>
<td>1</td>
<td>1</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_8236768922581542101631669">4. Get information for a vulnerability</h3>
<hr>
<p>Retrieves details for the specified vulnerability.</p>
<h5>Base Command</h5>
<pre><code>tenable-io-get-vulnerability-details</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 204px;"><strong>Argument Name</strong></th>
<th style="width: 385px;"><strong>Description</strong></th>
<th style="width: 119px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 204px;">vulnerabilityId</td>
<td style="width: 385px;">The unique ID of the vulnerability.</td>
<td style="width: 119px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 339px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 306px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.Name</td>
<td style="width: 63px;">string</td>
<td style="width: 306px;">The name of the vulnerability.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.Severity</td>
<td style="width: 63px;">number</td>
<td style="width: 306px;">Integer [0-4] indicating how severe the vulnerability is, where 0 is info only.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.Type</td>
<td style="width: 63px;">string</td>
<td style="width: 306px;">The type of the vulnerability.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.Family</td>
<td style="width: 63px;">string</td>
<td style="width: 306px;">Object containing plugin information such as family, type, and publication and modification dates.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.Description</td>
<td style="width: 63px;">string</td>
<td style="width: 306px;">The description of the vulnerability.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.Synopsis</td>
<td style="width: 63px;">string</td>
<td style="width: 306px;">A brief summary of the vulnerability.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.Solution</td>
<td style="width: 63px;">string</td>
<td style="width: 306px;">Information on how to fix the vulnerability.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.FirstSeen</td>
<td style="width: 63px;">date</td>
<td style="width: 306px;">When the vulnerability was first seen.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.LastSeen</td>
<td style="width: 63px;">date</td>
<td style="width: 306px;">When the vulnerability was last seen.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.PublicationDate</td>
<td style="width: 63px;">date</td>
<td style="width: 306px;">The publication date of the vulnerability.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.ModificationDate</td>
<td style="width: 63px;">date</td>
<td style="width: 306px;">The last modification date for the vulnerability in Unix time.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.VulnerabilityOccurences</td>
<td style="width: 63px;">number</td>
<td style="width: 306px;">A count of the vulnerability occurrences.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.CvssVector</td>
<td style="width: 63px;">string</td>
<td style="width: 306px;">The Common Vulnerability Scoring System vector.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.CvssBaseScore</td>
<td style="width: 63px;">string</td>
<td style="width: 306px;">The Common Vulnerability Scoring System allotted base score.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.Cvss3Vector</td>
<td style="width: 63px;">string</td>
<td style="width: 306px;">The Common Vulnerability Scoring System version 3 vector.</td>
</tr>
<tr>
<td style="width: 339px;">TenableIO.Vulnerabilities.Cvss3BaseScore</td>
<td style="width: 63px;">string</td>
<td style="width: 306px;">The Common Vulnerability Scoring System version 3 allotted base score.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!tenable-io-get-vulnerability-details vulnerability-id=10881</code></pre>
<h5>Human Readable Output</h5>
<h3>Vulnerability details - 10881</h3>
<table border="2">
<thead>
<tr>
<th>Name</th>
<th>Severity</th>
<th>Type</th>
<th>Family</th>
<th>Description</th>
<th>Synopsis</th>
<th>FirstSeen</th>
<th>LastSeen</th>
<th>PublicationDate</th>
<th>ModificationDate</th>
<th>VulnerabilityOccurences</th>
</tr>
</thead>
<tbody>
<tr>
<td>SSH Protocol Versions Supported</td>
<td>None</td>
<td>remote</td>
<td>General</td>
<td>This plugin determines the versions of the SSH protocol supported by the remote SSH daemon.</td>
<td>A SSH server is running on the remote host.</td>
<td>2018-07-03T22:08:05.242Z</td>
<td>2018-11-12T12:34:11.622Z</td>
<td>2002-03-06T00:00:00Z</td>
<td>2017-05-30T00:00:00Z</td>
<td>2</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_4110535863371542101635494">5. Get a list of vulnerabilities for an asset</h3>
<hr>
<p>Gets a list of up to 5000 the vulnerabilities recorded for a specified asset.</p>
<h5>Base Command</h5>
<pre><code>tenable-io-get-vulnerabilities-by-asset</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 494px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">hostname</td>
<td style="width: 494px;">Hostname of the asset.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">ip</td>
<td style="width: 494px;">IP of the asset.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">dateRange</td>
<td style="width: 494px;">The number of days of data prior to and including today that should be returned.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 343px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 306px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 343px;">TenableIO.Assets.Hostname</td>
<td style="width: 59px;">number</td>
<td style="width: 306px;">Hostname of the asset.</td>
</tr>
<tr>
<td style="width: 343px;">TenableIO.Assets.Vulnerabilities</td>
<td style="width: 59px;">number</td>
<td style="width: 306px;">A list of all the vulnerability IDs associated with the asset.</td>
</tr>
<tr>
<td style="width: 343px;">TenableIO.Vulnerabilities.Id</td>
<td style="width: 59px;">number</td>
<td style="width: 306px;">The vulnerability unique ID.</td>
</tr>
<tr>
<td style="width: 343px;">TenableIO.Vulnerabilities.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 306px;">The name of the vulnerability.</td>
</tr>
<tr>
<td style="width: 343px;">TenableIO.Vulnerabilities.Severity</td>
<td style="width: 59px;">number</td>
<td style="width: 306px;">Integer [0-4] indicating how severe the vulnerability is, where 0 is info only.</td>
</tr>
<tr>
<td style="width: 343px;">TenableIO.Vulnerabilities.Family</td>
<td style="width: 59px;">string</td>
<td style="width: 306px;">The vulnerability family.</td>
</tr>
<tr>
<td style="width: 343px;">TenableIO.Vulnerabilities.VulnerabilityOccurences</td>
<td style="width: 59px;">number</td>
<td style="width: 306px;">The number of times the vulnerability was found.</td>
</tr>
<tr>
<td style="width: 343px;">TenableIO.Vulnerabilities.VulnerabilityState</td>
<td style="width: 59px;">string</td>
<td style="width: 306px;">The current state of the reported vulnerability ("Active", "Fixed", "New", etc.).</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!tenable-io-get-vulnerabilities-by-asset hostname=debian8628.aspadmin.net</code></pre>
<h5>Human Readable Output</h5>
<h3>Vulnerabilities for asset debian8628.aspadmin.net</h3>
<table border="2">
<thead>
<tr>
<th>Id</th>
<th>Name</th>
<th>Severity</th>
<th>Family</th>
<th>VulnerabilityOccurences</th>
<th>VulnerabilityState</th>
</tr>
</thead>
<tbody>
<tr>
<td>11111</td>
<td>RPC Services Enumeration</td>
<td>None</td>
<td>Service detection</td>
<td>4</td>
<td>Active</td>
</tr>
<tr>
<td>11219</td>
<td>Nessus SYN scanner</td>
<td>None</td>
<td>Port scanners</td>
<td>2</td>
<td>Active</td>
</tr>
<tr>
<td>10114</td>
<td>ICMP Timestamp Request Remote Date Disclosure</td>
<td>None</td>
<td>General</td>
<td>1</td>
<td>Active</td>
</tr>
<tr>
<td>10223</td>
<td>RPC portmapper Service Detection</td>
<td>None</td>
<td>RPC</td>
<td>1</td>
<td>Active</td>
</tr>
<tr>
<td>10267</td>
<td>SSH Server Type and Version Information</td>
<td>None</td>
<td>Service detection</td>
<td>1</td>
<td>Resurfaced</td>
</tr>
<tr>
<td>10881</td>
<td>SSH Protocol Versions Supported</td>
<td>None</td>
<td>General</td>
<td>1</td>
<td>Resurfaced</td>
</tr>
<tr>
<td>10884</td>
<td>Network Time Protocol (NTP) Server Detection</td>
<td>None</td>
<td>Service detection</td>
<td>1</td>
<td>Active</td>
</tr>
<tr>
<td>11936</td>
<td>OS Identification</td>
<td>None</td>
<td>General</td>
<td>1</td>
<td>Resurfaced</td>
</tr>
<tr>
<td>12053</td>
<td>Host Fully Qualified Domain Name (FQDN) Resolution</td>
<td>None</td>
<td>General</td>
<td>1</td>
<td>Active</td>
</tr>
<tr>
<td>19506</td>
<td>Nessus Scan Information</td>
<td>None</td>
<td>Settings</td>
<td>1</td>
<td>Resurfaced</td>
</tr>
<tr>
<td>22964</td>
<td>Service Detection</td>
<td>None</td>
<td>Service detection</td>
<td>1</td>
<td>Resurfaced</td>
</tr>
<tr>
<td>25220</td>
<td>TCP/IP Timestamps Supported</td>
<td>None</td>
<td>General</td>
<td>1</td>
<td>Resurfaced</td>
</tr>
<tr>
<td>39520</td>
<td>Backported Security Patch Detection (SSH)</td>
<td>None</td>
<td>General</td>
<td>1</td>
<td>Resurfaced</td>
</tr>
<tr>
<td>45590</td>
<td>Common Platform Enumeration (CPE)</td>
<td>None</td>
<td>General</td>
<td>1</td>
<td>Resurfaced</td>
</tr>
<tr>
<td>46215</td>
<td>Inconsistent Hostname and IP Address</td>
<td>None</td>
<td>Settings</td>
<td>1</td>
<td>Active</td>
</tr>
<tr>
<td>53335</td>
<td>RPC portmapper (TCP)</td>
<td>None</td>
<td>RPC</td>
<td>1</td>
<td>Active</td>
</tr>
<tr>
<td>54615</td>
<td>Device Type</td>
<td>None</td>
<td>General</td>
<td>1</td>
<td>Resurfaced</td>
</tr>
<tr>
<td>70657</td>
<td>SSH Algorithms and Languages Supported</td>
<td>None</td>
<td>Misc.</td>
<td>1</td>
<td>Resurfaced</td>
</tr>
<tr>
<td>110723</td>
<td>No Credentials Provided</td>
<td>None</td>
<td>Settings</td>
<td>1</td>
<td>Resurfaced</td>
</tr>
<tr>
<td>117886</td>
<td>Local Checks Not Enabled (info)</td>
<td>None</td>
<td>Settings</td>
<td>1</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_3361940724151542101639987">6. Check the status of a scan</h3>
<hr>
<p>Checks the status of a specific scan using the scan ID. Possible statuses include: "Running", "Completed", and "Empty" (Ready to run).</p>
<h5>Base Command</h5>
<pre><code>tenable-io-get-scan-status</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 230px;"><strong>Argument Name</strong></th>
<th style="width: 344px;"><strong>Description</strong></th>
<th style="width: 134px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 230px;">scanId</td>
<td style="width: 344px;">The unique ID of the scan.</td>
<td style="width: 134px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 241px;"><strong>Path</strong></th>
<th style="width: 75px;"><strong>Type</strong></th>
<th style="width: 392px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 241px;">TenableIO.Scan.Id</td>
<td style="width: 75px;">string</td>
<td style="width: 392px;">The unique ID of the scan.</td>
</tr>
<tr>
<td style="width: 241px;">TenableIO.Scan.Status</td>
<td style="width: 75px;">string</td>
<td style="width: 392px;">The status of the scan.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!tenable-io-get-scan-status scan-id=10</code></pre>
<h5>Human Readable Output</h5>
<h3>Scan status for 10</h3>
<table border="2">
<thead>
<tr>
<th>Status</th>
<th>Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>completed</td>
<td>10</td>
</tr>
</tbody>
</table>
<h3 id="h_3361940724151542101639988">7. Pause a scan</h3>
<hr>
<p>Pauses all scans inputted as an array. Will pause scans whose status is 'Running'.
</p>
<h5>Base Command</h5>
<pre><code>tenable-io-pause-scan</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 230px;"><strong>Argument Name</strong></th>
<th style="width: 344px;"><strong>Description</strong></th>
<th style="width: 134px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 230px;">scanId</td>
<td style="width: 344px;">Comma-separated list of scan IDs.</td>
<td style="width: 134px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 241px;"><strong>Path</strong></th>
<th style="width: 75px;"><strong>Type</strong></th>
<th style="width: 392px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 241px;">TenableIO.Scan.Id</td>
<td style="width: 75px;">string</td>
<td style="width: 392px;">The unique ID of the scan.</td>
</tr>
<tr>
<td style="width: 241px;">TenableIO.Scan.Status</td>
<td style="width: 75px;">string</td>
<td style="width: 392px;">The status of the scan.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!tenable-io-pause-scan scan-id=10</code></pre>
<h5>Human Readable Output</h5>
<h3>The requested scan was paused successfully</h3>
<table border="2">
<thead>
<tr>
<th>Status</th>
<th>Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>Pausing</td>
<td>10</td>
</tr>
</tbody>
</table>
<h3 id="h_3361940724151542101639989">8. Resume a scan</h3>
<hr>
<p>Resumes all scans inputted as an array. Will work resume scans whose status is 'Paused'.</p>
<h5>Base Command</h5>
<pre><code>tenable-io-resume-scan</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 230px;"><strong>Argument Name</strong></th>
<th style="width: 344px;"><strong>Description</strong></th>
<th style="width: 134px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 230px;">scanId</td>
<td style="width: 344px;">Comma-separated list of scan IDs.</td>
<td style="width: 134px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 241px;"><strong>Path</strong></th>
<th style="width: 75px;"><strong>Type</strong></th>
<th style="width: 392px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 241px;">TenableIO.Scan.Id</td>
<td style="width: 75px;">string</td>
<td style="width: 392px;">The unique ID of the scan.</td>
</tr>
<tr>
<td style="width: 241px;">TenableIO.Scan.Status</td>
<td style="width: 75px;">string</td>
<td style="width: 392px;">The status of the scan.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!tenable-io-resume-scan scan-id=10</code></pre>
<h5>Human Readable Output</h5>
<h3>The requested scan was resumed successfully</h3>
<table border="2">
<thead>
<tr>
<th>Status</th>
<th>Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>Resuming</td>
<td>10</td>
</tr>
</tbody>
</table>
