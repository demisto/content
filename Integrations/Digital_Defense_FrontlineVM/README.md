<p>
Digital Defense Inc.'s Frontline Vulnerability Management solution comprehensively identifies and evaluates the security and business risk postures of network devices and applications deployed as premise, cloud, or hybrid network-based implementations. Now residing entirely in Amazon Web Services (AWS), Frontline VM easily addresses the security compliance requirements of organizations around the globe.

This integration was integrated and tested with version xx of Digital Defense FrontlineVM
</p>
<h2>Digital Defense FrontlineVM Playbook</h2>
<p>Populate this section with relevant playbook names.</p>
<h2>Use Cases</h2>
<ul>
<li>Use case 1</li>
<li>Use case 2</li>
</ul><h2>Detailed Description</h2>
<p>Populate this section with the .md file contents for detailed description.</p>
<h2>Fetch Incidents</h2>
<p>Populate this section with Fetch incidents data</p>
<h2>Configure Digital Defense FrontlineVM on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Digital Defense FrontlineVM.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>API Token to access Frontline.Cloud</strong></li>
   <li><strong>Fetch incidents</strong></li>
   <li><strong>Incident type</strong></li>
   <li><strong>Min vulnerability severity for fetching incidents.</strong></li>
   <li><strong>Rate at which to check vulnerability events when fetching incidents.</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li><a href="#frontline-get-assets" target="_self">Pull asset information from FrontlineVM: frontline-get-assets</a></li>
  <li><a href="#frontline-get-vulns" target="_self">Pull vulnerability information from FrontlineVM: frontline-get-vulns</a></li>
  <li><a href="#frontline-scan-asset" target="_self">Performs a scan on a given asset: frontline-scan-asset</a></li>
</ol>
<h3 id="frontline-get-assets">1. frontline-get-assets</h3>
<hr>
<p>Pull asset information from FrontlineVM</p>
<h5>Base Command</h5>
<p>
  <code>frontline-get-assets</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>ip_address</td>
      <td>Get assets for given IP Address</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_name</td>
      <td>Get assets with given label name (put name in quotes if spaces are required).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>max_days_since_scan</td>
      <td>Get hosts scanned within the given max day</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>hostname</td>
      <td>Get asset for given hostname</td>
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
      <td>FrontlineVM.Hosts</td>
      <td>unknown</td>
      <td>Returned host data pulled from Frontline.Cloud</td>
    </tr>
    <tr>
      <td>FrontlineVM.IPList</td>
      <td>unknown</td>
      <td>IP address list of found hosts.</td>
    </tr>
    <tr>
      <td>FrontlineVM.Hosts.ID</td>
      <td>unknown</td>
      <td>Host ID number</td>
    </tr>
    <tr>
      <td>FrontlineVM.Hosts.Hostname</td>
      <td>unknown</td>
      <td>Hostname of asset</td>
    </tr>
    <tr>
      <td>FrontlineVM.Hosts.IP</td>
      <td>unknown</td>
      <td>IP address</td>
    </tr>
    <tr>
      <td>FrontlineVM.Hosts.DNSHostname</td>
      <td>unknown</td>
      <td>DNS Hostname</td>
    </tr>
    <tr>
      <td>FrontlineVM.MAC</td>
      <td>unknown</td>
      <td>MAC Address</td>
    </tr>
    <tr>
      <td>FrontlineVM.Hosts.OS</td>
      <td>unknown</td>
      <td>Operating System</td>
    </tr>
    <tr>
      <td>FrontlineVM.Hosts.OSType</td>
      <td>unknown</td>
      <td>Operating System Type</td>
    </tr>
    <tr>
      <td>FrontlineVM.Hosts.CriticalVulnCount</td>
      <td>unknown</td>
      <td>DDI critical vulnerability severity count</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!frontline-get-assets ip_address=192.168.69.140</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "FrontlineVM": {
        "Hosts": [
            {
                "CriticalVulnCount": 9,
                "DNSHostname": "",
                "Hostname": "BUFF-HEARTBLEED",
                "ID": 65470955,
                "IP": "192.168.69.140",
                "MAC": "00:50:56:8d:bf:ba",
                "OS": "Ubuntu Linux",
                "OSType": "server"
            }
        ],
        "IPList": [
            "192.168.69.140"
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>FrontlineVM: Assets Found</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Hostname</strong></th>
      <th><strong>IP</strong></th>
      <th><strong>MAC</strong></th>
      <th><strong>OS</strong></th>
      <th><strong>OSType</strong></th>
      <th><strong>CriticalVulnCount</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 65470955 </td>
      <td> BUFF-HEARTBLEED </td>
      <td> 192.168.69.140 </td>
      <td> 00:50:56:8d:bf:ba </td>
      <td> Ubuntu Linux </td>
      <td> server </td>
      <td> 9 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="frontline-get-vulns">2. frontline-get-vulns</h3>
<hr>
<p>Pull vulnerability information from FrontlineVM</p>
<h5>Base Command</h5>
<p>
  <code>frontline-get-vulns</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>min_severity</td>
      <td>Select a minimum severity level of vulnerabilities to pull from Frontline. E.g. setting the min_severity=medium will pull all vulnerabilities with severity levels of medium, high, and critical.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>severity</td>
      <td>Will pull all vulnerabilities from Frontline with this severity.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>max_days_since_created</td>
      <td>Will pull vulnerabilities first found older than the given input (in days from now).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>min_days_since_created</td>
      <td>Will pull vulnerabilities first found to be newer than the given input (in days from now).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>host_id</td>
      <td>Pull vulnerabilities from specific host given the host ID.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ip_address</td>
      <td>IP address of host to pull vulnerability data from.</td>
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
      <td>FrontlineVM.Vulns</td>
      <td>unknown</td>
      <td>Returned vulnerability data pulled from Frontline.Cloud</td>
    </tr>
    <tr>
      <td>FrontlineVM.IPList</td>
      <td>unknown</td>
      <td>IP address list of found vulnerabilities.</td>
    </tr>
    <tr>
      <td>FrontlineVM.Stat</td>
      <td>unknown</td>
      <td>Statistic overview of vulnerabilities pulled.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!frontline-get-vulns min_severity=high</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "FrontlineVM": {
        "IPList": [
            "192.168.69.232",
            "192.168.69.177",
            "192.168.69.148",
            "192.168.69.63",
            "192.168.69.57",
            "192.168.69.185",
            "192.168.69.62",
            "192.168.69.64",
            "192.168.69.67",
            "192.168.69.137",
            "192.168.69.141",
            "192.168.69.245",
            "192.168.69.186",
            "192.168.69.108",
            "192.168.69.71",
            "192.168.69.141",
            "192.168.69.102",
            "192.168.69.204",
            "192.168.69.245",
            "192.168.69.137",
            "192.168.69.140",
            "192.168.69.140",
            "192.168.69.140",
            "192.168.69.140",
            "192.168.69.140",
            "192.168.69.57",
            "192.168.69.137",
            "192.168.69.137",
            "192.168.69.137",
            "192.168.69.137",
            "192.168.69.137",
            "192.168.69.245",
            "192.168.69.102",
            "192.168.69.204",
            "192.168.69.55",
            "192.168.69.124",
            "192.168.69.137",
            "192.168.69.108"
        ],
        "Vulns": [
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "debian-2",
                "ip-address": "192.168.69.232",
                "vuln-id": 2589048799,
                "vuln-info": "successfully logged in with username: user, password: user",
                "vuln-title": "Easily Guessable SSH Credentials"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "Test",
                "ip-address": "192.168.69.177",
                "vuln-id": 2589048312,
                "vuln-info": "successfully logged in with username: root, password: root",
                "vuln-title": "Easily Guessable SSH Credentials"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "UBUNTU",
                "ip-address": "192.168.69.148",
                "vuln-id": 2589049372,
                "vuln-info": "successfully logged in with username: user, password: user",
                "vuln-title": "Easily Guessable SSH Credentials"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "192.168.69.63",
                "ip-address": "192.168.69.63",
                "vuln-id": 2589048568,
                "vuln-info": "successfully logged in with username: root, password: root",
                "vuln-title": "Easily Guessable SSH Credentials"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "192.168.69.57",
                "ip-address": "192.168.69.57",
                "vuln-id": 2589049746,
                "vuln-info": "successfully logged in with username: admin, password: admin",
                "vuln-title": "Easily Guessable SSH Credentials"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "UBUNTU",
                "ip-address": "192.168.69.185",
                "vuln-id": 2589048707,
                "vuln-info": "successfully logged in with username: user, password: user",
                "vuln-title": "Easily Guessable SSH Credentials"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "192.168.69.62",
                "ip-address": "192.168.69.62",
                "vuln-id": 2589048191,
                "vuln-info": "successfully logged in with username: admin, password: admin",
                "vuln-title": "Easily Guessable SSH Credentials"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "192.168.69.64",
                "ip-address": "192.168.69.64",
                "vuln-id": 2589048953,
                "vuln-info": "successfully logged in with username: root, password: password",
                "vuln-title": "Easily Guessable SSH Credentials"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "192.168.69.67",
                "ip-address": "192.168.69.67",
                "vuln-id": 2589049082,
                "vuln-info": "successfully logged in with username: root, password: root",
                "vuln-title": "Easily Guessable SSH Credentials"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "WINXP-ORACLE",
                "ip-address": "192.168.69.137",
                "vuln-id": 2589049811,
                "vuln-info": "MS08-067",
                "vuln-title": "MS08-067 Microsoft Windows Server Service Stack Overflow (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "COMPUTER",
                "ip-address": "192.168.69.141",
                "vuln-id": 2589048429,
                "vuln-info": "MS09-050",
                "vuln-title": "MS09-050 Microsoft Windows SMB2 Command Execution Vulnerabilities (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "ATS-WIN7-ENT64",
                "ip-address": "192.168.69.245",
                "vuln-id": 2589049408,
                "vuln-info": "This asset is missing the MS17-010 patch.\n\nVulnerable Response:\n ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....\n 00 00 00 00 00 00 00 00 00 08 06 00 00 08 41 6a   ..............Aj\n 00 00 00                                          ...\n",
                "vuln-title": "MS17-010: SMB Remote Code Execution Vulnerability (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "WIN-30QQRC10MGG",
                "ip-address": "192.168.69.186",
                "vuln-id": 2589049851,
                "vuln-info": "This asset is missing the MS17-010 patch.\n\nVulnerable Response:\n ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....\n 00 00 00 00 00 00 00 00 00 50 06 00 02 a0 41 6a   .........P....Aj\n 00 00 00                                          ...\n",
                "vuln-title": "MS17-010: SMB Remote Code Execution Vulnerability (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "ATS-WIN10-2",
                "ip-address": "192.168.69.108",
                "vuln-id": 2589048229,
                "vuln-info": "This asset is missing the MS17-010 patch.\n\nVulnerable Response:\n ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....\n 00 00 00 00 00 00 00 00 07 e8 06 00 01 28 41 6a   .............(Aj\n 00 00 00                                          ...\n",
                "vuln-title": "MS17-010: SMB Remote Code Execution Vulnerability (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "WIN7WSUS",
                "ip-address": "192.168.69.71",
                "vuln-id": 2589048381,
                "vuln-info": "This asset is missing the MS17-010 patch.\n\nVulnerable Response:\n ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....\n 00 00 00 00 00 00 00 00 00 08 06 00 00 08 41 6a   ..............Aj\n 00 00 00                                          ...\n",
                "vuln-title": "MS17-010: SMB Remote Code Execution Vulnerability (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "COMPUTER",
                "ip-address": "192.168.69.141",
                "vuln-id": 2589048427,
                "vuln-info": "This asset is missing the MS17-010 patch.\n\nVulnerable Response:\n ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....\n 00 00 00 00 00 00 00 00 06 c0 06 00 00 30 41 6a   .............0Aj\n 00 00 00                                          ...\n",
                "vuln-title": "MS17-010: SMB Remote Code Execution Vulnerability (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "ATS-WIN7-2",
                "ip-address": "192.168.69.102",
                "vuln-id": 2589048886,
                "vuln-info": "This asset is missing the MS17-010 patch.\n\nVulnerable Response:\n ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....\n 00 00 00 00 00 00 00 00 00 08 06 00 00 08 41 6a   ..............Aj\n 00 00 00                                          ...\n",
                "vuln-title": "MS17-010: SMB Remote Code Execution Vulnerability (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "BASEWIN2K8SR2",
                "ip-address": "192.168.69.204",
                "vuln-id": 2589048636,
                "vuln-info": "Target asset is missing the patch for CVE-2019-0708:\n 03 00 00 09 02 f0 80 21 80                        .......!.\n",
                "vuln-title": "MS19-MAY: Microsoft RDP 'BlueKeep' Unauthenticated Remote Code Execution (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "ATS-WIN7-ENT64",
                "ip-address": "192.168.69.245",
                "vuln-id": 2589049393,
                "vuln-info": "Target asset is missing the patch for CVE-2019-0708:\n 03 00 00 09 02 f0 80 21 80                        .......!.\n",
                "vuln-title": "MS19-MAY: Microsoft RDP 'BlueKeep' Unauthenticated Remote Code Execution (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "WINXP-ORACLE",
                "ip-address": "192.168.69.137",
                "vuln-id": 2589049764,
                "vuln-info": "Target asset is missing the patch for CVE-2019-0708:\n 03 00 00 09 02 f0 80 21 80                        .......!.\n",
                "vuln-title": "MS19-MAY: Microsoft RDP 'BlueKeep' Unauthenticated Remote Code Execution (Network Check)"
            },
            {
                "date-created": "2019-11-13T17:10:53.286452Z",
                "ddi-severity": "critical",
                "hostname": "BUFF-HEARTBLEED",
                "ip-address": "192.168.69.140",
                "vuln-id": 2601574910,
                "vuln-info": "Server is vulnerable to Heartbleed.\n\nVulnerable response:\n 18 03 02 40 00 02 40 00 48 65 61 72 74 62 6c 65   ...@..@.Heartble\n 65 64 20 54 65 73 74 12 a8 48 97 cf bd 39 04 cc   ed Test..H...9..\n 16 0a 85 03 90 9f 7f 34 3d d3 de 00 00 66 c0 14   .......4=....f..\n c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f   ...\".!.9.8......\n c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16   ...5............\n 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e   ................\n 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04   .3.2.....E.D....\n 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05   ./...A..........\n 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06   ................\n 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02   .......I........\n",
                "vuln-title": "SSL Connection: Server Vulnerable to Heartbleed Attack"
            },
            {
                "date-created": "2019-11-13T17:10:53.286452Z",
                "ddi-severity": "critical",
                "hostname": "BUFF-HEARTBLEED",
                "ip-address": "192.168.69.140",
                "vuln-id": 2601574930,
                "vuln-info": "Server is vulnerable to Heartbleed.\n\nVulnerable response:\n 18 03 02 40 00 02 40 00 48 65 61 72 74 62 6c 65   ...@..@.Heartble\n 65 64 20 54 65 73 74 12 a8 48 97 cf bd 39 04 cc   ed Test..H...9..\n 16 0a 85 03 90 9f 7f 34 3d d3 de 00 00 66 c0 14   .......4=....f..\n c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f   ...\".!.9.8......\n c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16   ...5............\n 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e   ................\n 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04   .3.2.....E.D....\n 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05   ./...A..........\n 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06   ................\n 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02   .......I........\n",
                "vuln-title": "SSL Connection: Server Vulnerable to Heartbleed Attack"
            },
            {
                "date-created": "2019-11-13T17:10:53.286452Z",
                "ddi-severity": "critical",
                "hostname": "BUFF-HEARTBLEED",
                "ip-address": "192.168.69.140",
                "vuln-id": 2601574961,
                "vuln-info": "Server is vulnerable to Heartbleed.\n\nVulnerable response:\n 18 03 02 40 00 02 40 00 48 65 61 72 74 62 6c 65   ...@..@.Heartble\n 65 64 20 54 65 73 74 12 a8 48 97 cf bd 39 04 cc   ed Test..H...9..\n 16 0a 85 03 90 9f 7f 34 3d d3 de 00 00 66 c0 14   .......4=....f..\n c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f   ...\".!.9.8......\n c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16   ...5............\n 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e   ................\n 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04   .3.2.....E.D....\n 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05   ./...A..........\n 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06   ................\n 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02   .......I........\n",
                "vuln-title": "SSL Connection: Server Vulnerable to Heartbleed Attack"
            },
            {
                "date-created": "2019-11-13T17:10:53.286452Z",
                "ddi-severity": "critical",
                "hostname": "BUFF-HEARTBLEED",
                "ip-address": "192.168.69.140",
                "vuln-id": 2601574979,
                "vuln-info": "Server is vulnerable to Heartbleed.\n\nVulnerable response:\n 18 03 02 40 00 02 40 00 48 65 61 72 74 62 6c 65   ...@..@.Heartble\n 65 64 20 54 65 73 74 12 a8 48 97 cf bd 39 04 cc   ed Test..H...9..\n 16 0a 85 03 90 9f 7f 34 3d d3 de 00 00 66 c0 14   .......4=....f..\n c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f   ...\".!.9.8......\n c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16   ...5............\n 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e   ................\n 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04   .3.2.....E.D....\n 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05   ./...A..........\n 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06   ................\n 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02   .......I........\n",
                "vuln-title": "SSL Connection: Server Vulnerable to Heartbleed Attack"
            },
            {
                "date-created": "2019-11-13T17:10:53.286452Z",
                "ddi-severity": "critical",
                "hostname": "BUFF-HEARTBLEED",
                "ip-address": "192.168.69.140",
                "vuln-id": 2601575010,
                "vuln-info": "Server is vulnerable to Heartbleed.\n\nVulnerable response:\n 18 03 02 40 00 02 40 00 48 65 61 72 74 62 6c 65   ...@..@.Heartble\n 65 64 20 54 65 73 74 12 a8 48 97 cf bd 39 04 cc   ed Test..H...9..\n 16 0a 85 03 90 9f 7f 34 3d d3 de 00 00 66 c0 14   .......4=....f..\n c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f   ...\".!.9.8......\n c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16   ...5............\n 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e   ................\n 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04   .3.2.....E.D....\n 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05   ./...A..........\n 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06   ................\n 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02   .......I........\n",
                "vuln-title": "SSL Connection: Server Vulnerable to Heartbleed Attack"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "192.168.69.57",
                "ip-address": "192.168.69.57",
                "vuln-id": 2589049730,
                "vuln-info": "'root' : 'root' -\n\n\nLast login: Thu Oct 31 14:55:13 CDT 2019 on pts/0\nWelcome to Ubuntu 16.04 LTS (GNU/Linux 4.4.0-128-generic x86_64)\n\n * Documentation:  https://help.ubuntu.com/\n\n137 packages can be updated.\n1 update is a security update.\n\n\nroot@ubuntu:~# ",
                "vuln-title": "Unix Server Common Password"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "critical",
                "hostname": "WINXP-ORACLE",
                "ip-address": "192.168.69.137",
                "vuln-id": 2589049799,
                "vuln-info": "VNC Auth Password: password",
                "vuln-title": "VNC Server Easily Guessable Password"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "high",
                "hostname": "WINXP-ORACLE",
                "ip-address": "192.168.69.137",
                "vuln-id": 2589049776,
                "vuln-info": "Apache chunked encoding buffer overflow",
                "vuln-title": "Apache Chunked Encoding Buffer Overflow"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "high",
                "hostname": "WINXP-ORACLE",
                "ip-address": "192.168.69.137",
                "vuln-id": 2589049778,
                "vuln-info": "http://192.168.69.137/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cWINDOWS%5cwin.ini\n\n; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n[MCI Extensions.BAK]\naif=MPEGVideo\naifc=MPEGVideo\naiff=MPEGVideo\nasf=MPEGVideo2\nasx=MPEGVideo2\nau=MPEGVideo\nivf=MPEGVideo2\nm1v=MPEGVideo\nm3u=MPEGVideo2\nmp2=MPEGVideo\nmp2v=MPEGVideo\nmp3=MPEGVideo2\nmpa=MPEGVideo\nmpe=MPEGVideo\nmpeg=MPEGVideo\nmpg=MPEGVideo\nmpv2=MPEGVideo\nsnd=MPEGVideo\nwax=MPEGVideo2\nwm=MPEGVideo2\nwma=MPEGVideo2\nwmp=MPEGVideo2\nwmv=MPEGVideo2\nwmx=MPEGVideo2\nwvx=MPEGVideo2\nwpl=MPEGVideo\n",
                "vuln-title": "Apache Win32 Directory Traversal"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "high",
                "hostname": "WINXP-ORACLE",
                "ip-address": "192.168.69.137",
                "vuln-id": 2589049794,
                "vuln-info": "Found the following valid credentials:\nAdministrator/password\nuser/user\n\nData:\n\n\n*===============================================================\nWelcome to Microsoft Telnet Server.\n*===============================================================\nC:\\Documents and Settings\\Administrator>",
                "vuln-title": "Easily Guessable Telnet Credentials"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "high",
                "hostname": "WINXP-ORACLE",
                "ip-address": "192.168.69.137",
                "vuln-id": 2589049756,
                "vuln-info": "Support has ended for Windows XP. This host should be immediately upgraded.",
                "vuln-title": "Microsoft Windows XP End of Life"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "high",
                "hostname": "ATS-WIN7-ENT64",
                "ip-address": "192.168.69.245",
                "vuln-id": 2589049400,
                "vuln-info": "Vulnerable to MS12-020:\n\n 03 00 00 0f 02 f0 80 3e 00 00 03 03 ed 03 ed      .......>.......\n",
                "vuln-title": "MS12-020 Remote Desktop Protocol Use-After-Free Vulnerability (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "high",
                "hostname": "ATS-WIN7-2",
                "ip-address": "192.168.69.102",
                "vuln-id": 2589048854,
                "vuln-info": "Vulnerable to MS12-020:\n\n 03 00 00 0f 02 f0 80 3e 00 00 03 03 ed 03 ed      .......>.......\n",
                "vuln-title": "MS12-020 Remote Desktop Protocol Use-After-Free Vulnerability (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "high",
                "hostname": "BASEWIN2K8SR2",
                "ip-address": "192.168.69.204",
                "vuln-id": 2589048648,
                "vuln-info": "Vulnerable to MS12-020:\n\n 03 00 00 0f 02 f0 80 3e 00 00 03 03 ed 03 ed      .......>.......\n",
                "vuln-title": "MS12-020 Remote Desktop Protocol Use-After-Free Vulnerability (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "high",
                "hostname": "WIN-30QQRC10MGG",
                "ip-address": "192.168.69.55",
                "vuln-id": 2589048770,
                "vuln-info": "Host vulnerable to MS15-034:\n\nHTTP/1.1 416 Requested Range Not Satisfiable\nContent-Type: text/html\nLast-Modified: Wed, 04 Jul 2018 03:33:10 GMT\nAccept-Ranges: bytes\nETag: \"87812ebb4713d41:0\"\nServer: Microsoft-IIS/8.5\nDate: Wed, 06 Nov 2019 19:07:49 GMT\nContent-Length: 362\nContent-Range: bytes */701\n\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\"http://www.w3.org/TR/html4/strict.dtd\">\n<HTML><HEAD><TITLE>Requested Range Not Satisfiable</TITLE>\n<META HTTP-EQUIV=\"Content-Type\" Content=\"text/html; charset=us-ascii\"></HEAD>\n<BODY><h2>Requested Range Not Satisfiable</h2>\n<hr><p>HTTP Error 416. The requested range is not satisfiable.</p>\n</BODY></HTML>\n",
                "vuln-title": "MS15-034: Microsoft IIS HTTP.sys Remote Code Execution (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "high",
                "hostname": "WIN-30QQRC10MGG",
                "ip-address": "192.168.69.124",
                "vuln-id": 2589048530,
                "vuln-info": "Host vulnerable to MS15-034:\n\nHTTP/1.1 416 Requested Range Not Satisfiable\nContent-Type: text/html\nLast-Modified: Tue, 03 Jul 2018 22:36:57 GMT\nAccept-Ranges: bytes\nETag: \"16dc60591e13d41:0\"\nServer: Microsoft-IIS/8.5\nX-Powered-By: ASP.NET\nDate: Wed, 06 Nov 2019 19:07:38 GMT\nContent-Length: 362\nContent-Range: bytes */701\n\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\"http://www.w3.org/TR/html4/strict.dtd\">\n<HTML><HEAD><TITLE>Requested Range Not Satisfiable</TITLE>\n<META HTTP-EQUIV=\"Content-Type\" Content=\"text/html; charset=us-ascii\"></HEAD>\n<BODY><h2>Requested Range Not Satisfiable</h2>\n<hr><p>HTTP Error 416. The requested range is not satisfiable.</p>\n</BODY></HTML>\n",
                "vuln-title": "MS15-034: Microsoft IIS HTTP.sys Remote Code Execution (Network Check)"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "high",
                "hostname": "WINXP-ORACLE",
                "ip-address": "192.168.69.137",
                "vuln-id": 2589049784,
                "vuln-info": "Directory Traversals:\n192.168.69.137:80:\n\t/error/%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows/win.ini\n\nFile contents:\n; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n[MCI Extensions.BAK]\naif=MPEGVideo\naifc=MPEGVideo\naiff=MPEGVideo\nasf=MPEGVideo2\nasx=MPEGVideo2\nau=MPEGVideo\nivf=MPEGVideo2\nm1v=MPEGVideo\nm3u=MPEGVideo2\nmp2=MPEGVideo\nmp2v=MPEGVideo\nmp3=MPEGVideo2\nmpa=MPEGVideo\nmpe=MPEGVideo\nmpeg=MPEGVideo\nmpg=MPEGVideo\nmpv2=MPEGVideo\nsnd=MPEGVideo\nwax=MPEGVideo2\nwm=MPEGVideo2\nwma=MPEGVideo2\nwmp=MPEGVideo2\nwmv=MPEGVideo2\nwmx=MPEGVideo2\nwvx=MPEGVideo2\nwpl=MPEGVideo\n",
                "vuln-title": "Web Server Directory Traversal"
            },
            {
                "date-created": "2019-11-06T19:32:43.729338Z",
                "ddi-severity": "high",
                "hostname": "ATS-WIN10-2",
                "ip-address": "192.168.69.108",
                "vuln-id": 2589048203,
                "vuln-info": "Windows 10 version 1507 has reached end-of-life status",
                "vuln-title": "Windows 10 End of Life"
            }
        ]
    }
}{
    "FrontlineVM": {
        "critical-severity-count": 27,
        "high-severity-count": 11,
        "vulnerability-count": 38
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>FrontlineVM: Vulnerabilities Found</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>vuln-id</strong></th>
      <th><strong>hostname</strong></th>
      <th><strong>ip-address</strong></th>
      <th><strong>vuln-title</strong></th>
      <th><strong>date-created</strong></th>
      <th><strong>ddi-severity</strong></th>
      <th><strong>vuln-info</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 2589048799 </td>
      <td> debian-2 </td>
      <td> 192.168.69.232 </td>
      <td> Easily Guessable SSH Credentials </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> successfully logged in with username: user, password: user </td>
    </tr>
    <tr>
      <td> 2589048312 </td>
      <td> Test </td>
      <td> 192.168.69.177 </td>
      <td> Easily Guessable SSH Credentials </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> successfully logged in with username: root, password: root </td>
    </tr>
    <tr>
      <td> 2589049372 </td>
      <td> UBUNTU </td>
      <td> 192.168.69.148 </td>
      <td> Easily Guessable SSH Credentials </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> successfully logged in with username: user, password: user </td>
    </tr>
    <tr>
      <td> 2589048568 </td>
      <td> 192.168.69.63 </td>
      <td> 192.168.69.63 </td>
      <td> Easily Guessable SSH Credentials </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> successfully logged in with username: root, password: root </td>
    </tr>
    <tr>
      <td> 2589049746 </td>
      <td> 192.168.69.57 </td>
      <td> 192.168.69.57 </td>
      <td> Easily Guessable SSH Credentials </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> successfully logged in with username: admin, password: admin </td>
    </tr>
    <tr>
      <td> 2589048707 </td>
      <td> UBUNTU </td>
      <td> 192.168.69.185 </td>
      <td> Easily Guessable SSH Credentials </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> successfully logged in with username: user, password: user </td>
    </tr>
    <tr>
      <td> 2589048191 </td>
      <td> 192.168.69.62 </td>
      <td> 192.168.69.62 </td>
      <td> Easily Guessable SSH Credentials </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> successfully logged in with username: admin, password: admin </td>
    </tr>
    <tr>
      <td> 2589048953 </td>
      <td> 192.168.69.64 </td>
      <td> 192.168.69.64 </td>
      <td> Easily Guessable SSH Credentials </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> successfully logged in with username: root, password: password </td>
    </tr>
    <tr>
      <td> 2589049082 </td>
      <td> 192.168.69.67 </td>
      <td> 192.168.69.67 </td>
      <td> Easily Guessable SSH Credentials </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> successfully logged in with username: root, password: root </td>
    </tr>
    <tr>
      <td> 2589049811 </td>
      <td> WINXP-ORACLE </td>
      <td> 192.168.69.137 </td>
      <td> MS08-067 Microsoft Windows Server Service Stack Overflow (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> MS08-067 </td>
    </tr>
    <tr>
      <td> 2589048429 </td>
      <td> COMPUTER </td>
      <td> 192.168.69.141 </td>
      <td> MS09-050 Microsoft Windows SMB2 Command Execution Vulnerabilities (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> MS09-050 </td>
    </tr>
    <tr>
      <td> 2589049408 </td>
      <td> ATS-WIN7-ENT64 </td>
      <td> 192.168.69.245 </td>
      <td> MS17-010: SMB Remote Code Execution Vulnerability (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> This asset is missing the MS17-010 patch.<br><br>Vulnerable Response:<br> ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....<br> 00 00 00 00 00 00 00 00 00 08 06 00 00 08 41 6a   ..............Aj<br> 00 00 00                                          ...<br> </td>
    </tr>
    <tr>
      <td> 2589049851 </td>
      <td> WIN-30QQRC10MGG </td>
      <td> 192.168.69.186 </td>
      <td> MS17-010: SMB Remote Code Execution Vulnerability (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> This asset is missing the MS17-010 patch.<br><br>Vulnerable Response:<br> ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....<br> 00 00 00 00 00 00 00 00 00 50 06 00 02 a0 41 6a   .........P....Aj<br> 00 00 00                                          ...<br> </td>
    </tr>
    <tr>
      <td> 2589048229 </td>
      <td> ATS-WIN10-2 </td>
      <td> 192.168.69.108 </td>
      <td> MS17-010: SMB Remote Code Execution Vulnerability (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> This asset is missing the MS17-010 patch.<br><br>Vulnerable Response:<br> ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....<br> 00 00 00 00 00 00 00 00 07 e8 06 00 01 28 41 6a   .............(Aj<br> 00 00 00                                          ...<br> </td>
    </tr>
    <tr>
      <td> 2589048381 </td>
      <td> WIN7WSUS </td>
      <td> 192.168.69.71 </td>
      <td> MS17-010: SMB Remote Code Execution Vulnerability (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> This asset is missing the MS17-010 patch.<br><br>Vulnerable Response:<br> ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....<br> 00 00 00 00 00 00 00 00 00 08 06 00 00 08 41 6a   ..............Aj<br> 00 00 00                                          ...<br> </td>
    </tr>
    <tr>
      <td> 2589048427 </td>
      <td> COMPUTER </td>
      <td> 192.168.69.141 </td>
      <td> MS17-010: SMB Remote Code Execution Vulnerability (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> This asset is missing the MS17-010 patch.<br><br>Vulnerable Response:<br> ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....<br> 00 00 00 00 00 00 00 00 06 c0 06 00 00 30 41 6a   .............0Aj<br> 00 00 00                                          ...<br> </td>
    </tr>
    <tr>
      <td> 2589048886 </td>
      <td> ATS-WIN7-2 </td>
      <td> 192.168.69.102 </td>
      <td> MS17-010: SMB Remote Code Execution Vulnerability (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> This asset is missing the MS17-010 patch.<br><br>Vulnerable Response:<br> ff 53 4d 42 25 05 02 00 c0 88 01 44 00 10 00 00   .SMB%......D....<br> 00 00 00 00 00 00 00 00 00 08 06 00 00 08 41 6a   ..............Aj<br> 00 00 00                                          ...<br> </td>
    </tr>
    <tr>
      <td> 2589048636 </td>
      <td> BASEWIN2K8SR2 </td>
      <td> 192.168.69.204 </td>
      <td> MS19-MAY: Microsoft RDP 'BlueKeep' Unauthenticated Remote Code Execution (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> Target asset is missing the patch for CVE-2019-0708:<br> 03 00 00 09 02 f0 80 21 80                        .......!.<br> </td>
    </tr>
    <tr>
      <td> 2589049393 </td>
      <td> ATS-WIN7-ENT64 </td>
      <td> 192.168.69.245 </td>
      <td> MS19-MAY: Microsoft RDP 'BlueKeep' Unauthenticated Remote Code Execution (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> Target asset is missing the patch for CVE-2019-0708:<br> 03 00 00 09 02 f0 80 21 80                        .......!.<br> </td>
    </tr>
    <tr>
      <td> 2589049764 </td>
      <td> WINXP-ORACLE </td>
      <td> 192.168.69.137 </td>
      <td> MS19-MAY: Microsoft RDP 'BlueKeep' Unauthenticated Remote Code Execution (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> Target asset is missing the patch for CVE-2019-0708:<br> 03 00 00 09 02 f0 80 21 80                        .......!.<br> </td>
    </tr>
    <tr>
      <td> 2601574910 </td>
      <td> BUFF-HEARTBLEED </td>
      <td> 192.168.69.140 </td>
      <td> SSL Connection: Server Vulnerable to Heartbleed Attack </td>
      <td> 2019-11-13T17:10:53.286452Z </td>
      <td> critical </td>
      <td> Server is vulnerable to Heartbleed.<br><br>Vulnerable response:<br> 18 03 02 40 00 02 40 00 48 65 61 72 74 62 6c 65   ...@..@.Heartble<br> 65 64 20 54 65 73 74 12 a8 48 97 cf bd 39 04 cc   ed Test..H...9..<br> 16 0a 85 03 90 9f 7f 34 3d d3 de 00 00 66 c0 14   .......4=....f..<br> c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f   ...".!.9.8......<br> c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16   ...5............<br> 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e   ................<br> 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04   .3.2.....E.D....<br> 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05   ./...A..........<br> 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06   ................<br> 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02   .......I........<br> </td>
    </tr>
    <tr>
      <td> 2601574930 </td>
      <td> BUFF-HEARTBLEED </td>
      <td> 192.168.69.140 </td>
      <td> SSL Connection: Server Vulnerable to Heartbleed Attack </td>
      <td> 2019-11-13T17:10:53.286452Z </td>
      <td> critical </td>
      <td> Server is vulnerable to Heartbleed.<br><br>Vulnerable response:<br> 18 03 02 40 00 02 40 00 48 65 61 72 74 62 6c 65   ...@..@.Heartble<br> 65 64 20 54 65 73 74 12 a8 48 97 cf bd 39 04 cc   ed Test..H...9..<br> 16 0a 85 03 90 9f 7f 34 3d d3 de 00 00 66 c0 14   .......4=....f..<br> c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f   ...".!.9.8......<br> c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16   ...5............<br> 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e   ................<br> 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04   .3.2.....E.D....<br> 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05   ./...A..........<br> 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06   ................<br> 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02   .......I........<br> </td>
    </tr>
    <tr>
      <td> 2601574961 </td>
      <td> BUFF-HEARTBLEED </td>
      <td> 192.168.69.140 </td>
      <td> SSL Connection: Server Vulnerable to Heartbleed Attack </td>
      <td> 2019-11-13T17:10:53.286452Z </td>
      <td> critical </td>
      <td> Server is vulnerable to Heartbleed.<br><br>Vulnerable response:<br> 18 03 02 40 00 02 40 00 48 65 61 72 74 62 6c 65   ...@..@.Heartble<br> 65 64 20 54 65 73 74 12 a8 48 97 cf bd 39 04 cc   ed Test..H...9..<br> 16 0a 85 03 90 9f 7f 34 3d d3 de 00 00 66 c0 14   .......4=....f..<br> c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f   ...".!.9.8......<br> c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16   ...5............<br> 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e   ................<br> 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04   .3.2.....E.D....<br> 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05   ./...A..........<br> 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06   ................<br> 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02   .......I........<br> </td>
    </tr>
    <tr>
      <td> 2601574979 </td>
      <td> BUFF-HEARTBLEED </td>
      <td> 192.168.69.140 </td>
      <td> SSL Connection: Server Vulnerable to Heartbleed Attack </td>
      <td> 2019-11-13T17:10:53.286452Z </td>
      <td> critical </td>
      <td> Server is vulnerable to Heartbleed.<br><br>Vulnerable response:<br> 18 03 02 40 00 02 40 00 48 65 61 72 74 62 6c 65   ...@..@.Heartble<br> 65 64 20 54 65 73 74 12 a8 48 97 cf bd 39 04 cc   ed Test..H...9..<br> 16 0a 85 03 90 9f 7f 34 3d d3 de 00 00 66 c0 14   .......4=....f..<br> c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f   ...".!.9.8......<br> c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16   ...5............<br> 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e   ................<br> 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04   .3.2.....E.D....<br> 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05   ./...A..........<br> 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06   ................<br> 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02   .......I........<br> </td>
    </tr>
    <tr>
      <td> 2601575010 </td>
      <td> BUFF-HEARTBLEED </td>
      <td> 192.168.69.140 </td>
      <td> SSL Connection: Server Vulnerable to Heartbleed Attack </td>
      <td> 2019-11-13T17:10:53.286452Z </td>
      <td> critical </td>
      <td> Server is vulnerable to Heartbleed.<br><br>Vulnerable response:<br> 18 03 02 40 00 02 40 00 48 65 61 72 74 62 6c 65   ...@..@.Heartble<br> 65 64 20 54 65 73 74 12 a8 48 97 cf bd 39 04 cc   ed Test..H...9..<br> 16 0a 85 03 90 9f 7f 34 3d d3 de 00 00 66 c0 14   .......4=....f..<br> c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f   ...".!.9.8......<br> c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16   ...5............<br> 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e   ................<br> 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04   .3.2.....E.D....<br> 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05   ./...A..........<br> 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06   ................<br> 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02   .......I........<br> </td>
    </tr>
    <tr>
      <td> 2589049730 </td>
      <td> 192.168.69.57 </td>
      <td> 192.168.69.57 </td>
      <td> Unix Server Common Password </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> 'root' : 'root' -<br><br><br>Last login: Thu Oct 31 14:55:13 CDT 2019 on pts/0<br>Welcome to Ubuntu 16.04 LTS (GNU/Linux 4.4.0-128-generic x86_64)<br><br> * Documentation:  https://help.ubuntu.com/<br><br>137 packages can be updated.<br>1 update is a security update.<br><br><br>root@ubuntu:~#  </td>
    </tr>
    <tr>
      <td> 2589049799 </td>
      <td> WINXP-ORACLE </td>
      <td> 192.168.69.137 </td>
      <td> VNC Server Easily Guessable Password </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> critical </td>
      <td> VNC Auth Password: password </td>
    </tr>
    <tr>
      <td> 2589049776 </td>
      <td> WINXP-ORACLE </td>
      <td> 192.168.69.137 </td>
      <td> Apache Chunked Encoding Buffer Overflow </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> high </td>
      <td> Apache chunked encoding buffer overflow </td>
    </tr>
    <tr>
      <td> 2589049778 </td>
      <td> WINXP-ORACLE </td>
      <td> 192.168.69.137 </td>
      <td> Apache Win32 Directory Traversal </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> high </td>
      <td> http://192.168.69.137/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cWINDOWS%5cwin.ini<br><br>; for 16-bit app support<br>[fonts]<br>[extensions]<br>[mci extensions]<br>[files]<br>[Mail]<br>MAPI=1<br>[MCI Extensions.BAK]<br>aif=MPEGVideo<br>aifc=MPEGVideo<br>aiff=MPEGVideo<br>asf=MPEGVideo2<br>asx=MPEGVideo2<br>au=MPEGVideo<br>ivf=MPEGVideo2<br>m1v=MPEGVideo<br>m3u=MPEGVideo2<br>mp2=MPEGVideo<br>mp2v=MPEGVideo<br>mp3=MPEGVideo2<br>mpa=MPEGVideo<br>mpe=MPEGVideo<br>mpeg=MPEGVideo<br>mpg=MPEGVideo<br>mpv2=MPEGVideo<br>snd=MPEGVideo<br>wax=MPEGVideo2<br>wm=MPEGVideo2<br>wma=MPEGVideo2<br>wmp=MPEGVideo2<br>wmv=MPEGVideo2<br>wmx=MPEGVideo2<br>wvx=MPEGVideo2<br>wpl=MPEGVideo<br> </td>
    </tr>
    <tr>
      <td> 2589049794 </td>
      <td> WINXP-ORACLE </td>
      <td> 192.168.69.137 </td>
      <td> Easily Guessable Telnet Credentials </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> high </td>
      <td> Found the following valid credentials:<br>Administrator/password<br>user/user<br><br>Data:<br><br><br>*===============================================================<br>Welcome to Microsoft Telnet Server.<br>*===============================================================<br>C:\Documents and Settings\Administrator> </td>
    </tr>
    <tr>
      <td> 2589049756 </td>
      <td> WINXP-ORACLE </td>
      <td> 192.168.69.137 </td>
      <td> Microsoft Windows XP End of Life </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> high </td>
      <td> Support has ended for Windows XP. This host should be immediately upgraded. </td>
    </tr>
    <tr>
      <td> 2589049400 </td>
      <td> ATS-WIN7-ENT64 </td>
      <td> 192.168.69.245 </td>
      <td> MS12-020 Remote Desktop Protocol Use-After-Free Vulnerability (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> high </td>
      <td> Vulnerable to MS12-020:<br><br> 03 00 00 0f 02 f0 80 3e 00 00 03 03 ed 03 ed      .......>.......<br> </td>
    </tr>
    <tr>
      <td> 2589048854 </td>
      <td> ATS-WIN7-2 </td>
      <td> 192.168.69.102 </td>
      <td> MS12-020 Remote Desktop Protocol Use-After-Free Vulnerability (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> high </td>
      <td> Vulnerable to MS12-020:<br><br> 03 00 00 0f 02 f0 80 3e 00 00 03 03 ed 03 ed      .......>.......<br> </td>
    </tr>
    <tr>
      <td> 2589048648 </td>
      <td> BASEWIN2K8SR2 </td>
      <td> 192.168.69.204 </td>
      <td> MS12-020 Remote Desktop Protocol Use-After-Free Vulnerability (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> high </td>
      <td> Vulnerable to MS12-020:<br><br> 03 00 00 0f 02 f0 80 3e 00 00 03 03 ed 03 ed      .......>.......<br> </td>
    </tr>
    <tr>
      <td> 2589048770 </td>
      <td> WIN-30QQRC10MGG </td>
      <td> 192.168.69.55 </td>
      <td> MS15-034: Microsoft IIS HTTP.sys Remote Code Execution (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> high </td>
      <td> Host vulnerable to MS15-034:<br><br>HTTP/1.1 416 Requested Range Not Satisfiable<br>Content-Type: text/html<br>Last-Modified: Wed, 04 Jul 2018 03:33:10 GMT<br>Accept-Ranges: bytes<br>ETag: "87812ebb4713d41:0"<br>Server: Microsoft-IIS/8.5<br>Date: Wed, 06 Nov 2019 19:07:49 GMT<br>Content-Length: 362<br>Content-Range: bytes */701<br><br><!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd"><br><HTML><HEAD><TITLE>Requested Range Not Satisfiable</TITLE><br><META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD><br><BODY><h2>Requested Range Not Satisfiable</h2><br><hr><p>HTTP Error 416. The requested range is not satisfiable.</p><br></BODY></HTML><br> </td>
    </tr>
    <tr>
      <td> 2589048530 </td>
      <td> WIN-30QQRC10MGG </td>
      <td> 192.168.69.124 </td>
      <td> MS15-034: Microsoft IIS HTTP.sys Remote Code Execution (Network Check) </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> high </td>
      <td> Host vulnerable to MS15-034:<br><br>HTTP/1.1 416 Requested Range Not Satisfiable<br>Content-Type: text/html<br>Last-Modified: Tue, 03 Jul 2018 22:36:57 GMT<br>Accept-Ranges: bytes<br>ETag: "16dc60591e13d41:0"<br>Server: Microsoft-IIS/8.5<br>X-Powered-By: ASP.NET<br>Date: Wed, 06 Nov 2019 19:07:38 GMT<br>Content-Length: 362<br>Content-Range: bytes */701<br><br><!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd"><br><HTML><HEAD><TITLE>Requested Range Not Satisfiable</TITLE><br><META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD><br><BODY><h2>Requested Range Not Satisfiable</h2><br><hr><p>HTTP Error 416. The requested range is not satisfiable.</p><br></BODY></HTML><br> </td>
    </tr>
    <tr>
      <td> 2589049784 </td>
      <td> WINXP-ORACLE </td>
      <td> 192.168.69.137 </td>
      <td> Web Server Directory Traversal </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> high </td>
      <td> Directory Traversals:<br>192.168.69.137:80:<br>	/error/%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows/win.ini<br><br>File contents:<br>; for 16-bit app support<br>[fonts]<br>[extensions]<br>[mci extensions]<br>[files]<br>[Mail]<br>MAPI=1<br>[MCI Extensions.BAK]<br>aif=MPEGVideo<br>aifc=MPEGVideo<br>aiff=MPEGVideo<br>asf=MPEGVideo2<br>asx=MPEGVideo2<br>au=MPEGVideo<br>ivf=MPEGVideo2<br>m1v=MPEGVideo<br>m3u=MPEGVideo2<br>mp2=MPEGVideo<br>mp2v=MPEGVideo<br>mp3=MPEGVideo2<br>mpa=MPEGVideo<br>mpe=MPEGVideo<br>mpeg=MPEGVideo<br>mpg=MPEGVideo<br>mpv2=MPEGVideo<br>snd=MPEGVideo<br>wax=MPEGVideo2<br>wm=MPEGVideo2<br>wma=MPEGVideo2<br>wmp=MPEGVideo2<br>wmv=MPEGVideo2<br>wmx=MPEGVideo2<br>wvx=MPEGVideo2<br>wpl=MPEGVideo<br> </td>
    </tr>
    <tr>
      <td> 2589048203 </td>
      <td> ATS-WIN10-2 </td>
      <td> 192.168.69.108 </td>
      <td> Windows 10 End of Life </td>
      <td> 2019-11-06T19:32:43.729338Z </td>
      <td> high </td>
      <td> Windows 10 version 1507 has reached end-of-life status </td>
    </tr>
  </tbody>
</table>

<h3>FrontlineVM: Vulnerability Statisctics</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>vulnerability-count</strong></th>
      <th><strong>high-severity-count</strong></th>
      <th><strong>critical-severity-count</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 38 </td>
      <td> 11 </td>
      <td> 27 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="frontline-scan-asset">3. frontline-scan-asset</h3>
<hr>
<p>Performs a scan on a given asset.</p>
<h5>Base Command</h5>
<p>
  <code>frontline-scan-asset</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>ip_address</td>
      <td>IP address of asset to perform scan. To scan a range of ip addresses, first enter the low ip address and then a high ip address separated by a hyphen. E.g. 192.168.1.1-192.168.1.10</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>scan_policy</td>
      <td>Policy of scan (case sensitive)</td>
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
      <td>FrontlineVM.Scan</td>
      <td>unknown</td>
      <td>The response output of requested scan to perform.</td>
    </tr>
    <tr>
      <td>FrontlineVM.Scan.ID</td>
      <td>unknown</td>
      <td>Scan ID number</td>
    </tr>
    <tr>
      <td>FrontlineVM.Scan.Name</td>
      <td>unknown</td>
      <td>Scan name</td>
    </tr>
    <tr>
      <td>FrontlineVM.Scan.Policy</td>
      <td>unknown</td>
      <td>Scan policy name</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!frontline-scan-asset ip_address=192.168.69.140</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "FrontlineVM": {
        "Scan": {
            "ID": "219178",
            "IP": "192.168.69.140",
            "Name": "Demisto Scan  [192.168.69.140]",
            "Policy": "Default"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>FrontlineVM: Performing Scan</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>IP</strong></th>
      <th><strong>Policy</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 219178 </td>
      <td> Demisto Scan  [192.168.69.140] </td>
      <td> 192.168.69.140 </td>
      <td> Default </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h2>Additional Information</h2><h2>Known Limitations</h2><h2>Troubleshooting</h2>