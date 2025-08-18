<!DOCTYPE html>
<html>
<head>
<h1>Huawei Firewall</h1>
</head>
<body>

<h2>Overview</h2>
<p>
The Huawei USG6000E series consists of AI-based firewalls designed for enterprises.
<br>These devices leverage intelligent threat detection and collaborative defense to proactively protect against advanced threats.
<br>
They feature built-in hardware acceleration to significantly improve the performance of content security detection and IPSec services.
</p>

<~XSIAM>

<h2>This Pack Includes</h2>
<p>Data normalization capabilities:</p>
<ul>
<li>Data modeling rules to normalize Huawei Firewall logs that are ingested via Broker VM to Cortex XSIAM.</li>
<li>Ingested logs can be queried in XQL Search using the <em><i>huawei_fw_raw</i></em> dataset.</li>
</ul>

<h3>Supported Log Categories</h3>

<details>
<summary>Traffic management</summary>
<table>
<tr>
<th>Classification</th>
<th>Module Name</th>
<th>Details</th>
</tr>
<tr>
<td>Traffic management</td>
<td>BWM</td>
<td>Bandwidth module</td>
</tr>
</table>
</details>
<br>
<details>
<summary>System management</summary>
<table>
<tr>
<th>Classification</th>
<th>Module Name</th>
<th>Details</th>
</tr>
<tr>
<td rowspan="10">System management</td>
<td>PAF</td>
<td>Product adapter file (PAF) customization</td>
</tr>
<tr>
<td>SSH</td>
<td>STelnet module</td>
</tr>
<tr>
<td>SYSTEM</td>
<td>Alarms for CPU, memory, and session usage</td>
</tr>
<tr>
<td>TFTP</td>
<td>TFTP module</td>
</tr>
<tr>
<td>UPDATE</td>
<td>Signature database update</td>
</tr>
<tr>
<td>BWM</td>
<td>Bandwidth module</td>
</tr>
<tr>
<td>VOSCPU</td>
<td>CPU usage</td>
</tr>
<tr>
<td>VOSMEM</td>
<td>Memory usage</td>
</tr>
<tr>
<td>FWLCNS</td>
<td>License module</td>
</tr>
<tr>
<td>SNMPMAC</td>
<td>Across-Layer-3 MAC Identification</td>
</tr>
</table>
</details>
<br>

<h3>Supported Timestamp Formats</h3>
<table>
<tr>
<th>Format</th>
<th>Example</th>
</tr>
<tr>
<td>MMM dd yyyy HH:mm:ss </td>
<td>Aug 16 2024 12:30:50</td>
</tr>
</table>

<h2>Data Collection</h2>

<h3>Configure Huawei Firewall</h3>
<ol>
<li>Enable the Information Center. For instructions, refer to the <a href="https://support.huawei.com/hedex/hdx.do?docid=EDOC1100092598&id=EN-US_TASK_0178943611">Huawei documentation</a>.</li>
<li>Navigate to <strong>System</strong>.</li>
<li>In the left pane, select <strong>Log Configuration</strong>.</li>
<li>
Select the <strong>Log Configuration</strong> tab and configure the following settings:
<br><br>
<strong>System Logs</strong>
<ol>
<li>Enter the <i>Log Host IP Address</i>.</li>
<li>Enter the <i>Port</i> number (default is 514).</li>
</ol>
<br>
<strong>Service Logs</strong>
<ol>
<li>For <i>Log Format</i>, select <strong>Syslog</strong>.</li>
</ol>
<br>
<p>For more details on configuring log output, see this <a href="https://support.huawei.com/hedex/hdx.do?docid=EDOC1100092598&id=EN-US_XTASK_0178928516">configuration guide</a>.</p>
</li>
</ol>

<h3>Cortex XSIAM - Broker VM Configuration</h3>
<p>
To create or configure the Broker VM, refer to the <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#">Cortex XSIAM documentation</a>.
<br>
Follow these steps to configure the Broker VM to receive Huawei Firewall logs.
</p>
<ol>
<li>Navigate to <strong>Settings → Configuration → Data Broker → Broker VMs</strong>.</li>
<li>
In the <strong>APPS</strong> column on the <strong>Brokers</strong> tab, add the <strong>Syslog</strong> app for the relevant broker instance.
<br>
If the <strong>Syslog</strong> app already exists, hover over it and click <strong>Configure</strong>.
</li>
<li>Click <strong>Add New</strong>.</li>
<li>
Configure the Syslog Collector with the following parameters:
<table>
<tr>
<th>Parameter</th>
<th>Value</th>
</tr>
<tr>
<td>Protocol</td>
<td>Select the protocol (UDP, TCP, or Secure TCP) that you configured on your Huawei Firewall.</td>
</tr>
<tr>
<td>Port</td>
<td>Enter the syslog port for the Broker VM to listen on. This must match the port configured on the Huawei Firewall (default: 514).</td>
</tr>
<tr>
<td>Vendor</td>
<td>Enter `Huawei`.</td>
</tr>
<tr>
<td>Product</td>
<td>Enter `Firewall`.</td>
</tr>
</table>
</li>
</ol>

<h4>Notes</h4>
<p>
By default, the timestamp in the log header is in UTC.
<br>
To set the system time via the web UI, refer to the <a href="https://support.huawei.com/hedex/hdx.do?docid=EDOC1100092598&id=EN-US_XTASK_0178938248">Huawei documentation</a>.
</p>

</body>
</html>
</~XSIAM>
