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

<br>

<h3>Supported Log Categories</h3>

<details>
<summary>Traffic management</summary>
<table style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">
<tr>
<th style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Classification</th>
<th style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Module Name</th>
<th style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Details</th>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Traffic management</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">BWM</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Bandwidth module</td>
</tr>
</table>
</details>
<br>
<details>
<summary>System management</summary>
<table style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">
<tr>
<th style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Classification</th>
<th style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Module Name</th>
<th style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Details</th>
</tr>
<tr>
<td rowspan="10">System management</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">PAF</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Product adapter file (PAF) customization</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">SSH</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">STelnet module</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">SYSTEM</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Alarms for CPU, memory, and session usage</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">TFTP</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">TFTP module</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">UPDATE</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Signature database update</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">BWM</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Bandwidth module</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">VOSCPU</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">CPU usage</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">VOSMEM</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Memory usage</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">FWLCNS</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">License module</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">SNMPMAC</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Across-Layer-3 MAC Identification</td>
</tr>
</table>
</details>

<br>

<h2></h2>

<h3>Supported Timestamp Formats</h3>
<table style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">
<tr>
<th style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Format</th>
<th style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Example</th>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">MMM dd yyyy HH:mm:ss </td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Aug 17 2024 12:30:50</td>
</tr>
</table>
<h2></h2>

<br>

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
<table style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">
<tr>
<th style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Parameter</th>
<th style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Value</th>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Protocol</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Select the protocol (UDP, TCP, or Secure TCP) that you configured on your Huawei Firewall.</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Port</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Enter the syslog port for the Broker VM to listen on. This must match the port configured on the Huawei Firewall (default: 514).</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Vendor</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Enter `Huawei`.</td>
</tr>
<tr>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Product</td>
<td style="border: 1px solid black;padding: 5px;text-align: left;border-collapse: collapse;">Enter `FW`.</td>
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
