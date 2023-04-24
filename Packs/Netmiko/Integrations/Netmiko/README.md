
## Netmiko SSH module integration

  This integration provides ssh-based access to network devices, servers, and other appliances that support this method of configuration. For a complete list of supported platforms, please visit the below URL:

  [Netmiko Platforms.md on Github](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md)

  ## Configuration Parameters
  <ul>
  <li><i><b>Name</b></i>
   - Integration instance name
  <li><i><b>Platform</b> </i>
   - The Netmiko-specific platform name</li>
  <li><i><b>Hostname</b></i>
   - The IP address, Hostname, or FQDN to connect to over SSH</li>
  <li><i><b>Port</b></i>
   - The port to use for the SSH connection</li>
  <li><i><b>Credentials</b></i>
   - The credentials should be the same as the Tanium client.</li>
</ul>
<p>
<div align="center">

<b>NOTE</b>:  Platform names are taken from the supported
[SSH](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md#supported-ssh-device_type-values) or [Telnet](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md#supported-telnet-device_type-values) device type lists on GitHub.

</div>
</p>


<h2>Configure Netmiko Integration in Cortex XSOAR</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong></li>
  <li>Search for Netmiko.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a name for the integration instance.</li>
      <li><strong>Platform: </strong> the platform identifier taken from the above SSH or Telnet platform name lists (e.g., linux_ssh, paloalto_panos, etc.)</li>
      <li><strong>Hostname: </strong> The IP address, hostname, or FQDN for the device to connect to via SSH.</strong></li>
      <li><strong>Port: </strong> The port to connect to via SSH</li>
      <li><strong>Credentials: </strong>The username/password, or XSOAR credential object, to be used for the connection</li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance. This performs a simple connection to the system hosting the SSH server.
  </li>
</ol>
<h2>Commands</h2>
<p>
  The Netmiko integration currently only supports the netmiko-cmds command for SSH. This command can be used via the XSOAR CLI, as part of an automation, or as a task in an XSOAR playbook. Like other XSOAR commands, this object can be passed a single command, a list of commands, or an array of commands to execute in a single session. 
</p>

<ol>
  <li><a href="#netmiko-cmds" target="_self">Executes a command, or series of commands, over an SSH connection: netmiko-cmds</a></li>
</ol>

<h3 id="netmiko-cmds">1. netmiko-cmds</h3>
<hr>
<p>Executes a command, or series of commands, over an SSH connection. Outputs from the executed commands are returned to the incident/playground context.</p>
<h5>Base Command</h5>
<p>
  <code>netmiko-cmds</code>
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
      <td>cmds</td>
      <td>The command, or commands, to execute. When commands are manually specified and executed via the XSOAR CLI or in a task, place each command after the first on a new line (no comma required).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>disable_context</td>
      <td>The package ID. Package ID or package name is required. When both exist, ID is used.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>exit_argument</td>
      <td>The optional <b>exit</b> command to be executed after the <b>cmds</b> parameter. This is tied to the <b>requires_exit</b> optional parameter. (Default: <b>q</b></td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>isConfig</td>
      <td>Specifies whether or not the commands being executed require a <b>configure</b> command to be executed first (e.g., <b>conf t</b> for Cisco IOS). The specific configure command is handled by the Netmiko Python module, and is associated with the <b>Platform</b> parameter specified in the integration instance. (Default: <b>False</b>)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>override_host</td>
      <td>If specified, uses this host in place of the one specified in the instance configuration.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>override_password</td>
      <td>If specified, uses this password in place of the one specified in the instance configuration.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>override_platform</td>
      <td>If specified, uses this platform name in place of the one specified in the instance configuration.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>override_port</td>
      <td>If specified, uses this port in place of the one specified in the instance configuration.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>override_username</td>
      <td>If specified, uses this username in place of the one specified in the instance configuration.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>raw_print</td>
      <td>The package ID. Package ID or package name is required. When both exist, ID is used.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>require_enable</td>
      <td>Specifies whether or not the <b>enable</b> command must be executed before the commands specified in the cmds parameter. (Default: <b>False</b>)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>require_exit</td>
      <td>Specifies an optional command that must be executed upon completion of the cmds parameter being executed. (Default: <b>False</b>)</td>
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
      <td>Netmiko.Command</td>
      <td>String</td>
      <td>The executed command(s).</td>
    </tr>
    <tr>
      <td>Netmiko.DateTimeUTC</td>
      <td>Date</td>
      <td>The datetime at which the command(s) were executed (in UTC).</td>
    </tr>
    <tr>
      <td>Netmiko.Hostname</td>
      <td>String</td>
      <td>The hostname used for this execution of the integration.</td>
    </tr>
    <tr>
      <td>Netmiko.Output</td>
      <td>String</td>
      <td>The results of the command(s) that were executed.</td>
    </tr>
  </tbody>
</table>

<h3>Command Example (Single command)</h3>
<p>
  <code>!netmiko-cmds cmds="whoami"</code>
</p>
<h5>Context Example</h5>
<pre>
{
	"Command": "whoami",
	"DateTimeUTC": "2023-04-24T21:40:21.755985",
	"Hostname": "192.168.0.1",
	"Output": "[someuser@someserver ~]$ root"  }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h4>Command(s) against 192.168.0.1 (linux)</h4>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Command</strong></th>
        <th><strong>DateTimeUTC</strong></th>
        <th><strong>Hostname</strong></th>
        <th><strong>Output</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> whoami </td>
        <td> 2023-04-24T21:40:21.755985 </td>
        <td> 192.168.0.1 </td>
        <td> root </td>
      </tr>
    </tbody>
  </table>

<h3>Command Example (Multiple commands)</h3>
<h4> As multiple commands via CLI or task</h4>
<p>
  <pre><code>!netmiko-cmds cmds="whoami
  who"</code></pre>
</p>
<h4> As multiple commands via CLI or task using an array</h4>
<p><pre><code>array context key = ["whoami", "who"]
!netmiko-cmds cmds=${array}</code></pre>
</p>
<h5>Context Example</h5>
<pre>
{
	"Netmiko": [{
		"Command": "whoami",
		"DateTimeUTC": "2023-04-24T21:59:02.177240",
		"Hostname": "192.168.0.1",
		"Output": "[someuser@somehost ~]$ root"
	}, {
		"Command": "who",
		"DateTimeUTC": "2023-04-24T21:59:04.882842",
		"Hostname": "192.168.0.1",
		"Output": "[someuser@somehost ~]$ root pts/0        2023-04-24 17:58 (192.168.0.1)"
	}]
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h4>Command(s) against 192.168.0.1 (linux)</h4>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Command</strong></th>
        <th><strong>DateTimeUTC</strong></th>
        <th><strong>Hostname</strong></th>
        <th><strong>Output</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> whoami </td>
        <td> 2023-04-24T21:59:02.177240 </td>
        <td> 192.168.0.1 </td>
        <td> root </td>
      </tr>
    <tr>
        <td> who </td>
        <td> 2023-04-24T21:59:04.882842 </td>
        <td> 192.168.0.1 </td>
        <td> [someuser@somehost ~]$ root pts/0        2023-04-24 17:58 (192.168.0.1) </td>
      </tr>
    </tbody>
  </table>
</p>