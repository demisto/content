<!-- HTML_DOC -->
<p>Use the SMB integration to upload and download files from an SMB protocol.</p>
<p>The integration will utilize SMB2 protocol for communication if the remote SMB/CIFS service supports SMB2. Otherwise, the integration will automatically fall back to use SMB1 protocol.</p>
<h2>Configure SMB on Demisto</h2>
<p>If you did not configure the Server IP / Hostname, Server NetBIOS (AD) Name, or Domain parameters, you can configure them later on as command arguments. In that case, the test command in the instance configuration will return an error.</p>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for SMB.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server IP / Hostname</strong></li>
<li><strong>Port</strong></li>
<li><strong>Server NetBIOS (AD) Name</strong></li>
<li><strong>Domain</strong></li>
<li><strong>Username</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_89160909551542737819278">Download a file: smb-download</a></li>
<li><a href="#h_89160909551542737819278" target="_self">Upload a file: smb-upload</a></li>
</ol>
<h3 id="h_89160909551542737819278">1. Download a file</h3>
<hr>
<p>Downloads a file from an SMB server.</p>
<h5>Base Command</h5>
<p><code>smb-download</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 174.667px;"><strong>Argument Name</strong></th>
<th style="width: 431.333px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 174.667px;">hostname</td>
<td style="width: 431.333px;">Server IP address or hostname, for example, 1.2.3.4.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 174.667px;">nbname</td>
<td style="width: 431.333px;">Name of the server NetBIOS (AD).</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 174.667px;">domain</td>
<td style="width: 431.333px;">The host domain.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 174.667px;">file_path</td>
<td style="width: 431.333px;">The path to the file, starting from the share</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 174.667px;">download_and_attach</td>
<td style="width: 431.333px;">If "yes", the file is downloaded and attached. If "no", only the output is attached. Default is "yes".</td>
<td style="width: 101px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!smb-download file_path=/Shared/test.txt</pre>
<h5>Context Output</h5>
<p><img src="https://user-images.githubusercontent.com/39116813/48847906-59685380-edab-11e8-84ad-e3e012bc6c52.jpg" alt="playground - war room 2018-11-21 16-34-35"></p>
<h5>War Room Output</h5>
<p><img src="https://user-images.githubusercontent.com/39116813/48847811-22923d80-edab-11e8-9bf0-211c4dfc9fef.jpg" width="751" height="265"></p>
<h3 id="h_89160909551542737819278">2. Upload a file</h3>
<hr>
<p>Uploads a file to an SMB server.</p>
<h5>Base Command</h5>
<p><code>smb-upload</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 174.667px;"><strong>Argument Name</strong></th>
<th style="width: 431.333px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 174.667px;">hostname</td>
<td style="width: 431.333px;">Server IP address or hostname, for example, 1.2.3.4.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 174.667px;">nbname</td>
<td style="width: 431.333px;">Name of the server NetBIOS (AD).</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 174.667px;">domain</td>
<td style="width: 431.333px;">The host domain.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 174.667px;">file-path</td>
<td style="width: 431.333px;">The path to the file, starting from the share, for example: Share/Folder/File.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 174.667px;">entryID</td>
<td style="width: 431.333px;">The entry ID to the file to send to the share.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 174.667px;">content</td>
<td style="width: 431.333px;">The content of the file to send to the share</td>
<td style="width: 101px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h2>Troubleshooting</h2>
<p>The following error might be due to an incorrect file path, or a permissions issue.</p>
<p><img src="https://user-images.githubusercontent.com/39116813/48847948-769d2200-edab-11e8-944f-70f34f4130d6.jpg" alt="playground - war room 2018-11-21 16-35-18" width="755" height="110"></p>
