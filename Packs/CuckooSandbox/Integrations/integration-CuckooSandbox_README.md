<!-- HTML_DOC -->
<h2>Overview</h2>
<p>This integration was integrated and tested with Cuckoo Sandbox v2.0.6.</p>
<h2>Cuckoo Sandbox Playbook</h2>
<ul>
<li>
<strong>CuckooDetonateFile</strong>: Gets a file and detonates it on Cuckoo, returns report when available.</li>
<li>
<strong>CuckooDetonateURL</strong>: Gets a URL and detonates it on Cuckoo, returns report when available.</li>
<li>
<strong>CuckooGetScreenshots</strong>: Gets a taskID of Cuckoo's investigation and returns zipped screenshots</li>
</ul>
<h2>Use Cases</h2>
<ul>
<li>Analyze files and URLs in a safe environment (sandbox)</li>
<li>View Cuckoo's tasks and machines</li>
</ul>
<h2>Configure Cuckoo Sandbox on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Cuckoo Sandbox.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. <a href="https://192.168.0.1/" rel="nofollow">https://192.168.0.1</a>)</strong></li>
<li><strong>Username (Only if your Cuckoo service requires HTTP auth)</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_4691429048921543479084695">Create a task from a file: cuckoo-create-task-from-file</a></li>
<li><a href="#h_8399443619771543479089826">Get a task report: cuckoo-get-task-report</a></li>
<li><a href="#h_3333473918321543479054045">Get a list of all tasks: cuckoo-list-tasks</a></li>
<li><a href="#h_9023664726051543479018156">Submit a URL for analysis: cuckoo-create-task-from-url</a></li>
<li><a href="#h_2390913185341543479012736">Get task information: cuckoo-view-task</a></li>
<li><a href="#h_4659596363021543478987257">Delete a task: cuckoo-delete-task</a></li>
<li><a href="#h_6027435692261543478952098">Get analysis screenshots: cuckoo-task-screenshot</a></li>
<li><a href="#h_1430595341521543478937829">Get a list of analysis machines: cuckoo-machines-list</a></li>
<li><a href="#h_56128075761543478931427">Get analysis machine information: cuckoo-machine-view</a></li>
</ol>
<h3 id="h_4691429048921543479084695">1. Create a task from a file</h3>
<hr>
<p>Retrieves a file's entry ID and creates a task with it.</p>
<h5>Base Command</h5>
<pre><code>cuckoo-create-task-from-file</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 135.328125px;"><strong>Argument Name</strong></th>
<th style="width: 501.671875px;"><strong>Description</strong></th>
<th style="width: 69px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135.328125px;">entryID</td>
<td style="width: 501.671875px;">File entry ID</td>
<td style="width: 69px;">Optional</td>
</tr>
<tr>
<td style="width: 135.328125px;">fileID</td>
<td style="width: 501.671875px;">File ID</td>
<td style="width: 69px;">Optional</td>
</tr>
<tr>
<td style="width: 135.328125px;">machine</td>
<td style="width: 501.671875px;">Label of the machine to use for analysis</td>
<td style="width: 69px;">Optional</td>
</tr>
<tr>
<td style="width: 135.328125px;">package</td>
<td style="width: 501.671875px;">Analysis package to be used for the analysis</td>
<td style="width: 69px;">Optional</td>
</tr>
<tr>
<td style="width: 135.328125px;">timeout</td>
<td style="width: 501.671875px;">Analysis timeout (in seconds)</td>
<td style="width: 69px;">Optional</td>
</tr>
<tr>
<td style="width: 135.328125px;">enforce_timeout</td>
<td style="width: 501.671875px;">Enable to enforce the execution for the full timeout value</td>
<td style="width: 69px;">Optional</td>
</tr>
<tr>
<td style="width: 135.328125px;">platform</td>
<td style="width: 501.671875px;">Name of the platform to select the analysis machine from (e.g., “windows”)</td>
<td style="width: 69px;">Optional</td>
</tr>
<tr>
<td style="width: 135.328125px;">tags</td>
<td style="width: 501.671875px;">Define machine to start by tags. Platform must be set to use that. Tags are comma-separated</td>
<td style="width: 69px;">Optional</td>
</tr>
<tr>
<td style="width: 135.328125px;">memory</td>
<td style="width: 501.671875px;">Enables the creation of a full memory dump of the analysis machine</td>
<td style="width: 69px;">Optional</td>
</tr>
<tr>
<td style="width: 135.328125px;">options</td>
<td style="width: 501.671875px;">Options to pass to the analysis package</td>
<td style="width: 69px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 384.703125px;"><strong>Path</strong></th>
<th style="width: 335.296875px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 384.703125px;">Cuckoo.Task.ID</td>
<td style="width: 335.296875px;">ID of the task</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cuckoo-create-task-from-file entryID=814@a969c6ba-e443-4287-8dce-378aa183e2d5</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49157108-adcd7f00-f327-11e8-9ffb-3b57b4327a0c.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49157108-adcd7f00-f327-11e8-9ffb-3b57b4327a0c.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49157027-824a9480-f327-11e8-8813-15f08d63acee.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49157027-824a9480-f327-11e8-8813-15f08d63acee.png" alt="image"></a></p>
<h3 id="h_8399443619771543479089826">2. Get a task report</h3>
<hr>
<p>Retrieves a task report by a task ID.</p>
<h5>Base Command</h5>
<pre><code>cuckoo-get-task-report</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 298.15625px;"><strong>Argument Name</strong></th>
<th style="width: 231.84375px;"><strong>Description</strong></th>
<th style="width: 177px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 298.15625px;">id</td>
<td style="width: 231.84375px;">Task ID</td>
<td style="width: 177px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 302.703125px;"><strong>Path</strong></th>
<th style="width: 417.296875px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Category</td>
<td style="width: 417.296875px;">Category of task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Machine</td>
<td style="width: 417.296875px;">Machine of task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Errors</td>
<td style="width: 417.296875px;">Errors of task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Target</td>
<td style="width: 417.296875px;">Target of task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Package</td>
<td style="width: 417.296875px;">Package of task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.SampleID</td>
<td style="width: 417.296875px;">Sample ID of task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Guest</td>
<td style="width: 417.296875px;">Task guest</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Custom</td>
<td style="width: 417.296875px;">Custom values of task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Owner</td>
<td style="width: 417.296875px;">Task owner</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Priority</td>
<td style="width: 417.296875px;">Priority of task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Platform</td>
<td style="width: 417.296875px;">Platform of task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Options</td>
<td style="width: 417.296875px;">Task options</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Status</td>
<td style="width: 417.296875px;">Task status</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.EnforceTimeout</td>
<td style="width: 417.296875px;">Is timeout of task enforced</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Timeout</td>
<td style="width: 417.296875px;">Task timeout</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Memory</td>
<td style="width: 417.296875px;">Task memory</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Tags</td>
<td style="width: 417.296875px;">Task tags</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.ID</td>
<td style="width: 417.296875px;">ID of task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.AddedOn</td>
<td style="width: 417.296875px;">Date the task was added</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.CompletedOn</td>
<td style="width: 417.296875px;">Date the task was completed</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Score</td>
<td style="width: 417.296875px;">Reported score of the the task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.Monitor</td>
<td style="width: 417.296875px;">Monitor of the reported task</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.FileInfo.sha1</td>
<td style="width: 417.296875px;">The SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.FileInfo.name</td>
<td style="width: 417.296875px;">The file name.</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.FileInfo.type</td>
<td style="width: 417.296875px;">The file type.</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.FileInfo.sha256</td>
<td style="width: 417.296875px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.FileInfo.urls</td>
<td style="width: 417.296875px;">Related URLs of the file.</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.FileInfo.crc32</td>
<td style="width: 417.296875px;">The CRC32 of the file.</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.FileInfo.path</td>
<td style="width: 417.296875px;">The file path.</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.FileInfo.ssdeep</td>
<td style="width: 417.296875px;">The ssdeep of the file.</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.FileInfo.size</td>
<td style="width: 417.296875px;">The size of the file.</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.FileInfo.sha512</td>
<td style="width: 417.296875px;">The SHA512 hash of the file.</td>
</tr>
<tr>
<td style="width: 302.703125px;">Cuckoo.Task.FileInfo.md5</td>
<td style="width: 417.296875px;">The MD5 hash of the file.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cuckoo-get-task-report id=86</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49157277-16b4f700-f328-11e8-8b31-fb08c628d6da.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49157277-16b4f700-f328-11e8-8b31-fb08c628d6da.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49157339-3e0bc400-f328-11e8-9ddd-da51c00ac0f9.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49157339-3e0bc400-f328-11e8-9ddd-da51c00ac0f9.png" alt="image" width="750" height="625"></a></p>
<h3 id="h_3333473918321543479054045">3. Get a list of all tasks</h3>
<hr>
<p>Returns a list of all tasks.</p>
<h5>Base Command</h5>
<pre><code>cuckoo-list-tasks</code></pre>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 297.703125px;"><strong>Path</strong></th>
<th style="width: 422.296875px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Category</td>
<td style="width: 422.296875px;">Category of task</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Machine</td>
<td style="width: 422.296875px;">Machine of task</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Errors</td>
<td style="width: 422.296875px;">Errors of task</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Target</td>
<td style="width: 422.296875px;">Target of task</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Package</td>
<td style="width: 422.296875px;">Package of task</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.SampleID</td>
<td style="width: 422.296875px;">Sample ID of task</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Guest</td>
<td style="width: 422.296875px;">Task guest</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Custom</td>
<td style="width: 422.296875px;">Custom values of task</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Owner</td>
<td style="width: 422.296875px;">Task owner</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Priority</td>
<td style="width: 422.296875px;">Priority of task</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Platform</td>
<td style="width: 422.296875px;">Platform of task</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Options</td>
<td style="width: 422.296875px;">Task options</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Status</td>
<td style="width: 422.296875px;">Task status</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.EnforceTimeout</td>
<td style="width: 422.296875px;">Is timeout of task enforced</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Timeout</td>
<td style="width: 422.296875px;">Task timeout</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Memory</td>
<td style="width: 422.296875px;">Task memory</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.Tags</td>
<td style="width: 422.296875px;">Task tags</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.ID</td>
<td style="width: 422.296875px;">ID of task</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.AddedOn</td>
<td style="width: 422.296875px;">Date the task was added</td>
</tr>
<tr>
<td style="width: 297.703125px;">Cuckoo.Task.CompletedOn</td>
<td style="width: 422.296875px;">Date the task was completed</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cuckoo-list-tasks</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49157518-a6f33c00-f328-11e8-8539-2870fdbde759.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49157518-a6f33c00-f328-11e8-8539-2870fdbde759.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49157703-1c5f0c80-f329-11e8-8f21-4f9dbcaf3c87.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49157703-1c5f0c80-f329-11e8-8f21-4f9dbcaf3c87.png" alt="image"></a></p>
<h3 id="h_9023664726051543479018156">4. Submit a URL for analysis</h3>
<hr>
<p>Submits a URL to Cuckoo Sandbox for analysis.</p>
<h5>Base Command</h5>
<pre><code>cuckoo-create-task-from-url</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 291.78125px;"><strong>Argument Name</strong></th>
<th style="width: 246.21875px;"><strong>Description</strong></th>
<th style="width: 168px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 291.78125px;">url</td>
<td style="width: 246.21875px;">URL to analyze</td>
<td style="width: 168px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 379.703125px;"><strong>Path</strong></th>
<th style="width: 340.296875px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 379.703125px;">Cuckoo.Task.ID</td>
<td style="width: 340.296875px;">Task ID</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cuckoo-create-task-from-url url=google.com</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49157787-516b5f00-f329-11e8-81b0-0d595faf30e7.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49157787-516b5f00-f329-11e8-81b0-0d595faf30e7.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49157767-457f9d00-f329-11e8-8f01-10e753777cd8.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49157767-457f9d00-f329-11e8-8f01-10e753777cd8.png" alt="image"></a></p>
<h3 id="h_2390913185341543479012736">5. Get task information</h3>
<hr>
<p>Returns information for a specified task.</p>
<h5>Base Command</h5>
<pre><code>cuckoo-view-task</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 220.171875px;"><strong>Argument Name</strong></th>
<th style="width: 360.828125px;"><strong>Description</strong></th>
<th style="width: 126px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 220.171875px;">id</td>
<td style="width: 360.828125px;">A comma-separated list of task IDs for which to retrieve information.</td>
<td style="width: 126px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 344.8125px;"><strong>Path</strong></th>
<th style="width: 375.1875px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Category</td>
<td style="width: 375.1875px;">Category of task</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Machine</td>
<td style="width: 375.1875px;">Machine of task</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Errors</td>
<td style="width: 375.1875px;">Errors of task</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Target</td>
<td style="width: 375.1875px;">Target of task</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Package</td>
<td style="width: 375.1875px;">Package of task</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.SampleID</td>
<td style="width: 375.1875px;">Sample ID of task</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Guest</td>
<td style="width: 375.1875px;">Task guest</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Custom</td>
<td style="width: 375.1875px;">Custom values of task</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Owner</td>
<td style="width: 375.1875px;">Task owner</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Priority</td>
<td style="width: 375.1875px;">Priority of task</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Platform</td>
<td style="width: 375.1875px;">Platform of task</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Options</td>
<td style="width: 375.1875px;">Task options</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Status</td>
<td style="width: 375.1875px;">Task status</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.EnforceTimeout</td>
<td style="width: 375.1875px;">Is timeout of task enforced</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Timeout</td>
<td style="width: 375.1875px;">Task timeout</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Memory</td>
<td style="width: 375.1875px;">Task memory</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.Tags</td>
<td style="width: 375.1875px;">Task tags</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.ID</td>
<td style="width: 375.1875px;">ID of task</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.AddedOn</td>
<td style="width: 375.1875px;">Date the task was added</td>
</tr>
<tr>
<td style="width: 344.8125px;">Cuckoo.Task.CompletedOn</td>
<td style="width: 375.1875px;">Date the task was completed</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p>!cuckoo-view-task id=88</p>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49157858-7a8bef80-f329-11e8-808b-01796ac94398.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49157858-7a8bef80-f329-11e8-808b-01796ac94398.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49157878-87a8de80-f329-11e8-89ef-0bdd15b6bb77.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49157878-87a8de80-f329-11e8-89ef-0bdd15b6bb77.png" alt="image"></a></p>
<h3 id="h_4659596363021543478987257">6. Delete a task</h3>
<hr>
<p>Deletes a task from Cuckoo Sandbox.</p>
<h5>Base Command</h5>
<pre><code>cuckoo-delete-task</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>id</td>
<td>Task ID</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!cuckoo-delete-task id=88</pre>
<h3 id="h_6027435692261543478952098">7. Get analysis screenshots</h3>
<hr>
<p>Retrieves screenshots taken during a task analysis. If the screenshot number argument is omitted, the command retrieves a ZIP file with all screenshots.</p>
<h5>Base Command</h5>
<p><code>cuckoo-task-screenshot</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 154.96875px;"><strong>Argument Name</strong></th>
<th style="width: 482.03125px;"><strong>Description</strong></th>
<th style="width: 69px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154.96875px;">id</td>
<td style="width: 482.03125px;">ID of the task that generated the screenshot</td>
<td style="width: 69px;">Required</td>
</tr>
<tr>
<td style="width: 154.96875px;">screenshot</td>
<td style="width: 482.03125px;">Numerical identifier of a single screenshot (e.g., 0001, 0002)</td>
<td style="width: 69px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 354.171875px;"><strong>Path</strong></th>
<th style="width: 365.828125px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 354.171875px;">File.Size</td>
<td style="width: 365.828125px;">Size of file</td>
</tr>
<tr>
<td style="width: 354.171875px;">File.SHA1</td>
<td style="width: 365.828125px;">File SHA-1</td>
</tr>
<tr>
<td style="width: 354.171875px;">File.SHA256</td>
<td style="width: 365.828125px;">File SHA-256</td>
</tr>
<tr>
<td style="width: 354.171875px;">File.Name</td>
<td style="width: 365.828125px;">File name</td>
</tr>
<tr>
<td style="width: 354.171875px;">File.SSDeep</td>
<td style="width: 365.828125px;">File SSDeep</td>
</tr>
<tr>
<td style="width: 354.171875px;">File.EntryID</td>
<td style="width: 365.828125px;">File entry ID</td>
</tr>
<tr>
<td style="width: 354.171875px;">File.Info</td>
<td style="width: 365.828125px;">File info</td>
</tr>
<tr>
<td style="width: 354.171875px;">File.Type</td>
<td style="width: 365.828125px;">File type</td>
</tr>
<tr>
<td style="width: 354.171875px;">File.MD5</td>
<td style="width: 365.828125px;">File MD5</td>
</tr>
<tr>
<td style="width: 354.171875px;">File.Extension</td>
<td style="width: 365.828125px;">File extension</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cuckoo-task-screenshot id=90</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49158077-030a9000-f32a-11e8-989f-12f8770db8e9.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49158077-030a9000-f32a-11e8-989f-12f8770db8e9.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49158053-f128ed00-f329-11e8-9b81-722afff6f14f.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49158053-f128ed00-f329-11e8-9b81-722afff6f14f.png" alt="image" width="750" height="461"></a></p>
<h3 id="h_1430595341521543478937829">8 Get a list of analysis machines</h3>
<hr>
<p>Returns a list with details on the analysis machines available to Cuckoo.</p>
<h5>Base Command</h5>
<pre><code>cuckoo-machines-list</code></pre>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 291.96875px;"><strong>Path</strong></th>
<th style="width: 428.03125px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 291.96875px;">Machine.Status</td>
<td style="width: 428.03125px;">Status of machine</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.Locked</td>
<td style="width: 428.03125px;">Is the machine locked</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.Name</td>
<td style="width: 428.03125px;">Name of machine</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.ResultserverIP</td>
<td style="width: 428.03125px;">IP address of machine's result server</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.IP</td>
<td style="width: 428.03125px;">IP address of machine</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.Label</td>
<td style="width: 428.03125px;">Label of the machine</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.LockedChangedOn</td>
<td style="width: 428.03125px;">Last update time of machine lock status</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.Platform</td>
<td style="width: 428.03125px;">Platform of the machine</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.Snapshot</td>
<td style="width: 428.03125px;">Snapshot</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.Interface</td>
<td style="width: 428.03125px;">Interface of machine</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.StatusChangedOn</td>
<td style="width: 428.03125px;">Last update time of machine status</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.ID</td>
<td style="width: 428.03125px;">ID of machine</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.ResultserverPort</td>
<td style="width: 428.03125px;">Port address of machine's result server</td>
</tr>
<tr>
<td style="width: 291.96875px;">Machine.Tags</td>
<td style="width: 428.03125px;">Machine tags</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cuckoo-machines-list</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49158230-57ae0b00-f32a-11e8-8c6d-c01004978697.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49158230-57ae0b00-f32a-11e8-8c6d-c01004978697.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49158254-64326380-f32a-11e8-811e-dad6b1030eeb.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49158254-64326380-f32a-11e8-811e-dad6b1030eeb.png" alt="image"></a></p>
<h3 id="h_56128075761543478931427">9. Get analysis machine information</h3>
<hr>
<p>Returns details about the analysis machine associated with the specified machine name.</p>
<h5>Base Command</h5>
<pre><code>cuckoo-machine-view</code></pre>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 211.0625px;"><strong>Argument Name</strong></th>
<th style="width: 350.9375px;"><strong>Description</strong></th>
<th style="width: 144px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 211.0625px;">name</td>
<td style="width: 350.9375px;">Name of machine to get information for</td>
<td style="width: 144px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 292.96875px;"><strong>Path</strong></th>
<th style="width: 427.03125px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 292.96875px;">Machine.Status</td>
<td style="width: 427.03125px;">Status of machine</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.Locked</td>
<td style="width: 427.03125px;">Is the machine locked</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.Name</td>
<td style="width: 427.03125px;">Name of machine</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.ResultserverIP</td>
<td style="width: 427.03125px;">IP address of machine's result server</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.IP</td>
<td style="width: 427.03125px;">IP address of machine</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.Label</td>
<td style="width: 427.03125px;">Label of machine</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.LockedChangedOn</td>
<td style="width: 427.03125px;">last update time of machine lock status</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.Platform</td>
<td style="width: 427.03125px;">Platform of machine</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.Snapshot</td>
<td style="width: 427.03125px;">Snapshot</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.Interface</td>
<td style="width: 427.03125px;">Interface of machine</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.StatusChangedOn</td>
<td style="width: 427.03125px;">Last update time of machine status</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.ID</td>
<td style="width: 427.03125px;">ID of machine</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.ResultserverPort</td>
<td style="width: 427.03125px;">Port address of machine's result server</td>
</tr>
<tr>
<td style="width: 292.96875px;">Machine.Tags</td>
<td style="width: 427.03125px;">Machine tags</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cuckoo-machine-view name=windowsxp</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49158413-bffcec80-f32a-11e8-8ed2-e4d40f5a615e.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49158413-bffcec80-f32a-11e8-8ed2-e4d40f5a615e.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/11165655/49158380-ad82b300-f32a-11e8-9655-6958941205b7.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/11165655/49158380-ad82b300-f32a-11e8-9655-6958941205b7.png" alt="image"></a></p>