<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Demisto Lock is a mechanism that enables users to prevent concurrent execution of tasks. This is a native integration, which does not require configuration.</p>
<hr>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_27761285331529904975109">Get a lock: demisto-lock-get</a></li>
<li><a href="#h_742419847101529905253137">Show lock information: demisto-lock-info</a></li>
<li><a href="#h_439050099251529905261733">Release a lock: demisto-lock-release</a></li>
<li><a href="#h_329935457391529905267698">Release all locks: demisto-lock-release-all</a></li>
</ol>
<hr>
<h3 id="h_27761285331529904975109">Get a lock</h3>
<p>Gets a specific lock. If the lock doesn't exist, it creates one. If the lock is already in use, the command waits until the lock is released or until timeout is reached. If timeout is reached and the lock hasn't been released, the command fails to get the lock.</p>
<h5>Base Command</h5>
<p><code>demisto-lock-get</code></p>
<h5>Input</h5>
<table style="height: 195px; width: 679px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 225px;"><strong>Parameter</strong></td>
<td style="width: 429px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 225px;">name</td>
<td style="width: 429px;">Lock name. When omitted, the default is <em>Default</em>.</td>
</tr>
<tr>
<td style="width: 225px;">info</td>
<td style="width: 429px;">Additional information about the lock</td>
</tr>
<tr>
<td style="width: 225px;">timeout</td>
<td style="width: 429px;">Timeout to wait for the lock to be released</td>
</tr>
</tbody>
</table>
<hr>
<h3 id="h_742419847101529905253137">Show lock information</h3>
<p>Retreives information for a specified lock.</p>
<h5>Base Command</h5>
<p><code>demisto-lock-info</code></p>
<h5>Input</h5>
<table style="height: 195px; width: 679px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 225px;"><strong>Parameter</strong></td>
<td style="width: 429px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 225px;">name</td>
<td style="width: 429px;">Name of lock to retrieve information for. When omitted, the default is <em>Default</em>.</td>
</tr>
</tbody>
</table>
<hr>
<h3 id="h_439050099251529905261733">Release a lock</h3>
<p>Release a specified lock.</p>
<h5>Base Command</h5>
<p><code>demisto-lock-release</code></p>
<h5>Input</h5>
<table style="height: 195px; width: 679px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 225px;"><strong>Parameter</strong></td>
<td style="width: 429px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 225px;">name</td>
<td style="width: 429px;">Name of lock to release. When omitted, the default is <em>Default</em>.</td>
</tr>
</tbody>
</table>
<hr>
<h3 id="h_329935457391529905267698">Release all locks</h3>
<p>Release a specified lock.</p>
<h5>Base Command</h5>
<p><code>demisto-lock-release-all</code></p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h2>Troubleshooting</h2>
If you use multiple locks which might be set in parallel, it is recommended to enable the <b>Sync integration cache</b> (Available from Cortex XSOAR 6.2.0).