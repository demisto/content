<!-- HTML_DOC -->
<p>Use the Rasterize integration to convert images, PDFs, email bodies, and image files to raster images.</p>
<h2>Configure Rasterize on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Rasterize.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Use system proxy settings</strong></li>
<li>
<strong>with_errors</strong>: return warnings instead of errors.</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_97590845631548148243709">Rasterize a URL into an image or PDF: rasterize</a></li>
<li><a href="#h_415882509261548148248822">Rasterize an email body into an image: rasterize-email</a></li>
<li><a href="#h_518810691451548148254288">Rasterize an image file: rasterize-image</a></li>
</ol>
<h3 id="h_97590845631548148243709">1. Rasterize a URL into an image or PD</h3>
<hr>
<p>Rasterize a URL into image or PDF</p>
<h5>Base Command</h5>
<p><code>rasterize</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 517px;"><strong>Description</strong></th>
<th style="width: 77px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">url</td>
<td style="width: 517px;">The URL to rasterize. Must be the full URL, including the <code>http </code>prefix.</td>
<td style="width: 77px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">width</td>
<td style="width: 517px;">The page width, e.g., 50px (empty is entire page)</td>
<td style="width: 77px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">height</td>
<td style="width: 517px;">The page height, e.g., 50px (empty is entire page)</td>
<td style="width: 77px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">type</td>
<td style="width: 517px;">pdf or png, default is png</td>
<td style="width: 77px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code></code></p>
<h5>Context Example</h5>
<pre><code></code></pre>
<h5>Human Readable Output</h5>
<h3 id="h_415882509261548148248822">2. Rasterize an email body into an image</h3>
<hr>
<p>Rasterize an email body into an image.</p>
<h5>Base Command</h5>
<p><code>rasterize-email</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 159px;"><strong>Argument Name</strong></th>
<th style="width: 487px;"><strong>Description</strong></th>
<th style="width: 94px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 159px;">htmlBody</td>
<td style="width: 487px;">HTML body of the email</td>
<td style="width: 94px;">Required</td>
</tr>
<tr>
<td style="width: 159px;">width</td>
<td style="width: 487px;">The email width, e.g., 50px (empty is entire email)</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">height</td>
<td style="width: 487px;">The page height, e.g., 50px (empty is entire email)</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">type</td>
<td style="width: 487px;">pdf or png. Default is png.</td>
<td style="width: 94px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h3 id="h_518810691451548148254288">3. Rasterize an image file</h3>
<hr>
<p>Rasterize an image file.</p>
<h5>Base Command</h5>
<p><code>rasterize-image</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 161px;"><strong>Argument Name</strong></th>
<th style="width: 487px;"><strong>Description</strong></th>
<th style="width: 92px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 161px;">EntryID</td>
<td style="width: 487px;">Entry ID of the image file</td>
<td style="width: 92px;">Required</td>
</tr>
<tr>
<td style="width: 161px;">width</td>
<td style="width: 487px;">The image width, e.g., 50px (empty is entire image)</td>
<td style="width: 92px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">height</td>
<td style="width: 487px;">The image height, e.g., 50px (empty is entire image)</td>
<td style="width: 92px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>