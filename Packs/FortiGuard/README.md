<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the Fortinet FortiGuard integration to Fetch Malicious Indicators & Get URL Categories.</p>
<p>This integration was integrated and tested by Mostafa A. Mohamed "Aceilies"</p>
<h2>Configure FortiGuard on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for FortiGuard.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Account API Key</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, username + password, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_2511153492291543315020336">Gets a List of Indicators from FortiGuard: fortiguard-get-indicators</a></li>
<li><a href="#h_549888813401543315025030">Return Domain Information and reputation: url</a></li>

</ol>
<h3 id="h_2511153492291543315020336">1. Gets a List of Indicators from FortiGuard</h3>
<hr>
<p>Returns a file containing available IoCs.</p>
<h5>Base Command</h5>
<p><code>fortiguard-get-indicators</code></p>
<p> </p>
<h5>Context Output</h5>
<p> Returns a file containing the IoCs. </p>
<p> </p>
<h5>Command Example</h5>
<pre>!fortiguard-get-indicators</pre>
<h5>Context Example</h5>
<pre>File:[] 1 item<br>0:{} 10 items<br>Size:306403565<br>SHA1:65d3106269f0c8a741dc8d8cc2bea5950a96f41d<br>SHA256:d6f5614e9b08e03d608469605f2683f22f4baee0efa503af156419522e51b7ac<br>SHA512:5f0c1f7b5af9a7b2c55fa6df0a1c217cd2f87681ac91730ce8ec04bf57882ae135a115f0ffb3eed1a5f35f25fa66d8866d5dae73eacd0effd2deb6f0d36aa5b2<br>Name:FortiGuard Indicators<br>SSDeep:49152:Lw5QsajTG8gNr1whDz+CxAIcN7sy5nRYJgwPWt/00ejzvVmC85SvZFI+dW5MD6dN:LHvc<br>EntryID:191@c99acbc8-fca1-4f57-8958-2cbbee57d738<br>Info:text/plain<br>Type:ASCII text, with very long lines<br>MD5:8fdc14f47e46aa0e3fe8502435a639ee</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/12241410/49055026-d9087f00-f1fe-11e8-8026-45f8ed443944.png" width="749" height="225"></p>
<h3 id="h_549888813401543315025030">2. Return Domain Information and reputation</h3>
<hr>
<p>Returns information about FortiGate service groups.</p>
<h5>Base Command</h5>
<p><code>url</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 255px;"><strong>Argument Name</strong></th>
<th style="width: 302px;"><strong>Description</strong></th>
<th style="width: 151px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 255px;">url</td>
<td style="width: 302px;">URL to be Queried</td>
<td style="width: 151px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 333px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 306px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 333px;">categoryid</td>
<td style="width: 69px;">Integer</td>
<td style="width: 306px;">Queried URL Category ID</td>
</tr>
<tr>
<td style="width: 333px;">categoryname</td>
<td style="width: 69px;">string</td>
<td style="width: 306px;">Queried URL Category Name</td>
</tr>
<tr>
<td style="width: 333px;">url</td>
<td style="width: 69px;">string</td>
<td style="width: 306px;">Queried URL</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!url</pre>
<h5>Context Example</h5>
<pre>FortiGuard:{} 1 item<br>Url:[] 1 item<br>0:{} 3 items<br>categoryid:56<br>categoryname:Search Engines and Portals<br>url:google.com</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/12241410/49055027-d9087f00-f1fe-11e8-80b2-fa516df50343.png" width="752" height="295"></p>
