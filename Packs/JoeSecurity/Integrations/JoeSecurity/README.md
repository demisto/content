<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Use the Joe Security Sandbox integration to detect and analyze potentially malicious files.<br>Using the integration you can analyze URL links and sample files on different machine types (Windows, Android, iOS and Mac OS X).</p>
<p>All file types are supported.</p>
<p>This integration was integrated and tested with Joe Security v2.</p>
<h2>Playbooks</h2>
<hr>
<ul>
<li>JoeSecurity -Detonate URL</li>
<li>JoeSecurity -Detonate File</li>
<li>JoeSecurity -Detonate File From URL</li>
</ul>
<h2>Use Cases</h2>
<hr>
<ul>
<li>Add a file to the integrations war room.</li>
<li>Sample a file.</li>
<li>Get information on an old analysis.</li>
<li>Send a URL sample to Joe Security.</li>
</ul>
<h2>Prerequisites</h2>
<hr>
<p>Before you configure the integration, retrieve the API key from your Joe Security environment.</p>
<ol>
<li>Use this <a href="https://jbxcloud.joesecurity.org/">link</a> to log in to the Joe Security platform. </li>
<li>Click the button in the top-right corner and select <strong>Settings</strong>.</li>
<li>In the <strong>API Key</strong> section, select the <strong>I Agree</strong> checkbox. </li>
<li>Click the <strong>Generate API key</strong> button.</li>
<li>Copy the API key for later use.</li>
</ol>
<h2>Configure the Joe Security Integration on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Joe Security.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: A textual name for the integration instance.</li>
<li>
<strong>Joe Security URL</strong>: URL of the Joe Security server</li>
<li><strong>API Key</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Do not use by default</strong></li>
<li><strong>Cortex XSOAR engine</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>
</ol>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_45220795871529576244617">Ping the server: joe-is-online</a></li>
<li><a href="#h_943521905421529576252174">Submit a URL for analysis: joe-analysis-submit-url</a></li>
<li><a href="#h_980967680761529576288942">Get analysis information: joe-analysis-info</a></li>
<li><a href="#h_1469370781091529576297072">Get analyes list: joe-list-analysis</a></li>
<li><a href="#h_9039961881411529576308915">Submit sample for analysis: joe-analysis-submit-sample</a></li>
<li><a href="#h_898892470261529821002111">Search Analyses: joe-search</a></li>
<li><a href="#h_828752286601529821180424">Download a report: joe-download-report</a></li>
<li><a href="#h_875909818981529821491017">Download analysis file: joe-download-sample</a></li>
<li><a href="#h_4635149001851529821635082">Detonate a file: joe-detonate-file</a></li>
<li><a href="#h_6515981772361529821644621">Detonate a URL: joe-detonate-url</a></li>
</ol>
<h3 id="h_45220795871529576244617">Ping the server</h3>
<hr>
<p>Pings the Joe Security server to verify that it is responsive.</p>
<h5>Base Command</h5>
<p><code>joe-is-online</code></p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Data</h5>
<p>There is no context data for this command.</p>
<h5>Raw Output</h5>
<p>There is not raw output for this command.</p>
<h3 id="h_943521905421529576252174">Submit a URL for analysis</h3>
<hr>
<p>Submits a URL to Joe Security for analysis.</p>
<h5>Base Command</h5>
<p><code>joe-analysis-submit-url</code></p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 180px;"><strong>Required</strong></td>
<td style="width: 806px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">url</td>
<td style="width: 180px;">Required</td>
<td style="width: 806px;">URL to submit for analysis.</td>
</tr>
<tr>
<td style="width: 180px;">should_wait</td>
<td style="width: 180px;">Optional</td>
<td style="width: 806px;">Specifies if the command polls for the result of the analysis.</td>
</tr>
<tr>
<td style="width: 180px;">comments</td>
<td style="width: 180px;">Optional</td>
<td style="width: 806px;">Comments for the analysis.</td>
</tr>
<tr>
<td style="width: 180px;">Systems</td>
<td style="width: 180px;">Optional</td>
<td style="width: 806px;">
<p>Comma separated list of operating systems to run analysis on.</p>
<p>Valid values are:</p>
<ul>
<li>w7</li>
<li>w7x64</li>
<li>w7_1</li>
<li>w7_2</li>
<li>w7native</li>
<li>android2</li>
<li>android3</li>
<li>mac1</li>
<li>w7l</li>
<li>w7x64l</li>
<li>w10</li>
<li>android4</li>
<li>w7x64native</li>
<li>w7_3</li>
<li>w10native</li>
<li>android5native_1</li>
<li>w7_4</li>
<li>w7_5</li>
<li>w10x64</li>
<li>w7x64_hvm</li>
<li>android6</li>
<li>iphone1</li>
<li>w7_sec</li>
<li>macvm</li>
<li>w7_lang_packs</li>
<li>w7x64native_hvm</li>
<li>lnxubuntu1</li>
<li>lnxcentos1android7_nougat</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 180px;">internet-access</td>
<td style="width: 180px;">Optional</td>
<td style="width: 806px;">
<p>If to enable full internet access (boolean).</p>
<p>Default is <em>True.</em></p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="height: 306px; width: 660px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 156px;"><strong>Path</strong></td>
<td style="width: 166px;"><strong>Type</strong></td>
<td style="width: 494px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.WebID</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">Web ID</td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.FileName</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">Sample data, could be a file name or URL</td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.Status</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">Analysis status</td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.Comments</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">Analysis comments</td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.Time</td>
<td style="width: 166px;">Date</td>
<td style="width: 494px;">Time submitted</td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.Runs</td>
<td style="width: 166px;">Unknown</td>
<td style="width: 494px;">Sub-analysis information</td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.Result</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">Analysis results</td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.Errors</td>
<td style="width: 166px;">Unknown</td>
<td style="width: 494px;">Errors raised during sampling</td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.Systems</td>
<td style="width: 166px;">Unknown</td>
<td style="width: 494px;">Analysis operating system</td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.MD5</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">MD5 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.SHA1</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">SHA-1 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 156px;">Joe.Analysis.SHA256</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">SHA-256 has of the analysis sample</td>
</tr>
<tr>
<td style="width: 156px;">DBotScore.Vendor</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 156px;">DBotScore.Indicator</td>
<td style="width: 166px;">Unknown</td>
<td style="width: 494px;">The name of the sample file or URL</td>
</tr>
<tr>
<td style="width: 156px;">DBotScore.Type</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">
<p><em>url</em> - for URL samples</p>
<p><em>file </em>- for anything not URL sample</p>
</td>
</tr>
<tr>
<td style="width: 156px;">DBotScore.Score</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">
<p>Cortex XSOAR Dbot Score:</p>
<ul>
<li><em>Bad</em></li>
<li><em>Suspicious</em></li>
<li><em>Good</em></li>
</ul>
</td>
</tr>
<tr>
<td style="width: 156px;">DBotScore.Malicious.Vendor</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 156px;">DBotScore.Malicious.Detections</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">The sub analysis detection statuses</td>
</tr>
<tr>
<td style="width: 156px;">DBotScore.Malicious.SHA1</td>
<td style="width: 166px;">String</td>
<td style="width: 494px;">SHA-1 hash of the file</td>
</tr>
</tbody>
</table>
<h5>
<br>Raw Output</h5>
<p>There is no raw output for this command.</p>
<h3 id="h_980967680761529576288942">Get analysis information</h3>
<hr>
<p>Returns information for a specified analysis.</p>
<h5>Base Command</h5>
<p><code>joe-analysis-info</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 180px;"><strong>Required</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">webId</td>
<td style="width: 180px;">Required</td>
<td style="width: 565px;">Web ID. Supports comma-separated arrays.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="width: 732px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 197px;"><strong>Path</strong></th>
<th class="wysiwyg-text-align-left" style="width: 66px;"><strong>Type</strong></th>
<th class="wysiwyg-text-align-left" style="width: 435px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 197px;">Joe.Analysis.WebID</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">Web ID</td>
</tr>
<tr>
<td style="width: 197px;">Joe.Analysis.SampleName</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">Sample Data, could be a file name or URL</td>
</tr>
<tr>
<td style="width: 197px;">Joe.Analysis.Status</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">Analysis status</td>
</tr>
<tr>
<td style="width: 197px;">Joe.Analysis.Comments</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">Analysis comments</td>
</tr>
<tr>
<td style="width: 197px;">Joe.Analysis.Time</td>
<td style="width: 66px;">Date</td>
<td style="width: 435px;">Submitted time</td>
</tr>
<tr>
<td style="width: 197px;">Joe.Analysis.Runs</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 435px;">Sub-analysis information</td>
</tr>
<tr>
<td style="width: 197px;">Joe.Analysis.Result</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">Analysis results</td>
</tr>
<tr>
<td style="width: 197px;">Joe.Analysis.Errors</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 435px;">Errors raised during sampling</td>
</tr>
<tr>
<td style="width: 197px;">Joe.Analysis.Systems</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 435px;">Analysis operating system</td>
</tr>
<tr>
<td style="width: 197px;">Joe.Analysis.MD5</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">MD5 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 197px;">Joe.Analysis.SHA1</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">SHA-1 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 197px;">Joe.Analysis.SHA256</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">SHA-256 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 197px;">DBotScore.Vendor</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 197px;">DBotScore.Indicator</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 435px;">The name of the sample file or URL</td>
</tr>
<tr>
<td style="width: 197px;">DBotScore.Type</td>
<td style="width: 66px;">string</td>
<td style="width: 435px;">
<p><em>url</em> - for URL samples</p>
<p><em>file </em>- for anything not URL sample</p>
</td>
</tr>
<tr>
<td style="width: 197px;">DBotScore.Score</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">
<p>Cortex XSOAR Dbot Score:</p>
<ul>
<li><em>Bad</em></li>
<li><em>Suspicious</em></li>
<li><em>Good</em></li>
</ul>
</td>
</tr>
<tr>
<td style="width: 197px;">DBotScore.Malicious.Vendor</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 197px;">DBotScore.Malicious.Detections</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">The sub analysis detection statuses</td>
</tr>
<tr>
<td style="width: 197px;">DBotScore.Malicious.SHA1</td>
<td style="width: 66px;">String</td>
<td style="width: 435px;">The SHA-1 hash of the file</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>
<h3 id="h_1469370781091529576297072">Get analyses list</h3>
<hr>
<p>Returns a list of all analyses.</p>
<h5>Base Command</h5>
<p><code>joe-list-analysis</code></p>
<h5>Input</h5>
<p>There is no input for this command. </p>
<h5>Context Data</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 261px;"><strong>Path</strong></th>
<th class="wysiwyg-text-align-left" style="width: 83px;"><strong>Type</strong></th>
<th class="wysiwyg-text-align-left" style="width: 364px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 261px;">Joe.Analysis.WebID</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">Web ID</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.SampleName</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">Sample Data, could be a file name or URL</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Status</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">Analysis status</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Comments</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">Analysis comments</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Time</td>
<td style="width: 83px;">Date</td>
<td style="width: 364px;">Submitted time</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Runs</td>
<td style="width: 83px;">Unknown</td>
<td style="width: 364px;">Sub-analysis information</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Result</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">Analysis results</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Errors</td>
<td style="width: 83px;">Unknown</td>
<td style="width: 364px;">Errors raised during sampling</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Systems</td>
<td style="width: 83px;">Unknown</td>
<td style="width: 364px;">Analysis operating system</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.MD5</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">MD5 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.SHA1</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">SHA-1 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.SHA256</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">SHA-256 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Vendor</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Indicator</td>
<td style="width: 83px;">Unknown</td>
<td style="width: 364px;">The name of the sample file or URL</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Type</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">
<p><em>url</em> - for URL samples</p>
<p><em>file </em>- for anything not URL sample</p>
</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Score</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">
<p>Cortex XSOAR Dbot Score:</p>
<ul>
<li><em>Bad</em></li>
<li><em>Suspicious</em></li>
<li><em>Good</em></li>
</ul>
</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Malicious.Vendor</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Malicious.Detections</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">The sub analysis detection statuses</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Malicious.SHA1</td>
<td style="width: 83px;">String</td>
<td style="width: 364px;">The SHA-1 hash of the file</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>
<h3 id="h_9039961881411529576308915">Submit sample for analysis</h3>
<hr>
<p>Submits a sample to Joe Security for analysis.</p>
<h5>Base Command</h5>
<p><code>joe-analysis-submit-sample</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 117px;"><strong>Parameter</strong></th>
<th class="wysiwyg-text-align-left" style="width: 85px;"><strong>Required</strong></th>
<th class="wysiwyg-text-align-left" style="width: 506px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 117px;">file_id</td>
<td style="width: 85px;">Optional</td>
<td style="width: 506px;">War Room entry of a file (for example, 3245@4).</td>
</tr>
<tr>
<td style="width: 117px;">sample_url</td>
<td style="width: 85px;">Optional</td>
<td style="width: 506px;">URL of a sample file. Supports comma-seperated arrays.</td>
</tr>
<tr>
<td style="width: 117px;">should_wait</td>
<td style="width: 85px;">Optional</td>
<td style="width: 506px;">Specifies if the command polls for the result of the analysis</td>
</tr>
<tr>
<td style="width: 117px;">comments</td>
<td style="width: 85px;">Optional</td>
<td style="width: 506px;">Comments for the analysis</td>
</tr>
<tr>
<td style="width: 117px;">systems</td>
<td style="width: 85px;">Optional</td>
<td style="width: 506px;">
<p>Comma separated list of operating systems to run analysis on.</p>
<p>Valid values are:</p>
<ul>
<li>w7</li>
<li>w7x64</li>
<li>w7_1</li>
<li>w7_2</li>
<li>w7native</li>
<li>android2</li>
<li>android3</li>
<li>mac1</li>
<li>w7l</li>
<li>w7x64l</li>
<li>w10</li>
<li>android4</li>
<li>w7x64native</li>
<li>w7_3</li>
<li>w10native</li>
<li>android5native_1</li>
<li>w7_4</li>
<li>w7_5</li>
<li>w10x64</li>
<li>w7x64_hvm</li>
<li>android6</li>
<li>iphone1</li>
<li>w7_sec</li>
<li>macvm</li>
<li>w7_lang_packs</li>
<li>w7x64native_hvm</li>
<li>lnxubuntu1</li>
<li>lnxcentos1</li>
<li>android7_nougat</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 117px;">internet-access</td>
<td style="width: 85px;">Optional</td>
<td style="width: 506px;">Enable full internet access. Default is True.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 261px;"><strong>Path</strong></th>
<th class="wysiwyg-text-align-left" style="width: 90px;"><strong>Type</strong></th>
<th class="wysiwyg-text-align-left" style="width: 357px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 261px;">Joe.Analysis.WebID</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">Web ID</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.SampleName</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">Sample data, could be a file name or URL</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Status</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">Analysis status</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Comments</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">Analysis comments</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Time</td>
<td style="width: 90px;">Date</td>
<td style="width: 357px;">Submitted time</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Runs</td>
<td style="width: 90px;">Unknown</td>
<td style="width: 357px;">Sub-analysis information</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Result</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">Analysis results</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Errors</td>
<td style="width: 90px;">Unknown</td>
<td style="width: 357px;">Errors raised during sampling</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.Systems</td>
<td style="width: 90px;">Unknown</td>
<td style="width: 357px;">Analysis operating system</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.MD5</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">MD5 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.SHA1</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">SHA-1 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 261px;">Joe.Analysis.SHA256</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">SHA-256 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Vendor</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Indicator</td>
<td style="width: 90px;">Unknown</td>
<td style="width: 357px;">The name of the sample file or URL</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Type</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">
<p><em>url</em> - for URL samples</p>
<p><em>file </em>- for anything not URL sample</p>
</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Score</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">
<p>Cortex XSOAR Dbot Score:</p>
<ul>
<li><em>Bad</em></li>
<li><em>Suspicious</em></li>
<li><em>Good</em></li>
</ul>
</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Malicious.Vendor</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Malicious.Detections</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">The sub analysis detection statuses</td>
</tr>
<tr>
<td style="width: 261px;">DBotScore.Malicious.SHA1</td>
<td style="width: 90px;">String</td>
<td style="width: 357px;">The SHA-1 hash of the file</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>
<h3 id="h_898892470261529821002111">Search Analyses</h3>
<hr>
<p>Search through all analyses in Joe Security.</p>
<h5>Base Command</h5>
<p><code>joe-search</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 104px;"><strong>Parameter</strong></td>
<td style="width: 641px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 104px;">query</td>
<td style="width: 641px;">
<p>String to search for in these fields:</p>
<ul>
<li>webID</li>
<li>MD5</li>
<li>SHA1</li>
<li>SHA256</li>
<li>filename</li>
<li>URL</li>
<li>comments</li>
</ul>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 235px;"><strong>Path</strong></th>
<th class="wysiwyg-text-align-left" style="width: 102px;"><strong>Type</strong></th>
<th class="wysiwyg-text-align-left" style="width: 371px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 235px;">Joe.Analysis.WebID</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">Web ID</td>
</tr>
<tr>
<td style="width: 235px;">Joe.Analysis.SampleName</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">Sample data, could be a file name or URL</td>
</tr>
<tr>
<td style="width: 235px;">Joe.Analysis.Status</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">Analysis status</td>
</tr>
<tr>
<td style="width: 235px;">Joe.Analysis.Comments</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">Analysis comments</td>
</tr>
<tr>
<td style="width: 235px;">Joe.Analysis.Time</td>
<td style="width: 102px;">Date</td>
<td style="width: 371px;">Submitted time</td>
</tr>
<tr>
<td style="width: 235px;">Joe.Analysis.Runs</td>
<td style="width: 102px;">Unknown</td>
<td style="width: 371px;">Sub-analysis information</td>
</tr>
<tr>
<td style="width: 235px;">Joe.Analysis.Result</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">Analysis results</td>
</tr>
<tr>
<td style="width: 235px;">Joe.Analysis.Errors</td>
<td style="width: 102px;">Unknown</td>
<td style="width: 371px;">Errors raised during sampling</td>
</tr>
<tr>
<td style="width: 235px;">Joe.Analysis.Systems</td>
<td style="width: 102px;">Unknown</td>
<td style="width: 371px;">Analysis operating system</td>
</tr>
<tr>
<td style="width: 235px;">Joe.Analysis.MD5</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">MD5 has of the analysis sample</td>
</tr>
<tr>
<td style="width: 235px;">Joe.Analysis.SHA1</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">SHA-1 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 235px;">Joe.Analysis.SHA256</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">SHA-256 has of the analysis sample</td>
</tr>
<tr>
<td style="width: 235px;">DBotScore.Vendor</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 235px;">DBotScore.Indicator</td>
<td style="width: 102px;">Unknown</td>
<td style="width: 371px;">The name of the sample file or URL</td>
</tr>
<tr>
<td style="width: 235px;">DBotScore.Type</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">
<p><em>url</em> - for URL samples</p>
<p><em>file </em>- for anything not URL sample</p>
</td>
</tr>
<tr>
<td style="width: 235px;">DBotScore.Score</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">
<p>Cortex XSOAR Dbot Score:</p>
<ul>
<li><em>Bad</em></li>
<li><em>Suspicious</em></li>
<li><em>Good</em></li>
</ul>
</td>
</tr>
<tr>
<td style="width: 235px;">DBotScore.Malicious.Vendor</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 235px;">DBotScore.Malicious.Detections</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">The sub analysis detection statuses</td>
</tr>
<tr>
<td style="width: 235px;">DBotScore.Malicious.SHA1</td>
<td style="width: 102px;">String</td>
<td style="width: 371px;">The SHA-1 hash of the file</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>
<h3 id="h_828752286601529821180424">Download a report</h3>
<hr>
<p>Downloads a resource associated to a report. This can be the full report, dropped binaries, and so on. Click <a href="https://jbxcloud.joesecurity.org/userguide?sphinxurl=usage/webapi.html#v2-analysis-download"> here </a> to see the full report types list.</p>
<h5>Base Command</h5>
<p><code>joe-download-report</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 166px;"><strong>Parameter</strong></td>
<td style="width: 174px;"><strong>Required</strong></td>
<td style="width: 585px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 166px;">webid</td>
<td style="width: 174px;">Required</td>
<td style="width: 585px;">
<p>Web ID</p>
</td>
</tr>
<tr>
<td style="width: 166px;">type</td>
<td style="width: 174px;">Optional</td>
<td style="width: 585px;">
<p>Resource type to download, default is <em>html</em></p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 147px;"><strong>Path</strong></th>
<th class="wysiwyg-text-align-left" style="width: 106px;"><strong>Type</strong></th>
<th class="wysiwyg-text-align-left" style="width: 455px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">InfoFile.Name</td>
<td style="width: 106px;">String</td>
<td style="width: 455px;">Name of the file</td>
</tr>
<tr>
<td style="width: 147px;">InfoFile.EntryID</td>
<td style="width: 106px;">String</td>
<td style="width: 455px;">The entry ID of the sample</td>
</tr>
<tr>
<td style="width: 147px;">InfoFile.Size</td>
<td style="width: 106px;">Number</td>
<td style="width: 455px;">The size of the file</td>
</tr>
<tr>
<td style="width: 147px;">InfoFile.Type</td>
<td style="width: 106px;">String</td>
<td style="width: 455px;">File type (for example, <em>PE</em>)</td>
</tr>
<tr>
<td style="width: 147px;">InfoFile.Info</td>
<td style="width: 106px;">String</td>
<td style="width: 455px;">Basic information about the file</td>
</tr>
<tr>
<td style="width: 147px;">File.Extension</td>
<td style="width: 106px;">String</td>
<td style="width: 455px;">File extension</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>
<h3 id="h_875909818981529821491017">Download analysis file</h3>
<hr>
<p>Downloads the sample file of an analysis. For security considerations, the extension is <em>dontrun</em>.</p>
<h5>Base Command</h5>
<p><code>joe-download-sample</code></p>
<h5>Input</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 159px;"><strong>Parameter</strong></td>
<td style="width: 163px;"><strong>Required</strong></td>
<td style="width: 603px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 159px;">webid</td>
<td style="width: 163px;">Required</td>
<td style="width: 603px;">
<p>Web ID</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 123px;"><strong>Path</strong></th>
<th class="wysiwyg-text-align-left" style="width: 104px;"><strong>Type</strong></th>
<th class="wysiwyg-text-align-left" style="width: 481px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 123px;">File.Size</td>
<td style="width: 104px;">Number</td>
<td style="width: 481px;">The size of the file</td>
</tr>
<tr>
<td style="width: 123px;">File.SHA1</td>
<td style="width: 104px;">String</td>
<td style="width: 481px;">SHA-1 hash of the file</td>
</tr>
<tr>
<td style="width: 123px;">File.SHA256</td>
<td style="width: 104px;">String</td>
<td style="width: 481px;">SHA-256 hash of the file</td>
</tr>
<tr>
<td style="width: 123px;">File.Name</td>
<td style="width: 104px;">String</td>
<td style="width: 481px;">The sample name</td>
</tr>
<tr>
<td style="width: 123px;">File.SSDeep</td>
<td style="width: 104px;">String</td>
<td style="width: 481px;">ssdeep hash of the file</td>
</tr>
<tr>
<td style="width: 123px;">File.EntryID</td>
<td style="width: 104px;">String</td>
<td style="width: 481px;">War room entry ID of the file</td>
</tr>
<tr>
<td style="width: 123px;">File.Info</td>
<td style="width: 104px;">String</td>
<td style="width: 481px;">Basic information of the file</td>
</tr>
<tr>
<td style="width: 123px;">File.Type</td>
<td style="width: 104px;">String</td>
<td style="width: 481px;">File type (for example <em>PE</em>)</td>
</tr>
<tr>
<td style="width: 123px;">File MD5</td>
<td style="width: 104px;">String</td>
<td style="width: 481px;">MD5 hash of the file</td>
</tr>
<tr>
<td style="width: 123px;">File.Extension</td>
<td style="width: 104px;">String</td>
<td style="width: 481px;">File extension</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>
<h3 id="h_4635149001851529821635082">Detonate a file</h3>
<hr>
<p>Submits a file for analysis.</p>
<h5>Base Command</h5>
<p><code>joe-detonate-file</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 117px;"><strong>Parameter</strong></th>
<th class="wysiwyg-text-align-left" style="width: 81px;"><strong>Required</strong></th>
<th class="wysiwyg-text-align-left" style="width: 510px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 117px;">file_id</td>
<td style="width: 81px;">Optional</td>
<td style="width: 510px;">War room entry of a file (for example, 3245@4)</td>
</tr>
<tr>
<td style="width: 117px;">sample_url</td>
<td style="width: 81px;">Optional</td>
<td style="width: 510px;">URL of a sample file</td>
</tr>
<tr>
<td style="width: 117px;">comments</td>
<td style="width: 81px;">Optional</td>
<td style="width: 510px;">Comments for the analysis</td>
</tr>
<tr>
<td style="width: 117px;">systems</td>
<td style="width: 81px;">Optional</td>
<td style="width: 510px;">
<p>Comma separated list of operating systems to run the analysis on.</p>
<p>Valid values are:</p>
<ul>
<li>w7</li>
<li>w7x64</li>
<li>w7_1</li>
<li>w7_2</li>
<li>w7native</li>
<li>android2</li>
<li>android3</li>
<li>mac1</li>
<li>w7l</li>
<li>w7x64l</li>
<li>w10</li>
<li>android4</li>
<li>w7x64native</li>
<li>w7_3</li>
<li>w10native</li>
<li>android5native_1</li>
<li>w7_4</li>
<li>w7_5</li>
<li>w10x64</li>
<li>w7x64_hvm</li>
<li>android6</li>
<li>iphone1</li>
<li>w7_sec</li>
<li>macvm</li>
<li>w7_lang_packs</li>
<li>w7x64native_hvm</li>
<li>lnxubuntu1</li>
<li>lnxcentos1</li>
<li>android7_nougat</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 117px;">internet-access</td>
<td style="width: 81px;">Optional</td>
<td style="width: 510px;">If to enable full internet access. Default is True</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Context Data</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 260px;"><strong>Path</strong></th>
<th class="wysiwyg-text-align-left" style="width: 88px;"><strong>Type</strong></th>
<th class="wysiwyg-text-align-left" style="width: 360px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 260px;">Joe.Analysis.WebID</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">Web ID</td>
</tr>
<tr>
<td style="width: 260px;">Joe.Analysis.SampleName</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">Sample Data, could be a file name or URL</td>
</tr>
<tr>
<td style="width: 260px;">Joe.Analysis.Status</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">Analysis status</td>
</tr>
<tr>
<td style="width: 260px;">Joe.Analysis.Comments</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">Analysis comments</td>
</tr>
<tr>
<td style="width: 260px;">Joe.Analysis.Time</td>
<td style="width: 88px;">Date</td>
<td style="width: 360px;">Submission time</td>
</tr>
<tr>
<td style="width: 260px;">Joe.Analysis.Runs</td>
<td style="width: 88px;">Unknown</td>
<td style="width: 360px;">Sub-analysis information</td>
</tr>
<tr>
<td style="width: 260px;">Joe.Analysis.Result</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">Analysis results</td>
</tr>
<tr>
<td style="width: 260px;">Joe.Analysis.Errors</td>
<td style="width: 88px;">Unknown</td>
<td style="width: 360px;">Errors raised during sampling</td>
</tr>
<tr>
<td style="width: 260px;">Joe.Analysis.Systems</td>
<td style="width: 88px;">Unknown</td>
<td style="width: 360px;">Analysis operating system</td>
</tr>
<tr>
<td style="width: 260px;">Joe.Analysis.MD5</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">MD5 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 260px;">Joe.Analysis.SHA1</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">SHA-1 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 260px;">Joe.Analysis.SHA256</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">SHA-256 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 260px;">DBotScore.Vendor</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 260px;">DBotScore.Indicator</td>
<td style="width: 88px;">Unknown</td>
<td style="width: 360px;">The name of the sample file or URL</td>
</tr>
<tr>
<td style="width: 260px;">DBotScore.Type</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">
<p><em>url</em> - for URL samples</p>
<p><em>file </em>- for anything not URL sample</p>
</td>
</tr>
<tr>
<td style="width: 260px;">DBotScore.Score</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">
<p>Cortex XSOAR Dbot Score:</p>
<ul>
<li><em>Bad</em></li>
<li><em>Suspicious</em></li>
<li><em>Good</em></li>
</ul>
</td>
</tr>
<tr>
<td style="width: 260px;">DBotScore.Malicious.Vendor</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 260px;">DBotScore.Malicious.Detections</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">The sub analysis detection statuses</td>
</tr>
<tr>
<td style="width: 260px;">DBotScore.Malicious.SHA1</td>
<td style="width: 88px;">String</td>
<td style="width: 360px;">The SHA-1 has of the file</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>
<h3 id="h_6515981772361529821644621">Detonate a URL</h3>
<hr>
<p>Submits a URL for analysis.</p>
<h5>Base Command</h5>
<p><code>joe-detonate-url</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 116px;"><strong>Parameter</strong></th>
<th class="wysiwyg-text-align-left" style="width: 80px;"><strong>Required</strong></th>
<th class="wysiwyg-text-align-left" style="width: 512px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 116px;">url</td>
<td style="width: 80px;">Required</td>
<td style="width: 512px;">sample URL</td>
</tr>
<tr>
<td style="width: 116px;">comments</td>
<td style="width: 80px;">Optional</td>
<td style="width: 512px;">Comments for the analysis</td>
</tr>
<tr>
<td style="width: 116px;">systems</td>
<td style="width: 80px;">Optional</td>
<td style="width: 512px;">
<p>Comma separated list of operating systems to run the analysis on.</p>
<p>Valid values are:</p>
<ul>
<li>w7</li>
<li>w7x64</li>
<li>w7_1</li>
<li>w7_2</li>
<li>w7native</li>
<li>android2</li>
<li>android3</li>
<li>mac1</li>
<li>w7l</li>
<li>w7x64l</li>
<li>w10</li>
<li>android4</li>
<li>w7x64native</li>
<li>w7_3</li>
<li>w10native</li>
<li>android5native_1</li>
<li>w7_4</li>
<li>w7_5</li>
<li>w10x64</li>
<li>w7x64_hvm</li>
<li>android6</li>
<li>iphone1</li>
<li>w7_sec</li>
<li>macvm</li>
<li>w7_lang_packs</li>
<li>w7x64native_hvm</li>
<li>lnxubuntu1</li>
<li>lnxcentos1</li>
<li>android7_nougat</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 116px;">internet-access</td>
<td style="width: 80px;">Optional</td>
<td style="width: 512px;">If to enable full internet access. Default is True.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 210px;"><strong>Path</strong></th>
<th class="wysiwyg-text-align-left" style="width: 100px;"><strong>Type</strong></th>
<th class="wysiwyg-text-align-left" style="width: 398px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 210px;">Joe.Analysis.WebID</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">Web ID</td>
</tr>
<tr>
<td style="width: 210px;">Joe.Analysis.SampleName</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">Sample data, could be a file name or URL</td>
</tr>
<tr>
<td style="width: 210px;">Joe.Analysis.Status</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">Analysis status</td>
</tr>
<tr>
<td style="width: 210px;">Joe.Analysis.Comments</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">Analysis comments</td>
</tr>
<tr>
<td style="width: 210px;">Joe.Analysis.Time</td>
<td style="width: 100px;">Date</td>
<td style="width: 398px;">Submission time</td>
</tr>
<tr>
<td style="width: 210px;">Joe.Analysis.Runs</td>
<td style="width: 100px;">Unknown</td>
<td style="width: 398px;">Sub-analysis information</td>
</tr>
<tr>
<td style="width: 210px;">Joe.Analysis.Result</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">Analysis results</td>
</tr>
<tr>
<td style="width: 210px;">Joe.Analysis.Errors</td>
<td style="width: 100px;">Unknown</td>
<td style="width: 398px;">Errors raised during sampling</td>
</tr>
<tr>
<td style="width: 210px;">Joe.Analysis.Systems</td>
<td style="width: 100px;">Unknown</td>
<td style="width: 398px;">Analysis operating system</td>
</tr>
<tr>
<td style="width: 210px;">Joe.Analysis.MD5</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">MD5 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 210px;">Joe.Analysis.SHA1</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">SHA-1 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 210px;">Joe.Analysis.SHA256</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">SHA-256 hash of the analysis sample</td>
</tr>
<tr>
<td style="width: 210px;">DBotScore.Vendor</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 210px;">DBotScore.Indicator</td>
<td style="width: 100px;">Unknown</td>
<td style="width: 398px;">The name of the sample file or URL</td>
</tr>
<tr>
<td style="width: 210px;">DBotScore.Type</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">
<p><em>url</em> - for URL samples</p>
<p><em>file </em>- for anything not URL sample</p>
</td>
</tr>
<tr>
<td style="width: 210px;">DBotScore.Score</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">
<p>Cortex XSOAR Dbot Score:</p>
<ul>
<li><em>Bad</em></li>
<li><em>Suspicious</em></li>
<li><em>Good</em></li>
</ul>
</td>
</tr>
<tr>
<td style="width: 210px;">DBotScore.Malicious.Vendor</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">The name of the vendor (JoeSecurity)</td>
</tr>
<tr>
<td style="width: 210px;">DBotScore.Malicious.Detections</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">The sub analysis detection statuses</td>
</tr>
<tr>
<td style="width: 210px;">DBotScore.Malicious.SHA1</td>
<td style="width: 100px;">String</td>
<td style="width: 398px;">The SHA-1 hash of the file</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>