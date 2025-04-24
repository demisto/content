<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the TitaniumCloud Integration Malware Analysis Platform to increase detection, analysis and response efficiency by identifying files with global goodware and malware database. It is a powerful threat intelligence solution with up-to-date, threat classification and rich context on over 6B goodware and malware files.</p>
<p>This integration was integrated and tested with ReversingLabs TitaniumCloud™.</p>
<hr>
<h2>Use Cases</h2>
<ul>
<li>Provide a file reputation status for a file to prepare for emerging threats by monitoring malware.</li>
</ul>
<hr>
<h2>Prerequisites</h2>
<p>You need to obtain the following ReversingLabs TitaniumCloud information.</p>
<ul>
<li>
<strong>Base URL for malware presence</strong> :
<ul>
<li>Preconfigured on Cortex XSOAR - https://ticloud-aws1-api.reversinglabs.com
</li>
</ul>
</li>
<li>
<strong>Base URL for extended RL Data</strong> :
<ul>
<li>Preconfigured on Cortex XSOAR - https://ticloud-cdn-api.reversinglabs.com
</li>
</ul>
</li>
<li>
<strong>Credentials for ReversingLabs TitaniumCloud</strong>
<ul>
<li>UserName</li>
<li>Password</li>
</ul>
</li>
</ul>
<hr>
<h2>Configure ReversingLabs Titanium Cloud on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for ReversingLabs Titanium Cloud.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a meaningful name for the integration instance.</li>
<li>
<strong>Base URL for malware presence </strong>: https://ticloud-aws1-api.reversinglabs.com
</li>
<li>
<strong>Base URL for extended RL Data</strong> : https://ticloud-cdn-api.reversinglabs.com
</li>
<li>
<strong>Credentials and Password</strong>: paste the username and password for your TitaniumCloud account.</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>
</ol>
<hr>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ul>
<li>Retrieve malware presence status of a sample: file</li>
</ul>
<h3>Retrieve malware presence status of a sample: file</h3>
<p>Get the ReversingLabs malware presence status for a file. This service supports single has queries and the option to return additional response data. The ReversingLabs Malware Statuses are:</p>
<ul>
<li>Malicious</li>
<li>Suspicious</li>
<li>Known</li>
<li>Unknown</li>
</ul>
<h4>Command Example</h4>
<p><code>!file file="c4ab31a0e6bee10933367e74b8af630daed5bd5e" extended="true"</code></p>
<h4>Input</h4>
<table style="height: 69px; width: 657px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 139px;"><strong>Parameter</strong></td>
<td style="width: 402px;"><strong>Description</strong></td>
<td class="wysiwyg-text-align-center" style="width: 111px;"><strong>Required?</strong></td>
</tr>
<tr>
<td style="width: 139px;">file</td>
<td style="width: 402px;">The hash that you want to get reputation data for. Hexadecimal representation of SHA-1, SHA-256, SHA-512, or MD5 digest.</td>
<td class="wysiwyg-text-align-center" style="width: 111px;">required</td>
</tr>
<tr>
<td style="width: 139px;">extended</td>
<td style="width: 402px;">Directs the data browser to return richer response schema, with additional classifications and facts about the queried sample. If you do not specify this parameter in the command, the default is <em>false</em>.</td>
<td class="wysiwyg-text-align-center" style="width: 111px;">optional</td>
</tr>
</tbody>
</table>
<h4> </h4>
<h4>Human Readable Output (extended = false)</h4>
<p><img src="../../doc_files/integration-ReversingLabs_Titanium_Cloud_mceclip0.png"></p>
<h4>Human Readable Output (extended = true)</h4>
<p><img src="../../doc_files/integration-ReversingLabs_Titanium_Cloud_mceclip1.png"></p>
<h4> </h4>
<h4>Context Output</h4>
<table width="624">
<tbody>
<tr>
<td width="247">
<p><strong>Parameter</strong></p>
</td>
<td width="377">
<p><strong>Description</strong></p>
</td>
</tr>
<tr>
<td width="247">
<p>File.MD5</p>
</td>
<td width="377">
<p>Bad hash detected.</p>
</td>
</tr>
<tr>
<td width="247">
<p>File.SHA1</p>
</td>
<td width="377">
<p>Bad hash SHA-1.</p>
</td>
</tr>
<tr>
<td width="247">
<p>File.Malicious.Vendor</p>
</td>
<td width="377">
<p>For malicious files, the vendor that made the decision.</p>
</td>
</tr>
<tr>
<td width="247">
<p>File.Malicious.Detections</p>
</td>
<td width="377">
<p>For malicious files, the total number of detections.</p>
</td>
</tr>
<tr>
<td width="247">
<p>File.Malicious.TotalEngines</p>
</td>
<td width="377">
<p>For malicious files, the total number of engines.</p>
</td>
</tr>
<tr>
<td width="247">
<p>DBotScore.Indicator</p>
</td>
<td width="377">
<p>The indicator that is being tested.</p>
</td>
</tr>
<tr>
<td width="247">
<p>DBotScore.Type</p>
</td>
<td width="377">
<p>Indicator type.</p>
</td>
</tr>
<tr>
<td width="247">
<p>DBotScore.Vendor</p>
</td>
<td width="377">
<p>Vendor used to calculate the score.</p>
</td>
</tr>
<tr>
<td width="247">
<p>DBotScore.Score</p>
</td>
<td width="377">
<p>The actual score.</p>
</td>
</tr>
</tbody>
</table>
<h4> </h4>
<h4>Raw Output</h4>
<section class="results">
<div class="results">
<div class="result container-result-2" data-json='{
   "malware_presence":{
      "first_seen":"2018-05-28T03:15:44",
      "last_seen":"2018-05-28T03:19:00",
      "query_hash":{
         sha1:c4ab31a0e6bee10933367e74b8af630daed5bd5e
      },
      "scanner_count":45,
      "scanner_match":2,
      "scanner_percent":4.44444465637207,
      "status":"KNOWN",
      "threat_level":0,
      "trust_factor":5,

   }
}'>
<div class="container">
<div class="row">
<div class="col-lg-10 col-lg-offset-1">
<div class="bottom collapseable">
<div class="jsonholder ui-resizable">
<div class="json" tabindex="-1"> </div>
<div class="json" tabindex="-1">
<section class="results">
<div class="results">
<div class="result container-result-3" data-json='"rl":{
   "malware_presence":{
      "first_seen":"2018-05-28T03:15:44",
      "last_seen":"2018-05-28T03:19:00",
      "query_hash":{
         sha1:c4ab31a0e6bee10933367e74b8af630daed5bd5e
      },
      "scanner_count":45,
      "scanner_match":2,
      "scanner_percent":4.44444465637207,
      "status":"KNOWN",
      "threat_level":0,
      "trust_factor":5,

   }
}'>
<div class="container">
<div class="row">
<div class="col-lg-10 col-lg-offset-1">
<div class="bottom collapseable">
<div class="jsonholder ui-resizable">
<div class="json" tabindex="-1">
<span id="s-3" class="sBrace structure-1">{  </span><br>   <span id="s-4" class="sObjectK">"malware_presence"</span><span id="s-5" class="sColon">:</span><span id="s-6" class="sBrace structure-2">{  </span><br>      <span id="s-7" class="sObjectK">"first_seen"</span><span id="s-8" class="sColon">:</span><span id="s-9" class="sObjectV">"2018-05-28T03:15:44"</span><span id="s-10" class="sComma">,</span><br>      <span id="s-11" class="sObjectK">"last_seen"</span><span id="s-12" class="sColon">:</span><span id="s-13" class="sObjectV">"2018-05-28T03:19:00"</span><span id="s-14" class="sComma">,</span><br>      <span id="s-15" class="sObjectK">"query_hash"</span><span id="s-16" class="sColon">:</span><span id="s-17" class="sBrace structure-3">{  </span><br>         <span id="s-18" class="sObjectK"><span class="error">sha1</span></span><span id="s-19" class="sColon">:</span><span id="s-20" class="sObjectV"><span class="error">c4ab31a0e6bee10933367e74b8af630daed5bd5e</span></span><br>      <span id="s-21" class="sBrace structure-3">}</span><span id="s-22" class="sComma">,</span><br>      <span id="s-23" class="sObjectK">"scanner_count"</span><span id="s-24" class="sColon">:</span><span id="s-25" class="sObjectV">45</span><span id="s-26" class="sComma">,</span><br>      <span id="s-27" class="sObjectK">"scanner_match"</span><span id="s-28" class="sColon">:</span><span id="s-29" class="sObjectV">2</span><span id="s-30" class="sComma">,</span><br>      <span id="s-31" class="sObjectK">"scanner_percent"</span><span id="s-32" class="sColon">:</span><span id="s-33" class="sObjectV">4.44444465637207</span><span id="s-34" class="sComma">,</span><br>      <span id="s-35" class="sObjectK">"status"</span><span id="s-36" class="sColon">:</span><span id="s-37" class="sObjectV">"KNOWN"</span><span id="s-38" class="sComma">,</span><br>      <span id="s-39" class="sObjectK">"threat_level"</span><span id="s-40" class="sColon">:</span><span id="s-41" class="sObjectV">0</span><span id="s-42" class="sComma">,</span><br>      <span id="s-43" class="sObjectK">"trust_factor"</span><span id="s-44" class="sColon">:</span><span id="s-45" class="sObjectV">5</span><span id="s-46" class="sComma"><span class="error">,</span></span><br><br>   <span id="s-47" class="sBrace structure-2"><span class="error">}</span></span><br><span id="s-48" class="sBrace structure-1">}</span>
</div>
</div>
</div>
</div>
</div>
</div>
</div>
</div>
</section>
</div>
</div>
</div>
</div>
</div>
</div>
</div>
</div>
</section>
