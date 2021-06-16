<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the AlphaSOC Wisdom domain enrichment and threat intelligence plugin for Cortex XSOAR to retrieve flags from the AlphaSOC threat intelligence service. Once installed, you can use Cortex XSOAR commands to retrieve category and feature data (known as flags) from AlphaSOC to enrich data within Cortex XSOAR and guide runbooks (e.g. flagging a known C2 domain, phishing destination, a domain associated with unwanted programs, or a benign domain that is trusted by AlphaSOC).</p>
<p> </p>
<hr>
<h2>Prerequisites</h2>
<p>This integration requires an AlphaSOC API key. Navigate to <a href="https://alphasoc.com/wisdom/">https://alphasoc.com/wisdom/</a> to generate the API key. You can use the key for 30 days to evaluate the integration and additional context that AlphaSOC provides.</p>
<p>If you run into any problems using the integration, or wish to discuss licensing and API use beyond the 30 day evaluation period for the AlphaSOC Wisdom service, contact the <a href="mailto:support@alphasoc.com" target="_blank" rel="noopener">AlphaSOC support team</a>.</p>
<hr>
<h2>Configure the AlphaSOC integration on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for AlphaSOC Wisdom.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong><font style="vertical-align: inherit;">AlphaSOC API key</font></strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the connection and API key.</li>
</ol>
<hr>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_422050772161529842440330">Return a list of flags assigned to a domain: wisdom-domain-flags</a></li>
<li><a href="#h_254254248331529856911360">Return a list of flags assigned to an IP connection: wisdom-ip-flags</a></li>
</ol>
<hr>
<h3 id="h_422050772161529842440330">Return a list of flags assigned to a domain</h3>
<p>Returns a list of flags (categories and features) assigned to a domain by AlphaSOC Threat Intelligence.</p>
<h5>Base Command</h5>
<p><code>wisdom-domain-flags</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">domain</td>
<td style="width: 460px;">Internet domain or URL</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="height: 306px; width: 664px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 182px;"><strong>Path</strong></td>
<td style="width: 457px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 182px;">Domain.Name</td>
<td style="width: 457px;">Fully-qualified domain name (FDQN)</td>
</tr>
<tr>
<td style="width: 182px;">Wisdom.Flag</td>
<td style="width: 457px;">AlphaSOC security category or feature</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Examples</h5>
<ul>
<li><code>!wisdom-domain-flags	domain=microsoft775.com</code></li>
<li><code>!wisdom-domain-flags	domain=c0i8h8ac7e.bid</code></li>
<li><code>!wisdom-domain-flags	domain=service.downloadadmin.com</code></li>
<li><code>!wisdom-domain-flags	domain=luoxk.f3322.net</code></li>
</ul>
<h5>Raw Output</h5>
<pre>{  
   "flags":[  
      "c2"
   ]
}</pre>
<h5>Context Example</h5>
<pre>{  
   Wisdom:{  
      "flags":[  
         "c2"
      ]
   }
}</pre>
<hr>
<h3 id="h_254254248331529856911360">Return a list of flags assigned to an IP connection</h3>
<p>Returns a list of flags (categories and features) assigned to an IP connection (Defined by protocol, destination address, and port number) by AlphaSOC Threat Intelligence.</p>
<h5>Base Command</h5>
<p><code>wisdom-ip-flags</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">proto</td>
<td style="width: 460px;">
<p>Transport layer protocol</p>
<ul>
<li>TCP</li>
<li>UDP</li>
<li>ICMP</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 180px;">ip</td>
<td style="width: 460px;">Internet-based IPv4 or IPv6 address</td>
</tr>
<tr>
<td style="width: 180px;">port</td>
<td style="width: 460px;">Destination port</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="height: 306px; width: 664px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 182px;"><strong>Path</strong></td>
<td style="width: 457px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 182px;">Wisdom.Flag</td>
<td style="width: 457px;">AlphaSOC security category or feature</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Examples</h5>
<ul>
<li><code>!wisdom-ip-flags	proto=tcp	ip=182.176.178.74 port=1604</code></li>
<li><code>!wisdom-ip-flags	proto=tcp	ip=95.181.249.58 port=443</code></li>
</ul>
<h5>Raw Output</h5>
<pre>{  
   "flags":[  
      "tor"
   ]
}</pre>
<h5>Context Example</h5>
<pre>{  
   Wisdom:{  
      "flags":[  
         "tor"
      ]
   }
}</pre>