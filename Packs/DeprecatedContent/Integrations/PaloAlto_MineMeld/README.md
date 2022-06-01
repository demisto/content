<!-- HTML_DOC -->
<p>Use the Palo Alto Networks MineMeld integration to manage your MineMeld miners from within Cortex XSOAR. All commands require the <code>super admin</code> role.</p>
<h2>Use Cases</h2>
<ul>
<li>Add or remove indicators from a miner.</li>
<li>Fetch miners, IP addresses, files, domains, and URLs.</li>
<li>Get a list of all your miners.</li>
</ul>
<p><strong>NOTE</strong>: Indicators on an allow list get a DBot score of 1. Indicators on a block list get a DBot score of 3.</p>
<h2>Supported Miner Prototypes</h2>
<ul>
<li>localDB</li>
<li>listURLGeneric</li>
<li>listIPv4Generic</li>
<li>listDomainGeneric</li>
<li>listIPv6Generic</li>
</ul>
<h2>Configure Palo Alto Networks MineMeld on Cortex XSOAR:</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Palo Alto Networks MineMeld.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: A textual name for the integration instance.</li>
<li><strong> <font style="vertical-align: inherit;">Mine</font> </strong></li>
<li>
<strong> <font style="vertical-align: inherit;">meld URL</font> </strong> <font style="vertical-align: inherit;">: The URL of your MineMeld environment.</font>
</li>
<li>
<strong> <font style="vertical-align: inherit;">Username &amp;</font> <font style="vertical-align: inherit;"> Password</font> </strong> <font style="vertical-align: inherit;">: Your credentials in the MineMeld environment.</font>
</li>
<li>
<strong> <font style="vertical-align: inherit;">Block list names</font> </strong> <font style="vertical-align: inherit;">:</font> <font style="vertical-align: inherit;"> Comma separated list of miners, to be added to the Cortex XSOAR block list. </font>
</li>
<li>
<strong> <font style="vertical-align: inherit;">Allow list names:</font> </strong> <font style="vertical-align: inherit;"> CSV list of miners to add to the Cortex XSOAR allow list.</font>
</li>
<li><strong> <font style="vertical-align: inherit;">Use system proxy settings</font></strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details. All commands require the <code>super admin</code> role.</p>
<ol>
<li><a href="#h_99158719451533030125933">Add an indicator to a miner: minemeld-add-to-miner</a></li>
<li><a href="#h_84291944691533030131743">Remove an indicator from a miner: minemeld-remove-from-miner</a></li>
<li><a href="#h_8831063331321533030138926">Get miner details: minemeld-retrieve miner</a></li>
<li><a href="#h_5439582361971533030145741">Get an indicator from a miner: minemeld-get-indicator-from-miner</a></li>
<li><a href="#h_549080515261533045679386">Get IP address indicator: ip</a></li>
<li><a href="#h_7852984883241533030162610">Get file indicator: file</a></li>
<li><a href="#h_5903761773861533030170543">Get domain indicator: domain</a></li>
<li><a href="#h_6945056004471533030179038">Get URL indicator: url</a></li>
<li><a href="#h_8427503055071533030188825">Get a list of all the miners: minemeld-get-all-miners-names</a></li>
</ol>
<p> </p>
<h3 id="h_99158719451533030125933">1. Add an indicator to a miner</h3>
<hr>
<p>Adds a specified indicator to a specified miner. Do not add a single indicator to multiple miners.</p>
<h5>Base Command</h5>
<p><code>minemeld-add-to-miner</code></p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 168px;"><strong>Argument Name</strong></th>
<th style="width: 122px;"><strong>Description</strong></th>
<th style="width: 418px;">More Information</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168px;">miner</td>
<td style="width: 122px;">Miner name</td>
<td style="width: 418px;">To find the miner name, search for <strong>List of Supported</strong> <strong>Nodes</strong> on your MineMeld environment.</td>
</tr>
<tr>
<td style="width: 168px;">indicator</td>
<td style="width: 122px;">Indicator to add to miner</td>
<td style="width: 418px;">
<p>Any type of indicator.</p>
<p>Examples of valid indicators: </p>
<ul>
<li>IP address</li>
<li>File hash</li>
<li>Domain</li>
<li>URL</li>
<li>And more</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 168px;">comment</td>
<td style="width: 122px;">Textual description or comment for the indicator</td>
<td style="width: 418px;">-</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context output</h5>
<p>There is no context output for this command.</p>
<h5>Command example</h5>
<p><code>!minemeld-add-to-miner miner=Supicious indicator=7.7.7.7</code></p>
<h5>War Room Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/PaloAlto_MineMeld_mceclip0.png"></p>
<h3 id="h_84291944691533030131743">2. Remove an indicator from a miner</h3>
<hr>
<p>Removes a specified indicator from a specified miner.</p>
<h5>Base Command</h5>
<p><code>minemeld-remove-from-miner</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 142px;"><strong>Argument Name</strong></th>
<th style="width: 72px;"><strong>Description</strong></th>
<th style="width: 494px;"><strong>More Information</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142px;">miner</td>
<td style="width: 72px;">Miner name</td>
<td style="width: 494px;">To find the miner name, search for <strong>List of Supported</strong> <strong>Nodes</strong> on your MineMeld environment.</td>
</tr>
<tr>
<td style="width: 142px;">indicator</td>
<td style="width: 72px;">The indicator to remove</td>
<td style="width: 494px;">
<p>Any type of indicator.</p>
<p>Examples of valid indicators: </p>
<ul>
<li>IP address</li>
<li>File hash</li>
<li>Domain</li>
<li>URL</li>
<li>And more</li>
</ul>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context output</h5>
<p>There is no context output for this command.</p>
<h5>Command example</h5>
<p><code>!minemeld-remove-from-miner miner=Suspicious indicator=7.7.7.7</code></p>
<h5>War Room Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/PaloAlto_MineMeld_mceclip4.png"></p>
<p> </p>
<h3 id="h_8831063331321533030138926">3. Get miner details</h3>
<hr>
<p>Retrieves information about a specified miner.</p>
<h5>Base Code</h5>
<p><code>minemeld-retrieve-miner</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 206px;"><strong>Argument Name</strong></th>
<th style="width: 120px;"><strong>Description</strong></th>
<th style="width: 382px;"><strong>More Information</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">miner</td>
<td style="width: 120px;">Miner name</td>
<td style="width: 382px;">To select all miners type <strong><em>miner=</em><em>all</em></strong>.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 407px;"><strong>Path</strong></th>
<th style="width: 314px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 407px;">MineMeld.Miner</td>
<td style="width: 314px;">Entire miner object</td>
</tr>
<tr>
<td style="width: 407px;">MineMeld.Miner.name</td>
<td style="width: 314px;">Miner name</td>
</tr>
<tr>
<td style="width: 407px;">MineMeld.Miner.class</td>
<td style="width: 314px;">Miner class</td>
</tr>
<tr>
<td style="width: 407px;">MineMeld.Indicators</td>
<td style="width: 314px;">Entire indicator object</td>
</tr>
<tr>
<td style="width: 407px;">MineMeld.Indicators.miner</td>
<td style="width: 314px;">Miner of indicator</td>
</tr>
<tr>
<td style="width: 407px;">MineMeld.Indicators.type</td>
<td style="width: 314px;">Indicator type</td>
</tr>
<tr>
<td style="width: 407px;">MineMeld.Indicators.indicator</td>
<td style="width: 314px;">Indicator value</td>
</tr>
<tr>
<td style="width: 407px;">MineMeld.Indicators.comment</td>
<td style="width: 314px;">Indicator comment</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!minemeld-retrieve-miner miner=Suspicious</code></p>
<h5>War Room Output</h5>
<h5><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/PaloAlto_MineMeld_mceclip3.png"></h5>
<p> </p>
<h3 id="h_5439582361971533030145741">4. Get an indicator within a miner</h3>
<hr>
<p>Retrieves information about a specified indicator associated with a specified miner.</p>
<h5>Base Command</h5>
<p><code>minemeld-get-indicator-from-miner</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 262px;"><strong>Argument Name</strong></th>
<th style="width: 459px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 262px;">miner</td>
<td style="width: 459px;">Miner name</td>
</tr>
<tr>
<td style="width: 262px;">indicator</td>
<td style="width: 459px;">
<p>Any type of indicator.</p>
<p>Examples of valid indicators: </p>
<ul>
<li>IP address</li>
<li>File hash</li>
<li>Domain</li>
<li>URL</li>
<li>And more</li>
</ul>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 409px;"><strong>Path</strong></th>
<th style="width: 312px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 409px;">MineMeld.Miner</td>
<td style="width: 312px;">Entire miner object</td>
</tr>
<tr>
<td style="width: 409px;">MineMeld.Miner.name</td>
<td style="width: 312px;">Miner name</td>
</tr>
<tr>
<td style="width: 409px;">MineMeld.Indicators</td>
<td style="width: 312px;">Entire indicator object</td>
</tr>
<tr>
<td style="width: 409px;">MineMeld.Indicators.miner</td>
<td style="width: 312px;">Miner of the indicator</td>
</tr>
<tr>
<td style="width: 409px;">MineMeld.Indicators.type</td>
<td style="width: 312px;">Indicator type</td>
</tr>
<tr>
<td style="width: 409px;">MineMeld.Indicators.indicator</td>
<td style="width: 312px;">Indicator value</td>
</tr>
<tr>
<td style="width: 409px;">MineMeld.Indicators.comment</td>
<td style="width: 312px;">Indicator comment</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!minemeld-get-indicator-from-miner miner=Suspicious indicator=7.7.7.7</code></p>
<h5>War Room Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/PaloAlto_MineMeld_mceclip2.png"></p>
<h3 id="h_549080515261533045679386">5. Get IP address indicator</h3>
<hr>
<p>Retrieves all occurrences of the specified IP address, including the context in which it is found.</p>
<p>For this command to succeed, the miner (associated with the IP address indicator) has to be on a Cortex XSOAR block list or allow list.</p>
<h5>Base Command</h5>
<p><code>ip</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 355px;"><strong>Argument Name</strong></th>
<th style="width: 366px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 355px;">ip</td>
<td style="width: 366px;">IP address</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 239px;"><strong>Path</strong></th>
<th style="width: 482px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 239px;">DBotScore.Indicator</td>
<td style="width: 482px;">The Indicator</td>
</tr>
<tr>
<td style="width: 239px;">DBotScore.Type</td>
<td style="width: 482px;">The Indicator type</td>
</tr>
<tr>
<td style="width: 239px;">DBotScore.Vendor</td>
<td style="width: 482px;">The DBot score vendor</td>
</tr>
<tr>
<td style="width: 239px;">DBotScore.Score</td>
<td style="width: 482px;">The DBot score</td>
</tr>
<tr>
<td style="width: 239px;">IP.Malicious.Vendor</td>
<td style="width: 482px;">For malicious IP addresses, the vendor defined the IP address as malicious</td>
</tr>
<tr>
<td style="width: 239px;">IP.Malicious.Description</td>
<td style="width: 482px;">For malicious IP addresses, the reason why the vendor defined the IP address as malicious</td>
</tr>
<tr>
<td style="width: 239px;">IP.Address</td>
<td style="width: 482px;">IP address</td>
</tr>
<tr>
<td style="width: 239px;">IP.MineMeld.Indicators</td>
<td style="width: 482px;">Entire indicator object</td>
</tr>
<tr>
<td style="width: 239px;">IP.MineMeld.Indicators.indicator</td>
<td style="width: 482px;">Indicator value</td>
</tr>
<tr>
<td style="width: 239px;">IP.MineMeld.Indicators.miner</td>
<td style="width: 482px;">Miner of the indicator</td>
</tr>
<tr>
<td style="width: 239px;">IP.MineMeld.Indicators.type</td>
<td style="width: 482px;">Indicator type</td>
</tr>
<tr>
<td style="width: 239px;">IP.MineMeld.Indicators.comment</td>
<td style="width: 482px;">Indicator comment</td>
</tr>
<tr>
<td style="width: 239px;">MineMeld.Indicators</td>
<td style="width: 482px;">Entire indicator object</td>
</tr>
<tr>
<td style="width: 239px;">MineMeld.Indicators.indicator</td>
<td style="width: 482px;">Indicator value</td>
</tr>
<tr>
<td style="width: 239px;">MineMeld.Indicators.miner</td>
<td style="width: 482px;">Miner of the indicator</td>
</tr>
<tr>
<td style="width: 239px;">MineMeld.Indicators.type</td>
<td style="width: 482px;">Indicator type</td>
</tr>
<tr>
<td style="width: 239px;">MineMeld.Indicators.comment</td>
<td style="width: 482px;">Indicator comment</td>
</tr>
<tr>
<td style="width: 239px;">MineMeld.Miner</td>
<td style="width: 482px;">Entire miner object</td>
</tr>
<tr>
<td style="width: 239px;">MineMeld.Miner.name</td>
<td style="width: 482px;">Miner name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!ip ip=7.7.7.7 using-brand="Palo Alto Minemeld"</code></p>
<h5>War Room Output</h5>
<h5><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/PaloAlto_MineMeld_mceclip8.png"></h5>
<p> </p>
<h3 id="h_7852984883241533030162610">6. Get file indicator</h3>
<hr>
<p>Retrieves all occurrences of the specified file, including the context in which it is found.</p>
<p>For this command to succeed, the miner (associated with the file indicator) has to be on a Cortex XSOAR block list or allow list.</p>
<h5>Base Command</h5>
<p><code>file</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 327px;"><strong>Argument Name</strong></th>
<th style="width: 394px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 327px;">file</td>
<td style="width: 394px;">Any type of file hash</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 233px;"><strong>Path</strong></th>
<th style="width: 488px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 233px;">DBotScore.Indicator</td>
<td style="width: 488px;">The Indicator</td>
</tr>
<tr>
<td style="width: 233px;">DBotScore.Type</td>
<td style="width: 488px;">The Indicator type</td>
</tr>
<tr>
<td style="width: 233px;">DBotScore.Vendor</td>
<td style="width: 488px;">The DBot score vendor</td>
</tr>
<tr>
<td style="width: 233px;">DBotScore.Score</td>
<td style="width: 488px;">The DBot score</td>
</tr>
<tr>
<td style="width: 233px;">File.Malicious.Vendor</td>
<td style="width: 488px;">For malicious files, the vendor that defined the file as malicious</td>
</tr>
<tr>
<td style="width: 233px;">File.Malicious.Description</td>
<td style="width: 488px;">For malicious files, the reason why the vendor defined the file as malicious</td>
</tr>
<tr>
<td style="width: 233px;">File.MineMeld.Indicators</td>
<td style="width: 488px;">Entire indicator object</td>
</tr>
<tr>
<td style="width: 233px;">File.MineMeld.Indicators.indicator</td>
<td style="width: 488px;">Indicator value</td>
</tr>
<tr>
<td style="width: 233px;">File.MineMeld.Indicators.miner</td>
<td style="width: 488px;">Miner of the indicator.</td>
</tr>
<tr>
<td style="width: 233px;">File.MineMeld.Indicators.type</td>
<td style="width: 488px;">Indicator type</td>
</tr>
<tr>
<td style="width: 233px;">File.MineMeld.Indicators.comment</td>
<td style="width: 488px;">Indicator comment</td>
</tr>
<tr>
<td style="width: 233px;">MineMeld.Indicators</td>
<td style="width: 488px;">Entire indicator object</td>
</tr>
<tr>
<td style="width: 233px;">MineMeld.Indicators.indicator</td>
<td style="width: 488px;">Indicator value</td>
</tr>
<tr>
<td style="width: 233px;">MineMeld.Indicators.miner</td>
<td style="width: 488px;">Miner of the indicator</td>
</tr>
<tr>
<td style="width: 233px;">MineMeld.Indicators.type</td>
<td style="width: 488px;">Indicator type</td>
</tr>
<tr>
<td style="width: 233px;">MineMeld.Indicators.comment</td>
<td style="width: 488px;">Indicator comment</td>
</tr>
<tr>
<td style="width: 233px;">MineMeld.Miner</td>
<td style="width: 488px;">Entire miner object</td>
</tr>
<tr>
<td style="width: 233px;">MineMeld.Miner.name</td>
<td style="width: 488px;">Miner name</td>
</tr>
<tr>
<td style="width: 233px;">File.MD5</td>
<td style="width: 488px;">MD5 hash of the file</td>
</tr>
<tr>
<td style="width: 233px;">File.SHA1</td>
<td style="width: 488px;">SHA-1 hash of the file</td>
</tr>
<tr>
<td style="width: 233px;">File.SHA256</td>
<td style="width: 488px;">SHA-256 hash of the file</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command example</h5>
<p><code>!file file=9acb44549b41563697bb490144ec6258 using-brand="Palo Alto Minemeld"</code></p>
<h5>War Room Output</h5>
<h5><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/PaloAlto_MineMeld_mceclip6.png"></h5>
<p> </p>
<h3 id="h_5903761773861533030170543">7. Get domain indicator</h3>
<hr>
<p>Retrieves all occurrences of the specified domain, including the context in which it is found.</p>
<p>For this command to succeed, the miner (associated with the domain indicator) has to be on a Cortex XSOAR block list or allow list.</p>
<h5>Base Command</h5>
<p><code>domain</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 398px;"><strong>Argument Name</strong></th>
<th style="width: 323px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 398px;">domain</td>
<td style="width: 323px;">Domain</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>DBotScore.Indicator</td>
<td>The Indicator</td>
</tr>
<tr>
<td>DBotScore.Type</td>
<td>The Indicator type</td>
</tr>
<tr>
<td>DBotScore.Vendor</td>
<td>The DBot score vendor</td>
</tr>
<tr>
<td>DBotScore.Score</td>
<td>The DBot score</td>
</tr>
<tr>
<td>Domain.Malicious.Vendor</td>
<td>For malicious domains, the vendor that defined the domain as malicious</td>
</tr>
<tr>
<td>Domain.Malicious.Description</td>
<td>For malicious domains, the reason that the vendor defined the domain as malicious</td>
</tr>
<tr>
<td>Domain.Name</td>
<td>Domain name (value)</td>
</tr>
<tr>
<td>Domain.MineMeld.Indicators</td>
<td>Entire indicator object</td>
</tr>
<tr>
<td>Domain.MineMeld.Indicators.indicator</td>
<td>Indicator value</td>
</tr>
<tr>
<td>Domain.MineMeld.Indicators.miner</td>
<td>Indicator miner</td>
</tr>
<tr>
<td>Domain.MineMeld.Indicators.type</td>
<td>Indicator type</td>
</tr>
<tr>
<td>Domain.MineMeld.Indicators.comment</td>
<td>Indicator comment</td>
</tr>
<tr>
<td>MineMeld.Indicators</td>
<td>Entire indicator object</td>
</tr>
<tr>
<td>MineMeld.Indicators.indicator</td>
<td>Indicator value</td>
</tr>
<tr>
<td>MineMeld.Indicators.miner</td>
<td>Miner of the indicator</td>
</tr>
<tr>
<td>MineMeld.Indicators.type</td>
<td>Indicator type</td>
</tr>
<tr>
<td>MineMeld.Indicators.comment</td>
<td>Indicator comment</td>
</tr>
<tr>
<td>MineMeld.Miner</td>
<td>Entire miner object</td>
</tr>
<tr>
<td>MineMeld.Miner.name</td>
<td>Miner name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command example</h5>
<p><code>!domain domain=moogle.com using-brand="Palo Alto Minemeld"</code></p>
<h5>War Room Output</h5>
<h5><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/PaloAlto_MineMeld_mceclip7.png"></h5>
<p> </p>
<h3 id="h_6945056004471533030179038">8. Get URL indicator</h3>
<hr>
<p>Retrieves all occurrences of the specified URL, including the context in which it is found.</p>
<p>For this command to succeed, the miner (associated with the URL indicator) has to be on a Cortex XSOAR block list or allow list.</p>
<h5>Base Command</h5>
<p><code>url</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 275px;"><strong>Argument Name</strong></th>
<th style="width: 446px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 275px;">url</td>
<td style="width: 446px;">URL to retrieve instances for</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 256px;"><strong>Path</strong></th>
<th style="width: 465px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 256px;">DBotScore.Indicator</td>
<td style="width: 465px;">The Indicator</td>
</tr>
<tr>
<td style="width: 256px;">DBotScore.Type</td>
<td style="width: 465px;">The Indicator type</td>
</tr>
<tr>
<td style="width: 256px;">DBotScore.Vendor</td>
<td style="width: 465px;">The DBot score vendor</td>
</tr>
<tr>
<td style="width: 256px;">DBotScore.Score</td>
<td style="width: 465px;">The DBot score</td>
</tr>
<tr>
<td style="width: 256px;">URL.Malicious.Vendor</td>
<td style="width: 465px;">For malicious URLs, the vendor that defined the URL as malicious</td>
</tr>
<tr>
<td style="width: 256px;">URL.Malicious.Description</td>
<td style="width: 465px;">For malicious URLs, the reason that the vendor defined the URL as malicious</td>
</tr>
<tr>
<td style="width: 256px;">URL.Data</td>
<td style="width: 465px;">URL data (value)</td>
</tr>
<tr>
<td style="width: 256px;">URL.MineMeld.Indicators</td>
<td style="width: 465px;">Entire indicator object</td>
</tr>
<tr>
<td style="width: 256px;">URL.MineMeld.Indicators.indicator</td>
<td style="width: 465px;">Indicator value</td>
</tr>
<tr>
<td style="width: 256px;">URL.MineMeld.Indicators.miner</td>
<td style="width: 465px;">Miner of the indicator</td>
</tr>
<tr>
<td style="width: 256px;">URL.MineMeld.Indicators.type</td>
<td style="width: 465px;">Indicator type</td>
</tr>
<tr>
<td style="width: 256px;">URL.MineMeld.Indicators.comment</td>
<td style="width: 465px;">Indicator comment</td>
</tr>
<tr>
<td style="width: 256px;">MineMeld.Indicators</td>
<td style="width: 465px;">Entire indicator object</td>
</tr>
<tr>
<td style="width: 256px;">MineMeld.Indicators.indicator</td>
<td style="width: 465px;">Indicator value</td>
</tr>
<tr>
<td style="width: 256px;">MineMeld.Indicators.miner</td>
<td style="width: 465px;">Miner of the Indicator</td>
</tr>
<tr>
<td style="width: 256px;">MineMeld.Indicators.type</td>
<td style="width: 465px;">Indicator type</td>
</tr>
<tr>
<td style="width: 256px;">MineMeld.Indicators.comment</td>
<td style="width: 465px;">Indicator comment</td>
</tr>
<tr>
<td style="width: 256px;">MineMeld.Miner</td>
<td style="width: 465px;">Entire miner object</td>
</tr>
<tr>
<td style="width: 256px;">MineMeld.Miner.name</td>
<td style="width: 465px;">Miner name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command example</h5>
<p><code>!url url=voogle.com/malicious.exe using-brand="Palo Alto Minemeld"</code></p>
<h5>War Room Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/PaloAlto_MineMeld_mceclip5.png"></p>
<p> </p>
<h3 id="h_8427503055071533030188825">9. Get a list of all the miners</h3>
<hr>
<p>Retrieves the names of all the miners, the class of each miner, and how many indicators are associated with each miner.</p>
<h5>Base Command</h5>
<p><code>minemeld-get-all-miners-names</code></p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>MineMeld.Miner</td>
<td>Entire miner object</td>
</tr>
<tr>
<td>MineMeld.Miner.name</td>
<td>Miner name</td>
</tr>
<tr>
<td>MineMeld.Miner.class</td>
<td>Miner class</td>
</tr>
<tr>
<td>MineMeld.Miner.indicators</td>
<td>Number of miner indicators</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command example</h5>
<p>!minemeld-get-all-miners-names</p>
<h5>War Room Output</h5>
<pre> <img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/PaloAlto_MineMeld_mceclip1.png"></pre>
