<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the Signal Sciences next-gen web application firewall to increase security and maintain reliability.</p>
</div>
<div class="cl-preview-section">
<h2 id="configure-signal-sciences-waf-on-demisto">Configure Signal Sciences WAF on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Signal Sciences WAF.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Email</strong></li>
<li><strong>Token</strong></li>
<li><strong>Corporation Name (should match the pattern [0-9a-z_.-]+)</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Fetch Interval (in minutes)</strong></li>
<li><strong>CSV list of sites to fetch from. If no sites are specified, events from all corporation’s sites will be fetched.</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#get-a-sites-whitelist" target="_self">Get a site’s allow list: sigsci-get-whitelist</a></li>
<li><a href="#get-a-sites-blacklist-sigsci-get-blacklist" target="_self">Get a site’s block list: sigsci-get-blacklist</a></li>
<li><a href="#add-an-ip-address-to-a-whitelist-sigsci-whitelist-add-ip" target="_self">Add an IP address to an allow list: sigsci-whitelist-add-ip</a></li>
<li><a href="#add-an-ip-address-to-a-blacklist-sigsci-blacklist-add-ip" target="_self">Add an IP address to a block list: sigsci-blacklist-add-ip</a></li>
<li><a href="#remove-an-ip-address-from-a-whitelist-sigsci-whitelist-remove-ip" target="_self">Remove an IP address from an allow list: sigsci-whitelist-remove-ip</a></li>
<li><a href="#remove-an-ip-address-from-a-blacklist" target="_self">Remove an IP address from a block list: sigsci-blacklist-remove-ip</a></li>
<li><a href="#get-all-site-names" target="_self">Get all site names: sigsci-get-sites</a></li>
<li><a href="#create-a-list-for-a-site" target="_self">Create a list for a site: sigsci-create-site-list</a></li>
<li><a href="#get-information-for-a-site-list" target="_self">Get information for a site list: sigsci-get-site-list</a></li>
<li><a href="#delete-a-site-list" target="_self">Delete a site list: sigsci-delete-site-list</a></li>
<li><a href="#update-a-site-list" target="_self">Update a site list: sigsci-update-site-list</a></li>
<li><a href="#add-an-alert-to-a-site" target="_self">Add an alert to a site: sigsci-add-alert</a></li>
<li><a href="#get-information-for-an-alert" target="_self">Get information for an alert: sigsci-get-alert</a></li>
<li><a href="#delete-an-alert-from-a-site" target="_self">Delete an alert from a site: sigsci-delete-alert</a></li>
<li><a href="#update-attributes-for-an-alert" target="_self">Update attributes for an alert: sigsci-update-alert</a></li>
<li><a href="#get-all-alerts-for-a-site" target="_self">Get all alerts for a site: sigsci-get-all-alerts</a></li>
<li><a href="#get-all-lists-for-a-site" target="_self">Get all lists for a site: sigsci-get-all-site-lists</a></li>
<li><a href="#create-a-corp-list" target="_self">Create a corp list: sigsci-create-corp-list</a></li>
<li><a href="#get-information-for-a-corp-list" target="_self">Get information for a corp list: sigsci-get-corp-list</a></li>
<li><a href="#delete-a-corp-list" target="_self">Delete a corp list: sigsci-delete-corp-list</a></li>
<li><a href="#update-a-corp-list" target="_self">Update a corp list: sigsci-update-corp-list</a></li>
<li><a href="#get-information-for-all-lists-of-a-corp" target="_self">Get information for all lists of a corp: sigsci-get-all-corp-lists</a></li>
<li><a href="#get-a-list-of-events" target="_self">Get a list of events: sigsci-fetch-events</a></li>
<li><a href="#get-an-event-by-event-id" target="_self">Get an event by event ID: sigsci-get-event-by-id</a></li>
<li><a href="#expire-an-event" target="_self">Expire an event: sigsci-expire-event</a></li>
<li><a href="#get-requests-for-a-site" target="_self">Get requests for a site: sigsci-get-requests</a></li>
<li><a href="#get-a-request-by-request-id" target="_self">Get a request by request ID: sigsci-get-request-by-id</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-a-sites-whitelist">1. Get a site’s allow list</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Fetches a site’s allow list, which resides on the Signal Sciences’ platform.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-whitelist</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 169px;"><strong>Argument Name</strong></th>
<th style="width: 473px;"><strong>Description</strong></th>
<th style="width: 98px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 169px;">siteName</td>
<td style="width: 473px;">The site that holds the allow list you want to get.</td>
<td style="width: 98px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 377px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 304px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 377px;">SigSciences.Corp.Site.Whitelist.ID</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">ID for this particular entry.</td>
</tr>
<tr>
<td style="width: 377px;">SigSciences.Corp.Site.Whitelist.Source</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">IP Address present in the allow list.</td>
</tr>
<tr>
<td style="width: 377px;">SigSciences.Corp.Site.Whitelist.ExpiryDate</td>
<td style="width: 59px;">date</td>
<td style="width: 304px;">Expiration Timestamp.</td>
</tr>
<tr>
<td style="width: 377px;">SigSciences.Corp.Site.Whitelist.Note</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">Note associated with the tag.</td>
</tr>
<tr>
<td style="width: 377px;">SigSciences.Corp.Site.Whitelist.CreatedDate</td>
<td style="width: 59px;">date</td>
<td style="width: 304px;">The created date timestamp</td>
</tr>
<tr>
<td style="width: 377px;">SigSciences.Corp.Site.Whitelist.CreatedBy</td>
<td style="width: 59px;">string</td>
<td style="width: 304px;">The user who added this source.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-get-whitelist siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SigSciences.Corp.Site.Whitelist": [
        {
            "ExpiryDate": "", 
            "Note": "docdoc", 
            "Source": "9.7.9.7", 
            "CreatedBy": "user@demisto.com", 
            "CreatedDate": "2019-03-28T09:52:47Z", 
            "ID": "5c9c996fc7213901971d5679"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="signal-sciences---whitelist">Signal Sciences - Whitelist</h3>
</div>
<div class="cl-preview-section">
<p>Number of IPs in the allow list 1</p>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Source</th>
<th>Note</th>
<th>Created Date</th>
<th>Created By</th>
</tr>
</thead>
<tbody>
<tr>
<td>9.7.9.7</td>
<td>docdoc</td>
<td>2019-03-28T09:52:47Z</td>
<td>user@demisto.com</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-sites-blacklist-sigsci-get-blacklist">2. Get a site’s blacklist: sigsci-get-blacklist</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Fetches a site’s block list, which resides on the Signal Sciences’ platform.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-blacklist</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 172px;"><strong>Argument Name</strong></th>
<th style="width: 468px;"><strong>Description</strong></th>
<th style="width: 100px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 172px;">siteName</td>
<td style="width: 468px;">The site that holds the block list you wish to get</td>
<td style="width: 100px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 384px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 298px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 384px;">SigSciences.Corp.Site.Blacklist.ID</td>
<td style="width: 58px;">string</td>
<td style="width: 298px;">The ID for this entry.</td>
</tr>
<tr>
<td style="width: 384px;">SigSciences.Corp.Site.Blacklist.Source</td>
<td style="width: 58px;">string</td>
<td style="width: 298px;">The IP address on the blacklist.</td>
</tr>
<tr>
<td style="width: 384px;">SigSciences.Corp.Site.Blacklist.ExpiryDate</td>
<td style="width: 58px;">date</td>
<td style="width: 298px;">The expiration timestamp.</td>
</tr>
<tr>
<td style="width: 384px;">SigSciences.Corp.Site.Blacklist.Note</td>
<td style="width: 58px;">string</td>
<td style="width: 298px;">The note associated with the tag.</td>
</tr>
<tr>
<td style="width: 384px;">SigSciences.Corp.Site.Blacklist.CreatedDate</td>
<td style="width: 58px;">date</td>
<td style="width: 298px;">The created date timestamp.</td>
</tr>
<tr>
<td style="width: 384px;">SigSciences.Corp.Site.Blacklist.CreatedBy</td>
<td style="width: 58px;">string</td>
<td style="width: 298px;">The user who added this source.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-get-blacklist siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SigSciences.Corp.Site.Blacklist": [
        {
            "ExpiryDate": "", 
            "Note": "docdoc", 
            "Source": "5.7.5.7", 
            "CreatedBy": "user@demisto.com", 
            "CreatedDate": "2019-03-28T09:52:49Z", 
            "ID": "5c9c9971719dcc0198a38a5b"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="signal-sciences---blacklist">Signal Sciences - Blacklist</h3>
</div>
<div class="cl-preview-section">
<p>Number of IPs in the block list 1</p>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Source</th>
<th>Note</th>
<th>Created Date</th>
<th>Created By</th>
</tr>
</thead>
<tbody>
<tr>
<td>5.7.5.7</td>
<td>docdoc</td>
<td>2019-03-28T09:52:49Z</td>
<td>user@demisto.com</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="add-an-ip-address-to-a-whitelist-sigsci-whitelist-add-ip">3. Add an IP address to an allow list: sigsci-whitelist-add-ip</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds an IP address to a site’s allow list, which resides the Signal Sciences’ platform.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-whitelist-add-ip</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 140px;"><strong>Argument Name</strong></th>
<th style="width: 529px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 140px;">siteName</td>
<td style="width: 529px;">The site that holds the allow list you want to add an IP address to.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 140px;">ip</td>
<td style="width: 529px;">The IP address to add to the site’s allow list in CSV format.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 140px;">note</td>
<td style="width: 529px;">The note associated with the tag.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 140px;">expires</td>
<td style="width: 529px;">The datetime for the IP address to removed from the site’s allow list (in RFC3339 format). To keep the IP address on the site’s allow list indefinitely, do not specify this argument.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 387px;"><strong>Path</strong></th>
<th style="width: 57px;"><strong>Type</strong></th>
<th style="width: 296px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 387px;">SigSciences.Corp.Site.Whitelist.Source</td>
<td style="width: 57px;">string</td>
<td style="width: 296px;">The IP address on the allow list.</td>
</tr>
<tr>
<td style="width: 387px;">SigSciences.Corp.Site.Whitelist.Note</td>
<td style="width: 57px;">string</td>
<td style="width: 296px;">The note associated with the tag.</td>
</tr>
<tr>
<td style="width: 387px;">SigSciences.Corp.Site.Whitelist.ID</td>
<td style="width: 57px;">string</td>
<td style="width: 296px;">The ID for this entry.</td>
</tr>
<tr>
<td style="width: 387px;">SigSciences.Corp.Site.Whitelist.CreatedBy</td>
<td style="width: 57px;">string</td>
<td style="width: 296px;">The user who added this source.</td>
</tr>
<tr>
<td style="width: 387px;">SigSciences.Corp.Site.Whitelist.CreatedDate</td>
<td style="width: 57px;">date</td>
<td style="width: 296px;">The created date timestamp</td>
</tr>
<tr>
<td style="width: 387px;">SigSciences.Corp.Site.Whitelist.ExpiryDate</td>
<td style="width: 57px;">date</td>
<td style="width: 296px;">The expiration timestamp.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-whitelist-add-ip ip=9.7.9.7 note=docdoc siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SigSciences.Corp.Site.Whitelist": {
        "ExpiryDate": "", 
        "Note": "docdoc", 
        "Source": "9.7.9.7", 
        "CreatedBy": "user@demisto.com", 
        "CreatedDate": "2019-03-28T13:30:34Z", 
        "ID": "5c9ccc7a342a24019743d265"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="signal-sciences---adding-an-ip-to-whitelist">Signal Sciences - Adding an IP to allow list</h3>
</div>
<div class="cl-preview-section">
<p>The IP 9.7.9.7 has been successfully added to allow list.</p>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Source</th>
<th>Note</th>
<th>Expiration date</th>
</tr>
</thead>
<tbody>
<tr>
<td>9.7.9.7</td>
<td>docdoc</td>
<td>Not Set</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="add-an-ip-address-to-a-blacklist-sigsci-blacklist-add-ip">4. Add an IP address to a block list: sigsci-blacklist-add-ip</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds an IP to a site’s block list, which resides on the Signal Sciences’ platform.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-blacklist-add-ip</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 141px;"><strong>Argument Name</strong></th>
<th style="width: 528px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">siteName</td>
<td style="width: 528px;">The site that holds the block list you wish to add to</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 141px;">ip</td>
<td style="width: 528px;">The IP address to add to the site’s block list in CSV format.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 141px;">note</td>
<td style="width: 528px;">The note associated with the tag.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 141px;">expires</td>
<td style="width: 528px;">The datetime for the IP address to removed from the site’s block list (in RFC3339 format). To keep the IP address on the site’s block list indefinitely, do not specify this argument.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 385px;"><strong>Path</strong></th>
<th style="width: 57px;"><strong>Type</strong></th>
<th style="width: 298px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 385px;">SigSciences.Corp.Site.Blacklist.Source</td>
<td style="width: 57px;">string</td>
<td style="width: 298px;">The IP address on the blacklist.</td>
</tr>
<tr>
<td style="width: 385px;">SigSciences.Corp.Site.Blacklist.Note</td>
<td style="width: 57px;">string</td>
<td style="width: 298px;">The note associated with the tag.</td>
</tr>
<tr>
<td style="width: 385px;"><a href="http://sigsciences.corp.site.blacklist.id/">SigSciences.Corp.Site.Blacklist.ID</a></td>
<td style="width: 57px;">string</td>
<td style="width: 298px;">The ID for this entry.</td>
</tr>
<tr>
<td style="width: 385px;">SigSciences.Corp.Site.Blacklist.CreatedBy</td>
<td style="width: 57px;">string</td>
<td style="width: 298px;">The user who added this source.</td>
</tr>
<tr>
<td style="width: 385px;">SigSciences.Corp.Site.Blacklist.CreatedDate</td>
<td style="width: 57px;">date</td>
<td style="width: 298px;">The created date timestamp.</td>
</tr>
<tr>
<td style="width: 385px;">SigSciences.Corp.Site.Blacklist.ExpiryDate</td>
<td style="width: 57px;">date</td>
<td style="width: 298px;">The expiration timestamp.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-blacklist-add-ip ip=5.7.5.7 note=docdoc siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SigSciences.Corp.Site.Blacklist": {
        "ExpiryDate": "", 
        "Note": "docdoc", 
        "Source": "5.7.5.7", 
        "CreatedBy": "user@demisto.com", 
        "CreatedDate": "2019-03-28T13:30:35Z", 
        "ID": "5c9ccc7bf7c34301986b1d82"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="signal-sciences---adding-an-ip-to-blacklist">Signal Sciences - Adding an IP to block list</h3>
</div>
<div class="cl-preview-section">
<p>The IP 5.7.5.7 has been successfully added to block list.</p>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Source</th>
<th>Note</th>
<th>Expiration date</th>
</tr>
</thead>
<tbody>
<tr>
<td>5.7.5.7</td>
<td>docdoc</td>
<td>Not Set</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="remove-an-ip-address-from-a-whitelist-sigsci-whitelist-remove-ip">5. Remove an IP address from an allow list: sigsci-whitelist-remove-ip</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Removes an IP address from a site’s allow list, which resides on the Signal Sciences’ platform.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-whitelist-remove-ip</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 140px;"><strong>Argument Name</strong></th>
<th style="width: 528px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 140px;">siteName</td>
<td style="width: 528px;">The site that contains the allow list you want to remove an IP address from.</td>
<td style="width: 72px;">Required</td>
</tr>
<tr>
<td style="width: 140px;">IP</td>
<td style="width: 528px;">The IP address entry to remove.</td>
<td style="width: 72px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-whitelist-remove-ip IP=4.7.4.7 siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h3 id="remove-an-ip-address-from-a-blacklist">6. Remove an IP address from a block list</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Removes an IP from a site’s block list, which resides on the Signal Sciences’ platform.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-blacklist-remove-ip</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 142px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142px;">siteName</td>
<td style="width: 526px;">The site that contains the block list you want to remove an IP address from.</td>
<td style="width: 72px;">Required</td>
</tr>
<tr>
<td style="width: 142px;">IP</td>
<td style="width: 526px;">The IP address entry to remove.</td>
<td style="width: 72px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-blacklist-remove-ip IP=6.8.6.8 siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h3 id="get-all-site-names">7. Get all site names</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns all site names from the Signal Sciences platform.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-sites</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-6">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 368px;"><strong>Path</strong></th>
<th style="width: 84px;"><strong>Type</strong></th>
<th style="width: 288px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 368px;">SigSciences.Site.Name</td>
<td style="width: 84px;">string</td>
<td style="width: 288px;">The site name.</td>
</tr>
<tr>
<td style="width: 368px;">SigSciences.Site.CreatedDate</td>
<td style="width: 84px;">date</td>
<td style="width: 288px;">The site creation date.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="create-a-list-for-a-site">8. Create a list for a site</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Creates a new list for a given site on the Signal Sciences platform.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-create-site-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 139px;"><strong>Argument Name</strong></th>
<th style="width: 530px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">siteName</td>
<td style="width: 530px;">The name of the site in Signal Sciences you want to add a list to.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 139px;">list_name</td>
<td style="width: 530px;">The name of the list to create on Signal Sciences.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 139px;">list_type</td>
<td style="width: 530px;">The type for the list you wish to create on Signal Sciences. Legal types are IP, String, Country or Wildcard</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 139px;">entries_list</td>
<td style="width: 530px;">A CSV list of values, consistent with the list’s type.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 139px;">description</td>
<td style="width: 530px;">Short text that describes the new list.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-7">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 359px;"><strong>Path</strong></th>
<th style="width: 90px;"><strong>Type</strong></th>
<th style="width: 291px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 359px;">SigSciences.Corp.Site.List.Name</td>
<td style="width: 90px;">string</td>
<td style="width: 291px;">The name of the list.</td>
</tr>
<tr>
<td style="width: 359px;">SigSciences.Corp.Site.List.Type</td>
<td style="width: 90px;">string</td>
<td style="width: 291px;">The type of the list.</td>
</tr>
<tr>
<td style="width: 359px;">SigSciences.Corp.Site.List.Entries</td>
<td style="width: 90px;">unknown</td>
<td style="width: 291px;">The entry list of the list.</td>
</tr>
<tr>
<td style="width: 359px;">SigSciences.Corp.Site.List.ID</td>
<td style="width: 90px;">string</td>
<td style="width: 291px;">The ID of the list.</td>
</tr>
<tr>
<td style="width: 359px;">SigSciences.Corp.Site.List.Description</td>
<td style="width: 90px;">string</td>
<td style="width: 291px;">The description of the list.</td>
</tr>
<tr>
<td style="width: 359px;">SigSciences.Corp.Site.List.CreatedBy</td>
<td style="width: 90px;">string</td>
<td style="width: 291px;">The creator of the list.</td>
</tr>
<tr>
<td style="width: 359px;">SigSciences.Corp.Site.List.CreatedDate</td>
<td style="width: 90px;">string</td>
<td style="width: 291px;">The creation date of the list.</td>
</tr>
<tr>
<td style="width: 359px;">SigSciences.Corp.Site.List.UpdatedDate</td>
<td style="width: 90px;">string</td>
<td style="width: 291px;">The last update date of the list.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-6">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-create-site-list entries_list=56.1.1.1 list_name=sitelistdoc list_type=IP siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h3 id="get-information-for-a-site-list">9. Get information for a site list</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns all the data about a site list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-8">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-site-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-8">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">siteName</td>
<td style="width: 526px;">The name of the site in Signal Sciences that the list you’re searching for belongs to.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">list_id</td>
<td style="width: 526px;">The ID of the list.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-8">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 361px;"><strong>Path</strong></th>
<th style="width: 88px;"><strong>Type</strong></th>
<th style="width: 291px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.List.Name</td>
<td style="width: 88px;">string</td>
<td style="width: 291px;">The name of the list.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.List.Type</td>
<td style="width: 88px;">string</td>
<td style="width: 291px;">The type of the list.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.List.Entries</td>
<td style="width: 88px;">unknown</td>
<td style="width: 291px;">The entry list of the list.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.List.ID</td>
<td style="width: 88px;">unknown</td>
<td style="width: 291px;">The ID of the list.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.List.Description</td>
<td style="width: 88px;">unknown</td>
<td style="width: 291px;">The description of the list.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.List.CreatedBy</td>
<td style="width: 88px;">unknown</td>
<td style="width: 291px;">The creator of the list.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.List.CreatedDate</td>
<td style="width: 88px;">unknown</td>
<td style="width: 291px;">The creation date of the list.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.List.UpdatedDate</td>
<td style="width: 88px;">unknown</td>
<td style="width: 291px;">The last update date of the list.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-7">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-get-site-list list_id=site.sitelistdoc3 siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-4">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SigSciences.Corp.Site.List": {
        "Name": "sitelistdoc3", 
        "CreatedDate": "2019-03-28T09:20:34Z", 
        "UpdatedDate": "2019-03-28T09:53:01Z", 
        "CreatedBy": "user@demisto.com", 
        "Entries": [
            "6.1.7.1", 
            "77.8.77.8"
        ], 
        "Type": "ip", 
        "ID": "site.sitelistdoc3", 
        "Description": ""
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="found-data-about-list-with-id-site.sitelistdoc3">Found data about list with ID: site.sitelistdoc3</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Name</th>
<th>ID</th>
<th>Type</th>
<th>Entries</th>
<th>Created By</th>
<th>Created Date</th>
<th>Updated Date</th>
</tr>
</thead>
<tbody>
<tr>
<td>sitelistdoc3</td>
<td>site.sitelistdoc3</td>
<td>ip</td>
<td>6.1.7.1,<br> 77.8.77.8</td>
<td>user@demisto.com</td>
<td>2019-03-28T09:20:34Z</td>
<td>2019-03-28T09:53:01Z</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="delete-a-site-list">10. Delete a site list</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes a site list in Signal Sciences.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-9">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-delete-site-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-9">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 520px;"><strong>Description</strong></th>
<th style="width: 76px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">siteName</td>
<td style="width: 520px;">The name of the site in Signal Sciences you want to delete a list from.</td>
<td style="width: 76px;">Required</td>
</tr>
<tr>
<td style="width: 144px;">list_id</td>
<td style="width: 520px;">The ID of the list in Signal Sciences to delete.</td>
<td style="width: 76px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-9">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-8">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-delete-site-list list_id=site.sitelistdoc2 siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h3 id="update-a-site-list">11. Update a site list</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Updates a site list in Signal Sciences.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-10">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-update-site-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-10">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 148px;"><strong>Argument Name</strong></th>
<th style="width: 521px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">siteName</td>
<td style="width: 521px;">The name of the site in Signal Sciences that the list to update belongs to.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 148px;">list_id</td>
<td style="width: 521px;">The ID of the list to update.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 148px;">method</td>
<td style="width: 521px;">The method to use, must be “Add” or “Remove”. The method will determine whether the given entries are added to or removed from the list.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 148px;">entries_list</td>
<td style="width: 521px;">A CSV list of values, consistent with the list’s type.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 148px;">description</td>
<td style="width: 521px;">A description for the updated list.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-10">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 276px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 396px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 276px;">SigSciences.Corp.Site.List.Name</td>
<td style="width: 68px;">string</td>
<td style="width: 396px;">The name of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 276px;">SigSciences.Corp.Site.List.Type</td>
<td style="width: 68px;">string</td>
<td style="width: 396px;">The type of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 276px;">SigSciences.Corp.Site.List.Entries</td>
<td style="width: 68px;">unknown</td>
<td style="width: 396px;">The entry list of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 276px;">SigSciences.Corp.Site.List.ID</td>
<td style="width: 68px;">string</td>
<td style="width: 396px;">The ID of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 276px;">SigSciences.Corp.Site.List.Description</td>
<td style="width: 68px;">string</td>
<td style="width: 396px;">The description of the list in Signal Sciences. Maximum is 140 characters.</td>
</tr>
<tr>
<td style="width: 276px;">SigSciences.Corp.Site.List.CreatedBy</td>
<td style="width: 68px;">string</td>
<td style="width: 396px;">The creator of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 276px;">SigSciences.Corp.Site.List.CreatedDate</td>
<td style="width: 68px;">string</td>
<td style="width: 396px;">The creation date of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 276px;">SigSciences.Corp.Site.List.UpdatedDate</td>
<td style="width: 68px;">string</td>
<td style="width: 396px;">The last update date of the list in Signal Sciences.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-9">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-update-site-list entries_list=77.8.77.8 list_id=site.sitelistdoc3 method=Add siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-5">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SigSciences.Corp.Site.List": {
        "Name": "sitelistdoc3", 
        "CreatedDate": "2019-03-28T09:20:34Z", 
        "UpdatedDate": "2019-03-28T09:53:01Z", 
        "CreatedBy": "user@demisto.com", 
        "Entries": [
            "6.1.7.1", 
            "77.8.77.8"
        ], 
        "Type": "ip", 
        "ID": "site.sitelistdoc3", 
        "Description": ""
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="signal-sciences---updating-a-list">Signal Sciences - Updating a list</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Name</th>
<th>ID</th>
<th>Type</th>
<th>Entries</th>
<th>Created By</th>
<th>Created Date</th>
<th>Updated Date</th>
</tr>
</thead>
<tbody>
<tr>
<td>sitelistdoc3</td>
<td>site.sitelistdoc3</td>
<td>ip</td>
<td>6.1.7.1,<br> 77.8.77.8</td>
<td>user@demisto.com</td>
<td>2019-03-28T09:20:34Z</td>
<td>2019-03-28T09:53:01Z</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="add-an-alert-to-a-site">12. Add an alert to a site</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds a custom alert to a site in Signal Sciences.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-11">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-add-alert</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-11">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 531px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">siteName</td>
<td style="width: 531px;">The name of the site to add an alert to.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">long_name</td>
<td style="width: 531px;">A human readable description of the alert. Must be between 3 and 25 characters.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">interval</td>
<td style="width: 531px;">The number of minutes of past traffic to examine. Must be 1, 10 or 60.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">tag_name</td>
<td style="width: 531px;">The name of the tag whose occurrences the alert is watching. Must match an existing tag.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">threshold</td>
<td style="width: 531px;">The number of occurrences of the tag in the specified interval that are required to trigger the alert.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">enabled</td>
<td style="width: 531px;">A flag to toggle this alert (“True” or “False”).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">action</td>
<td style="width: 531px;">A flag that describes what happens when the alert is triggered. “info” creates an incident in the dashboard. “flagged” creates an incident and blocks traffic for 24 hours.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-11">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 343px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 330px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.ID</td>
<td style="width: 67px;">string</td>
<td style="width: 330px;">The unique ID of the alert.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.SiteID</td>
<td style="width: 67px;">string</td>
<td style="width: 330px;">The ID of the site.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.TagName</td>
<td style="width: 67px;">string</td>
<td style="width: 330px;">The name of the tag whose occurrences the alert is watching.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.LongName</td>
<td style="width: 67px;">string</td>
<td style="width: 330px;">A short description of the alert.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.Interval</td>
<td style="width: 67px;">number</td>
<td style="width: 330px;">The number of minutes of past traffic to examine.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.Threshold</td>
<td style="width: 67px;">number</td>
<td style="width: 330px;">The number of occurrences of the tag in the specified interval that are required to trigger the alert.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.BlockDurationSeconds</td>
<td style="width: 67px;">number</td>
<td style="width: 330px;">The number of seconds that this alert is active.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.SkipNotifications</td>
<td style="width: 67px;">boolean</td>
<td style="width: 330px;">A flag to disable external notifications - Slack, webhooks, emails, and so on.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.Enabled</td>
<td style="width: 67px;">boolean</td>
<td style="width: 330px;">A flag to toggle this alert.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.Action</td>
<td style="width: 67px;">string</td>
<td style="width: 330px;">A flag that describes what happens when the alert is triggered.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.CreatedDate</td>
<td style="width: 67px;">date</td>
<td style="width: 330px;">The timestamp of event (RFC3339 format).</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-10">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-add-alert action='info' enabled=False interval=60 long_name=tttt siteName=demisto tag_name=USERAGENT threshold=100</pre>
</div>
<div class="cl-preview-section">
<h3 id="get-information-for-an-alert">13. Get information for an alert</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves data for an alert.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-12">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-alert</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-12">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 510px;"><strong>Description</strong></th>
<th style="width: 79px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">siteName</td>
<td style="width: 510px;">The name of the site the alert you want to get data for belongs to.</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">alert_id</td>
<td style="width: 510px;">The ID of the alert to retrieve.</td>
<td style="width: 79px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-12">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 350px;"><strong>Path</strong></th>
<th style="width: 60px;"><strong>Type</strong></th>
<th style="width: 330px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 350px;">SigSciences.Corp.Site.Alert.ID</td>
<td style="width: 60px;">string</td>
<td style="width: 330px;">The unique ID of the alert.</td>
</tr>
<tr>
<td style="width: 350px;">SigSciences.Corp.Site.Alert.SiteID</td>
<td style="width: 60px;">string</td>
<td style="width: 330px;">The ID of the site.</td>
</tr>
<tr>
<td style="width: 350px;">SigSciences.Corp.Site.Alert.TagName</td>
<td style="width: 60px;">string</td>
<td style="width: 330px;">The name of the tag whose occurrences the alert is watching.</td>
</tr>
<tr>
<td style="width: 350px;">SigSciences.Corp.Site.Alert.LongName</td>
<td style="width: 60px;">string</td>
<td style="width: 330px;">A short description of the alert.</td>
</tr>
<tr>
<td style="width: 350px;">SigSciences.Corp.Site.Alert.Interval</td>
<td style="width: 60px;">number</td>
<td style="width: 330px;">The number of minutes of past traffic to examine.</td>
</tr>
<tr>
<td style="width: 350px;">SigSciences.Corp.Site.Alert.Threshold</td>
<td style="width: 60px;">number</td>
<td style="width: 330px;">The number of occurrences of the tag in the specified interval that are required to trigger the alert.</td>
</tr>
<tr>
<td style="width: 350px;">SigSciences.Corp.Site.Alert.BlockDurationSeconds</td>
<td style="width: 60px;">number</td>
<td style="width: 330px;">The number of seconds this alert is active.</td>
</tr>
<tr>
<td style="width: 350px;">SigSciences.Corp.Site.Alert.SkipNotifications</td>
<td style="width: 60px;">boolean</td>
<td style="width: 330px;">A flag to disable external notifications - Slack, webhooks, emails, and so on.</td>
</tr>
<tr>
<td style="width: 350px;">SigSciences.Corp.Site.Alert.Enabled</td>
<td style="width: 60px;">boolean</td>
<td style="width: 330px;">A flag to toggle this alert.</td>
</tr>
<tr>
<td style="width: 350px;">SigSciences.Corp.Site.Alert.Action</td>
<td style="width: 60px;">string</td>
<td style="width: 330px;">A flag that describes what happens when the alert is triggered.</td>
</tr>
<tr>
<td style="width: 350px;">SigSciences.Corp.Site.Alert.CreatedDate</td>
<td style="width: 60px;">date</td>
<td style="width: 330px;">The timestamp of the event (RFC3339 format).</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-11">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-get-alert alert_id=5b8ba7fd7a54b34f0c0f12cc siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="delete-an-alert-from-a-site">14. Delete an alert from a site</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes an alert from a given site in Signal Sciences.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-13">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-delete-alert</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-13">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 195px;"><strong>Argument Name</strong></th>
<th style="width: 442px;"><strong>Description</strong></th>
<th style="width: 103px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 195px;">siteName</td>
<td style="width: 442px;">The name of the site to delete an alert from.</td>
<td style="width: 103px;">Required</td>
</tr>
<tr>
<td style="width: 195px;">alert_id</td>
<td style="width: 442px;">The ID of the alert to delete.</td>
<td style="width: 103px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-13">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-12">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-delete-alert alert_id=5b8ba7fd7a54b34f0c0f12cc siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h3 id="update-attributes-for-an-alert">15. Update attributes for an alert</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Updates the attributes of a given alert.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-14">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-update-alert</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-14">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 533px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">siteName</td>
<td style="width: 533px;">The site of the alert to update.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">alert_id</td>
<td style="width: 533px;">The ID of the alert to update.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">tag_name</td>
<td style="width: 533px;">The name of the tag whose occurrences the alert is watching.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">long_name</td>
<td style="width: 533px;">A human readable description of the alert. Must be between 3 and 25 characters.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">interval</td>
<td style="width: 533px;">The number of minutes of past traffic to examine.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">threshold</td>
<td style="width: 533px;">The number of occurrences of the tag in the specified interval that are required to trigger the alert.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">enabled</td>
<td style="width: 533px;">A flag to toggle this alert.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">action</td>
<td style="width: 533px;">A flag that describes what happens when the alert is triggered. “info” creates an incident in the dashboard. “flagged” creates an incident and blocks traffic for 24 hours.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-14">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 343px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 330px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.CreatedDate</td>
<td style="width: 67px;">string</td>
<td style="width: 330px;">The unique ID of the alert.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.SiteID</td>
<td style="width: 67px;">string</td>
<td style="width: 330px;">The ID of the site.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.TagName</td>
<td style="width: 67px;">string</td>
<td style="width: 330px;">The name of the tag whose occurrences the alert is watching.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.LongName</td>
<td style="width: 67px;">string</td>
<td style="width: 330px;">A short description of the alert.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.Interval</td>
<td style="width: 67px;">number</td>
<td style="width: 330px;">The number of minutes of past traffic to examine.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.Threshold</td>
<td style="width: 67px;">number</td>
<td style="width: 330px;">The number of occurrences of the tag in the specified interval that are required to trigger the alert.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.BlockDurationSeconds</td>
<td style="width: 67px;">number</td>
<td style="width: 330px;">The number of seconds that this alert is active.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.SkipNotifications</td>
<td style="width: 67px;">boolean</td>
<td style="width: 330px;">A flag to disable external notifications - Slack, webhooks, emails, and so on.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.Enabled</td>
<td style="width: 67px;">boolean</td>
<td style="width: 330px;">A flag to toggle this alert.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.Action</td>
<td style="width: 67px;">string</td>
<td style="width: 330px;">A flag that describes what happens when the alert is triggered.</td>
</tr>
<tr>
<td style="width: 343px;">SigSciences.Corp.Site.Alert.CreatedDate</td>
<td style="width: 67px;">date</td>
<td style="width: 330px;">The timestamp of event (RFC3339 format).</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-13">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-update-alert action=flagged alert_id=5c9c8f35c7213901971d2e5a enabled=False interval=10 long_name=ggggg siteName=demisto tag_name=SQLI threshold=40</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-7">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SigSciences.Corp.Site.Alert": {
        "LongName": "ggggg", 
        "SkipNotifications": "", 
        "Interval": 10, 
        "Enabled": true, 
        "Threshold": 40, 
        "SiteID": "", 
        "TagName": "SQLI", 
        "CreatedDate": "2019-03-28T09:09:09Z", 
        "Action": "flagged", 
        "ID": "5c9c8f35c7213901971d2e5a", 
        "BlockDurationSeconds": ""
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-7">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="updated-alert-5c9c8f35c7213901971d2e5a.-new-values">Updated alert 5c9c8f35c7213901971d2e5a. new values:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Created Date</th>
<th>Tag Name</th>
<th>Action</th>
<th>Long Name</th>
<th>Interval (In Minutes)</th>
<th>Threshold</th>
<th>Enabled</th>
</tr>
</thead>
<tbody>
<tr>
<td>5c9c8f35c7213901971d2e5a</td>
<td>2019-03-28T09:09:09Z</td>
<td>SQLI</td>
<td>flagged</td>
<td>ggggg</td>
<td>10</td>
<td>40</td>
<td>true</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-all-alerts-for-a-site">16. Get all alerts for a site</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves all alerts for given a site.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-15">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-all-alerts</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-15">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 208px;"><strong>Argument Name</strong></th>
<th style="width: 411px;"><strong>Description</strong></th>
<th style="width: 121px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 208px;">siteName</td>
<td style="width: 411px;">The name of site to get alerts for.</td>
<td style="width: 121px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-15">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 348px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 330px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 348px;">SigSciences.Corp.Site.Alert.ID</td>
<td style="width: 62px;">string</td>
<td style="width: 330px;">The unique ID of the alert.</td>
</tr>
<tr>
<td style="width: 348px;">SigSciences.Corp.Site.Alert.SiteID</td>
<td style="width: 62px;">string</td>
<td style="width: 330px;">The ID of the site.</td>
</tr>
<tr>
<td style="width: 348px;">SigSciences.Corp.Site.Alert.TagName</td>
<td style="width: 62px;">string</td>
<td style="width: 330px;">The name of the tag whose occurrences the alert is watching.</td>
</tr>
<tr>
<td style="width: 348px;">SigSciences.Corp.Site.Alert.LongName</td>
<td style="width: 62px;">string</td>
<td style="width: 330px;">A short description of the alert.</td>
</tr>
<tr>
<td style="width: 348px;">SigSciences.Corp.Site.Alert.Interval</td>
<td style="width: 62px;">number</td>
<td style="width: 330px;">The number of minutes of past traffic to examine.</td>
</tr>
<tr>
<td style="width: 348px;">SigSciences.Corp.Site.Alert.Threshold</td>
<td style="width: 62px;">number</td>
<td style="width: 330px;">The number of occurrences of the tag in the specified interval that are required to trigger the alert.</td>
</tr>
<tr>
<td style="width: 348px;">SigSciences.Corp.Site.Alert.BlockDurationSeconds</td>
<td style="width: 62px;">number</td>
<td style="width: 330px;">The number of seconds this alert is active.</td>
</tr>
<tr>
<td style="width: 348px;">SigSciences.Corp.Site.Alert.SkipNotification</td>
<td style="width: 62px;">boolean</td>
<td style="width: 330px;">A flag to disable external notifications - Slack, webhooks, emails, and so on.</td>
</tr>
<tr>
<td style="width: 348px;">SigSciences.Corp.Site.Alert.Enabled</td>
<td style="width: 62px;">boolean</td>
<td style="width: 330px;">A flag to toggle this alert.</td>
</tr>
<tr>
<td style="width: 348px;">SigSciences.Corp.Site.Alert.Action</td>
<td style="width: 62px;">string</td>
<td style="width: 330px;">A flag that describes what happens when the alert is triggered.</td>
</tr>
<tr>
<td style="width: 348px;">SigSciences.Corp.Site.Alert.CreatedDate</td>
<td style="width: 62px;">date</td>
<td style="width: 330px;">The timestamp of event (RFC3339 format).</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-14">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-get-all-alerts siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-8">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SigSciences.Corp.Site.Alert": [
        {
            "LongName": "ggggg", 
            "SkipNotifications": "", 
            "Interval": 10, 
            "Enabled": true, 
            "Threshold": 40, 
            "SiteID": "", 
            "TagName": "SQLI", 
            "CreatedDate": "2019-03-28T09:09:09Z", 
            "Action": "flagged", 
            "ID": "5c9c8f35c7213901971d2e5a", 
            "BlockDurationSeconds": ""
        }, 
        {
            "LongName": "The site's Online Agent count is zero", 
            "SkipNotifications": "", 
            "Interval": 5, 
            "Enabled": false, 
            "Threshold": 0, 
            "SiteID": "", 
            "TagName": "agent_count", 
            "CreatedDate": "2018-08-30T21:00:03Z", 
            "Action": "siteMetricInfo", 
            "ID": "5b885ad33be3360a3f80237c", 
            "BlockDurationSeconds": 21600
        }, 
        {
            "LongName": "The average RPS across all agents is less than 10", 
            "SkipNotifications": "", 
            "Interval": 5, 
            "Enabled": false, 
            "Threshold": 3000, 
            "SiteID": "", 
            "TagName": "requests_total", 
            "CreatedDate": "2018-08-30T21:00:03Z", 
            "Action": "siteMetricInfo", 
            "ID": "5b885ad33be3360a3f80237b", 
            "BlockDurationSeconds": 21600
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-8">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="signal-sciences---alert-list">Signal Sciences - Alert list</h3>
</div>
<div class="cl-preview-section">
<p>Number of alerts in site: 3</p>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Created Date</th>
<th>Tag Name</th>
<th>Action</th>
<th>Long Name</th>
<th>Interval (In Minutes)</th>
<th>Threshold</th>
<th>Block Duration Seconds</th>
<th>Enabled</th>
</tr>
</thead>
<tbody>
<tr>
<td>5c9c8f35c7213901971d2e5a</td>
<td>2019-03-28T09:09:09Z</td>
<td>SQLI</td>
<td>flagged</td>
<td>ggggg</td>
<td>10</td>
<td>40</td>
<td> </td>
<td>true</td>
</tr>
<tr>
<td>5b885ad33be3360a3f80237c</td>
<td>2018-08-30T21:00:03Z</td>
<td>agent_count</td>
<td>siteMetricInfo</td>
<td>The site’s Online Agent count is zero</td>
<td>5</td>
<td>0</td>
<td>21600</td>
<td>false</td>
</tr>
<tr>
<td>5b885ad33be3360a3f80237b</td>
<td>2018-08-30T21:00:03Z</td>
<td>requests_total</td>
<td>siteMetricInfo</td>
<td>The average RPS across all agents is less than 10</td>
<td>5</td>
<td>3000</td>
<td>21600</td>
<td>false</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-all-lists-for-a-site">17. Get all lists for a site</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves all site lists for a given site.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-16">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-all-site-lists</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-16">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 191px;"><strong>Argument Name</strong></th>
<th style="width: 440px;"><strong>Description</strong></th>
<th style="width: 109px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 191px;">siteName</td>
<td style="width: 440px;">The name of the site to retrieve lists for.</td>
<td style="width: 109px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-16">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 286px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 396px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 286px;">SigSciences.Corp.Site.List.Name</td>
<td style="width: 58px;">string</td>
<td style="width: 396px;">The name of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 286px;">SigSciences.Corp.Site.List.Type</td>
<td style="width: 58px;">string</td>
<td style="width: 396px;">The type of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 286px;">SigSciences.Corp.Site.List.Entries</td>
<td style="width: 58px;">unknown</td>
<td style="width: 396px;">The entry list of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 286px;">SigSciences.Corp.Site.List.ID</td>
<td style="width: 58px;">string</td>
<td style="width: 396px;">The ID of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 286px;">SigSciences.Corp.Site.List.Description</td>
<td style="width: 58px;">string</td>
<td style="width: 396px;">The description of the list in Signal Sciences. Maximum is 140 characters.</td>
</tr>
<tr>
<td style="width: 286px;">SigSciences.Corp.Site.List.CreatedBy</td>
<td style="width: 58px;">string</td>
<td style="width: 396px;">The creator of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 286px;">SigSciences.Corp.Site.List.CreatedDate</td>
<td style="width: 58px;">string</td>
<td style="width: 396px;">The creation date of the list in Signal Sciences.</td>
</tr>
<tr>
<td style="width: 286px;">SigSciences.Corp.Site.List.UpdatedDate</td>
<td style="width: 58px;">string</td>
<td style="width: 396px;">The last update date of the list in Signal Sciences.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-15">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-get-all-site-lists siteName=demisto</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-9">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SigSciences.Corp.Site.List": [
        {
            "Name": "sitelistdoc", 
            "CreatedDate": "2019-03-28T09:52:55Z", 
            "UpdatedDate": "2019-03-28T09:52:55Z", 
            "CreatedBy": "user@demisto.com", 
            "Entries": [
                "56.1.1.1"
            ], 
            "Type": "ip", 
            "ID": "site.sitelistdoc", 
            "Description": ""
        }, 
        {
            "Name": "sitelistdoc3", 
            "CreatedDate": "2019-03-28T09:20:34Z", 
            "UpdatedDate": "2019-03-28T13:30:41Z", 
            "CreatedBy": "user@demisto.com", 
            "Entries": [
                "6.1.7.1", 
                "77.8.77.8"
            ], 
            "Type": "ip", 
            "ID": "site.sitelistdoc3", 
            "Description": ""
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-9">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="signal-sciences---list-of-site-lists">Signal Sciences - list of site lists</h3>
</div>
<div class="cl-preview-section">
<p>Number of site lists in site: 2</p>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Name</th>
<th>ID</th>
<th>Type</th>
<th>Entries</th>
<th>Created By</th>
<th>Created Date</th>
<th>Updated Date</th>
</tr>
</thead>
<tbody>
<tr>
<td>sitelistdoc</td>
<td>site.sitelistdoc</td>
<td>ip</td>
<td>56.1.1.1</td>
<td>user@demisto.com</td>
<td>2019-03-28T09:52:55Z</td>
<td>2019-03-28T09:52:55Z</td>
</tr>
<tr>
<td>sitelistdoc3</td>
<td>site.sitelistdoc3</td>
<td>ip</td>
<td>6.1.7.1,<br> 77.8.77.8</td>
<td>user@demisto.com</td>
<td>2019-03-28T09:20:34Z</td>
<td>2019-03-28T13:30:41Z</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="create-a-corp-list">18. Create a corp list</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Creates a new corp list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-17">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-create-corp-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-17">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 153px;"><strong>Argument Name</strong></th>
<th style="width: 508px;"><strong>Description</strong></th>
<th style="width: 79px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153px;">list_name</td>
<td style="width: 508px;">A name for the new list.</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">list_type</td>
<td style="width: 508px;">The type for the new list (“IP”, “String”, “Country”, or “Wildcard”).</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">entries_list</td>
<td style="width: 508px;">A CSV list of values, consistent with the list’s type.</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">description</td>
<td style="width: 508px;">Short text that describes the new list.</td>
<td style="width: 79px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-17">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 338px;"><strong>Path</strong></th>
<th style="width: 94px;"><strong>Type</strong></th>
<th style="width: 308px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.Name</td>
<td style="width: 94px;">string</td>
<td style="width: 308px;">The name of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.Type</td>
<td style="width: 94px;">string</td>
<td style="width: 308px;">The type of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.Entries</td>
<td style="width: 94px;">unknown</td>
<td style="width: 308px;">The entry list of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.ID</td>
<td style="width: 94px;">string</td>
<td style="width: 308px;">The ID of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.Description</td>
<td style="width: 94px;">string</td>
<td style="width: 308px;">The description of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.CreatedBy</td>
<td style="width: 94px;">string</td>
<td style="width: 308px;">The creator of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.CreatedDate</td>
<td style="width: 94px;">string</td>
<td style="width: 308px;">The creation date of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.UpdatedDate</td>
<td style="width: 94px;">string</td>
<td style="width: 308px;">The last update date of the list.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-16">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-create-corp-list entries_list=3.5.3.5 list_name=fordoc list_type=IP</pre>
</div>
<div class="cl-preview-section">
<h3 id="get-information-for-a-corp-list">19. Get information for a corp list</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves all data about a given corp list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-18">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-corp-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-18">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 216px;"><strong>Argument Name</strong></th>
<th style="width: 400px;"><strong>Description</strong></th>
<th style="width: 124px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 216px;">list_id</td>
<td style="width: 400px;">The ID of the list to get data for.</td>
<td style="width: 124px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-18">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 340px;"><strong>Path</strong></th>
<th style="width: 92px;"><strong>Type</strong></th>
<th style="width: 308px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 340px;">SigSciences.Corp.List.Name</td>
<td style="width: 92px;">unknown</td>
<td style="width: 308px;">The name of the list.</td>
</tr>
<tr>
<td style="width: 340px;">SigSciences.Corp.List.Type</td>
<td style="width: 92px;">unknown</td>
<td style="width: 308px;">The type of the list.</td>
</tr>
<tr>
<td style="width: 340px;">SigSciences.Corp.List.Entries</td>
<td style="width: 92px;">unknown</td>
<td style="width: 308px;">The entry list of the list.</td>
</tr>
<tr>
<td style="width: 340px;">SigSciences.Corp.List.ID</td>
<td style="width: 92px;">unknown</td>
<td style="width: 308px;">The ID of the list.</td>
</tr>
<tr>
<td style="width: 340px;">SigSciences.Corp.List.Description</td>
<td style="width: 92px;">unknown</td>
<td style="width: 308px;">The description of the list.</td>
</tr>
<tr>
<td style="width: 340px;">SigSciences.Corp.List.CreatedBy</td>
<td style="width: 92px;">unknown</td>
<td style="width: 308px;">The creator of the list.</td>
</tr>
<tr>
<td style="width: 340px;">SigSciences.Corp.List.CreatedDate</td>
<td style="width: 92px;">unknown</td>
<td style="width: 308px;">The creation date of the list.</td>
</tr>
<tr>
<td style="width: 340px;">SigSciences.Corp.List.UpdatedDate</td>
<td style="width: 92px;">unknown</td>
<td style="width: 308px;">The last update date of the list.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-17">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-get-corp-list list_id=corp.fordoc2</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-10">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SigSciences.Corp.List": {
        "Name": "fordoc2", 
        "CreatedDate": "2019-03-28T09:14:43Z", 
        "UpdatedDate": "2019-03-28T09:53:14Z", 
        "CreatedBy": "user@demisto.com", 
        "Entries": [
            "44.2.44.2", 
            "55.7.55.7"
        ], 
        "Type": "ip", 
        "ID": "corp.fordoc2", 
        "Description": ""
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-10">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="found-data-about-list-with-id-corp.fordoc2">Found data about list with ID: corp.fordoc2</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Name</th>
<th>ID</th>
<th>Type</th>
<th>Entries</th>
<th>Created By</th>
<th>Created Date</th>
<th>Updated Date</th>
</tr>
</thead>
<tbody>
<tr>
<td>fordoc2</td>
<td>corp.fordoc2</td>
<td>ip</td>
<td>44.2.44.2,<br> 55.7.55.7</td>
<td>user@demisto.com</td>
<td>2019-03-28T09:14:43Z</td>
<td>2019-03-28T09:53:14Z</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="delete-a-corp-list">20. Delete a corp list</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes a given corp list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-19">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-delete-corp-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-19">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 238px;"><strong>Argument Name</strong></th>
<th style="width: 366px;"><strong>Description</strong></th>
<th style="width: 136px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 238px;">list_id</td>
<td style="width: 366px;">The ID of the list to delete.</td>
<td style="width: 136px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-19">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-18">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-delete-corp-list list_id=corp.maya</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-11">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="update-a-corp-list">21. Update a corp list</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Updates (add or delete) entries for a given corp list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-20">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-update-corp-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-20">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 522px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">list_id</td>
<td style="width: 522px;">The ID of the list you wish to update</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">method</td>
<td style="width: 522px;">The method to use - must be “Add” or “Remove”. The method will determine whether the entries you provide are added to the list or removed from it</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">entries_list</td>
<td style="width: 522px;">A list of values, consistent with the list’s type, separated by commas</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">description</td>
<td style="width: 522px;">A description for the updated list.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-20">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 333px;"><strong>Path</strong></th>
<th style="width: 99px;"><strong>Type</strong></th>
<th style="width: 308px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 333px;">SigSciences.Corp.List.Name</td>
<td style="width: 99px;">unknown</td>
<td style="width: 308px;">The name of the list.</td>
</tr>
<tr>
<td style="width: 333px;">SigSciences.Corp.List.Type</td>
<td style="width: 99px;">unknown</td>
<td style="width: 308px;">The type of the list.</td>
</tr>
<tr>
<td style="width: 333px;">SigSciences.Corp.List.Entries</td>
<td style="width: 99px;">unknown</td>
<td style="width: 308px;">The entry list of the list.</td>
</tr>
<tr>
<td style="width: 333px;">SigSciences.Corp.List.ID</td>
<td style="width: 99px;">unknown</td>
<td style="width: 308px;">The ID of the list.</td>
</tr>
<tr>
<td style="width: 333px;">SigSciences.Corp.List.Description</td>
<td style="width: 99px;">unknown</td>
<td style="width: 308px;">The description of the list.</td>
</tr>
<tr>
<td style="width: 333px;">SigSciences.Corp.List.CreatedBy</td>
<td style="width: 99px;">unknown</td>
<td style="width: 308px;">The creator of the list.</td>
</tr>
<tr>
<td style="width: 333px;">SigSciences.Corp.List.CreatedDate</td>
<td style="width: 99px;">unknown</td>
<td style="width: 308px;">The creation date of the list.</td>
</tr>
<tr>
<td style="width: 333px;">SigSciences.Corp.List.UpdatedDate</td>
<td style="width: 99px;">unknown</td>
<td style="width: 308px;">The last update date of the list.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-19">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!sigsci-update-corp-list entries_list=55.7.55.7 list_id=corp.fordoc2 method=Add</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-12">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SigSciences.Corp.List": {
        "Name": "fordoc2", 
        "CreatedDate": "2019-03-28T09:14:43Z", 
        "UpdatedDate": "2019-03-28T09:53:14Z", 
        "CreatedBy": "user@demisto.com", 
        "Entries": [
            "44.2.44.2", 
            "55.7.55.7"
        ], 
        "Type": "ip", 
        "ID": "corp.fordoc2", 
        "Description": ""
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-12">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="signal-sciences---updating-a-list-1">Signal Sciences - Updating a list</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Name</th>
<th>ID</th>
<th>Type</th>
<th>Entries</th>
<th>Created By</th>
<th>Created Date</th>
<th>Updated Date</th>
</tr>
</thead>
<tbody>
<tr>
<td>fordoc2</td>
<td>corp.fordoc2</td>
<td>ip</td>
<td>44.2.44.2,<br> 55.7.55.7</td>
<td>user@demisto.com</td>
<td>2019-03-28T09:14:43Z</td>
<td>2019-03-28T09:53:14Z</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-information-for-all-lists-of-a-corp">22. Get information for all lists of a corp</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves data about all lists for the given corp.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-21">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-all-corp-lists</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-21">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-21">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 338px;"><strong>Path</strong></th>
<th style="width: 94px;"><strong>Type</strong></th>
<th style="width: 308px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.Name</td>
<td style="width: 94px;">unknown</td>
<td style="width: 308px;">The name of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.Type</td>
<td style="width: 94px;">unknown</td>
<td style="width: 308px;">The type of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.Entries</td>
<td style="width: 94px;">unknown</td>
<td style="width: 308px;">The entry list of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.ID</td>
<td style="width: 94px;">unknown</td>
<td style="width: 308px;">The ID of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.Description</td>
<td style="width: 94px;">unknown</td>
<td style="width: 308px;">The description of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.CreatedBy</td>
<td style="width: 94px;">unknown</td>
<td style="width: 308px;">The creator of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.CreatedDate</td>
<td style="width: 94px;">unknown</td>
<td style="width: 308px;">The creation date of the list.</td>
</tr>
<tr>
<td style="width: 338px;">SigSciences.Corp.List.UpdatedDate</td>
<td style="width: 94px;">unknown</td>
<td style="width: 308px;">The last update date of the list.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-events">23. Get a list of events</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Fetches events from Signal Sciences.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-22">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-fetch-events</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-22">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 175px;"><strong>Argument Name</strong></th>
<th style="width: 464px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 175px;">siteName</td>
<td style="width: 464px;">The name of the site to fetch events from.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 175px;">from_time</td>
<td style="width: 464px;">The POSIX Unix time to start.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">until_time</td>
<td style="width: 464px;">The POSIX Unix time to end.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">sort</td>
<td style="width: 464px;">The sort order (“asc” or “desc”).</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">since_id</td>
<td style="width: 464px;">The ID of the first object in the set.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">max_id</td>
<td style="width: 464px;">The ID of the last object in the set.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">limit</td>
<td style="width: 464px;">The maximum number of entries to return.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">page</td>
<td style="width: 464px;">The page of the results.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">action</td>
<td style="width: 464px;">The action to filter by (‘flagged’ or ‘info’).</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">tag</td>
<td style="width: 464px;">The tag to filter by. Must be a valid tag name.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">ip</td>
<td style="width: 464px;">The ID to filter by.</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">status</td>
<td style="width: 464px;">The status to filter by (“active” or “expired”).</td>
<td style="width: 101px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-22">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 355px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 327px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.ID</td>
<td style="width: 58px;">string</td>
<td style="width: 327px;">The unique ID of the event.</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.Timestamp</td>
<td style="width: 58px;">date</td>
<td style="width: 327px;">The timestamp of the event (RFC3339 format).</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.Source</td>
<td style="width: 58px;">string</td>
<td style="width: 327px;">The source information, for example, “IP”.</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.RemoteCountryCode</td>
<td style="width: 58px;">string</td>
<td style="width: 327px;">The country code.</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.RemoteHostname</td>
<td style="width: 58px;">string</td>
<td style="width: 327px;">The remote hostname.</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.UserAgents</td>
<td style="width: 58px;">unknown</td>
<td style="width: 327px;">An array of user agents.</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.Action</td>
<td style="width: 58px;">unknown</td>
<td style="width: 327px;">If “flagged”, the IP address is flagged and subsequent malicious requests will be blocked. If “info”, the IP address is flagged and subsequent requests will be logged.</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.Reasons</td>
<td style="width: 58px;">unknown</td>
<td style="width: 327px;">The reason the event was triggered.</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.RequestCount</td>
<td style="width: 58px;">number</td>
<td style="width: 327px;">The total number of requests.</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.TagCount</td>
<td style="width: 58px;">number</td>
<td style="width: 327px;">The total number of tags.</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.Window</td>
<td style="width: 58px;">number</td>
<td style="width: 327px;">The time window (in seconds) when the items were detected.</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.DateExpires</td>
<td style="width: 58px;">string</td>
<td style="width: 327px;">The date the event expires (RFC3339 format).</td>
</tr>
<tr>
<td style="width: 355px;">SigSciences.Corp.Site.Event.ExpiredBy</td>
<td style="width: 58px;">string</td>
<td style="width: 327px;">The email address of the user that expired the event (if the event is expired manually).</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-an-event-by-event-id">24. Get an event by event ID</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves an event by the event ID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-23">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-event-by-id</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-23">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 196px;"><strong>Argument Name</strong></th>
<th style="width: 431px;"><strong>Description</strong></th>
<th style="width: 113px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 196px;">siteName</td>
<td style="width: 431px;">Name of the site to get the event from</td>
<td style="width: 113px;">Required</td>
</tr>
<tr>
<td style="width: 196px;">event_id</td>
<td style="width: 431px;">The ID of the event.</td>
<td style="width: 113px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-23">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 346px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 327px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.ID</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">The unique ID of the event.</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.Timestamp</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">The timestamp of the event (RFC3339 format).</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.Source</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">Source information, for example, “IP”.</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.RemoteCountryCode</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">The country code.</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.RemoteHostname</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">The remote hostname.</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.UserAgents</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">An array of user agents.</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.Action</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">If “flagged”, the IP address is flagged and subsequent malicious requests will be blocked. If “info”, the IP address is flagged and subsequent requests will be logged.</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.Reasons</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">The reason the event was triggered.</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.RequestCount</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">The total number of requests.</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.TagCount</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">The total number of tags.</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.Window</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">The time window (in seconds) when the items were detected.</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.DateExpires</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">The date the event expires (RFC3339 format).</td>
</tr>
<tr>
<td style="width: 346px;">SigSciences.Corp.Site.Event.ExpiredBy</td>
<td style="width: 67px;">unknown</td>
<td style="width: 327px;">The email address of the user that expired the event (if the event is expired manually).</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="expire-an-event">25. Expire an event</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Expires a given event.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-24">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-expire-event</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-24">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 179px;"><strong>Argument Name</strong></th>
<th style="width: 459px;"><strong>Description</strong></th>
<th style="width: 102px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 179px;">siteName</td>
<td style="width: 459px;">The name of the site to expire an event from.</td>
<td style="width: 102px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">event_id</td>
<td style="width: 459px;">The ID of the event to expire.</td>
<td style="width: 102px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-requests-for-a-site">26. Get requests for a site</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves requests from a given site according to a search query.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-25">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-requests</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-25">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 155px;"><strong>Argument Name</strong></th>
<th style="width: 514px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">siteName</td>
<td style="width: 514px;">The name of the site to get requests from.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">page</td>
<td style="width: 514px;">The page of the results. Maximum is 1000 requests.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">limit</td>
<td style="width: 514px;">The number of entries to return.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">q</td>
<td style="width: 514px;">The search query, in Signal Sciences syntax. If a query is not supplied, no requests will be returned.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-24">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 362px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 310px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.ID</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The unique ID of the request.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.ServerHostName</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The server hostname.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.RemoteIP</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The remote IP address.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.RemoteHostName</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The remote hostname.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.RemoteCountryCode</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The remote country code.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.UserAgent</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The user agent of the request.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.Timestamp</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The timestamp (RFC3339 format).</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.Method</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The HTTP method, for example, “PUT”.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.ServerName</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The server name.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.Protocol</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The HTTP protocol, for example, “HTTP/1.1” .</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.Path</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The path.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.URI</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The URI.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.ResponseCode</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The HTTP response code.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.ResponseSize</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The HTTP response size.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.ResponseMillis</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The response time in millis.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.AgentResponseCode</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The agent response code.</td>
</tr>
<tr>
<td style="width: 362px;">SigSciences.Corp.Site.Request.Tags</td>
<td style="width: 68px;">unknown</td>
<td style="width: 310px;">The array of relevant tags.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-request-by-request-id">27. Get a request by request ID</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves a request by request ID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-26">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>sigsci-get-request-by-id</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-26">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 213px;"><strong>Argument Name</strong></th>
<th style="width: 405px;"><strong>Description</strong></th>
<th style="width: 122px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 213px;">siteName</td>
<td style="width: 405px;">The name of the site to get from.</td>
<td style="width: 122px;">Required</td>
</tr>
<tr>
<td style="width: 213px;">request_id</td>
<td style="width: 405px;">The ID of the request to get.</td>
<td style="width: 122px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-25">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 361px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 310px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.ID</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The unique ID of the request.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.ServerHostName</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">Server hostname.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.RemoteIP</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The remote IP address.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.RemoteHostName</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The remote hostname.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.RemoteCountryCode</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The remote country code.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.UserAgent</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The user agent of the request.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.Timestamp</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The timestamp RFC3339 date time serverHostname string.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.Method</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The HTTP method, for example, “PUT”.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.ServerName</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The server name.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.Protocol</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The HTTP protocol, for example “HTTP/1.1”.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.Path</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The path.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.URI</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The URI.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.ResponseCode</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The HTTP response code.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.ResponseSize</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The HTTP response size.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.ResponseMillis</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The response time in milliseconds.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.AgentResponseCode</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">The agent response code.</td>
</tr>
<tr>
<td style="width: 361px;">SigSciences.Corp.Site.Request.Tags</td>
<td style="width: 69px;">unknown</td>
<td style="width: 310px;">An array of relevant tags.</td>
</tr>
</tbody>
</table>
</div>
</div>