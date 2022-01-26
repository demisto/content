<!-- HTML_DOC -->
<p>Use the ThreatX integration to enrich intel and automate enforcement actions on the ThreatX Next Gen WAF.</p>
<p> </p>
<h2>Use Cases</h2>
<ul>
<li>Add and remove CIDR ranges and IP addresses to various block lists or the allow list</li>
<li>Gather Entity metadata for intel enrichment and DBot scoring</li>
<li>Set Entity notes for SOC integration or further automation</li>
</ul>
<p> </p>
<h2>Configure ThreatX on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for ThreatX.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Customer Name</strong>: Contact the ThreatX SOC for your Customer Name</li>
<li><strong>ThreatX Server URL (e.g., https://provision.threatx.io/ )</strong></li>
<li>
<strong>API Key</strong>: Contact the ThreatX SOC for your API Key</li>
<li>
<strong>DBot Score Threshold</strong>: Set the threshold ThreatX Risk score (1 to 100) which will be translated to Malicious DBot scores. Default is 70.</li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<p> </p>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<p> </p>
<ol>
<li><a href="#h_59c15eb9-7d02-4619-bf4c-928361850aed" target="_self">Temporarily block an IP address or CIDR: threatx-block-ip</a></li>
<li><a href="#h_4a194e38-057c-458d-9a99-1be7321f3824" target="_self">Unblock an IP address or CIDR: threatx-unblock-ip</a></li>
<li><a href="#h_b6f120d1-595a-46a0-b881-c768cb198c85" target="_self">Block list an IP address or CIDR: threatx-blacklist-ip</a></li>
<li><a href="#h_1f19f572-dfb3-46b4-a19d-b3a883af1ddc" target="_self">Remove an IP address or CIDR from the block list: threatx-unblacklist-ip</a></li>
<li><a href="#h_4c6d37d6-b0d3-4cb0-8b4f-1d27f8b0773f" target="_self">Add an IP address or CIDR to allow list: threatx-whitelist-ip</a></li>
<li><a href="#h_3de39027-25e1-47c2-94a1-3273d5a306ea" target="_self">Remove an IP address or CIDR from the allow list: threatx-unwhitelist-ip</a></li>
<li><a href="#h_2ef4b677-f78b-4551-9145-62cf54e475c0" target="_self">Get entity information: threatx-get-entities</a></li>
<li><a href="#h_882e9901-cf9e-4022-925f-7fffe952f323" target="_self">Get entity notes: threatx-get-entity-notes</a></li>
<li><a href="#h_5f86c9a3-44b4-40ab-b81d-8c5ce83a2efe" target="_self">Add a note to an entity: threatx-add-entity-note</a></li>
</ol>
<p> </p>
<h3 id="h_59c15eb9-7d02-4619-bf4c-928361850aed">1. Temporarily block an IP address or CIDR</h3>
<hr>
<p> </p>
<p>Temporarily blocks an IP address or CIDR.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>threatx-block-ip</code></p>
<p> </p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 511px;"><strong>Description</strong></th>
<th style="width: 83px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">ip</td>
<td style="width: 511px;">IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".</td>
<td style="width: 83px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">description</td>
<td style="width: 511px;">The description of the IP record in the block list. The default value is: "Added by ThreatX Cortex XSOAR Integration".</td>
<td style="width: 83px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output </h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 139px;"><strong>Path</strong></th>
<th style="width: 88px;"><strong>Type</strong></th>
<th style="width: 513px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">IP.Address</td>
<td style="width: 88px;">string</td>
<td style="width: 513px;">IP address or CIDR that was blocked.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example </h5>
<pre>!threatx-block-ip ip=12.12.12.12
</pre>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "IP": [
        {
            "Address": "12.12.12.12"
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>Result</th>
</tr>
</thead>
<tbody>
<tr>
<td>Blocklist entry for ip 12.12.12.12 added</td>
</tr>
</tbody>
</table>
<p>  </p>
<h3 id="h_4a194e38-057c-458d-9a99-1be7321f3824">2. Unblock an IP address or CIDR</h3>
<hr>
<p>Unblocks a blocked IP address or CIDR.</p>
<h5>Base Command</h5>
<p><code>threatx-unblock-ip</code></p>
<h5>Input </h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 152px;"><strong>Argument Name</strong></th>
<th style="width: 505px;"><strong>Description</strong></th>
<th style="width: 83px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 152px;">ip</td>
<td style="width: 505px;">IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".</td>
<td style="width: 83px;">Required</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 134px;"><strong>Path</strong></th>
<th style="width: 83px;"><strong>Type</strong></th>
<th style="width: 523px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">IP.Address</td>
<td style="width: 83px;">string</td>
<td style="width: 523px;">IP address or CIDR that was unblocked.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example </h5>
<pre>!threatx-unblock-ip ip=12.12.12.12
</pre>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "IP": [
        {
            "Address": "12.12.12.12"
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<table>
<thead>
<tr>
<th>Result</th>
</tr>
</thead>
<tbody>
<tr>
<td>Block list entry for ip 12.12.12.12 removed</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_b6f120d1-595a-46a0-b881-c768cb198c85">3. Block list an IP address or CIDR </h3>
<hr>
<p>Adds an IP address or CIDR to the block list. </p>
<h5>Base Command</h5>
<p><code>threatx-blacklist-ip</code></p>
<h5>Input</h5>
<table style="width: 647px;">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 430px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">ip</td>
<td style="width: 430px;">IP address or CIDR in CSV format, for example: "10.1.1.1,10.1.1.0/24".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">description</td>
<td style="width: 511px;">The description of the IP record in the block list. The default value is: "Added by ThreatX Cortex XSOAR Integration".</td>
<td style="width: 83px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 115px;"><strong>Path</strong></th>
<th style="width: 77px;"><strong>Type</strong></th>
<th style="width: 548px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 115px;">IP.Address</td>
<td style="width: 77px;">string</td>
<td style="width: 548px;">IP address or CIDR that was added to the blacklist.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!threatx-blacklist-ip ip=12.12.12.12
</pre>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "IP": [
        {
            "Address": "12.12.12.12"
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>Result</th>
</tr>
</thead>
<tbody>
<tr>
<td>Block list entry for ip 12.12.12.12 added</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_1f19f572-dfb3-46b4-a19d-b3a883af1ddc">4. Remove an IP address or CIDR from the block list</h3>
<hr>
<p>Removes an IP address or CIDR from the block list.</p>
<h5>Base Command</h5>
<p><code>threatx-unblacklist-ip</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 503px;"><strong>Description</strong></th>
<th style="width: 88px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">ip</td>
<td style="width: 503px;">IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".</td>
<td style="width: 88px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output </h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 107px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 565px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 107px;">IP.Address</td>
<td style="width: 68px;">string</td>
<td style="width: 565px;">IP address or CIDR that was removed from the block list.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!threatx-unblacklist-ip ip=12.12.12.12
</pre>
<h5>Context Example</h5>
<pre>{
    "IP": [
        {
            "Address": "12.12.12.12"
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>Result</th>
</tr>
</thead>
<tbody>
<tr>
<td>Block list entry for ip 12.12.12.12 removed</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_4c6d37d6-b0d3-4cb0-8b4f-1d27f8b0773f">5. Add an IP address or CIDR to allow list</h3>
<hr>
<p> Adds an IP address or CIDR to the allow list.</p>
<h5>Base Command</h5>
<p><code>threatx-whitelist-ip</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 148px;"><strong>Argument Name</strong></th>
<th style="width: 509px;"><strong>Description</strong></th>
<th style="width: 83px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">ip</td>
<td style="width: 509px;">IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".</td>
<td style="width: 83px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">description</td>
<td style="width: 511px;">The description of the IP record in the allow list. The default value is: "Added by ThreatX Cortex XSOAR Integration".</td>
<td style="width: 83px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output </h5>
<table style="width: 750px;">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>IP.Address</td>
<td>string</td>
<td>IP address or CIDR was added to the allow list.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example </h5>
<pre>!threatx-whitelist-ip ip=12.12.12.12
</pre>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "IP": [
        {
            "Address": "12.12.12.12"
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>Result</th>
</tr>
</thead>
<tbody>
<tr>
<td>Whitelist entry for ip 12.12.12.12 added</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3de39027-25e1-47c2-94a1-3273d5a306ea">6. Remove an IP address or CIDR from the allow list</h3>
<hr>
<p>Removes an IP address or CIDR from the allow list. </p>
<h5>Base Command</h5>
<p><code>threatx-unwhitelist-ip</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 83px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">ip</td>
<td style="width: 506px;">IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".</td>
<td style="width: 83px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output </h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 102px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 575px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 102px;">IP.Address</td>
<td style="width: 63px;">string</td>
<td style="width: 575px;">IP address or CIDR that was removed from the allow list.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!threatx-unwhitelist-ip ip=12.12.12.12
</pre>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "IP": [
        {
            "Address": "12.12.12.12"
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>Result</th>
</tr>
</thead>
<tbody>
<tr>
<td>Allow list entry for ip 12.12.12.12 removed</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_2ef4b677-f78b-4551-9145-62cf54e475c0">7. Get entity information</h3>
<hr>
<p>Returns high-level entity information by Entity ID, Entity Name, or Entity IP.</p>
<h5>Base Command</h5>
<p><code>threatx-get-entities</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 132px;"><strong>Argument Name</strong></th>
<th style="width: 537px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 132px;">timeframe</td>
<td style="width: 537px;">Look-back timeframe for the query. Options are 1-Hour, 1-Day, 1-Week, 1-Month, or 3-Months. Note: long look-back timeframes for a large number of Entities can timeout.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 132px;">entity_name</td>
<td style="width: 537px;">CSV list of Entity names.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 132px;">entity_id</td>
<td style="width: 537px;">CSV list of Entity ID hashes.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 132px;">entity_ip</td>
<td style="width: 537px;">CSV list of Entity IP addresses.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output </h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 291px;"><strong>Path</strong></th>
<th style="width: 109px;"><strong>Type</strong></th>
<th style="width: 340px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 291px;">Threatx.Entity.ID</td>
<td style="width: 109px;">string</td>
<td style="width: 340px;">ID hash of the Entity</td>
</tr>
<tr>
<td style="width: 291px;">Threatx.Entity.Name</td>
<td style="width: 109px;">string</td>
<td style="width: 340px;">Name of the Entity</td>
</tr>
<tr>
<td style="width: 291px;">Threatx.Entity.IP</td>
<td style="width: 109px;">string</td>
<td style="width: 340px;">IP address of the Entity</td>
</tr>
<tr>
<td style="width: 291px;">Threatx.Entity.Risk</td>
<td style="width: 109px;">integer</td>
<td style="width: 340px;">Risk score of the Entity</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example </h5>
<pre>!threatx-get-entities timeframe=1-Day entity_name=CynicalGraaf,OveconfidentRas
</pre>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Threatx": {
        "Entity": [
            {
                "ID": "1061035762581303669",
                "Name": "OveconfidentRas",
                "Risk": 0,
                "IP": [
                    201.93.212.87
                ]
            },
            {
                "ID": "566056709675514809",
                "Name": "CynicalGraaf",
                "Risk": 0,
                "IP": [
                    1.125.227.13
                ]
            }
        ]
    }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<table style="width: 595px;" border="2">
<thead>
<tr>
<th style="width: 171px;">ThreatX Risk Score</th>
<th style="width: 84px;">IP Addresses</th>
<th style="width: 118px;">Name</th>
<th style="width: 213px;">ID</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 171px;">0</td>
<td style="width: 84px;">201.93.212.87</td>
<td style="width: 118px;">OveconfidentRas</td>
<td style="width: 213px;">1061035762581303669</td>
</tr>
<tr>
<td style="width: 171px;">55</td>
<td style="width: 84px;">1.125.227.13</td>
<td style="width: 118px;">CynicalGraaf</td>
<td style="width: 213px;">566056709675514809</td>
</tr>
</tbody>
</table>
<p>  </p>
<h3 id="h_882e9901-cf9e-4022-925f-7fffe952f323">8. Get entity notes</h3>
<hr>
<p>Returns the notes attached to an entity by Entity ID. </p>
<h5>Base Command</h5>
<p><code>threatx-get-entity-notes</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 470px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">entity_id</td>
<td style="width: 470px;">ID hash of the Entity. To retrieve this value, run the <a href="#h_2ef4b677-f78b-4551-9145-62cf54e475c0" target="_self">threatx-get-entities</a> command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 374px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 286px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 374px;">Threatx.Entity.ID</td>
<td style="width: 80px;">string</td>
<td style="width: 286px;">ID hash of the Entity</td>
</tr>
<tr>
<td style="width: 374px;">Threatx.Entity.Note.content</td>
<td style="width: 80px;">string</td>
<td style="width: 286px;">Content of the Note</td>
</tr>
<tr>
<td style="width: 374px;">Threatx.Entity.Note.timestamp</td>
<td style="width: 80px;">string</td>
<td style="width: 286px;">Timestamp of the Note</td>
</tr>
<tr>
<td style="width: 374px;">Threatx.Entity.Note.username</td>
<td style="width: 80px;">string</td>
<td style="width: 286px;">Author of the Note</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example </h5>
<pre>!threatx-get-entity-notes entity_id=566056709675514809
</pre>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Threatx": {
        "Entity": [
            {
                "ID": "566056709675514809",
                "Note": [
                    {
                        "content": "Demisto test note.",
                        "entity_id": "566056709675514809",
                        "timestamp": "2019-05-31 18:41:09",
                        "username": "user@domain.com"
                    }
                ]
            }
        ]
    }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>Username</th>
<th>Timestamp</th>
<th>Entity Id</th>
<th>Content</th>
</tr>
</thead>
<tbody>
<tr>
<td>user@domain.com</td>
<td>2019-05-31 18:41:09</td>
<td>566056709675514809</td>
<td>Demisto test note.</td>
</tr>
<tr>
<td>user@domain.com</td>
<td>2019-05-30 23:36:23</td>
<td>566056709675514809</td>
<td>this is a test note</td>
</tr>
<tr>
<td>user@domain.com</td>
<td>2019-05-12 21:36:12</td>
<td>566056709675514809</td>
<td>Another test note</td>
</tr>
<tr>
<td>user@domain.com</td>
<td>2019-05-12 21:34:48</td>
<td>566056709675514809</td>
<td>test-note-from-demisto</td>
</tr>
</tbody>
</table>
<p>  </p>
<h3 id="h_5f86c9a3-44b4-40ab-b81d-8c5ce83a2efe">9. Add a note to an entity</h3>
<hr>
<p>Adds a new note to an entity.</p>
<h5>Base Command</h5>
<p><code>threatx-add-entity-note</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 154px;"><strong>Argument Name</strong></th>
<th style="width: 515px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154px;">entity_id</td>
<td style="width: 515px;">ID hash of the Entity. To retrieve this value, run the threatx-get-entities command.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 154px;">message</td>
<td style="width: 515px;">Contents of the note.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command. </p>
<h5>Command Example</h5>
<pre>!threatx-add-entity-note entity_id=566056709675514809 message="test note."
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>Result</th>
</tr>
</thead>
<tbody>
<tr>
<td>Note for Entity&lt;id=566056709675514809&gt; created</td>
</tr>
</tbody>
</table>
