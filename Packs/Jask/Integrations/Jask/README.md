<!-- HTML_DOC -->
<p>Deprecated. Use Sumo Logic Cloud SIEM integration instead. For further details about the migration, visit our <a href="https://xsoar.pan.dev/docs/reference/integrations/sumo-logic-sec#migrating-from-jask-content-pack">Sumo Logic SIEM integration documentation</a>.</p>
<h2>Overview</h2>
<hr>
<p>Use the JASK integration to manage entities, signals, and insights.</p>
<p> </p>
<h2>Configure the JASK Integration on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for JASK.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Override default fetch query</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and token</li>
</ol>
<p> </p>
<h2>Fetched Incidents Data</h2>
<hr>
<p>The integration fetches insights. The first fetch returns insights from the previous 24 hour period. By default, the fetch will fetch all insights with the status <em><strong>new</strong></em> and <em><strong>in-progress</strong></em>. This is a sample default query: workflow_status:(new OR inprogress). You can modify the default query in the <strong><em>Override default fetch query</em></strong> parameter.</p>
<p> </p>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_78423230251533534464758">Get details for an insight: jask-get-insight-details</a></li>
<li><a href="#h_455075379781533534471017">Get comments for an insight: jask-get-insight-comments</a></li>
<li><a href="#h_5004381221501533534476337">Get details for a signal: jask-get-signal-details</a></li>
<li><a href="#h_8236589612211533534481518">Get details for an entity: jask-get-entity-details</a></li>
<li><a href="#h_7145323282911533534488219">Get related entities: jask-get-related-entities</a></li>
<li><a href="#h_8632925473601533534494371">Get a list of entities on allow list: jask-get-whitelisted-entities</a></li>
<li><a href="#h_2458651614281533534504337">Search JASK insights: jask-search-insights</a></li>
<li><a href="#h_3876303084951533534510096">Search JASK signals: jask-search-signals</a></li>
<li><a href="#h_2402374295611533534516772">Search JASK entities: jask-search-entities</a></li>
</ol>
<p> </p>
<h3 id="h_78423230251533534464758">1. Get details for an insight</h3>
<hr>
<p><i>Note:</i> This command is deprecated. Use `sumologic-sec-insight-get-details` command in Sumo Logic SIEM integration. For further details, visit our <a href="https://xsoar.pan.dev/docs/reference/integrations/sumo-logic-sec#migrating-from-jask-content-pack">Sumo Logic SIEM integration documentation</a>.</p>
<p>Returns detailed information for a specified insight.</p>
<p> </p>
<h5>Base Command</h5>
<p><code>jask-get-insight-details</code></p>
<p> </p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Parameter</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>insight-id</td>
<td>The insight to retrieve details for</td>
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
<td>Jask.Insight.Id</td>
<td>Insight ID</td>
</tr>
<tr>
<td>Jask.Insight.Name</td>
<td>Insight name</td>
</tr>
<tr>
<td>Jask.Insight.Action</td>
<td>Insight action</td>
</tr>
<tr>
<td>Jask.Insight.Entity</td>
<td>The main entity related to the insight</td>
</tr>
<tr>
<td>Jask.Insight.AssignedTo</td>
<td>Who the insight was assigned to</td>
</tr>
<tr>
<td>Jask.Insight.Description</td>
<td>Insight description</td>
</tr>
<tr>
<td>Jask.Insight.IpAddress</td>
<td>Insight IP address</td>
</tr>
<tr>
<td>Jask.Insight.LastUpdated</td>
<td>The time the insight was last updated</td>
</tr>
<tr>
<td>Jask.Insight.LastUpdatedBy</td>
<td>The last person to update the insight</td>
</tr>
<tr>
<td>Jask.Insight.Severity</td>
<td>Insight severity</td>
</tr>
<tr>
<td>Jask.Insight.InsightTime</td>
<td>The time of the insight</td>
</tr>
<tr>
<td>Jask.Insight.WorkflowStatus</td>
<td>Insight status</td>
</tr>
<tr>
<td>Jask.Insight.RelatedEntityList.Id</td>
<td>The ID of the related entity</td>
</tr>
<tr>
<td>Jask.Insight.RelatedEntityList.EntityType</td>
<td>Related entity type</td>
</tr>
<tr>
<td>Jask.Insight.RelatedEntityList.Hostname</td>
<td>The hostname of the related entity</td>
</tr>
<tr>
<td>Jask.Insight.SignalList.Id</td>
<td>Signal ID</td>
</tr>
<tr>
<td>Jask.Insight.SignalList.Name</td>
<td>Signal name</td>
</tr>
<tr>
<td>Jask.Insight.SignalList.Category</td>
<td>Signal category</td>
</tr>
<tr>
<td>Jask.Insight.SignalList.SourceType</td>
<td>The source of the signal</td>
</tr>
<tr>
<td>Jask.Insight.SignalListMetadata.Patterns.Count</td>
<td>Number of signals of the category pattern</td>
</tr>
<tr>
<td>Jask.Insight.SignalListMetadata.Anomalies.Count</td>
<td>Number of signals of the category anomaly</td>
</tr>
<tr>
<td>Jask.Insight.SignalListMetadata.ThreatIntel.Count</td>
<td>Number of signals of the category threat intelligence</td>
</tr>
<tr>
<td>Jask.Insight.RelatedEntityList.IpAddress</td>
<td>IP address of the related entity</td>
</tr>
<tr>
<td>Jask.Insight.RelatedEntityList.IsWhitelisted</td>
<td>Whether or not the entity is on allow list</td>
</tr>
<tr>
<td>Jask.Insight.RelatedEntityList.RiskScore</td>
<td>The risk score of the related entity</td>
</tr>
<tr>
<td>Jask.Insight.RelatedEntityList.Source</td>
<td>The source of the related entity</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!jask-get-insight-details insight-id="7ead8dc9-d541-3484-9320-ea593729e7cc"</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Jask": {
        "Insight": {
            "SignalListMetadata": {
                "Patterns": {
                    "Count": 4
                }, 
                "ThreatIntel": {
                    "Count": 0
                }, 
                "Anomalies": {
                    "Count": 0
                }
            }, 
            "WorkflowStatus": "new", 
            "Description": "Exfiltration, C2 Risk Score: 14", 
            "IpAddress": "104.236.54.196", 
            "Severity": 2, 
            "RelatedEntityList": [], 
            "LastUpdated": "2018-07-13T05:17:55.620330", 
            "EntityDetails": {
                "EntityType": "ip", 
                "Name": "^^^104.236.54.196^^^", 
                "RiskScore": 9, 
                "Hostname": "Unknown", 
                "Source": "discovery", 
                "LastSeen": "Sun, 05 Aug 2018 10:00:56 GMT", 
                "PrimaryEntityType": null, 
                "IpAddress": "^^^104.236.54.196^^^", 
                "Id": "7ead8dc9-d541-3484-9320-ea593729e7cc", 
                "FirstSeen": "Wed, 14 Feb 2018 19:54:31 GMT"
            }, 
            "InsightTime": "2018-07-11T18:59:12", 
            "Id": "7ead8dc9-d541-3484-9320-ea593729e7cc", 
            "SignalList": [
                {
                    "Category": "Exfiltration", 
                    "Name": "Hexadecimal in DNS Query Domain", 
                    "Timestamp": "2018-07-11T19:06:14", 
                    "ThreatIndicators": [
                        {
                            "Value": "analytics-9dd8570e3fd957ce828c34761a8e98b8.xyz", 
                            "IndicatorType": "hostname"
                        }
                    ], 
                    "Score": "2", 
                    "Description": "Encoding in hexadecimal is a way that attackers can bypass network security devices that are inspecting traffic.  While hexadecimal often appears in subdomains, it much less frequent in domains.", 
                    "Id": "b7f76616-f27b-5c18-b503-2d3dbab1bb96", 
                    "SourceType": "rule"
                }, 
                {
                    "Category": "C2", 
                    "Name": "TeslaCrypt Ransomware Domain", 
                    "Timestamp": "2018-07-11T19:51:16", 
                    "ThreatIndicators": [
                        {
                            "Value": "o4dm3.leaama.at", 
                            "IndicatorType": "hostname"
                        }
                    ], 
                    "Score": "6", 
                    "Description": "TeslaCrypt is a ransomware that encrypts documents, databases, code, bitcoin wallets and more. This rule looks for DNS queries that include domains known to be associated with TeslaCrypt.", 
                    "Id": "67b2ba91-9c32-5ffb-9587-873ef68f7899", 
                    "SourceType": "rule"
                }, 
                {
                    "Category": "C2", 
                    "Name": "TeslaCrypt Ransomware Domain", 
                    "Timestamp": "2018-07-11T19:51:17", 
                    "ThreatIndicators": [
                        {
                            "Value": "kbv5s.kylepasse.at", 
                            "IndicatorType": "hostname"
                        }
                    ], 
                    "Score": "6", 
                    "Description": "TeslaCrypt is a ransomware that encrypts documents, databases, code, bitcoin wallets and more. This rule looks for DNS queries that include domains known to be associated with TeslaCrypt.", 
                    "Id": "26fc053b-ad5f-5f39-8e48-12feb39b77d2", 
                    "SourceType": "rule"
                }, 
                {
                    "Category": "C2", 
                    "Name": "TorrentLocker Ransomware Domain", 
                    "Timestamp": "2018-07-11T19:51:19", 
                    "ThreatIndicators": [
                        {
                            "Value": "mz7oyb3v32vshcvk.tormidle.at", 
                            "IndicatorType": "hostname"
                        }
                    ], 
                    "Score": "6", 
                    "Description": "TorrentLocker is a ransomware that encrypts documents, databases, code, bitcoin wallets and more. This rule looks for DNS queries that include domains known to be associated with TorrentLocker.", 
                    "Id": "7ed97e33-73fd-599c-9c55-6c89aa0e7bf3", 
                    "SourceType": "rule"
                }
            ], 
            "Name": "Possible Malware - Ransomware (TeslaCrypt) and Data Exfiltration"
        }
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/7270217/43684921-fbe92ade-98b1-11e8-9794-92f65a727065.png" width="753" height="396"></p>
<p><img src="https://user-images.githubusercontent.com/7270217/43684938-6d4f3222-98b2-11e8-9601-a301bea40052.png" width="753" height="419"></p>
<p> </p>
<h3 id="h_455075379781533534471017">2. Get comments for an insight</h3>
<hr>
<p><i>Note:</i> This command is deprecated. Use `sumologic-sec-insight-get-comments` command in Sumo Logic SIEM integration. For further details, visit our <a href="https://xsoar.pan.dev/docs/reference/integrations/sumo-logic-sec#migrating-from-jask-content-pack">Sumo Logic SIEM integration documentation</a>.</p>
<p>Returns comments for a specified insight.</p>
<p> </p>
<h5>Base Command</h5>
<p><code>jask-get-insight-comments</code></p>
<p> </p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<th><strong>Parameter</strong></th>
<th><strong>Description</strong></th>
</tr>
<tr>
<td>insight-id</td>
<td>The insight to retrieve comments for</td>
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
<td>Jask.InsightCommentList.id</td>
<td>Comment ID</td>
</tr>
<tr>
<td>Jask.InsightCommentList.InsightId</td>
<td>Insight ID</td>
</tr>
<tr>
<td>Jask.InsightCommentList.Author</td>
<td>Author of comment</td>
</tr>
<tr>
<td>Jask.InsightCommentList.Body</td>
<td>Comment body</td>
</tr>
<tr>
<td>Jask.InsightCommentList.LastUpdated</td>
<td>The date the comment was last updated</td>
</tr>
<tr>
<td>Jask.InsightCommentList.Timestamp</td>
<td>The time of the comment</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>asdf</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>asdf</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p>asdf</p>
<p> </p>
<h3 id="h_5004381221501533534476337">3. Get details for a signal</h3>
<hr>
<p><i>Note:</i> This command is deprecated. Use `sumologic-sec-signal-get-details` command in Sumo Logic SIEM integration. For further details, visit our <a href="https://xsoar.pan.dev/docs/reference/integrations/sumo-logic-sec#migrating-from-jask-content-pack">Sumo Logic SIEM integration documentation</a>.</p>
<p>Returns detailed information for a specified signal.</p>
<p> </p>
<h5>Base Command</h5>
<p><code>jask-get-signal-details</code></p>
<p> </p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Parameter</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>signal-id</td>
<td>The signal to retrieve details for</td>
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
<td>Jask.Signal.Id</td>
<td>Signal ID</td>
</tr>
<tr>
<td>Jask.Signal.Name</td>
<td>Signal name</td>
</tr>
<tr>
<td>Jask.Signal.Category</td>
<td>Signal category</td>
</tr>
<tr>
<td>Jask.Signal.Description</td>
<td>Signal description</td>
</tr>
<tr>
<td>Jask.Signal.Score</td>
<td>Signal score</td>
</tr>
<tr>
<td>Jask.Signal.SourceType</td>
<td>The source type of the signal</td>
</tr>
<tr>
<td>Jask.Signal.Timestamp</td>
<td>The time of the signal</td>
</tr>
<tr>
<td>Jask.Signal.Metadata.RecordType</td>
<td>Record type</td>
</tr>
<tr>
<td>Jask.Signal.Metadata.RecordCount</td>
<td>The associated count of each record type</td>
</tr>
<tr>
<td>Jask.SignalThreatIndicators.IndicatorType</td>
<td>Threat indicator type</td>
</tr>
<tr>
<td>Jask.Signal.ThreatIndicators.Value</td>
<td>Value of the threat indicator</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!jask-get-signal-details signal-id=b7f76616-f27b-5c18-b503-2d3dbab1bb96</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Jask": {
        "Signal": {
            "Category": "Exfiltration", 
            "SourceType": "rule", 
            "Name": "Hexadecimal in DNS Query Domain", 
            "Timestamp": "2018-07-11T19:06:14", 
            "ThreatIndicators": [
                {
                    "Value": "analytics-9dd8570e3fd957ce828c34761a8e98b8.xyz", 
                    "IndicatorType": "hostname"
                }
            ], 
            "Score": "2", 
            "Description": "Encoding in hexadecimal is a way that attackers can bypass network security devices that are inspecting traffic.  While hexadecimal often appears in subdomains, it much less frequent in domains.", 
            "Id": "b7f76616-f27b-5c18-b503-2d3dbab1bb96", 
            "Metadata": [
                {
                    "RecordType": "flow", 
                    "RecordCount": 0
                }, 
                {
                    "RecordType": "notice", 
                    "RecordCount": 0
                }, 
                {
                    "RecordType": "http", 
                    "RecordCount": 0
                }
            ]
        }
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/7270217/43685069-bb7351ca-98b4-11e8-976c-6d601e0d7b42.png" alt="image" width="751" height="525"></p>
<p> </p>
<h3 id="h_8236589612211533534481518">4. Get details for an entity</h3>
<hr>
<p><i>Note:</i> This command is deprecated. Use `sumologic-sec-entity-get-details` command in Sumo Logic SIEM integration. For further details, visit our <a href="https://xsoar.pan.dev/docs/reference/integrations/sumo-logic-sec#migrating-from-jask-content-pack">Sumo Logic SIEM integration documentation</a>.</p>
<p>Returns detailed information about a speficied entity.</p>
<p> </p>
<h5>Base Command</h5>
<p><code>jask-get-entity-details</code></p>
<p> </p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Parameter</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>entity-id</td>
<td>The entity to retrieve details for</td>
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
<td>Jask.Entity.Id</td>
<td>Entity ID</td>
</tr>
<tr>
<td>Jask.Entity.Name</td>
<td>Entity name</td>
</tr>
<tr>
<td>Jask.Entity.IpAddress</td>
<td>Entity IP address</td>
</tr>
<tr>
<td>Jask.Entity.FirstSeen</td>
<td>Time the entity was first seen</td>
</tr>
<tr>
<td>Jask.Entity.LastSeen</td>
<td>Time the entity was last seen</td>
</tr>
<tr>
<td>Jask.Entity.Source</td>
<td>The source of the entity</td>
</tr>
<tr>
<td>Jask.Entity.AssetType</td>
<td>Asset type</td>
</tr>
<tr>
<td>Jask.Entity.PrimaryAssetType</td>
<td>Primary asset type</td>
</tr>
<tr>
<td>Jask.Entity.HostName</td>
<td>Hostname</td>
</tr>
<tr>
<td>Jask.Entity.RiskScore</td>
<td>Risk score</td>
</tr>
<tr>
<td>Jask.Entity.IsWhiteListed</td>
<td>Whether or not the entity is on allow list</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!jask-get-entity-details entity-id=d07ef37f-06c1-58c3-a7a0-c1cd0fa4cd8e</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Jask": {
        "Entity": {
            "Name": "craig.campbell", 
            "EntityType": "username", 
            "PrimaryEntityType": "hostname", 
            "Source": "ad", 
            "LastSeen": "Sun, 05 Aug 2018 10:30:18 GMT", 
            "Groups": [
                "CN=Remote Desktop Users,CN=Builtin,DC=corp,DC=skaj,DC=ai"
            ], 
            "Id": "d07ef37f-06c1-58c3-a7a0-c1cd0fa4cd8e", 
            "FirstSeen": "Thu, 01 Mar 2018 16:52:50 GMT"
        }
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/7270217/43685094-4774a4f8-98b5-11e8-88fc-867d30fba121.png" alt="image" width="750" height="374"></p>
<p> </p>
<h3 id="h_7145323282911533534488219">5. Get related entities</h3>
<hr>
<p><i>Note:</i> This command is deprecated and will not be supported in Sumo Logic SIEM. For further details, visit our <a href="https://xsoar.pan.dev/docs/reference/integrations/sumo-logic-sec#migrating-from-jask-content-pack">Sumo Logic SIEM integration documentation</a>.</p>
<p>Get all related entities for the specified entity.</p>
<p> </p>
<h5>Base Command</h5>
<p><code>jask-get-related-entities</code></p>
<p> </p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Parameter</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>entity-id</td>
<td>The entity ID that the related entities are retrieved for</td>
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
<td>Jask.RelatedEntityList.Id</td>
<td>Entity ID</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.Name</td>
<td>Entity name</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.Email</td>
<td>Entity email</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.Source</td>
<td>Entity source</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.UserName</td>
<td>Username of the related entity</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.HostName</td>
<td>Entity hostname</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.Active</td>
<td>Whether or not the entity is active</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.Admin</td>
<td>Entity admin</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.AssetType</td>
<td>Asset type</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.CreatedTimestamp</td>
<td>Time the entity was created</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.FirstSeen</td>
<td>Time the entity was first seen</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.GivenName</td>
<td>Name given to the entity</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.IsWhiteListed</td>
<td>Whether or not the entity is on allow list</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.LastSeen</td>
<td>Time the entity was last seen</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.LastName</td>
<td>The last name</td>
</tr>
<tr>
<td>Jask.RelatedEntityList.RiskScore</td>
<td>Entity risk score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!jask-get-related-entities entity-id=d5d04bc6-c00a-4a9a-a8f5-6f6231f55d80</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Jask": {
        "RelatedEntityList": [
            {
                "Username": "craig.campbell", 
                "Name": "craig.campbell", 
                "LastName": "Campbell", 
                "EntityType": "username", 
                "Id": "d07ef37f-06c1-58c3-a7a0-c1cd0fa4cd8e", 
                "CreatedTimestamp": "2018-01-23T05:01:38", 
                "Source": "ad", 
                "LastSeen": "2018-08-05T10:30:18", 
                "Groups": [
                    "CN=Remote Desktop Users,CN=Builtin,DC=corp,DC=skaj,DC=ai"
                ], 
                "Active": true, 
                "GivenName": "Craig", 
                "Email": "example.gmail.com", 
                "FirstSeen": "2018-03-01T16:52:50"
            }, 
            {
                "EntityType": "hostname", 
                "Name": "sea-dt5820-357.corp.skaj.ai", 
                "Hostname": "sea-dt5820-357.corp.skaj.ai", 
                "Source": "ad", 
                "LastSeen": "2018-08-05T10:30:38", 
                "Groups": [
                    "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=corp,DC=skaj,DC=ai", 
                    "CN=Cert Publishers,CN=Users,DC=corp,DC=skaj,DC=ai"
                ], 
                "Id": "7d63f14f-81c0-5442-9de1-6061404bcbd7", 
                "FirstSeen": "2018-02-15T16:04:35"
            }
        ]
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/7270217/43685082-fe26e220-98b4-11e8-8050-77e37a7348c4.png" alt="image" width="752" height="197"></p>
<p> </p>
<h3 id="h_8632925473601533534494371">6. Get a list of entities on allow list</h3>
<hr>
<p><i>Note:</i> This command is deprecated and will not be supported in Sumo Logic SIEM. For further details, visit our <a href="https://xsoar.pan.dev/docs/reference/integrations/sumo-logic-sec#migrating-from-jask-content-pack">Sumo Logic SIEM integration documentation</a>.</p>
<p>Returns a list of all entities on allow list.</p>
<p> </p>
<h5>Base Command</h5>
<p><code>jask-get-whitelisted-entities</code></p>
<p> </p>
<h5>Input</h5>
<p>There are no inputs for this command.</p>
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
<td>Jask.Whitelisted.EntityList.Id</td>
<td>ID of the entity on allow list</td>
</tr>
<tr>
<td>Jask.Whitelisted.EntityList.Name</td>
<td>Name of the entity on allow list</td>
</tr>
<tr>
<td>Jask.Whitelisted.EntityList.UserName</td>
<td>Username of the entity on allow list</td>
</tr>
<tr>
<td>Jask.Whitelisted.EntityList.ModelId</td>
<td>The modelID of the entity on allow list</td>
</tr>
<tr>
<td>Jask.Whitelisted.EntityList.Timestamp</td>
<td>Time of the entity on allow list</td>
</tr>
<tr>
<td>Jask.Whitelisted.EntityList.Metadata.TotalCount</td>
<td>Number of entities on allow list</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!jask-get-whitelisted-entities</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Jask": {
        "WhiteListed": {
            "EntityList": [
                {
                    "UserName": "demisto", 
                    "Timestamp": "2018-05-31T21:20:45.302635", 
                    "Name": "wittes-imac-pro.local", 
                    "Id": "e0a7172f-aa5d-4ba9-ae66-b49d99d9b4e7", 
                    "ModelId": "e0a7172f-aa5d-4ba9-ae66-b49d99d9b4e7"
                }, 
                {
                    "UserName": "demisto", 
                    "Timestamp": "2018-05-31T21:12:54.003527", 
                    "Name": "172.18.20.20", 
                    "Id": "d5d04bc6-c00a-4a9a-a8f5-6f6231f55d80", 
                    "ModelId": "d5d04bc6-c00a-4a9a-a8f5-6f6231f55d80"
                }, 
                {
                    "UserName": "demisto", 
                    "Timestamp": "2018-05-31T21:20:37.218586", 
                    "Name": "192.168.2.195", 
                    "Id": "306360bb-57d2-4a8d-a882-a7b3f2b92429", 
                    "ModelId": "306360bb-57d2-4a8d-a882-a7b3f2b92429"
                }
            ], 
            "Metadata": {
                "TotalCount": 3
            }
        }
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/7270217/43685014-eb84c642-98b3-11e8-8f7d-e16e3c68514a.png" alt="image" width="752" height="219"></p>
<p> </p>
<h3 id="h_2458651614281533534504337">7. Search JASK insights</h3>
<hr>
<p><i>Note:</i> This command is deprecated. Use `sumologic-sec-insight-search` command in Sumo Logic SIEM integration. For further details, visit our <a href="https://xsoar.pan.dev/docs/reference/integrations/sumo-logic-sec#migrating-from-jask-content-pack">Sumo Logic SIEM integration documentation</a>.</p>
<p>Search for JASK insights according to specific criteria.</p>
<p> </p>
<h5>Base Command</h5>
<p><code>jask-search-insights</code></p>
<p> </p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Parameter</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>last-seen</td>
<td>When the insight was last seen. Defaults to 'All time' if no time arguments are specified.</td>
</tr>
<tr>
<td>rating</td>
<td>Comma-separated list of values between 1-5 (inclusive)</td>
</tr>
<tr>
<td>status</td>
<td>Comma-separated list of values (new, inprogress, closed)</td>
</tr>
<tr>
<td>assigned-team</td>
<td>Comma-separated list of values</td>
</tr>
<tr>
<td>assigned-user</td>
<td>Comma-separated list of values</td>
</tr>
<tr>
<td>offset</td>
<td>The page offset for the results</td>
</tr>
<tr>
<td>limit</td>
<td>How many results to retrieve</td>
</tr>
<tr>
<td>sort</td>
<td>What to sort the results by</td>
</tr>
<tr>
<td>time-from</td>
<td>Start time for the search (MM/DD/YYYY)</td>
</tr>
<tr>
<td>time-to</td>
<td>End time for the search (MM/DD/YYYY)</td>
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
<td>Jask.Insight.Id</td>
<td>Insight ID</td>
</tr>
<tr>
<td>Jask.Insight.Name</td>
<td>Insight name</td>
</tr>
<tr>
<td>Jask.Insight.Action</td>
<td>The action to take on the insight</td>
</tr>
<tr>
<td>Jask.Insight.AssignedTo</td>
<td>Who the insight was assigned to</td>
</tr>
<tr>
<td>Jask.Insight.Description</td>
<td>Insight description</td>
</tr>
<tr>
<td>Jask.Insight.IpAddress</td>
<td>Insight IP address</td>
</tr>
<tr>
<td>Jask.Insight.LastUpdated</td>
<td>When the insight was last updated</td>
</tr>
<tr>
<td>Jask.Insight.LastUpdatedBy</td>
<td>Who the insight was last updated by</td>
</tr>
<tr>
<td>Jask.Insight.Severity</td>
<td>Insight severity</td>
</tr>
<tr>
<td>Jask.Insight.InsightTime</td>
<td>Time of the insight</td>
</tr>
<tr>
<td>Jask.WorkflowStatus</td>
<td>Insight status</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!jask-search-insights last-seen="Last 48 hours" limit=2 assigned-user=unassigned</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Jask": {
        "Insight": [
            {
                "WorkflowStatus": "new", 
                "Description": "Multiple signals related to lateral movement with other anomalies and threats.", 
                "InsightTime": "2018-08-04T11:06:14", 
                "LastUpdated": "2018-08-04T11:06:15.373616", 
                "AssignedTo": "unassigned", 
                "Severity": 1, 
                "IpAddress": "172.18.20.20", 
                "Id": "a01f689c-f7da-4838-bf5c-2046f1736aff", 
                "Name": "Insider Threat - Lateral Movement with Increased Traffic"
            }, 
            {
                "WorkflowStatus": "new", 
                "Description": "Multiple signals related to user, network and other threats.", 
                "InsightTime": "2018-08-04T11:05:12", 
                "LastUpdated": "2018-08-04T11:05:13.654486", 
                "AssignedTo": "unassigned", 
                "Severity": 1, 
                "IpAddress": "^^^172.18.20.20^^^", 
                "Id": "88cd2086-126f-4e95-a6c5-dde91f86afb6", 
                "Name": "User Anomalies with Beaconing Behavior"
            }
        ]
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/7270217/43685112-911cc8a6-98b5-11e8-96d6-4e67c59e45db.png" alt="image" width="752" height="191"></p>
<p> </p>
<h3 id="h_3876303084951533534510096">8. Search JASK signals</h3>
<hr>
<p><i>Note:</i> This command is deprecated. Use `sumologic-sec-signal-search` command in Sumo Logic SIEM integration. For further details, visit our <a href="https://xsoar.pan.dev/docs/reference/integrations/sumo-logic-sec#migrating-from-jask-content-pack">Sumo Logic SIEM integration documentation</a>.</p>
<p>Search for JASK signals according to specific criteria.</p>
<p> </p>
<h5>Base Command</h5>
<p><code>jask-search-signals</code></p>
<p> </p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Parameter</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>last-seen</td>
<td>When the insight was last seen. Defaults to 'All time' if no time arguments are specified.</td>
</tr>
<tr>
<td>source</td>
<td>Comma-separated list of values (threatintel, rule, anomaly)</td>
</tr>
<tr>
<td>category</td>
<td>Comma-separated list of values form options (Attack Stage, C2, Defense Evasion, Discovery, Exfiltration, Exploitation, External Recon, Internal Recon, Lateral Movement, Threat Intelligence, Traffic Anomaly)</td>
</tr>
<tr>
<td>offset</td>
<td>The page offset for the results</td>
</tr>
<tr>
<td>limit</td>
<td>The maximum number of signals to retrieve</td>
</tr>
<tr>
<td>sort</td>
<td>What to sort the results by</td>
</tr>
<tr>
<td>time-from</td>
<td>Start time for the search (MM/DD/YYYY)</td>
</tr>
<tr>
<td>time-to</td>
<td>End time for the search (MM/DD/YYYY)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>asdfas</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!jask-search-signals last-seen="Last 24 hours" category="Attack Stage, C2" offset="0" limit="10" sort="score:desc"</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Jask": {
        "Signal": [
            {
                "Category": "C2", 
                "Name": "TeslaCrypt Ransomware Domain", 
                "Timestamp": "2018-08-04T11:59:26.447586", 
                "ThreatIndicators": [
                    {
                        "Value": "lovemydress.pl", 
                        "IndicatorType": "hostname"
                    }
                ], 
                "Score": "6", 
                "Description": "TeslaCrypt is a ransomware that encrypts documents, databases, code, bitcoin wallets and more. This rule looks for DNS queries that include domains known to be associated with TeslaCrypt.", 
                "Id": "79d796dc-97e6-11e8-bdd7-02346534339c", 
                "SourceType": "rule"
            }, 
            {
                "Category": "Attack Stage", 
                "Name": "SSH Password Brute Force", 
                "Timestamp": "2018-08-04T10:36:35.256445", 
                "ThreatIndicators": [
                    {
                        "Value": "104.236.48.178", 
                        "IndicatorType": "ip"
                    }
                ], 
                "Score": "2", 
                "Description": "SSH Password brute force attack detected", 
                "Id": "79d790a6-97e6-11e8-bdc7-02346534339c", 
                "SourceType": "rule"
            }, 
            {
                "Category": "Attack Stage", 
                "Name": "SSH Password Brute Force", 
                "Timestamp": "2018-08-04T11:24:49.534168", 
                "ThreatIndicators": [
                    {
                        "Value": "^^^104.236.48.178^^^", 
                        "IndicatorType": "ip"
                    }
                ], 
                "Score": "2", 
                "Description": "SSH Password brute force attack detected", 
                "Id": "79d78eb2-97e6-11e8-bdc2-02346534339c", 
                "SourceType": "rule"
            }
        ]
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/7270217/43684958-b96c6cb0-98b2-11e8-838f-db2d78f7f209.png" alt="image" width="752" height="225"></p>
<p> </p>
<h3 id="h_2402374295611533534516772">9. Search JASK entities</h3>
<hr>
<p><i>Note:</i> This command is deprecated. Use `sumologic-sec-entity-search` command in Sumo Logic SIEM integration. For further details, visit our <a href="https://xsoar.pan.dev/docs/reference/integrations/sumo-logic-sec#migrating-from-jask-content-pack">Sumo Logic SIEM integration documentation</a>.</p>
<p>Search for JASK entities according to specific criteria.</p>
<p> </p>
<h5>Base Command</h5>
<p><code>jask-search-entities</code></p>
<p> </p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Parameter</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>last-seen</td>
<td>When the insight was last seen. Defaults to 'All time' if no time arguments are specified.</td>
</tr>
<tr>
<td>entity-type</td>
<td>Comma-separated list of values (username, hostname, ip)</td>
</tr>
<tr>
<td>offset</td>
<td>The page offset for the results</td>
</tr>
<tr>
<td>limit</td>
<td>How many results to retrieve</td>
</tr>
<tr>
<td>sort</td>
<td>What to sort the results by</td>
</tr>
<tr>
<td>time-from</td>
<td>Start time for the search(MM/DD/YYYY)</td>
</tr>
<tr>
<td>time-to</td>
<td>End time for the search (MM/DD/YYYY)</td>
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
<td>Jask.Entity.Id</td>
<td>Entity ID</td>
</tr>
<tr>
<td>Jask.Entity.Name</td>
<td>Entity name</td>
</tr>
<tr>
<td>Jask.Entity.FirstSeen</td>
<td>When the entity was first seen</td>
</tr>
<tr>
<td>Jask.Entity.LastSeen</td>
<td>When the entity was last seen</td>
</tr>
<tr>
<td>Jask.Entity.Source</td>
<td>The source of the entity</td>
</tr>
<tr>
<td>Jask.Entity.EntityType</td>
<td>Entity type</td>
</tr>
<tr>
<td>Jask.Entity.PrimaryEntityType</td>
<td>The primary entity type</td>
</tr>
<tr>
<td>Jask.Entity.HostName</td>
<td>Entity hostname</td>
</tr>
<tr>
<td>Jask.Entity.RiskScore</td>
<td>Entity risk score</td>
</tr>
<tr>
<td>Jask.Entity.IsWhiteListed</td>
<td>Whether or not the entity is on allow list</td>
</tr>
<tr>
<td>Jask.Entity.Groups</td>
<td>The groups of the entity</td>
</tr>
<tr>
<td>Jask.Entity.Ip.Address</td>
<td>Entity IP address</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!jask-search-entities entity-type=ip limit=3 time-from=08/04/2018 time-to=08/05/2018</code></p>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Jask": {
        "Entity": [
            {
                "EntityType": "ip", 
                "Name": "112.175.209.72", 
                "Hostname": "Unknown", 
                "Source": "discovery", 
                "PrimaryEntityType": null, 
                "IpAddress": "^^^112.175.209.72^^^", 
                "Id": "68fe56f0-4cbc-4664-9227-868069607636"
            }, 
            {
                "EntityType": "ip", 
                "Name": "186.185.91.72", 
                "Hostname": "Unknown", 
                "Source": "discovery", 
                "PrimaryEntityType": null, 
                "IpAddress": "^^^186.185.91.72^^^", 
                "Id": "ada67af4-a7c1-45f4-9740-69b095ffdac6"
            }, 
            {
                "EntityType": "ip", 
                "Name": "105.102.75.16", 
                "Hostname": "Unknown", 
                "Source": "discovery", 
                "PrimaryEntityType": null, 
                "IpAddress": "^^^105.102.75.16^^^", 
                "Id": "b3e40046-0450-48a4-8752-6a20aec89143"
            }
        ]
    }
}</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/7270217/43685003-c0169ecc-98b3-11e8-892a-dd85e72e715e.png" alt="image" width="752" height="59"></p>
<p> </p>
