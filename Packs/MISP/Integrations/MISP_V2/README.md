<!-- HTML_DOC -->
<p>Use the MISP integration to create manage events, samples, and attributes, and add various object types.</p>
<p> </p>
<h2>Configure MISP V2 on Cortex XSOAR</h2>
<p> </p>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for MISP V2.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>MISP server URL (e.g.,<span> </span><a href="https://192.168.0.1/" rel="nofollow">https://192.168.0.1</a>)</strong></li>
<li><strong>API Key</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<p> </p>
<h2>Commands</h2>
<p> </p>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<p> </p>
<ol>
<li><a href="#h_4f615456-b26c-48b8-89ee-3ef4be73dedf" target="_self">Search for events: misp-search</a></li>
<li><a href="#h_4f637628-b26c-48b8-89ee-3ef4be73dedf" target="_self">Search for attributes: misp-search-attributes</a></li>
<li><a href="#h_53acd13b-9862-45fe-ba8f-9f524ef0795d" target="_self">Get the reputation of a file: file</a></li>
<li><a href="#h_58d2d4e2-08aa-4c78-9f67-9415508ac63c" target="_self">Check if a URL is in MISP events: url</a></li>
<li><a href="#h_8ffb723c-d3f8-40fc-a15a-ecb8b011d507" target="_self">Get the reputation of an IP address: ip</a></li>
<li><a href="#h_699dedd4-2412-4cb5-b6b1-aeaf965195e5" target="_self">Create a MISP event: misp-create-event</a></li>
<li><a href="#h_2249eec0-1a73-42ef-8422-fc8f2bc9b167" target="_self">Download a file sample: misp-download-sample</a></li>
<li><a href="#h_d770e98c-2d22-49f0-b875-d5a5e760e775" target="_self">Add an attribute to an event: misp-add-attribute</a></li>
<li><a href="#h_f325c9d3-2e07-46e9-8e69-6b96f9030909" target="_self">Upload a file sample: misp-upload-sample</a></li>
<li><a href="#h_bc997769-2b6d-4324-afde-74ec8b896ee2" target="_self">Delete an event: misp-delete-event</a></li>
<li><a href="#h_d47d7978-435a-4999-ba8a-2f581356f032" target="_self">Add a tag to an event or attribute: misp-add-tag</a></li>
<li><a href="#h_04357de2-77f9-48d7-a47e-bc4e9ec2c563" target="_self">Add sighting to an attribute: misp-add-sighting</a></li>
<li><a href="#h_92415f70-7f80-4d61-98a1-696a40fc3c73" target="_self">Add an OSINT feed: misp-add-events-from-feed</a></li>
<li><a href="#h_f2dd36fd-1ac6-40ef-81ad-3a6b4422b342" target="_self">Add an email object to an event: misp-add-email-object</a></li>
<li><a href="#h_7fbf18d8-075a-422f-b28f-217948bc5182" target="_self">Add a domain object to an event: misp-add-domain-object</a></li>
<li><a href="#h_c495c545-f854-4bd3-b65c-c703415cf1b4" target="_self">Add a URL object to an event: misp-add-url-object</a></li>
<li><a href="#h_d89bbb90-7744-427b-9bbb-484eb751f21c" target="_self">Add an object to an event: misp-add-object</a></li>
<li><a href="#h_fde36c78-62d4-4e37-b895-dcef403a0e89" target="_self">Add an IP object to an event: misp-add-ip-object</a></li>
</ol>
<p> </p>
<h3 id="h_4f615456-b26c-48b8-89ee-3ef4be73dedf">1. Search for events</h3>
<p> </p>
<hr>
<p> </p>
<p>Search for events in MISP.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-search</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 535px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">type</td>
<td style="width: 535px;">The attribute type. Use any valid MISP attribute.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">value</td>
<td style="width: 535px;">Search for the specified value in the attributes' value field.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">category</td>
<td style="width: 535px;">The attribute category. Use any valid MISP attribute category.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">org</td>
<td style="width: 535px;">Search by creator organization by supplying the organization ID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">tags</td>
<td style="width: 535px;">A comma-separated list of tags to include in the results. To exclude a tag, prefix the
        tag name with "!". Can be: "AND", "OR", and "NOT" followed by ":". To chain logical operators use ";". 
        for example, "AND:tag1,tag2;OR:tag3".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">from</td>
<td style="width: 535px;">Event search start date (2015-02-15)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">to</td>
<td style="width: 535px;">Event search end date (2015-02-15)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">last</td>
<td style="width: 535px;">Events published within the last "x" amount of time. Valid time values are days, hours, and minutes (for example "5d", "12h", "30m"). This filter uses the published timestamp of the event.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">eventid</td>
<td style="width: 535px;">The events to include or exclude from the search</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">uuid</td>
<td style="width: 535px;">Return events that include an attribute with the given UUID. Alternatively the event's UUID must match the value(s) passed, e.g., 59523300-4be8-4fa6-8867-0037ac110002</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">to_ids</td>
<td style="width: 535px;">Whether to return only the attributes set with the "to_ids" flag</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 334px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 344px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334px;">MISP.Event.ID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">MISP event ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Distribution</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">MISP event distribution.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.ThreatLevelID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Threat level of the MISP event (1 High, 2 Medium, 3 Low, 4 Undefined).</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.PublishTimestamp</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Timestamp of the publish time (if published).</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.EventCreatorEmail</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Email address of the event creator.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Date</td>
<td style="width: 62px;">date</td>
<td style="width: 344px;">Event creation date.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Locked</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Is the event locked.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.OwnerOrganisation.ID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Owner organization ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.OwnerOrganisation.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Owner organization name.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.OwnerOrganisation.UUID</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Owner organization UUID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.RelatedEvent.ID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Event IDs of related events (can be a list).</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.ProposalEmailLock</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">If email lock was proposed.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Timestamp</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Timestamp of the event.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Galaxy.Description</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Event's galaxy description.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Galaxy.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Galaxy name.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Galaxy.Type</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Galaxy type.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Published</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Whether the event is published.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.DisableCorrelation</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Whether correlation is disabled.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.UUID</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Event UUID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.ShadowAttribute</td>
<td style="width: 62px;">Unknown</td>
<td style="width: 344px;">Event shadow attributes.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.Distribution</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Attribute distribution.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.Value</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Attribute value.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.EventID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Attribute event ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.Timestamp</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Attribute timestamp.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.Deleted</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Whether the attribute is deleted.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.DisableCorrelation</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Whether attribute correlation is disabled.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.Type</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Attribute type.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.ID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Attribute ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.UUID</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Attribute UUID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.ShadowAttribute</td>
<td style="width: 62px;">Unknown</td>
<td style="width: 344px;">Attribute shadow attribute.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.ToIDs</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Whether the Intrusion Detection System flag is set.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.Category</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Attribute category.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.SharingGroupID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Attribute sharing group ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Attribute.Comment</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Attribute comment.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Analysis</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Event analysis (0 Initial, 1 Ongoing, 2 Completed).</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.SharingGroupID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Event sharing group ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Tag.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">All tag names in the event.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.MetaCategory</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Object meta category.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Distribution</td>
<td style="width: 62px;">Number</td>
<td style="width: 344px;">Distribution of object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Name</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Name of the object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.TemplateVersion</td>
<td style="width: 62px;">Number</td>
<td style="width: 344px;">Template version of the object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.EventID</td>
<td style="width: 62px;">Number</td>
<td style="width: 344px;">ID of the event which the object first created.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.TemplateUUID</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">UUID of the template</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Timestamp</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Timestamp of object creation</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Deleted</td>
<td style="width: 62px;">Boolean</td>
<td style="width: 344px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.ID</td>
<td style="width: 62px;">Number</td>
<td style="width: 344px;">ID of object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.UUID</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">UUID of the object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.Value</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Value of attribute.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.EventID</td>
<td style="width: 62px;">Number</td>
<td style="width: 344px;">ID of first event that originated from the object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.Timestamp</td>
<td style="width: 62px;">Date</td>
<td style="width: 344px;">Timestamp of object creation.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.Deleted</td>
<td style="width: 62px;">Boolean</td>
<td style="width: 344px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.ObjectID</td>
<td style="width: 62px;">Number</td>
<td style="width: 344px;">ID of the object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.DisableCorrelation</td>
<td style="width: 62px;">Boolean</td>
<td style="width: 344px;">Whether correlation is disabled.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.ID</td>
<td style="width: 62px;">Unknown</td>
<td style="width: 344px;">ID of the attribute.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.ObjectRelation</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Relation of the object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.Type</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Type of object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.UUID</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">UUID of the attribute.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.ToIDs</td>
<td style="width: 62px;">Boolean</td>
<td style="width: 344px;">Whether the to_ids flag is on.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.Category</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Category of the attribute.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.SharingGroupID</td>
<td style="width: 62px;">Number</td>
<td style="width: 344px;">ID of the sharing group.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Attribute.Comment</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Comment of the attribute.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Event.Object.Description</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Description of the object.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-search category="External analysis" type="url"</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "MISP.Event": [
        {
            "EventCreatorEmail": "admin@admin.test", 
            "SharingGroupID": "0", 
            "Organisation": {
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002", 
                "ID": "1", 
                "Name": "ORGNAME"
            }, 
            "ShadowAttribute": [], 
            "Distribution": "0", 
            "ProposalEmailLock": false, 
            "Timestamp": "1565012166", 
            "Object": [
                {
                    "Comment": "", 
                    "EventID": "743", 
                    "Timestamp": "1565012146", 
                    "Description": "Url object", 
                    "UUID": "3c90797e-2aba-4ac2-bc4a-73c797425e1f", 
                    "Deleted": false, 
                    "Attribute": [
                        {
                            "Category": "Network activity", 
                            "Comment": "", 
                            "ShadowAttribute": [], 
                            "UUID": "287e1b44-24c1-45b9-9ef9-541d00ae447b", 
                            "ObjectID": "3223", 
                            "Deleted": false, 
                            "Timestamp": "1565012146", 
                            "ToIDs": true, 
                            "Value": "www.google.com", 
                            "ID": "26138", 
                            "SharingGroupID": "0", 
                            "ObjectRelation": "domain", 
                            "EventID": "743", 
                            "DisableCorrelation": false, 
                            "Type": "url", 
                            "Distribution": "5", 
                            "Galaxy": []
                        }
                    ], 
                    "TemplateUUID": "9f8cea74-16fe-4968-a2b4-026676949ac6", 
                    "TemplateVersion": "7", 
                    "SharingGroupID": "0", 
                    "ObjectReference": [], 
                    "MetaCategory": "network", 
                    "Distribution": "5", 
                    "ID": "3223", 
                    "Name": "ip-port"
                }
            ], 
            "ThreatLevelID": "1", 
            "Date": "2019-08-05", 
            "RelatedEvent": [
                {
                    "ID": "753"
                }
            ], 
            "Info": "Example event", 
            "Locked": false, 
            "OwnerOrganisation": {
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002", 
                "ID": "1", 
                "Name": "ORGNAME"
            }, 
            "Analysis": "0", 
            "Published": false, 
            "DisableCorrelation": false, 
            "ID": "743", 
            "PublishTimestamp": "0", 
            "UUID": "5d48302c-bf84-4671-9080-0728ac110002", 
            "Attribute": [
                {
                    "Category": "External analysis", 
                    "Comment": "Just an example", 
                    "ShadowAttribute": [], 
                    "UUID": "c320c9f6-4619-450a-b150-9c62e341fbfe", 
                    "ObjectID": "0", 
                    "Deleted": false, 
                    "Timestamp": "1565012014", 
                    "ToIDs": false, 
                    "Value": "www.example.com", 
                    "ID": "26128", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": null, 
                    "EventID": "743", 
                    "DisableCorrelation": false, 
                    "Type": "url", 
                    "Distribution": "0", 
                    "Galaxy": []
                }
            ], 
            "Galaxy": []
        }, 
        {
            "EventCreatorEmail": "admin@admin.test", 
            "SharingGroupID": "0", 
            "Organisation": {
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002", 
                "ID": "1", 
                "Name": "ORGNAME"
            }, 
            "ShadowAttribute": [], 
            "Distribution": "0", 
            "ProposalEmailLock": false, 
            "Timestamp": "1565013591", 
            "Object": [], 
            "ThreatLevelID": "1", 
            "Date": "2019-08-05", 
            "RelatedEvent": [
                {
                    "ID": "743"
                }
            ], 
            "Info": "Example event", 
            "Locked": false, 
            "OwnerOrganisation": {
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002", 
                "ID": "1", 
                "Name": "ORGNAME"
            }, 
            "Analysis": "0", 
            "Published": false, 
            "DisableCorrelation": false, 
            "ID": "753", 
            "PublishTimestamp": "0", 
            "UUID": "5d483655-ac78-4765-9169-70f7ac110002", 
            "Attribute": [
                {
                    "Category": "External analysis", 
                    "Comment": "Just an example", 
                    "ShadowAttribute": [], 
                    "UUID": "8468ac01-126f-4e73-8cff-7371303014aa", 
                    "ObjectID": "0", 
                    "Deleted": false, 
                    "Timestamp": "1565013591", 
                    "ToIDs": false, 
                    "Value": "www.example.com", 
                    "ID": "26160", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": null, 
                    "EventID": "753", 
                    "DisableCorrelation": false, 
                    "Type": "url", 
                    "Distribution": "0", 
                    "Galaxy": []
                }
            ], 
            "Galaxy": []
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<h3>Results in MISP for search:</h3>
<p> </p>
<table>
<thead>
<tr>
<th>category</th>
<th>type</th>
<th>type_attribute</th>
</tr>
</thead>
<tbody>
<tr>
<td>External analysis</td>
<td>url</td>
<td>url</td>
</tr>
<tr>
<td>Total of 2 events found</td>
<td> </td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Event ID: 743</h3>
<p> </p>
<table border="2">
<thead>
<tr>
<th>Analysis</th>
<th>Attributes</th>
<th>Event Creator Email</th>
<th>Info</th>
<th>Related Events</th>
<th>Threat Level ID</th>
<th>Timestamp</th>
</tr>
</thead>
<tbody>
<tr>
<td>Initial</td>
<td>[<br> {<br> "ID": "26128",<br> "Type": "url",<br> "Category": "External analysis",<br> "ToIDs": false,<br> "UUID": "c320c9f6-4619-450a-b150-9c62e341fbfe",<br> "EventID": "743",<br> "Distribution": "0",<br> "Timestamp": "1565012014",<br> "Comment": "Just an example",<br> "SharingGroupID": "0",<br> "Deleted": false,<br> "DisableCorrelation": false,<br> "ObjectID": "0",<br> "ObjectRelation": null,<br> "Value": "www.example.com",<br> "Galaxy": [],<br> "ShadowAttribute": []<br> },<br> {<br> "ID": "26136",<br> "Type": "ip-src",<br> "Category": "Payload delivery",<br> "ToIDs": true,<br> "UUID": "9fc2d7b1-b784-47fc-ad2d-cdcb5df85144",<br> "EventID": "743",<br> "Distribution": "5",<br> "Timestamp": "1565012133",<br> "Comment": "Unknown IP",<br> "SharingGroupID": "0",<br> "Deleted": false,<br> "DisableCorrelation": false,<br> "ObjectID": "0",<br> "ObjectRelation": null,<br> "Value": "8.8.3.3",<br> "Galaxy": [],<br> "ShadowAttribute": []<br> }<br> ]</td>
<td>admin@admin.test</td>
<td>Example event</td>
<td>{'ID': '753'}</td>
<td>HIGH</td>
<td>2019-08-05 13:36:06</td>
</tr>
</tbody>
</table>
<p> </p>


<h3 id="h_4f637628-b26c-48b8-89ee-3ef4be73dedf">2. Search for attributes</h3>
<p> </p>
<hr>
<p> </p>
<p>Search for attributes in MISP.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-search-attributes</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 535px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">type</td>
<td style="width: 535px;">The attribute type. Use any valid MISP attribute.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">value</td>
<td style="width: 535px;">Search for the specified value in the attributes' value field.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">category</td>
<td style="width: 535px;">The attribute category. Use any valid MISP attribute category.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">uuid</td>
<td style="width: 535px;">Return events that include an attribute with the given UUID. Alternatively the event's UUID
 must match the value(s) passed, e.g., 59523300-4be8-4fa6-8867-0037ac110002.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">to_ids</td>
<td style="width: 535px;">Whether to return only the attributes set with the "to_ids" flag.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">last</td>
<td style="width: 535px;">Events published within the last "x" amount of time. Valid time values are days, hours, and minutes (for example "5d", "12h", "30m"). This filter uses the published timestamp of the event.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">include_decay_score</td>
<td style="width: 535px;">Include the decay score at attribute level.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 334px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 344px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334px;">MISP.Attribute.Distribution</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Attribute distribution.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Value</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Attribute value.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.EventID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Attribute event ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Timestamp</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Attribute timestamp.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Deleted</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Whether the attribute is deleted.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.DisableCorrelation</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Whether attribute correlation is disabled.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Type</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Attribute type.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.ID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Attribute ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.UUID</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Attribute UUID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.ShadowAttribute</td>
<td style="width: 62px;">Unknown</td>
<td style="width: 344px;">Attribute shadow attribute.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.ToIDs</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Whether the Intrusion Detection System flag is set.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Category</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Attribute category.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.SharingGroupID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Attribute sharing group ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Comment</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Attribute comment.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.ID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">MISP event ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.Distribution</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">MISP event distribution.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.ThreatLevelID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Threat level of the MISP event (1 High, 2 Medium, 3 Low, 4 Undefined).</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.PublishTimestamp</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Timestamp of the publish time (if published).</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.EventCreatorEmail</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Email address of the event creator.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.Date</td>
<td style="width: 62px;">date</td>
<td style="width: 344px;">Event creation date.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.Locked</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Is the event locked.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.OwnerOrganisation.ID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Owner organization ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.OwnerOrganisation.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Owner organization name.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.OwnerOrganisation.UUID</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Owner organization UUID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.RelatedEvent.ID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Event IDs of related events (can be a list).</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.ProposalEmailLock</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">If email lock was proposed.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.Timestamp</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Timestamp of the event.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.Galaxy.Description</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Event's galaxy description.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.Galaxy.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Galaxy name.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.Galaxy.Type</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Galaxy type.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.Published</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Whether the event is published.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.DisableCorrelation</td>
<td style="width: 62px;">boolean</td>
<td style="width: 344px;">Whether correlation is disabled.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.UUID</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Event UUID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.ShadowAttribute</td>
<td style="width: 62px;">Unknown</td>
<td style="width: 344px;">Event shadow attributes.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.Analysis</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Event analysis (0 Initial, 1 Ongoing, 2 Completed).</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.SharingGroupID</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Event sharing group ID.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Event.Tag.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">All tag names in the event.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Object.MetaCategory</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Object meta category.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Object.Distribution</td>
<td style="width: 62px;">Number</td>
<td style="width: 344px;">Distribution of object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Object.Name</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Name of the object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Object.TemplateVersion</td>
<td style="width: 62px;">Number</td>
<td style="width: 344px;">Template version of the object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Object.EventID</td>
<td style="width: 62px;">Number</td>
<td style="width: 344px;">ID of the event which the object first created.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Object.TemplateUUID</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">UUID of the template.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Object.Timestamp</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Timestamp of object creation.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Object.Deleted</td>
<td style="width: 62px;">Boolean</td>
<td style="width: 344px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Object.ID</td>
<td style="width: 62px;">Number</td>
<td style="width: 344px;">ID of object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Object.UUID</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">UUID of the object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Object.Description</td>
<td style="width: 62px;">String</td>
<td style="width: 344px;">Description of the object.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Galaxy.Description</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Event's galaxy description.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Galaxy.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">Galaxy name.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Galaxy.Type</td>
<td style="width: 62px;">number</td>
<td style="width: 344px;">Galaxy type.</td>
</tr>
<tr>
<td style="width: 334px;">MISP.Attribute.Tag.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 344px;">All tag names in the event.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-search-attributes category="Other" value="Ferrari"</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "MISP.Attribute": [
    {
        'ID': '215746',
        'EventID': '12041',
        'ObjectID': '35655',
        'ObjectRelation': 'make',
        'Category': 'Other',
        'Type': 'text',
        'ToIDs': False,
        'UUID': '175c30f8-8bba-44bc-9727-7065da0ed109',
        'Timestamp': '1619620662',
        'Distribution': '5',
        'SharingGroupID': '0',
        'Comment': '',
        'Deleted': False,
        'DisableCorrelation': True,
        'Value': 'Ferrari',
        'Event': {
            'OrganisationID': '1',
            'Distribution': '0',
            'ID': '12041',
            'Info': 'Testplayboook',
            'OwnerOrganisation.ID': '1',
            'UUID': '60897327-db98-4cab-8911-32faac110002'
            },
        'Object': {
            'ID': '35655',
            'Distribution': '5',
            'SharingGroupID': '0'
            }
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p> </p>
<h3>MISP attributes-search returned 2 attributes.</h3>
<h4>Attribute ID: 67899</h4>
<table>
<thead>
<tr>
<th>Category</th>
<th>Comment</th>
<th>Deleted</th>
<th>DisableCorrelation</th>
<th>Distribution</th>
<th>Event</th>
<th>EventID</th>
<th>ID</th>
<th>Object</th>
<th>ObjectID</th>
<th>ObjectRelation</th>
<th>SharingGroupID</th>
<th>Timestamp</th>
<th>ToIDs</th>
<th>Type</th>
<th>UUID</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr>
<td>Other</td>
<td></td>
<td>false</td>
<td>true</td>
<td>5</td>
<td>OrganisationID: 1<br>Distribution: 0<br>ID: 12041<br>Info: Testplayboook<br>OwnerOrganisation.ID: 1<br>UUID: 60897327-db98-4cab-8911-32faac110002</td>
<td>12041</td>
<td>215746</td>
<td>ID: 35655<br>Distribution: 5<br>SharingGroupID: 0</td>
<td>35655</td>
<td>make</td>
<td>0</td>
<td>1619620662</td>
<td>false</td>
<td>text</td>
<td>175c30f8-8bba-44bc-9727-7065da0ed109</td>
<td>Ferrari</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<h3 id="h_53acd13b-9862-45fe-ba8f-9f524ef0795d">3. Get the reputation of a file</h3>
<p> </p>
<hr>
<p> </p>
<p>Checks the file reputation of the given hash.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>file</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 145px;"><strong>Argument Name</strong></th>
<th style="width: 516px;"><strong>Description</strong></th>
<th style="width: 79px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145px;">file</td>
<td style="width: 516px;">A CSV list of file hashes to query. Can be MD5, SHA1, or SHA256. </td>
<td style="width: 79px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 699px;">
<thead>
<tr>
<th style="width: 180px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 447px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">File.MD5</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 447px;">Bad hash found.</td>
</tr>
<tr>
<td style="width: 180px;">File.SHA1</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 447px;">Bad SHA1 hash.</td>
</tr>
<tr>
<td style="width: 180px;">File.SHA256</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 447px;">Bad SHA256 hash.</td>
</tr>
<tr>
<td style="width: 180px;">File.Malicious.Vendor</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 447px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 180px;">File.Malicious.Description</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 447px;">For malicious files, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Indicator</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 447px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Type</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 447px;">Indicator type.</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Vendor</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 447px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Score</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 447px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!file file="3d74da0a7276735f1afae01951b39ff7a9d92c94"</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "DBotScore": [
        {
            "Vendor": "MISP", 
            "Indicator": "3d74da0a7276735f1afae01951b39ff7a9d92c94", 
            "Score": 3, 
            "Type": "hash"
        }
    ], 
    "File": [
        {
            "Malicious": {
                "Vendor": "MISP", 
                "Description": "file hash found in MISP event with ID: 754"
            }, 
            "SHA1": "3d74da0a7276735f1afae01951b39ff7a9d92c94"
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<h3>Results found in MISP for hash: 3d74da0a7276735f1afae01951b39ff7a9d92c94</h3>
<p> </p>
<table>
<thead>
<tr>
<th>EventID</th>
<th>Organisation</th>
<th>Threat Level</th>
</tr>
</thead>
<tbody>
<tr>
<td>754</td>
<td>MISP</td>
<td>HIGH</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h3 id="h_58d2d4e2-08aa-4c78-9f67-9415508ac63c">4. Check if a URL is in MISP events</h3>
<p> </p>
<hr>
<p> </p>
<p>Checks if the URL is in MISP events.</p>
<p>Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>url</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 316px;"><strong>Argument Name</strong></th>
<th style="width: 245px;"><strong>Description</strong></th>
<th style="width: 179px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 316px;">url</td>
<td style="width: 245px;">URL to check.</td>
<td style="width: 179px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 188px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 486px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 188px;">URL.Data</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 486px;">Bad URLs found.</td>
</tr>
<tr>
<td style="width: 188px;">URL.Malicious.Vendor</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 486px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 188px;">URL.Malicious.Description</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 486px;">For malicious URLs, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 188px;">DBotScore.Indicator</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 486px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 188px;">DBotScore.Type</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 486px;">Indicator type.</td>
</tr>
<tr>
<td style="width: 188px;">DBotScore.Vendor</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 486px;">
<p>The vendor used to calculate the score.</p>
</td>
</tr>
<tr>
<td style="width: 188px;">DBotScore.Score</td>
<td style="width: 66px;">Unknown</td>
<td style="width: 486px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!url url="www.example.com"</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "URL": [
        {
            "Malicious": {
                "Vendor": "MISP.ORGNAME", 
                "Description": "IP Found in MISP event: 743"
            }, 
            "Data": "www.example.com"
        }, 
        {
            "Malicious": {
                "Vendor": "MISP.ORGNAME", 
                "Description": "IP Found in MISP event: 753"
            }, 
            "Data": "www.example.com"
        }
    ], 
    "DBotScore": [
        {
            "Vendor": "MISP.ORGNAME", 
            "Indicator": "www.example.com", 
            "Score": 3, 
            "Type": "url"
        }, 
        {
            "Vendor": "MISP.ORGNAME", 
            "Indicator": "www.example.com", 
            "Score": 3, 
            "Type": "url"
        }
    ], 
    "MISP.Event": [
        {
            "EventCreatorEmail": "admin@admin.test", 
            "SharingGroupID": "0", 
            "Organisation": {
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002", 
                "ID": "1", 
                "Name": "ORGNAME"
            }, 
            "ShadowAttribute": [], 
            "Distribution": "0", 
            "ProposalEmailLock": false, 
            "Timestamp": "1565013625", 
            "Object": [],
            "Attribute": [
                {
                    "Category": "External analysis", 
                    "Comment": "Just an example", 
                    "ShadowAttribute": [], 
                    "UUID": "c320c9f6-4619-450a-b150-9c62e341fbfe", 
                    "ObjectID": "0", 
                    "Deleted": false, 
                    "Timestamp": "1565012014", 
                    "ToIDs": false, 
                    "Value": "www.example.com", 
                    "ID": "26128", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": null, 
                    "EventID": "743", 
                    "DisableCorrelation": false, 
                    "Type": "url", 
                    "Distribution": "0", 
                    "Galaxy": []
                }
            ]
            "Galaxy": []
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<h3>MISP Reputation for URL:<span> </span>www.example.com</h3>
<p> </p>
<table border="2">
<thead>
<tr>
<th>EventID</th>
<th>Organisation</th>
<th>Threat Level</th>
</tr>
</thead>
<tbody>
<tr>
<td>743</td>
<td>MISP.ORGNAME</td>
<td>HIGH</td>
</tr>
<tr>
<td>753</td>
<td>MISP.ORGNAME</td>
<td>HIGH</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h3 id="h_8ffb723c-d3f8-40fc-a15a-ecb8b011d507">5. Get the reputation of an IP address</h3>
<p> </p>
<hr>
<p> </p>
<p>Checks the reputation of an IP address</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>ip</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 270px;"><strong>Argument Name</strong></th>
<th style="width: 315px;"><strong>Description</strong></th>
<th style="width: 155px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 270px;">ip</td>
<td style="width: 315px;">IP address to check.</td>
<td style="width: 155px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 172px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 504px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 172px;">IP.Address</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 504px;">Bad IP address found.</td>
</tr>
<tr>
<td style="width: 172px;">IP.Malicious.Vendor</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 504px;">For malicious IPs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 172px;">IP.Malicious.Description</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 504px;">For malicious IPs, the reason that the vendor made the decision.       </td>
</tr>
<tr>
<td style="width: 172px;">DBotScore.Indicator</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 504px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 172px;">DBotScore.Type</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 504px;">Indicator type.</td>
</tr>
<tr>
<td style="width: 172px;">DBotScore.Vendor</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 504px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 172px;">DBotScore.Score</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 504px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!ip ip="8.8.3.3"</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "IP": [
        {
            "Malicious": {
                "Vendor": "MISP.ORGNAME", 
                "Description": "IP Found in MISP event: 743"
            }, 
            "Address": "8.8.3.3"
        }
    ], 
    "DBotScore": [
        {
            "Vendor": "MISP.ORGNAME", 
            "Indicator": "8.8.3.3", 
            "Score": 3, 
            "Type": "ip"
        }
    ], 
    "MISP.Event": [
        {
            "EventCreatorEmail": "admin@admin.test", 
            "SharingGroupID": "0", 
            "Organisation": {
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002", 
                "ID": "1", 
                "Name": "ORGNAME"
            }, 
            "ShadowAttribute": [], 
            "Distribution": "0", 
            "ProposalEmailLock": false, 
            "Timestamp": "1565013625", 
            "Object": [
            ],
            "Attribute": [
                {
                    "Category": "External analysis", 
                    "Comment": "Just an example", 
                    "ShadowAttribute": [], 
                    "UUID": "c320c9f6-4619-450a-b150-9c62e341fbfe", 
                    "ObjectID": "0", 
                    "Deleted": false, 
                    "Timestamp": "1565012014", 
                    "ToIDs": false, 
                    "Value": "8.8.3.3", 
                    "ID": "26128", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": null, 
                    "EventID": "743", 
                    "DisableCorrelation": false, 
                    "Type": "url", 
                    "Distribution": "0", 
                    "Galaxy": []
                }
            "Galaxy": []
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<h3>Results found in MISP for IP: 8.8.3.3</h3>
<p> </p>
<table>
<thead>
<tr>
<th>EventID</th>
<th>Organisation</th>
<th>Threat Level</th>
</tr>
</thead>
<tbody>
<tr>
<td>743</td>
<td>MISP.ORGNAME</td>
<td>HIGH</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h3 id="h_699dedd4-2412-4cb5-b6b1-aeaf965195e5">6. Create a MISP event</h3>
<p> </p>
<hr>
<p> </p>
<p>Creates a new MISP event.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-create-event</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 193px;"><strong>Argument Name</strong></th>
<th style="width: 435px;"><strong>Description</strong></th>
<th style="width: 112px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 193px;">type</td>
<td style="width: 435px;">Event type of the new event.</td>
<td style="width: 112px;">Optional</td>
</tr>
<tr>
<td style="width: 193px;">category</td>
<td style="width: 435px;">Category of the new event.</td>
<td style="width: 112px;">Optional</td>
</tr>
<tr>
<td style="width: 193px;">to_ids</td>
<td style="width: 435px;">Create the event with the IDS flag.</td>
<td style="width: 112px;">Optional</td>
</tr>
<tr>
<td style="width: 193px;">distribution</td>
<td style="width: 435px;">Where to distribute the attribute.</td>
<td style="width: 112px;">Optional</td>
</tr>
<tr>
<td style="width: 193px;">comment</td>
<td style="width: 435px;">Comment for the event.</td>
<td style="width: 112px;">Optional</td>
</tr>
<tr>
<td style="width: 193px;">value</td>
<td style="width: 435px;">Value to add to the event.</td>
<td style="width: 112px;">Required</td>
</tr>
<tr>
<td style="width: 193px;">info</td>
<td style="width: 435px;">Event name.</td>
<td style="width: 112px;">Required</td>
</tr>
<tr>
<td style="width: 193px;">published</td>
<td style="width: 435px;">Whether to publish the event.</td>
<td style="width: 112px;">Optional</td>
</tr>
<tr>
<td style="width: 193px;">threat_level_id</td>
<td style="width: 435px;">MISP Threat level ID. Default is "high".</td>
<td style="width: 112px;">Optional</td>
</tr>
<tr>
<td style="width: 193px;">analysis</td>
<td style="width: 435px;">The analysis level. Default is "initial".</td>
<td style="width: 112px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table>
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>MISP.Event.ID</td>
<td>number</td>
<td>MISP event ID.</td>
</tr>
<tr>
<td>MISP.Event.Distribution</td>
<td>number</td>
<td>MISP event distribution.</td>
</tr>
<tr>
<td>MISP.Event.ThreatLevelID</td>
<td>number</td>
<td>Threat level of the MISP event (1 High, 2 Medium, 3 Low, 4 Undefined).</td>
</tr>
<tr>
<td>MISP.Event.PublishTimestamp</td>
<td>number</td>
<td>Timestamp of the publish time (if published).</td>
</tr>
<tr>
<td>MISP.Event.EventCreatorEmail</td>
<td>string</td>
<td>Email address of the event creator.</td>
</tr>
<tr>
<td>MISP.Event.Date</td>
<td>date</td>
<td>Event creation date.</td>
</tr>
<tr>
<td>MISP.Event.Locked</td>
<td>boolean</td>
<td>Whether the event is locked.</td>
</tr>
<tr>
<td>MISP.Event.OwnerOrganisation.ID</td>
<td>number</td>
<td>Owner organization ID.</td>
</tr>
<tr>
<td>MISP.Event.OwnerOrganisation.Name</td>
<td>string</td>
<td>Owner organization name.</td>
</tr>
<tr>
<td>MISP.Event.OwnerOrganisation.UUID</td>
<td>string</td>
<td>Owner organization UUID.</td>
</tr>
<tr>
<td>MISP.Event.RelatedEvent.ID</td>
<td>number</td>
<td>Event IDs of related events (can be a list).</td>
</tr>
<tr>
<td>MISP.Event.ProposalEmailLock</td>
<td>boolean</td>
<td>Whether email lock is proposed.</td>
</tr>
<tr>
<td>MISP.Event.Timestamp</td>
<td>number</td>
<td>Timestamp of the event.</td>
</tr>
<tr>
<td>MISP.Event.Galaxy.Description</td>
<td>string</td>
<td>Event's galaxy description.</td>
</tr>
<tr>
<td>MISP.Event.Galaxy.Name</td>
<td>string</td>
<td>Galaxy name.</td>
</tr>
<tr>
<td>MISP.Event.Galaxy.Type</td>
<td>number</td>
<td>Galaxy type.</td>
</tr>
<tr>
<td>MISP.Event.Published</td>
<td>boolean</td>
<td>Whether the event is published.</td>
</tr>
<tr>
<td>MISP.Event.DisableCorrelation</td>
<td>boolean</td>
<td>Whether correlation is disabled.</td>
</tr>
<tr>
<td>MISP.Event.UUID</td>
<td>string</td>
<td>Event UUID.</td>
</tr>
<tr>
<td>MISP.Event.ShadowAttribute</td>
<td>Unknown</td>
<td>Event shadow attributes.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.Distribution</td>
<td>number</td>
<td>Attribute distribution.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.Value</td>
<td>string</td>
<td>Attribute value.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.EventID</td>
<td>number</td>
<td>Attribute event ID.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.Timestamp</td>
<td>number</td>
<td>Attribute timestamp.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.Deleted</td>
<td>boolean</td>
<td>Whether the attribute was deleted.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.DisableCorrelation</td>
<td>boolean</td>
<td>Whether attribute correlation is disabled.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.Type</td>
<td>string</td>
<td>Attribute type.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.ID</td>
<td>number</td>
<td>Attribute ID.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.UUID</td>
<td>string</td>
<td>Attribute UUID.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.ShadowAttribute</td>
<td>Unknown</td>
<td>Attribute shadow attribute.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.ToIDs</td>
<td>boolean</td>
<td>Is the Intrusion Detection System flag set.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.Category</td>
<td>string</td>
<td>Attribute category.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.SharingGroupID</td>
<td>number</td>
<td>Attribute sharing group ID.</td>
</tr>
<tr>
<td>MISP.Event.Attribute.Comment</td>
<td>string</td>
<td>Attribute comment for the attribute.</td>
</tr>
<tr>
<td>MISP.Event.Analysis</td>
<td>number</td>
<td>Event analysis (0 Initial, 1 Ongoing, 2 Completed).</td>
</tr>
<tr>
<td>MISP.Event.SharingGroupID</td>
<td>number</td>
<td>Event sharing group ID.</td>
</tr>
<tr>
<td>MISP.Event.Tag.Name</td>
<td>string</td>
<td>All tag names in the event.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-create-event info="Example event" value="www.example.com" category="External analysis" type="url" comment="Just an example"</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "MISP.Event": [
        {
            "EventCreatorEmail": "admin@admin.test", 
            "SharingGroupID": "0", 
            "Organisation": {
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002", 
                "ID": "1", 
                "Name": "ORGNAME"
            }, 
            "ShadowAttribute": [], 
            "Distribution": "0", 
            "ProposalEmailLock": false, 
            "Timestamp": "1565013591", 
            "Object": [], 
            "ThreatLevelID": "1", 
            "Date": "2019-08-05", 
            "RelatedEvent": [
                {
                    "ID": "743"
                }
            ], 
            "Info": "Example event", 
            "Locked": false, 
            "OwnerOrganisation": {
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002", 
                "ID": "1", 
                "Name": "ORGNAME"
            }, 
            "Analysis": "0", 
            "Published": false, 
            "DisableCorrelation": false, 
            "ID": "753", 
            "PublishTimestamp": "0", 
            "UUID": "5d483655-ac78-4765-9169-70f7ac110002", 
            "Attribute": [
                {
                    "Category": "External analysis", 
                    "Comment": "Just an example", 
                    "ShadowAttribute": [], 
                    "UUID": "8468ac01-126f-4e73-8cff-7371303014aa", 
                    "ObjectID": "0", 
                    "Deleted": false, 
                    "Timestamp": "1565013591", 
                    "ToIDs": false, 
                    "Value": "www.example.com", 
                    "ID": "26160", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": null, 
                    "EventID": "753", 
                    "DisableCorrelation": false, 
                    "Type": "url", 
                    "Distribution": "0", 
                    "Galaxy": []
                }
            ], 
            "Galaxy": []
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<h2>MISP create event</h2>
<p> </p>
<p>New event with ID: 753 has been successfully created.</p>
<p> </p>
<h3 id="h_2249eec0-1a73-42ef-8422-fc8f2bc9b167">7. Download a file sample</h3>
<p> </p>
<hr>
<p> </p>
<p>Downloads a file sample from MISP.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-download-sample</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 538px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">hash</td>
<td style="width: 538px;">A hash in MD5 format. If the "allSamples" argument is supplied, this can be any one of the following: md5, sha1, and sha256.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">eventID</td>
<td style="width: 538px;">If set, will only fetch data from the given event ID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">allSamples</td>
<td style="width: 538px;">If set, will return all samples from events that match the hash supplied in the "hash
" argument.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">unzip</td>
<td style="width: 538px;">Return one zipped file, or all files unzipped. Default is "false" (one zipped file).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-download-sample hash="3d74da0a7276735f1afae01951b39ff7a9d92c94"</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<p>Couldn't find file with hash 3d74da0a7276735f1afae01951b39ff7a9d92c94</p>
<p> </p>
<h3 id="h_d770e98c-2d22-49f0-b875-d5a5e760e775">8. Add an attribute to an event</h3>
<p> </p>
<hr>
<p> </p>
<p>Adds an attribute to an existing MISP event.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-add-attribute</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 155px;"><strong>Argument Name</strong></th>
<th style="width: 502px;"><strong>Description</strong></th>
<th style="width: 83px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">id</td>
<td style="width: 502px;">MISP event ID.</td>
<td style="width: 83px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">type</td>
<td style="width: 502px;">Attribute type.</td>
<td style="width: 83px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">category</td>
<td style="width: 502px;">Attribute category.</td>
<td style="width: 83px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">to_ids</td>
<td style="width: 502px;">Whether to return only events set with the "to_ids" flag. Default is "true".</td>
<td style="width: 83px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">distribution</td>
<td style="width: 502px;">Where to distribute the attribute.</td>
<td style="width: 83px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">comment</td>
<td style="width: 502px;">Comment for the event.</td>
<td style="width: 83px;">.Required</td>
</tr>
<tr>
<td style="width: 155px;">value</td>
<td style="width: 502px;">Attribute value</td>
<td style="width: 83px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 284px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 395px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 284px;">MISP.Event.ID</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">MISP event ID.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Distribution</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">MISP event distribution.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.ThreatLevelID</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Threat level of the MISP event (1 High, 2 Medium, 3 Low, 4 Undefined).</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.PublishTimestamp</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Timestamp of the publish time (if published).</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.EventCreatorEmail</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">Email address of the event creator.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Date</td>
<td style="width: 59px;">date</td>
<td style="width: 395px;">Event creation date.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Locked</td>
<td style="width: 59px;">boolean</td>
<td style="width: 395px;">Is the event locked.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.OwnerOrganisation.ID</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Owner organization ID.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.OwnerOrganisation.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">Owner organization name.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.OwnerOrganisation.UUID</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">Owner organization UUID.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.RelatedEvent.ID</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Event IDs of related events (can be a list).</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.ProposalEmailLock</td>
<td style="width: 59px;">boolean</td>
<td style="width: 395px;">Wheter email lock is proposed.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Timestamp</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Timestamp of the event.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Galaxy.Description</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">Galaxy description.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Galaxy.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">Galaxy name.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Galaxy.Type</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Galaxy type.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Published</td>
<td style="width: 59px;">boolean</td>
<td style="width: 395px;">Whether the event is published.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.DisableCorrelation</td>
<td style="width: 59px;">boolean</td>
<td style="width: 395px;">Whether correlation disabled.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.UUID</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">Event UUID.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.ShadowAttribute</td>
<td style="width: 59px;">Unknown</td>
<td style="width: 395px;">Event shadow attributes.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.Distribution</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Attribute distribution.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.Value</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">Attribute value.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.EventID</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Attribute event ID.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.Timestamp</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Attribute timestamp.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.Deleted</td>
<td style="width: 59px;">boolean</td>
<td style="width: 395px;">Whether the attribute was deleted.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.DisableCorrelation</td>
<td style="width: 59px;">boolean</td>
<td style="width: 395px;">Whether attribute correlation is disabled.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.Type</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">Attribute type.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.ID</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Attribute ID.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.UUID</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">Attribute UUID.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.ShadowAttribute</td>
<td style="width: 59px;">Unknown</td>
<td style="width: 395px;">Attribute shadow attribute.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.ToIDs</td>
<td style="width: 59px;">boolean</td>
<td style="width: 395px;">Whether the Intrusion Detection System flag is set.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.Category</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">Attribute category.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.SharingGroupID</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Attribute sharing group ID.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Attribute.Comment</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">Attribute comment.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Analysis</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Event analysis (0 Initial, 1 Ongoing, 2 Completed).</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.SharingGroupID</td>
<td style="width: 59px;">number</td>
<td style="width: 395px;">Event sharing group ID.</td>
</tr>
<tr>
<td style="width: 284px;">MISP.Event.Tag.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 395px;">All tag names in the event.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-add-attribute id=743 comment="Unknown IP" value="8.8.3.3" category="Payload delivery" type="ip-src"</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "MISP.Event": [
        {
            "EventCreatorEmail": "admin@admin.test", 
            "SharingGroupID": "0", 
            "Organisation": {
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002", 
                "ID": "1", 
                "Name": "ORGNAME"
            }, 
            "ShadowAttribute": [], 
            "Distribution": "0", 
            "ProposalEmailLock": false, 
            "Timestamp": "1565013607", 
            "Object": [
                {
                    "Comment": "", 
                    "EventID": "743", 
                    "Timestamp": "1565012146", 
                    "Description": "An IP address (or domain or hostname) and a port seen as a tuple (or as a triple) in a specific time frame.", 
                    "UUID": "3c90797e-2aba-4ac2-bc4a-73c797425e1f", 
                    "Deleted": false, 
                    "Attribute": [
                        {
                            "Category": "Network activity", 
                            "Comment": "", 
                            "ShadowAttribute": [], 
                            "UUID": "e3ada1ae-da37-4efe-9581-73aa95960624", 
                            "ObjectID": "3223", 
                            "Deleted": false, 
                            "Timestamp": "1565012146", 
                            "ToIDs": false, 
                            "Value": "8080", 
                            "ID": "26137", 
                            "SharingGroupID": "0", 
                            "ObjectRelation": "dst-port", 
                            "EventID": "743", 
                            "DisableCorrelation": true, 
                            "Type": "port", 
                            "Distribution": "5", 
                            "Galaxy": []
                        }, 
                        {
                            "Category": "Network activity", 
                            "Comment": "", 
                            "ShadowAttribute": [], 
                            "UUID": "287e1b44-24c1-45b9-9ef9-541d00ae447b", 
                            "ObjectID": "3223", 
                            "Deleted": false, 
                            "Timestamp": "1565012146", 
                            "ToIDs": true, 
                            "Value": "google.com", 
                            "ID": "26138", 
                            "SharingGroupID": "0", 
                            "ObjectRelation": "domain", 
                            "EventID": "743", 
                            "DisableCorrelation": false, 
                            "Type": "domain", 
                            "Distribution": "5", 
                            "Galaxy": []
                        }, 
                        {
                            "Category": "Network activity", 
                            "Comment": "", 
                            "ShadowAttribute": [], 
                            "UUID": "5ef0f03b-f85a-4d8d-97c3-c3f740623a73", 
                            "ObjectID": "3223", 
                            "Deleted": false, 
                            "Timestamp": "1565012146", 
                            "ToIDs": true, 
                            "Value": "8.8.8.8", 
                            "ID": "26139", 
                            "SharingGroupID": "0", 
                            "ObjectRelation": "ip", 
                            "EventID": "743", 
                            "DisableCorrelation": false, 
                            "Type": "ip-dst", 
                            "Distribution": "5", 
                            "Galaxy": []
                        }, 
                        {
                            "Category": "Network activity", 
                            "Comment": "", 
                            "ShadowAttribute": [], 
                            "UUID": "953e3da1-a4b5-4fe2-8d35-7e1afdb72e74", 
                            "ObjectID": "3223", 
                            "Deleted": false, 
                            "Timestamp": "1565012146", 
                            "ToIDs": true, 
                            "Value": "4.4.4.4", 
                            "ID": "26140", 
                            "SharingGroupID": "0", 
                            "ObjectRelation": "ip", 
                            "EventID": "743", 
                            "DisableCorrelation": false, 
                            "Type": "ip-dst", 
                            "Distribution": "5", 
                            "Galaxy": []
                        }, 
                        {
                            "Category": "Other", 
                            "Comment": "", 
                            "ShadowAttribute": [], 
                            "UUID": "f1d3cd7e-ed01-4aba-bb8f-65c0ac119707", 
                            "ObjectID": "3223", 
                            "Deleted": false, 
                            "Timestamp": "1565012146", 
                            "ToIDs": false, 
                            "Value": "2018-05-05", 
                            "ID": "26141", 
                            "SharingGroupID": "0", 
                            "ObjectRelation": "first-seen", 
                            "EventID": "743", 
                            "DisableCorrelation": true, 
                            "Type": "datetime", 
                            "Distribution": "5", 
                            "Galaxy": []
                        }
                    ], 
                    "TemplateUUID": "9f8cea74-16fe-4968-a2b4-026676949ac6", 
                    "TemplateVersion": "7", 
                    "SharingGroupID": "0", 
                    "ObjectReference": [], 
                    "MetaCategory": "network", 
                    "Distribution": "5", 
                    "ID": "3223", 
                    "Name": "ip-port"
                },
            ], 
            "ThreatLevelID": "1", 
            "Date": "2019-08-05", 
            "RelatedEvent": [
                {
                    "ID": "753"
                }
            ], 
            "Info": "Example event", 
            "Locked": false, 
            "OwnerOrganisation": {
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002", 
                "ID": "1", 
                "Name": "ORGNAME"
            }, 
            "Analysis": "0", 
            "Published": false, 
            "DisableCorrelation": false, 
            "ID": "743", 
            "PublishTimestamp": "0", 
            "UUID": "5d48302c-bf84-4671-9080-0728ac110002", 
            "Attribute": [], 
            "Galaxy": []
        }
    ]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<h2>MISP add attribute</h2>
<p> </p>
<p>New attribute: 8.8.3.3 was added to event id 743.</p>
<p> </p>
<h3 id="h_f325c9d3-2e07-46e9-8e69-6b96f9030909">9 Upload a file sample</h3>
<p> </p>
<hr>
<p> </p>
<p>Uploads a file sample to MISP.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-upload-sample</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 157.8px;"><strong>Argument Name</strong></th>
<th style="width: 509.2px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 157.8px;">fileEntryID</td>
<td style="width: 509.2px;">Entry ID of the file to upload.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 157.8px;">event_id</td>
<td style="width: 509.2px;">The event ID of the event to which to add the uploaded file.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157.8px;">distribution</td>
<td style="width: 509.2px;">The distribution setting used for the attributes and for the newly created event, if relevant (0-3).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157.8px;">to_ids</td>
<td style="width: 509.2px;">Flags all attributes created during the transaction to be marked as "to_ids" or not.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157.8px;">category</td>
<td style="width: 509.2px;">The category that will be assigned to the uploaded samples, (Payload delivery, Artifacts dropped, Payload Installation, External Analysis).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157.8px;">info</td>
<td style="width: 509.2px;">Used to populate the event info field if no event ID is supplied. Alternatively, if not supplied, MISP will generate a message showing that it is a malware sample collection generated on the given day.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157.8px;">analysis</td>
<td style="width: 509.2px;">The analysis level. Default is "initial".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157.8px;">threat_level_id</td>
<td style="width: 509.2px;">The threat level ID of the newly created event. Default is "high".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157.8px;">comment</td>
<td style="width: 509.2px;">This will populate the comment field of any attribute created using this API.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
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
<td>MISP.UploadedSample</td>
<td>Unknown</td>
<td>Object containing {filename: event id} of the uploaded file.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-upload-sample fileEntryID=655@6 info="MISP V2 Integration"</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "MISP.UploadedSample": {
        "MISP_V2_unified.yml": 754
    }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<p>MISP upload sample</p>
<p> </p>
<ul>
<li>message: Success, saved all attributes.</li>
<li>event id: 754</li>
<li>file name: MISP_V2_unified.yml</li>
</ul>
<p> </p>
<h3 id="h_bc997769-2b6d-4324-afde-74ec8b896ee2">10. Delete an event</h3>
<p> </p>
<hr>
<p> </p>
<p>Deletes an event according to event ID.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-delete-event</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 276.4px;"><strong>Argument Name</strong></th>
<th style="width: 302.6px;"><strong>Description</strong></th>
<th style="width: 160px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 276.4px;">event_id</td>
<td style="width: 302.6px;">Event ID to delete.</td>
<td style="width: 160px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-delete-event event_id=735</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<h3 id="h_d47d7978-435a-4999-ba8a-2f581356f032">11. Add a tag to an event or attribute</h3>
<p> </p>
<hr>
<p> </p>
<p>Adds a tag to the given UUID event or attribute.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-add-tag</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 138.6px;"><strong>Argument Name</strong></th>
<th style="width: 529.4px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138.6px;">uuid</td>
<td style="width: 529.4px;">UUID of the attribute/event, for example: "59575300-4be8-4ff6-8767-0037ac110032".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138.6px;">tag</td>
<td style="width: 529.4px;">Tag to add to the attribute or event.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 284.4px;"><strong>Path</strong></th>
<th style="width: 59.6px;"><strong>Type</strong></th>
<th style="width: 395px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 284.4px;">MISP.Event.ID</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">MISP event ID.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Distribution</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">MISP event distribution.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.ThreatLevelID</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Threat level of the MISP event (1 High, 2 Medium, 3 Low, 4 Undefined).</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.PublishTimestamp</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Timestamp of the publish time (if published).</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.EventCreatorEmail</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">Email address of the event creator.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Date</td>
<td style="width: 59.6px;">date</td>
<td style="width: 395px;">Event creation date.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Locked</td>
<td style="width: 59.6px;">boolean</td>
<td style="width: 395px;">Whether the event is locked.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.OwnerOrganisation.ID</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Owner organization ID.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.OwnerOrganisation.Name</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">Owner organization name.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.OwnerOrganisation.UUID</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">Owner organization UUID.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.RelatedEvent.ID</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Event IDs of related events (can be a list).</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.ProposalEmailLock</td>
<td style="width: 59.6px;">boolean</td>
<td style="width: 395px;">Whether email lock is proposed.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Timestamp</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Timestamp of the event.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Galaxy.Description</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">Galaxy description.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Galaxy.Name</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">Galaxy name.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Galaxy.Type</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Galaxy type</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Published</td>
<td style="width: 59.6px;">boolean</td>
<td style="width: 395px;">Whether the event is published.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.DisableCorrelation</td>
<td style="width: 59.6px;">boolean</td>
<td style="width: 395px;">Whether correlation is disabled.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.UUID</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">Event UUID.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.ShadowAttribute</td>
<td style="width: 59.6px;">Unknown</td>
<td style="width: 395px;">Event shadow attributes.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.Distribution</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Attribute distribution.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.Value</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">Attribute value.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.EventID</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Attribute event ID.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.Timestamp</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Attribute timestamp.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.Deleted</td>
<td style="width: 59.6px;">boolean</td>
<td style="width: 395px;">Is the attribute deleted.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.DisableCorrelation</td>
<td style="width: 59.6px;">boolean</td>
<td style="width: 395px;">Is attribute correlation disabled.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.Type</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">Attribute type.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.ID</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Attribute ID.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.UUID</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">Attribute UUID.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.ShadowAttribute</td>
<td style="width: 59.6px;">Unknown</td>
<td style="width: 395px;">Attribute shadow attribute.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.ToIDs</td>
<td style="width: 59.6px;">boolean</td>
<td style="width: 395px;">Is the Intrusion Detection System flag set.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.Category</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">Attribute category.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.SharingGroupID</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Attribute sharing group ID.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Attribute.Comment</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">Attribute comment.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Analysis</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Event analysis (0 Initial, 1 Ongoing, 2 Completed).</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.SharingGroupID</td>
<td style="width: 59.6px;">number</td>
<td style="width: 395px;">Event sharing group ID.</td>
</tr>
<tr>
<td style="width: 284.4px;">MISP.Event.Tag.Name</td>
<td style="width: 59.6px;">string</td>
<td style="width: 395px;">All tag names in the event.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-add-tag tag="Example tag" uuid=5ce29ac4-3b54-459e-a6ee-00acac110002</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "MISP.Event": []
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<p>Tag Example tag has been successfully added to event 5ce29ac4-3b54-459e-a6ee-00acac110002</p>
<p> </p>
<h3 id="h_04357de2-77f9-48d7-a47e-bc4e9ec2c563">12. Add sighting to an attribute</h3>
<p> </p>
<hr>
<p> </p>
<p>Adds sighting to an attribute. The id and uuid arguments are optional, but one must be specified in the command.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-add-sighting</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table>
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>type</td>
<td>Type of sighting to add.</td>
<td>Required</td>
</tr>
<tr>
<td>id</td>
<td>ID of the attribute to which to add a sighting. Required if <em>uuid</em> is empty. Can be retrieved from the misp-search command.</td>
<td>Optional</td>
</tr>
<tr>
<td>uuid</td>
<td>UUID of the attribute to which to add a sighting. Required if <em>id</em> is empty. Can be retrieved from the misp-search command.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-add-sighting type=sighting uuid=23513ce2-2060-4bc8-9b44-6bd735e4f740</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<p>Sighting 'sighting' has been successfully added to attribute 23513ce2-2060-4bc8-9b44-6bd735e4f740</p>
<p> </p>
<h3 id="h_92415f70-7f80-4d61-98a1-696a40fc3c73">13. Add an OSINT feed</h3>
<p> </p>
<hr>
<p> </p>
<p>Adds an OSINT feed.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-add-events-from-feed</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 230.8px;"><strong>Argument Name</strong></th>
<th style="width: 384.2px;"><strong>Description</strong></th>
<th style="width: 123px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 230.8px;">feed</td>
<td style="width: 384.2px;">URL of the feed to add.</td>
<td style="width: 123px;">Optional</td>
</tr>
<tr>
<td style="width: 230.8px;">limit</td>
<td style="width: 384.2px;">Maximum number of files to add.</td>
<td style="width: 123px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 214.4px;"><strong>Path</strong></th>
<th style="width: 106.6px;"><strong>Type</strong></th>
<th style="width: 418px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 214.4px;">MISP.Event.ID</td>
<td style="width: 106.6px;">number</td>
<td style="width: 418px;">IDs of newly created events.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-add-events-from-feed limit=14 feed=CIRCL</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<h5>Total of 0 events was added to MISP.</h5>
<p> </p>
<h3 id="h_f2dd36fd-1ac6-40ef-81ad-3a6b4422b342">14. Add an email object to an event</h3>
<p> </p>
<hr>
<p> </p>
<p>Adds an email object to the specified event ID.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-add-email-object</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 199.4px;"><strong>Argument Name</strong></th>
<th style="width: 433.6px;"><strong>Description</strong></th>
<th style="width: 106px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 199.4px;">entry_id</td>
<td style="width: 433.6px;">Entry ID of the email.</td>
<td style="width: 106px;">Required</td>
</tr>
<tr>
<td style="width: 199.4px;">event_id</td>
<td style="width: 433.6px;">ID of the event to which to add the object.</td>
<td style="width: 106px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 334.8px;"><strong>Path</strong></th>
<th style="width: 60.2px;"><strong>Type</strong></th>
<th style="width: 345px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334.8px;">MISP.Event.ID</td>
<td style="width: 60.2px;">number</td>
<td style="width: 345px;">MISP event ID.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.MetaCategory</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Object meta category.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Distribution</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">Distribution of object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Name</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Name of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.TemplateVersion</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">Template version of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.EventID</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">ID of the event in which the object was first created.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.TemplateUUID</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">UUID of the template.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Timestamp</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Timestamp when the object was created.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Deleted</td>
<td style="width: 60.2px;">Boolean</td>
<td style="width: 345px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.ID</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">ID of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.UUID</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">UUID of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Value</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Value of the attribute.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.EventID</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">ID of the first event from which the object originated.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Timestamp</td>
<td style="width: 60.2px;">Date</td>
<td style="width: 345px;">Timestamp when the object was created.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Deleted</td>
<td style="width: 60.2px;">Boolean</td>
<td style="width: 345px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.ObjectID</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">ID of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.DisableCorrelation</td>
<td style="width: 60.2px;">Boolean</td>
<td style="width: 345px;">Whether correlation is disabled.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.ID</td>
<td style="width: 60.2px;">Unknown</td>
<td style="width: 345px;">ID of the attribute.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.ObjectRelation</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Relation of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Type</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Object type.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.UUID</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">UUID of the attribute.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.ToIDs</td>
<td style="width: 60.2px;">Boolean</td>
<td style="width: 345px;">Whether the to_ids flag is on.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Category</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Category of the attribute.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.SharingGroupID</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">ID of the sharing group.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Comment</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Comment of the attribute.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Description</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Description of the object.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-add-email-object event_id=743 entry_id=678@6</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "MISP.Event": {
        "Object": {
            "Comment": "", 
            "EventID": "743", 
            "Timestamp": "1565013620", 
            "Description": "Email object describing an email with meta-information", 
            "UUID": "e00e6a2c-682b-48b3-bb01-aee21832ebf0", 
            "Deleted": false, 
            "Attribute": [
                {
                    "Category": "External analysis", 
                    "Comment": "", 
                    "UUID": "52d1d881-a1fb-4a2c-b5bc-047fb0073c2f", 
                    "ObjectID": "3231", 
                    "Deleted": false, 
                    "Timestamp": "1565013620", 
                    "ToIDs": false, 
                    "Value": "Full email.eml", 
                    "ID": "26175", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "eml", 
                    "EventID": "743", 
                    "value1": "Full email.eml", 
                    "DisableCorrelation": true, 
                    "Type": "attachment", 
                    "Distribution": "5", 
                    "value2": ""
                }
                {
                    "Category": "Payload delivery", 
                    "Comment": "", 
                    "UUID": "5ddaae1c-ce54-4191-9d61-907d2c101103", 
                    "ObjectID": "3231", 
                    "Deleted": false, 
                    "Timestamp": "1565013620", 
                    "ToIDs": false, 
                    "Value": "&lt;example.gmail.com&gt;", 
                    "ID": "26177", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "message-id", 
                    "EventID": "743", 
                    "value1": "&lt;example.gmail.com&gt;", 
                    "DisableCorrelation": true, 
                    "Type": "email-message-id", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Network activity", 
                    "Comment": "", 
                    "UUID": "26daac8a-730e-4951-bad1-d8134feba2cb", 
                    "ObjectID": "3231", 
                    "Deleted": false, 
                    "Timestamp": "1565013620", 
                    "ToIDs": true, 
                    "Value": "\"Example Demisto (ca)\" &lt;example@demisto.com&gt;", 
                    "ID": "26178", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "to", 
                    "EventID": "743", 
                    "value1": "\"Example Demisto (ca)\" &lt;example.&gt;", 
                    "DisableCorrelation": true, 
                    "Type": "email-dst", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Payload delivery", 
                    "Comment": "", 
                    "UUID": "d6ca6b5f-edba-4d46-9a9f-15fec4f6bd2b", 
                    "ObjectID": "3231", 
                    "Deleted": false, 
                    "Timestamp": "1565013620", 
                    "ToIDs": false, 
                    "Value": "[TEST][DEMISTO] CASO 1 EMAIL DA SISTEMA DEMISTO | ZIP+PASSWORD", 
                    "ID": "26179", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "subject", 
                    "EventID": "743", 
                    "value1": "[TEST][DEMISTO] CASO 1 EMAIL DA SISTEMA DEMISTO | ZIP+PASSWORD", 
                    "DisableCorrelation": false, 
                    "Type": "email-subject", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Payload delivery", 
                    "Comment": "", 
                    "UUID": "983eaba4-a94e-49ab-ae18-40151778a9ba", 
                    "ObjectID": "3231", 
                    "Deleted": false, 
                    "Timestamp": "1565013620", 
                    "ToIDs": true, 
                    "Value": "\"Example Demisto (ca)\" &lt;example@demisto.com&gt;", 
                    "ID": "26180", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "from", 
                    "EventID": "743", 
                    "value1": "\"Example Demisto (ca)\" &lt;example@demisto.com&gt;", 
                    "DisableCorrelation": false, 
                    "Type": "email-src", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Payload delivery", 
                    "Comment": "", 
                    "UUID": "c432d6c7-5d34-4b64-a6b4-5813d1874bd2", 
                    "ObjectID": "3231", 
                    "Deleted": false, 
                    "Timestamp": "1565013620", 
                    "ToIDs": true, 
                    "Value": "example@demisto.com", 
                    "ID": "26181", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "return-path", 
                    "EventID": "743", 
                    "value1": "example@demisto.com", 
                    "DisableCorrelation": false, 
                    "Type": "email-src", 
                    "Distribution": "5", 
                    "value2": ""
                }
            ], 
            "TemplateUUID": "a0c666e0-fc65-4be8-b48f-3423d788b552", 
            "TemplateVersion": "12", 
            "SharingGroupID": "0", 
            "MetaCategory": "network", 
            "Distribution": "5", 
            "ID": "3231", 
            "Name": "email"
        }, 
        "ID": "743"
    }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<p>Object has been added to MISP event ID 743</p>
<p> </p>
<h3 id="h_7fbf18d8-075a-422f-b28f-217948bc5182">15. Add a domain object to an event</h3>
<p> </p>
<hr>
<p> </p>
<p>Adds a domain object.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-add-domain-object</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 509px;"><strong>Description</strong></th>
<th style="width: 79px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">event_id</td>
<td style="width: 509px;">ID of a MISP event.</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">name</td>
<td style="width: 509px;">The domain name, for example: "google.com".</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">dns</td>
<td style="width: 509px;">A list (array) or IP addresses resolved by DNS.</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">creation_date</td>
<td style="width: 509px;">Date that the domain was created.</td>
<td style="width: 79px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">last_seen</td>
<td style="width: 509px;">Datetime that the domain was last seen, for example:<span> </span><code>2019-02-03</code>.</td>
<td style="width: 79px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">first_seen</td>
<td style="width: 509px;">Datetime that the domain was first seen, for example:<span> </span><code>2019-02-03</code>.</td>
<td style="width: 79px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">text</td>
<td style="width: 509px;">A description of the domain.</td>
<td style="width: 79px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 334.8px;"><strong>Path</strong></th>
<th style="width: 60.2px;"><strong>Type</strong></th>
<th style="width: 345px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334.8px;">MISP.Event.ID</td>
<td style="width: 60.2px;">number</td>
<td style="width: 345px;">MISP event ID.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.MetaCategory</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Object meta category.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Distribution</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">Distribution of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Name</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Name of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.TemplateVersion</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">Template version of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.EventID</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">ID of the event in which the object was first created.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.TemplateUUID</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">UUID of the template.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Timestamp</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Timestamp when the object was created.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Deleted</td>
<td style="width: 60.2px;">Boolean</td>
<td style="width: 345px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.ID</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">ID of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.UUID</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">UUID of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Value</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Value of the attribute.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.EventID</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">ID of the first event from which the object originated.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Timestamp</td>
<td style="width: 60.2px;">Date</td>
<td style="width: 345px;">Timestamp of object creation</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Deleted</td>
<td style="width: 60.2px;">Boolean</td>
<td style="width: 345px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.ObjectID</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">ID of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.DisableCorrelation</td>
<td style="width: 60.2px;">Boolean</td>
<td style="width: 345px;">Whether correlation is disabled.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.ID</td>
<td style="width: 60.2px;">Unknown</td>
<td style="width: 345px;">ID of the attribute.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.ObjectRelation</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Relation of the object.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Type</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Object type.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.UUID</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">UUID of the attribute.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.ToIDs</td>
<td style="width: 60.2px;">Boolean</td>
<td style="width: 345px;">Whether the to_ids flag is on.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Category</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Category of the attribute.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.SharingGroupID</td>
<td style="width: 60.2px;">Number</td>
<td style="width: 345px;">ID of the sharing group.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Attribute.Comment</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Comment of the attribute.</td>
</tr>
<tr>
<td style="width: 334.8px;">MISP.Event.Object.Description</td>
<td style="width: 60.2px;">String</td>
<td style="width: 345px;">Description of the object.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-add-domain-object event_id=743 dns="8.8.8.8,8.8.4.4" name="google.com" text="Google DNS"</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "MISP.Event": {
        "Object": {
            "Comment": "", 
            "EventID": "743", 
            "Timestamp": "1565013623", 
            "Description": "A domain and IP address seen as a tuple in a specific time frame.", 
            "UUID": "ee732c55-78d4-4e2a-8616-e1b07c85397b", 
            "Deleted": false, 
            "Attribute": [
                {
                    "Category": "Network activity", 
                    "Comment": "", 
                    "UUID": "c52ec904-30c9-47ce-a7d5-a1aaa9326576", 
                    "ObjectID": "3232", 
                    "Deleted": false, 
                    "Timestamp": "1565013623", 
                    "ToIDs": true, 
                    "Value": "8.8.8.8", 
                    "ID": "26182", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "ip", 
                    "EventID": "743", 
                    "value1": "8.8.8.8", 
                    "DisableCorrelation": false, 
                    "Type": "ip-dst", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Network activity", 
                    "Comment": "", 
                    "UUID": "b48f0132-c90a-4b79-ae12-190476155b47", 
                    "ObjectID": "3232", 
                    "Deleted": false, 
                    "Timestamp": "1565013623", 
                    "ToIDs": true, 
                    "Value": "8.8.4.4", 
                    "ID": "26183", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "ip", 
                    "EventID": "743", 
                    "value1": "8.8.4.4", 
                    "DisableCorrelation": false, 
                    "Type": "ip-dst", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Network activity", 
                    "Comment": "", 
                    "UUID": "8fc80065-07ca-4151-b8e4-df919aa53dbb", 
                    "ObjectID": "3232", 
                    "Deleted": false, 
                    "Timestamp": "1565013623", 
                    "ToIDs": true, 
                    "Value": "google.com", 
                    "ID": "26184", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "domain", 
                    "EventID": "743", 
                    "value1": "google.com", 
                    "DisableCorrelation": false, 
                    "Type": "domain", 
                    "Distribution": "5", 
                    "value2": ""
                }
            ], 
            "TemplateUUID": "43b3b146-77eb-4931-b4cc-b66c60f28734", 
            "TemplateVersion": "6", 
            "SharingGroupID": "0", 
            "MetaCategory": "network", 
            "Distribution": "5", 
            "ID": "3232", 
            "Name": "domain-ip"
        }, 
        "ID": "743"
    }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<p>Object has been added to MISP event ID 743</p>
<p> </p>
<h3 id="h_c495c545-f854-4bd3-b65c-c703415cf1b4">16. Add a URL object to an event</h3>
<p> </p>
<hr>
<p> </p>
<p>Adds a URL object to a MISP event.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-add-url-object</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 162px;"><strong>Argument Name</strong></th>
<th style="width: 492px;"><strong>Description</strong></th>
<th style="width: 86px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162px;">url</td>
<td style="width: 492px;">Full URL to add to the event.</td>
<td style="width: 86px;">Required</td>
</tr>
<tr>
<td style="width: 162px;">first_seen</td>
<td style="width: 492px;">Date that this URL was first seen, for example:<span> </span><code>2019-02-03</code>.</td>
<td style="width: 86px;">Optional</td>
</tr>
<tr>
<td style="width: 162px;">text</td>
<td style="width: 492px;">Description of the URL.</td>
<td style="width: 86px;">Optional</td>
</tr>
<tr>
<td style="width: 162px;">last_seen</td>
<td style="width: 492px;">Date that this URL was last seen, for example:<span> </span><code>2019-02-03</code>.</td>
<td style="width: 86px;">Optional</td>
</tr>
<tr>
<td style="width: 162px;">event_id</td>
<td style="width: 492px;">ID of the event.</td>
<td style="width: 86px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 333.8px;"><strong>Path</strong></th>
<th style="width: 61.2px;"><strong>Type</strong></th>
<th style="width: 345px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 333.8px;">MISP.Event.ID</td>
<td style="width: 61.2px;">number</td>
<td style="width: 345px;">MISP event ID.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.MetaCategory</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Object meta category.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Distribution</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">Distribution of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Name</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Name of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.TemplateVersion</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">Template version of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.EventID</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">ID of the event in which the object was first created.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.TemplateUUID</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">UUID of the template.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Timestamp</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Timestamp when the object was created.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Deleted</td>
<td style="width: 61.2px;">Boolean</td>
<td style="width: 345px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.ID</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">ID of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.UUID</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">UUID of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Value</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Value of the attribute.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.EventID</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">ID of the first event from which the object originated.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Timestamp</td>
<td style="width: 61.2px;">Date</td>
<td style="width: 345px;">Timestamp when the object was created.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Deleted</td>
<td style="width: 61.2px;">Boolean</td>
<td style="width: 345px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.ObjectID</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">ID of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.DisableCorrelation</td>
<td style="width: 61.2px;">Boolean</td>
<td style="width: 345px;">Whether correlation is disabled.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.ID</td>
<td style="width: 61.2px;">Unknown</td>
<td style="width: 345px;">ID of the attribute.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.ObjectRelation</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Relation of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Type</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Object type.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.UUID</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">UUID of the attribute.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.ToIDs</td>
<td style="width: 61.2px;">Boolean</td>
<td style="width: 345px;">Whether the to_ids flag is on.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Category</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Category of the attribute.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.SharingGroupID</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">ID of the sharing group.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Comment</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Comment of the attribute.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Description</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Description of the object.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-add-url-object event_id=743 url=https://github.com/MISP/misp-objects/blob/master/objects/url/definition.json?q=1</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "MISP.Event": {
        "Object": {
            "Comment": "", 
            "EventID": "743", 
            "Timestamp": "1565013625", 
            "Description": "url object describes an url along with its normalized field (like extracted using faup parsing library) and its metadata.", 
            "UUID": "f2da7f70-0fa9-446d-8c0e-e2b87f348d3d", 
            "Deleted": false, 
            "Attribute": [
                {
                    "Category": "Network activity", 
                    "Comment": "", 
                    "UUID": "9abd47bd-749a-40a1-a79d-1dc8aa9d843f", 
                    "ObjectID": "3233", 
                    "Deleted": false, 
                    "Timestamp": "1565013625", 
                    "ToIDs": true, 
                    "Value": "https://github.com/MISP/misp-objects/blob/master/objects/url/definition.json?q=1", 
                    "ID": "26185", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "url", 
                    "EventID": "743", 
                    "value1": "https://github.com/MISP/misp-objects/blob/master/objects/url/definition.json?q=1", 
                    "DisableCorrelation": false, 
                    "Type": "url", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Other", 
                    "Comment": "", 
                    "UUID": "b8595c60-8eca-4963-8bf9-656adbe86566", 
                    "ObjectID": "3233", 
                    "Deleted": false, 
                    "Timestamp": "1565013625", 
                    "ToIDs": false, 
                    "Value": "https", 
                    "ID": "26186", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "scheme", 
                    "EventID": "743", 
                    "value1": "https", 
                    "DisableCorrelation": true, 
                    "Type": "text", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Other", 
                    "Comment": "", 
                    "UUID": "3f7a901d-07ac-4b65-9cf1-a2470d229a90", 
                    "ObjectID": "3233", 
                    "Deleted": false, 
                    "Timestamp": "1565013625", 
                    "ToIDs": false, 
                    "Value": "/MISP/misp-objects/blob/master/objects/url/definition.json", 
                    "ID": "26187", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "resource_path", 
                    "EventID": "743", 
                    "value1": "/MISP/misp-objects/blob/master/objects/url/definition.json", 
                    "DisableCorrelation": false, 
                    "Type": "text", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Other", 
                    "Comment": "", 
                    "UUID": "8c2c385b-4f75-4aac-a670-15fe9eb08ce5", 
                    "ObjectID": "3233", 
                    "Deleted": false, 
                    "Timestamp": "1565013625", 
                    "ToIDs": false, 
                    "Value": "q=1", 
                    "ID": "26188", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "query_string", 
                    "EventID": "743", 
                    "value1": "q=1", 
                    "DisableCorrelation": false, 
                    "Type": "text", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Network activity", 
                    "Comment": "", 
                    "UUID": "5098cb2c-27d8-483f-b467-b6d5732a2008", 
                    "ObjectID": "3233", 
                    "Deleted": false, 
                    "Timestamp": "1565013625", 
                    "ToIDs": true, 
                    "Value": "github.com", 
                    "ID": "26189", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "domain", 
                    "EventID": "743", 
                    "value1": "github.com", 
                    "DisableCorrelation": false, 
                    "Type": "domain", 
                    "Distribution": "5", 
                    "value2": ""
                }
            ], 
            "TemplateUUID": "60efb77b-40b5-4c46-871b-ed1ed999fce5", 
            "TemplateVersion": "7", 
            "SharingGroupID": "0", 
            "MetaCategory": "network", 
            "Distribution": "5", 
            "ID": "3233", 
            "Name": "url"
        }, 
        "ID": "743"
    }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<p>Object has been added to MISP event ID 743</p>
<p> </p>
<h3 id="h_d89bbb90-7744-427b-9bbb-484eb751f21c">17. Add an object to an event</h3>
<p> </p>
<hr>
<p> </p>
<p>Adds any other object to MISP.</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-add-object</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 138.8px;"><strong>Argument Name</strong></th>
<th style="width: 473.2px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138.8px;">event_id</td>
<td style="width: 473.2px;">ID of the event to add the object to.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138.8px;">template</td>
<td style="width: 473.2px;">Template name. For more information, see the <a href="https://www.misp-project.org/objects.html" target="_blank" rel="nofollow noopener">MISP documentation</a>.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138.8px;">attributes</td>
<td style="width: 473.2px;">attributes</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 333.8px;"><strong>Path</strong></th>
<th style="width: 61.2px;"><strong>Type</strong></th>
<th style="width: 345px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 333.8px;">MISP.Event.ID</td>
<td style="width: 61.2px;">number</td>
<td style="width: 345px;">MISP event ID.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.MetaCategory</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Object meta category.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Distribution</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">Distribution of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Name</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Name of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.TemplateVersion</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">Template version of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.EventID</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">ID of the event in which the object was first created.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.TemplateUUID</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">UUID of the template.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Timestamp</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Timestamp when the object was created.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Deleted</td>
<td style="width: 61.2px;">Boolean</td>
<td style="width: 345px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.ID</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">ID of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.UUID</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">UUID of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Value</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Value of the attribute.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.EventID</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">ID of the first event from which the object originated.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Timestamp</td>
<td style="width: 61.2px;">Date</td>
<td style="width: 345px;">Timestamp when the object was created.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Deleted</td>
<td style="width: 61.2px;">Boolean</td>
<td style="width: 345px;">Whether the object was deleted?</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.ObjectID</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">ID of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.DisableCorrelation</td>
<td style="width: 61.2px;">Boolean</td>
<td style="width: 345px;">Whether correlation is disabled.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.ID</td>
<td style="width: 61.2px;">Unknown</td>
<td style="width: 345px;">ID of the attribute.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.ObjectRelation</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Relation of the object.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Type</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Object type.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.UUID</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">UUID of the attribute.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.ToIDs</td>
<td style="width: 61.2px;">Boolean</td>
<td style="width: 345px;">Whether the to_ids flag is on.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Category</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Category of the attribute.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.SharingGroupID</td>
<td style="width: 61.2px;">Number</td>
<td style="width: 345px;">ID of the sharing group.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Attribute.Comment</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Comment of the attribute.</td>
</tr>
<tr>
<td style="width: 333.8px;">MISP.Event.Object.Description</td>
<td style="width: 61.2px;">String</td>
<td style="width: 345px;">Description of the object.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<p><code>!misp-add-object event_id="15" template="vehicle" attributes="{'description': 'Manager Ferrari', 'make': 'Ferrari', 'model': '308 GTS'}"</code><br> <code>!misp-add-object event_id=15 template="http-request" attributes="{'url': 'https://foaas.com/awesome/Mom', 'method': 'GET', 'basicauth-user': 'username', 'basicauth-password': 'password'}</code><br> <code>!misp-add-object event_id=15 template=device attributes="{'name': 'AndroidPhone', 'device-type': 'Mobile', 'OS': 'Android', 'version': '9 PKQ1'}"</code></p>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "MISP.Event": {
        "Object": {
            "Comment": "", 
            "EventID": "743", 
            "Timestamp": "1565013618", 
            "Description": "Vehicle object template to describe a vehicle information and registration", 
            "UUID": "00b4293d-2c4d-4c7d-83b6-e72b0a199402", 
            "Deleted": false, 
            "Attribute": [
                {
                    "Category": "Other", 
                    "Comment": "", 
                    "UUID": "dc7fa7d8-afb4-4740-8f97-ed10adce735f", 
                    "ObjectID": "3230", 
                    "Deleted": false, 
                    "Timestamp": "1565013618", 
                    "ToIDs": false, 
                    "Value": "Manager Ferrari", 
                    "ID": "26172", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "description", 
                    "EventID": "743", 
                    "value1": "Manager Ferrari", 
                    "DisableCorrelation": true, 
                    "Type": "text", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Other", 
                    "Comment": "", 
                    "UUID": "8eeabab2-627e-4b1f-b4bd-c11b624fdabe", 
                    "ObjectID": "3230", 
                    "Deleted": false, 
                    "Timestamp": "1565013618", 
                    "ToIDs": false, 
                    "Value": "Ferrari", 
                    "ID": "26173", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "make", 
                    "EventID": "743", 
                    "value1": "Ferrari", 
                    "DisableCorrelation": true, 
                    "Type": "text", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Other", 
                    "Comment": "", 
                    "UUID": "bfa5455c-22c2-45b1-9212-eefc59e4b430", 
                    "ObjectID": "3230", 
                    "Deleted": false, 
                    "Timestamp": "1565013618", 
                    "ToIDs": false, 
                    "Value": "308 GTS", 
                    "ID": "26174", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "model", 
                    "EventID": "743", 
                    "value1": "308 GTS", 
                    "DisableCorrelation": true, 
                    "Type": "text", 
                    "Distribution": "5", 
                    "value2": ""
                }
            ], 
            "TemplateUUID": "683c076c-f695-4ff2-8efa-e98a418049f4", 
            "TemplateVersion": "1", 
            "SharingGroupID": "0", 
            "MetaCategory": "misc", 
            "Distribution": "5", 
            "ID": "3230", 
            "Name": "vehicle"
        }, 
        "ID": "743"
    }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<p>Object has been added to MISP event ID 743</p>
<p> </p>
<h3 id="h_fde36c78-62d4-4e37-b895-dcef403a0e89">18. Add an IP object to an event</h3>
<p> </p>
<hr>
<p> </p>
<p>Adds an IP Object to the MISP event. The following arguments are optional, but at least one must be supplied for the
 command to run successfully: "ip", "dst_port", "src_port", "domain", "hostname", "ip_src", and "ip_dst".</p>
<p> </p>
<h5>Base Command</h5>
<p> </p>
<p><code>misp-add-ip-object</code></p>
<p> </p>
<h5>Input</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 220.6px;"><strong>Argument Name</strong></th>
<th style="width: 399.4px;"><strong>Description</strong></th>
<th style="width: 118px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 220.6px;">event_id</td>
<td style="width: 399.4px;">ID of an event.</td>
<td style="width: 118px;">Required</td>
</tr>
<tr>
<td style="width: 220.6px;">ip</td>
<td style="width: 399.4px;">IP address (require one of).</td>
<td style="width: 118px;">Optional</td>
</tr>
<tr>
<td style="width: 220.6px;">dst_port</td>
<td style="width: 399.4px;">Destination port number.</td>
<td style="width: 118px;">Optional</td>
</tr>
<tr>
<td style="width: 220.6px;">src_port</td>
<td style="width: 399.4px;">Source port number.</td>
<td style="width: 118px;">Optional</td>
</tr>
<tr>
<td style="width: 220.6px;">domain</td>
<td style="width: 399.4px;">Domain.</td>
<td style="width: 118px;">Optional</td>
</tr>
<tr>
<td style="width: 220.6px;">hostname</td>
<td style="width: 399.4px;">Hostname.</td>
<td style="width: 118px;">Optional</td>
</tr>
<tr>
<td style="width: 220.6px;">ip_src</td>
<td style="width: 399.4px;">IP source.</td>
<td style="width: 118px;">Optional</td>
</tr>
<tr>
<td style="width: 220.6px;">ip_dst</td>
<td style="width: 399.4px;">IP destination.</td>
<td style="width: 118px;">Optional</td>
</tr>
<tr>
<td style="width: 220.6px;">first_seen</td>
<td style="width: 399.4px;">Date when the tuple was first seen.</td>
<td style="width: 118px;">Optional</td>
</tr>
<tr>
<td style="width: 220.6px;">last_seen</td>
<td style="width: 399.4px;">Date when the tuple was last seen.</td>
<td style="width: 118px;">Optional</td>
</tr>
<tr>
<td style="width: 220.6px;">comment</td>
<td style="width: 399.4px;">A description of the object.</td>
<td style="width: 118px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 331.8px;"><strong>Path</strong></th>
<th style="width: 63.2px;"><strong>Type</strong></th>
<th style="width: 345px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 331.8px;">MISP.Event.ID</td>
<td style="width: 63.2px;">number</td>
<td style="width: 345px;">MISP event ID.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.MetaCategory</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">Object meta category.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Distribution</td>
<td style="width: 63.2px;">Number</td>
<td style="width: 345px;">Distribution of the object.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Name</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">Name of the object.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.TemplateVersion</td>
<td style="width: 63.2px;">Number</td>
<td style="width: 345px;">Template version of the object.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.EventID</td>
<td style="width: 63.2px;">Number</td>
<td style="width: 345px;">ID of the event in which the object was first created.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.TemplateUUID</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">UUID of the template.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Timestamp</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">Timestamp when the object was created.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Deleted</td>
<td style="width: 63.2px;">Boolean</td>
<td style="width: 345px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.ID</td>
<td style="width: 63.2px;">Number</td>
<td style="width: 345px;">ID of the object.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.UUID</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">UUID of the object.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.Value</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">Value of the attribute.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.EventID</td>
<td style="width: 63.2px;">Number</td>
<td style="width: 345px;">ID of the first event from which the object originated.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.Timestamp</td>
<td style="width: 63.2px;">Date</td>
<td style="width: 345px;">Timestamp when the object was created.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.Deleted</td>
<td style="width: 63.2px;">Boolean</td>
<td style="width: 345px;">Whether the object was deleted.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.ObjectID</td>
<td style="width: 63.2px;">Number</td>
<td style="width: 345px;">ID of the object.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.DisableCorrelation</td>
<td style="width: 63.2px;">Boolean</td>
<td style="width: 345px;">Whether correlation is disabled.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.ID</td>
<td style="width: 63.2px;">Unknown</td>
<td style="width: 345px;">ID of the attribute.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.ObjectRelation</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">Relation of the object.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.Type</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">Object type.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.UUID</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">UUID of the attribute.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.ToIDs</td>
<td style="width: 63.2px;">Boolean</td>
<td style="width: 345px;">Whether the to_ids flag is on.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.Category</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">Category of the attribute.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.SharingGroupID</td>
<td style="width: 63.2px;">Number</td>
<td style="width: 345px;">ID of the sharing group.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Attribute.Comment</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">Comment of the attribute.</td>
</tr>
<tr>
<td style="width: 331.8px;">MISP.Event.Object.Description</td>
<td style="width: 63.2px;">String</td>
<td style="width: 345px;">Description of the object.</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!misp-add-ip-object event_id="743" ip="8.8.8.8,4.4.4.4" dst_port="8080" domain="google.com" first_seen="2018-05-05" text="test dns"</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "MISP.Event": {
        "Object": {
            "Comment": "", 
            "EventID": "743", 
            "Timestamp": "1565013616", 
            "Description": "An IP address (or domain or hostname) and a port seen as a tuple (or as a triple) in a specific time frame.", 
            "UUID": "14990bd5-aae0-4ceb-be1a-4fee9f6a0af4", 
            "Deleted": false, 
            "Attribute": [
                {
                    "Category": "Network activity", 
                    "Comment": "", 
                    "UUID": "2136e8a8-33a3-4480-ba3a-54e165ef7a80", 
                    "ObjectID": "3229", 
                    "Deleted": false, 
                    "Timestamp": "1565013616", 
                    "ToIDs": false, 
                    "Value": "8080", 
                    "ID": "26167", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "dst-port", 
                    "EventID": "743", 
                    "value1": "8080", 
                    "DisableCorrelation": true, 
                    "Type": "port", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Network activity", 
                    "Comment": "", 
                    "UUID": "0d5952c5-218c-4a25-8a0c-f361ef37420a", 
                    "ObjectID": "3229", 
                    "Deleted": false, 
                    "Timestamp": "1565013616", 
                    "ToIDs": true, 
                    "Value": "google.com", 
                    "ID": "26168", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "domain", 
                    "EventID": "743", 
                    "value1": "google.com", 
                    "DisableCorrelation": false, 
                    "Type": "domain", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Network activity", 
                    "Comment": "", 
                    "UUID": "ebb067d7-4f5e-4536-a164-2df7eafc3060", 
                    "ObjectID": "3229", 
                    "Deleted": false, 
                    "Timestamp": "1565013616", 
                    "ToIDs": true, 
                    "Value": "8.8.8.8", 
                    "ID": "26169", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "ip", 
                    "EventID": "743", 
                    "value1": "8.8.8.8", 
                    "DisableCorrelation": false, 
                    "Type": "ip-dst", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Network activity", 
                    "Comment": "", 
                    "UUID": "99e0cfe2-8581-4ffd-ad39-b8bee6325203", 
                    "ObjectID": "3229", 
                    "Deleted": false, 
                    "Timestamp": "1565013616", 
                    "ToIDs": true, 
                    "Value": "4.4.4.4", 
                    "ID": "26170", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "ip", 
                    "EventID": "743", 
                    "value1": "4.4.4.4", 
                    "DisableCorrelation": false, 
                    "Type": "ip-dst", 
                    "Distribution": "5", 
                    "value2": ""
                }, 
                {
                    "Category": "Other", 
                    "Comment": "", 
                    "UUID": "a85528af-5b1e-4bb4-99bd-80fa46c4f5ae", 
                    "ObjectID": "3229", 
                    "Deleted": false, 
                    "Timestamp": "1565013616", 
                    "ToIDs": false, 
                    "Value": "2018-05-05", 
                    "ID": "26171", 
                    "SharingGroupID": "0", 
                    "ObjectRelation": "first-seen", 
                    "EventID": "743", 
                    "value1": "2018-05-05", 
                    "DisableCorrelation": true, 
                    "Type": "datetime", 
                    "Distribution": "5", 
                    "value2": ""
                }
            ], 
            "TemplateUUID": "9f8cea74-16fe-4968-a2b4-026676949ac6", 
            "TemplateVersion": "7", 
            "SharingGroupID": "0", 
            "MetaCategory": "network", 
            "Distribution": "5", 
            "ID": "3229", 
            "Name": "ip-port"
        }, 
        "ID": "743"
    }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p> </p>
<p>Object has been added to MISP event ID 743</p>
