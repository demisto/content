<!-- HTML_DOC -->
<p>Use the ThreatConnect integration to identify, manage, and block threats.</p>
<p>This integration was integrated and tested with ThreatConnect Python SDK v2.</p>
<h2>Configure ThreatConnect on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for ThreatConnect1.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Access ID</strong></li>
<li><strong>Secret Key</strong></li>
<li><strong>baseUrl</strong></li>
<li><strong>Default Organization</strong></li>
<li><strong>ProxyIP (or http://${ip} )</strong></li>
<li><strong>ProxyPort</strong></li>
<li><strong>Rating threshold for Malicious Indicators</strong></li>
<li><strong>Confidence threshold for Malicious Indicators</strong></li>
<li><strong>Indicator Reputation Freshness (in days)</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_dbc09d92-a6ff-4bd1-a989-ee279906188b" target="_self">Search for an IP indicator: ip</a></li>
<li><a href="#h_5f8f617c-5b41-4fc6-ba71-6bc198ce0240" target="_self">Search for a URL indicator: url</a></li>
<li><a href="#h_859a0134-0b4c-40bb-a8aa-1243a27b5fa4" target="_self">Search for a file indicator: file</a></li>
<li><a href="#h_3a6fb44d-fcba-47d2-a5ae-641e96a870af" target="_self">Retrieve possible owners from an account: tc-owners</a></li>
<li><a href="#h_3a6fb44d-fcba-47d2-a5ae-641e96a870af" target="_self">Retrieve all indicators: tc-indicators</a></li>
<li><a href="#h_12844d43-9ff8-46e4-8550-ec028fbce8d3" target="_self">Get all tags: tc-get-tags</a></li>
<li><a href="#h_0762aaab-f5de-45c2-939f-954166a60794" target="_self">Tag an existing indicator: tc-tag-indicator</a></li>
<li><a href="#h_342891d8-10d5-4baa-a495-9e86964eecb3" target="_self">Get an indicator: tc-get-indicator</a></li>
<li><a href="#h_e47ad233-a892-44ff-b25e-bbcdca5a6f63" target="_self">Get all indicators with a specific tag: tc-get-indicators-by-tag</a></li>
<li><a href="#h_649b49f2-29a7-4d31-b83b-b203bf9ad1cf" target="_self">Add a new indicator: tc-add-indicator</a></li>
<li><a href="#h_b0a86eb2-45a9-42a6-a5ce-a25d9a31d32d" target="_self">Create a new incident: tc-create-incident</a></li>
<li><a href="#h_4e0b7529-7cab-47fb-809a-ffaaa5800be5" target="_self">Fetch incidents: tc-fetch-incidents</a></li>
<li><a href="#h_eb3696f0-25b9-44a8-9cc5-fe565f9a2b2e" target="_self">Associate an indicator to an incident: tc-incident-associate-indicator</a></li>
<li><a href="#h_df630abe-38a7-4284-b1e1-0c6d429e3441" target="_self">Check domain reputation: domain</a></li>
<li><a href="#h_6af335c1-ae10-4995-a697-4171ef6b9c72" target="_self">Get incidents related to an indicator: tc-get-incident-associate-indicators</a></li>
<li><a href="#h_c9985831-99c5-4891-897f-f09b474bc6bd" target="_self">Update an indicator: tc-update-indicator</a></li>
<li><a href="#h_1a688e98-9b79-4ff6-9f7c-b1bccbf89bda" target="_self">Remove a tag from an indicator: tc-delete-indicator-tag</a></li>
<li><a href="#h_7c90955d-4d35-4735-81fc-5ea32675153f" target="_self">Delete an indicator: tc-delete-indicator</a></li>
<li><a href="#h_f9c279e5-4370-4569-afa9-003c206aecd1" target="_self">Create a group from a campaign: tc-create-campaign</a></li>
<li><a href="#h_8b47bb5b-0493-4b1b-95a4-d4d0470cf7d6" target="_self">Create a group from an event: tc-create-event</a></li>
<li><a href="#h_ccc84238-6dc6-41b5-857d-da1acba22018" target="_self">Create a group from threats: tc-create-threat</a></li>
<li><a href="#h_2df64364-579d-4818-87fd-6b6f390b7ef8" target="_self">Delete a group: tc-delete-group</a></li>
<li><a href="#h_6b003c50-591f-4eca-877a-2ac84cc7b168" target="_self">Add an attribute to an event: tc-add-group-attribute</a></li>
<li><a href="#h_169e4b19-afb5-4cb6-964a-91bd81b4d0d5" target="_self">Get a list of events: tc-get-events</a></li>
<li><a href="#h_71af8759-08b2-4944-8e9b-4f6e95496e45" target="_self">Get all groups: tc-get-groups</a></li>
<li><a href="#h_641be290-4112-41cd-a1dd-618c6edcf974" target="_self">Add a security label to a group: tc-add-group-security-label</a></li>
<li><a href="#h_2824aa8e-94c3-4491-9be9-989afc0c57d6" target="_self">Add tags to a group: tc-add-group-tag</a></li>
<li><a href="#h_07fd4c7b-a093-42a9-a8f0-54049edfd572" target="_self">Get all indicator types: tc-get-indicator-types</a></li>
<li><a href="#h_ee65b495-4e67-4a92-9218-76ce69e1c273" target="_self">Associate an indicator to a group: tc-group-associate-indicator</a></li>
<li><a href="#h_93b38c5f-321e-42e4-9297-998875571b68" target="_self">Create a document group: tc-create-document-group</a></li>
<li><a href="#h_a9460cff-1c67-4516-a849-3b79fca39d97" target="_self">Retrieve a single group: tc-get-group</a></li>
<li><a href="#h_194dd92c-4b86-4f93-b518-d4791dceda62" target="_self">Retrieves the attribute of a group: tc-get-group-attributes</a></li>
<li><a href="#h_1ea1f849-40aa-4ad5-ad6f-b5a719b0ea4a" target="_self">Retrieves the security labels of a group: tc-get-group-security-labels</a></li>
<li><a href="#h_3e053624-ac89-4759-ace2-67f90f75cf0a" target="_self">Retrieves the tags of a group: tc-get-group-tags</a></li>
<li><a href="#h_ea226a75-dcb3-4b7c-a2cc-6c4772492481" target="_self">Downloads the contents of a document: tc-download-document</a></li>
<li><a href="#h_fb44bbee-2172-4579-b056-805c45288080" target="_self">Returns indicators associated with a group: tc-get-group-indicators</a></li>
<li><a href="#h_035ca80f-4cb4-4adf-b50d-86f9f67c427b" target="_self">Returns indicators associated with a specified group: tc-get-associated-groups</a></li>
<li><a href="#h_20deac42-acae-425b-bdce-b611b0469a79" target="_self">Associates one group with another group: tc-associate-group-to-group</a></li>
</ol>
<h3 id="h_dbc09d92-a6ff-4bd1-a989-ee279906188b">1. Search for an IP address indicator</h3>
<hr>
<p>Searches for an indicator of type IP address.</p>
<h5>Base Command</h5>
<p><code>ip</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 157px;"><strong>Argument Name</strong></th>
<th style="width: 466.188px;"><strong>Description</strong></th>
<th style="width: 83.8124px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 157px;">ip</td>
<td style="width: 466.188px;">The IPv4 or IPv6 address.</td>
<td style="width: 83.8124px;">Required</td>
</tr>
<tr>
<td style="width: 157px;">owners</td>
<td style="width: 466.188px;">A CSV list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners.</td>
<td style="width: 83.8124px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">ratingThreshold</td>
<td style="width: 466.188px;">A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical".</td>
<td style="width: 83.8124px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">confidenceThreshold</td>
<td style="width: 466.188px;">A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed".</td>
<td style="width: 83.8124px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 185px;"><strong>Path</strong></th>
<th style="width: 75.816px;"><strong>Type</strong></th>
<th style="width: 446.184px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 185px;">TC.Indicator.Name</td>
<td style="width: 75.816px;">string</td>
<td style="width: 446.184px;">The name of the indicator.</td>
</tr>
<tr>
<td style="width: 185px;">TC.Indicator.Type</td>
<td style="width: 75.816px;">string</td>
<td style="width: 446.184px;">The type of the indicator.</td>
</tr>
<tr>
<td style="width: 185px;">TC.Indicator.ID</td>
<td style="width: 75.816px;">string</td>
<td style="width: 446.184px;">The ID of the indicator.</td>
</tr>
<tr>
<td style="width: 185px;">TC.Indicator.Description</td>
<td style="width: 75.816px;">string</td>
<td style="width: 446.184px;">The description of the indicator.</td>
</tr>
<tr>
<td style="width: 185px;">TC.Indicator.Owner</td>
<td style="width: 75.816px;">string</td>
<td style="width: 446.184px;">The owner of the indicator.</td>
</tr>
<tr>
<td style="width: 185px;">TC.Indicator.CreateDate</td>
<td style="width: 75.816px;">date</td>
<td style="width: 446.184px;">The date on which the indicator was created.</td>
</tr>
<tr>
<td style="width: 185px;">TC.Indicator.LastModified</td>
<td style="width: 75.816px;">date</td>
<td style="width: 446.184px;">The date on which the indicator was modified.</td>
</tr>
<tr>
<td style="width: 185px;">TC.Indicator.Rating</td>
<td style="width: 75.816px;">number</td>
<td style="width: 446.184px;">The threat rating of the indicator.</td>
</tr>
<tr>
<td style="width: 185px;">TC.Indicator.Confidence</td>
<td style="width: 75.816px;">number</td>
<td style="width: 446.184px;">The confidence rating of the indicator.</td>
</tr>
<tr>
<td style="width: 185px;">DBotScore.Indicator</td>
<td style="width: 75.816px;">string</td>
<td style="width: 446.184px;">The value assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 185px;">DBotScore.Type</td>
<td style="width: 75.816px;">string</td>
<td style="width: 446.184px;">The type assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 185px;">DBotScore.Score</td>
<td style="width: 75.816px;">number</td>
<td style="width: 446.184px;">The score assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 185px;">DBotScore.Vendor</td>
<td style="width: 75.816px;">string</td>
<td style="width: 446.184px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 185px;">IP.Address</td>
<td style="width: 75.816px;">string</td>
<td style="width: 446.184px;">The IP address of the indicator.</td>
</tr>
<tr>
<td style="width: 185px;">IP.Malicious.Vendor</td>
<td style="width: 75.816px;">string</td>
<td style="width: 446.184px;">For malicious IP addresses, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 185px;">IP.Malicious.Description</td>
<td style="width: 75.816px;">string</td>
<td style="width: 446.184px;">For malicious IP addresses, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ip ip=7.77.7.7</pre>
<h5>Context Example</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_50242697-cfc09b80-03d3-11e9-9615-35fc485fa84c_1_Search_for_an_IP_indicator.png" alt="50242697-cfc09b80-03d3-11e9-9615-35fc485fa84c_1_Search_for_an_IP_indicator.png"></p>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_50281763-2e7c2880-0459-11e9-88ea-ed6532e56bad_1_Human_Readable_Output.png" alt="50281763-2e7c2880-0459-11e9-88ea-ed6532e56bad_1_Human_Readable_Output.png"></p>
<h3 id="h_5f8f617c-5b41-4fc6-ba71-6bc198ce0240">2. Search for an indicator of type URL</h3>
<hr>
<p>Searches for an indicator of type URL.</p>
<h5>Base Command</h5>
<p><code>url</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 163.601px;"><strong>Argument Name</strong></th>
<th style="width: 473.399px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 163.601px;">url</td>
<td style="width: 473.399px;">The URL for which to search. For example, "www.demisto.com".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 163.601px;">owners</td>
<td style="width: 473.399px;">A CSV list of a client's organizations, sources, or communities to which a client’s API user has been granted permission. For example, "owner1", "owner2", or "owner3".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 163.601px;">ratingThreshold</td>
<td style="width: 473.399px;">A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 163.601px;">confidenceThreshold</td>
<td style="width: 473.399px;">A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 204px;"><strong>Path</strong></th>
<th style="width: 95.2708px;"><strong>Type</strong></th>
<th style="width: 408.729px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 204px;">TC.Indicator.Name</td>
<td style="width: 95.2708px;">string</td>
<td style="width: 408.729px;">The name of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.Type</td>
<td style="width: 95.2708px;">string</td>
<td style="width: 408.729px;">The type of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.ID</td>
<td style="width: 95.2708px;">string</td>
<td style="width: 408.729px;">The ID of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.Description</td>
<td style="width: 95.2708px;">string</td>
<td style="width: 408.729px;">The description of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.Owner</td>
<td style="width: 95.2708px;">string</td>
<td style="width: 408.729px;">The owner of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.CreateDate</td>
<td style="width: 95.2708px;">date</td>
<td style="width: 408.729px;">The date on which the indicator was created.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.LastModified</td>
<td style="width: 95.2708px;">date</td>
<td style="width: 408.729px;">The date on which the indicator was last modified.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.Rating</td>
<td style="width: 95.2708px;">number</td>
<td style="width: 408.729px;">The threat rating of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.Confidence</td>
<td style="width: 95.2708px;">number</td>
<td style="width: 408.729px;">The confidence rating of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">DBotScore.Indicator</td>
<td style="width: 95.2708px;">string</td>
<td style="width: 408.729px;">The value assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">DBotScore.Type</td>
<td style="width: 95.2708px;">string</td>
<td style="width: 408.729px;">The type assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">DBotScore.Score</td>
<td style="width: 95.2708px;">number</td>
<td style="width: 408.729px;">The score assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">DBotScore.Vendor</td>
<td style="width: 95.2708px;">string</td>
<td style="width: 408.729px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 204px;">URL.Data</td>
<td style="width: 95.2708px;">string</td>
<td style="width: 408.729px;">The data of the URL indicator.</td>
</tr>
<tr>
<td style="width: 204px;">URL.Malicious.Vendor</td>
<td style="width: 95.2708px;">string</td>
<td style="width: 408.729px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 204px;">URL.Malicious.Description</td>
<td style="width: 95.2708px;">string</td>
<td style="width: 408.729px;">For malicious URLs, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!url url=https://a.co.il</pre>
<h5>Context Example</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_50274409-df78c800-0445-11e9-9a30-6f3335a6a60a_2_Search_for_a_URL_indicator_Context_Example.png" alt="50274409-df78c800-0445-11e9-9a30-6f3335a6a60a_2_Search_for_a_URL_indicator_Context_Example.png"></p>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/43cf97390b184fce1f2f08ebc92c7848c7bcc04a/docs/images/Integrations/ThreatConnect_50281785-3d62db00-0459-11e9-8d1d-6e5841fa37e6.png"></p>
<h3 id="h_859a0134-0b4c-40bb-a8aa-1243a27b5fa4">3. Search for an indicator of type file</h3>
<hr>
<p>Searches for an indicator of type file.</p>
<h5>Base Command</h5>
<p><code>file</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 191.604px;"><strong>Argument Name</strong></th>
<th style="width: 445.396px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 191.604px;">file</td>
<td style="width: 445.396px;">The hash of the file. Can be "MD5", "SHA-1", or "SHA-256".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 191.604px;">owners</td>
<td style="width: 445.396px;">A CSV list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 191.604px;">ratingThreshold</td>
<td style="width: 445.396px;">A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 191.604px;">confidenceThreshold</td>
<td style="width: 445.396px;">A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 204px;"><strong>Path</strong></th>
<th style="width: 113.396px;"><strong>Type</strong></th>
<th style="width: 390.604px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 204px;">TC.Indicator.Name</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The name of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.Type</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The type of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.ID</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The ID of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.Description</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The description of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.Owner</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The owner of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.CreateDate</td>
<td style="width: 113.396px;">date</td>
<td style="width: 390.604px;">The date on which the indicator was created.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.LastModified</td>
<td style="width: 113.396px;">date</td>
<td style="width: 390.604px;">The last date on which the indicator was modified.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.Rating</td>
<td style="width: 113.396px;">number</td>
<td style="width: 390.604px;">The threat rating of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.Confidence</td>
<td style="width: 113.396px;">number</td>
<td style="width: 390.604px;">The confidence rating of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.File.MD5</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The MD5 hash of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.File.SHA1</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The SHA1 hash of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">TC.Indicator.File.SHA256</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The SHA256 hash of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">DBotScore.Indicator</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The value assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">DBotScore.Type</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The type assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">DBotScore.Score</td>
<td style="width: 113.396px;">number</td>
<td style="width: 390.604px;">The score assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">DBotScore.Vendor</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 204px;">File.MD5</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The MD5 hash of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">File.SHA1</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The SHA1 hash of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">File.SHA256</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">The SHA256 hash of the indicator.</td>
</tr>
<tr>
<td style="width: 204px;">File.Malicious.Vendor</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 204px;">File.Malicious.Description</td>
<td style="width: 113.396px;">string</td>
<td style="width: 390.604px;">For malicious files, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_50275319-bd804500-0447-11e9-927f-3e272f74bb60.png" alt="50275319-bd804500-0447-11e9-927f-3e272f74bb60.png"></p>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_50281206-64201200-0457-11e9-8b72-4db2d9aadb0a.png" alt="50281206-64201200-0457-11e9-8b72-4db2d9aadb0a.png"></p>
<h3 id="h_3a6fb44d-fcba-47d2-a5ae-641e96a870af">4. Retrieves all owners for the current account</h3>
<hr>
<p>Retrieves all owners for the current account.</p>
<h5>Base Command</h5>
<p><code>tc-owners</code></p>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 270.146px;"><strong>Path</strong></th>
<th style="width: 74.8542px;"><strong>Type</strong></th>
<th style="width: 363px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 270.146px;">TC.Owner.Name</td>
<td style="width: 74.8542px;">string</td>
<td style="width: 363px;">The name of the owner.</td>
</tr>
<tr>
<td style="width: 270.146px;">TC.Owner.ID</td>
<td style="width: 74.8542px;">string</td>
<td style="width: 363px;">The ID of the owner.</td>
</tr>
<tr>
<td style="width: 270.146px;">TC.Owner.Type</td>
<td style="width: 74.8542px;">string</td>
<td style="width: 363px;">The type of the owner.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<p> </p>
<h3>5. Retrieve a list of all indicators</h3>
<hr>
<p>Retrieves a list of all indicators.</p>
<h5>Base Command</h5>
<p><code>tc-indicators</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 197.587px;"><strong>Argument Name</strong></th>
<th style="width: 418.413px;"><strong>Description</strong></th>
<th style="width: 91px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 197.587px;">owner</td>
<td style="width: 418.413px;">A list of results filtered by the owner of the indicator.</td>
<td style="width: 91px;">Optional</td>
</tr>
<tr>
<td style="width: 197.587px;">limit</td>
<td style="width: 418.413px;">The maximum number of results that can be returned. The default is 500.</td>
<td style="width: 91px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 206px;"><strong>Path</strong></th>
<th style="width: 90.6841px;"><strong>Type</strong></th>
<th style="width: 411.316px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">TC.Indicator.Name</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The name of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Type</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The type of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.ID</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The ID of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Description</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The description of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Owner</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The owner of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.CreateDate</td>
<td style="width: 90.6841px;">date</td>
<td style="width: 411.316px;">The date on which the indicator was created.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.LastModified</td>
<td style="width: 90.6841px;">date</td>
<td style="width: 411.316px;">The last date on which the indicator was modified.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Rating</td>
<td style="width: 90.6841px;">number</td>
<td style="width: 411.316px;">The threat rating of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Confidence</td>
<td style="width: 90.6841px;">number</td>
<td style="width: 411.316px;">The confidence rating of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.WhoisActive</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The active indicator (for domains only).</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.MD5</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The MD5 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.SHA1</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The SHA1 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.SHA256</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The SHA256 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Indicator</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The value assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Type</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The type assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Score</td>
<td style="width: 90.6841px;">number</td>
<td style="width: 411.316px;">The score assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Vendor</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Address</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The IP address of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Malicious.Vendor</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">For malicious IP addresses, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Malicious.Description</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">For malicious IP addresses, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Data</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The data of the URL of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Malicious.Vendor</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Malicious.Description</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">For malicious URLs, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Name</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The name of the domain.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Vendor</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Description</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">For malicious domains, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">File.MD5</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.SHA1</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.SHA256</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.Malicious.Vendor</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">File.Malicious.Description</td>
<td style="width: 90.6841px;">string</td>
<td style="width: 411.316px;">For malicious files, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-indicators limit=5</pre>
<h5>Context Example</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_50281877-96327380-0459-11e9-8c94-a1136e0949a7.png" alt="50281877-96327380-0459-11e9-8c94-a1136e0949a7.png"></p>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_50281832-6edba680-0459-11e9-8ac2-e0f00b97db98.png" alt="50281832-6edba680-0459-11e9-8ac2-e0f00b97db98.png"></p>
<h3 id="h_12844d43-9ff8-46e4-8550-ec028fbce8d3">6. Return a list of all ThreatConnect tags</h3>
<hr>
<p>Returns a list of all ThreatConnect tags.</p>
<h5>Base Command</h5>
<p><code>tc-get-tags</code></p>
<h5>Input</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<tbody>
<tr>
<th style="width: 323.882px;"><strong>Argument Name</strong></th>
<th style="width: 79.118px;"><strong>Description</strong></th>
<th style="width: 302px;">Required</th>
</tr>
<tr>
<td style="width: 323.882px;">tag</td>
<td style="width: 79.118px;">The name of the tag</td>
<td style="width: 302px;">Required</td>
</tr>
<tr>
<td style="width: 323.882px;">indicator</td>
<td style="width: 79.118px;">
<div>
<div><span>The indicator to tag. For example, for an IP indicator, "8.8.8.8".</span></div>
</div>
</td>
<td style="width: 302px;">Required</td>
</tr>
<tr>
<td style="width: 323.882px;">owner</td>
<td style="width: 79.118px;">
<div>
<div>
<div>
<div><span>A list of indicators filtered by the owner.</span></div>
</div>
</div>
</div>
</td>
<td style="width: 302px;"> Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 214.955px;"><strong>Path</strong></th>
<th style="width: 191.045px;"><strong>Type</strong></th>
<th style="width: 302px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 214.955px;">TC.Tags</td>
<td style="width: 191.045px;">Unknown</td>
<td style="width: 302px;">A list of tags.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-get-tags</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_50281926-c37f2180-0459-11e9-83bb-8d6abeb79d48.png" alt="50281926-c37f2180-0459-11e9-83bb-8d6abeb79d48.png"></p>
<h3 id="h_0762aaab-f5de-45c2-939f-954166a60794">7. Add a tag to an existing indicator</h3>
<hr>
<p>Adds a tag to an existing indicator.</p>
<h5>Base Command</h5>
<p><code>tc-tag-indicator</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 188.375px;"><strong>Argument Name</strong></th>
<th style="width: 441.625px;"><strong>Description</strong></th>
<th style="width: 79px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 188.375px;">tag</td>
<td style="width: 441.625px;">The name of the tag.</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 188.375px;">indicator</td>
<td style="width: 441.625px;">The indicator to tag. For example, for an IP indicator, "8.8.8.8".</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 188.375px;">owner</td>
<td style="width: 441.625px;">A list of indicators filtered by the owner.</td>
<td style="width: 79px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-tag-indicator indicator=7.77.7.7 tag=NewTagName</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_50282035-18bb3300-045a-11e9-9a51-1bc93a3b7df0_7_Tag_an_existing_indicator_Human_Readable_Output.png" alt="50282035-18bb3300-045a-11e9-9a51-1bc93a3b7df0_7_Tag_an_existing_indicator_Human_Readable_Output.png"></p>
<h3 id="h_342891d8-10d5-4baa-a495-9e86964eecb3">8. Retrieves information about an indicator</h3>
<hr>
<p>Retrieves information about an indicator.</p>
<h5>Base Command</h5>
<p><code>tc-get-indicator</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 211.587px;"><strong>Argument Name</strong></th>
<th style="width: 425.413px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 211.587px;">indicator</td>
<td style="width: 425.413px;">The name of the indicator by which to search. The command retrieves information from all owners. Can be an IP address, a URL, or a file hash.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 211.587px;">ratingThreshold</td>
<td style="width: 425.413px;">A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211.587px;">confidenceThreshold</td>
<td style="width: 425.413px;">A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 206px;"><strong>Path</strong></th>
<th style="width: 90.7014px;"><strong>Type</strong></th>
<th style="width: 411.299px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">TC.Indicator.Name</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The name of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Type</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The type of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.ID</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The ID of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Description</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The description of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Owner</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The owner of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.CreateDate</td>
<td style="width: 90.7014px;">date</td>
<td style="width: 411.299px;">The date on which the indicator was created.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.LastModified</td>
<td style="width: 90.7014px;">date</td>
<td style="width: 411.299px;">The last date on which the indicator was modified.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Rating</td>
<td style="width: 90.7014px;">number</td>
<td style="width: 411.299px;">The threat rating of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Confidence</td>
<td style="width: 90.7014px;">number</td>
<td style="width: 411.299px;">The confidence rating of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.WhoisActive</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The active indicator (for domains only).</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.MD5</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The MD5 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.SHA1</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The SHA1 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.SHA256</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The SHA256 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Indicator</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The value assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Type</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The type assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Score</td>
<td style="width: 90.7014px;">number</td>
<td style="width: 411.299px;">The score assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Vendor</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Address</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The IP address of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Malicious.Vendor</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">For malicious IP addresses, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Malicious.Description</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">For malicious IP addresses, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Data</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The data of the indicator of the URL.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Malicious.Vendor</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Malicious.Description</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">For malicious URLs, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Name</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The domain name of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Vendor</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Description</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">For malicious domains, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">File.MD5</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.SHA1</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.SHA256</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.Malicious.Vendor</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">File.Malicious.Description</td>
<td style="width: 90.7014px;">string</td>
<td style="width: 411.299px;">For malicious files, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-get-indicator indicator=7.77.7.7</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/43cf97390b184fce1f2f08ebc92c7848c7bcc04a/docs/images/Integrations/ThreatConnect_50282140-78b1d980-045a-11e9-995b-a9fc2595b663_8_Get_an_indicator_Human_Readable_Output.png" alt="50282140-78b1d980-045a-11e9-995b-a9fc2595b663_8_Get_an_indicator_Human_Readable_Output.png"></p>
<h3 id="h_e47ad233-a892-44ff-b25e-bbcdca5a6f63">9. Fetch all indicators that have a tag</h3>
<hr>
<p>Fetches all indicators that have a tag.</p>
<h5>Base Command</h5>
<p><code>tc-get-indicators-by-tag</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 190px;"><strong>Argument Name</strong></th>
<th style="width: 419.594px;"><strong>Description</strong></th>
<th style="width: 99.4062px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 190px;">tag</td>
<td style="width: 419.594px;">The name of the tag by which to filter.</td>
<td style="width: 99.4062px;">Required</td>
</tr>
<tr>
<td style="width: 190px;">owner</td>
<td style="width: 419.594px;">A list of indicators filtered by the owner.</td>
<td style="width: 99.4062px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 206px;"><strong>Path</strong></th>
<th style="width: 88.6702px;"><strong>Type</strong></th>
<th style="width: 413.33px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">TC.Indicator.Name</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The name of the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Type</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The type of the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.ID</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The ID of the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Description</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The description of the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Owner</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The owner of the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.CreateDate</td>
<td style="width: 88.6702px;">date</td>
<td style="width: 413.33px;">The date on which the tagged indicator was created.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.LastModified</td>
<td style="width: 88.6702px;">date</td>
<td style="width: 413.33px;">The last date on which the tagged indicator was modified.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Rating</td>
<td style="width: 88.6702px;">number</td>
<td style="width: 413.33px;">The threat rating of the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Confidence</td>
<td style="width: 88.6702px;">number</td>
<td style="width: 413.33px;">The confidence rating of the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.WhoisActive</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The active indicator (for domains only).</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.MD5</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The MD5 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.SHA1</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The SHA1 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.SHA256</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The SHA256 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Indicator</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The value assigned by DBot for the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Type</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The type assigned by DBot for the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Score</td>
<td style="width: 88.6702px;">number</td>
<td style="width: 413.33px;">The score assigned by DBot for the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Vendor</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Address</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The IP address of the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Malicious.Vendor</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">For malicious IP addresses, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Malicious.Description</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">For malicious IP addresses, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Data</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The data of the URL of the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Malicious.Vendor</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Malicious.Description</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">For malicious URLs, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Name</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The domain name of the tagged indicator.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Vendor</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Description</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">For malicious domains, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">File.MD5</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.SHA1</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.SHA256</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.Malicious.Vendor</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">File.Malicious.Description</td>
<td style="width: 88.6702px;">string</td>
<td style="width: 413.33px;">For malicious files, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-get-indicators-by-tag tag=NewTagName</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_50281832-6edba680-0459-11e9-8ac2-e0f00b97db98_9_Get_all_indicators_with_a_specific_tag_Human_Readable.png" alt="50281832-6edba680-0459-11e9-8ac2-e0f00b97db98_9_Get_all_indicators_with_a_specific_tag_Human_Readable.png"></p>
<h3 id="h_649b49f2-29a7-4d31-b83b-b203bf9ad1cf">10. Add a new indicator to ThreatConnect</h3>
<hr>
<p>Adds a new indicator to ThreatConnect.</p>
<h5>Base Command</h5>
<p><code>tc-add-indicator</code></p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 240.288px;"><strong>Argument Name</strong></th>
<th style="width: 395.712px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 240.288px;">indicator</td>
<td style="width: 395.712px;">The indicator to add.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 240.288px;">rating</td>
<td style="width: 395.712px;">The threat rating of the indicator. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 240.288px;">confidence</td>
<td style="width: 395.712px;">The confidence rating of the indicator. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 240.288px;">owner</td>
<td style="width: 395.712px;">The owner of the new indicator. The default is the "defaultOrg" parameter.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 206px;"><strong>Path</strong></th>
<th style="width: 132.715px;"><strong>Type</strong></th>
<th style="width: 369.285px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">TC.Indicator.Name</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The name the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Type</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The type of indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.ID</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The ID of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Description</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The description of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Owner</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The owner of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.CreateDate</td>
<td style="width: 132.715px;">date</td>
<td style="width: 369.285px;">The date on which the added indicator was created.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.LastModified</td>
<td style="width: 132.715px;">date</td>
<td style="width: 369.285px;">The last date on which the added indicator was modified.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Rating</td>
<td style="width: 132.715px;">number</td>
<td style="width: 369.285px;">The threat rating of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Confidence</td>
<td style="width: 132.715px;">number</td>
<td style="width: 369.285px;">The confidence rating of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.WhoisActive</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The active indicator (for domains only).</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.MD5</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The MD5 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.SHA1</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The SHA1 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.SHA256</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The SHA256 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Address</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The IP address of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Malicious.Vendor</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">For malicious IP addresses, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Malicious.Description</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">For malicious IP addresses, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Data</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The data of the URL of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Malicious.Vendor</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Malicious.Description</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">For malicious URLs, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Name</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The name of the added indicator of the domain.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Vendor</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Description</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">For malicious domains, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">File.MD5</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.SHA1</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.SHA256</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.Malicious.Vendor</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">File.Malicious.Description</td>
<td style="width: 132.715px;">string</td>
<td style="width: 369.285px;">For malicious files, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-add-indicator indicator="9.9.4.4" rating="2" confidence="87"</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_50282140-78b1d980-045a-11e9-995b-a9fc2595b663.png" alt="50282140-78b1d980-045a-11e9-995b-a9fc2595b663.png"></p>
<h3 id="h_b0a86eb2-45a9-42a6-a5ce-a25d9a31d32d">11. Create a new incident group</h3>
<hr>
<p>Creates a new incident group.</p>
<h5>Base Command</h5>
<p><code>tc-create-incident</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 151.917px;"><strong>Argument Name</strong></th>
<th style="width: 485.083px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151.917px;">owner</td>
<td style="width: 485.083px;">The owner of the new incident. The default is the "defaultOrg" parameter.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151.917px;">incidentName</td>
<td style="width: 485.083px;">The name of the incident group.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 151.917px;">eventDate</td>
<td style="width: 485.083px;">The creation time of an incident in the "2017-03-21T00:00:00Z" format.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151.917px;">tag</td>
<td style="width: 485.083px;">The tag applied to the incident.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151.917px;">securityLabel</td>
<td style="width: 485.083px;">The security label applied to the incident. Can be "TLP:RED", "TLP:GREEN", "TLP:AMBER", or "TLP:WHITE".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151.917px;">description</td>
<td style="width: 485.083px;">The description of the incident.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 182px;"><strong>Path</strong></th>
<th style="width: 102.375px;"><strong>Type</strong></th>
<th style="width: 423.625px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 182px;">TC.Incident.Name</td>
<td style="width: 102.375px;">string</td>
<td style="width: 423.625px;">The name of the new incident group.</td>
</tr>
<tr>
<td style="width: 182px;">TC.Incident.Owner</td>
<td style="width: 102.375px;">string</td>
<td style="width: 423.625px;">The owner of the new incident.</td>
</tr>
<tr>
<td style="width: 182px;">TC.Incident.EventDate</td>
<td style="width: 102.375px;">date</td>
<td style="width: 423.625px;">The date on which the event that indicates an incident occurred.</td>
</tr>
<tr>
<td style="width: 182px;">TC.Incident.Tag</td>
<td style="width: 102.375px;">string</td>
<td style="width: 423.625px;">The name of the tag of the new incident.</td>
</tr>
<tr>
<td style="width: 182px;">TC.Incident.SecurityLabel</td>
<td style="width: 102.375px;">string</td>
<td style="width: 423.625px;">The security label of the new incident.</td>
</tr>
<tr>
<td style="width: 182px;">TC.Incident.ID</td>
<td style="width: 102.375px;">Unknown</td>
<td style="width: 423.625px;">The ID of the new incident.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-create-incident incidentName="NewIncident" description="NewIncident" severity="Critical" category="Intrusion" company=Demisto tag=demisto</pre>
<p> </p>
<h3 id="h_4e0b7529-7cab-47fb-809a-ffaaa5800be5">12. Fetch incidents from ThreatConnect</h3>
<hr>
<p>Fetches incidents from ThreatConnect.</p>
<h5>Base Command</h5>
<p><code>tc-fetch-incidents</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 200.354px;"><strong>Argument Name</strong></th>
<th style="width: 411.646px;"><strong>Description</strong></th>
<th style="width: 96px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 200.354px;">incidentId</td>
<td style="width: 411.646px;">The fetched incidents filtered by ID.</td>
<td style="width: 96px;">Optional</td>
</tr>
<tr>
<td style="width: 200.354px;">owner</td>
<td style="width: 411.646px;">The fetched incidents filtered by owner.</td>
<td style="width: 96px;">Optional</td>
</tr>
<tr>
<td style="width: 200.354px;">incidentName</td>
<td style="width: 411.646px;">The fetched incidents filtered by incident name.</td>
<td style="width: 96px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 193px;"><strong>Path</strong></th>
<th style="width: 110.264px;"><strong>Type</strong></th>
<th style="width: 404.736px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 193px;">TC.Incident</td>
<td style="width: 110.264px;">string</td>
<td style="width: 404.736px;">The name of the group of fetched incidents.</td>
</tr>
<tr>
<td style="width: 193px;">TC.Incident.ID</td>
<td style="width: 110.264px;">string</td>
<td style="width: 404.736px;">The ID of the fetched incidents.</td>
</tr>
<tr>
<td style="width: 193px;">TC.Incident.Owner</td>
<td style="width: 110.264px;">string</td>
<td style="width: 404.736px;">The owner of the fetched incidents.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-fetch-incidents incidentId=64862</pre>
<p><!-- remove the following comments to manually add an image: --></p>
<p> </p>
<h3 id="h_eb3696f0-25b9-44a8-9cc5-fe565f9a2b2e">13. Associate an indicator with an existing incident</h3>
<hr>
<p>Associates an indicator with an existing incident. The indicator must exist before running this command. To add an indicator, run the tc-add-indicator command.</p>
<h5>Base Command</h5>
<p><code>tc-incident-associate-indicator</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 184.625px;"><strong>Argument Name</strong></th>
<th style="width: 452.375px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 184.625px;">indicatorType</td>
<td style="width: 452.375px;">The type of the indicator. Can be "ADDRESSES", "EMAIL_ADDRESSES", "URLS", "HOSTS", "FILES", or "CUSTOM_INDICATORS".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 184.625px;">incidentId</td>
<td style="width: 452.375px;">The ID of the incident to which the indicator is associated.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 184.625px;">indicator</td>
<td style="width: 452.375px;">The name of the indicator.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 184.625px;">owner</td>
<td style="width: 452.375px;">A list of indicators filtered by the owner.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 206px;"><strong>Path</strong></th>
<th style="width: 101.708px;"><strong>Type</strong></th>
<th style="width: 400.292px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">TC.Indicator.Name</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The name of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Type</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The type of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.ID</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The ID of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Description</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The description of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Owner</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The owner of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.CreateDate</td>
<td style="width: 101.708px;">date</td>
<td style="width: 400.292px;">The date on which the indicator associated was created.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.LastModified</td>
<td style="width: 101.708px;">date</td>
<td style="width: 400.292px;">The last date on which the indicator associated was modified.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Rating</td>
<td style="width: 101.708px;">number</td>
<td style="width: 400.292px;">The threat rating of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Confidence</td>
<td style="width: 101.708px;">number</td>
<td style="width: 400.292px;">The confidence rating of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.WhoisActive</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The active indicator (for domains only).</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.MD5</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The MD5 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.SHA1</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The SHA1 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.File.SHA256</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The SHA256 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Address</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">IP address of the associated indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Malicious.Vendor</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">For malicious IP addresses, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">IP.Malicious.Description</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">For malicious IP addresses, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Data</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The data of the URL of the associated indicator of the file.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Malicious.Vendor</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">URL.Malicious.Description</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">For malicious URLs, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Name</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The name of the indicator of the domain.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Vendor</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Description</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">For malicious domains, the full description.</td>
</tr>
<tr>
<td style="width: 206px;">File.MD5</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.SHA1</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.SHA256</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 206px;">File.Malicious.Vendor</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">File.Malicious.Description</td>
<td style="width: 101.708px;">string</td>
<td style="width: 400.292px;">For malicious files, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-incident-associate-indicator indicator=46.148.22.18 incidentId=64862 indicatorType=ADDRESSES</pre>
<h5>Human Readable Output</h5>
<h3 id="h_df630abe-38a7-4284-b1e1-0c6d429e3441">14. Search for an indicator of type domain</h3>
<hr>
<p>Searches for an indicator of type domain.</p>
<h5>Base Command</h5>
<p><code>domain</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 207.611px;"><strong>Argument Name</strong></th>
<th style="width: 429.389px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 207.611px;">domain</td>
<td style="width: 429.389px;">The name of the domain.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 207.611px;">owners</td>
<td style="width: 429.389px;">A CSV list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 207.611px;">ratingThreshold</td>
<td style="width: 429.389px;">A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 207.611px;">confidenceThreshold</td>
<td style="width: 429.389px;">A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 206px;"><strong>Path</strong></th>
<th style="width: 99.7466px;"><strong>Type</strong></th>
<th style="width: 402.253px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">TC.Indicator.Name</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">The name of the of the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Type</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">The type of the domain.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.ID</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">The ID of the domain.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Description</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">The description of the domain.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Owner</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">The owner of the domain.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.CreateDate</td>
<td style="width: 99.7466px;">date</td>
<td style="width: 402.253px;">The date on which the indicator of the domain was created.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.LastModified</td>
<td style="width: 99.7466px;">date</td>
<td style="width: 402.253px;">The last date on which the indicator of the domain was modified.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Rating</td>
<td style="width: 99.7466px;">number</td>
<td style="width: 402.253px;">The threat rating of the domain.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.Confidence</td>
<td style="width: 99.7466px;">number</td>
<td style="width: 402.253px;">The confidence rating of the domain.</td>
</tr>
<tr>
<td style="width: 206px;">TC.Indicator.WhoisActive</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">The active indicator (for domains only).</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Indicator</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">The value assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Type</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">The type assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Score</td>
<td style="width: 99.7466px;">number</td>
<td style="width: 402.253px;">The score assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 206px;">DBotScore.Vendor</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Name</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">The name of the domain.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Vendor</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 206px;">Domain.Malicious.Description</td>
<td style="width: 99.7466px;">string</td>
<td style="width: 402.253px;">For malicious domains, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!domain domain=com-mapsfinder.info</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/ThreatConnect_45597328-339d8780-b9d3-11e8-8f72-94a09c8c75ee.png" alt="45597328-339d8780-b9d3-11e8-8f72-94a09c8c75ee.png"></p>
<h3 id="h_6af335c1-ae10-4995-a697-4171ef6b9c72">15. Return indicators related to a specific incident</h3>
<hr>
<p>Returns indicators that are related to a specific incident.</p>
<h5>Base Command</h5>
<p><code>tc-get-incident-associate-indicators</code></p>
<p>ermission 2</p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 229.26px;"><strong>Argument Name</strong></th>
<th style="width: 370.74px;"><strong>Description</strong></th>
<th style="width: 109px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 229.26px;">incidentId</td>
<td style="width: 370.74px;">The ID of the incident.</td>
<td style="width: 109px;">Required</td>
</tr>
<tr>
<td style="width: 229.26px;">owner</td>
<td style="width: 370.74px;">A list of indicators filtered by the owner.</td>
<td style="width: 109px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 237.958px;"><strong>Path</strong></th>
<th style="width: 22.0417px;"><strong>Type</strong></th>
<th style="width: 448px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 237.958px;">TC.Indicator.Name</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The name of the returned indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.Type</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The type of the returned indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.ID</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The ID of the returned indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.Description</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The description of the returned indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.Owner</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The owner of the returned indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.CreateDate</td>
<td style="width: 22.0417px;">date</td>
<td style="width: 448px;">The date on which the returned indicator was created.</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.LastModified</td>
<td style="width: 22.0417px;">date</td>
<td style="width: 448px;">The last date on which the returned indicator was modified.</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.Rating</td>
<td style="width: 22.0417px;">number</td>
<td style="width: 448px;">The threat rating of the returned indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.Confidence</td>
<td style="width: 22.0417px;">number</td>
<td style="width: 448px;">The confidence rating of the returned indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.WhoisActive</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The active indicator (for domains only).</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.File.MD5</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The MD5 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.File.SHA1</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The SHA1 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 237.958px;">TC.Indicator.File.SHA256</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The SHA256 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 237.958px;">DBotScore.Indicator</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The value assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">DBotScore.Type</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The type assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">DBotScore.Score</td>
<td style="width: 22.0417px;">number</td>
<td style="width: 448px;">The score assigned by DBot for the indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">DBotScore.Vendor</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 237.958px;">IP.Address</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The IP address of the returned indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">IP.Malicious.Vendor</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">For malicious IP addresses, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 237.958px;">IP.Malicious.Description</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">For malicious IP addresses, the full description.</td>
</tr>
<tr>
<td style="width: 237.958px;">URL.Data</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The data of the URL of the returned indicator.</td>
</tr>
<tr>
<td style="width: 237.958px;">URL.Malicious.Vendor</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 237.958px;">URL.Malicious.Description</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">For malicious URLs, the full description.</td>
</tr>
<tr>
<td style="width: 237.958px;">Domain.Name</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The name of the domain.</td>
</tr>
<tr>
<td style="width: 237.958px;">Domain.Malicious.Vendor</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 237.958px;">Domain.Malicious.Description</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">For malicious domains, the full description.</td>
</tr>
<tr>
<td style="width: 237.958px;">File.MD5</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 237.958px;">File.SHA1</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 237.958px;">File.SHA256</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 237.958px;">File.Malicious.Vendor</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 237.958px;">File.Malicious.Description</td>
<td style="width: 22.0417px;">string</td>
<td style="width: 448px;">For malicious files, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-get-incident-associate-indicators incidentId=64862</pre>
<h3 id="h_c9985831-99c5-4891-897f-f09b474bc6bd">16. Update the indicator in ThreatConnect</h3>
<hr>
<p>Updates the indicator in ThreatConnect.</p>
<h5>Base Command</h5>
<p><code>tc-update-indicator</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 211.049px;"><strong>Argument Name</strong></th>
<th style="width: 426.951px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 211.049px;">indicator</td>
<td style="width: 426.951px;">The name of the updated indicator.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 211.049px;">rating</td>
<td style="width: 426.951px;">The threat rating of the updated indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211.049px;">confidence</td>
<td style="width: 426.951px;">The confidence rating of the updated indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211.049px;">size</td>
<td style="width: 426.951px;">The size of the file of the updated indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211.049px;">dnsActive</td>
<td style="width: 426.951px;">The active DNS indicator (only for hosts).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211.049px;">whoisActive</td>
<td style="width: 426.951px;">The active indicator (only for hosts).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211.049px;">updatedValues</td>
<td style="width: 426.951px;">A CSV list of field:value pairs to update. For example, "rating=3", "confidence=42", and "description=helloWorld".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211.049px;">falsePositive</td>
<td style="width: 426.951px;">The updated indicator set as a false positive. Can be "True" or "False".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211.049px;">observations</td>
<td style="width: 426.951px;">The number observations on the updated indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211.049px;">securityLabel</td>
<td style="width: 426.951px;">The security label applied to the incident. Can be "TLP:RED", "TLP:GREEN", "TLP:AMBER", or "TLP:WHITE".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211.049px;">threatAssessConfidence</td>
<td style="width: 426.951px;">Assesses the confidence rating of the indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 211.049px;">threatAssessRating</td>
<td style="width: 426.951px;">Assesses the threat rating of the indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 256.951px;"><strong>Path</strong></th>
<th style="width: 10px;"><strong>Type</strong></th>
<th style="width: 448px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 256.951px;">TC.Indicator.Name</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The name of the indicator.</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.Type</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The type of the indicator.</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.ID</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The ID of the indicator.</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.Description</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The description of the indicator.</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.Owner</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The owner of the indicator.</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.CreateDate</td>
<td style="width: 10px;">date</td>
<td style="width: 448px;">The date on which the indicator was created.</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.LastModified</td>
<td style="width: 10px;">date</td>
<td style="width: 448px;">The last date on which the indicator was modified.</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.Rating</td>
<td style="width: 10px;">number</td>
<td style="width: 448px;">The threat rating of the indicator.</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.Confidence</td>
<td style="width: 10px;">number</td>
<td style="width: 448px;">The confidence rating of the indicator.</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.WhoisActive</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The active indicator (for domains only).</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.File.MD5</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The MD5 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.File.SHA1</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The SHA1 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 256.951px;">TC.Indicator.File.SHA256</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The SHA256 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 256.951px;">IP.Address</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The IP address of the indicator.</td>
</tr>
<tr>
<td style="width: 256.951px;">IP.Malicious.Vendor</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">For malicious IP addresses, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 256.951px;">IP.Malicious.Description</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">For malicious IP addresses, the full description.</td>
</tr>
<tr>
<td style="width: 256.951px;">URL.Data</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The data of the URL of the indicator.</td>
</tr>
<tr>
<td style="width: 256.951px;">URL.Malicious.Vendor</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 256.951px;">URL.Malicious.Description</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">For malicious URLs, the full description.</td>
</tr>
<tr>
<td style="width: 256.951px;">Domain.Name</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The domain name of the indicator.</td>
</tr>
<tr>
<td style="width: 256.951px;">Domain.Malicious.Vendor</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 256.951px;">Domain.Malicious.Description</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">For malicious domains, the full description.</td>
</tr>
<tr>
<td style="width: 256.951px;">File.MD5</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 256.951px;">File.SHA1</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 256.951px;">File.SHA256</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 256.951px;">File.Malicious.Vendor</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 256.951px;">File.Malicious.Description</td>
<td style="width: 10px;">string</td>
<td style="width: 448px;">For malicious files, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_1a688e98-9b79-4ff6-9f7c-b1bccbf89bda">17. Remove a tag from a specified indicator</h3>
<hr>
<p>Removes a tag from a specified indicator.</p>
<h5>Base Command</h5>
<p><code>tc-delete-indicator-tag</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 201.813px;"><strong>Argument Name</strong></th>
<th style="width: 418.188px;"><strong>Description</strong></th>
<th style="width: 88px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 201.813px;">indicator</td>
<td style="width: 418.188px;">The name of the indicator from which to remove a tag.</td>
<td style="width: 88px;">Required</td>
</tr>
<tr>
<td style="width: 201.813px;">tag</td>
<td style="width: 418.188px;">The name of the tag to remove from the indicator.</td>
<td style="width: 88px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 241.934px;"><strong>Path</strong></th>
<th style="width: 18.0659px;"><strong>Type</strong></th>
<th style="width: 448px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 241.934px;">TC.Indicator.Name</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The name of the indicator.</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.Type</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The type of the indicator.</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.ID</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The ID of the indicator.</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.Description</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The description of the indicator.</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.Owner</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The owner of the indicator.</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.CreateDate</td>
<td style="width: 18.0659px;">date</td>
<td style="width: 448px;">The date on which the indicator was created.</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.LastModified</td>
<td style="width: 18.0659px;">date</td>
<td style="width: 448px;">The last date on which the indicator was modified.</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.Rating</td>
<td style="width: 18.0659px;">number</td>
<td style="width: 448px;">The threat rating of the indicator.</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.Confidence</td>
<td style="width: 18.0659px;">number</td>
<td style="width: 448px;">The confidence rating of the indicator.</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.WhoisActive</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The active indicator (for domains only).</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.File.MD5</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The MD5 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.File.SHA1</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The SHA1 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 241.934px;">TC.Indicator.File.SHA256</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The SHA256 hash of the indicator of the file.</td>
</tr>
<tr>
<td style="width: 241.934px;">IP.Address</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The IP address of the indicator.</td>
</tr>
<tr>
<td style="width: 241.934px;">IP.Malicious.Vendor</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">For malicious IP addresses, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 241.934px;">IP.Malicious.Description</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">For malicious IP addresses, the full description.</td>
</tr>
<tr>
<td style="width: 241.934px;">URL.Data</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The data of the URL of the indicator.</td>
</tr>
<tr>
<td style="width: 241.934px;">URL.Malicious.Vendor</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 241.934px;">URL.Malicious.Description</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">For malicious URLs, the full description.</td>
</tr>
<tr>
<td style="width: 241.934px;">Domain.Name</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The domain name of the indicator.</td>
</tr>
<tr>
<td style="width: 241.934px;">Domain.Malicious.Vendor</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 241.934px;">Domain.Malicious.Description</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">For malicious domains, the full description.</td>
</tr>
<tr>
<td style="width: 241.934px;">File.MD5</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 241.934px;">File.SHA1</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 241.934px;">File.SHA256</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 241.934px;">File.Malicious.Vendor</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 241.934px;">File.Malicious.Description</td>
<td style="width: 18.0659px;">string</td>
<td style="width: 448px;">For malicious files, the full description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_7c90955d-4d35-4735-81fc-5ea32675153f">18. Delete an indicator from ThreatConnect</h3>
<hr>
<p>Deletes an indicator from ThreatConnect.</p>
<h5>Base Command</h5>
<p><code>tc-delete-indicator</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 255.372px;"><strong>Argument Name</strong></th>
<th style="width: 337.628px;"><strong>Description</strong></th>
<th style="width: 115px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 255.372px;">indicator</td>
<td style="width: 337.628px;">The name of the indicator to delete.</td>
<td style="width: 115px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<h3 id="h_f9c279e5-4370-4569-afa9-003c206aecd1">19. Create a group based on the Campaign type</h3>
<hr>
<p>Creates a group based on the "Campaign" type.</p>
<h5>Base Command</h5>
<p><code>tc-create-campaign</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 192.969px;"><strong>Argument Name</strong></th>
<th style="width: 443.031px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 192.969px;">name</td>
<td style="width: 443.031px;">The name of the campaign group.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 192.969px;">firstSeen</td>
<td style="width: 443.031px;">The earliest date on which the campaign was seen.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 192.969px;">owner</td>
<td style="width: 443.031px;">The owner of the new incident. The default is the "defaultOrg" parameter.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 192.969px;">description</td>
<td style="width: 443.031px;">The description of the campaign.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 192.969px;">tag</td>
<td style="width: 443.031px;">The name of the tag to apply to the campaign.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 192.969px;">securityLabel</td>
<td style="width: 443.031px;">The security label of the campaign. For example, "TLP:Green".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 239px;"><strong>Path</strong></th>
<th style="width: 76.375px;"><strong>Type</strong></th>
<th style="width: 392.625px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 239px;">TC.Campaign.Name</td>
<td style="width: 76.375px;">string</td>
<td style="width: 392.625px;">The name of the campaign.</td>
</tr>
<tr>
<td style="width: 239px;">TC.Campaign.Owner</td>
<td style="width: 76.375px;">string</td>
<td style="width: 392.625px;">The owner of the campaign.</td>
</tr>
<tr>
<td style="width: 239px;">TC.Campaign.FirstSeen</td>
<td style="width: 76.375px;">date</td>
<td style="width: 392.625px;">The earliest date on which the campaign was seen.</td>
</tr>
<tr>
<td style="width: 239px;">TC.Campaign.Tag</td>
<td style="width: 76.375px;">string</td>
<td style="width: 392.625px;">The tag of the campaign.</td>
</tr>
<tr>
<td style="width: 239px;">TC.Campaign.SecurityLevel</td>
<td style="width: 76.375px;">string</td>
<td style="width: 392.625px;">The security label of the campaign.</td>
</tr>
<tr>
<td style="width: 239px;">TC.Campaign.ID</td>
<td style="width: 76.375px;">string</td>
<td style="width: 392.625px;">The ID of the campaign.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5> </h5>
<h3 id="h_8b47bb5b-0493-4b1b-95a4-d4d0470cf7d6">20. Create a group based on the Event type</h3>
<hr>
<p>Creates a group based on the "Event" type.</p>
<h5>Base Command</h5>
<p><code>tc-create-event</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 162.819px;"><strong>Argument Name</strong></th>
<th style="width: 473.181px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162.819px;">name</td>
<td style="width: 473.181px;">The name of the event group.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 162.819px;">eventDate</td>
<td style="width: 473.181px;">The date on which the event occurred. If the date is not specified, the current date is used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 162.819px;">status</td>
<td style="width: 473.181px;">The status of the event. Can be "Needs Review", "False Positive", "No Further Action", or "Escalated".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 162.819px;">owner</td>
<td style="width: 473.181px;">The owner of the event.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 162.819px;">description</td>
<td style="width: 473.181px;">The description of the event.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 162.819px;">tag</td>
<td style="width: 473.181px;">The tag of the event.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 241.684px;"><strong>Path</strong></th>
<th style="width: 102.316px;"><strong>Type</strong></th>
<th style="width: 363px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 241.684px;">TC.Event.Name</td>
<td style="width: 102.316px;">string</td>
<td style="width: 363px;">The name of the event.</td>
</tr>
<tr>
<td style="width: 241.684px;">TC.Event.Date</td>
<td style="width: 102.316px;">date</td>
<td style="width: 363px;">The date of the event.</td>
</tr>
<tr>
<td style="width: 241.684px;">TC.Event.Status</td>
<td style="width: 102.316px;">string</td>
<td style="width: 363px;">The status of the event.</td>
</tr>
<tr>
<td style="width: 241.684px;">TC.Event.Owner</td>
<td style="width: 102.316px;">string</td>
<td style="width: 363px;">The owner of the event.</td>
</tr>
<tr>
<td style="width: 241.684px;">TC.Event.Tag</td>
<td style="width: 102.316px;">string</td>
<td style="width: 363px;">The tag of the event.</td>
</tr>
<tr>
<td style="width: 241.684px;">TC.Event.ID</td>
<td style="width: 102.316px;">string</td>
<td style="width: 363px;">The ID of the event.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5> </h5>
<h3 id="h_ccc84238-6dc6-41b5-857d-da1acba22018">21. Create a group based on the Threats type</h3>
<hr>
<p>Creates a group based on the "Threats" type.</p>
<h5>Base Command</h5>
<p><code>tc-create-threat</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 268.594px;"><strong>Argument Name</strong></th>
<th style="width: 312.406px;"><strong>Description</strong></th>
<th style="width: 126px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 268.594px;">name</td>
<td style="width: 312.406px;">The name of the threat group.</td>
<td style="width: 126px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 241.389px;"><strong>Path</strong></th>
<th style="width: 103.611px;"><strong>Type</strong></th>
<th style="width: 362px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 241.389px;">TC.Threat.Name</td>
<td style="width: 103.611px;">string</td>
<td style="width: 362px;">The name of the threat.</td>
</tr>
<tr>
<td style="width: 241.389px;">TC.Threat.ID</td>
<td style="width: 103.611px;">string</td>
<td style="width: 362px;">The ID of the threat.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5> </h5>
<h3 id="h_2df64364-579d-4818-87fd-6b6f390b7ef8">22. Delete a group</h3>
<hr>
<p>Deletes a group.</p>
<h5>Base Command</h5>
<p><code>tc-delete-group</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 177.281px;"><strong>Argument Name</strong></th>
<th style="width: 458.719px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 177.281px;">groupID</td>
<td style="width: 458.719px;">The ID of the group to delete.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 177.281px;">type</td>
<td style="width: 458.719px;">The type of the group to delete. Can be "Incidents", "Events", "Campaigns", or "Threats".</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_6b003c50-591f-4eca-877a-2ac84cc7b168">23. Add an attribute to a specified group</h3>
<hr>
<p>Adds an attribute to a specified group.</p>
<h5>Base Command</h5>
<p><code>tc-add-group-attribute</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 163.17px;"><strong>Argument Name</strong></th>
<th style="width: 473.83px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 163.17px;">group_id</td>
<td style="width: 473.83px;">The ID of the group to which to add attributes. To get the ID of the group, run the tc-get-groups command.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 163.17px;">attribute_type</td>
<td style="width: 473.83px;">The type of attribute to add to the group. The type is located in the UI in a specific group or under Org Config.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 163.17px;">attribute_value</td>
<td style="width: 473.83px;">The value of the attribute.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 163.17px;">group_type</td>
<td style="width: 473.83px;">The type of the group. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 211px;"><strong>Path</strong></th>
<th style="width: 69.0556px;"><strong>Type</strong></th>
<th style="width: 426.944px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 211px;">TC.Group.DateAdded</td>
<td style="width: 69.0556px;">Date</td>
<td style="width: 426.944px;">The date on which the attribute was added.</td>
</tr>
<tr>
<td style="width: 211px;">TC.Group.LastModified</td>
<td style="width: 69.0556px;">Date</td>
<td style="width: 426.944px;">The date on which the added attribute was last modified.</td>
</tr>
<tr>
<td style="width: 211px;">TC.Group.Type</td>
<td style="width: 69.0556px;">String</td>
<td style="width: 426.944px;">The type of the group to which the attribute was added.</td>
</tr>
<tr>
<td style="width: 211px;">TC.Group.Value</td>
<td style="width: 69.0556px;">String</td>
<td style="width: 426.944px;">The value of the attribute added to the group.</td>
</tr>
<tr>
<td style="width: 211px;">TC.Group.ID</td>
<td style="width: 69.0556px;">Number</td>
<td style="width: 426.944px;">The group ID to which the attribute was added.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-add-group-attribute attribute_type="EXTERNAL ID" attribute_value=123456789 group_id=4406377 group_type=events</pre>
<h3 id="h_169e4b19-afb5-4cb6-964a-91bd81b4d0d5">24. Return a list of events</h3>
<hr>
<p>Returns a list of events.</p>
<h5>Base Command</h5>
<p><code>tc-get-events</code></p>
<h5><span style="font-size: 15px;"> </span></h5>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 265.781px;"><strong>Path</strong></th>
<th style="width: 36.2187px;"><strong>Type</strong></th>
<th style="width: 405px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 265.781px;">TC.Event.DateAdded</td>
<td style="width: 36.2187px;">Date</td>
<td style="width: 405px;">The date on which the event was added.</td>
</tr>
<tr>
<td style="width: 265.781px;">TC.Event.EventDate</td>
<td style="width: 36.2187px;">Date</td>
<td style="width: 405px;">The date on which the event occurred.</td>
</tr>
<tr>
<td style="width: 265.781px;">TC.Event.ID</td>
<td style="width: 36.2187px;">Number</td>
<td style="width: 405px;">The ID of the event.</td>
</tr>
<tr>
<td style="width: 265.781px;">TC.Event.OwnerName</td>
<td style="width: 36.2187px;">String</td>
<td style="width: 405px;">The name of the owner of the event.</td>
</tr>
<tr>
<td style="width: 265.781px;">TC.Event.Status</td>
<td style="width: 36.2187px;">String</td>
<td style="width: 405px;">The status of the event.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-get-events</pre>
<h3 id="h_71af8759-08b2-4944-8e9b-4f6e95496e45">25. Return all groups</h3>
<hr>
<p>Returns all groups, filtered by the group type.</p>
<h5>Base Command</h5>
<p><code>tc-get-groups</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 184.774px;"><strong>Argument Name</strong></th>
<th style="width: 451.226px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 184.774px;">group_type</td>
<td style="width: 451.226px;">The type of the group. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 204.844px;"><strong>Path</strong></th>
<th style="width: 99.1563px;"><strong>Type</strong></th>
<th style="width: 403px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 204.844px;">TC.Group.DateAdded</td>
<td style="width: 99.1563px;">Date</td>
<td style="width: 403px;">The date on which the group was added.</td>
</tr>
<tr>
<td style="width: 204.844px;">TC.Group.EventDate</td>
<td style="width: 99.1563px;">Date</td>
<td style="width: 403px;">The date on which the event occurred.</td>
</tr>
<tr>
<td style="width: 204.844px;">TC.Group.Name</td>
<td style="width: 99.1563px;">String</td>
<td style="width: 403px;">The name of the group.</td>
</tr>
<tr>
<td style="width: 204.844px;">TC.Group.OwnerName</td>
<td style="width: 99.1563px;">String</td>
<td style="width: 403px;">The name of the owner of the group.</td>
</tr>
<tr>
<td style="width: 204.844px;">TC.Group.Status</td>
<td style="width: 99.1563px;">String</td>
<td style="width: 403px;">The status of the group.</td>
</tr>
<tr>
<td style="width: 204.844px;">TC.Group.ID</td>
<td style="width: 99.1563px;">Number</td>
<td style="width: 403px;">The ID of the group.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-get-groups group_type=events</pre>
<h3 id="h_641be290-4112-41cd-a1dd-618c6edcf974">26. Add a security label to a group</h3>
<hr>
<p>Adds a security label to a group.</p>
<h5>Base Command</h5>
<p><code>tc-add-group-security-label</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr style="height: 23.543px;">
<th style="width: 168.34px; height: 23.543px;"><strong>Argument Name</strong></th>
<th style="width: 467.66px; height: 23.543px;"><strong>Description</strong></th>
<th style="width: 71px; height: 23.543px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr style="height: 43px;">
<td style="width: 168.34px; height: 43px;">group_id</td>
<td style="width: 467.66px; height: 43px;">The ID of the group to which to add the security label. To get the ID, run the tc-get-groups command.</td>
<td style="width: 71px; height: 43px;">Required</td>
</tr>
<tr style="height: 65px;">
<td style="width: 168.34px; height: 65px;">group_type</td>
<td style="width: 467.66px; height: 65px;">The type of the group to which to add the security label. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px; height: 65px;">Required</td>
</tr>
<tr style="height: 43px;">
<td style="width: 168.34px; height: 43px;">security_label_name</td>
<td style="width: 467.66px; height: 43px;">The name of the security label to add to the group. For example, "TLP:GREEN".</td>
<td style="width: 71px; height: 43px;">Required</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Command Example</h5>
<pre>!tc-add-group-security-label group_id=4406377 group_type=events security_label_name=TLP:GREEN</pre>
<h3 id="h_2824aa8e-94c3-4491-9be9-989afc0c57d6">27. Adds tags to a specified group</h3>
<hr>
<p>Adds tags to a specified group.</p>
<h5>Base Command</h5>
<p><code>tc-add-group-tag</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 191.031px;"><strong>Argument Name</strong></th>
<th style="width: 444.969px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 191.031px;">group_id</td>
<td style="width: 444.969px;">The ID of the group to which to add the tag. To get the ID, run the tc-get-groups command.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 191.031px;">group_type</td>
<td style="width: 444.969px;">The type of the group to which to add the tag. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 191.031px;">tag_name</td>
<td style="width: 444.969px;">The name of the tag to add to the group.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-add-group-tag group_id=4378343 group_type=events tag_name=phishing</pre>
<h3 id="h_07fd4c7b-a093-42a9-a8f0-54049edfd572">28. Returns all indicator types</h3>
<hr>
<p>Returns all indicator types available.</p>
<h5>Base Command</h5>
<p><code>tc-get-indicator-types</code></p>
<h5>Input</h5>
<table style="width: 765px;" border="2" cellpadding="6">
<tbody>
<tr>
<th style="width: 491px;"><strong>Argument Name</strong></th>
<th style="width: 10px;"><strong>Description</strong></th>
<th style="width: 473px;"><strong>Required</strong></th>
</tr>
<tr>
<td style="width: 491px;">group_id</td>
<td style="width: 10px;">
<div>
<div><span>The ID of the group to which to add the tag. To get the ID, run the tc-get-groups command.</span></div>
</div>
</td>
<td style="width: 473px;">Required</td>
</tr>
<tr>
<td style="width: 491px;">group_type</td>
<td style="width: 10px;">
<div>
<div><span>The type of the group to which to add the tag.</span></div>
<div><span>Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents",</span></div>
<div><span>"intrusionSets", "reports", "signatures", or "threats".</span></div>
</div>
</td>
<td style="width: 473px;">Required</td>
</tr>
<tr>
<td style="width: 491px;">tag_name</td>
<td style="width: 10px;">The name of the indicator. For example, "indicator_type=emailAddresses" where "indicator=a@a.co.il".</td>
<td style="width: 473px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 269.375px;"><strong>Path</strong></th>
<th style="width: 18.625px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 269.375px;">TC.IndicatorType.ApiBranch</td>
<td style="width: 18.625px;">String</td>
<td style="width: 419px;">The branch of the API.</td>
</tr>
<tr>
<td style="width: 269.375px;">TC.IndicatorType.ApiEntity</td>
<td style="width: 18.625px;">String</td>
<td style="width: 419px;">The entity of the API.</td>
</tr>
<tr>
<td style="width: 269.375px;">TC.IndicatorType.CasePreference</td>
<td style="width: 18.625px;">String</td>
<td style="width: 419px;">The case preference of the indicator. For example, "sensitive", "upper", or "lower".</td>
</tr>
<tr>
<td style="width: 269.375px;">TC.IndicatorType.Custom</td>
<td style="width: 18.625px;">Boolean</td>
<td style="width: 419px;">Whether the indicator is a custom indicator.</td>
</tr>
<tr>
<td style="width: 269.375px;">TC.IndicatorType.Parsable</td>
<td style="width: 18.625px;">Boolean</td>
<td style="width: 419px;">Whether the indicator can be parsed.</td>
</tr>
<tr>
<td style="width: 269.375px;">TC.IndicatorType.Value1Type</td>
<td style="width: 18.625px;">String</td>
<td style="width: 419px;">The name of the indicator.</td>
</tr>
<tr>
<td style="width: 269.375px;">TC.IndicatorType.Value1Label</td>
<td style="width: 18.625px;">String</td>
<td style="width: 419px;">The value label of the indicator.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-get-indicator-types</pre>
<h3 id="h_ee65b495-4e67-4a92-9218-76ce69e1c273">29. Associates an indicator with a group</h3>
<hr>
<p>Associates an indicator with a group.</p>
<h5>Base Command</h5>
<p><code>tc-group-associate-indicator</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 201.649px;"><strong>Argument Name</strong></th>
<th style="width: 434.351px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 201.649px;">indicator_type</td>
<td style="width: 434.351px;">The type of the indicator. To get the available types, run the tc-get-indicator-types command. The indicator must be spelled as displayed in the ApiBranch column of the UI.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 201.649px;">indicator</td>
<td style="width: 434.351px;">The name of the indicator. For example, "indicator_type=emailAddresses" where "indicator=a@a.co.il".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 201.649px;">group_type</td>
<td style="width: 434.351px;">The type of the group. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 201.649px;">group_id</td>
<td style="width: 434.351px;">The ID of the group. To get the ID of the group, run the tc-get-groups command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 330.58px;"><strong>Path</strong></th>
<th style="width: 57.4201px;"><strong>Type</strong></th>
<th style="width: 319px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 330.58px;">TC.Group.GroupID</td>
<td style="width: 57.4201px;">Number</td>
<td style="width: 319px;">The ID of the group.</td>
</tr>
<tr>
<td style="width: 330.58px;">TC.Group.GroupType</td>
<td style="width: 57.4201px;">String</td>
<td style="width: 319px;">The type of the group.</td>
</tr>
<tr>
<td style="width: 330.58px;">TC.Group.Indicator</td>
<td style="width: 57.4201px;">String</td>
<td style="width: 319px;">The name of the indicator.</td>
</tr>
<tr>
<td style="width: 330.58px;">TC.Group.IndicatorType</td>
<td style="width: 57.4201px;">String</td>
<td style="width: 319px;">The type of the indicator.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-group-associate-indicator group_id=4406377 group_type=events indicator_type=emailAddresses indicator=a@a.co.il</pre>
<h3 id="h_93b38c5f-321e-42e4-9297-998875571b68">30. Create a document group</h3>
<hr>
<p>Creates a document group.</p>
<h5>Base Command</h5>
<p><code>tc-create-document-group</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 199.264px;"><strong>Argument Name</strong></th>
<th style="width: 437.736px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 199.264px;">file_name</td>
<td style="width: 437.736px;">The name of the file to display in the UI.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 199.264px;">name</td>
<td style="width: 437.736px;">The name of the file.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 199.264px;">malware</td>
<td style="width: 437.736px;">Whether the file is malware. If "true", ThreatConnect creates a password-protected ZIP file on your local machine that contains the sample and uploads the ZIP file.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 199.264px;">password</td>
<td style="width: 437.736px;">The password of the ZIP file.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 199.264px;">security_label</td>
<td style="width: 437.736px;">The security label of the group.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 199.264px;">description</td>
<td style="width: 437.736px;">A description of the group.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 199.264px;">entry_id</td>
<td style="width: 437.736px;">The file of the ID of the entry, as displayed in the War Room.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 233.722px;"><strong>Path</strong></th>
<th style="width: 27.2778px;"><strong>Type</strong></th>
<th style="width: 446px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 233.722px;">TC.Group.Name</td>
<td style="width: 27.2778px;">String</td>
<td style="width: 446px;">The name of the group.</td>
</tr>
<tr>
<td style="width: 233.722px;">TC.Group.Owner</td>
<td style="width: 27.2778px;">String</td>
<td style="width: 446px;">The owner of the group.</td>
</tr>
<tr>
<td style="width: 233.722px;">TC.Group.EventDate</td>
<td style="width: 27.2778px;">Date</td>
<td style="width: 446px;">The date on which the group was created.</td>
</tr>
<tr>
<td style="width: 233.722px;">TC.Group.Description</td>
<td style="width: 27.2778px;">String</td>
<td style="width: 446px;">The description of the group.</td>
</tr>
<tr>
<td style="width: 233.722px;">TC.Group.SecurityLabel</td>
<td style="width: 27.2778px;">String</td>
<td style="width: 446px;">The security label of the group.</td>
</tr>
<tr>
<td style="width: 233.722px;">TC.Group.ID</td>
<td style="width: 27.2778px;">Number</td>
<td style="width: 446px;">The ID of the group to which the attribute was added.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tc-create-document-group file_name="sample.pdf" name="sample.pdf" EntryID="13094@b2672a50-1db8-4424-8dcc-2136f4548ce4"</pre>
<h3 id="h_a9460cff-1c67-4516-a849-3b79fca39d97">31. Retrieve a single group</h3>
<hr>
<p>Retrieves a single group.</p>
<h5>Base Command</h5>
<p><code>tc-get-group</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 145.382px;"><strong>Argument Name</strong></th>
<th style="width: 490.618px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145.382px;">group_type</td>
<td style="width: 490.618px;">The type of group for which to return the ID. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145.382px;">group_id</td>
<td style="width: 490.618px;">The ID of the group to retrieve. To get the ID, run the tc-get-groups command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 308.924px;"><strong>Path</strong></th>
<th style="width: 10px;"><strong>Type</strong></th>
<th style="width: 401px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 308.924px;">TC.Group.DateAdded</td>
<td style="width: 10px;">Date</td>
<td style="width: 401px;">The date on which the group was added.</td>
</tr>
<tr>
<td style="width: 308.924px;">TC.Group.EventDate</td>
<td style="width: 10px;">Date</td>
<td style="width: 401px;">The date on which the event occurred.</td>
</tr>
<tr>
<td style="width: 308.924px;">TC.Group.Name</td>
<td style="width: 10px;">String</td>
<td style="width: 401px;">The name of the group.</td>
</tr>
<tr>
<td style="width: 308.924px;">TC.Group.Owner.ID</td>
<td style="width: 10px;">Number</td>
<td style="width: 401px;">The ID of the group owner.</td>
</tr>
<tr>
<td style="width: 308.924px;">TC.Group.Owner.Name</td>
<td style="width: 10px;">String</td>
<td style="width: 401px;">The name of the group owner.</td>
</tr>
<tr>
<td style="width: 308.924px;">TC.Group.Owner.Type</td>
<td style="width: 10px;">String</td>
<td style="width: 401px;">The type of the owner.</td>
</tr>
<tr>
<td style="width: 308.924px;">TC.Group.Status</td>
<td style="width: 10px;">String</td>
<td style="width: 401px;">The status of the group.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!tc-get-group group_id=4579650 group_type=events</code></p>
<h5>Context Example</h5>
<pre>{
    "TC.Group": {
        "DateAdded": "2019-09-18T10:08:37Z",
        "EventDate": "2019-09-18T10:08:37Z",
        "ID": 4579650,
        "Name": "MyTest",
        "Owner": {
            "ID": 737,
            "Name": "Demisto Inc.",
            "Type": "Organization"
        },
        "Status": "Needs Review"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>ThreatConnect Group information</h3>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 193.958px;"><strong>DateAdded</strong></th>
<th style="width: 131.042px;"><strong>EventDate</strong></th>
<th style="width: 62px;"><strong>ID</strong></th>
<th style="width: 49px;"><strong>Name</strong></th>
<th style="width: 136px;"><strong>Owner</strong></th>
<th style="width: 94px;"><strong>Status</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 193.958px;">2019-09-18T10:08:37Z</td>
<td style="width: 131.042px;">2019-09-18T10:08:37Z</td>
<td style="width: 62px;">4579650</td>
<td style="width: 49px;">MyTest</td>
<td style="width: 136px;">Type: Organization<br> Name: Demisto Inc.<br> ID: 737</td>
<td style="width: 94px;">Needs Review</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_194dd92c-4b86-4f93-b518-d4791dceda62">32. Retrieve the attribute of a group</h3>
<hr>
<p>Retrieves the attribute of a group.</p>
<h5>Base Command</h5>
<p><code>tc-get-group-attributes</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 197.465px;"><strong>Argument Name</strong></th>
<th style="width: 438.535px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 197.465px;">group_type</td>
<td style="width: 438.535px;">The type of group for which to return the attribute. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 197.465px;">group_id</td>
<td style="width: 438.535px;">The ID of the group for which to return the attribute. To get the ID, run the tc-get-groups command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 293.517px;"><strong>Path</strong></th>
<th style="width: 18.4826px;"><strong>Type</strong></th>
<th style="width: 395px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 293.517px;">TC.Group.Attribute.DateAdded</td>
<td style="width: 18.4826px;">Date</td>
<td style="width: 395px;">The date on which the group was added.</td>
</tr>
<tr>
<td style="width: 293.517px;">TC.Group.Attribute.Displayed</td>
<td style="width: 18.4826px;">Boolean</td>
<td style="width: 395px;">Whether the attribute is displayed on the UI.</td>
</tr>
<tr>
<td style="width: 293.517px;">TC.Group.Attribute.AttributeID</td>
<td style="width: 18.4826px;">Number</td>
<td style="width: 395px;">The ID of the attribute.</td>
</tr>
<tr>
<td style="width: 293.517px;">TC.Group.Attribute.LastModified</td>
<td style="width: 18.4826px;">Date</td>
<td style="width: 395px;">The date on which the attribute was last modified.</td>
</tr>
<tr>
<td style="width: 293.517px;">TC.Group.Attribute.Type</td>
<td style="width: 18.4826px;">String</td>
<td style="width: 395px;">The type of the attribute.</td>
</tr>
<tr>
<td style="width: 293.517px;">TC.Group.Attribute.Value</td>
<td style="width: 18.4826px;">String</td>
<td style="width: 395px;">The value of the attribute.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!tc-get-group-attributes group_id=4579650 group_type=events</code></p>
<h5>Context Example</h5>
<pre>{
    "TC.Group.Attribute": [
        {
            "AttributeID": 20279371,
            "DateAdded": "2019-09-18T10:13:06Z",
            "Displayed": false,
            "GroupID": 4579650,
            "LastModified": "2019-09-18T10:13:06Z",
            "Type": "External ID",
            "Value": "123456789"
        },
        {
            "AttributeID": 20279370,
            "DateAdded": "2019-09-18T10:11:37Z",
            "Displayed": false,
            "GroupID": 4579650,
            "LastModified": "2019-09-18T10:11:37Z",
            "Type": "External ID",
            "Value": "123456789"
        },
        {
            "AttributeID": 20279368,
            "DateAdded": "2019-09-18T10:10:07Z",
            "Displayed": false,
            "GroupID": 4579650,
            "LastModified": "2019-09-18T10:10:07Z",
            "Type": "External ID",
            "Value": "123456789"
        },
        {
            "AttributeID": 20279366,
            "DateAdded": "2019-09-18T10:08:38Z",
            "Displayed": false,
            "GroupID": 4579650,
            "LastModified": "2019-09-18T10:08:38Z",
            "Type": "External ID",
            "Value": "123456789"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>ThreatConnect Group Attributes</h3>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 119.278px;"><strong>AttributeID</strong></th>
<th style="width: 49.7222px;"><strong>Type</strong></th>
<th style="width: 80px;"><strong>Value</strong></th>
<th style="width: 170px;"><strong>DateAdded</strong></th>
<th style="width: 171px;"><strong>LastModified</strong></th>
<th style="width: 78px;"><strong>Displayed</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 119.278px;">20279371</td>
<td style="width: 49.7222px;">External ID</td>
<td style="width: 80px;">123456789</td>
<td style="width: 170px;">2019-09-18T10:13:06Z</td>
<td style="width: 171px;">2019-09-18T10:13:06Z</td>
<td style="width: 78px;">false</td>
</tr>
<tr>
<td style="width: 119.278px;">20279370</td>
<td style="width: 49.7222px;">External ID</td>
<td style="width: 80px;">123456789</td>
<td style="width: 170px;">2019-09-18T10:11:37Z</td>
<td style="width: 171px;">2019-09-18T10:11:37Z</td>
<td style="width: 78px;">false</td>
</tr>
<tr>
<td style="width: 119.278px;">20279368</td>
<td style="width: 49.7222px;">External ID</td>
<td style="width: 80px;">123456789</td>
<td style="width: 170px;">2019-09-18T10:10:07Z</td>
<td style="width: 171px;">2019-09-18T10:10:07Z</td>
<td style="width: 78px;">false</td>
</tr>
<tr>
<td style="width: 119.278px;">20279366</td>
<td style="width: 49.7222px;">External ID</td>
<td style="width: 80px;">123456789</td>
<td style="width: 170px;">2019-09-18T10:08:38Z</td>
<td style="width: 171px;">2019-09-18T10:08:38Z</td>
<td style="width: 78px;">false</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_1ea1f849-40aa-4ad5-ad6f-b5a719b0ea4a">33. Retrieve the security labels of a group</h3>
<hr>
<p>Retrieves the security labels of a group.</p>
<h5>Base Command</h5>
<p><code>tc-get-group-security-labels</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 162.934px;"><strong>Argument Name</strong></th>
<th style="width: 473.066px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162.934px;">group_type</td>
<td style="width: 473.066px;">The type of group for which to return the security labels. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 162.934px;">group_id</td>
<td style="width: 473.066px;">The ID of the group for which to return the security labels. To get the ID, run the tc-get-groups command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 276.135px;"><strong>Path</strong></th>
<th style="width: 49.8646px;"><strong>Type</strong></th>
<th style="width: 381px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 276.135px;">TC.Group.SecurityLabel.Name</td>
<td style="width: 49.8646px;">String</td>
<td style="width: 381px;">The name of the security label.</td>
</tr>
<tr>
<td style="width: 276.135px;">TC.Group.SecurityLabel.Description</td>
<td style="width: 49.8646px;">String</td>
<td style="width: 381px;">The description of the security label.</td>
</tr>
<tr>
<td style="width: 276.135px;">TC.Group.SecurityLabel.DateAdded</td>
<td style="width: 49.8646px;">Date</td>
<td style="width: 381px;">The date on which the security label was added.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!tc-get-group-security-labels group_id=4579650 group_type=events</code></p>
<h5>Context Example</h5>
<pre>{
    "TC.Group.SecurityLabel": [
        {
            "DateAdded": "2016-08-31T00:00:00Z",
            "Description": "This security label is used for information that is useful for the awareness of all participating organizations as well as with peers within the broader community or sector.",
            "GroupID": 4579650,
            "Name": "TLP:GREEN"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>ThreatConnect Group Security Labels</h3>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 150.486px;"><strong>Name</strong></th>
<th style="width: 454.514px;"><strong>Description</strong></th>
<th style="width: 102px;"><strong>DateAdded</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 150.486px;">TLP:GREEN</td>
<td style="width: 454.514px;">This security label is used for information that is useful for the awareness of all participating organizations as well as with peers within the broader community or sector.</td>
<td style="width: 102px;">2016-08-31T00:00:00Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3e053624-ac89-4759-ace2-67f90f75cf0a">34. Retrieves the tags of a group</h3>
<hr>
<p>Retrieves the tags of a group.</p>
<h5>Base Command</h5>
<p><code>tc-get-group-tags</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 154.497px;"><strong>Argument Name</strong></th>
<th style="width: 481.503px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154.497px;">group_type</td>
<td style="width: 481.503px;">The type of group for which to return the tags. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 154.497px;">group_id</td>
<td style="width: 481.503px;">The ID of the group for which to return the tags. To get the ID, run the tc-get-groups command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 301.813px;"><strong>Path</strong></th>
<th style="width: 92.1875px;"><strong>Type</strong></th>
<th style="width: 313px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 301.813px;">TC.Group.Tag.Name</td>
<td style="width: 92.1875px;">String</td>
<td style="width: 313px;">The name of the tag.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!tc-get-group-tags group_id=4579650 group_type=events</code></p>
<h5>Context Example</h5>
<pre>{
    "TC.Group.Tag": [
        {
            "GroupID": 4579650,
            "Name": "Testing"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>ThreatConnect Group Tags</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Name</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Testing</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_ea226a75-dcb3-4b7c-a2cc-6c4772492481">35. Downloads the contents of a document</h3>
<hr>
<p>Downloads the contents of a document.</p>
<h5>Base Command</h5>
<p><code>tc-download-document</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 281.927px;"><strong>Argument Name</strong></th>
<th style="width: 285.073px;"><strong>Description</strong></th>
<th style="width: 140px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 281.927px;">document_id</td>
<td style="width: 285.073px;">The ID of the document.</td>
<td style="width: 140px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 147.951px;"><strong>Path</strong></th>
<th style="width: 38.0486px;"><strong>Type</strong></th>
<th style="width: 522px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147.951px;">File.Size</td>
<td style="width: 38.0486px;">Number</td>
<td style="width: 522px;">The size of the file.</td>
</tr>
<tr>
<td style="width: 147.951px;">File.SHA1</td>
<td style="width: 38.0486px;">String</td>
<td style="width: 522px;">The SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 147.951px;">File.SHA256</td>
<td style="width: 38.0486px;">String</td>
<td style="width: 522px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 147.951px;">File.Name</td>
<td style="width: 38.0486px;">String</td>
<td style="width: 522px;">The name of the file.</td>
</tr>
<tr>
<td style="width: 147.951px;">File.SSDeep</td>
<td style="width: 38.0486px;">String</td>
<td style="width: 522px;">The ssdeep hash of the file (same as displayed in file entries).</td>
</tr>
<tr>
<td style="width: 147.951px;">File.EntryID</td>
<td style="width: 38.0486px;">String</td>
<td style="width: 522px;">The entry ID of the file.</td>
</tr>
<tr>
<td style="width: 147.951px;">File.Info</td>
<td style="width: 38.0486px;">String</td>
<td style="width: 522px;">The information of the file.</td>
</tr>
<tr>
<td style="width: 147.951px;">File.Type</td>
<td style="width: 38.0486px;">String</td>
<td style="width: 522px;">The type of the file.</td>
</tr>
<tr>
<td style="width: 147.951px;">File.MD5</td>
<td style="width: 38.0486px;">String</td>
<td style="width: 522px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 147.951px;">File.Extension</td>
<td style="width: 38.0486px;">String</td>
<td style="width: 522px;">The extension of the file.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!tc-download-document document_id=1234567</code></p>
<h3 id="h_fb44bbee-2172-4579-b056-805c45288080">36. Returns indicators associated with a group</h3>
<hr>
<p>Returns indicators associated with a group.</p>
<h5>Base Command</h5>
<p><code>tc-get-group-indicators</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 145.955px;"><strong>Argument Name</strong></th>
<th style="width: 490.045px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145.955px;">group_type</td>
<td style="width: 490.045px;">The type of the group for which to return the indicators. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145.955px;">group_id</td>
<td style="width: 490.045px;">The ID of the group for which to return the indicators. To get the ID, run the tc-get-groups command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 326.354px;"><strong>Path</strong></th>
<th style="width: 49.6458px;"><strong>Type</strong></th>
<th style="width: 332px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 326.354px;">TC.Group.Indicator.Summary</td>
<td style="width: 49.6458px;">String</td>
<td style="width: 332px;">The summary of the indicator.</td>
</tr>
<tr>
<td style="width: 326.354px;">TC.Group.Indicator.ThreatAssessConfidence</td>
<td style="width: 49.6458px;">String</td>
<td style="width: 332px;">The confidence rating of the indicator.</td>
</tr>
<tr>
<td style="width: 326.354px;">TC.Group.Indicator.IndicatorID</td>
<td style="width: 49.6458px;">Number</td>
<td style="width: 332px;">The ID of the indicator.</td>
</tr>
<tr>
<td style="width: 326.354px;">TC.Group.Indicator.DateAdded</td>
<td style="width: 49.6458px;">Date</td>
<td style="width: 332px;">The date on which the indicator was added.</td>
</tr>
<tr>
<td style="width: 326.354px;">TC.Group.Indicator.Type</td>
<td style="width: 49.6458px;">String</td>
<td style="width: 332px;">The type of the indicator.</td>
</tr>
<tr>
<td style="width: 326.354px;">TC.Group.Indicator.Rating</td>
<td style="width: 49.6458px;">Number</td>
<td style="width: 332px;">The threat rating of the indicator.</td>
</tr>
<tr>
<td style="width: 326.354px;">TC.Group.Indicator.ThreatAssertRating</td>
<td style="width: 49.6458px;">Number</td>
<td style="width: 332px;">The rating of the threat assert.</td>
</tr>
<tr>
<td style="width: 326.354px;">TC.Group.Indicator.OwnerName</td>
<td style="width: 49.6458px;">String</td>
<td style="width: 332px;">The name of the owner of the indicator.</td>
</tr>
<tr>
<td style="width: 326.354px;">TC.Group.Indicator.LastModified</td>
<td style="width: 49.6458px;">Date</td>
<td style="width: 332px;">The date that the indicator was last modified.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!tc-get-group-indicators group_id=4579650 group_type=events</code></p>
<h5>Context Example</h5>
<pre>{
    "TC.Group.Indicator": [
        {
            "Confidence": null,
            "DateAdded": "2019-01-03T16:08:07Z",
            "GroupID": 4579650,
            "IndicatorID": 63441869,
            "LastModified": "2019-01-03T16:08:15Z",
            "OwnerName": "Demisto Inc.",
            "Rating": 2,
            "Summary": "a@a.co.il",
            "ThreatAssertRating": 2,
            "ThreatAssessConfidence": 0,
            "Type": "EmailAddress"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>ThreatConnect Group Indicators</h3>
<table style="width: 1162px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 142.507px;"><strong>DateAdded</strong></th>
<th style="width: 26.493px;"><strong>GroupID</strong></th>
<th style="width: 92px;"><strong>IndicatorID</strong></th>
<th style="width: 102px;"><strong>LastModified</strong></th>
<th style="width: 98px;"><strong>OwnerName</strong></th>
<th style="width: 51px;"><strong>Rating</strong></th>
<th style="width: 75px;"><strong>Summary</strong></th>
<th style="width: 153px;"><strong>ThreatAssertRating</strong></th>
<th style="width: 192px;"><strong>ThreatAssessConfidence</strong></th>
<th style="width: 94px;"><strong>Type</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142.507px;">2019-01-03T16:08:07Z</td>
<td style="width: 26.493px;">4579650</td>
<td style="width: 92px;">63441869</td>
<td style="width: 102px;">2019-01-03T16:08:15Z</td>
<td style="width: 98px;">Demisto Inc.</td>
<td style="width: 51px;">2.0</td>
<td style="width: 75px;">a@a.co.il</td>
<td style="width: 153px;">2.0</td>
<td style="width: 192px;">0.0</td>
<td style="width: 94px;">EmailAddress</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_035ca80f-4cb4-4adf-b50d-86f9f67c427b">37. Returns indicators associated with a specific group</h3>
<hr>
<p>Returns indicators associated with a specified group.</p>
<h5>Base Command</h5>
<p><code>tc-get-associated-groups</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 161.823px;"><strong>Argument Name</strong></th>
<th style="width: 474.177px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 161.823px;">group_type</td>
<td style="width: 474.177px;">The type of group. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 161.823px;">group_id</td>
<td style="width: 474.177px;">The ID of the group. To get the ID, run the tc-get-groups command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 323.465px;"><strong>Path</strong></th>
<th style="width: 74.5347px;"><strong>Type</strong></th>
<th style="width: 310px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 323.465px;">TC.Group.AssociatedGroup.DateAdded</td>
<td style="width: 74.5347px;">Date</td>
<td style="width: 310px;">The date on which group was added.</td>
</tr>
<tr>
<td style="width: 323.465px;">TC.Group.AssociatedGroup.GroupID</td>
<td style="width: 74.5347px;">Number</td>
<td style="width: 310px;">The ID of the group.</td>
</tr>
<tr>
<td style="width: 323.465px;">TC.Group.AssociatedGroup.Name</td>
<td style="width: 74.5347px;">String</td>
<td style="width: 310px;">The name of the group.</td>
</tr>
<tr>
<td style="width: 323.465px;">TC.Group.AssociatedGroup.OwnerName</td>
<td style="width: 74.5347px;">String</td>
<td style="width: 310px;">The name of the owner of the group.</td>
</tr>
<tr>
<td style="width: 323.465px;">TC.Group.AssociatedGroup.Type</td>
<td style="width: 74.5347px;">String</td>
<td style="width: 310px;">The type of the group.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!tc-get-associated-groups group_id=4579650 group_type=events</code></p>
<h5>Context Example</h5>
<pre>{
    "TC.Group.AssociatedGroup": [
        {
            "DateAdded": "2019-01-13T18:13:19Z",
            "GroupID": 3594873,
            "Name": "NewCampaign",
            "OwnerName": "Demisto Inc.",
            "Type": "Campaign"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>ThreatConnect Associated Groups</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 126.517px;"><strong>GroupID</strong></th>
<th style="width: 100.483px;"><strong>Name</strong></th>
<th style="width: 96px;"><strong>Type</strong></th>
<th style="width: 132px;"><strong>OwnerName</strong></th>
<th style="width: 225px;"><strong>DateAdded</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 126.517px;">3594873</td>
<td style="width: 100.483px;">NewCampaign</td>
<td style="width: 96px;">Campaign</td>
<td style="width: 132px;">Demisto Inc.</td>
<td style="width: 225px;">2019-01-13T18:13:19Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_20deac42-acae-425b-bdce-b611b0469a79">38. Associates one group with another group</h3>
<hr>
<p>Associates one group with another group.</p>
<h5>Base Command</h5>
<p><code>tc-associate-group-to-group</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 203.063px;"><strong>Argument Name</strong></th>
<th style="width: 432.938px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 203.063px;">group_type</td>
<td style="width: 432.938px;">The type of the group. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 203.063px;">group_id</td>
<td style="width: 432.938px;">The ID of the group. To get the ID of the group, run the tc-get-groups command.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 203.063px;">associated_group_type</td>
<td style="width: 432.938px;">The type of group to associate. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 203.063px;">associated_group_id</td>
<td style="width: 432.938px;">The ID of the group to associate.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 344.705px;"><strong>Path</strong></th>
<th style="width: 78.2951px;"><strong>Type</strong></th>
<th style="width: 284px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 344.705px;">TC.Group.AssociatedGroup.AssociatedGroupID</td>
<td style="width: 78.2951px;">Number</td>
<td style="width: 284px;">The ID of the associated group.</td>
</tr>
<tr>
<td style="width: 344.705px;">TC.Group.AssociatedGroup.AssociatedGroupType</td>
<td style="width: 78.2951px;">String</td>
<td style="width: 284px;">The type of the associated group.</td>
</tr>
<tr>
<td style="width: 344.705px;">TC.Group.AssociatedGroup.GroupID</td>
<td style="width: 78.2951px;">Number</td>
<td style="width: 284px;">The ID of the group to associate to.</td>
</tr>
<tr>
<td style="width: 344.705px;">TC.Group.AssociatedGroup.GroupType</td>
<td style="width: 78.2951px;">String</td>
<td style="width: 284px;">The type of the group to associate to.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!tc-associate-group-to-group associated_group_id=3594873 associated_group_type=campaigns group_id=4410738 group_type=events</code></p>
<h5>Context Example</h5>
<pre>{
    "TC.Group.AssociatedGroup": {
        "AssociatedGroupID": 3594873,
        "AssociatedGroupType": "campaigns",
        "GroupID": 4410738,
        "GroupType": "events"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>The group 3594873 was associated successfully.</p>
