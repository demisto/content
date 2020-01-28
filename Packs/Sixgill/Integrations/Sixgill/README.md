<p>
Sixgill’s cyber threat intelligence solution focuses on customers’ intelligence needs, helping them mitigate risk to their organizations more effectively and more efficiently. Using an agile and automatic collection methodology, Sixgill provides broad coverage of exclusive-access deep and dark web sources, as well as relevant surface web sources. Sixgill utilizes artificial intelligence and machine learning to automate the production cycle of cyber intelligence from monitoring through extraction to production. 

Automatic monitoring of cybercrime, providing actionable intelligence from exclusive clear, deep and dark web forums and markets. Detect, analyze and mitigate financial fraud in near real-time.

Integration:
<ul>
<li>Retrieving Sixgill's DarkFeed Threat Intelligence indicators (IOC)</li>
<li>Retrieving Sixgill's Actionable Alerts as incidents</li>
</ul>
This integration was integrated and tested with version 0.1.0 of Sixgill
</p>
<h2>Sixgill Playbook</h2>
<p>
Sixgill - DarkFeed - Indicators:
The playbook extracts a STIX bundle then uses StixParser automation in order to parse and push indicators into demisto’s platform.
</p>
<h2>Use Cases</h2>
<ul>
<li>Fetching Sixgill's DarkFeed Threat Intelligence indicators.</li>
<li>Fetching Sixgill's Alerts & Events as incidents.</li>
</ul>
<h2>Detailed Description</h2>
<p>Configure an API account:</p>
<p>To configure an instance of Sixgill's integration in Demisto, you need to supply your API key and client Secret. Please contact support@cybersixgill.com to receive these.</p>
<h2>Fetch Incidents</h2>
<p>Sixgill's alerts are pushed as incidents to Demisto platform. </p>
<h2>Configure Sixgill on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Sixgill.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Sixgill API client ID</strong></li>
   <li><strong>Sixgill API client secret</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>fetch-incidents: fetch-incidents</li>
  <li>sixgill-get-indicators: sixgill-get-indicators</li>
</ol>
<h3>1. fetch-incidents</h3>
<hr>
<p>Get Sixgill's alerts as incidents</p>
<h5>Base Command</h5>
<p>
  <code>fetch-incidents</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Sixgill's API client id and client secret.</li>
    <li>Organization is registered to consume data using Demisto platform</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>maxIncidents</td>
      <td>Max number of incidents that can be fetched</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>severity</td>
      <td>Filter by alert template severity</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>threat_level</td>
      <td>Filter by alert threat level</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>threat_type</td>
      <td>Filter by alert threat type</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!fetch-incidents</code>
</p>

<h5>Human Readable Output</h5>
Sixgill's Alert:
<pre>
{
    'alert_name': 'someAlert', 
    'content': '', 
    'date': '2019-08-06 23:20:35', 
    'id': '<id>',
    'lang': 'English', 
    'langcode': 'en', 
    'read': False, 
    'severity': 10,
    'threat_level': 'emerging', 
    'threats': [<threats_tags>], 
    'title': 'some alert',
    'user_id': '<user_id>'
}
</pre>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>2. sixgill-get-indicators</h3>
<hr>
<p>Fetching Sixgill's DarkFeed Threat Intelligence indicators as a STIX V2.0 bundle format</p>
<h5>Base Command</h5>
<p>
  <code>sixgill-get-indicators</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Sixgill's API client id and client secret.</li>
    <li>Organization is registered to consume data using Demisto platform</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
     <tr>
      <td>maxIndicators</td>
      <td>Max number of indicators that can be fetched</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>InfoFile.EntryID</td>
      <td>String</td>
      <td>The EntryID of the report file</td>
    </tr>
    <tr>
      <td>InfoFile.Extension</td>
      <td>String</td>
      <td>The extension of the report file</td>
    </tr>
    <tr>
      <td>InfoFile.Name</td>
      <td>String</td>
      <td>The name of the report file</td>
    </tr>
    <tr>
      <td>InfoFile.Info</td>
      <td>String</td>
      <td>The info of the report file</td>
    </tr>
    <tr>
      <td>InfoFile.Size</td>
      <td>Number</td>
      <td>The size of the report file</td>
    </tr>
    <tr>
      <td>InfoFile.Type</td>
      <td>Number</td>
      <td>The type of the report file</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!get-indicators</code>
</p>

<h5>Human Readable Output</h5>
<pre>
# Fetched <num_of_indicators> DarkFeed indicators
</pre>

<h5>Output</h5>
<pre>
{
"id": "bundle--9fe23422-1339-47db-9ef0-117bd0b5cb84", 
"objects": 
    [
        {"created": "2017-01-20T00:00:00.000Z", "definition": {"tlp": "amber"}, "definition_type": "tlp", "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "type": "marking-definition"}, 
        {"created": "2019-12-26T00:00:00Z", "definition": {"statement": "Copyright Sixgill 2020. All rights reserved."}, "definition_type": "statement", "id": "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4", "type": "marking-definition"}, 
        {"created": "2020-01-21T12:31:13.822Z", "description": "Shell access to this domain is being sold on dark web markets", "external_reference": [{"description": "Mitre attack tactics and technique reference", "mitre_attack_tactic": "Establish & Maintain Infrastructure", "mitre_attack_tactic_id": "TA0022", "mitre_attack_tactic_url": "https://attack.mitre.org/tactics/TA0022/", "mitre_attack_technique": "Compromise 3rd party infrastructure to support delivery", "mitre_attack_technique_id": "T1334", "mitre_attack_technique_url": "https://attack.mitre.org/techniques/T1334/", "source_name": "mitre-attack"}], "id": "indicator--54c285d5-931c-43b2-829b-b4374da993b2", "labels": ["compromised", "shell", "webshell", "Establish & Maintain Infrastructure", "Compromise 3rd party infrastructure to support delivery"], "lang": "en", "modified": "2020-01-21T12:31:13.822Z", "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4", "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"], "pattern": "[domain-name:value = 'http://lyweixinyijia.com']", "sixgill_actor": "belgrad", "sixgill_confidence": 90, "sixgill_feedid": "darkfeed_001", "sixgill_feedname": "compromised_sites", "sixgill_postid": "4dd781acdfa683c0e96b830d95481e4a38b3184c", "sixgill_posttitle": "Shop designer furniture and unique furniture  from lush sofas to dining tables for your bedroom, living room, dining room and more       http://lyweixinyijia.com", "sixgill_severity": 70, "sixgill_source": "market_magbo", "spec_version": "2.0", "type": "indicator", "valid_from": "2019-12-20T14:08:19Z", "score": "High"}, 
        {"created": "2020-01-21T12:31:13.907Z", "description": "Shell access to this domain is being sold on dark web markets", "external_reference": [{"description": "Mitre attack tactics and technique reference", "mitre_attack_tactic": "Establish & Maintain Infrastructure", "mitre_attack_tactic_id": "TA0022", "mitre_attack_tactic_url": "https://attack.mitre.org/tactics/TA0022/", "mitre_attack_technique": "Compromise 3rd party infrastructure to support delivery", "mitre_attack_technique_id": "T1334", "mitre_attack_technique_url": "https://attack.mitre.org/techniques/T1334/", "source_name": "mitre-attack"}], "id": "indicator--560d6f92-0513-409f-989e-f9f3ee290d9b", "labels": ["compromised", "shell", "webshell", "Establish & Maintain Infrastructure", "Compromise 3rd party infrastructure to support delivery"], "lang": "en", "modified": "2020-01-21T12:31:13.907Z", "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4", "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"], "pattern": "[domain-name:value = 'http://mypersonalizedhealthcare.com']", "sixgill_actor": "cpanel", "sixgill_confidence": 90, "sixgill_feedid": "darkfeed_001", "sixgill_feedname": "compromised_sites", "sixgill_postid": "ae3c4cbafb8244aa0bc0b8eb9bdaf0d0eef84e30", "sixgill_posttitle": "Our site is currently under Cons       http://mypersonalizedhealthcare.com", "sixgill_severity": 70, "sixgill_source": "market_magbo", "spec_version": "2.0", "type": "indicator", "valid_from": "2019-12-20T14:37:18Z", "score": "High"}, 
        {"created": "2020-01-21T12:31:13.913Z", "description": "Shell access to this domain is being sold on dark web markets", "external_reference": [{"description": "Mitre attack tactics and technique reference", "mitre_attack_tactic": "Establish & Maintain Infrastructure", "mitre_attack_tactic_id": "TA0022", "mitre_attack_tactic_url": "https://attack.mitre.org/tactics/TA0022/", "mitre_attack_technique": "Compromise 3rd party infrastructure to support delivery", "mitre_attack_technique_id": "T1334", "mitre_attack_technique_url": "https://attack.mitre.org/techniques/T1334/", "source_name": "mitre-attack"}], "id": "indicator--8c8c3e32-4c8c-454c-bb79-fcc6eee96138", "labels": ["compromised", "shell", "webshell", "Establish & Maintain Infrastructure", "Compromise 3rd party infrastructure to support delivery"], "lang": "en", "modified": "2020-01-21T12:31:13.913Z", "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4", "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"], "pattern": "[domain-name:value = 'http://sokesi.com']", "sixgill_actor": "belgrad", "sixgill_confidence": 90, "sixgill_feedid": "darkfeed_001", "sixgill_feedname": "compromised_sites", "sixgill_postid": "f8c79be04c95711d548d4e1014442722b5cd0889", "sixgill_posttitle": "Cool Car DVD Player and Headrest - Naviskauto       http://sokesi.com", "sixgill_severity": 70, "sixgill_source": "market_magbo", "spec_version": "2.0", "type": "indicator", "valid_from": "2019-12-20T14:21:07Z", "score": "High"}, 
        {"created": "2020-01-21T12:31:13.919Z", "description": "Shell access to this domain is being sold on dark web markets", "external_reference": [{"description": "Mitre attack tactics and technique reference", "mitre_attack_tactic": "Establish & Maintain Infrastructure", "mitre_attack_tactic_id": "TA0022", "mitre_attack_tactic_url": "https://attack.mitre.org/tactics/TA0022/", "mitre_attack_technique": "Compromise 3rd party infrastructure to support delivery", "mitre_attack_technique_id": "T1334", "mitre_attack_technique_url": "https://attack.mitre.org/techniques/T1334/", "source_name": "mitre-attack"}], "id": "indicator--32d46830-d626-4a29-b1be-1c85ac328587", "labels": ["compromised", "shell", "webshell", "Establish & Maintain Infrastructure", "Compromise 3rd party infrastructure to support delivery"], "lang": "en", "modified": "2020-01-21T12:31:13.919Z", "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4", "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"], "pattern": "[domain-name:value = 'https://floridahbpa.com']", "sixgill_actor": "nitupme", "sixgill_confidence": 90, "sixgill_feedid": "darkfeed_001", "sixgill_feedname": "compromised_sites", "sixgill_postid": "eae819a9d97867bb994318772d9beaa51d943ce5", "sixgill_posttitle": "Home - Florida HBPA | Florida Thoroughbred Racing       https://floridahbpa.com", "sixgill_severity": 70, "sixgill_source": "market_magbo", "spec_version": "2.0", "type": "indicator", "valid_from": "2019-12-20T14:32:22Z", "score": "High"}
    ], 
"spec_version": "2.0", 
"type": "bundle"
}
</pre>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h2>Additional Information</h2><h2>Known Limitations</h2><h2>Troubleshooting</h2><p>Contact us: support@cybersixgill.com</p>