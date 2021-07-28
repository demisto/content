<!-- HTML_DOC -->
<section class="article-info">
        <div class="article-content">
          <div class="article-body"><h2>Overview</h2>
<p>Use this integration to manage and orchestrate your IBM Resilient Systems incident response from Cortex XSOAR.</p>
<hr>
<h2>Configure the IBM Resilient Systems Integration on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for IBM&nbsp;Resilient Systems.</li>
<li>Click&nbsp;<strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li><strong>Name</strong>: a textual name for the integration instance</li>
<li><strong>Server URL</strong></li>
<li><strong>Credentials (either username and password or API key ID and API key secret, see <a href="https://www.ibm.com/support/knowledgecenter/SSBRUQ_35.0.0/com.ibm.resilient.doc/admin/API_accounts.htm">here</a> for more details about API key ID and secret)</strong></li>
<li><strong>Organization name</strong></li>
<li><strong>Do not validate server certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and token.</li>
</ol>
<hr>
<h2>Fetched Incidents Data</h2>
<p>Need more information.</p>
<hr>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_43150070651528808250950">Search for incidents: rs-search-incidents</a></li>
<li><a href="#h_736120856181528808732843">Update an incident: rs-update-incident</a></li>
<li><a href="#h_822352343351528809805787">Get a list of incident members: rs-incident-get-members</a></li>
<li><a href="#h_77974582581528810221337">Get incident information: rs-get-incident</a></li>
<li><a href="#h_672396217841528810416196">Update information for an incident member: rs-incidents-update-member</a></li>
<li><a href="#h_2927197521131528810601114">Get a list of users: rs-get-users</a></li>
<li><a href="#h_2792064041461528810768909">Close an incident: rs-close-incident</a></li>
<li><a href="#h_3906354711831528810903159">Create an incident: rs-create-incident</a></li>
<li><a href="#h_9611617552241528811470715">Get artifacts for an incident: rs-incident-artifacts</a></li>
<li><a href="#h_1823709132691528812526569">Get attachments of an incident: rs-incident-attachments</a></li>
<li><a href="#h_9184065563181528813233519">Get related incidents: rs-related-incidents</a></li>
<li><a href="#h_7077667663711528814261115">Get tasks for an incident: rs-incidents-get-tasks</a></li>
<li><a href="#h_9184065563181528813233520">Add a note to an incident: rs-add-note</a></li>
<li><a href="#h_7077667663711528814261121">Add an artifact to an incident: rs-add-artifact</a></li>
</ol>
<p>&nbsp;</p>
<h3 id="h_43150070651528808250950">Search for incidents: rs-search-incidents</h3>
<p>Search for incidents in your IBM Resilient system.</p>
<h5>Command Example</h5>
<p><code>!rs-search-incidents severity=Low,Medium incident-type=CommunicationError</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">severity</td>
<td style="width: 503px;">
<p>Incident severity (comma separated)</p>
<ul>
<li>Low</li>
<li>Medium</li>
<li>High</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 211px;">date-created-before</td>
<td style="width: 503px;">Created date of the incident before a specified date (YYYY-MM-DDTHH:MM:SSZ, for example, 2018-05-07T10:59:07Z)</td>
</tr>
<tr>
<td style="width: 211px;">date-created-after</td>
<td style="width: 503px;">Created date of the incident after a specified (format YYYY-MM-DDTHH:MM:SSZ, for example, 2018-05-07T10:59:07Z)</td>
</tr>
<tr>
<td style="width: 211px;">date-created-within-the-last</td>
<td style="width: 503px;">Created date of the incident within the last time frame (days/hours/minutes). Should be entered as a number, and used with the timeframe argument.</td>
</tr>
<tr>
<td style="width: 211px;">timeframe</td>
<td style="width: 503px;">Time frame to search within for incident. Should be used with within-the-last/due-in argument.</td>
</tr>
<tr>
<td style="width: 211px;">date-occurred-within-the-last</td>
<td style="width: 503px;">Occurred date of the incident within the last time frame (days/hours/minutes). Should be entered as a number, and used with with the timeframe argument.</td>
</tr>
<tr>
<td style="width: 211px;">date-occurred-before</td>
<td style="width: 503px;">Occurred date of the incident before given date (YYYY-MM-DDTHH:MM:SSZ, for example, 2018-05-07T10:59:07Z)</td>
</tr>
<tr>
<td style="width: 211px;">date-occurred-after</td>
<td style="width: 503px;">Occurred date of the incident after a specified date (YYYY-MM-DDTHH:MM:SSZ, for example, 2018-05-07T10:59:07Z)</td>
</tr>
<tr>
<td style="width: 211px;">incident-type</td>
<td style="width: 503px;">Incident type</td>
</tr>
<tr>
<td style="width: 211px;">nist</td>
<td style="width: 503px;">NIST Attack Vectors</td>
</tr>
<tr>
<td style="width: 211px;">status</td>
<td style="width: 503px;">Incident status</td>
</tr>
<tr>
<td style="width: 211px;">due-in</td>
<td style="width: 503px;">Due date of the incident in a specific timeframe (days/hours/minutes). Should be entered as a number, along with with the timeframe argument.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.CreateDate</td>
<td style="width: 503px;">Created date of the incident</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Name</td>
<td style="width: 503px;">Incident name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.DiscoveredDate</td>
<td style="width: 503px;">Discovered date of the incident</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Id</td>
<td style="width: 503px;">Incident ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Phase</td>
<td style="width: 503px;">Incident phase</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Severity</td>
<td style="width: 503px;">Incident severity</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Description</td>
<td style="width: 503px;">Incident description</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>DiscoveredDate:2018-05-18T08:49:38Z
Id:2112
Name:Incident Name
Owner:Owner Name
Phase:Respond
Severity:Low</pre>
<hr>
<h3 id="h_736120856181528808732843">Update an incident: rs-update-incident</h3>
<p>Updater an incident in your IBM Resilient system.</p>
<h5>Command Example</h5>
<p><code>!rs-update-incident incident-id=2222 severity=High incident-type=Malware</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">incident-id</td>
<td style="width: 503px;">Incident ID to update</td>
</tr>
<tr>
<td style="width: 211px;">severity</td>
<td style="width: 503px;">Severity to update</td>
</tr>
<tr>
<td style="width: 211px;">owner</td>
<td style="width: 503px;">User's full name set as the incident owner</td>
</tr>
<tr>
<td style="width: 211px;">incident-type</td>
<td style="width: 503px;">Incident type (added to the current incident types list)</td>
</tr>
<tr>
<td style="width: 211px;">resolution</td>
<td style="width: 503px;">Incident resolution</td>
</tr>
<tr>
<td style="width: 211px;">resolution-summary</td>
<td style="width: 503px;">Incident resolution summary</td>
</tr>
<tr>
<td style="width: 211px;">description</td>
<td style="width: 503px;">Incident description</td>
</tr>
<tr>
<td style="width: 211px;">name</td>
<td style="width: 503px;">Incident name</td>
</tr>
<tr>
<td style="width: 211px;">nist</td>
<td style="width: 503px;">NIST Attack Vectors (added to the current list of NIST attack vendors)</td>
</tr>
<tr>
<td style="width: 211px;">other-fields</td>
<td style="width: 503px;">A json object of the form: {field_name: new_field_value} currently we support the following field types<br /><img src="https://github.com/demisto/content/raw/3322c5933388f2ea9c52dc9fe31a5feb52bc1050/Packs/IBMResilientSystems/doc_files/support_field_types.png" /></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>Incident was updated successfully.</pre>
<hr>
<h3 id="h_822352343351528809805787">Get a list of incident members: rs-incident-get-members</h3>
<p>Get a list of members associated with the incident.</p>
<h5>Command Example</h5>
<p><code>!rs-incidents-get-members incident-id=2111</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">incident-id</td>
<td style="width: 503px;">
<p>Incident ID to get members of</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Id</td>
<td style="width: 503px;">Incident ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Members.FirstName</td>
<td style="width: 503px;">Member's first name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Members.LastName</td>
<td style="width: 503px;">Member's last name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Members.ID</td>
<td style="width: 503px;">Member's ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Members.Email</td>
<td style="width: 503px;">Member's email address</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>[  
   {  
     Email:user1@mail.com 
     FirstName:User1First 
     ID:4      
     LastName:User1Last
   },
   {  
      Email:demisto@demisto.com 
      FirstName:Demisto 
      ID:1
      LastName:Demisto
   }
]</pre>
<hr>
<h3 id="h_77974582581528810221337">Get incident information: rs-get-incident</h3>
<p>Get information for an incident.</p>
<h5>Command Example</h5>
<p><code>!rs-get-incident incident-id=2111</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">incident-id</td>
<td style="width: 503px;">
<p>Incident ID to get information for</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.CreateDate</td>
<td style="width: 503px;">Created date of the incident</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Name</td>
<td style="width: 503px;">Incident name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Resolution</td>
<td style="width: 503px;">Incident resolution</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.DiscoveredDate</td>
<td style="width: 503px;">Discovered date of the incident</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.ResolutionSummary</td>
<td style="width: 503px;">Incident resolution summary</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Id</td>
<td style="width: 503px;">Incident ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Phase</td>
<td style="width: 503px;">Incident phase</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Severity</td>
<td style="width: 503px;">Incident severity</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Description</td>
<td style="width: 503px;">Incident description</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Confirmed</td>
<td style="width: 503px;">Incident confirmation</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.NegativePr</td>
<td style="width: 503px;">Negative PR likellihood</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.DateOccurred</td>
<td style="width: 503px;">Date occurred of incident</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Reporter</td>
<td style="width: 503px;">Name of reporting individual</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.NistAttackVectors</td>
<td style="width: 503px;">Incident NIST attack vectors</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>{
    Confirmed:false
    CreatedDate:2018-05-22T23:47:25Z
    DateOccurred:2018-03-30T04:00:00Z
    Description:Desciprion
    DiscoveredDate:2018-05-01T04:00:00Z
    DueDate:2018-05-31T04:00:00Z
    ExposureType:Individual
    Id:2111
    Name:Incident name
    NegativePr:true
    NistAttackVectors:External/RemovableMedia
    Owner:Owner name
    Phase:Initial
    Reporter:Reporter name
    Resolution:Unresolved
    ResolutionSummary:summary
    Severity:Low
}</pre>
<hr>
<h3 id="h_672396217841528810416196">Update information for an incident member: rs-incidents-update-member</h3>
<p>Update information for a member associated with an incident.</p>
<h5>Command Example</h5>
<p><code>!rs-incidents-update-member incident-id=2111 members=1</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">incident-id</td>
<td style="width: 503px;">
<p>Incident ID to get information for</p>
</td>
</tr>
<tr>
<td style="width: 211px;">members</td>
<td style="width: 503px;">
<p>Members' IDs to set (comma separated)</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>Email:demisto@demisto.com
FirstName:Demisto
ID:1
LastName:Demisto</pre>
<hr>
<h3 id="h_2927197521131528810601114">Get a list of users: rs-get-users</h3>
<p>Returns a list of users in the IBM Resilient system.</p>
<h5>Command Example</h5>
<p><code>!rs-get-users</code></p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>[
  {
    Email:demistodev@demisto.com
    FirstName:Demisto
    ID:3
    LastName:Developer
  },
  {
    Email:demisto@demisto.com
    FirstName:Demisto
    ID:1
    LastName:Demisto
  }
]</pre>
<hr>
<h3 id="h_2792064041461528810768909">Close an incident: rs-close-incident</h3>
<p>Close an incident in the IBM Resilient system.</p>
<h5>Command Example</h5>
<p><code>!rs-close-incident incident-id=2111</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">incident-id</td>
<td style="width: 503px;">
<p>ID of the incident to close</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>Incident 2111 was closed.</pre>
<hr>
<h3 id="h_3906354711831528810903159">Create an incident: rs-create-incident</h3>
<p>Create an incident in the IBM Resilient system.</p>
<h5>Command Example</h5>
<p><code>!rs-create-incident name=IncidentName</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">name</td>
<td style="width: 503px;">
<p>Incident name</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>Incident  was created.</pre>
<hr>
<h3 id="h_9611617552241528811470715">Get artifacts for an incident: rs-incident-artifacts</h3>
<p>Return artifacts for an incident in the IBM Resilient system.</p>
<h5>Command Example</h5>
<p><code>!rs-incident-artifacts incident-id=2111</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">incident-id</td>
<td style="width: 503px;">
<p>Incident ID to get artifacts for</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Id</td>
<td style="width: 503px;">Incident ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Name</td>
<td style="width: 503px;">Incident name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.CreatedDate</td>
<td style="width: 503px;">Artifact created date</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.Creator</td>
<td style="width: 503px;">Artifact creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.Description</td>
<td style="width: 503px;">Artifact description</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.ID</td>
<td style="width: 503px;">Artifact ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.Type</td>
<td style="width: 503px;">Artifact type</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.Value</td>
<td style="width: 503px;">Artifact value</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.Attachments.ContentType</td>
<td style="width: 503px;">Attachment content type</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.Attachments.CreatedDate</td>
<td style="width: 503px;">Attachment created date</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.Attachments.Creator</td>
<td style="width: 503px;">Attachment creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.Attachments.ID</td>
<td style="width: 503px;">Attachment ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.Attachments.Name</td>
<td style="width: 503px;">Attachment name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Artifacts.Attachments.Size</td>
<td style="width: 503px;">Attachment size</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>{
  "Attachments":
    {
       "ContentType":"application/json",
       "CreatedDate":"2018-05-27T06:54:53Z",
       "Creator":"CreatorName",
       "ID":"4",
       "Name":"artifact.json",
       "Size":"3627"
    },
    {
       "CreatedDate":"2018-05-27T06:54:53Z",
       "Creator":"CreatorName",
       "ID":"5",
       "Type":"Email Attachment",
       "Value":"artifact.json"
    }
}</pre>
<hr>
<h3 id="h_1823709132691528812526569">Get attachments of an incident: rs-incident-attachments</h3>
<p>Return attachments for an incident in the IBM Resilient system.</p>
<h5>Command Example</h5>
<p><code>!rs-incident-attachments incident-id=2111</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">incident-id</td>
<td style="width: 503px;">
<p>Incident ID to get attachments for</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Id</td>
<td style="width: 503px;">Incident ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Name</td>
<td style="width: 503px;">Incident name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Owner</td>
<td style="width: 503px;">Incident owner</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Attachments.ContentType</td>
<td style="width: 503px;">Attachment content type</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Attachments.CreatedDate</td>
<td style="width: 503px;">Attachment created date</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Attachments.Creator</td>
<td style="width: 503px;">Attachment creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Attachments.ID</td>
<td style="width: 503px;">Attachment ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Attachments.Name</td>
<td style="width: 503px;">Attachment name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Attachments.Size</td>
<td style="width: 503px;">Attachment size</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>{
  "ContentType":"image/png",
  "CreatedDate":"2018-05-28T06:40:28Z",
  "Creator":"CreatorName",
  "ID":"7",
  "Name":"image.png",
  "Size":"4491"
}</pre>
<hr>
<h3 id="h_9184065563181528813233519">Get related incidents: rs-related-incidents</h3>
<p>Get incidents related to a specified incident in the IBM Resilient system.</p>
<h5>Command Example</h5>
<p><code>!rs-related-incidents incident-id=2111</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">incident-id</td>
<td style="width: 503px;">
<p>Incident ID to get related incidents for</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Id</td>
<td style="width: 503px;">Incident ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Related.CreatedDate</td>
<td style="width: 503px;">Created date of related incident</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Related.Name</td>
<td style="width: 503px;">Name of related incident</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Related.ID</td>
<td style="width: 503px;">ID of related incident</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Related.Status</td>
<td style="width: 503px;">Status (Active/Closed) of related incident</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Related.Artifacts.CreatedDate</td>
<td style="width: 503px;">Created date of artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Related.Artifacts.ID</td>
<td style="width: 503px;">ID of artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Related.Artifacts.Creator</td>
<td style="width: 503px;">Creator of artifact</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>[
{
"Artifacts":[
{
   "CreatedDate":"2018-05-27T06:26:37Z",
   "Creator":"v",
   "ID":3
},
{
   "CreatedDate":"2018-05-27T06:29:49Z",
   "Creator":"CreatorName",
   "Description":"atta",
   "ID":"4"
},
{
"CreatedDate":"2018-04-27T23:01:10Z",
"ID":2095,
"Name":"test Incident 1 - Email",
"Status":"Active"
}
]
]</pre>
<hr>
<h3 id="h_7077667663711528814261115">Get tasks for an incident: rs-incidents-get-tasks</h3>
<p>Get tasks for an incident in the IBM Resilient system.</p>
<h5>Command Example</h5>
<p><code>!rs-related-incidents incident-id=2111</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">incident-id</td>
<td style="width: 503px;">
<p>Incident ID to get tasks for</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Id</td>
<td style="width: 503px;">Incident ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Name</td>
<td style="width: 503px;">Incident name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Tasks.Category</td>
<td style="width: 503px;">Task category</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Tasks.Creator</td>
<td style="width: 503px;">Task creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Tasks.DueDate</td>
<td style="width: 503px;">Task due date</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Tasks.Form</td>
<td style="width: 503px;">Task form</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Tasks.ID</td>
<td style="width: 503px;">Task ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Tasks.Name</td>
<td style="width: 503px;">Task name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Tasks.Required</td>
<td style="width: 503px;">Task required</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.Incidents.Tasks.Status</td>
<td style="width: 503px;">Task status (Open/Closed)</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>[
{
"Category":"Initial"
"Creator":"CreatorName"
DueDate:2018-05-31T04:00:00Z
ID:2251303
Name:task
Required:true
Status:Open
},
{
Category:Respond
Creator:CreatorName
DueDate:2018-05-15T04:00:00Z
Form:data_compromised
ID:2251302
Instructions:It is critical to determine whether personal information was foreseeably compromised or exposed. If so, this will drive a series of activities based on a myriad of breach notification regulations. Perform the necessary research to determine whether any personal information was possibly exposed to unauthorized individuals and update the value of the Data Compromised field and the information on the Incident Breach Information tab above or on the Details tab on the incident.
Name:Investigate exposure of PI
Required:true
Status:Closed
}
]</pre></div></div></section>
<hr>
<h3 id="h_9184065563181528813233520">Add a note to an incident: rs-add-note</h3>
<p>Add a note to an incident</p>
<h5>Command Example</h5>
<p><code>!rs-add-note incident-id=2111 note="This is a note"</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">incident-id</td>
<td style="width: 503px;">
<p>Incident ID to add the note there</p>
</td>
</tr>
<tr>
<td style="width: 211px;">note</td>
<td style="width: 503px;">
<p>The text of the note</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 630px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.type</td>
<td style="width: 503px;"> The type of the note (incident or task)</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.id</td>
<td style="width: 503px;">The note's ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.parent_id</td>
<td style="width: 503px;">The ID of the parent note (null for top-level note)</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.user_id</td>
<td style="width: 503px;">The ID of the user who created the note</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.user_fname</td>
<td style="width: 503px;">The user's first name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.user_lname</td>
<td style="width: 503px;">The user's last name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.text</td>
<td style="width: 503px;">The note text</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.create_date</td>
<td style="width: 503px;">The date the note was created</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.modify_date</td>
<td style="width: 503px;">The date the note was modified</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.is_deleted</td>
<td style="width: 503px;">The flag indicating if the note is deleted</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.modify_user.id</td>
<td style="width: 503px;">The user that last modified the note</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.modify_user.first_name</td>
<td style="width: 503px;">The user's last name that last modified the note</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.modify_user.last_name</td>
<td style="width: 503px;">The user's first name that last modified the note</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.inc_id</td>
<td style="width: 503px;">The ID of the incident to which this note belongs</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.inc_name</td>
<td style="width: 503px;">The name of the incident to which this note belongs</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.task_id</td>
<td style="width: 503px;">The ID of the task to which this note belongs. Will be null on incident notes</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.task_name</td>
<td style="width: 503px;">The name of the task to which this note belongs. Will be null on incident notes</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.task_custom</td>
<td style="width: 503px;">For task note, whether or not that task is custom. Null for incident notes</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.task_members</td>
<td style="width: 503px;">For task notes, the list of that task's members, if any. Null for incident notes</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.task_at_id</td>
<td style="width: 503px;">For task notes, whether or not that task is an automatic task</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.inc_owner</td>
<td style="width: 503px;">The owner of the incident to which this note belongs</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.user_name</td>
<td style="width: 503px;">The owner of the incident to which this note belongs</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.modify_principal.id</td>
<td style="width: 503px;">The ID of the principal</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.modify_principal.type</td>
<td style="width: 503px;">The type of the principal Currently only user or group</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.modify_principal.name</td>
<td style="width: 503px;">The name of the principal</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.modify_principal.display_name</td>
<td style="width: 503px;">The display name of the principal</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.comment_perms.update</td>
<td style="width: 503px;">The permission of the current user to update this note</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentNote.comment_perms.delete</td>
<td style="width: 503px;">The permission of the current user to delete this note</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>The note was added successfully to incident 2111.</pre>
<hr>
<h3 id="h_7077667663711528814261121">Add an artifact to an incident: rs-add-artifact</h3>
<p>Add an artifact to an incident.</p>
<h5>Command Example</h5>
<p><code>!rs-add-artifact incident-id=2111 artifact-type="IP Address" artifact-value="1.1.1.1" artifact-description"Description of the artifact"</code></p>
<h5>Input</h5>
<table style="height: 287px; width: 737px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 211px;"><strong>&nbsp;Parameter</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 211px;">incident-id</td>
<td style="width: 503px;">
<p>Incident ID to add the artifact there</p>
</td>
</tr>
<tr>
<td style="width: 211px;">artifact-type</td>
<td style="width: 503px;">
<p>The type of the artifact</p>
</td>
</tr>
<tr>
<td style="width: 211px;">artifact-value</td>
<td style="width: 503px;">
<p>The value of the artifact</p>
</td>
</tr>
<tr>
<td style="width: 211px;">artifact-description</td>
<td style="width: 503px;">
<p>The description of the artifact</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 630px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.id</td>
<td style="width: 503px;">The id of the artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.type</td>
<td style="width: 503px;">The type of the artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.value</td>
<td style="width: 503px;">The value of the artifact, this would be for example the IP address for an IP address artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.description</td>
<td style="width: 503px;">The description of the artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.attachment</td>
<td style="width: 503px;">The files are attached to the artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.parent_id</td>
<td style="width: 503px;">The parent artifact ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.id</td>
<td style="width: 503px;">The ID of the artifact creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.fname</td>
<td style="width: 503px;">The first name of the artifact creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.lname</td>
<td style="width: 503px;">The last name of the artifact creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.display_name</td>
<td style="width: 503px;">The display name of the artifact creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.status</td>
<td style="width: 503px;">The status of the artifact creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.email</td>
<td style="width: 503px;">The email of the artifact creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.phone</td>
<td style="width: 503px;">The phone number of the artifact creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.cell</td>
<td style="width: 503px;">The cellphone number of the artifact creator</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.title</td>
<td style="width: 503px;">The user's job title (e.g. Incident Response Manager)</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.locked</td>
<td style="width: 503px;">The status of the creator's acount (true if locked false otherwise)</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.password_changed</td>
<td style="width: 503px;">The user's password has changed (true if changed false otherwise)</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.is_external</td>
<td style="width: 503px;">The user's account is authenticated externally</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator.ui_theme</td>
<td style="width: 503px;">The UI theme the user has selected. The Resilient UI recognizes the following values (darkmode lightmode verydarkmode)</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.inc_id</td>
<td style="width: 503px;">The incident ID</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.inc_name</td>
<td style="width: 503px;">The incident name</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.inc_owner</td>
<td style="width: 503px;">The incident owner</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.created</td>
<td style="width: 503px;">The date when the artifact is created</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.last_modified_time</td>
<td style="width: 503px;">The last date on which the artifact changed</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.last_modified_by.id</td>
<td style="width: 503px;">The ID of the last who changed the artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.last_modified_by.type</td>
<td style="width: 503px;">The type of the last who changed the artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.last_modified_by.name</td>
<td style="width: 503px;">The name of the last who changed the artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.last_modified_by.display_name</td>
<td style="width: 503px;">The display name of the last who changed the artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.perms.read</td>
<td style="width: 503px;">The permission of the current user to read this artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.perms.write</td>
<td style="width: 503px;">The permission of the current user to write this artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.perms.delete</td>
<td style="width: 503px;">The permission of the current user to delete this artifact</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.properties</td>
<td style="width: 503px;">The additional artifact properties</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.hash</td>
<td style="width: 503px;">The hash of the incident</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.relating</td>
<td style="width: 503px;">Whether or not this artifact should be used for relating to other incidents</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator_principal.id</td>
<td style="width: 503px;">The ID of the principal</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator_principal.type</td>
<td style="width: 503px;">The type of the principal. Currently only user or group</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator_principal.name</td>
<td style="width: 503px;">The API name of the principal</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.creator_principal.display_name</td>
<td style="width: 503px;">The display name of the principal</td>
</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.ip.source</td>
<td style="width: 503px;">The IP address is a source</tr>
<tr>
<td style="width: 210px;">Resilient.incidentArtifact.ip.destination</td>
<td style="width: 503px;">The IP address is a destination</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Raw Output</h5>
<pre>The artifact was added successfully to incident 2111.</pre>
