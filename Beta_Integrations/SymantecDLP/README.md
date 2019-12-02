<p>
Symantec Data Loss Prevention let's you discover, monitor and protect your sensitive corporate information.
</p>
</ul><h2>Detailed Description</h2>
<p>Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.</p>
<h2>Fetch Incidents</h2>
<p>The Symantec Data Loss Prevention integration is configured to fetch incidents and integrate them into Demisto's incidents and has the fetch limit parameter.</p>
<h2>Configure Symantec Data Loss Prevention on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Symantec Data Loss Prevention.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Enforce Server (e.g. https://192.168.0.1)</strong></li>
   <li><strong>Username</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Use system proxy settings</strong></li>
   <li><strong>Fetch incidents</strong></li>
   <li><strong>Incident type</strong></li>
   <li><strong>First fetch timestamp (<number><time unit>e.g., 12 hours, 7 days)</strong></li>
   <li><strong>Saved Report ID</strong></li>
   <li><strong>Fetch limit</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<p>In order that the integration will work you must create a Web Service user, role and saved report in the Enforce Server administration. </p>
<p> To create an user and role do the following:</p>
<ol>
<li>
Log on to the Enforce Server administration console with Administator access mode.
</li>
<li>
Go to System > Login Management > Roles > Add Role
</li>
<li>
Enter a name for the new role in the Name field.
</li>
<li>
In the User Privileges section, select the privileges you want.
</li>
<li>
Click on the Save button.
</li>
<li>
Go to System > Login Management > DLP Users
</li>
<li>
Click on the Add User button and create a user.
</li>
<li>
Go to the Roles section, select the new role being created.
</li>
<li> Select the same role in the Default Role menu.
</li>
<li>
Click on the Save button.
</li>
</ol>
<p>To create a saved report do the following:</p>
<ol>
<li>Log on to the Enforce Server administration console.</li>
<li>Go to Incidents > Incident Reports</li>
<li>Select an incident from the list of reports.</li>
<li>Click Advanced Filters & Summarization.</li>
<li>In the Summarize By menu, verify that no primary summary selected and no
secondary summary selected are chosen.</li>
<li>Select > Report > Save, and enter the report name in the Name field</li>
<li>Click Save</li>
<li>To retrive the ID of the saved report, move your mouse cursor over the report name.</li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>symantec-dlp-list-incidents: symantec-dlp-list-incidents</li>
  <li>symantec-dlp-get-incident-details: symantec-dlp-get-incident-details</li>
  <li>symantec-dlp-update-incident: symantec-dlp-update-incident</li>
  <li>symantec-dlp-incident-binaries: symantec-dlp-incident-binaries</li>
  <li>symantec-dlp-list-custom-attributes: symantec-dlp-list-custom-attributes</li>
  <li>symantec-dlp-list-incident-status: symantec-dlp-list-incident-status</li>
  <li>symantec-dlp-incident-violations: symantec-dlp-incident-violations</li>
</ol>
<h3>1. symantec-dlp-list-incidents</h3>
<hr>
<p>Returns a list of incidents.</p>
<h5>Base Command</h5>
<p>
  <code>symantec-dlp-list-incidents</code>
</p>

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
      <td>creation_date</td>
      <td>Get incidents with creation date later than specified. Given in free text (e.g. '2 days')</td>
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
      <td>SymantecDLP.Incident.ID</td>
      <td>Number</td>
      <td>The ID of the Incident</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!symantec-dlp-list-incidents</code>
</p>

<h5>Context Example</h5>
<pre>
    [
        "SymantecDLP.Incident.ID": [
            1111,
            2222,
            3333
        ]
    ]
</pre>
<h5>Human Readable Output</h5>
<h3>Symantec DLP incidents</h3>
<table style="width:100px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 1111 </td>
    </tr>
    <tr>
      <td> 2222 </td>
    </tr>
    <tr>
      <td> 3333 </td>
    </tr>
  </tbody>
</table>
<p>
<h3>Additional Information</h3>
<p></p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>2. symantec-dlp-get-incident-details</h3>
<hr>
<p>Returns the details of the specified incident.</p>
<h5>Base Command</h5>
<p>
  <code>symantec-dlp-get-incident-details</code>
</p>

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
      <td>incident_id</td>
      <td>Incident ID to get details of.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>custom_attributes</td>
      <td>This argument can get the following values:
all - If all custom attributes are needed
none - If none of the custom attributes are needed
specific attributes - A list of custom attributes names, seperated by comma. For example: ca1,ca2,ca3
custom attribute group name - A list of custom attributes group names, seperated by comma. For example: cag1, cag2, cag3. This value will retrive all custom attributes in the mentioned group.
The value "none" is default.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>custom_data</td>
      <td>A list of custom attributes names / custom attribute group names. List should be comma seperated. For example: item1,item2,item3</td>
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
      <td>SymantecDLP.Incident.ID</td>
      <td>Number</td>
      <td>The ID of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.LongID</td>
      <td>Number</td>
      <td>The long ID of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.StatusCode</td>
      <td>String</td>
      <td>The status code of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.CreationDate</td>
      <td>Date</td>
      <td>The creation date of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.DetectionDate</td>
      <td>Date</td>
      <td>The detection date of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.Severity</td>
      <td>String</td>
      <td>The severity of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.MessageSource</td>
      <td>String</td>
      <td>The localized label that corresponds to the Symantec DLP product that generated the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.MessageSourceType</td>
      <td>String</td>
      <td>Indicates the Symantec DLP product that generated the incident. Can be: NETWORK, DISCOVER, ENDPOINT, DIM, DAR.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.MessageType</td>
      <td>String</td>
      <td>Indicates the Symantec DLP product component that generated the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.MessageTypeID</td>
      <td>Number</td>
      <td>The ID of the Message Type.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.Policy.Name</td>
      <td>String</td>
      <td>The name of the policy.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.Policy.Version</td>
      <td>String</td>
      <td>The version of the policy.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.Policy.Label</td>
      <td>String</td>
      <td>The label of the policy.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.Policy.ID</td>
      <td>Number</td>
      <td>The ID of the policy.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.BlockedStatus</td>
      <td>String</td>
      <td>Indicates whether the message was blocked or not.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.MatchCount</td>
      <td>Number</td>
      <td>Indicates the number of detection rule matches in the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.RuleViolationCount</td>
      <td>Number</td>
      <td>Indicates the number of policy rules that were violated.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.DetectionServer</td>
      <td>String</td>
      <td>The name of the detection server that created the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.DataOwner.Name</td>
      <td>String</td>
      <td>The name of the data owner.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.DataOwner.Email</td>
      <td>String</td>
      <td>The email of the data owner.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.EventDate</td>
      <td>Date</td>
      <td>The date and time at which the violation event occurred.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatedPolicyRule.Name</td>
      <td>String</td>
      <td>The name of the rule within the policy that the message violated.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatedPolicyRule.ID</td>
      <td>Number</td>
      <td>The ID of the rule within the policy that the message violated.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.OtherViolatedPolicy.Name</td>
      <td>String</td>
      <td>The name of any additional policies that the message violated.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.OtherViolatedPolicy.Version</td>
      <td>String</td>
      <td>The version of any additional policies that the message violated.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.OtherViolatedPolicy.Label</td>
      <td>String</td>
      <td>The label of any additional policies that the message violated.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.OtherViolatedPolicy.ID</td>
      <td>Number</td>
      <td>The ID of any additional policies that the message violated.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.CustomAttribute.Name</td>
      <td>String</td>
      <td>The custom attribute name.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.CustomAttribute.Value</td>
      <td>String</td>
      <td>The custom attribute value.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!symantec-dlp-get-incident-details incident_id=2222 custom_attributes="specific attributes</code>" custom_data=ca1,ca2,ca3
</p>

<h5>Context Example</h5>
<pre>
"SymantecDLP.Incident: {
    'ID': 2222,
    'LongID': 2222,
    'StatusCode': 'SUCCESS',
    'CreationDate': '2018-08-01T11:50:16',
    'DetectionDate': '2018-08-01T11:50:16',
    'Severity': 'high',
    'MessageSource': 'Endpoint',
    'MessageSourceType': 'ENDPOINT',
    'MessageType': 'Endpoint Copy to Network Share',
    'MessageTypeID': 33,
    'Policy.Name': 'CCN number',
    'Policy.Version': 1,
    'Policy.Label': 'label',
    'Policy.ID': '2203',
    'ViolatedPolicyRule': [
        'Name': CCN number,
        'ID': '334'
    ],
    'OtherViolatedPolicy': [
        'Name': 'CREDIT CARD POLICY TEST',
        'Version': 13,
        'Label': 'label12'
        'ID': '2134'
    ],
    'BlockedStatus': 'Passed',
    'MatchCount': 1,
    'RuleViolationCount': 1,
    'DetectionServer': 'Local - Endpoint',
    'DataOwner': {
        'Name': 'name',
        'Email': 'email',
    },
    'EventDate': '2018-08-01T11:50:16',
    'CustomAttribute': [
        {
            'Name': 'ca1'
            'Value': 'val1'
        },
        {
            'Name': 'ca2'
            'Value': 'val2'
        },
        {
            'Name': 'ca3'
            'Value': 'val3'
        },
    ]
}
</pre>

<h5>Human Readable Output</h5>
<h3>Symantec DLP incident 2222 details</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Creation Date</strong></th>
      <th><strong>Detection Date</strong></th>
      <th><strong>Severity</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>DLP Module</strong></th>
      <th>DLP Module subtype</th>
      <th>Policy Name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 2222 </td>
      <td> 2018-08-01T11:50:16 </td>
      <td> 2018-08-01T11:50:16 </td>
      <td> high </td>
      <td> SUCCESS </td>
      <td> ENDPOINT </td>
      <td> Endpoint Copy to Network Share </td>
      <td> CCN number </td>
    </tr>
  </tbody>
</table>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>3. symantec-dlp-update-incident</h3>
<hr>
<p>Updates the details of a specific incident.</p>
<h5>Base Command</h5>
<p>
  <code>symantec-dlp-update-incident</code>
</p>


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
      <td>incident_id</td>
      <td>Incident ID to update.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>severity</td>
      <td>Represents the severity level of the incident.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>status</td>
      <td>Represents the status value of the incident.
You define incident status values using the
Enforce Server administration console.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>remediation_status</td>
      <td>Represents the remediation status of an
incident.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>remediation_location</td>
      <td>Represents the remediation location of the
incident. Values can be user-defined.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>custom_attribute_name</td>
      <td>The custom attribute name.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>custom_attribute_value</td>
      <td>The custom attribute value.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>data_owner_name</td>
      <td>The data owner name.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>data_owner_email</td>
      <td>The data owner email.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>note</td>
      <td>The note to be added.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>note_time</td>
      <td>The time of the note in ISO format.</td>
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
  <code>!symantec-dlp-update-incident incident_id=2222 data_owner_email=EMAIL data_owner_name=NAME note=NOTE note_time=2018-08-01T11:50:16</code>
</p>

<h5>Human Readable Output</h5>
<h3>Symantec DLP incident 2222 details</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Batch ID</strong></th>
      <th><strong>Inaccessible Incident Long ID</strong></th>
      <th><strong>Inaccessible Incident ID</strong></th>
      <th><strong>Status Code</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 44102 </td>
      <td> [] </td>
      <td> [] </td>
      <td> SUCCESS </td>
    </tr>
  </tbody>
</table>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>4. symantec-dlp-incident-binaries</h3>
<hr>
<p>Retrieves additional components of the message that generated the
incident, might include binary files.</p>
<h5>Base Command</h5>
<p>
  <code>symantec-dlp-incident-binaries</code>
</p>

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
      <td>incident_id</td>
      <td>Incident ID to get binaries of.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>include_original_message</td>
      <td>Indicates whether the Web Service should include the original message in the response document or not.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>include_all_components</td>
      <td>Indicates whether the Web Service should include all message components (for example, headers and file attachments) in the response document or not.</td>
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
      <td>SymantecDLP.Incident.ID</td>
      <td>Number</td>
      <td>The ID of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.LongID</td>
      <td>Number</td>
      <td>The long ID of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.OriginalMessage</td>
      <td>String</td>
      <td>The original message of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Component.ID</td>
      <td>Number</td>
      <td>The ID of the component</td>
    </tr>
    <tr>
      <td>SymantecDLP.Component.Name</td>
      <td>String</td>
      <td>The name of the component.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Component.TypeID</td>
      <td>Number</td>
      <td>The ID of the type of the component.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Component.Type</td>
      <td>String</td>
      <td>The type of the component</td>
    </tr>
    <tr>
      <td>SymantecDLP.Component.Content</td>
      <td>String</td>
      <td>The content of the component</td>
    </tr>
    <tr>
      <td>SymantecDLP.Component.LongID</td>
      <td>Number</td>
      <td>The long ID of the component.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!symantec-dlp-incident-binaries incident_id=2222</code>
</p>
<h5>Context Example</h5>
<pre>
"SymantecDLP.Incident": {
    'ID': 2222,
    'OriginalMessage': 'msg',
    'Component': [
        'ID': 69065,
        'Name': 'CCN.txt',
        'TypeID': 'ATTACHMENT_TEXT',
        'Content': '4386280016300125',
        'LongID': 69065 
    ],
    'LongID': 2222
}
</pre>

<h5>Human Readable Output</h5>
<h3>Symantec DLP incident 2222 binaries</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Original Message</strong></th>
      <th><strong>Long ID</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 2222 </td>
      <td> msg </td>
      <td> 2222 </td>
    </tr>
  </tbody>
</table>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>5. symantec-dlp-list-custom-attributes</h3>
<hr>
<p>Returns a list of all custom attribute names defined in
the Symantec DLP deployment.</p>
<h5>Base Command</h5>
<p>
  <code>symantec-dlp-list-custom-attributes</code>
</p>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!symantec-dlp-list-custom-attributes</code>
</p>

<h5>Human Readable Output</h5>
<h3>Symantec DLP custom attributes</h3>
<table style="width:100px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Custom Attribute</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> ca1 </td>
    </tr>
    <tr>
      <td> ca2 </td>
    </tr>
    <tr>
      <td> ca3 </td>
    </tr>
  </tbody>
</table>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>6. symantec-dlp-list-incident-status</h3>
<hr>
<p>Returns a list of the custom status values defined in the
Symantec DLP deployment.</p>
<h5>Base Command</h5>
<p>
  <code>symantec-dlp-list-incident-status</code>
</p>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!symantec-dlp-list-incident-status</code>
</p>

<h5>Human Readable Output</h5>
<h3>Symantec DLP incident status</h3>
<table style="width:100px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Incident Status</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> status1 </td>
    </tr>
    <tr>
      <td> status2 </td>
    </tr>
    <tr>
      <td> status3 </td>
    </tr>
  </tbody>
</table>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>7. symantec-dlp-incident-violations</h3>
<hr>
<p>Returns the highlighted matches of a specific incident.</p>
<h5>Base Command</h5>
<p>
  <code>symantec-dlp-incident-violations</code>
</p>


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
      <td>incident_id</td>
      <td>The ID of the incident.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>include_image_violations</td>
      <td>Indicates whether image violations should be included in the Incident Violations Response.</td>
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
      <td>SymantecDLP.Incident.ID</td>
      <td>Number</td>
      <td>The ID of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.LongID</td>
      <td>Number</td>
      <td>The long ID of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.StatusCode</td>
      <td>String</td>
      <td>The status code of the incident.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatingComponent.Name</td>
      <td>String</td>
      <td>The name of the violationg component.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatingComponent.DocumentFormat</td>
      <td>String</td>
      <td>The document format of the violationg component.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatingComponent.Type</td>
      <td>String</td>
      <td>The type of the violationg component.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatingComponent.TypeID</td>
      <td>Number</td>
      <td>The type ID of the violationg component.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatingComponent.ViolatingCount</td>
      <td>Number</td>
      <td>Indicates the number of policy rules that were violated.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatingComponent.ViolatingSegment.DocumentViolation</td>
      <td>String</td>
      <td>Details about the document violation.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatingComponent.ViolatingSegment.FileSizeViolation</td>
      <td>Number</td>
      <td>Details about the file size violation.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatingComponent.ViolatingSegment.Text.Data</td>
      <td>String</td>
      <td>The data that triggered the violation.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatingComponent.ViolatingSegment.Text.Type</td>
      <td>String</td>
      <td>The type of data that triggered the violation.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatingComponent.ViolatingSegment.Text.RuleID</td>
      <td>Number</td>
      <td>The rule ID which triggered the violation.</td>
    </tr>
    <tr>
      <td>SymantecDLP.Incident.ViolatingComponent.ViolatingSegment.Text.RuleName</td>
      <td>String</td>
      <td>The rule name which triggered the violation.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!symantec-dlp-incident-violations incident_id=35364</code>
</p>

<h5>Context Example</h5>
<pre>
"SymantecDLP.Incident": {
    'ID': 35364,
    'LongID': 35364,
    'StatusCode': 'SUCCESS',
    'ViolatingComponent': [
        {
            'Name': 'C:\\Users\\Administrator\\Desktop\\CCN.txt',
            'DocumentFormat': 'ascii',
            'Type': 'Attachment',
            'TypeID' 3,
            'ViolatingCount': 1,
            'ViolatingSegment': [
                {
                    'DocumentViolation': None,
                    'FileSizeViolation': None,
                    'Text': [
                        {
                            'Data': '4386280016300125',
                            'Type': 'Violation',
                            'RuleID': 12288,
                            'RuleName': 'CCN'
                        }
                    ]
                }
            ]
        }
    ]
}
</pre>

<h5>Human Readable Output</h5>
<h3>Symantec DLP incident status</h3>
<table style="width:100px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 35364 </td>
    </tr>
  </tbody>
</table>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h2>Troubleshooting</h2>
<p>When running the command "symantec-get-incident-details' there might be situation you are getting the following error message:</p>
<img alt="" src="https://user-images.githubusercontent.com/53565845/69337251-19aba480-0c69-11ea-94e6-90a3b6778a91.png"/>
<br>
<br>
<p>If it does happen, please check your Symantec DLP system is configured properly.</p>
