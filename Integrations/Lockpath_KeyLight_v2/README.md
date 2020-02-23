<p>
Use the LockPath KeyLight integration to manage GRC tickets in the Keylight platform.

This integration was integrated and tested with version 5.3.035 of Lockpath KeyLight v2
</p>
<h2>Use Cases</h2>
<ul>
<li> Manage your Keylight tickets. </li>
</ul><h2>Detailed Description</h2>
<ul>
<li> Use LockPath KeyLight to manage tickets.</li>
</ul><h2>Fetch Incidents</h2>
<li>`Fetch incidents` option fetches all records from a certain component.</li>
<li> The fetch applies the "Greater Than" filter on the specified field in order to fetch only the latest records.</li>
<li> It's suggested to specify a date field for the fetch.</li>
<h2>Configure Lockpath KeyLight v2 on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Lockpath KeyLight v2.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Server URL in the form of https://[server]:<port> (e.g. https://192.168.0.1:4443)</strong></li>
   <li><strong>Credentials</strong></li>
   <li><strong>Incident type</strong></li>
   <li><strong>Name of component to fetch from</strong></li>
   <li><strong>Name of field to fetch by</strong></li>
   <li><strong>Fetch Limit</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Use system proxy settings</strong></li>
   <li><strong>Fetch incidents</strong></li>
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
  <li>kl-get-component: kl-get-component</li>
  <li>kl-get-field-list: kl-get-field-list</li>
  <li>kl-get-field: kl-get-field</li>
  <li>kl-get-record: kl-get-record</li>
  <li>kl-get-records: kl-get-records</li>
  <li>kl-get-record-count: kl-get-record-count</li>
  <li>kl-get-record-attachments: kl-get-record-attachments</li>
  <li>kl-get-record-attachment: kl-get-record-attachment</li>
  <li>kl-delete-record: kl-delete-record</li>
  <li>kl-delete-record-attachment: kl-delete-record-attachment</li>
  <li>kl-get-lookup-report-column-fields: kl-get-lookup-report-column-fields</li>
  <li>kl-create-record: kl-create-record</li>
  <li>kl-update-record: kl-update-record</li>
</ol>
<h3>1. kl-get-component</h3>
<hr>
<p>Retrieves a component specified by ID or alias. If no parameters are specified, all components will be retrieved.</p>
<h5>Base Command</h5>
<p>
  <code>kl-get-component</code>
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
      <td>component_id</td>
      <td>The id of the component.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>alias</td>
      <td>The alias of the component.</td>
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
      <td>Keylight.Component.ID</td>
      <td>String</td>
      <td>The ID of the component.</td>
    </tr>
    <tr>
      <td>Keylight.Component.Name</td>
      <td>String</td>
      <td>The name of the component.</td>
    </tr>
    <tr>
      <td>Keylight.Component.ShortName</td>
      <td>String</td>
      <td>The short name of the component.</td>
    </tr>
    <tr>
      <td>Keylight.Component.SystemName</td>
      <td>String</td>
      <td>The system name of the component.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!kl-get-component alias="_auditdemisto"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Keylight.Component": {
        "ID": 10359,
        "Name": "Audit Tasks (Demisto Test)",
        "ShortName": "_auditdemisto",
        "SystemName": "_auditdemisto"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Keylight Components</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>ShortName</strong></th>
      <th><strong>SystemName</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 10359 </td>
      <td> Audit Tasks (Demisto Test) </td>
      <td> _auditdemisto </td>
      <td> _auditdemisto </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>2. kl-get-field-list</h3>
<hr>
<p>Retrieves a detail field listing for a component specified by ID.</p>
<h5>Base Command</h5> 
<p>
  <code>kl-get-field-list</code>
</p>


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
      <td>component_id</td>
      <td>The id of the component.</td>
      <td>Required</td>
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
      <td>Keylight.Field.ID</td>
      <td>String</td>
      <td>The ID of the field.</td>
    </tr>
    <tr>
      <td>Keylight.Field.Name</td>
      <td>String</td>
      <td>The field's name.</td>
    </tr>
    <tr>
      <td>Keylight.Field.SystemName</td>
      <td>String</td>
      <td>The system name of the field.</td>
    </tr>
    <tr>
      <td>Keylight.Field.ShortName</td>
      <td>String</td>
      <td>The short name of the field.</td>
    </tr>
    <tr>
      <td>Keylight.Field.ReadOnly</td>
      <td>Boolean</td>
      <td>Is the field read only.</td>
    </tr>
    <tr>
      <td>Keylight.Field.Required</td>
      <td>Boolean</td>
      <td>Is the field required.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!kl-get-field-list component_id="10359"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Keylight.Field": [
        {
            "FieldType": 5,
            "ID": 8998,
            "MatrixRows": [],
            "Name": "Assignee",
            "OneToMany": false,
            "ReadOnly": false,
            "Required": true,
            "ShortName": "_assignee",
            "SystemName": "_assignee"
        },
        {
            "FieldType": 8,
            "ID": 9071,
            "MatrixRows": [],
            "Name": "Attachment",
            "OneToMany": true,
            "ReadOnly": false,
            "Required": false,
            "ShortName": "_attachment",
            "SystemName": "_attachment"
        },
        {
            "FieldType": 5,
            "ID": 8997,
            "MatrixRows": [],
            "Name": "Audit Project",
            "OneToMany": false,
            "ReadOnly": false,
            "Required": true,
            "ShortName": "_auditprojecttest",
            "SystemName": "_auditprojecttest"
        },
        {
            "FieldType": 5,
            "ID": 9003,
            "MatrixRows": [],
            "Name": "Authority Doc Citations",
            "OneToMany": false,
            "ReadOnly": false,
            "Required": true,
            "ShortName": "_authdoccitationtest",
            "SystemName": "_authdoccitationtest"
        },
        {
            "FieldType": 1,
            "ID": 9013,
            "MatrixRows": [],
            "Name": "Comments",
            "OneToMany": false,
            "ReadOnly": false,
            "Required": false,
            "ShortName": "_commentstest",
            "SystemName": "_commentstest"
        },
        {
            "FieldType": 3,
            "ID": 8949,
            "MatrixRows": [],
            "Name": "Created At",
            "OneToMany": false,
            "ReadOnly": true,
            "Required": false,
            "ShortName": "CreatedAt",
            "SystemName": "CreatedAt"
        },
        {
            "FieldType": 5,
            "ID": 8950,
            "MatrixRows": [],
            "Name": "Created By",
            "OneToMany": false,
            "ReadOnly": true,
            "Required": false,
            "ShortName": "CreatedBy",
            "SystemName": "CreatedBy"
        },
        {
            "FieldType": 2,
            "ID": 8948,
            "MatrixRows": [],
            "Name": "Current Revision",
            "OneToMany": false,
            "ReadOnly": true,
            "Required": false,
            "ShortName": "Version",
            "SystemName": "Version"
        },
        {
            "FieldType": 2,
            "ID": 8999,
            "MatrixRows": [],
            "Name": "Current Revision",
            "OneToMany": false,
            "ReadOnly": true,
            "Required": false,
            "ShortName": "_auditprojecttest_Version",
            "SystemName": "_auditprojecttest_Version"
        },
        {
            "FieldType": 2,
            "ID": 9004,
            "MatrixRows": [],
            "Name": "Current Revision",
            "OneToMany": false,
            "ReadOnly": true,
            "Required": false,
            "ShortName": "_authdoccitationtest_Version",
            "SystemName": "_authdoccitationtest_Version"
        },
        {
            "FieldType": 10,
            "ID": 8956,
            "MatrixRows": [],
            "Name": "Deleted",
            "OneToMany": false,
            "ReadOnly": true,
            "Required": false,
            "ShortName": "Deleted",
            "SystemName": "Deleted"
        },
        {
            "FieldType": 1,
            "ID": 9082,
            "MatrixRows": [],
            "Name": "Description",
            "OneToMany": false,
            "ReadOnly": false,
            "Required": true,
            "ShortName": "_taskdesc",
            "SystemName": "_taskdesc"
        },
        {
            "FieldType": 8,
            "ID": 9084,
            "MatrixRows": [],
            "Name": "Document Attachment",
            "OneToMany": true,
            "ReadOnly": false,
            "Required": false,
            "ShortName": "_Document",
            "SystemName": "_Document"
        },
        {
            "FieldType": 3,
            "ID": 9002,
            "MatrixRows": [],
            "Name": "Due Date",
            "OneToMany": false,
            "ReadOnly": false,
            "Required": true,
            "ShortName": "_duedatetest",
            "SystemName": "_duedatetest"
        },
        {
            "FieldType": 8,
            "ID": 9006,
            "MatrixRows": [],
            "Name": "Evidence",
            "OneToMany": true,
            "ReadOnly": false,
            "Required": false,
            "ShortName": "_evidencetest",
            "SystemName": "_evidencetest"
        },
        {
            "FieldType": 2,
            "ID": 8947,
            "MatrixRows": [],
            "Name": "Id",
            "OneToMany": false,
            "ReadOnly": true,
            "Required": false,
            "ShortName": "Id",
            "SystemName": "Id"
        },
        {
            "FieldType": 2,
            "ID": 8959,
            "MatrixRows": [],
            "Name": "Published Revision",
            "OneToMany": false,
            "ReadOnly": true,
            "Required": false,
            "ShortName": "PublishedVersion",
            "SystemName": "PublishedVersion"
        },
        {
            "FieldType": 1,
            "ID": 9083,
            "MatrixRows": [],
            "MaxLength": 100,
            "Name": "Task ID",
            "OneToMany": false,
            "ReadOnly": false,
            "Required": true,
            "ShortName": "_taskid",
            "SystemName": "_taskid"
        },
        {
            "FieldType": 3,
            "ID": 8952,
            "MatrixRows": [],
            "Name": "Updated At",
            "OneToMany": false,
            "ReadOnly": true,
            "Required": false,
            "ShortName": "UpdatedAt",
            "SystemName": "UpdatedAt"
        },
        {
            "FieldType": 5,
            "ID": 8953,
            "MatrixRows": [],
            "Name": "Updated By",
            "OneToMany": false,
            "ReadOnly": true,
            "Required": false,
            "ShortName": "UpdatedBy",
            "SystemName": "UpdatedBy"
        },
        {
            "FieldType": 1,
            "ID": 9012,
            "MatrixRows": [],
            "MaxLength": 100,
            "Name": "Work Log",
            "OneToMany": false,
            "ReadOnly": false,
            "Required": false,
            "ShortName": "_worktime",
            "SystemName": "_worktime"
        },
        {
            "FieldType": 5,
            "ID": 8957,
            "MatrixRows": [],
            "Name": "Workflow Stage",
            "OneToMany": false,
            "ReadOnly": true,
            "Required": false,
            "ShortName": "WorkflowStage",
            "SystemName": "WorkflowStage"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Keylight fields for component 10359:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>SystemName</strong></th>
      <th><strong>ShortName</strong></th>
      <th><strong>ReadOnly</strong></th>
      <th><strong>Required</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 8998 </td>
      <td> Assignee </td>
      <td> _assignee </td>
      <td> _assignee </td>
      <td> false </td>
      <td> true </td>
    </tr>
    <tr>
      <td> 9071 </td>
      <td> Attachment </td>
      <td> _attachment </td>
      <td> _attachment </td>
      <td> false </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 8997 </td>
      <td> Audit Project </td>
      <td> _auditprojecttest </td>
      <td> _auditprojecttest </td>
      <td> false </td>
      <td> true </td>
    </tr>
    <tr>
      <td> 9003 </td>
      <td> Authority Doc Citations </td>
      <td> _authdoccitationtest </td>
      <td> _authdoccitationtest </td>
      <td> false </td>
      <td> true </td>
    </tr>
    <tr>
      <td> 9013 </td>
      <td> Comments </td>
      <td> _commentstest </td>
      <td> _commentstest </td>
      <td> false </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 8949 </td>
      <td> Created At </td>
      <td> CreatedAt </td>
      <td> CreatedAt </td>
      <td> true </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 8950 </td>
      <td> Created By </td>
      <td> CreatedBy </td>
      <td> CreatedBy </td>
      <td> true </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 8948 </td>
      <td> Current Revision </td>
      <td> Version </td>
      <td> Version </td>
      <td> true </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 8999 </td>
      <td> Current Revision </td>
      <td> _auditprojecttest_Version </td>
      <td> _auditprojecttest_Version </td>
      <td> true </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 9004 </td>
      <td> Current Revision </td>
      <td> _authdoccitationtest_Version </td>
      <td> _authdoccitationtest_Version </td>
      <td> true </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 8956 </td>
      <td> Deleted </td>
      <td> Deleted </td>
      <td> Deleted </td>
      <td> true </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 9082 </td>
      <td> Description </td>
      <td> _taskdesc </td>
      <td> _taskdesc </td>
      <td> false </td>
      <td> true </td>
    </tr>
    <tr>
      <td> 9084 </td>
      <td> Document Attachment </td>
      <td> _Document </td>
      <td> _Document </td>
      <td> false </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 9002 </td>
      <td> Due Date </td>
      <td> _duedatetest </td>
      <td> _duedatetest </td>
      <td> false </td>
      <td> true </td>
    </tr>
    <tr>
      <td> 9006 </td>
      <td> Evidence </td>
      <td> _evidencetest </td>
      <td> _evidencetest </td>
      <td> false </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 8947 </td>
      <td> Id </td>
      <td> Id </td>
      <td> Id </td>
      <td> true </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 8959 </td>
      <td> Published Revision </td>
      <td> PublishedVersion </td>
      <td> PublishedVersion </td>
      <td> true </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 9083 </td>
      <td> Task ID </td>
      <td> _taskid </td>
      <td> _taskid </td>
      <td> false </td>
      <td> true </td>
    </tr>
    <tr>
      <td> 8952 </td>
      <td> Updated At </td>
      <td> UpdatedAt </td>
      <td> UpdatedAt </td>
      <td> true </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 8953 </td>
      <td> Updated By </td>
      <td> UpdatedBy </td>
      <td> UpdatedBy </td>
      <td> true </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 9012 </td>
      <td> Work Log </td>
      <td> _worktime </td>
      <td> _worktime </td>
      <td> false </td>
      <td> false </td>
    </tr>
    <tr>
      <td> 8957 </td>
      <td> Workflow Stage </td>
      <td> WorkflowStage </td>
      <td> WorkflowStage </td>
      <td> true </td>
      <td> false </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>3. kl-get-field</h3>
<hr>
<p>Retrieves details for a field specified by ID.</p>
<h5>Base Command</h5>
<p>
  <code>kl-get-field</code>
</p>


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
      <td>component_id</td>
      <td>The ID of the component. Get the ID from the kl-get-component command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>field_name</td>
      <td>The name of the field.</td>
      <td>Required</td>
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
      <td>Keylight.Field.ID</td>
      <td>String</td>
      <td>The ID of the field.</td>
    </tr>
    <tr>
      <td>Keylight.Field.Name</td>
      <td>String</td>
      <td>The field's name.</td>
    </tr>
    <tr>
      <td>Keylight.Field.SystemName</td>
      <td>String</td>
      <td>The system name of the field.</td>
    </tr>
    <tr>
      <td>Keylight.Field.ShortName</td>
      <td>String</td>
      <td>The short name of the field.</td>
    </tr>
    <tr>
      <td>Keylight.Field.ReadOnly</td>
      <td>Boolean</td>
      <td>Is the field read only.</td>
    </tr>
    <tr>
      <td>Keylight.Field.Required</td>
      <td>String</td>
      <td>Is the field required.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!kl-get-field component_id="10359" field_name="Task ID"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Keylight.Field": {
        "FieldType": 1,
        "ID": 9083,
        "MatrixRows": [],
        "MaxLength": 100,
        "Name": "Task ID",
        "OneToMany": false,
        "ReadOnly": false,
        "Required": true,
        "ShortName": "_taskid",
        "SystemName": "_taskid"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Keylight field 9083:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>SystemName</strong></th>
      <th><strong>ShortName</strong></th>
      <th><strong>ReadOnly</strong></th>
      <th><strong>Required</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 9083 </td>
      <td> Task ID </td>
      <td> _taskid </td>
      <td> _taskid </td>
      <td> false </td>
      <td> true </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>4. kl-get-record</h3>
<hr>
<p>Returns the complete set of fields for a given record within a component.</p>
<h5>Base Command</h5>
<p>
  <code>kl-get-record</code>
</p>


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
      <td>component_id</td>
      <td>The component ID. Get the D from the kl-get-component.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>field_names</td>
      <td>The filter specific for field names.
* Case sensitive.
* If one of the names contains a space, add all names in parenthesis (such as "Id,Published Revision").</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>record_id</td>
      <td>The record ID. Get the ID from Keylight or from the kl-get-records command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>detailed</td>
      <td>Whether to get detailed records. Default is false.</td>
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
      <td>Keylight.Record.ID</td>
      <td>String</td>
      <td>The record ID.</td>
    </tr>
    <tr>
      <td>Keylight.Record.Fields</td>
      <td>String</td>
      <td>The fields in the record.</td>
    </tr>
    <tr>
      <td>Keylight.Record.ComponentID</td>
      <td>String</td>
      <td>The component ID of the record.</td>
    </tr>
    <tr>
      <td>Keylight.Record.DisplayName</td>
      <td>String</td>
      <td>The display name of the record.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code> </code>
</p>

<h5>Human Readable Output</h5>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>5. kl-get-records</h3>
<hr>
<p>Retrieves the title/default field for a set of records within a chosen component.
Filters may be applied to retrieve only the records meeting the selected criteria.</p>
<h5>Base Command</h5>
<p>
  <code>kl-get-records</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
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
      <td>component_id</td>
      <td>The ID of the desired component. Get the ID from the kl-get-component command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>page_index</td>
      <td>The index of the page of result to return. Must be >= 0</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>page_size</td>
      <td>The index of the page of result to return. Must be between 0 and 100.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>filter_type</td>
      <td>The type of filter to apply. Can be: "Contains", "Excludes", "Starts With", "Ends With", "Equals", "Not Equals", "Greater Than", "Less Than", "Greater Than", "Less Than", "Greater Equals Than", "Between", "Not Between", "Is Null", "Is Not Null".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>filter_field_name</td>
      <td>The name of the field for which to apply the filter.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>filter_value</td>
      <td>The value for which to filter.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>detailed</td>
      <td>Whether to get detailed records.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>returned_fields</td>
      <td>A list of specific fields to return. If empty, return all fields.</td>
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
      <td>Keylight.Record.ComponentID</td>
      <td>String</td>
      <td>The ID of the component containing the record.</td>
    </tr>
    <tr>
      <td>Keylight.Record.DisplayName</td>
      <td>String</td>
      <td>The display name of the record.</td>
    </tr>
    <tr>
      <td>Keylight.Record.Fields</td>
      <td>Unknown</td>
      <td>The fields in the record.</td>
    </tr>
    <tr>
      <td>Keylight.Record.ID</td>
      <td>Unknown</td>
      <td>The ID of the record.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!kl-get-records component_id="10359" filter_type="Starts With" filter_field_name="Task ID" filter_value="Updated" detailed="True"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Keylight.Record": [
        {
            "ComponentID": "10359",
            "DisplayName": "Updated by Demisto Test Playbook",
            "Fields": {
                "Assignee": null,
                "Attachment": [],
                "Audit Project": "Project",
                "Authority Doc Citations": null,
                "Comments": null,
                "Created At": "2019-12-24T10:09:23.6108718",
                "Created By": "Development, Demisto",
                "Current Revision": 2,
                "Deleted": false,
                "Description": null,
                "DisplayName": "Updated by Demisto Test Playbook",
                "Document Attachment": [],
                "Due Date": null,
                "Evidence": [],
                "Id": 107,
                "Published Revision": 2,
                "Task ID": "Updated by Demisto Test Playbook",
                "Updated At": "2019-12-24T10:15:27.8176824",
                "Updated By": "Development, Demisto",
                "Work Log": null,
                "Workflow Stage": "Published"
            },
            "ID": 107
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Records for component 10359 </h3>
<h3>with filter "Starts With: Updated" on field "Task ID"</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Assignee</strong></th>
      <th><strong>Attachment</strong></th>
      <th><strong>Audit Project</strong></th>
      <th><strong>Authority Doc Citations</strong></th>
      <th><strong>Comments</strong></th>
      <th><strong>Created At</strong></th>
      <th><strong>Created By</strong></th>
      <th><strong>Current Revision</strong></th>
      <th><strong>Deleted</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>DisplayName</strong></th>
      <th><strong>Document Attachment</strong></th>
      <th><strong>Due Date</strong></th>
      <th><strong>Evidence</strong></th>
      <th><strong>Id</strong></th>
      <th><strong>Published Revision</strong></th>
      <th><strong>Task ID</strong></th>
      <th><strong>Updated At</strong></th>
      <th><strong>Updated By</strong></th>
      <th><strong>Work Log</strong></th>
      <th><strong>Workflow Stage</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>  </td>
      <td>  </td>
      <td> Project </td>
      <td>  </td>
      <td>  </td>
      <td> 2019-12-24T10:09:23.6108718 </td>
      <td> Development, Demisto </td>
      <td> 2 </td>
      <td> false </td>
      <td>  </td>
      <td> Updated by Demisto Test Playbook </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
      <td> 107 </td>
      <td> 2 </td>
      <td> Updated by Demisto Test Playbook </td>
      <td> 2019-12-24T10:15:27.8176824 </td>
      <td> Development, Demisto </td>
      <td>  </td>
      <td> Published </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>6. kl-get-record-count</h3>
<hr>
<p>Get the number of records for a specific component and filter.</p>
<h5>Base Command</h5>
<p>
  <code>kl-get-record-count</code>
</p>


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
      <td>component_id</td>
      <td>The ID of the desired component. Get the ID from the kl-get-component command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>filter_type</td>
      <td>The type of filter to apply. Can be: "Contains", "Excludes", "Starts With", "Ends With", "Equals", "Not Equals", "Greater Than", "Less Than", "Greater Than", "Less Than", "Greater Equals Than", "Between", "Not Between", "Is Null", "Is Not Null".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>filter_field_name</td>
      <td>The name of the field for which to apply the filter.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>filter_value</td>
      <td>The value for which to filter.</td>
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
  <code>!kl-get-record-count component_id=10359</code>
</p>

<h5>Human Readable Output</h5>
<p>
<h2>There are **23** records in component 10359.</h2>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>7. kl-get-record-attachments</h3>
<hr>
<p>Return the attachments of a specific field and record.</p>
<h5>Base Command</h5>
<p>
  <code>kl-get-record-attachments</code>
</p>


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
      <td>component_id</td>
      <td>The ID of the desired component. Get the ID from the kl-get-component command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>record_id</td>
      <td>The record ID. Can get from Keylight or from the kl-get-records command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>field_name</td>
      <td>The name of the field that holds the attachments. Must be type "Documents".</td>
      <td>Required</td>
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
      <td>Keylight.Attachment.FileName</td>
      <td>String</td>
      <td>The name of the attachment.</td>
    </tr>
    <tr>
      <td>Keylight.Attachment.FieldID</td>
      <td>String</td>
      <td>The field ID of the attachment.</td>
    </tr>
    <tr>
      <td>Keylight.Attachment.DocumentID</td>
      <td>String</td>
      <td>The ID of the document containing the attachment.</td>
    </tr>
    <tr>
      <td>Keylight.Attachment.ComponentID</td>
      <td>String</td>
      <td>The component ID of the attachment.</td>
    </tr>
    <tr>
      <td>Keylight.Attachment.RecordID</td>
      <td>String</td>
      <td>The record ID of the attachment.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!kl-get-record-attachments component_id=10359 field_name="Evidence" record_id=4</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Keylight.Attachment": [
        {
            "ComponentID": "10359",
            "DocumentID": 409,
            "FieldID": 9006,
            "FileName": "20170105_133423 (1).jpg",
            "RecordID": "4"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Field Evidence in record 4 has the following attachments:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ComponentID</strong></th>
      <th><strong>DocumentID</strong></th>
      <th><strong>FieldID</strong></th>
      <th><strong>FileName</strong></th>
      <th><strong>RecordID</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 10359 </td>
      <td> 409 </td>
      <td> 9006 </td>
      <td> 20170105_133423 (1).jpg </td>
      <td> 4 </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>8. kl-get-record-attachment</h3>
<hr>
<p>Returns a single attachment associated with the component ID, record ID, documents field ID, and the document ID.</p>
<h5>Base Command</h5>
<p>
  <code>kl-get-record-attachment</code>
</p>


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
      <td>component_id</td>
      <td>The ID of the desired component. Get the ID from the kl-get-component command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>record_id</td>
      <td>The record ID. Can get from Keylight or from the kl-get-records command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>field_name</td>
      <td>The name of the field that holds the attachments. Must be type "Documents".</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>document_id</td>
      <td>The ID of the document.</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!kl-get-record-attachment component_id=10359 field_name="Evidence" record_id=4 document_id=409</code>
</p>


<h3>9. kl-delete-record</h3>
<hr>
<p>Deletes a selected record from within a chosen component.</p>
<h5>Base Command</h5>
<p>
  <code>kl-delete-record</code>
</p>


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
      <td>component_id</td>
      <td>The component ID. Get the ID from the kl-get-component command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>record_id</td>
      <td>The record ID.</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!kl-delete-record component_id="10359" record_id="106"</code>
</p>

<h5>Human Readable Output</h5>
<p>
<h3>Record 106 of component 10359 was deleted successfully.</h3>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>10. kl-delete-record-attachment</h3>
<hr>
<p>Deletes a specific attachment.</p>
<h5>Base Command</h5>
<p>
  <code>kl-delete-record-attachment</code>
</p>


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
      <td>component_id</td>
      <td>The ID of the component. Get the ID from the kl-get-component command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>record_id</td>
      <td>The ID of the record to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>field_id</td>
      <td>The ID of the field.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>document_id</td>
      <td>The ID of the document to delete.</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!kl-delete-record-attachment component_id=10359 field_name="Evidence" record_id=4 document_id=409</code>
</p>

<h5>Human Readable Output</h5>
<p>
<h3>Attachment was successfully deleted from the Documents field. </h3>
</p>

<h3>11. kl-get-lookup-report-column-fields</h3>
<hr>
<p>Retrieves information of each field in a field path, which relates to a lookup report column.</p>
<h5>Base Command</h5>
<p>
  <code>kl-get-lookup-report-column-fields</code>
</p>


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
      <td>lookup_field_id</td>
      <td>The lookup field ID, which relates to a lookup field that uses the report definition.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>field_path_id</td>
      <td>The field path ID, which relates to the field path that retrieves fields. Get from the kl-get-record command. Detailed=True.</td>
      <td>Required</td>
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
      <td>Keylight.LookupField.ID</td>
      <td>String</td>
      <td>The lookup field's ID.</td>
    </tr>
    <tr>
      <td>Keylight.LookupField.Name</td>
      <td>String</td>
      <td>The lookup field's name.</td>
    </tr>
    <tr>
      <td>Keylight.LookupField.ComponentID</td>
      <td>String</td>
      <td>The lookup field's component ID.</td>
    </tr>
    <tr>
      <td>Keylight.LookupField.SystemName</td>
      <td>String</td>
      <td>The system name of the lookup field.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code> </code>
</p>

<h5>Human Readable Output</h5>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>12. kl-create-record</h3>
<hr>
<p>Creates a new record within the specified component of the Keylight application.
* The Required option for a field is only enforced through the user interface, not through Demisto.</p>
<h5>Base Command</h5>
<p>
  <code>kl-create-record</code>
</p>


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
      <td>component_id</td>
      <td>The ID of the component the record should be created in. Get the ID from the kl-get-component command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>record_json</td>
      <td>A JSON file in the format that the API requests. The exact format is found in the API documentation.</td>
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
      <td>Keylight.Record.ComponentID</td>
      <td>String</td>
      <td>The component ID of the record.</td>
    </tr>
    <tr>
      <td>Keylight.Record.DisplayName</td>
      <td>String</td>
      <td>The display name of the record.</td>
    </tr>
    <tr>
      <td>Keylight.Record.Fields</td>
      <td>Unknown</td>
      <td>The fields in the record.</td>
    </tr>
    <tr>
      <td>Keylight.Record.ID</td>
      <td>String</td>
      <td>The record ID.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!kl-create-record component_id="10359" record_json="[{\"fieldName\": \"Task ID\", \"value\": \"Created by Demisto Test Playbook\", \"isLookup\": false}, {\"fieldName\": \"Audit Project\", \"value\": 3, \"isLookup\": true}]"</code>
</p>

<h5>Human Readable Output</h5>
<p>

<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/50324325/71411887-d40d3d80-2653-11ea-8781-35c3eb643f74.png"
 alt="image"></a>
</p>

<h3>13. kl-update-record</h3>
<hr>
<p>Update fields in a specified record.
* The Required option for a field is only enforced through the user interface, not through Demisto.</p>
<h5>Base Command</h5>
<p>
  <code>kl-update-record</code>
</p>


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
      <td>component_id</td>
      <td>The ID of the component. Get the ID from the kl-get-component command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>record_id</td>
      <td>The ID of the record to be updated. Get the ID from Keylight or from the kl-get-records command.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>record_json</td>
      <td>A JSON file in the format that the API requests. The exact format is found in the API documentation.</td>
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
      <td>Keylight.Record.ComponentID</td>
      <td>String</td>
      <td>The ID of the component the record is in.</td>
    </tr>
    <tr>
      <td>Keylight.Record.DisplayName</td>
      <td>String</td>
      <td>The display name of the record.</td>
    </tr>
    <tr>
      <td>Keylight.Record.Fields</td>
      <td>String</td>
      <td>The fields in the record.</td>
    </tr>
    <tr>
      <td>Keylight.Record.ID</td>
      <td>String</td>
      <td>The record ID</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!kl-update-record component_id="10359" record_id="106" record_json="[{\"fieldName\": \"Task ID\", \"value\": \"Updated by Demisto Test Playbook\", \"isLookup\": false}, {\"fieldName\": \"Audit Project\", \"value\": 3, \"isLookup\": true}]"</code>
</p>

<h5>Human Readable Output</h5>
<p>

<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/50324325/71411939-fef79180-2653-11ea-90de-984bea0f2484.png"
 alt="image" ></a>
</p>


