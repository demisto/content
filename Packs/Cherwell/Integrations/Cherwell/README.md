<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Cherwell is a cloud-based IT service management solution.</p>
</div>
<div class="cl-preview-section">
<h2 id="configure-cherwell-on-demisto">Configure Cherwell on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Cherwell.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>URL (example: <a href="https://my.domain.com/">https://my.domain.com</a>)</strong></li>
<li><strong>Username</strong></li>
<li><strong>Client id</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy</strong></li>
<li><strong>First fetch timestamp ( <time>, e.g., 12 hours, 7 days)</time></strong></li>
<li><strong>CSV list of objects to fetch. The default is incident, for example: incident,problem,service)</strong></li>
<li><strong>Max results to fetch (defualt is 30)</strong></li>
<li><strong>Advanced Query to fetch</strong></li>
<li><strong>Fetch attachments (include attachements in fetch process)</strong></li>
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
<li><a href="#create-a-business-object" target="_self">Create a business object: cherwell-create-business-object</a></li>
<li><a href="#update-a-business-object" target="_self">Update a business object: cherwell-update-business-object</a></li>
<li><a href="#delete-a-business-object" target="_self">Delete a business object: cherwell-delete-business-object</a></li>
<li><a href="#get-information-for-a-business-object" target="_self">Get information for a business object: cherwell-get-business-object</a></li>
<li><a href="#download-attachments-for-a-business-object" target="_self">Download attachments for a business object: cherwell-download-attachments</a></li>
<li><a href="#upload-an-attachment-to-a-business-object" target="_self">Upload an attachment to a business object: cherwell-upload-attachment</a></li>
<li><a href="#link-related-business-objects" target="_self">Link related business objects: cherwell-link-business-objects</a></li>
<li><a href="#unlink-related-business-objects" target="_self">Unlink related business objects: cherwell-unlink-business-objects</a></li>
<li><a href="#get-information-for-business-object-attachments" target="_self">Get information for business object attachments: cherwell-get-attachments-info</a></li>
<li><a href="#remove-an-attachment-from-a-business-object" target="_self">Remove an attachment from a business object: cherwell-remove-attachment</a></li>
<li><a href="#query-a-business-object" target="_self">Query a business object: cherwell-query-business-object</a></li>
<li><a href="#get-information-for-a-field" target="_self">Get information for a field: cherwell-get-field-info</a></li>
<li><a href="#run-a-saved-search" target="_self">Run a saved search: cherwell-run-saved-search</a></li>
<li><a href="#get-a-business-object-id" target="_self">Get a business object ID: cherwell-get-business-object-id</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="create-a-business-object">1. Create a business object</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Creates a business object.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-create-business-object</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 527px;"><strong>Description</strong></th>
<th style="width: 75px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">type</td>
<td style="width: 527px;">Business object type, for example: “Incident”.</td>
<td style="width: 75px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">json</td>
<td style="width: 527px;">Data JSON containing the relevant fields and their values, for example:<br> {“title”: “some value”}).</td>
<td style="width: 75px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 378px;"><strong>Path</strong></th>
<th style="width: 73px;"><strong>Type</strong></th>
<th style="width: 289px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 378px;">Cherwell.BusinessObjects.RecordId</td>
<td style="width: 73px;">String</td>
<td style="width: 289px;">Business object record ID.</td>
</tr>
<tr>
<td style="width: 378px;">Cherwell.BusinessObjects.PublicId</td>
<td style="width: 73px;">String</td>
<td style="width: 289px;">Business object public ID.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-create-business-object type=incident json=`{"Priority": "3", "CustomerDisplayName": "Playbook customer", "Description": "This incident was created by Cherwell documentation script"}</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Cherwell.BusinessObjects": {
        "RecordId": "944b6c9333fea00cf4a25b40b08542bdcb4db64327", 
        "PublicId": "10222"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="new-incident-was-created">New Incident was created</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Public Id</th>
<th>Record Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>10222</td>
<td>944b6c9333fea00cf4a25b40b08542bdcb4db64327</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="update-a-business-object">2. Update a business object</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Update a business object with the specified fields.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-update-business-object</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 168px;"><strong>Argument Name</strong></th>
<th style="width: 485px;"><strong>Description</strong></th>
<th style="width: 87px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168px;">type</td>
<td style="width: 485px;">Business object type, for example: “Incident”.</td>
<td style="width: 87px;">Required</td>
</tr>
<tr>
<td style="width: 168px;">json</td>
<td style="width: 485px;">Data JSON containing the relevant fields and their values.</td>
<td style="width: 87px;">Required</td>
</tr>
<tr>
<td style="width: 168px;">id_value</td>
<td style="width: 485px;">Public ID or record ID.</td>
<td style="width: 87px;">Required</td>
</tr>
<tr>
<td style="width: 168px;">id_type</td>
<td style="width: 485px;">Type of ID.</td>
<td style="width: 87px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Cherwell.BusinessObjects.RecordId</td>
<td>String</td>
<td>Business object record ID.</td>
</tr>
<tr>
<td>Cherwell.BusinessObjects.PublicId</td>
<td>Unknown</td>
<td>Business object public ID.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-update-business-object id_type=public_id id_value=10216 json={“Priority”:“3”} type=incident</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Cherwell.BusinessObjects": {
        "RecordId": "944b6c68c70cb404b1066e4ff4bde663f8ade81c52", 
        "PublicId": "10216"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="incident-10216-was-updated">Incident 10216 was updated</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Public Id</th>
<th>Record Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>10216</td>
<td>944b6c68c70cb404b1066e4ff4bde663f8ade81c52</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="delete-a-business-object">3. Delete a business object</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes a given business object.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-delete-business-object</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 177px;"><strong>Argument Name</strong></th>
<th style="width: 462px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 177px;">type</td>
<td style="width: 462px;">Business object type, for example: “Incident”.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 177px;">id_value</td>
<td style="width: 462px;">Public ID or record ID.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 177px;">id_type</td>
<td style="width: 462px;">Type of ID.</td>
<td style="width: 101px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-delete-business-object id_type=public_id id_value=10194 type=incident</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="record-10194-of-type-incident-was-deleted.">Record 10194 of type incident was deleted.</h3>
</div>
<div class="cl-preview-section">
<h3 id="get-information-for-a-business-object">4. Get information for a business object</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets a business object by an ID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-get-business-object</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 178px;"><strong>Argument Name</strong></th>
<th style="width: 461px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 178px;">type</td>
<td style="width: 461px;">Business object type, for example: “Incident”.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 178px;">id_value</td>
<td style="width: 461px;">Public ID or record ID.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 178px;">id_type</td>
<td style="width: 461px;">Type of ID.</td>
<td style="width: 101px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-get-business-object id_type=public_id id_value=10216 type=incident</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Cherwell.BusinessObjects": {
        "Service": "Account Management", 
        "LastModByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
        "CreatedByEmail": "", 
        "Comments": "", 
        "ShowAllServices": "False", 
        "RecurringIncident": "False", 
        "ReviewByDeadline": "", 
        "PortalAffectsPrimaryFunction": "False", 
        "CustomerTypeID": "", 
        "NextStatusOneStep": "&lt;Trebuchet&gt;&lt;ActionInfoDef ID=\"93d9abdb6242", 
        "OwnedByManager": "", 
        "Level3EscalationTeam": "", 
        "Stat_IncidentEscalated": "False", 
        "TasksOnHold": "False", 
        "Stat_SLAResolutionBreached": "False", 
        "NextStatusText": "Begin Work", 
        "SLA_Key": "_Incident", 
        "CIDowntimeInMinutes": "0", 
        "Withdraw": "False", 
        "CustomerSubscriptionLevel": "", 
        "CombinedKB": "", 
        "SCTFired": "False", 
        "PublicId": "10216", 
        "SCTRecID": "", 
        "Stat_DateTimeReOpened": "", 
        "SLAIDForCI": "", 
        "CreatedDuring": "Only on weekends", 
        "ApprovalBlockID": "", 
        "TotalSTCTimeInMinutes": "0", 
        "OwnedBy": "", 
        "CloseDescription": "", 
        "SLANameForCustomer": "", 
        "Impact": "", 
        "PortalAltContactInfo": "", 
        "Stat_DateTimeAssigned": "", 
        "Stat_ResponseTime": "0", 
        "DefaultTeam": "", 
        "PendingReason": "", 
        "SLAName": "Corporate", 
        "SLAResponseWarning": "4/29/2019 9:45 AM", 
        "Priority": "3", 
        "Source": "Phone", 
        "Location": "", 
        "LinkedSLAs": " ,  , ", 
        "ServiceCatalogTemplateName": "", 
        "ServiceCartID": "", 
        "CustomerDisplayName": "Playbook customer", 
        "ClosedBy": "", 
        "ClonedIncident": "False", 
        "ChangeID": "", 
        "CreatedDateTime": "4/28/2019 1:39 PM", 
        "NextStatus": "In Progress", 
        "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f", 
        "ConfigItemTypeID": "", 
        "STCTimeInMinutes": "0", 
        "LastModifiedDateTime": "4/28/2019 1:57 PM", 
        "ConfigItemRecID": "", 
        "PendingStartDateTime": "", 
        "MajorIncidentID": "", 
        "ServiceID": "9389f6f40e1ab014733fa341dab8e03b0d3c380b07", 
        "WasCIDown": "False", 
        "Urgency": "", 
        "Stat_SLAResponseWarning": "False", 
        "Stat_DateTimeInProgress": "", 
        "Stat_FirstCallResolution": "False", 
        "ServiceEntitlements": "Platinum, Gold, Silver, Corporate", 
        "IncidentchildRecID": "", 
        "ClonedIncidentID": "", 
        "CreatedBy": "API User", 
        "SLAID": "938aad773b01d0140385e84d19aa5205c5acf8c839", 
        "ClosedOn1stCall": "False", 
        "Category": "", 
        "SubcategoryID": "", 
        "Stat_SLAResolutionGood": "False", 
        "SmartClassifySearchString": "", 
        "MajorIncidentRecID": "", 
        "LinkedProblem": "", 
        "TotalTasks": "1", 
        "TasksClosed": "False", 
        "PortalAffectsMultipleUsers": "False", 
        "ShowContactInformation": "False", 
        "SLATargetTimeID": "", 
        "Status": "New", 
        "CIDownEndDateTime": "", 
        "TotalTaskTime": "0", 
        "Level2EscalationComplete": "True", 
        "Stat_SLAResponseGood": "False", 
        "PendingPreviousStatus": "", 
        "SLAIDForCustomer": "", 
        "Stat_DateTimeResponded": "", 
        "CartItemID": "", 
        "RequesterDepartment": "", 
        "IncidentchildID": "", 
        "RecordId": "944b6c68c70cb404b1066e4ff4bde663f8ade81c52", 
        "ReasonForBreach": "", 
        "ClosedDateTime": "", 
        "LastModTimeStamp": "", 
        "Subcategory": "", 
        "MajorIncident": "False", 
        "Level3EscalationComplete": "True", 
        "TasksInProgress": "False", 
        "SLANameForService": "", 
        "IncidentType": "Incident", 
        "Stat_SLAResponseBreached": "False", 
        "CIDownStartDateTime": "", 
        "IncidentDurationInDays": "0.01", 
        "CreatedByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
        "RecID": "944b6c68c70cb404b1066e4ff4bde663f8ade81c52", 
        "SLAResolveByDeadline": "5/1/2019 1:39 PM", 
        "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00", 
        "Cause": "", 
        "Stat_IncidentReopened": "False", 
        "SLANameForCI": "", 
        "Stat_DateTimeResolved": "", 
        "Description": "Example scripts test playbook", 
        "Stat_NumberOfTouches": "10", 
        "OwnedByTeam": "", 
        "SLAIDForService": "", 
        "BreachNotes": "", 
        "Cost": "0", 
        "CustomerRecID": "944b37889fdb5a0e8f519b422095314c29cdbca16a", 
        "ConfigItemType": "", 
        "IncidentID": "10216", 
        "ConfigItemDisplayName": "", 
        "SLAResolutionWarning": "5/1/2019 1:24 PM", 
        "Stat_DateTimeClosed": "", 
        "ClosedByID": "", 
        "Stat_24x7ElapsedTime": "0", 
        "Level2EscalationTeam": "", 
        "SLARespondByDeadline": "4/29/2019 10:00 AM", 
        "OwnedByID": "", 
        "LastModBy": "API User", 
        "Stat_NumberOfEscalations": "0", 
        "StatusDesc": "", 
        "PendingEndDateTime": "", 
        "Stat_SLAResolutionWarning": "False", 
        "TaskClosedCount": "0", 
        "ServiceCustomerIsEntitled": "True", 
        "OwnedByTeamID": "", 
        "IncidentDurationInHours": "0.3"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="incident-10216">Incident: 10216</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Rec ID</th>
<th>Incident ID</th>
<th>Created Date Time</th>
<th>Created During</th>
<th>Created By</th>
<th>Created By ID</th>
<th>Status</th>
<th>Status Desc</th>
<th>Service</th>
<th>Category</th>
<th>Subcategory</th>
<th>Specifics Type Id</th>
<th>Description</th>
<th>Impact</th>
<th>Urgency</th>
<th>Priority</th>
<th>Closed Date Time</th>
<th>Closed By</th>
<th>Closed By ID</th>
<th>Cost</th>
<th>Last Mod Time Stamp</th>
<th>Owned By Team</th>
<th>Owned By Team ID</th>
<th>Owned By</th>
<th>Owned By ID</th>
<th>Customer Type ID</th>
<th>Customer Rec ID</th>
<th>Close Description</th>
<th>Linked Problem</th>
<th>Last Modified Date Time</th>
<th>Last Mod By</th>
<th>Last Mod By ID</th>
<th>Config Item Type ID</th>
<th>Config Item Rec ID</th>
<th>In cident Duration In Days</th>
<th>Incident Type</th>
<th>SLA Respond By Deadline</th>
<th>SLAID</th>
<th>SLA Name</th>
<th>SLA Target Time ID</th>
<th>SLA Resolve By Deadline</th>
<th>Closed On 1 St Call</th>
<th>Source</th>
<th>Change ID</th>
<th>In cident Duration In Hours</th>
<th>Customer Display Name</th>
<th>Owned By Manager</th>
<th>Created By Email</th>
<th>Pending Reason</th>
<th>Review By Deadline</th>
<th>Stat _ Number Of Touches</th>
<th>Stat _ First Call Resolution</th>
<th>Stat _ Incident Escalated</th>
<th>Stat _ Number Of Escalations</th>
<th>Stat _24 X 7 Elapsed Time</th>
<th>Stat _ Incident Reopened</th>
<th>Stat _ Date Time Responded</th>
<th>Stat _ Response Time</th>
<th>Stat _SLA Response Breached</th>
<th>Stat _SLA Resolution Breached</th>
<th>Service ID</th>
<th>Pending Previous Status</th>
<th>Portal Affects Primary Function</th>
<th>Portal Affects Multiple Users</th>
<th>Portal Alt Contact Info</th>
<th>SLAID For Customer</th>
<th>SLAID For Service</th>
<th>SLAID For CI</th>
<th>Linked SL As</th>
<th>SLA Name For CI</th>
<th>SLA Name For Customer</th>
<th>SLA Name For Service</th>
<th>Reason For Breach</th>
<th>Config Item Display Name</th>
<th>Breach Notes</th>
<th>Show All Services</th>
<th>Show Contact Information</th>
<th>Service Entitlements</th>
<th>Service Customer Is Entitled</th>
<th>Combined KB</th>
<th>Total Tasks</th>
<th>Stat _SLA Resolution Warning</th>
<th>Stat _SLA Response Warning</th>
<th>Stat _SLA Resolution Good</th>
<th>Stat _SLA Response Good</th>
<th>Stat _ Date Time Assigned</th>
<th>Stat _ Date Time In Progress</th>
<th>Stat _ Date Time Resolved</th>
<th>Stat _ Date Time Closed</th>
<th>Stat _ Date Time Re Opened</th>
<th>SLA Response Warning</th>
<th>SLA Resolution Warning</th>
<th>Pending Start Date Time</th>
<th>Pending End Date Time</th>
<th>STC Time In Minutes</th>
<th>Total STC Time In Minutes</th>
<th>Location</th>
<th>Next Status</th>
<th>Next Status Text</th>
<th>Next Status One Step</th>
<th>SLA_ Key</th>
<th>Status ID</th>
<th>Subcategory ID</th>
<th>Smart Classify Search String</th>
<th>Total Task Time</th>
<th>Config Item Type</th>
<th>Approval Block ID</th>
<th>Cloned Incident ID</th>
<th>Recurring Incident</th>
<th>Was CI Down</th>
<th>CI Down Start Date Time</th>
<th>CI Down End Date Time</th>
<th>Major Incident</th>
<th>Major Incident Rec ID</th>
<th>Major Incident ID</th>
<th>Incidentchild ID</th>
<th>Incidentchild Rec ID</th>
<th>Cause</th>
<th>Cloned Incident</th>
<th>Comments</th>
<th>CI Downtime In Minutes</th>
<th>Withdraw</th>
<th>Customer Subscription Level</th>
<th>Service Cart ID</th>
<th>Cart Item ID</th>
<th>SCT Rec ID</th>
<th>Tasks In Progress</th>
<th>Tasks Closed</th>
<th>Task Closed Count</th>
<th>Tasks On Hold</th>
<th>SCT Fired</th>
<th>Requester Department</th>
<th>Level 2 Escalation Complete</th>
<th>Level 3 Escalation Complete</th>
<th>Default Team</th>
<th>Level 2 Escalation Team</th>
<th>Level 3 Escalation Team</th>
<th>Service Catalog Template Name</th>
<th>Public Id</th>
<th>Record Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>944b6c68c70cb404b1066e4ff4bde663f8ade81c52</td>
<td>10216</td>
<td>4/28/2019 1:39 PM</td>
<td>Only on weekends</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td>New</td>
<td> </td>
<td>Account Management</td>
<td> </td>
<td> </td>
<td>9398862125defd58a8deea46fe88acc411a96e2b00</td>
<td>Example scripts test playbook</td>
<td> </td>
<td> </td>
<td>3</td>
<td> </td>
<td> </td>
<td> </td>
<td>0</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>944b37889fdb5a0e8f519b422095314c29cdbca16a</td>
<td> </td>
<td> </td>
<td>4/28/2019 1:57 PM</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td> </td>
<td> </td>
<td>0.01</td>
<td>Incident</td>
<td>4/29/2019 10:00 AM</td>
<td>938aad773b01d0140385e84d19aa5205c5acf8c839</td>
<td>Corporate</td>
<td> </td>
<td>5/1/2019 1:39 PM</td>
<td>False</td>
<td>Phone</td>
<td> </td>
<td>0.3</td>
<td>Playbook customer</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>10</td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>0</td>
<td>False</td>
<td> </td>
<td>0</td>
<td>False</td>
<td>False</td>
<td>9389f6f40e1ab014733fa341dab8e03b0d3c380b07</td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>, ,</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td>Platinum, Gold, Silver, Corporate</td>
<td>True</td>
<td> </td>
<td>1</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>4/29/2019 9:45 AM</td>
<td>5/1/2019 1:24 PM</td>
<td> </td>
<td> </td>
<td>0</td>
<td>0</td>
<td> </td>
<td>In Progress</td>
<td>Begin Work</td>
<td>&lt;ActionInfoDef ID="93d9abdb6242</td>
<td>_Incident</td>
<td>938729d99cb110f2a6c3e5488ead246422a7cd115f</td>
<td> </td>
<td> </td>
<td>0</td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td> </td>
<td>0</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td>True</td>
<td>True</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>10216</td>
<td>944b6c68c70cb404b1066e4ff4bde663f8ade81c52</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="download-attachments-for-a-business-object">5. Download attachments for a business object</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Downloads imported attachements from a specified business object.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-download-attachments</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 183px;"><strong>Argument Name</strong></th>
<th style="width: 456px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 183px;">type</td>
<td style="width: 456px;">Business object type, for example: “Incident”.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 183px;">id_type</td>
<td style="width: 456px;">Type of ID.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 183px;">id_value</td>
<td style="width: 456px;">Public ID or record ID.</td>
<td style="width: 101px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 115px;"><strong>Path</strong></th>
<th style="width: 218px;"><strong>Type</strong></th>
<th style="width: 407px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 115px;">File</td>
<td style="width: 218px;">Unknown</td>
<td style="width: 407px;">File result entries.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-download-attachments id_type=public_id id_value=10216 type=incident</pre>
</div>
<div class="cl-preview-section">
<h3 id="upload-an-attachment-to-a-business-object">6. Upload an attachment to a business object</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Uploads an attachment to a specified business object.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-upload-attachment</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 177px;"><strong>Argument Name</strong></th>
<th style="width: 462px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 177px;">type</td>
<td style="width: 462px;">Business object type, for example: “Incident”.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 177px;">id_type</td>
<td style="width: 462px;">Type of ID.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 177px;">id_value</td>
<td style="width: 462px;">Public ID or record ID.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 177px;">file_entry_id</td>
<td style="width: 462px;">File entry ID.</td>
<td style="width: 101px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 372px;"><strong>Path</strong></th>
<th style="width: 37px;"><strong>Type</strong></th>
<th style="width: 331px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 372px;">Cherwell.UploadedAttachments.AttachmentFileId</td>
<td style="width: 37px;">String</td>
<td style="width: 331px;">AttachmentFileId to use to get information about the attachment.</td>
</tr>
<tr>
<td style="width: 372px;">Cherwell.UploadedAttachments.BusinessObjectType</td>
<td style="width: 37px;">String</td>
<td style="width: 331px;">Business object type, for example: “Incident”.</td>
</tr>
<tr>
<td style="width: 372px;">Cherwell.UploadedAttachments.PublicId</td>
<td style="width: 37px;">String</td>
<td style="width: 331px;">Public ID.</td>
</tr>
<tr>
<td style="width: 372px;">Cherwell.UploadedAttachments.RecordId</td>
<td style="width: 37px;">String</td>
<td style="width: 331px;">Record ID.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-upload-attachment file_entry_id=87@674 id_type=public_id id_value=10216 type=incident</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Cherwell.UploadedAttachments": {
        "BusinessObjectType": "incident", 
        "AttachmentFileId": "944b6c9346d83133b838a64629b29964206a1dae6b", 
        "PublicId": "10216"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="attachment-944b6c9346d83133b838a64629b29964206a1dae6b-was-successfully-attached-to-incident-10216">Attachment: 944b6c9346d83133b838a64629b29964206a1dae6b, was successfully attached to incident 10216</h3>
</div>
<div class="cl-preview-section">
<h3 id="link-related-business-objects">7. Link related business objects</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Links business objects that are related.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-link-business-objects</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
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
<td>parent_type</td>
<td>Parent business object type name.</td>
<td>Required</td>
</tr>
<tr>
<td>parent_record_id</td>
<td>Parent business object record ID.</td>
<td>Required</td>
</tr>
<tr>
<td>child_type</td>
<td>Child business object type name.</td>
<td>Required</td>
</tr>
<tr>
<td>child_record_id</td>
<td>Child business object record ID.</td>
<td>Required</td>
</tr>
<tr>
<td>relationship_id</td>
<td>Relationship ID.</td>
<td>Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-6">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-6">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-link-business-objects relationship_id=9369187528b417b4a17aaa4646b7f7a78b3c821be9 parent_type=incident child_type=task parent_record_id=944b6c68c70cb404b1066e4ff4bde663f8ade81c52 child_record_id=944b6a8c455a91041f71fb42e2b085e1db50b0c57c</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="incident-944b6c68c70cb404b1066e4ff4bde663f8ade81c52-and-task-944b6a8c455a91041f71fb42e2b085e1db50b0c57c-were-linked">Incident 944b6c68c70cb404b1066e4ff4bde663f8ade81c52 and Task 944b6a8c455a91041f71fb42e2b085e1db50b0c57c were linked</h3>
</div>
<div class="cl-preview-section">
<h3 id="unlink-related-business-objects">8. Unlink related business objects</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Unlinks business objects that are linked and related.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-unlink-business-objects</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 219px;"><strong>Argument Name</strong></th>
<th style="width: 401px;"><strong>Description</strong></th>
<th style="width: 120px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 219px;">parent_type</td>
<td style="width: 401px;">Parent business object type name.</td>
<td style="width: 120px;">Required</td>
</tr>
<tr>
<td style="width: 219px;">parent_record_id</td>
<td style="width: 401px;">Parent business object record ID.</td>
<td style="width: 120px;">Required</td>
</tr>
<tr>
<td style="width: 219px;">child_type</td>
<td style="width: 401px;">Child business object type name.</td>
<td style="width: 120px;">Required</td>
</tr>
<tr>
<td style="width: 219px;">child_record_id</td>
<td style="width: 401px;">Child business object record ID.</td>
<td style="width: 120px;">Required</td>
</tr>
<tr>
<td style="width: 219px;">relationship_id</td>
<td style="width: 401px;">Relationship ID.</td>
<td style="width: 120px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-7">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-7">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-unlink-business-objects relationship_id=9369187528b417b4a17aaa4646b7f7a78b3c821be9 parent_type=incident child_type=task parent_record_id=944b6c68c70cb404b1066e4ff4bde663f8ade81c52 child_record_id=944b6a8c455a91041f71fb42e2b085e1db50b0c57c</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="incident-944b6c68c70cb404b1066e4ff4bde663f8ade81c52-and-task-944b6a8c455a91041f71fb42e2b085e1db50b0c57c-were-unlinked">Incident 944b6c68c70cb404b1066e4ff4bde663f8ade81c52 and Task 944b6a8c455a91041f71fb42e2b085e1db50b0c57c were unlinked</h3>
</div>
<div class="cl-preview-section">
<h3 id="get-information-for-business-object-attachments">9. Get information for business object attachments</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets information for business object attachments.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-8">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-get-attachments-info</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-8">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 188px;"><strong>Argument Name</strong></th>
<th style="width: 451px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 188px;">type</td>
<td style="width: 451px;">Business object type, for example: “Incident”.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 188px;">id_type</td>
<td style="width: 451px;">Type of ID.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 188px;">id_value</td>
<td style="width: 451px;">Public ID or record ID.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 188px;">attachment_type</td>
<td style="width: 451px;">Type of attachment.</td>
<td style="width: 101px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-8">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 368px;"><strong>Path</strong></th>
<th style="width: 39px;"><strong>Type</strong></th>
<th style="width: 333px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 368px;">Cherwell.AttachmentsInfo.AttachmentFiledId</td>
<td style="width: 39px;">String</td>
<td style="width: 333px;">Attachment field ID.</td>
</tr>
<tr>
<td style="width: 368px;">Cherwell.AttachmentsInfo.FileName</td>
<td style="width: 39px;">String</td>
<td style="width: 333px;">File name.</td>
</tr>
<tr>
<td style="width: 368px;">Cherwell.AttachmentsInfo.AttachmentId</td>
<td style="width: 39px;">String</td>
<td style="width: 333px;">Attachment ID.</td>
</tr>
<tr>
<td style="width: 368px;">Cherwell.AttachmentsInfo.BusinessObjectType</td>
<td style="width: 39px;">String</td>
<td style="width: 333px;">Business object type, for example: “Incident”.</td>
</tr>
<tr>
<td style="width: 368px;">Cherwell.AttachmentsInfo.BusinessObjectPublicId</td>
<td style="width: 39px;">String</td>
<td style="width: 333px;">Business object public ID.</td>
</tr>
<tr>
<td style="width: 368px;">Cherwell.AttachmentsInfo.BusinessObjectRecordId</td>
<td style="width: 39px;">String</td>
<td style="width: 333px;">Business object record ID.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-8">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-get-attachments-info id_type=public_id id_value=10216 type=incident attachment_type=imported</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-4">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Cherwell.AttachmentsInfo": [
        {
            "AttachmentFiledId": "944b6c8f48465818fb3a9c4f51837002dea63691e2", 
            "FileName": "Cherwell 2.txt", 
            "AttachmentId": "944b6c8f4806110229bd134a829dd04b9d81f4e06c", 
            "BusinessObjectPublicId": "10216", 
            "BusinessObjectType": "incident"
        }, 
        {
            "AttachmentFiledId": "944b6c9346d83133b838a64629b29964206a1dae6b", 
            "FileName": "Cherwell 2.txt", 
            "AttachmentId": "944b6c93462aff7a93cc1c4d16a4bb2f9326ad58fe", 
            "BusinessObjectPublicId": "10216", 
            "BusinessObjectType": "incident"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-7">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="incident-10216-attachments">Incident 10216 attachments:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Attachment Filed Id</th>
<th>File Name</th>
<th>Attachment Id</th>
<th>Business Object Type</th>
<th>Business Object Public Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>944b6c8f48465818fb3a9c4f51837002dea63691e2</td>
<td>Cherwell 2.txt</td>
<td>944b6c8f4806110229bd134a829dd04b9d81f4e06c</td>
<td>incident</td>
<td>10216</td>
</tr>
<tr>
<td>944b6c9346d83133b838a64629b29964206a1dae6b</td>
<td>Cherwell 2.txt</td>
<td>944b6c93462aff7a93cc1c4d16a4bb2f9326ad58fe</td>
<td>incident</td>
<td>10216</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="remove-an-attachment-from-a-business-object">10. Remove an attachment from a business object</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Remove an attachment from the specified business object.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-9">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-remove-attachment</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-9">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 188px;"><strong>Argument Name</strong></th>
<th style="width: 451px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 188px;">type</td>
<td style="width: 451px;">Business object type, for example: “Incident”.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 188px;">id_type</td>
<td style="width: 451px;">Type of ID.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 188px;">id_value</td>
<td style="width: 451px;">Public ID or record ID.</td>
<td style="width: 101px;">Required</td>
</tr>
<tr>
<td style="width: 188px;">attachment_id</td>
<td style="width: 451px;">Attachment ID to remove.</td>
<td style="width: 101px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-9">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-9">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-remove-attachment id_type=public_id attachment_id=944b6ac2597ce4050531c6471c8aca352c699f2394 id_value=10216 type=incident</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-8">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="attachment-944b6ac2597ce4050531c6471c8aca352c699f2394-was-successfully-removed-from-incident-10216">Attachment: 944b6ac2597ce4050531c6471c8aca352c699f2394, was successfully removed from incident 10216</h3>
</div>
<div class="cl-preview-section">
<h3 id="query-a-business-object">11. Query a business object</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Runs advanced queries to search in a specified business object.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-10">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-query-business-object</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-10">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 141px;"><strong>Argument Name</strong></th>
<th style="width: 528px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">type</td>
<td style="width: 528px;">Business object type, for example: “Incident”.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 141px;">query</td>
<td style="width: 528px;">The query to run. A CSV list of filters such that each filter is of the form: [“field_name”,“operator”,“value”] and operator is one of: ‘eq’=equal, ‘gt’=grater-than, ‘lt’=less-than, ‘contains’, ‘startwith’. Special characters shoud be escaped.<br> Example: <code>[["CreatedDateTime":"gt":"4/10/2019 3:10:12 PM"]["Priority","eq","1"]]</code>.<br> NOTE: If multiple filters are received for the same field name, an ‘OR’ operation between the filters will be performed, if the field names are different an ‘AND’ operation will be performed.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 141px;">max_results</td>
<td style="width: 528px;">Maximum number of results to pull.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-10">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-10">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-query-business-object query=[[“Description”,“eq”,“This incident was created by Cherwell documentation script”]] type=incident</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-5">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Cherwell.QueryResults": [
        {
            "Service": "", 
            "LastModByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "CreatedByEmail": "", 
            "Comments": "", 
            "ShowAllServices": "False", 
            "RecurringIncident": "False", 
            "ReviewByDeadline": "1/1/1900 12:00:00 AM", 
            "PortalAffectsPrimaryFunction": "False", 
            "CustomerTypeID": "", 
            "NextStatusOneStep": "&lt;Trebuchet&gt;&lt;ActionInfoDef ID=\"93d9abdb6242", 
            "OwnedByManager": "", 
            "Level3EscalationTeam": "", 
            "Stat_IncidentEscalated": "False", 
            "TasksOnHold": "False", 
            "Stat_SLAResolutionBreached": "False", 
            "NextStatusText": "Begin Work", 
            "SLA_Key": "_Incident", 
            "CIDowntimeInMinutes": "0.00", 
            "Withdraw": "False", 
            "CustomerSubscriptionLevel": "", 
            "CombinedKB": "", 
            "SCTFired": "False", 
            "PublicId": "10195", 
            "SCTRecID": "", 
            "Stat_DateTimeReOpened": "", 
            "SLAIDForCI": "", 
            "CreatedDuring": "Only on weekends", 
            "ApprovalBlockID": "", 
            "TotalSTCTimeInMinutes": "0", 
            "OwnedBy": "", 
            "CloseDescription": "", 
            "SLANameForCustomer": "", 
            "Impact": "", 
            "PortalAltContactInfo": "", 
            "Stat_DateTimeAssigned": "", 
            "Stat_ResponseTime": "0", 
            "DefaultTeam": "", 
            "PendingReason": "", 
            "SLAName": "Corporate", 
            "SLAResponseWarning": "4/29/2019 9:45:00 AM", 
            "Priority": "3", 
            "Source": "Phone", 
            "Location": "", 
            "LinkedSLAs": " ,  , ", 
            "ServiceCatalogTemplateName": "", 
            "ServiceCartID": "", 
            "CustomerDisplayName": "Playbook customer", 
            "ClosedBy": "", 
            "ClonedIncident": "", 
            "ChangeID": "", 
            "CreatedDateTime": "4/28/2019 10:46:00 AM", 
            "NextStatus": "In Progress", 
            "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f", 
            "ConfigItemTypeID": "", 
            "STCTimeInMinutes": "0", 
            "LastModifiedDateTime": "4/28/2019 10:46:00 AM", 
            "ConfigItemRecID": "", 
            "PendingStartDateTime": "", 
            "MajorIncidentID": "", 
            "ServiceID": "", 
            "WasCIDown": "False", 
            "Urgency": "", 
            "Stat_SLAResponseWarning": "False", 
            "Stat_DateTimeInProgress": "", 
            "Stat_FirstCallResolution": "False", 
            "ServiceEntitlements": "", 
            "IncidentchildRecID": "", 
            "ClonedIncidentID": "", 
            "CreatedBy": "API User", 
            "SLAID": "938aad773b01d0140385e84d19aa5205c5acf8c839", 
            "ClosedOn1stCall": "False", 
            "Category": "", 
            "SubcategoryID": "", 
            "Stat_SLAResolutionGood": "False", 
            "SmartClassifySearchString": "", 
            "MajorIncidentRecID": "", 
            "LinkedProblem": "", 
            "TotalTasks": "0.00", 
            "TasksClosed": "False", 
            "PortalAffectsMultipleUsers": "False", 
            "ShowContactInformation": "False", 
            "SLATargetTimeID": "", 
            "Status": "New", 
            "CIDownEndDateTime": "", 
            "TotalTaskTime": "0.00", 
            "Level2EscalationComplete": "True", 
            "Stat_SLAResponseGood": "False", 
            "PendingPreviousStatus": "", 
            "SLAIDForCustomer": "", 
            "Stat_DateTimeResponded": "", 
            "CartItemID": "", 
            "RequesterDepartment": "", 
            "IncidentchildID": "", 
            "RecordId": "944b6ad2180700e3d4006d4b61813cac3f6c505f21", 
            "ReasonForBreach": "", 
            "ClosedDateTime": "", 
            "LastModTimeStamp": "Byte[] Array", 
            "Subcategory": "", 
            "MajorIncident": "False", 
            "Level3EscalationComplete": "True", 
            "TasksInProgress": "False", 
            "SLANameForService": "", 
            "IncidentType": "Incident", 
            "Stat_SLAResponseBreached": "False", 
            "CIDownStartDateTime": "", 
            "IncidentDurationInDays": "0.00", 
            "CreatedByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "RecID": "944b6ad2180700e3d4006d4b61813cac3f6c505f21", 
            "SLAResolveByDeadline": "5/1/2019 10:46:00 AM", 
            "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00", 
            "Cause": "", 
            "Stat_IncidentReopened": "False", 
            "SLANameForCI": "", 
            "Stat_DateTimeResolved": "", 
            "Description": "This incident was created by Cherwell documentation script", 
            "Stat_NumberOfTouches": "2", 
            "OwnedByTeam": "", 
            "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae", 
            "SLAIDForService": "", 
            "BreachNotes": "", 
            "Cost": "0.00", 
            "CustomerRecID": "944b37889fdb5a0e8f519b422095314c29cdbca16a", 
            "ConfigItemType": "", 
            "IncidentID": "10195", 
            "ConfigItemDisplayName": "", 
            "SLAResolutionWarning": "5/1/2019 10:31:00 AM", 
            "Stat_DateTimeClosed": "", 
            "ClosedByID": "", 
            "Stat_24x7ElapsedTime": "0", 
            "Level2EscalationTeam": "", 
            "SLARespondByDeadline": "4/29/2019 10:00:00 AM", 
            "OwnedByID": "", 
            "LastModBy": "API User", 
            "Stat_NumberOfEscalations": "0", 
            "StatusDesc": "", 
            "PendingEndDateTime": "", 
            "Stat_SLAResolutionWarning": "False", 
            "TaskClosedCount": "0", 
            "ServiceCustomerIsEntitled": "False", 
            "OwnedByTeamID": "", 
            "IncidentDurationInHours": "0.00"
        }, 
        {
            "Service": "", 
            "LastModByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "CreatedByEmail": "", 
            "Comments": "", 
            "ShowAllServices": "False", 
            "RecurringIncident": "False", 
            "ReviewByDeadline": "1/1/1900 12:00:00 AM", 
            "PortalAffectsPrimaryFunction": "False", 
            "CustomerTypeID": "", 
            "NextStatusOneStep": "&lt;Trebuchet&gt;&lt;ActionInfoDef ID=\"93d9abdb6242", 
            "OwnedByManager": "", 
            "Level3EscalationTeam": "", 
            "Stat_IncidentEscalated": "False", 
            "TasksOnHold": "False", 
            "Stat_SLAResolutionBreached": "False", 
            "NextStatusText": "Begin Work", 
            "SLA_Key": "_Incident", 
            "CIDowntimeInMinutes": "0.00", 
            "Withdraw": "False", 
            "CustomerSubscriptionLevel": "", 
            "CombinedKB": "", 
            "SCTFired": "False", 
            "PublicId": "10196", 
            "SCTRecID": "", 
            "Stat_DateTimeReOpened": "", 
            "SLAIDForCI": "", 
            "CreatedDuring": "Only on weekends", 
            "ApprovalBlockID": "", 
            "TotalSTCTimeInMinutes": "0", 
            "OwnedBy": "", 
            "CloseDescription": "", 
            "SLANameForCustomer": "", 
            "Impact": "", 
            "PortalAltContactInfo": "", 
            "Stat_DateTimeAssigned": "", 
            "Stat_ResponseTime": "0", 
            "DefaultTeam": "", 
            "PendingReason": "", 
            "SLAName": "Corporate", 
            "SLAResponseWarning": "4/29/2019 9:45:00 AM", 
            "Priority": "3", 
            "Source": "Phone", 
            "Location": "", 
            "LinkedSLAs": " ,  , ", 
            "ServiceCatalogTemplateName": "", 
            "ServiceCartID": "", 
            "CustomerDisplayName": "Playbook customer", 
            "ClosedBy": "", 
            "ClonedIncident": "", 
            "ChangeID": "", 
            "CreatedDateTime": "4/28/2019 10:49:04 AM", 
            "NextStatus": "In Progress", 
            "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f", 
            "ConfigItemTypeID": "", 
            "STCTimeInMinutes": "0", 
            "LastModifiedDateTime": "4/28/2019 10:49:04 AM", 
            "ConfigItemRecID": "", 
            "PendingStartDateTime": "", 
            "MajorIncidentID": "", 
            "ServiceID": "", 
            "WasCIDown": "False", 
            "Urgency": "", 
            "Stat_SLAResponseWarning": "False", 
            "Stat_DateTimeInProgress": "", 
            "Stat_FirstCallResolution": "False", 
            "ServiceEntitlements": "", 
            "IncidentchildRecID": "", 
            "ClonedIncidentID": "", 
            "CreatedBy": "API User", 
            "SLAID": "938aad773b01d0140385e84d19aa5205c5acf8c839", 
            "ClosedOn1stCall": "False", 
            "Category": "", 
            "SubcategoryID": "", 
            "Stat_SLAResolutionGood": "False", 
            "SmartClassifySearchString": "", 
            "MajorIncidentRecID": "", 
            "LinkedProblem": "", 
            "TotalTasks": "0.00", 
            "TasksClosed": "False", 
            "PortalAffectsMultipleUsers": "False", 
            "ShowContactInformation": "False", 
            "SLATargetTimeID": "", 
            "Status": "New", 
            "CIDownEndDateTime": "", 
            "TotalTaskTime": "0.00", 
            "Level2EscalationComplete": "True", 
            "Stat_SLAResponseGood": "False", 
            "PendingPreviousStatus": "", 
            "SLAIDForCustomer": "", 
            "Stat_DateTimeResponded": "", 
            "CartItemID": "", 
            "RequesterDepartment": "", 
            "IncidentchildID": "", 
            "RecordId": "944b6ad94320debe6d94f14c9eab770ccbf16ab981", 
            "ReasonForBreach": "", 
            "ClosedDateTime": "", 
            "LastModTimeStamp": "Byte[] Array", 
            "Subcategory": "", 
            "MajorIncident": "False", 
            "Level3EscalationComplete": "True", 
            "TasksInProgress": "False", 
            "SLANameForService": "", 
            "IncidentType": "Incident", 
            "Stat_SLAResponseBreached": "False", 
            "CIDownStartDateTime": "", 
            "IncidentDurationInDays": "0.00", 
            "CreatedByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "RecID": "944b6ad94320debe6d94f14c9eab770ccbf16ab981", 
            "SLAResolveByDeadline": "5/1/2019 10:49:04 AM", 
            "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00", 
            "Cause": "", 
            "Stat_IncidentReopened": "False", 
            "SLANameForCI": "", 
            "Stat_DateTimeResolved": "", 
            "Description": "This incident was created by Cherwell documentation script", 
            "Stat_NumberOfTouches": "2", 
            "OwnedByTeam": "", 
            "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae", 
            "SLAIDForService": "", 
            "BreachNotes": "", 
            "Cost": "0.00", 
            "CustomerRecID": "944b37889fdb5a0e8f519b422095314c29cdbca16a", 
            "ConfigItemType": "", 
            "IncidentID": "10196", 
            "ConfigItemDisplayName": "", 
            "SLAResolutionWarning": "5/1/2019 10:34:04 AM", 
            "Stat_DateTimeClosed": "", 
            "ClosedByID": "", 
            "Stat_24x7ElapsedTime": "0", 
            "Level2EscalationTeam": "", 
            "SLARespondByDeadline": "4/29/2019 10:00:00 AM", 
            "OwnedByID": "", 
            "LastModBy": "API User", 
            "Stat_NumberOfEscalations": "0", 
            "StatusDesc": "", 
            "PendingEndDateTime": "", 
            "Stat_SLAResolutionWarning": "False", 
            "TaskClosedCount": "0", 
            "ServiceCustomerIsEntitled": "False", 
            "OwnedByTeamID": "", 
            "IncidentDurationInHours": "0.00"
        }, 
        {
            "Service": "", 
            "LastModByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "CreatedByEmail": "", 
            "Comments": "", 
            "ShowAllServices": "False", 
            "RecurringIncident": "False", 
            "ReviewByDeadline": "1/1/1900 12:00:00 AM", 
            "PortalAffectsPrimaryFunction": "False", 
            "CustomerTypeID": "", 
            "NextStatusOneStep": "&lt;Trebuchet&gt;&lt;ActionInfoDef ID=\"93d9abdb6242", 
            "OwnedByManager": "", 
            "Level3EscalationTeam": "", 
            "Stat_IncidentEscalated": "False", 
            "TasksOnHold": "False", 
            "Stat_SLAResolutionBreached": "False", 
            "NextStatusText": "Begin Work", 
            "SLA_Key": "_Incident", 
            "CIDowntimeInMinutes": "0.00", 
            "Withdraw": "False", 
            "CustomerSubscriptionLevel": "", 
            "CombinedKB": "", 
            "SCTFired": "False", 
            "PublicId": "10197", 
            "SCTRecID": "", 
            "Stat_DateTimeReOpened": "", 
            "SLAIDForCI": "", 
            "CreatedDuring": "Only on weekends", 
            "ApprovalBlockID": "", 
            "TotalSTCTimeInMinutes": "0", 
            "OwnedBy": "", 
            "CloseDescription": "", 
            "SLANameForCustomer": "", 
            "Impact": "", 
            "PortalAltContactInfo": "", 
            "Stat_DateTimeAssigned": "", 
            "Stat_ResponseTime": "0", 
            "DefaultTeam": "", 
            "PendingReason": "", 
            "SLAName": "Corporate", 
            "SLAResponseWarning": "4/29/2019 9:45:00 AM", 
            "Priority": "3", 
            "Source": "Phone", 
            "Location": "", 
            "LinkedSLAs": " ,  , ", 
            "ServiceCatalogTemplateName": "", 
            "ServiceCartID": "", 
            "CustomerDisplayName": "Playbook customer", 
            "ClosedBy": "", 
            "ClonedIncident": "", 
            "ChangeID": "", 
            "CreatedDateTime": "4/28/2019 10:50:14 AM", 
            "NextStatus": "In Progress", 
            "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f", 
            "ConfigItemTypeID": "", 
            "STCTimeInMinutes": "0", 
            "LastModifiedDateTime": "4/28/2019 10:50:14 AM", 
            "ConfigItemRecID": "", 
            "PendingStartDateTime": "", 
            "MajorIncidentID": "", 
            "ServiceID": "", 
            "WasCIDown": "False", 
            "Urgency": "", 
            "Stat_SLAResponseWarning": "False", 
            "Stat_DateTimeInProgress": "", 
            "Stat_FirstCallResolution": "False", 
            "ServiceEntitlements": "", 
            "IncidentchildRecID": "", 
            "ClonedIncidentID": "", 
            "CreatedBy": "API User", 
            "SLAID": "938aad773b01d0140385e84d19aa5205c5acf8c839", 
            "ClosedOn1stCall": "False", 
            "Category": "", 
            "SubcategoryID": "", 
            "Stat_SLAResolutionGood": "False", 
            "SmartClassifySearchString": "", 
            "MajorIncidentRecID": "", 
            "LinkedProblem": "", 
            "TotalTasks": "0.00", 
            "TasksClosed": "False", 
            "PortalAffectsMultipleUsers": "False", 
            "ShowContactInformation": "False", 
            "SLATargetTimeID": "", 
            "Status": "New", 
            "CIDownEndDateTime": "", 
            "TotalTaskTime": "0.00", 
            "Level2EscalationComplete": "True", 
            "Stat_SLAResponseGood": "False", 
            "PendingPreviousStatus": "", 
            "SLAIDForCustomer": "", 
            "Stat_DateTimeResponded": "", 
            "CartItemID": "", 
            "RequesterDepartment": "", 
            "IncidentchildID": "", 
            "RecordId": "944b6adc04cf7a9815eca846cab074f00ec7f9e4e1", 
            "ReasonForBreach": "", 
            "ClosedDateTime": "", 
            "LastModTimeStamp": "Byte[] Array", 
            "Subcategory": "", 
            "MajorIncident": "False", 
            "Level3EscalationComplete": "True", 
            "TasksInProgress": "False", 
            "SLANameForService": "", 
            "IncidentType": "Incident", 
            "Stat_SLAResponseBreached": "False", 
            "CIDownStartDateTime": "", 
            "IncidentDurationInDays": "0.00", 
            "CreatedByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "RecID": "944b6adc04cf7a9815eca846cab074f00ec7f9e4e1", 
            "SLAResolveByDeadline": "5/1/2019 10:50:14 AM", 
            "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00", 
            "Cause": "", 
            "Stat_IncidentReopened": "False", 
            "SLANameForCI": "", 
            "Stat_DateTimeResolved": "", 
            "Description": "This incident was created by Cherwell documentation script", 
            "Stat_NumberOfTouches": "2", 
            "OwnedByTeam": "", 
            "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae", 
            "SLAIDForService": "", 
            "BreachNotes": "", 
            "Cost": "0.00", 
            "CustomerRecID": "944b37889fdb5a0e8f519b422095314c29cdbca16a", 
            "ConfigItemType": "", 
            "IncidentID": "10197", 
            "ConfigItemDisplayName": "", 
            "SLAResolutionWarning": "5/1/2019 10:35:14 AM", 
            "Stat_DateTimeClosed": "", 
            "ClosedByID": "", 
            "Stat_24x7ElapsedTime": "0", 
            "Level2EscalationTeam": "", 
            "SLARespondByDeadline": "4/29/2019 10:00:00 AM", 
            "OwnedByID": "", 
            "LastModBy": "API User", 
            "Stat_NumberOfEscalations": "0", 
            "StatusDesc": "", 
            "PendingEndDateTime": "", 
            "Stat_SLAResolutionWarning": "False", 
            "TaskClosedCount": "0", 
            "ServiceCustomerIsEntitled": "False", 
            "OwnedByTeamID": "", 
            "IncidentDurationInHours": "0.00"
        }, 
        {
            "Service": "", 
            "LastModByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "CreatedByEmail": "", 
            "Comments": "", 
            "ShowAllServices": "False", 
            "RecurringIncident": "False", 
            "ReviewByDeadline": "1/1/1900 12:00:00 AM", 
            "PortalAffectsPrimaryFunction": "False", 
            "CustomerTypeID": "", 
            "NextStatusOneStep": "&lt;Trebuchet&gt;&lt;ActionInfoDef ID=\"93d9abdb6242", 
            "OwnedByManager": "", 
            "Level3EscalationTeam": "", 
            "Stat_IncidentEscalated": "False", 
            "TasksOnHold": "False", 
            "Stat_SLAResolutionBreached": "False", 
            "NextStatusText": "Begin Work", 
            "SLA_Key": "_Incident", 
            "CIDowntimeInMinutes": "0.00", 
            "Withdraw": "False", 
            "CustomerSubscriptionLevel": "", 
            "CombinedKB": "", 
            "SCTFired": "False", 
            "PublicId": "10198", 
            "SCTRecID": "", 
            "Stat_DateTimeReOpened": "", 
            "SLAIDForCI": "", 
            "CreatedDuring": "Only on weekends", 
            "ApprovalBlockID": "", 
            "TotalSTCTimeInMinutes": "0", 
            "OwnedBy": "", 
            "CloseDescription": "", 
            "SLANameForCustomer": "", 
            "Impact": "", 
            "PortalAltContactInfo": "", 
            "Stat_DateTimeAssigned": "", 
            "Stat_ResponseTime": "0", 
            "DefaultTeam": "", 
            "PendingReason": "", 
            "SLAName": "Corporate", 
            "SLAResponseWarning": "4/29/2019 9:45:00 AM", 
            "Priority": "3", 
            "Source": "Phone", 
            "Location": "", 
            "LinkedSLAs": " ,  , ", 
            "ServiceCatalogTemplateName": "", 
            "ServiceCartID": "", 
            "CustomerDisplayName": "Playbook customer", 
            "ClosedBy": "", 
            "ClonedIncident": "", 
            "ChangeID": "", 
            "CreatedDateTime": "4/28/2019 10:50:37 AM", 
            "NextStatus": "In Progress", 
            "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f", 
            "ConfigItemTypeID": "", 
            "STCTimeInMinutes": "0", 
            "LastModifiedDateTime": "4/28/2019 10:50:37 AM", 
            "ConfigItemRecID": "", 
            "PendingStartDateTime": "", 
            "MajorIncidentID": "", 
            "ServiceID": "", 
            "WasCIDown": "False", 
            "Urgency": "", 
            "Stat_SLAResponseWarning": "False", 
            "Stat_DateTimeInProgress": "", 
            "Stat_FirstCallResolution": "False", 
            "ServiceEntitlements": "", 
            "IncidentchildRecID": "", 
            "ClonedIncidentID": "", 
            "CreatedBy": "API User", 
            "SLAID": "938aad773b01d0140385e84d19aa5205c5acf8c839", 
            "ClosedOn1stCall": "False", 
            "Category": "", 
            "SubcategoryID": "", 
            "Stat_SLAResolutionGood": "False", 
            "SmartClassifySearchString": "", 
            "MajorIncidentRecID": "", 
            "LinkedProblem": "", 
            "TotalTasks": "0.00", 
            "TasksClosed": "False", 
            "PortalAffectsMultipleUsers": "False", 
            "ShowContactInformation": "False", 
            "SLATargetTimeID": "", 
            "Status": "New", 
            "CIDownEndDateTime": "", 
            "TotalTaskTime": "0.00", 
            "Level2EscalationComplete": "True", 
            "Stat_SLAResponseGood": "False", 
            "PendingPreviousStatus": "", 
            "SLAIDForCustomer": "", 
            "Stat_DateTimeResponded": "", 
            "CartItemID": "", 
            "RequesterDepartment": "", 
            "IncidentchildID": "", 
            "RecordId": "944b6adcea4815e9e43fd64fa691d39ec58eb78db3", 
            "ReasonForBreach": "", 
            "ClosedDateTime": "", 
            "LastModTimeStamp": "Byte[] Array", 
            "Subcategory": "", 
            "MajorIncident": "False", 
            "Level3EscalationComplete": "True", 
            "TasksInProgress": "False", 
            "SLANameForService": "", 
            "IncidentType": "Incident", 
            "Stat_SLAResponseBreached": "False", 
            "CIDownStartDateTime": "", 
            "IncidentDurationInDays": "0.00", 
            "CreatedByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "RecID": "944b6adcea4815e9e43fd64fa691d39ec58eb78db3", 
            "SLAResolveByDeadline": "5/1/2019 10:50:37 AM", 
            "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00", 
            "Cause": "", 
            "Stat_IncidentReopened": "False", 
            "SLANameForCI": "", 
            "Stat_DateTimeResolved": "", 
            "Description": "This incident was created by Cherwell documentation script", 
            "Stat_NumberOfTouches": "2", 
            "OwnedByTeam": "", 
            "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae", 
            "SLAIDForService": "", 
            "BreachNotes": "", 
            "Cost": "0.00", 
            "CustomerRecID": "944b37889fdb5a0e8f519b422095314c29cdbca16a", 
            "ConfigItemType": "", 
            "IncidentID": "10198", 
            "ConfigItemDisplayName": "", 
            "SLAResolutionWarning": "5/1/2019 10:35:37 AM", 
            "Stat_DateTimeClosed": "", 
            "ClosedByID": "", 
            "Stat_24x7ElapsedTime": "0", 
            "Level2EscalationTeam": "", 
            "SLARespondByDeadline": "4/29/2019 10:00:00 AM", 
            "OwnedByID": "", 
            "LastModBy": "API User", 
            "Stat_NumberOfEscalations": "0", 
            "StatusDesc": "", 
            "PendingEndDateTime": "", 
            "Stat_SLAResolutionWarning": "False", 
            "TaskClosedCount": "0", 
            "ServiceCustomerIsEntitled": "False", 
            "OwnedByTeamID": "", 
            "IncidentDurationInHours": "0.00"
        }, 
        {
            "Service": "", 
            "LastModByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "CreatedByEmail": "", 
            "Comments": "", 
            "ShowAllServices": "False", 
            "RecurringIncident": "False", 
            "ReviewByDeadline": "1/1/1900 12:00:00 AM", 
            "PortalAffectsPrimaryFunction": "False", 
            "CustomerTypeID": "", 
            "NextStatusOneStep": "&lt;Trebuchet&gt;&lt;ActionInfoDef ID=\"93d9abdb6242", 
            "OwnedByManager": "", 
            "Level3EscalationTeam": "", 
            "Stat_IncidentEscalated": "False", 
            "TasksOnHold": "False", 
            "Stat_SLAResolutionBreached": "False", 
            "NextStatusText": "Begin Work", 
            "SLA_Key": "_Incident", 
            "CIDowntimeInMinutes": "0.00", 
            "Withdraw": "False", 
            "CustomerSubscriptionLevel": "", 
            "CombinedKB": "", 
            "SCTFired": "False", 
            "PublicId": "10199", 
            "SCTRecID": "", 
            "Stat_DateTimeReOpened": "", 
            "SLAIDForCI": "", 
            "CreatedDuring": "Only on weekends", 
            "ApprovalBlockID": "", 
            "TotalSTCTimeInMinutes": "0", 
            "OwnedBy": "", 
            "CloseDescription": "", 
            "SLANameForCustomer": "", 
            "Impact": "", 
            "PortalAltContactInfo": "", 
            "Stat_DateTimeAssigned": "", 
            "Stat_ResponseTime": "0", 
            "DefaultTeam": "", 
            "PendingReason": "", 
            "SLAName": "Corporate", 
            "SLAResponseWarning": "4/29/2019 9:45:00 AM", 
            "Priority": "3", 
            "Source": "Phone", 
            "Location": "", 
            "LinkedSLAs": " ,  , ", 
            "ServiceCatalogTemplateName": "", 
            "ServiceCartID": "", 
            "CustomerDisplayName": "Playbook customer", 
            "ClosedBy": "", 
            "ClonedIncident": "", 
            "ChangeID": "", 
            "CreatedDateTime": "4/28/2019 10:52:09 AM", 
            "NextStatus": "In Progress", 
            "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f", 
            "ConfigItemTypeID": "", 
            "STCTimeInMinutes": "0", 
            "LastModifiedDateTime": "4/28/2019 10:52:09 AM", 
            "ConfigItemRecID": "", 
            "PendingStartDateTime": "", 
            "MajorIncidentID": "", 
            "ServiceID": "", 
            "WasCIDown": "False", 
            "Urgency": "", 
            "Stat_SLAResponseWarning": "False", 
            "Stat_DateTimeInProgress": "", 
            "Stat_FirstCallResolution": "False", 
            "ServiceEntitlements": "", 
            "IncidentchildRecID": "", 
            "ClonedIncidentID": "", 
            "CreatedBy": "API User", 
            "SLAID": "938aad773b01d0140385e84d19aa5205c5acf8c839", 
            "ClosedOn1stCall": "False", 
            "Category": "", 
            "SubcategoryID": "", 
            "Stat_SLAResolutionGood": "False", 
            "SmartClassifySearchString": "", 
            "MajorIncidentRecID": "", 
            "LinkedProblem": "", 
            "TotalTasks": "0.00", 
            "TasksClosed": "False", 
            "PortalAffectsMultipleUsers": "False", 
            "ShowContactInformation": "False", 
            "SLATargetTimeID": "", 
            "Status": "New", 
            "CIDownEndDateTime": "", 
            "TotalTaskTime": "0.00", 
            "Level2EscalationComplete": "True", 
            "Stat_SLAResponseGood": "False", 
            "PendingPreviousStatus": "", 
            "SLAIDForCustomer": "", 
            "Stat_DateTimeResponded": "", 
            "CartItemID": "", 
            "RequesterDepartment": "", 
            "IncidentchildID": "", 
            "RecordId": "944b6ae081fc6b7a7f28144ce5b844ceada8cb9c10", 
            "ReasonForBreach": "", 
            "ClosedDateTime": "", 
            "LastModTimeStamp": "Byte[] Array", 
            "Subcategory": "", 
            "MajorIncident": "False", 
            "Level3EscalationComplete": "True", 
            "TasksInProgress": "False", 
            "SLANameForService": "", 
            "IncidentType": "Incident", 
            "Stat_SLAResponseBreached": "False", 
            "CIDownStartDateTime": "", 
            "IncidentDurationInDays": "0.00", 
            "CreatedByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "RecID": "944b6ae081fc6b7a7f28144ce5b844ceada8cb9c10", 
            "SLAResolveByDeadline": "5/1/2019 10:52:09 AM", 
            "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00", 
            "Cause": "", 
            "Stat_IncidentReopened": "False", 
            "SLANameForCI": "", 
            "Stat_DateTimeResolved": "", 
            "Description": "This incident was created by Cherwell documentation script", 
            "Stat_NumberOfTouches": "2", 
            "OwnedByTeam": "", 
            "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae", 
            "SLAIDForService": "", 
            "BreachNotes": "", 
            "Cost": "0.00", 
            "CustomerRecID": "944b37889fdb5a0e8f519b422095314c29cdbca16a", 
            "ConfigItemType": "", 
            "IncidentID": "10199", 
            "ConfigItemDisplayName": "", 
            "SLAResolutionWarning": "5/1/2019 10:37:09 AM", 
            "Stat_DateTimeClosed": "", 
            "ClosedByID": "", 
            "Stat_24x7ElapsedTime": "0", 
            "Level2EscalationTeam": "", 
            "SLARespondByDeadline": "4/29/2019 10:00:00 AM", 
            "OwnedByID": "", 
            "LastModBy": "API User", 
            "Stat_NumberOfEscalations": "0", 
            "StatusDesc": "", 
            "PendingEndDateTime": "", 
            "Stat_SLAResolutionWarning": "False", 
            "TaskClosedCount": "0", 
            "ServiceCustomerIsEntitled": "False", 
            "OwnedByTeamID": "", 
            "IncidentDurationInHours": "0.00"
        }, 
        {
            "Service": "", 
            "LastModByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "CreatedByEmail": "", 
            "Comments": "", 
            "ShowAllServices": "False", 
            "RecurringIncident": "False", 
            "ReviewByDeadline": "1/1/1900 12:00:00 AM", 
            "PortalAffectsPrimaryFunction": "False", 
            "CustomerTypeID": "", 
            "NextStatusOneStep": "&lt;Trebuchet&gt;&lt;ActionInfoDef ID=\"93d9abdb6242", 
            "OwnedByManager": "", 
            "Level3EscalationTeam": "", 
            "Stat_IncidentEscalated": "False", 
            "TasksOnHold": "False", 
            "Stat_SLAResolutionBreached": "False", 
            "NextStatusText": "Begin Work", 
            "SLA_Key": "_Incident", 
            "CIDowntimeInMinutes": "0.00", 
            "Withdraw": "False", 
            "CustomerSubscriptionLevel": "", 
            "CombinedKB": "", 
            "SCTFired": "False", 
            "PublicId": "10200", 
            "SCTRecID": "", 
            "Stat_DateTimeReOpened": "", 
            "SLAIDForCI": "", 
            "CreatedDuring": "Only on weekends", 
            "ApprovalBlockID": "", 
            "TotalSTCTimeInMinutes": "0", 
            "OwnedBy": "", 
            "CloseDescription": "", 
            "SLANameForCustomer": "", 
            "Impact": "", 
            "PortalAltContactInfo": "", 
            "Stat_DateTimeAssigned": "", 
            "Stat_ResponseTime": "0", 
            "DefaultTeam": "", 
            "PendingReason": "", 
            "SLAName": "Corporate", 
            "SLAResponseWarning": "4/29/2019 9:45:00 AM", 
            "Priority": "3", 
            "Source": "Phone", 
            "Location": "", 
            "LinkedSLAs": " ,  , ", 
            "ServiceCatalogTemplateName": "", 
            "ServiceCartID": "", 
            "CustomerDisplayName": "Playbook customer", 
            "ClosedBy": "", 
            "ClonedIncident": "", 
            "ChangeID": "", 
            "CreatedDateTime": "4/28/2019 10:54:10 AM", 
            "NextStatus": "In Progress", 
            "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f", 
            "ConfigItemTypeID": "", 
            "STCTimeInMinutes": "0", 
            "LastModifiedDateTime": "4/28/2019 10:54:10 AM", 
            "ConfigItemRecID": "", 
            "PendingStartDateTime": "", 
            "MajorIncidentID": "", 
            "ServiceID": "", 
            "WasCIDown": "False", 
            "Urgency": "", 
            "Stat_SLAResponseWarning": "False", 
            "Stat_DateTimeInProgress": "", 
            "Stat_FirstCallResolution": "False", 
            "ServiceEntitlements": "", 
            "IncidentchildRecID": "", 
            "ClonedIncidentID": "", 
            "CreatedBy": "API User", 
            "SLAID": "938aad773b01d0140385e84d19aa5205c5acf8c839", 
            "ClosedOn1stCall": "False", 
            "Category": "", 
            "SubcategoryID": "", 
            "Stat_SLAResolutionGood": "False", 
            "SmartClassifySearchString": "", 
            "MajorIncidentRecID": "", 
            "LinkedProblem": "", 
            "TotalTasks": "0.00", 
            "TasksClosed": "False", 
            "PortalAffectsMultipleUsers": "False", 
            "ShowContactInformation": "False", 
            "SLATargetTimeID": "", 
            "Status": "New", 
            "CIDownEndDateTime": "", 
            "TotalTaskTime": "0.00", 
            "Level2EscalationComplete": "True", 
            "Stat_SLAResponseGood": "False", 
            "PendingPreviousStatus": "", 
            "SLAIDForCustomer": "", 
            "Stat_DateTimeResponded": "", 
            "CartItemID": "", 
            "RequesterDepartment": "", 
            "IncidentchildID": "", 
            "RecordId": "944b6ae5343bba7bc4c4fc43709d223378c3ae6dcb", 
            "ReasonForBreach": "", 
            "ClosedDateTime": "", 
            "LastModTimeStamp": "Byte[] Array", 
            "Subcategory": "", 
            "MajorIncident": "False", 
            "Level3EscalationComplete": "True", 
            "TasksInProgress": "False", 
            "SLANameForService": "", 
            "IncidentType": "Incident", 
            "Stat_SLAResponseBreached": "False", 
            "CIDownStartDateTime": "", 
            "IncidentDurationInDays": "0.00", 
            "CreatedByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "RecID": "944b6ae5343bba7bc4c4fc43709d223378c3ae6dcb", 
            "SLAResolveByDeadline": "5/1/2019 10:54:10 AM", 
            "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00", 
            "Cause": "", 
            "Stat_IncidentReopened": "False", 
            "SLANameForCI": "", 
            "Stat_DateTimeResolved": "", 
            "Description": "This incident was created by Cherwell documentation script", 
            "Stat_NumberOfTouches": "2", 
            "OwnedByTeam": "", 
            "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae", 
            "SLAIDForService": "", 
            "BreachNotes": "", 
            "Cost": "0.00", 
            "CustomerRecID": "944b37889fdb5a0e8f519b422095314c29cdbca16a", 
            "ConfigItemType": "", 
            "IncidentID": "10200", 
            "ConfigItemDisplayName": "", 
            "SLAResolutionWarning": "5/1/2019 10:39:10 AM", 
            "Stat_DateTimeClosed": "", 
            "ClosedByID": "", 
            "Stat_24x7ElapsedTime": "0", 
            "Level2EscalationTeam": "", 
            "SLARespondByDeadline": "4/29/2019 10:00:00 AM", 
            "OwnedByID": "", 
            "LastModBy": "API User", 
            "Stat_NumberOfEscalations": "0", 
            "StatusDesc": "", 
            "PendingEndDateTime": "", 
            "Stat_SLAResolutionWarning": "False", 
            "TaskClosedCount": "0", 
            "ServiceCustomerIsEntitled": "False", 
            "OwnedByTeamID": "", 
            "IncidentDurationInHours": "0.00"
        }, 
        {
            "Service": "", 
            "LastModByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "CreatedByEmail": "", 
            "Comments": "", 
            "ShowAllServices": "False", 
            "RecurringIncident": "False", 
            "ReviewByDeadline": "1/1/1900 12:00:00 AM", 
            "PortalAffectsPrimaryFunction": "False", 
            "CustomerTypeID": "", 
            "NextStatusOneStep": "&lt;Trebuchet&gt;&lt;ActionInfoDef ID=\"93d9abdb6242", 
            "OwnedByManager": "", 
            "Level3EscalationTeam": "", 
            "Stat_IncidentEscalated": "False", 
            "TasksOnHold": "False", 
            "Stat_SLAResolutionBreached": "False", 
            "NextStatusText": "Begin Work", 
            "SLA_Key": "_Incident", 
            "CIDowntimeInMinutes": "0.00", 
            "Withdraw": "False", 
            "CustomerSubscriptionLevel": "", 
            "CombinedKB": "", 
            "SCTFired": "False", 
            "PublicId": "10221", 
            "SCTRecID": "", 
            "Stat_DateTimeReOpened": "", 
            "SLAIDForCI": "", 
            "CreatedDuring": "Only on weekends", 
            "ApprovalBlockID": "", 
            "TotalSTCTimeInMinutes": "0", 
            "OwnedBy": "", 
            "CloseDescription": "", 
            "SLANameForCustomer": "", 
            "Impact": "", 
            "PortalAltContactInfo": "", 
            "Stat_DateTimeAssigned": "", 
            "Stat_ResponseTime": "0", 
            "DefaultTeam": "", 
            "PendingReason": "", 
            "SLAName": "Corporate", 
            "SLAResponseWarning": "4/29/2019 9:45:00 AM", 
            "Priority": "3", 
            "Source": "Phone", 
            "Location": "", 
            "LinkedSLAs": " ,  , ", 
            "ServiceCatalogTemplateName": "", 
            "ServiceCartID": "", 
            "CustomerDisplayName": "Playbook customer", 
            "ClosedBy": "", 
            "ClonedIncident": "", 
            "ChangeID": "", 
            "CreatedDateTime": "4/28/2019 1:55:55 PM", 
            "NextStatus": "In Progress", 
            "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f", 
            "ConfigItemTypeID": "", 
            "STCTimeInMinutes": "0", 
            "LastModifiedDateTime": "4/28/2019 1:55:55 PM", 
            "ConfigItemRecID": "", 
            "PendingStartDateTime": "", 
            "MajorIncidentID": "", 
            "ServiceID": "", 
            "WasCIDown": "False", 
            "Urgency": "", 
            "Stat_SLAResponseWarning": "False", 
            "Stat_DateTimeInProgress": "", 
            "Stat_FirstCallResolution": "False", 
            "ServiceEntitlements": "", 
            "IncidentchildRecID": "", 
            "ClonedIncidentID": "", 
            "CreatedBy": "API User", 
            "SLAID": "938aad773b01d0140385e84d19aa5205c5acf8c839", 
            "ClosedOn1stCall": "False", 
            "Category": "", 
            "SubcategoryID": "", 
            "Stat_SLAResolutionGood": "False", 
            "SmartClassifySearchString": "", 
            "MajorIncidentRecID": "", 
            "LinkedProblem": "", 
            "TotalTasks": "0.00", 
            "TasksClosed": "False", 
            "PortalAffectsMultipleUsers": "False", 
            "ShowContactInformation": "False", 
            "SLATargetTimeID": "", 
            "Status": "New", 
            "CIDownEndDateTime": "", 
            "TotalTaskTime": "0.00", 
            "Level2EscalationComplete": "True", 
            "Stat_SLAResponseGood": "False", 
            "PendingPreviousStatus": "", 
            "SLAIDForCustomer": "", 
            "Stat_DateTimeResponded": "", 
            "CartItemID": "", 
            "RequesterDepartment": "", 
            "IncidentchildID": "", 
            "RecordId": "944b6c8f3610a630a0feb04bae8d72e73760921611", 
            "ReasonForBreach": "", 
            "ClosedDateTime": "", 
            "LastModTimeStamp": "Byte[] Array", 
            "Subcategory": "", 
            "MajorIncident": "False", 
            "Level3EscalationComplete": "True", 
            "TasksInProgress": "False", 
            "SLANameForService": "", 
            "IncidentType": "Incident", 
            "Stat_SLAResponseBreached": "False", 
            "CIDownStartDateTime": "", 
            "IncidentDurationInDays": "0.00", 
            "CreatedByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "RecID": "944b6c8f3610a630a0feb04bae8d72e73760921611", 
            "SLAResolveByDeadline": "5/1/2019 1:55:55 PM", 
            "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00", 
            "Cause": "", 
            "Stat_IncidentReopened": "False", 
            "SLANameForCI": "", 
            "Stat_DateTimeResolved": "", 
            "Description": "This incident was created by Cherwell documentation script", 
            "Stat_NumberOfTouches": "2", 
            "OwnedByTeam": "", 
            "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae", 
            "SLAIDForService": "", 
            "BreachNotes": "", 
            "Cost": "0.00", 
            "CustomerRecID": "944b37889fdb5a0e8f519b422095314c29cdbca16a", 
            "ConfigItemType": "", 
            "IncidentID": "10221", 
            "ConfigItemDisplayName": "", 
            "SLAResolutionWarning": "5/1/2019 1:40:55 PM", 
            "Stat_DateTimeClosed": "", 
            "ClosedByID": "", 
            "Stat_24x7ElapsedTime": "0", 
            "Level2EscalationTeam": "", 
            "SLARespondByDeadline": "4/29/2019 10:00:00 AM", 
            "OwnedByID": "", 
            "LastModBy": "API User", 
            "Stat_NumberOfEscalations": "0", 
            "StatusDesc": "", 
            "PendingEndDateTime": "", 
            "Stat_SLAResolutionWarning": "False", 
            "TaskClosedCount": "0", 
            "ServiceCustomerIsEntitled": "False", 
            "OwnedByTeamID": "", 
            "IncidentDurationInHours": "0.00"
        }, 
        {
            "Service": "", 
            "LastModByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "CreatedByEmail": "", 
            "Comments": "", 
            "ShowAllServices": "False", 
            "RecurringIncident": "False", 
            "ReviewByDeadline": "1/1/1900 12:00:00 AM", 
            "PortalAffectsPrimaryFunction": "False", 
            "CustomerTypeID": "", 
            "NextStatusOneStep": "&lt;Trebuchet&gt;&lt;ActionInfoDef ID=\"93d9abdb6242", 
            "OwnedByManager": "", 
            "Level3EscalationTeam": "", 
            "Stat_IncidentEscalated": "False", 
            "TasksOnHold": "False", 
            "Stat_SLAResolutionBreached": "False", 
            "NextStatusText": "Begin Work", 
            "SLA_Key": "_Incident", 
            "CIDowntimeInMinutes": "0.00", 
            "Withdraw": "False", 
            "CustomerSubscriptionLevel": "", 
            "CombinedKB": "", 
            "SCTFired": "False", 
            "PublicId": "10222", 
            "SCTRecID": "", 
            "Stat_DateTimeReOpened": "", 
            "SLAIDForCI": "", 
            "CreatedDuring": "Only on weekends", 
            "ApprovalBlockID": "", 
            "TotalSTCTimeInMinutes": "0", 
            "OwnedBy": "", 
            "CloseDescription": "", 
            "SLANameForCustomer": "", 
            "Impact": "", 
            "PortalAltContactInfo": "", 
            "Stat_DateTimeAssigned": "", 
            "Stat_ResponseTime": "0", 
            "DefaultTeam": "", 
            "PendingReason": "", 
            "SLAName": "Corporate", 
            "SLAResponseWarning": "4/29/2019 9:45:00 AM", 
            "Priority": "3", 
            "Source": "Phone", 
            "Location": "", 
            "LinkedSLAs": " ,  , ", 
            "ServiceCatalogTemplateName": "", 
            "ServiceCartID": "", 
            "CustomerDisplayName": "Playbook customer", 
            "ClosedBy": "", 
            "ClonedIncident": "", 
            "ChangeID": "", 
            "CreatedDateTime": "4/28/2019 1:57:37 PM", 
            "NextStatus": "In Progress", 
            "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f", 
            "ConfigItemTypeID": "", 
            "STCTimeInMinutes": "0", 
            "LastModifiedDateTime": "4/28/2019 1:57:37 PM", 
            "ConfigItemRecID": "", 
            "PendingStartDateTime": "", 
            "MajorIncidentID": "", 
            "ServiceID": "", 
            "WasCIDown": "False", 
            "Urgency": "", 
            "Stat_SLAResponseWarning": "False", 
            "Stat_DateTimeInProgress": "", 
            "Stat_FirstCallResolution": "False", 
            "ServiceEntitlements": "", 
            "IncidentchildRecID": "", 
            "ClonedIncidentID": "", 
            "CreatedBy": "API User", 
            "SLAID": "938aad773b01d0140385e84d19aa5205c5acf8c839", 
            "ClosedOn1stCall": "False", 
            "Category": "", 
            "SubcategoryID": "", 
            "Stat_SLAResolutionGood": "False", 
            "SmartClassifySearchString": "", 
            "MajorIncidentRecID": "", 
            "LinkedProblem": "", 
            "TotalTasks": "0.00", 
            "TasksClosed": "False", 
            "PortalAffectsMultipleUsers": "False", 
            "ShowContactInformation": "False", 
            "SLATargetTimeID": "", 
            "Status": "New", 
            "CIDownEndDateTime": "", 
            "TotalTaskTime": "0.00", 
            "Level2EscalationComplete": "True", 
            "Stat_SLAResponseGood": "False", 
            "PendingPreviousStatus": "", 
            "SLAIDForCustomer": "", 
            "Stat_DateTimeResponded": "", 
            "CartItemID": "", 
            "RequesterDepartment": "", 
            "IncidentchildID": "", 
            "RecordId": "944b6c9333fea00cf4a25b40b08542bdcb4db64327", 
            "ReasonForBreach": "", 
            "ClosedDateTime": "", 
            "LastModTimeStamp": "Byte[] Array", 
            "Subcategory": "", 
            "MajorIncident": "False", 
            "Level3EscalationComplete": "True", 
            "TasksInProgress": "False", 
            "SLANameForService": "", 
            "IncidentType": "Incident", 
            "Stat_SLAResponseBreached": "False", 
            "CIDownStartDateTime": "", 
            "IncidentDurationInDays": "0.00", 
            "CreatedByID": "944856551f982d9572dcf549a4a5d8811f02075fd5", 
            "RecID": "944b6c9333fea00cf4a25b40b08542bdcb4db64327", 
            "SLAResolveByDeadline": "5/1/2019 1:57:37 PM", 
            "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00", 
            "Cause": "", 
            "Stat_IncidentReopened": "False", 
            "SLANameForCI": "", 
            "Stat_DateTimeResolved": "", 
            "Description": "This incident was created by Cherwell documentation script", 
            "Stat_NumberOfTouches": "2", 
            "OwnedByTeam": "", 
            "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae", 
            "SLAIDForService": "", 
            "BreachNotes": "", 
            "Cost": "0.00", 
            "CustomerRecID": "944b37889fdb5a0e8f519b422095314c29cdbca16a", 
            "ConfigItemType": "", 
            "IncidentID": "10222", 
            "ConfigItemDisplayName": "", 
            "SLAResolutionWarning": "5/1/2019 1:42:37 PM", 
            "Stat_DateTimeClosed": "", 
            "ClosedByID": "", 
            "Stat_24x7ElapsedTime": "0", 
            "Level2EscalationTeam": "", 
            "SLARespondByDeadline": "4/29/2019 10:00:00 AM", 
            "OwnedByID": "", 
            "LastModBy": "API User", 
            "Stat_NumberOfEscalations": "0", 
            "StatusDesc": "", 
            "PendingEndDateTime": "", 
            "Stat_SLAResolutionWarning": "False", 
            "TaskClosedCount": "0", 
            "ServiceCustomerIsEntitled": "False", 
            "OwnedByTeamID": "", 
            "IncidentDurationInHours": "0.00"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-9">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="query-results">Query Results</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Rec ID</th>
<th>Incident ID</th>
<th>Created Date Time</th>
<th>Created During</th>
<th>Created By</th>
<th>Created By ID</th>
<th>Status</th>
<th>Status Desc</th>
<th>Service</th>
<th>Category</th>
<th>Subcategory</th>
<th>Specifics Type Id</th>
<th>Description</th>
<th>Impact</th>
<th>Urgency</th>
<th>Priority</th>
<th>Closed Date Time</th>
<th>Closed By</th>
<th>Closed By ID</th>
<th>Cost</th>
<th>Last Mod Time Stamp</th>
<th>Owned By Team</th>
<th>Owned By Team ID</th>
<th>Owned By</th>
<th>Owned By ID</th>
<th>Customer Type ID</th>
<th>Customer Rec ID</th>
<th>Close Description</th>
<th>Linked Problem</th>
<th>Last Modified Date Time</th>
<th>Last Mod By</th>
<th>Last Mod By ID</th>
<th>Config Item Type ID</th>
<th>Config Item Rec ID</th>
<th>In cident Duration In Days</th>
<th>Incident Type</th>
<th>SLA Respond By Deadline</th>
<th>SLAID</th>
<th>SLA Name</th>
<th>SLA Target Time ID</th>
<th>SLA Resolve By Deadline</th>
<th>Closed On 1 St Call</th>
<th>Source</th>
<th>Change ID</th>
<th>In cident Duration In Hours</th>
<th>Customer Display Name</th>
<th>Owned By Manager</th>
<th>Created By Email</th>
<th>Pending Reason</th>
<th>Review By Deadline</th>
<th>Stat _ Number Of Touches</th>
<th>Stat _ First Call Resolution</th>
<th>Stat _ Incident Escalated</th>
<th>Stat _ Number Of Escalations</th>
<th>Stat _24 X 7 Elapsed Time</th>
<th>Stat _ Incident Reopened</th>
<th>Stat _ Date Time Responded</th>
<th>Stat _ Response Time</th>
<th>Stat _SLA Response Breached</th>
<th>Stat _SLA Resolution Breached</th>
<th>Service ID</th>
<th>Pending Previous Status</th>
<th>Portal Affects Primary Function</th>
<th>Portal Affects Multiple Users</th>
<th>Portal Alt Contact Info</th>
<th>SLAID For Customer</th>
<th>SLAID For Service</th>
<th>SLAID For CI</th>
<th>Linked SL As</th>
<th>SLA Name For CI</th>
<th>SLA Name For Customer</th>
<th>SLA Name For Service</th>
<th>Reason For Breach</th>
<th>Config Item Display Name</th>
<th>Breach Notes</th>
<th>Show All Services</th>
<th>Show Contact Information</th>
<th>Service Entitlements</th>
<th>Service Customer Is Entitled</th>
<th>Combined KB</th>
<th>Total Tasks</th>
<th>Stat _SLA Resolution Warning</th>
<th>Stat _SLA Response Warning</th>
<th>Stat _SLA Resolution Good</th>
<th>Stat _SLA Response Good</th>
<th>Stat _ Date Time Assigned</th>
<th>Stat _ Date Time In Progress</th>
<th>Stat _ Date Time Resolved</th>
<th>Stat _ Date Time Closed</th>
<th>Stat _ Date Time Re Opened</th>
<th>SLA Response Warning</th>
<th>SLA Resolution Warning</th>
<th>Pending Start Date Time</th>
<th>Pending End Date Time</th>
<th>STC Time In Minutes</th>
<th>Total STC Time In Minutes</th>
<th>Location</th>
<th>Next Status</th>
<th>Next Status Text</th>
<th>Next Status One Step</th>
<th>SLA_ Key</th>
<th>Status ID</th>
<th>Subcategory ID</th>
<th>Smart Classify Search String</th>
<th>Total Task Time</th>
<th>Config Item Type</th>
<th>Approval Block ID</th>
<th>Cloned Incident ID</th>
<th>Recurring Incident</th>
<th>Was CI Down</th>
<th>CI Down Start Date Time</th>
<th>CI Down End Date Time</th>
<th>Major Incident</th>
<th>Major Incident Rec ID</th>
<th>Major Incident ID</th>
<th>Incidentchild ID</th>
<th>Incidentchild Rec ID</th>
<th>Cause</th>
<th>Cloned Incident</th>
<th>Comments</th>
<th>CI Downtime In Minutes</th>
<th>Withdraw</th>
<th>Customer Subscription Level</th>
<th>Service Cart ID</th>
<th>Cart Item ID</th>
<th>SCT Rec ID</th>
<th>Tasks In Progress</th>
<th>Tasks Closed</th>
<th>Task Closed Count</th>
<th>Tasks On Hold</th>
<th>SCT Fired</th>
<th>Requester Department</th>
<th>Level 2 Escalation Complete</th>
<th>Level 3 Escalation Complete</th>
<th>Default Team</th>
<th>Level 2 Escalation Team</th>
<th>Level 3 Escalation Team</th>
<th>Service Catalog Template Name</th>
<th>Business Object Id</th>
<th>Public Id</th>
<th>Record Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>944b6ad2180700e3d4006d4b61813cac3f6c505f21</td>
<td>10195</td>
<td>4/28/2019 10:46:00 AM</td>
<td>Only on weekends</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td>New</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>9398862125defd58a8deea46fe88acc411a96e2b00</td>
<td>This incident was created by Cherwell documentation script</td>
<td> </td>
<td> </td>
<td>3</td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Byte[] Array</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>944b37889fdb5a0e8f519b422095314c29cdbca16a</td>
<td> </td>
<td> </td>
<td>4/28/2019 10:46:00 AM</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Incident</td>
<td>4/29/2019 10:00:00 AM</td>
<td>938aad773b01d0140385e84d19aa5205c5acf8c839</td>
<td>Corporate</td>
<td> </td>
<td>5/1/2019 10:46:00 AM</td>
<td>False</td>
<td>Phone</td>
<td> </td>
<td>0.00</td>
<td>Playbook customer</td>
<td> </td>
<td> </td>
<td> </td>
<td>1/1/1900 12:00:00 AM</td>
<td>2</td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>0</td>
<td>False</td>
<td> </td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>, ,</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td>False</td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>4/29/2019 9:45:00 AM</td>
<td>5/1/2019 10:31:00 AM</td>
<td> </td>
<td> </td>
<td>0</td>
<td>0</td>
<td> </td>
<td>In Progress</td>
<td>Begin Work</td>
<td>&lt;ActionInfoDef ID="93d9abdb6242</td>
<td>_Incident</td>
<td>938729d99cb110f2a6c3e5488ead246422a7cd115f</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td>True</td>
<td>True</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>6dd53665c0c24cab86870a21cf6434ae</td>
<td>10195</td>
<td>944b6ad2180700e3d4006d4b61813cac3f6c505f21</td>
</tr>
<tr>
<td>944b6ad94320debe6d94f14c9eab770ccbf16ab981</td>
<td>10196</td>
<td>4/28/2019 10:49:04 AM</td>
<td>Only on weekends</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td>New</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>9398862125defd58a8deea46fe88acc411a96e2b00</td>
<td>This incident was created by Cherwell documentation script</td>
<td> </td>
<td> </td>
<td>3</td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Byte[] Array</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>944b37889fdb5a0e8f519b422095314c29cdbca16a</td>
<td> </td>
<td> </td>
<td>4/28/2019 10:49:04 AM</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Incident</td>
<td>4/29/2019 10:00:00 AM</td>
<td>938aad773b01d0140385e84d19aa5205c5acf8c839</td>
<td>Corporate</td>
<td> </td>
<td>5/1/2019 10:49:04 AM</td>
<td>False</td>
<td>Phone</td>
<td> </td>
<td>0.00</td>
<td>Playbook customer</td>
<td> </td>
<td> </td>
<td> </td>
<td>1/1/1900 12:00:00 AM</td>
<td>2</td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>0</td>
<td>False</td>
<td> </td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>, ,</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td>False</td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>4/29/2019 9:45:00 AM</td>
<td>5/1/2019 10:34:04 AM</td>
<td> </td>
<td> </td>
<td>0</td>
<td>0</td>
<td> </td>
<td>In Progress</td>
<td>Begin Work</td>
<td>&lt;ActionInfoDef ID="93d9abdb6242</td>
<td>_Incident</td>
<td>938729d99cb110f2a6c3e5488ead246422a7cd115f</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td>True</td>
<td>True</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>6dd53665c0c24cab86870a21cf6434ae</td>
<td>10196</td>
<td>944b6ad94320debe6d94f14c9eab770ccbf16ab981</td>
</tr>
<tr>
<td>944b6adc04cf7a9815eca846cab074f00ec7f9e4e1</td>
<td>10197</td>
<td>4/28/2019 10:50:14 AM</td>
<td>Only on weekends</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td>New</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>9398862125defd58a8deea46fe88acc411a96e2b00</td>
<td>This incident was created by Cherwell documentation script</td>
<td> </td>
<td> </td>
<td>3</td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Byte[] Array</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>944b37889fdb5a0e8f519b422095314c29cdbca16a</td>
<td> </td>
<td> </td>
<td>4/28/2019 10:50:14 AM</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Incident</td>
<td>4/29/2019 10:00:00 AM</td>
<td>938aad773b01d0140385e84d19aa5205c5acf8c839</td>
<td>Corporate</td>
<td> </td>
<td>5/1/2019 10:50:14 AM</td>
<td>False</td>
<td>Phone</td>
<td> </td>
<td>0.00</td>
<td>Playbook customer</td>
<td> </td>
<td> </td>
<td> </td>
<td>1/1/1900 12:00:00 AM</td>
<td>2</td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>0</td>
<td>False</td>
<td> </td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>, ,</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td>False</td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>4/29/2019 9:45:00 AM</td>
<td>5/1/2019 10:35:14 AM</td>
<td> </td>
<td> </td>
<td>0</td>
<td>0</td>
<td> </td>
<td>In Progress</td>
<td>Begin Work</td>
<td>&lt;ActionInfoDef ID="93d9abdb6242</td>
<td>_Incident</td>
<td>938729d99cb110f2a6c3e5488ead246422a7cd115f</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td>True</td>
<td>True</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>6dd53665c0c24cab86870a21cf6434ae</td>
<td>10197</td>
<td>944b6adc04cf7a9815eca846cab074f00ec7f9e4e1</td>
</tr>
<tr>
<td>944b6adcea4815e9e43fd64fa691d39ec58eb78db3</td>
<td>10198</td>
<td>4/28/2019 10:50:37 AM</td>
<td>Only on weekends</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td>New</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>9398862125defd58a8deea46fe88acc411a96e2b00</td>
<td>This incident was created by Cherwell documentation script</td>
<td> </td>
<td> </td>
<td>3</td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Byte[] Array</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>944b37889fdb5a0e8f519b422095314c29cdbca16a</td>
<td> </td>
<td> </td>
<td>4/28/2019 10:50:37 AM</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Incident</td>
<td>4/29/2019 10:00:00 AM</td>
<td>938aad773b01d0140385e84d19aa5205c5acf8c839</td>
<td>Corporate</td>
<td> </td>
<td>5/1/2019 10:50:37 AM</td>
<td>False</td>
<td>Phone</td>
<td> </td>
<td>0.00</td>
<td>Playbook customer</td>
<td> </td>
<td> </td>
<td> </td>
<td>1/1/1900 12:00:00 AM</td>
<td>2</td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>0</td>
<td>False</td>
<td> </td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>, ,</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td>False</td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>4/29/2019 9:45:00 AM</td>
<td>5/1/2019 10:35:37 AM</td>
<td> </td>
<td> </td>
<td>0</td>
<td>0</td>
<td> </td>
<td>In Progress</td>
<td>Begin Work</td>
<td>&lt;ActionInfoDef ID="93d9abdb6242</td>
<td>_Incident</td>
<td>938729d99cb110f2a6c3e5488ead246422a7cd115f</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td>True</td>
<td>True</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>6dd53665c0c24cab86870a21cf6434ae</td>
<td>10198</td>
<td>944b6adcea4815e9e43fd64fa691d39ec58eb78db3</td>
</tr>
<tr>
<td>944b6ae081fc6b7a7f28144ce5b844ceada8cb9c10</td>
<td>10199</td>
<td>4/28/2019 10:52:09 AM</td>
<td>Only on weekends</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td>New</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>9398862125defd58a8deea46fe88acc411a96e2b00</td>
<td>This incident was created by Cherwell documentation script</td>
<td> </td>
<td> </td>
<td>3</td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Byte[] Array</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>944b37889fdb5a0e8f519b422095314c29cdbca16a</td>
<td> </td>
<td> </td>
<td>4/28/2019 10:52:09 AM</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Incident</td>
<td>4/29/2019 10:00:00 AM</td>
<td>938aad773b01d0140385e84d19aa5205c5acf8c839</td>
<td>Corporate</td>
<td> </td>
<td>5/1/2019 10:52:09 AM</td>
<td>False</td>
<td>Phone</td>
<td> </td>
<td>0.00</td>
<td>Playbook customer</td>
<td> </td>
<td> </td>
<td> </td>
<td>1/1/1900 12:00:00 AM</td>
<td>2</td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>0</td>
<td>False</td>
<td> </td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>, ,</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td>False</td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>4/29/2019 9:45:00 AM</td>
<td>5/1/2019 10:37:09 AM</td>
<td> </td>
<td> </td>
<td>0</td>
<td>0</td>
<td> </td>
<td>In Progress</td>
<td>Begin Work</td>
<td>&lt;ActionInfoDef ID="93d9abdb6242</td>
<td>_Incident</td>
<td>938729d99cb110f2a6c3e5488ead246422a7cd115f</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td>True</td>
<td>True</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>6dd53665c0c24cab86870a21cf6434ae</td>
<td>10199</td>
<td>944b6ae081fc6b7a7f28144ce5b844ceada8cb9c10</td>
</tr>
<tr>
<td>944b6ae5343bba7bc4c4fc43709d223378c3ae6dcb</td>
<td>10200</td>
<td>4/28/2019 10:54:10 AM</td>
<td>Only on weekends</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td>New</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>9398862125defd58a8deea46fe88acc411a96e2b00</td>
<td>This incident was created by Cherwell documentation script</td>
<td> </td>
<td> </td>
<td>3</td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Byte[] Array</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>944b37889fdb5a0e8f519b422095314c29cdbca16a</td>
<td> </td>
<td> </td>
<td>4/28/2019 10:54:10 AM</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Incident</td>
<td>4/29/2019 10:00:00 AM</td>
<td>938aad773b01d0140385e84d19aa5205c5acf8c839</td>
<td>Corporate</td>
<td> </td>
<td>5/1/2019 10:54:10 AM</td>
<td>False</td>
<td>Phone</td>
<td> </td>
<td>0.00</td>
<td>Playbook customer</td>
<td> </td>
<td> </td>
<td> </td>
<td>1/1/1900 12:00:00 AM</td>
<td>2</td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>0</td>
<td>False</td>
<td> </td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>, ,</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td>False</td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>4/29/2019 9:45:00 AM</td>
<td>5/1/2019 10:39:10 AM</td>
<td> </td>
<td> </td>
<td>0</td>
<td>0</td>
<td> </td>
<td>In Progress</td>
<td>Begin Work</td>
<td>&lt;ActionInfoDef ID="93d9abdb6242</td>
<td>_Incident</td>
<td>938729d99cb110f2a6c3e5488ead246422a7cd115f</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td>True</td>
<td>True</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>6dd53665c0c24cab86870a21cf6434ae</td>
<td>10200</td>
<td>944b6ae5343bba7bc4c4fc43709d223378c3ae6dcb</td>
</tr>
<tr>
<td>944b6c8f3610a630a0feb04bae8d72e73760921611</td>
<td>10221</td>
<td>4/28/2019 1:55:55 PM</td>
<td>Only on weekends</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td>New</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>9398862125defd58a8deea46fe88acc411a96e2b00</td>
<td>This incident was created by Cherwell documentation script</td>
<td> </td>
<td> </td>
<td>3</td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Byte[] Array</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>944b37889fdb5a0e8f519b422095314c29cdbca16a</td>
<td> </td>
<td> </td>
<td>4/28/2019 1:55:55 PM</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Incident</td>
<td>4/29/2019 10:00:00 AM</td>
<td>938aad773b01d0140385e84d19aa5205c5acf8c839</td>
<td>Corporate</td>
<td> </td>
<td>5/1/2019 1:55:55 PM</td>
<td>False</td>
<td>Phone</td>
<td> </td>
<td>0.00</td>
<td>Playbook customer</td>
<td> </td>
<td> </td>
<td> </td>
<td>1/1/1900 12:00:00 AM</td>
<td>2</td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>0</td>
<td>False</td>
<td> </td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>, ,</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td>False</td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>4/29/2019 9:45:00 AM</td>
<td>5/1/2019 1:40:55 PM</td>
<td> </td>
<td> </td>
<td>0</td>
<td>0</td>
<td> </td>
<td>In Progress</td>
<td>Begin Work</td>
<td>&lt;ActionInfoDef ID="93d9abdb6242</td>
<td>_Incident</td>
<td>938729d99cb110f2a6c3e5488ead246422a7cd115f</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td>True</td>
<td>True</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>6dd53665c0c24cab86870a21cf6434ae</td>
<td>10221</td>
<td>944b6c8f3610a630a0feb04bae8d72e73760921611</td>
</tr>
<tr>
<td>944b6c9333fea00cf4a25b40b08542bdcb4db64327</td>
<td>10222</td>
<td>4/28/2019 1:57:37 PM</td>
<td>Only on weekends</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td>New</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>9398862125defd58a8deea46fe88acc411a96e2b00</td>
<td>This incident was created by Cherwell documentation script</td>
<td> </td>
<td> </td>
<td>3</td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Byte[] Array</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>944b37889fdb5a0e8f519b422095314c29cdbca16a</td>
<td> </td>
<td> </td>
<td>4/28/2019 1:57:37 PM</td>
<td>API User</td>
<td>944856551f982d9572dcf549a4a5d8811f02075fd5</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>Incident</td>
<td>4/29/2019 10:00:00 AM</td>
<td>938aad773b01d0140385e84d19aa5205c5acf8c839</td>
<td>Corporate</td>
<td> </td>
<td>5/1/2019 1:57:37 PM</td>
<td>False</td>
<td>Phone</td>
<td> </td>
<td>0.00</td>
<td>Playbook customer</td>
<td> </td>
<td> </td>
<td> </td>
<td>1/1/1900 12:00:00 AM</td>
<td>2</td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>0</td>
<td>False</td>
<td> </td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>, ,</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td>False</td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>4/29/2019 9:45:00 AM</td>
<td>5/1/2019 1:42:37 PM</td>
<td> </td>
<td> </td>
<td>0</td>
<td>0</td>
<td> </td>
<td>In Progress</td>
<td>Begin Work</td>
<td>&lt;ActionInfoDef ID="93d9abdb6242</td>
<td>_Incident</td>
<td>938729d99cb110f2a6c3e5488ead246422a7cd115f</td>
<td> </td>
<td> </td>
<td>0.00</td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td> </td>
<td> </td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>0.00</td>
<td>False</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>False</td>
<td>False</td>
<td>0</td>
<td>False</td>
<td>False</td>
<td> </td>
<td>True</td>
<td>True</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>6dd53665c0c24cab86870a21cf6434ae</td>
<td>10222</td>
<td>944b6c9333fea00cf4a25b40b08542bdcb4db64327</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-information-for-a-field">12. Get information for a field</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets information for a field, by one of its properties (Name, Display Name or id)</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-11">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-get-field-info</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-11">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 157px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 84px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 157px;">type</td>
<td style="width: 499px;">Business object type, for example: “Incident”.</td>
<td style="width: 84px;">Required</td>
</tr>
<tr>
<td style="width: 157px;">field_property</td>
<td style="width: 499px;">Field property to search by (Name, Display Name, or Field id)</td>
<td style="width: 84px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-11">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 234px;"><strong>Path</strong></th>
<th style="width: 39px;"><strong>Type</strong></th>
<th style="width: 467px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 234px;">Cherwell.FieldInfo.DisplayName</td>
<td style="width: 39px;">String</td>
<td style="width: 467px;">Field display name (as it displays in the Cherwell UI).</td>
</tr>
<tr>
<td style="width: 234px;">Cherwell.FieldInfo.FieldId</td>
<td style="width: 39px;">String</td>
<td style="width: 467px;">Field ID.</td>
</tr>
<tr>
<td style="width: 234px;">Cherwell.FieldInfo.Name</td>
<td style="width: 39px;">String</td>
<td style="width: 467px;">The name to use when working with business object commands.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-11">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-get-field-info field_property=CreatedDateTime type=incident</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-6">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Cherwell.FieldInfo": {
        "FieldId": "c1e86f31eb2c4c5f8e8615a5189e9b19", 
        "DisplayName": "Created Date Time", 
        "Name": "CreatedDateTime"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-10">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="field-info">Field info:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Display Name</th>
<th>Name</th>
<th>Field Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>Created Date Time</td>
<td>CreatedDateTime</td>
<td>c1e86f31eb2c4c5f8e8615a5189e9b19</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="run-a-saved-search">13. Run a saved search</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns the results of a saved search.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-12">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-run-saved-search</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-12">Input</h5>
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
<td style="width: 155px;">association_id</td>
<td style="width: 514px;">Business object association ID for the saved search.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">scope</td>
<td style="width: 514px;">Scope name or ID for the saved search</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">scope_owner</td>
<td style="width: 514px;">Scope owner ID for the saved search. Use “(None)” when no scope owner exists.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">search_name</td>
<td style="width: 514px;">Name of the saved search.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-12">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-12">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-run-saved-search association_id=9355d5ed41e384ff345b014b6cb1c6e748594aea5b scope=Global scope_owner=(None) search_name="All Tasks"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-7">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Cherwell.SearchOperation": [
        {
            "Status": "Closed", 
            "PublicId": "10072", 
            "Description": "", 
            "Title": "GUI", 
            "RecordId": "9449a066635e9e9b3f38444cf5a630ee2724a469b9", 
            "TaskID": "10072", 
            "OwnedBy": "Cherwell Admin", 
            "BusinessObjectId": "942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83"
        }, 
        {
            "Status": "Closed", 
            "PublicId": "10080", 
            "Description": "task description", 
            "Title": "task title", 
            "RecordId": "9449a0862f42722b78b5634c9dbade02e280e52f11", 
            "TaskID": "10080", 
            "OwnedBy": "Cherwell Admin", 
            "BusinessObjectId": "942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83"
        }, 
        {
            "Status": "Closed", 
            "PublicId": "10081", 
            "Description": "task description", 
            "Title": "task title", 
            "RecordId": "9449a08a3efcf1db28326d4dafa22479c37fe09cd5", 
            "TaskID": "10081", 
            "OwnedBy": "Cherwell Admin", 
            "BusinessObjectId": "942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83"
        }, 
        {
            "Status": "Closed", 
            "PublicId": "10082", 
            "Description": "", 
            "Title": "cghgf", 
            "RecordId": "9449b9f04d4b994ccdca0a4f098e92228145c4e72c", 
            "TaskID": "10082", 
            "OwnedBy": "Cherwell Admin", 
            "BusinessObjectId": "942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83"
        }, 
        {
            "Status": "New", 
            "PublicId": "10119", 
            "Description": "", 
            "Title": "title", 
            "RecordId": "944b39a51c706dde2ab37841388cc820859dea8456", 
            "TaskID": "10119", 
            "OwnedBy": "", 
            "BusinessObjectId": "942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83"
        }, 
        {
            "Status": "New", 
            "PublicId": "10001", 
            "Description": "ttt", 
            "Title": "uuut", 
            "RecordId": "9448a4870ffab3ba7ee6724e3ebfa36f011d965145", 
            "TaskID": "10001", 
            "OwnedBy": "Cherwell Admin", 
            "BusinessObjectId": "942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83"
        }, 
        {
            "Status": "New", 
            "PublicId": "10002", 
            "Description": "", 
            "Title": "eqqeqeqe", 
            "RecordId": "9448afb815536a7b3127834539994b9f53c3703ed0", 
            "TaskID": "10002", 
            "OwnedBy": "Cherwell Admin", 
            "BusinessObjectId": "942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83"
        }, 
        {
            "Status": "New", 
            "PublicId": "10021", 
            "Description": "", 
            "Title": "test title", 
            "RecordId": "944977ef42c01c601cb8e745bba719b4a6895f3de4", 
            "TaskID": "10021", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10022", 
            "Description": "", 
            "Title": "test title", 
            "RecordId": "944977f301ccf86baf57eb4c52b4bea85b3682f925", 
            "TaskID": "10022", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10024", 
            "Description": "", 
            "Title": "test title", 
            "RecordId": "9449781896704cd401241b488589c69789bee0fb11", 
            "TaskID": "10024", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10043", 
            "Description": "task description", 
            "Title": "task title", 
            "RecordId": "94499f411b9c13ea5ca97f43da8c94e7328c38be36", 
            "TaskID": "10043", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10053", 
            "Description": "task description", 
            "Title": "task title", 
            "RecordId": "94499f7bb2f1a12ba2987345e8b067a431a57b07e6", 
            "TaskID": "10053", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10057", 
            "Description": "task description", 
            "Title": "task title", 
            "RecordId": "94499f8d63397d8d0a5b5045e495316875a0b631c0", 
            "TaskID": "10057", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10068", 
            "Description": "task description", 
            "Title": "task title", 
            "RecordId": "94499ff511585f36be6b1341a88ac1c73c22d8c8fe", 
            "TaskID": "10068", 
            "OwnedBy": "", 
            "BusinessObjectId": "942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83"
        }, 
        {
            "Status": "New", 
            "PublicId": "10033", 
            "Description": "task description", 
            "Title": "task title", 
            "RecordId": "94499f0468196077abf8c0400da0657dead40d7b6f", 
            "TaskID": "10033", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10120", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b39f4c1306780e78c8041acb93ffbc41fdbd8bc", 
            "TaskID": "10120", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10121", 
            "Description": "Test task generated from scripts test playbook", 
            "Title": "Test task", 
            "RecordId": "944b4393f40916105fe65849c49965481628eea295", 
            "TaskID": "10121", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10122", 
            "Description": "Test task generated from scripts test playbook", 
            "Title": "Test task", 
            "RecordId": "944b439a962359c8824b334fdf8a2bcc40c303a4eb", 
            "TaskID": "10122", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10123", 
            "Description": "Test task generated from scripts test playbook", 
            "Title": "Test task", 
            "RecordId": "944b44510919158936d66a4e5286837c47b25d613c", 
            "TaskID": "10123", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10127", 
            "Description": "Test task generated from scripts test playbook", 
            "Title": "Test task", 
            "RecordId": "944b446f7562049be9f7d44b0783b9644876ab03e5", 
            "TaskID": "10127", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10129", 
            "Description": "Test task generated from scripts test playbook", 
            "Title": "Test task", 
            "RecordId": "944b44894e5d712c9592d5412fb83c546fac5c9688", 
            "TaskID": "10129", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10134", 
            "Description": "Test task generated from scripts test playbook", 
            "Title": "Test task", 
            "RecordId": "944b44a44b6d0c4fb99eb14353a05e5ebda7efb5dc", 
            "TaskID": "10134", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10139", 
            "Description": "Test task generated from scripts test playbook", 
            "Title": "Test task", 
            "RecordId": "944b44d7740f60dc87aa0b4ef6889bd786fb2a2a74", 
            "TaskID": "10139", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10140", 
            "Description": "Test task generated from scripts test playbook", 
            "Title": "Test task", 
            "RecordId": "944b44dbb6c03845eb370644db9ac7d26dd71fad5c", 
            "TaskID": "10140", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10141", 
            "Description": "Test task generated from scripts test playbook", 
            "Title": "Test task", 
            "RecordId": "944b44de9bb7a424100d104f61be2d0374109f8f91", 
            "TaskID": "10141", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10144", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b6991f263b08e435a334b02b43492d8dfefb268", 
            "TaskID": "10144", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10145", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b699e91d6c12cd473cd4a1e963bf60da43025de", 
            "TaskID": "10145", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10146", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b69a268eff7406469e040d2938fbf16bfe85b44", 
            "TaskID": "10146", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10149", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b69a91fcaef0837f77d485c9c528f8509d9716b", 
            "TaskID": "10149", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10150", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b69e47d417d8f8b27b242de8fc03f268a173f66", 
            "TaskID": "10150", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10151", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b69e9f44759a3738d0a4b699e90b50c1b8d6904", 
            "TaskID": "10151", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10152", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b6a8c455a91041f71fb42e2b085e1db50b0c57c", 
            "TaskID": "10152", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10086", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2a2e2265573607dc504d938b9cd1b7b5beb486", 
            "TaskID": "10086", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10087", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2a5cbd9b699c445ae34871b467788b1120540d", 
            "TaskID": "10087", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10088", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2a6e2338721062328f4101bba9db35a61f8f12", 
            "TaskID": "10088", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10089", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2a767fb644f94a92854ee9838b2adf0a845d65", 
            "TaskID": "10089", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10091", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2ca7824f846faff5a24f518568fcd7156032f9", 
            "TaskID": "10091", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10092", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2ceb13f1b5836a1a754f66bc4caf74e8e2a4f3", 
            "TaskID": "10092", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10093", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2d2b96859578d6bcae49ef859d45b952d4eed1", 
            "TaskID": "10093", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10094", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2d2d9bc03300e8c70344d89690885e8506c608", 
            "TaskID": "10094", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10095", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2d4d9bc7ab3df904794b8d934c75ccecfa7c48", 
            "TaskID": "10095", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10096", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2d675563cdc4e9cc964c02b35a57b2a869906e", 
            "TaskID": "10096", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10097", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2d7172a44b3bee37e84ef78c619b66e7481a50", 
            "TaskID": "10097", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10098", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2d7f6d7fda754e799a4cc19e5a04ece36c49b6", 
            "TaskID": "10098", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10099", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2d8a3c57191395d24c4f3ab5d551509e71e611", 
            "TaskID": "10099", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10100", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2d8e7993b1c823cb55460783bc17f6ee308531", 
            "TaskID": "10100", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10101", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2d96470c230f9679af40e1947ed535416993dd", 
            "TaskID": "10101", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10102", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b2da3d661eca663e8f3495ca6f94453887c9004", 
            "TaskID": "10102", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10103", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b36cef67a7d923c0ac545dbb5a0430ec0230d09", 
            "TaskID": "10103", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10104", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b36d7f68da49c3d1ea149b0bdbe199adc79f5f3", 
            "TaskID": "10104", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10105", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b36db46e1ec76e7f2ab49adb58a13d9d14a3f9f", 
            "TaskID": "10105", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10106", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b36ecb3b22b624e678b4109bc4fea7bb5a84191", 
            "TaskID": "10106", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10107", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b36f90e1f8067ee66a74c6d93fc6d15c3e64d95", 
            "TaskID": "10107", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10108", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b37a575da3f72f135204cc7bccf9ed8308e9817", 
            "TaskID": "10108", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10109", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b37dbb8a901685a75e44e77bebec4ea21e28eef", 
            "TaskID": "10109", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10110", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b37e32adba0e59643224d35b5236508eba1298f", 
            "TaskID": "10110", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10111", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b37e5ef64a18ad4804e499d99da4eed9d04b4b2", 
            "TaskID": "10111", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10112", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b37e9a646b27b22fda84570be3dfb80da3d2d00", 
            "TaskID": "10112", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10113", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b37eb4c381f52d524c94e4d99c71d11608683ae", 
            "TaskID": "10113", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10114", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b37fa73d701a44c2e544cd88c21b4a4004cc1d0", 
            "TaskID": "10114", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10115", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b38078bd4c37cde06e34b26bf97ded4482a40d1", 
            "TaskID": "10115", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10116", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b3810de1534bee1d65f4e56a13f25d7d948e55d", 
            "TaskID": "10116", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10117", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b38fd81e400b60a207d428ab9919cdcc8672261", 
            "TaskID": "10117", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }, 
        {
            "Status": "New", 
            "PublicId": "10118", 
            "Description": "Test task generated from test playbook", 
            "Title": "Test task", 
            "RecordId": "944b39100884e09063bfb5435faaeb99bbd12675fd", 
            "TaskID": "10118", 
            "OwnedBy": "", 
            "BusinessObjectId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-11">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="all-tasks-results">All Tasks results:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Task ID</th>
<th>Title</th>
<th>Owned By</th>
<th>Status</th>
<th>Description</th>
<th>Business Object Id</th>
<th>Public Id</th>
<th>Record Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>10072</td>
<td>GUI</td>
<td>Cherwell Admin</td>
<td>Closed</td>
<td> </td>
<td>942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83</td>
<td>10072</td>
<td>9449a066635e9e9b3f38444cf5a630ee2724a469b9</td>
</tr>
<tr>
<td>10080</td>
<td>task title</td>
<td>Cherwell Admin</td>
<td>Closed</td>
<td>task description</td>
<td>942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83</td>
<td>10080</td>
<td>9449a0862f42722b78b5634c9dbade02e280e52f11</td>
</tr>
<tr>
<td>10081</td>
<td>task title</td>
<td>Cherwell Admin</td>
<td>Closed</td>
<td>task description</td>
<td>942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83</td>
<td>10081</td>
<td>9449a08a3efcf1db28326d4dafa22479c37fe09cd5</td>
</tr>
<tr>
<td>10082</td>
<td>cghgf</td>
<td>Cherwell Admin</td>
<td>Closed</td>
<td> </td>
<td>942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83</td>
<td>10082</td>
<td>9449b9f04d4b994ccdca0a4f098e92228145c4e72c</td>
</tr>
<tr>
<td>10119</td>
<td>title</td>
<td> </td>
<td>New</td>
<td> </td>
<td>942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83</td>
<td>10119</td>
<td>944b39a51c706dde2ab37841388cc820859dea8456</td>
</tr>
<tr>
<td>10001</td>
<td>uuut</td>
<td>Cherwell Admin</td>
<td>New</td>
<td>ttt</td>
<td>942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83</td>
<td>10001</td>
<td>9448a4870ffab3ba7ee6724e3ebfa36f011d965145</td>
</tr>
<tr>
<td>10002</td>
<td>eqqeqeqe</td>
<td>Cherwell Admin</td>
<td>New</td>
<td> </td>
<td>942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83</td>
<td>10002</td>
<td>9448afb815536a7b3127834539994b9f53c3703ed0</td>
</tr>
<tr>
<td>10021</td>
<td>test title</td>
<td> </td>
<td>New</td>
<td> </td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10021</td>
<td>944977ef42c01c601cb8e745bba719b4a6895f3de4</td>
</tr>
<tr>
<td>10022</td>
<td>test title</td>
<td> </td>
<td>New</td>
<td> </td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10022</td>
<td>944977f301ccf86baf57eb4c52b4bea85b3682f925</td>
</tr>
<tr>
<td>10024</td>
<td>test title</td>
<td> </td>
<td>New</td>
<td> </td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10024</td>
<td>9449781896704cd401241b488589c69789bee0fb11</td>
</tr>
<tr>
<td>10043</td>
<td>task title</td>
<td> </td>
<td>New</td>
<td>task description</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10043</td>
<td>94499f411b9c13ea5ca97f43da8c94e7328c38be36</td>
</tr>
<tr>
<td>10053</td>
<td>task title</td>
<td> </td>
<td>New</td>
<td>task description</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10053</td>
<td>94499f7bb2f1a12ba2987345e8b067a431a57b07e6</td>
</tr>
<tr>
<td>10057</td>
<td>task title</td>
<td> </td>
<td>New</td>
<td>task description</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10057</td>
<td>94499f8d63397d8d0a5b5045e495316875a0b631c0</td>
</tr>
<tr>
<td>10068</td>
<td>task title</td>
<td> </td>
<td>New</td>
<td>task description</td>
<td>942e71e8c5c493f3e5f2f54f5c9c086719b6bc8d83</td>
<td>10068</td>
<td>94499ff511585f36be6b1341a88ac1c73c22d8c8fe</td>
</tr>
<tr>
<td>10033</td>
<td>task title</td>
<td> </td>
<td>New</td>
<td>task description</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10033</td>
<td>94499f0468196077abf8c0400da0657dead40d7b6f</td>
</tr>
<tr>
<td>10120</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10120</td>
<td>944b39f4c1306780e78c8041acb93ffbc41fdbd8bc</td>
</tr>
<tr>
<td>10121</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from scripts test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10121</td>
<td>944b4393f40916105fe65849c49965481628eea295</td>
</tr>
<tr>
<td>10122</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from scripts test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10122</td>
<td>944b439a962359c8824b334fdf8a2bcc40c303a4eb</td>
</tr>
<tr>
<td>10123</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from scripts test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10123</td>
<td>944b44510919158936d66a4e5286837c47b25d613c</td>
</tr>
<tr>
<td>10127</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from scripts test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10127</td>
<td>944b446f7562049be9f7d44b0783b9644876ab03e5</td>
</tr>
<tr>
<td>10129</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from scripts test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10129</td>
<td>944b44894e5d712c9592d5412fb83c546fac5c9688</td>
</tr>
<tr>
<td>10134</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from scripts test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10134</td>
<td>944b44a44b6d0c4fb99eb14353a05e5ebda7efb5dc</td>
</tr>
<tr>
<td>10139</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from scripts test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10139</td>
<td>944b44d7740f60dc87aa0b4ef6889bd786fb2a2a74</td>
</tr>
<tr>
<td>10140</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from scripts test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10140</td>
<td>944b44dbb6c03845eb370644db9ac7d26dd71fad5c</td>
</tr>
<tr>
<td>10141</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from scripts test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10141</td>
<td>944b44de9bb7a424100d104f61be2d0374109f8f91</td>
</tr>
<tr>
<td>10144</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10144</td>
<td>944b6991f263b08e435a334b02b43492d8dfefb268</td>
</tr>
<tr>
<td>10145</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10145</td>
<td>944b699e91d6c12cd473cd4a1e963bf60da43025de</td>
</tr>
<tr>
<td>10146</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10146</td>
<td>944b69a268eff7406469e040d2938fbf16bfe85b44</td>
</tr>
<tr>
<td>10149</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10149</td>
<td>944b69a91fcaef0837f77d485c9c528f8509d9716b</td>
</tr>
<tr>
<td>10150</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10150</td>
<td>944b69e47d417d8f8b27b242de8fc03f268a173f66</td>
</tr>
<tr>
<td>10151</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10151</td>
<td>944b69e9f44759a3738d0a4b699e90b50c1b8d6904</td>
</tr>
<tr>
<td>10152</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10152</td>
<td>944b6a8c455a91041f71fb42e2b085e1db50b0c57c</td>
</tr>
<tr>
<td>10086</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10086</td>
<td>944b2a2e2265573607dc504d938b9cd1b7b5beb486</td>
</tr>
<tr>
<td>10087</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10087</td>
<td>944b2a5cbd9b699c445ae34871b467788b1120540d</td>
</tr>
<tr>
<td>10088</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10088</td>
<td>944b2a6e2338721062328f4101bba9db35a61f8f12</td>
</tr>
<tr>
<td>10089</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10089</td>
<td>944b2a767fb644f94a92854ee9838b2adf0a845d65</td>
</tr>
<tr>
<td>10091</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10091</td>
<td>944b2ca7824f846faff5a24f518568fcd7156032f9</td>
</tr>
<tr>
<td>10092</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10092</td>
<td>944b2ceb13f1b5836a1a754f66bc4caf74e8e2a4f3</td>
</tr>
<tr>
<td>10093</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10093</td>
<td>944b2d2b96859578d6bcae49ef859d45b952d4eed1</td>
</tr>
<tr>
<td>10094</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10094</td>
<td>944b2d2d9bc03300e8c70344d89690885e8506c608</td>
</tr>
<tr>
<td>10095</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10095</td>
<td>944b2d4d9bc7ab3df904794b8d934c75ccecfa7c48</td>
</tr>
<tr>
<td>10096</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10096</td>
<td>944b2d675563cdc4e9cc964c02b35a57b2a869906e</td>
</tr>
<tr>
<td>10097</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10097</td>
<td>944b2d7172a44b3bee37e84ef78c619b66e7481a50</td>
</tr>
<tr>
<td>10098</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10098</td>
<td>944b2d7f6d7fda754e799a4cc19e5a04ece36c49b6</td>
</tr>
<tr>
<td>10099</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10099</td>
<td>944b2d8a3c57191395d24c4f3ab5d551509e71e611</td>
</tr>
<tr>
<td>10100</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10100</td>
<td>944b2d8e7993b1c823cb55460783bc17f6ee308531</td>
</tr>
<tr>
<td>10101</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10101</td>
<td>944b2d96470c230f9679af40e1947ed535416993dd</td>
</tr>
<tr>
<td>10102</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10102</td>
<td>944b2da3d661eca663e8f3495ca6f94453887c9004</td>
</tr>
<tr>
<td>10103</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10103</td>
<td>944b36cef67a7d923c0ac545dbb5a0430ec0230d09</td>
</tr>
<tr>
<td>10104</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10104</td>
<td>944b36d7f68da49c3d1ea149b0bdbe199adc79f5f3</td>
</tr>
<tr>
<td>10105</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10105</td>
<td>944b36db46e1ec76e7f2ab49adb58a13d9d14a3f9f</td>
</tr>
<tr>
<td>10106</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10106</td>
<td>944b36ecb3b22b624e678b4109bc4fea7bb5a84191</td>
</tr>
<tr>
<td>10107</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10107</td>
<td>944b36f90e1f8067ee66a74c6d93fc6d15c3e64d95</td>
</tr>
<tr>
<td>10108</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10108</td>
<td>944b37a575da3f72f135204cc7bccf9ed8308e9817</td>
</tr>
<tr>
<td>10109</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10109</td>
<td>944b37dbb8a901685a75e44e77bebec4ea21e28eef</td>
</tr>
<tr>
<td>10110</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10110</td>
<td>944b37e32adba0e59643224d35b5236508eba1298f</td>
</tr>
<tr>
<td>10111</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10111</td>
<td>944b37e5ef64a18ad4804e499d99da4eed9d04b4b2</td>
</tr>
<tr>
<td>10112</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10112</td>
<td>944b37e9a646b27b22fda84570be3dfb80da3d2d00</td>
</tr>
<tr>
<td>10113</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10113</td>
<td>944b37eb4c381f52d524c94e4d99c71d11608683ae</td>
</tr>
<tr>
<td>10114</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10114</td>
<td>944b37fa73d701a44c2e544cd88c21b4a4004cc1d0</td>
</tr>
<tr>
<td>10115</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10115</td>
<td>944b38078bd4c37cde06e34b26bf97ded4482a40d1</td>
</tr>
<tr>
<td>10116</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10116</td>
<td>944b3810de1534bee1d65f4e56a13f25d7d948e55d</td>
</tr>
<tr>
<td>10117</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10117</td>
<td>944b38fd81e400b60a207d428ab9919cdcc8672261</td>
</tr>
<tr>
<td>10118</td>
<td>Test task</td>
<td> </td>
<td>New</td>
<td>Test task generated from test playbook</td>
<td>9355d5ed41e384ff345b014b6cb1c6e748594aea5b</td>
<td>10118</td>
<td>944b39100884e09063bfb5435faaeb99bbd12675fd</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-a-business-object-id">14. Get a business object ID</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets a general business object ID by name.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-13">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>cherwell-get-business-object-id</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-13">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 301px;"><strong>Argument Name</strong></th>
<th style="width: 303px;"><strong>Description</strong></th>
<th style="width: 136px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 301px;">business_object_name</td>
<td style="width: 303px;">Business object name.</td>
<td style="width: 136px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-13">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 465px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 212px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 465px;">Cherwell.BusinessObjectInfo.BusinessObjectId</td>
<td style="width: 63px;">String</td>
<td style="width: 212px;">Business object ID.</td>
</tr>
<tr>
<td style="width: 465px;">Cherwell.BusinessObjectInfo.BusinessObjectName</td>
<td style="width: 63px;">String</td>
<td style="width: 212px;">Business object name.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-13">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>cherwell-get-business-object-id business_object_name=incident</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-8">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Cherwell.BusinessObjectInfo": {
        "BusinessObjectName": "incident", 
        "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-12">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="business-object-info">Business Object Info:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Business Object Id</th>
<th>Business Object Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>6dd53665c0c24cab86870a21cf6434ae</td>
<td>incident</td>
</tr>
</tbody>
</table>
</div>
</div>