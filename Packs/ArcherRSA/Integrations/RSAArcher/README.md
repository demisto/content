<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Deprecated. Use the RSA Archer v2 integration instead.</p>
<hr>
<h2>Configure the RSA Archer integration on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for RSA Archer.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong> <font style="vertical-align: inherit;">Server URL</font> </strong></li>
<li><strong>Instance name</strong></li>
<li><strong>Username </strong></li>
<li><strong>Password </strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Timezone offset in minutes of the RSA Archer server machine (+60, -60, in minutes)</strong></li>
<li><strong><span>Application ID for fetch</span></strong></li>
<li><strong><span>The application's base ID. For example "Incident ID"</span></strong></li>
<li><strong><span>fetchFilter - Specific filters for fetching in the form of an xml string</span></strong></li>
<li><strong><span>Use Archer's REST API instead of its SOAP API</span></strong></li>
<li><strong><span>Use European Time format (dd/mm/yyyy) instead of the American one</span></strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>
</ol>
<hr>
<h2>Fetched Incidents Data</h2>
<p>Fetches incidents data from RSA Archer, by using the <code>archer-fetch-incidents</code> command. In the first fetch, the program fetches incidents from the previous day until the time you run the command.</p>
<hr>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_4037375851529412223838">Create a record: archer-create-record</a></li>
<li><a href="#h_914233048261529412549945">Update a record: archer-update-record</a></li>
<li><a href="#h_377947634511529414421607">Get record information: archer-get-record</a></li>
<li><a href="#h_223017324201529414881226">Get application details or list of all applications: archer-search-applications</a></li>
<li><a href="#h_627545777501529417021123">Search for records: archer-search-records</a></li>
<li><a href="#h_679870256851529417291431">Get all application fields: archer-get-application-fields</a></li>
<li><a href="#h_3433767521251529417638918">Delete a record: archer-delete-record</a></li>
<li><a href="#h_6050463921701529488407195">Map list value name to list value ID: archer-get-field</a></li>
<li><a href="#h_5870377172201529489370638">Get all reports: archer-get-reports</a></li>
<li><a href="#h_3865501923301529490045363">Perform statistic search: archer-execute-statistic-search-by-report</a></li>
<li><a href="#h_3375463583901529490543773">Get search criteria: archer-get-search-options-by-guid</a></li>
<li><a href="#h_6267948584551529490882938">Search records by report: archer-search-records-by-report</a></li>
<li><a href="#h_5690460115251529491112217">Get field mapping by level ID: archer-get-mapping-by-level</a></li>
<li><a href="#h_3906877896001529492105590">Fetch Archer incidents: archer-manually-fetch-incident</a></li>
<li><a href="#h_862940326801529492724147">Download Archer file to the War Room: archer-get-file</a></li>
<li><a href="#h_5111225307651529492866353">Upload a file from Cortex XSOAR to Archer: archer-upload-file</a></li>
<li><a href="#h_447548299391529493439939">Add data to the detailed analysis field: archer-add-to-detailed-analysis</a></li>
<li><a href="#h_81021858117391550577986609">Get an Archer user's user ID: archer-get-user-id</a></li>
<li><a href="#h_75316240823191550577993400">Get a list of values for a field: archer-get-valuelist</a></li>
</ol>
<hr>
<h3 id="h_4037375851529412223838">Create a record</h3>
<p>Creates a new content record in a specified application.</p>
<h5>Base Command</h5>
<p><code>archer-create-record</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">applicationId</td>
<td style="width: 460px;">ID of the application to create a record in</td>
</tr>
<tr>
<td style="width: 180px;">fieldsToValues</td>
<td style="width: 460px;">
<p>Record fields in JSON format. Field name is case sensitive.</p>
<p>Example: <code>{ Name1: Value1, Name2: Value2 }</code></p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="height: 306px; width: 664px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 182px;"><strong>Path</strong></td>
<td style="width: 457px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 182px;">Archer.Record.Id</td>
<td style="width: 457px;">Record Content ID</td>
</tr>
<tr>
<td style="width: 182px;">Archer.Record.Fields</td>
<td style="width: 457px;">Record property fields</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-create-record applicationId="75" fieldsToValues="{\"Description\":\"Demisto Fraud Referrer \",\"Date/Time Occurred\":\"3/23/2018 7:00 AM\",\"Date/Time Identified\":\"3/23/2018 7:00 AM\",\"Date/Time Reported\":\"3/23/2018 7:00 AM\",\"Executive Summary\":\"test\", \"Incident Report\": \"test incident report from Demisto\"}"</code></p>
<h5>Raw Output</h5>
<pre>{  
   "Record":{  
      "Fields":{  
         "Date/Time Identified":"3/23/2018 7:00 AM",
         "Date/Time Occurred":"3/23/2018 7:00 AM",
         "Date/Time Reported":"3/23/2018 7:00 AM",
         "Description":"Demisto Fraud Referrer ",
         "Executive Summary":"test",
         "Incident Report":"test incident report from Demisto"
      },
      "Id":"227645"
   }
}</pre>
<hr>
<h3 id="h_914233048261529412549945">Update a record</h3>
<p>Updates an existing content record in a specified application.</p>
<h5>Base Command</h5>
<p><code>archer-update-record</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">contentId</td>
<td style="width: 460px;">Content (record) ID to update</td>
</tr>
<tr>
<td style="width: 180px;">applicationId</td>
<td style="width: 460px;">
<p>ID of the application to update a record in</p>
</td>
</tr>
<tr>
<td style="width: 180px;">fieldsToValues</td>
<td style="width: 460px;">
<p>Record fields in JSON format. Field name is case sensitive.</p>
<p>Example: <code>{ Name1: Value1, Name2: Value2 }</code></p>
</td>
</tr>
<tr>
<td style="width: 180px;">incidentId</td>
<td style="width: 460px;">
<p>Incident ID of the record.</p>
<p>Example: <code>id=12345 for INC-12345</code></p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<p>There is no context data for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-update-record applicationId=433 contentId=227538 fieldsToValues={\"Title\":\"test\"}</code></p>
<h5>Raw Output</h5>
<pre>content id = 227538 was updated successfully.</pre>
<hr>
<h3 id="h_377947634511529414421607">Get record information</h3>
<p>Returns information for a content record in a specified application.</p>
<h5>Base Command</h5>
<p><code>archer-get-record</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">contentId</td>
<td style="width: 460px;">Incident (record) ID to get details for</td>
</tr>
<tr>
<td style="width: 180px;">applicationId</td>
<td style="width: 460px;">ID of the application to get the record from</td>
</tr>
<tr>
<td style="width: 180px;">incidentId</td>
<td style="width: 460px;">
<p>Incident ID of the record.</p>
<p>Example: <code>id=12345 for INC-12345</code></p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="height: 306px; width: 656px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 307px;"><strong>Path</strong></td>
<td style="width: 332px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 307px;">Archer.Record.Id</td>
<td style="width: 332px;">Content ID of the record</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields</td>
<td style="width: 332px;">Content property fields</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Incident Status</td>
<td style="width: 332px;">Incident status</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Record Status</td>
<td style="width: 332px;">Record status</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Last Updated</td>
<td style="width: 332px;">Last updated</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Days Open</td>
<td style="width: 332px;">Days open</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Date Created</td>
<td style="width: 332px;">Date created</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Title</td>
<td style="width: 332px;">Title</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Incident Summary</td>
<td style="width: 332px;">Incident summary</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Threat Category</td>
<td style="width: 332px;">Threat category</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Threat Valid</td>
<td style="width: 332px;">Threat valid</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-get-record applicationId=433 contentId=227538</code></p>
<h5>Raw Output</h5>
<pre>"Record": {
    "Fields": {
      "Actor, Tactics \u0026 Techniques": null,
      "Affected Facility": null,
      "Archive": null,
      "Attach to InfoSec Briefing": null,
      "Attack Category": null,
      "Automatic Incident Handler Access": "SOC: L2 Incident Handler,SOC: L1 Incident Handler",
      "Count of Risks": "0",
      "Count of Risks Increased": "No",
      "Date Created": "2018-02-18T10:45:47+02:00",
      "Date/Time Assigned": null,
      "Date/Time Closed": null,
      "Date/Time Modified": "2018-02-22T14:32:46+02:00",
      "Date/Time Returned": null,
      "Days Open": "0",
      "Generate Incident Response Tasks": "No",
      "Incident Details": null,
      "Incident ID": "227538",
      "Incident ID (DFM)": "227538",
      "Incident ID (KPI)": "227538",
      "Incident Journal": null,
      "Incident Owner": null,
      "Incident Queue": "L1 Incident Handlers",
      "Incident Response Procedures": null,
      "Incident Status": "New",
      "Incident Summary": "inside_record_test_1_summary"...</pre>
<hr>
<h3 id="h_223017324201529414881226">Get application details or list of all applications</h3>
<p>Returns details for an application or a list of all applications.</p>
<h5>Base Command</h5>
<p><code>archer-search-applications</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">findByName</td>
<td style="width: 460px;">Get application by the application name. To return all applications, leave this parameter empty.</td>
</tr>
<tr>
<td style="width: 180px;">findById</td>
<td style="width: 460px;">Get application by the application ID. To return all applications, leave this parameter empty.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="height: 306px; width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 307px;"><strong>Path</strong></td>
<td style="width: 332px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 307px;">Archer.Record.Id</td>
<td style="width: 332px;">Content ID of the record</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields</td>
<td style="width: 332px;">Content property fields</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Incident Status</td>
<td style="width: 332px;">Incident status</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Record Status</td>
<td style="width: 332px;">Record status</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Last Updated</td>
<td style="width: 332px;">Last updated</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Days Open</td>
<td style="width: 332px;">Days open</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Date Created</td>
<td style="width: 332px;">Date created</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Title</td>
<td style="width: 332px;">Title</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Incident Summary</td>
<td style="width: 332px;">Incident summary</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Threat Category</td>
<td style="width: 332px;">Threat category</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields.Threat Valid</td>
<td style="width: 332px;">Threat valid</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-search-applications findById=433</code></p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "Guid":"fa254559-4922-4aea-8d53-66b4e3442585",
      "Id":433,
      "LanguageId":1,
      "Name":"Security Incidents",
      "Status":1,
      "Type":2
   },
   {  
      "Guid":"6fda8f2c-d74d-4bf1-aada-def95cba4aaf",
      "Id":17,
      "LanguageId":1,
      "Name":"Vulnerabilities",
      "Status":1,
      "Type":2
   }   ...
]
</pre>
<hr>
<h3 id="h_627545777501529417021123">Search for records</h3>
<p>Search for records within a specified application.</p>
<h5>Base Command</h5>
<p><code>archer-search-records</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">applicationId</td>
<td style="width: 460px;">ID of the application to search records in</td>
</tr>
<tr>
<td style="width: 180px;">fieldsToDisplay</td>
<td style="width: 460px;">
<p>Fields to display in the search results, in array format.</p>
<p>Example: <code>"Title,Incident Summary"</code></p>
</td>
</tr>
<tr>
<td style="width: 180px;">maxResults</td>
<td style="width: 460px;">
<p>Maximum search results to return. Default is 100.</p>
</td>
</tr>
<tr>
<td style="width: 180px;">searchValue</td>
<td style="width: 460px;">
<p>Search value. To search for all, leave this parameter empty.</p>
</td>
</tr>
<tr>
<td style="width: 180px;">fieldToSearchOn</td>
<td style="width: 460px;">
<p>Name of field to search on. To search for all, leave this parameter empty.</p>
</td>
</tr>
<tr>
<td style="width: 180px;">numericOperator</td>
<td style="width: 460px;">
<p>Numeric search operator</p>
</td>
</tr>
<tr>
<td style="width: 180px;">dateOperator</td>
<td style="width: 460px;">
<p>Date search operator</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="height: 306px; width: 656px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 307px;"><strong>Path</strong></td>
<td style="width: 332px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 307px;">Archer.Record.Id</td>
<td style="width: 332px;">Content of the record</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.ApplicationId</td>
<td style="width: 332px;">Application ID of the record</td>
</tr>
<tr>
<td style="width: 307px;">Archer.Record.Fields</td>
<td style="width: 332px;">Property fields of the record</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-search-records applicationId=433 maxResults=1</code></p>
<h5>Raw Output</h5>
<pre>{
  "Fields": 
  {
    "Incident ID": "225828",
    "Record": 
    {
      "Actor, Tactics \u0026 Techniques": null,
      "Affected Facility": null,
      "Archive": null,
      "Attach to InfoSec Briefing": null,
      "Attack Category": null,
      "Automatic Incident Handler Access": "SOC: L2 Incident Handler,SOC: L1 Incident Handler",...
      "Date Created": "2017-10-14T09:55:25+03:00",
      "Date/Time Assigned": null,
      "Date/Time Closed": null,
      "Date/Time Escalated": null,
      "Date/Time Modified": "2017-10-14T09:55:25+03:00",
      "Date/Time Returned": null,
      "Days Open": "0",
      "Incident ID": "225828",...
      "Record Status": "New",...
    }
  },
  "Id": "225828",
  "ModuleId": "433"
}
</pre>
<hr>
<h3 id="h_679870256851529417291431">Get all application fields</h3>
<p>Returns all application fields by application ID.</p>
<h5>Base Command</h5>
<p><code>archer-get-application-fields</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">applicationId</td>
<td style="width: 460px;">ID of the application to search fields in</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="height: 306px; width: 656px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 307px;"><strong>Path</strong></td>
<td style="width: 332px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 307px;">Archer.ApplicationFields</td>
<td style="width: 332px;">Application property fields</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-get-application-fields applicationId=433</code></p>
<h5>Raw Output</h5>
<pre>{
  "ApplicationFields": [
    {
      "FieldId": "15698",
      "FieldName": "Incident Response Procedures",
      "FieldType": 9,
      "LevelId": 232
    },
    {
      "FieldId": "15700",
      "FieldName": "Not Applicable Incident Response Procedures",
      "FieldType": 9,
      "LevelId": 232
    },
    {
      "FieldId": "15742",
      "FieldName": "CAST - SOC Incident Procs - DO NOT DELETE",
      "FieldType": 1001,
      "LevelId": 232
    }...
}
</pre>
<hr>
<h3 id="h_3433767521251529417638918">Delete a record</h3>
<p>Deletes an existing record from a specified application.</p>
<h5>Base Command</h5>
<p><code>archer-delete-record</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">applicationId</td>
<td style="width: 460px;">ID of the application to delete a record from</td>
</tr>
<tr>
<td style="width: 180px;">contentId</td>
<td style="width: 460px;">Content (record) ID to delete</td>
</tr>
<tr>
<td style="width: 180px;">incidentId</td>
<td style="width: 460px;">
<p>Incident ID of the record.</p>
<p>Example: <code>id=12345 for INC-12345</code></p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<p>There is no context data for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-delete-record applicationId=423 contentId=227542</code></p>
<h5>Raw Output</h5>
<pre>content id = 227542 was deleted successfully</pre>
<hr>
<h3 id="h_6050463921701529488407195">Map list value name to list value ID</h3>
<p>Returns mapping from list value name to list value ID.</p>
<h5>Base Command</h5>
<p><code>archer-get-field</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">fieldId</td>
<td style="width: 460px;">ID of the field</td>
</tr>
<tr>
<td style="width: 180px;">applicationId</td>
<td style="width: 460px;">ID of the application to get the field value from</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<p>There is no context data for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-get-field applicationId=433 fieldID=16107</code></p>
<h5>Raw Output</h5>
<pre>{
    "FieldId": "16107",
    "Name": "Last Updated",
    "Type": 22,
    "levelId": 232
}</pre>
<hr>
<h3 id="h_5870377172201529489370638">Get all reports</h3>
<p>Returns all reports from Archer.</p>
<h5>Base Command</h5>
<p><code>archer-get-reports</code></p>
<p> </p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<p> </p>
<h5>Context Data</h5>
<p>There is no context data for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-get-reports</code></p>
<h5>Raw Output</h5>
<pre>{
    "ReportValues":
    {
        "ReportValue":[
            {
                "ApplicationGUID":"4cf0d0c6-4b51-404c-91c2-40ade972e95b",
                "ApplicationName":"Policies",
                "ReportDescription":"This report displays a listing of all security Policies.",
                "ReportGUID":"22961b81-4866-40ea-a298-99afb348598d",
                "ReportName":"Policies - Summary view"
            },
            {
                "ApplicationGUID":"138d3151-c1f5-4e7d-b6c9-4399e1d922ae",...</pre>
<hr>
<h3 id="h_3865501923301529490045363">Perform statistic search</h3>
<p>Performs a statistic search by report GUID.</p>
<h5>Base Command</h5>
<p><code>archer-execute-statistic-search-by-report</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">reportGuid</td>
<td style="width: 460px;">GUID of the report</td>
</tr>
<tr>
<td style="width: 180px;">maxResults</td>
<td style="width: 460px;">Maximum number of pages of the reports</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="height: 306px; width: 656px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 307px;"><strong>Path</strong></td>
<td style="width: 332px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 307px;">Archer.StatisticSearch</td>
<td style="width: 332px;">Search results</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-get-application-fields applicationId=433</code></p>
<h5>Raw Output</h5>
<pre>{
    "Groups": {
        "-count": "3",
        "Metadata": {
            "FieldDefinitions": {
                "FieldDefinition": [
                    {
                        "-alias": "Classification",
                        "-guid": "769b2548-6a98-49b6-95c5-03e391f0a40e",
                        "-id": "76",
                        "-name": "Classification"
                    },
                    {
                        "-alias": "Standard_Name",
                        "-guid": "a569fd34-16f9-4965-93b0-889fcb91ba7a",
                        "-id": "1566",
                        "-name": "Standard Name"
                    }
                ]
            }
        },
        "Total": {
            "Aggregate": {
                "-Count": "1497",
                "-FieldId": "1566"
            }
        }
    }
}
</pre>
<hr>
<h3 id="h_3375463583901529490543773">Get search criteria</h3>
<p>Returns search criteria by report GUID.</p>
<h5>Base Command</h5>
<p><code>archer-get-search-options-by-guid</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">reportGuid</td>
<td style="width: 460px;">GUID of the report</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<p>There is no context data for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-get-search-options-by-guid reportGuid=246b1d4b294e46c4a4713853456234f7</code></p>
<h5>Raw Output</h5>
<pre>{
    "SearchReport": {
        "Criteria": {
            "Filter": {
                "Conditions": {
                    "ValueListFilterCondition": [
                        {
                            "Field": "302",
                            "IncludeChildren": "False",
                            "IsNoSelectionIncluded": "False",
                            "Operator": "DoesNotContain",
                            "Values": {
                                "Value": "470"
                            }
                        },
                        {
                            "Field": "304",
                            "IncludeChildren": "False",
                            "IsNoSelectionIncluded": "False",
                            "Operator": "Contains",
                            "Values": {
                                "Value": "473"
                            }
                        }
                    ]
                },
                "OperatorLogic": ""
            },
            "ModuleCriteria": {
                "BuildoutRelationship": "Union",
                "IsKeywordModule": "False",
                "Module": "75",
                "SortFields": {
                    "SortField": {
                        "Field": "296",
                        "SortType": "Descending"
                    }
                }
            }
        },
        "DisplayFields": {
            "DisplayField": [
                "296",
                "302",
                "304",
                "7850",
                "342"
            ]
        },
        "PageSize": "20"
    }
}
</pre>
<hr>
<h3 id="h_6267948584551529490882938">Search records by report</h3>
<p>Searches records by report GUID.</p>
<h5>Base Command</h5>
<p><code>archer-search-records-by-report</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">reportGuid</td>
<td style="width: 460px;">GUID of the report</td>
</tr>
<tr>
<td style="width: 180px;">maxResults</td>
<td style="width: 460px;">Maximum number of pages of the reports</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<table style="height: 306px; width: 656px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 307px;"><strong>Path</strong></td>
<td style="width: 332px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 307px;">Archer.StatisticSearch.Records.Record</td>
<td style="width: 332px;">Search results (records)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-search-records-by-report reportGuid=365121a3-6145-48ea-8a01-5d000c5c65cf</code></p>
<h5>Raw Output</h5>
<pre>{
    "Records": {
        "-count": "20",
        "LevelCounts": {
            "LevelCount": {
                "-count": "20",
                "-guid": "4d664bbf-4f15-4f5c-a81f-888f5901ba26",
                "-id": "3"
            }
        },
        "Metadata": {
            "FieldDefinitions": {
                "FieldDefinition": [
                    {
                        "-alias": "Policy_ID",
                        "-guid": "4b765f84-d381-4543-9d7c-1f9e716d4c4d",
                        "-id": "1578",
                        "-name": "Policy ID"
                    }...
</pre>
<hr>
<h3 id="h_5690460115251529491112217">Get field mapping by level ID</h3>
<p>Returns mapping of fields by level ID.</p>
<h5>Base Command</h5>
<p><code>archer-get-mapping-by-level</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">level</td>
<td style="width: 460px;">Level ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<p>There is no context data for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-get-mapping-by-level level=232</code></p>
<h5>Raw Output</h5>
<pre>{
    "15698": {
        "Name": "Incident Response Procedures",
        "Type": 9,
        "levelId": "232"
    },
    "15700": {
        "Name": "Not Applicable Incident Response Procedures",
        "Type": 9,
        "levelId": "232"
    }...
</pre>
<hr>
<h3 id="h_3906877896001529492105590">Fetch Archer incidents</h3>
<p>Fetches specific incidents from Archer to the Cortex XSOAR War Room. You can also manually fetch automations.</p>
<h5>Base Command</h5>
<p><code>archer-manually-fetch-incident</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">applicationId</td>
<td style="width: 460px;">
<p>ID of the application to get the incident from.</p>
</td>
</tr>
<tr>
<td style="width: 180px;">incidentIds</td>
<td style="width: 460px;">IDs of incidents to get details for, comma separated</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<p>There is no context data for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-manually-fetch-incident applicationId=433 incidentIds=227536</code></p>
<h5>Raw Output</h5>
<pre>{
    "details": "Incident Summary: inside_record_test_0_summary",
    "labels": [
        {
            "Related Security Incidents (Direct Link)-Incident Summary": "inside_record_test_1_summary"
        }...
</pre>
<hr>
<h3 id="h_862940326801529492724147">Download Archer file to the War Room</h3>
<p>Downloads a file from Archer to the Cortex XSOAR War Room context.</p>
<h5>Base Command</h5>
<p><code>archer-get-file</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">fieldId</td>
<td style="width: 460px;">
<p>Archer file ID</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<p>There is no context data for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-get-file fileId=3</code></p>
<h5>Raw Output</h5>
<pre>Uploaded file: Screen Shot 2018-02-22 at 11.09.33.png'</pre>
<hr>
<h3 id="h_5111225307651529492866353">Upload a file from Cortex XSOAR to Archer</h3>
<p>Uploads a file from Cortex XSOAR to Archer.</p>
<h5>Base Command</h5>
<p><code>archer-upload-file</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">contentId</td>
<td style="width: 460px;">
<p>Content (record) ID to add the file to</p>
</td>
</tr>
<tr>
<td style="width: 180px;">applicationId</td>
<td style="width: 460px;">
<p>ID of the application to upload the file to</p>
</td>
</tr>
<tr>
<td style="width: 180px;">incidentId</td>
<td style="width: 460px;">
<p>Incident ID to add the file to</p>
</td>
</tr>
<tr>
<td style="width: 180px;">entryId</td>
<td style="width: 460px;">
<p>Entry ID of the file in the Cortex XSOAR context</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<p>There is no context data for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-upload-file applicationId=433 contentId=227610 entryId=61@95</code></p>
<h5>Raw Output</h5>
<pre>File uploaded successfully.</pre>
<hr>
<h3 id="h_447548299391529493439939">Add data to the detailed analysis field</h3>
<p>Adds data to the detailed analysis field.</p>
<h5>Base Command</h5>
<p><code>archer-add-to-detailed-analysis</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 665px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 180px;"><strong>Parameter</strong></td>
<td style="width: 460px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">contentId</td>
<td style="width: 460px;">
<p>Incident (record) ID to set the field's data</p>
</td>
</tr>
<tr>
<td style="width: 180px;">applicationId</td>
<td style="width: 460px;">
<p>ID of the application to set the record's field</p>
</td>
</tr>
<tr>
<td style="width: 180px;">incidentId</td>
<td style="width: 460px;">
<p>Incident ID to add the file to</p>
</td>
</tr>
<tr>
<td style="width: 180px;">value</td>
<td style="width: 460px;">
<p>Value to add to the Detailed Analysis</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Data</h5>
<p>There is no context data for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!archer-set-detailed-analysis applicationId=433 contentId=227610 value="test string"</code></p>
<h5>Raw Output</h5>
<pre>Detailed Analysis updated successfully.</pre>
<hr>
<h3 id="h_81021858117391550577986609">Get an Archer user's user ID</h3>
<p>Returns the user ID of an Archer user.</p>
<h5>Base Command</h5>
<p><code>archer-get-user-id</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<td style="width: 141px;">Argument Name</td>
<td style="width: 536px;">Description</td>
<td style="width: 63px;">Required</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">userInfo</td>
<td style="width: 536px;">Username in the form of "Domain\username". For example, userInfo="mydomain\myusername"</td>
<td style="width: 63px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;">
<thead>
<tr>
<td>Path</td>
<td>Description</td>
</tr>
</thead>
<tbody>
<tr>
<td>Archer.User.UserId</td>
<td> User ID of the Archer user</td>
</tr>
</tbody>
</table>
<hr>
<h3 id="h_75316240823191550577993400">Get a list of values for a field</h3>
<p>Returns list of values for a specified field, e.g., fieldID=16114. This command only works for value list fields (type 4).</p>
<h5>Base Command</h5>
<p><code>archer-get-valuelist</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<td style="width: 141px;">Argument Name</td>
<td style="width: 536px;">Description</td>
<td style="width: 63px;">Required</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">fieldID</td>
<td style="width: 536px;">Field ID</td>
<td style="width: 63px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>