   <section class="article-info">
        <div class="article-content">
          <div class="article-body"><p>An attack simulation platform that provides validations for security controls, responses, and remediation exercises.</p>
<p>This integration was integrated and tested with AttackIQ FireDrill&nbsp;v2.15.96.</p>
<h2>Use Cases</h2>
<ul>
<ul>
<li>Retrieves a list of testing scenarios.</li>
<li>Executes testing of penetration assessments.</li>
<li>Retrieves detailed assessment results.</li>
<li>Triggers other playbook-based assessment results.</li>
</ul>
</ul>
<h2>Configure AttackIQ Platform on Demisto</h2>
<ul>
<ul>
<ol>
<li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong> &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
<li>Search for AttackIQ Platform.</li>
<li>Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
<ul>
<li><strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. https://example.net)</strong></li>
<li><strong>API Token</strong>: Account's private token (as appears in attackIQ UI)</li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.</li>
</ol>
</ul>
</ul>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ul>
<ul>
<ol>
<li><a href="#h_844be2cc-f626-4c68-87c4-67ebda47adf6" target="_self">Get assessment information by ID: attackiq-get-assessment-by-id</a></li>
<li><a href="#h_c69c2e00-8816-4871-af79-7ee29eaca30d" target="_self">Get all assessments details by page: attackiq-list-assessments</a></li>
<li><a href="#h_ac367a07-13b6-4f27-8375-f4c9029ac09a" target="_self">Activates an assessment: attackiq-activate-assessment</a></li>
<li><a href="#h_bb20be26-2e6e-4372-93a0-b1ef4726834b" target="_self">Run tests in the assessment: attackiq-run-all-tests-in-assessment</a></li>
<li><a href="#h_d02f6624-77da-4645-a39b-0457e24acb34" target="_self">Get an assessment execution status: attackiq-get-assessment-execution-status</a></li>
<li><a href="#h_49db999d-f35d-4a01-a400-67523ce51679" target="_self">Get a test execution status: attackiq-get-test-execution-status</a></li>
<li><a href="#h_aaaee141-3cb4-43de-a2de-e0fcffba5669" target="_self">Get a list of tests by assessment: attackiq-list-tests-by-assessment</a></li>
<li><a href="#h_044bc4ea-ed11-4cc0-84f1-2e0b32751f26" target="_self">Get the test results of an assessment: attackiq-get-test-results</a></li>
 <li><a href="#attackiq-list-assessment-templates" target="_self">List all available assessment templates: attackiq-list-assessment-templates</a></li>
<li><a href="#attackiq-list-assets" target="_self">List all assets: attackiq-list-assets</a></li>
<li><a href="#attackiq-create-assessment" target="_self">Creates a new assesment: attackiq-create-assessment</a></li>
<li><a href="#attackiq-add-assets-to-assessment" target="_self">Adds assets or asset groups to an assesment: attackiq-add-assets-to-assessment</a></li>
<li><a href="#attackiq-delete-assessment" target="_self">Deletes an assessment: attackiq-delete-assessment</a></li>
</ol>
</ul>
</ul>
<h3 id="h_844be2cc-f626-4c68-87c4-67ebda47adf6">1. Get assessment information by ID</h3>
<hr />
<p>Returns all assessment information by ID in the AttackIQ Platform.</p>
<h5>Base Command</h5>
<p><code>attackiq-get-assessment-by-id</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 190px;"><strong>Argument Name</strong></th>
<th style="width: 403px;"><strong>Description</strong></th>
<th style="width: 115px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 190px;">assessment_id</td>
<td style="width: 403px;">The ID of the assessment to return.</td>
<td style="width: 115px;">Required</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 390px;"><strong>Path</strong></th>
<th style="width: 93px;"><strong>Type</strong></th>
<th style="width: 225px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.Id</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The ID of the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.Name</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The name of the assessment name.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.Description</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The description of the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.StartDate</td>
<td style="width: 93px;">Date</td>
<td style="width: 225px;">The start date of the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.EndDate</td>
<td style="width: 93px;">Date</td>
<td style="width: 225px;">The end date of the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.AssessmentState</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The state of the assessment. Can be Active or Inactive.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.DefaultSchedule</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The default schedule timing (cron) of the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.AssessmentTemplateId</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The template ID of the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.AssessmentTemplateName</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The template name of the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.AssessmentTemplateDescription</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The template description of the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.AssessmentTemplateDefaultSchedule</td>
<td style="width: 93px;">Unknown</td>
<td style="width: 225px;">The assessment's template default schedule timing (cron).</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.AssessmentTemplateCompany</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The owner of the template.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.AssessmentTemplateCreated</td>
<td style="width: 93px;">Date</td>
<td style="width: 225px;">The date that the template was created.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.AssessmentTemplateModified</td>
<td style="width: 93px;">Date</td>
<td style="width: 225px;">The date the template was last modified.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.Creator</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The user who created the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.Owner</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The user who owns the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.User</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The user who ran the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.Created</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The time that the assessment was created.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.Modified</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The time that the assessment was last modified.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.Users</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The user IDs that can access the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.Groups</td>
<td style="width: 93px;">String</td>
<td style="width: 225px;">The user groups who can access the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.DefaultAssetCount</td>
<td style="width: 93px;">Number</td>
<td style="width: 225px;">The number of machines (assets) that are connected to the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.DefaultAssetGroupCount</td>
<td style="width: 93px;">Number</td>
<td style="width: 225px;">The number of asset groups that are connected to the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.MasterJobCount</td>
<td style="width: 93px;">Number</td>
<td style="width: 225px;">The number of tests that ran in the assessment.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.Count</td>
<td style="width: 93px;">Number</td>
<td style="width: 225px;">The total number of assessments.</td>
</tr>
<tr>
<td style="width: 390px;">AttackIQ.Assessment.RemainingPages</td>
<td style="width: 93px;">Number</td>
<td style="width: 225px;">The number of remaining pages to return. For example, if the total number of pages is 6, and the last fetch was page 5, the value is 1.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!attackiq-get-assessment-by-id assessment_id=c4e352ae-1506-4c74-bd90-853f02dd765a</pre>
<h5>Context Example</h5>
<pre>{
    "AttackIQ.Assessment": {
        "AssessmentState": "Active",
        "AssessmentTemplateCompany": "906d5ec6-101c-4ae6-8906-b93ce0529060",
        "AssessmentTemplateCreated": "2016-07-01T20:26:43.494459Z",
        "AssessmentTemplateDefaultSchedule": null,
        "AssessmentTemplateDescription": "Variety of common ransomware variants",
        "AssessmentTemplateId": "59d35f4a-2da0-4c4a-a08a-c30cb41dae6b",
        "AssessmentTemplateModified": "2019-02-19T03:31:54.393885Z",
        "AssessmentTemplateName": "Ransomware Project",
        "Created": "2019-08-27T10:17:09.809036Z",
        "Creator": "akrupnik@paloaltonetworks.com",
        "DefaultAssetCount": 1,
        "DefaultAssetGroupCount": 0,
        "DefaultSchedule": "41;8;*;*;1",
        "Description": "Test of common ransomware variants",
        "EndDate": null,
        "Groups": [],
        "Id": "c4e352ae-1506-4c74-bd90-853f02dd765a",
        "MasterJobCount": 3,
        "Modified": "2019-09-18T08:16:23.079961Z",
        "Name": "Arseny's ransomware project",
        "Owner": "akrupnik@paloaltonetworks.com",
        "StartDate": null,
        "User": "akrupnik@paloaltonetworks.com",
        "Users": [
            "71e92cf9-5159-466c-8050-142d1ba279ea"
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>AttackIQ Assessment c4e352ae-1506-4c74-bd90-853f02dd765a</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Id</strong></th>
<th><strong>Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>User</strong></th>
<th><strong>Created</strong></th>
<th><strong>Modified</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>c4e352ae-1506-4c74-bd90-853f02dd765a</td>
<td>Arseny's ransomware project</td>
<td>Test of common ransomware variants</td>
<td>akrupnik@paloaltonetworks.com</td>
<td>2019-08-27T10:17:09.809036Z</td>
<td>2019-09-18T08:16:23.079961Z</td>
</tr>
</tbody>
</table>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="h_c69c2e00-8816-4871-af79-7ee29eaca30d">2. Get all assessments details by page</h3>
<hr />
<p>Returns all assessment details by page.</p>
<h5>Base Command</h5>
<p><code>
  attackiq-list-assessments
</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 170px;"><strong>Argument Name</strong></th>
<th style="width: 433px;"><strong>Description</strong></th>
<th style="width: 105px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170px;">page_number</td>
<td style="width: 433px;">The page number to return.</td>
<td style="width: 105px;">Optional</td>
</tr>
<tr>
<td style="width: 170px;">page_size</td>
<td style="width: 433px;">The number of results to return per page.</td>
<td style="width: 105px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 389px;"><strong>Path</strong></th>
<th style="width: 94px;"><strong>Type</strong></th>
<th style="width: 225px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.Id</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The ID of the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.Name</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The name of the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.Description</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The description of the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.StartDate</td>
<td style="width: 94px;">Date</td>
<td style="width: 225px;">The start date of the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.EndDate</td>
<td style="width: 94px;">Date</td>
<td style="width: 225px;">The end date of the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.AssessmentState</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The state of the assessment. Can be Active or Inactive.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.DefaultSchedule</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The default schedule timing (cron) of the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.AssessmentTemplateId</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The template ID of the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.AssessmentTemplateName</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The template name of the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.AssessmentTemplateDescription</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The template description of the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.AssessmentTemplateDefaultSchedule</td>
<td style="width: 94px;">Unknown</td>
<td style="width: 225px;">The default schedule timing (cron) of the template assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.AssessmentTemplateCompany</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The owner of the template.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.AssessmentTemplateCreated</td>
<td style="width: 94px;">Date</td>
<td style="width: 225px;">The date that the template was created.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.AssessmentTemplateModified</td>
<td style="width: 94px;">Date</td>
<td style="width: 225px;">The date the template was last modified.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.Creator</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The user who created the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.Owner</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The user who owned the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.User</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The user that ran the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.Created</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The time that the assessment was created.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.Modified</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The time that the assessment was last modified.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.Users</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The User IDs that can access the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.Groups</td>
<td style="width: 94px;">String</td>
<td style="width: 225px;">The user groups who can access the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.DefaultAssetCount</td>
<td style="width: 94px;">Number</td>
<td style="width: 225px;">The number of machines (assets) that are connected to the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.DefaultAssetGroupCount</td>
<td style="width: 94px;">Number</td>
<td style="width: 225px;">The number of asset groups that are connected to the assessment.</td>
</tr>
<tr>
<td style="width: 389px;">AttackIQ.Assessment.MasterJobCount</td>
<td style="width: 94px;">Number</td>
<td style="width: 225px;">The number of tests that ran in the assessment.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!attackiq-list-assessments page_size=5</pre>
<h5>Context Example</h5>
<pre>{
    "AttackIQ.Assessment": 11
}
</pre>
<h5>Human Readable Output</h5>
<h3>AttackIQ Assessments Page 1/12</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Id</strong></th>
<th><strong>Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>User</strong></th>
<th><strong>Created</strong></th>
<th><strong>Modified</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>c4e352ae-1506-4c74-bd90-853f02dd765a</td>
<td>Arseny's ransomware project</td>
<td>Test of common ransomware variants</td>
<td>akrupnik@paloaltonetworks.com</td>
<td>2019-08-27T10:17:09.809036Z</td>
<td>2019-09-18T08:16:23.079961Z</td>
</tr>
<tr>
<td>f57edb34-ccb2-4695-b79c-bb739cab70a1</td>
<td>Arseny's ransomware project</td>
<td>Test of common ransomware variants</td>
<td>akrupnik@paloaltonetworks.com</td>
<td>2019-09-02T11:52:09.915614Z</td>
<td>2019-09-16T09:02:59.401994Z</td>
</tr>
<tr>
<td>8978fe24-607a-4815-a36a-89fb6191b318</td>
<td>ATT&amp;CK by the Numbers @ NOVA BSides 2019</td>
<td>AttackIQ’s analysis and mapping of the “ATT&amp;CK by the Numbers” @ NOVA BSides 2019</td>
<td>akrupnik@paloaltonetworks.com</td>
<td>2019-09-05T08:47:38.243320Z</td>
<td>2019-09-10T11:16:25.619197Z</td>
</tr>
<tr>
<td>5baca9b4-e55c-497f-a05a-8004b9a36efe</td>
<td>Custom</td>
<td>Custom project</td>
<td>darbel@paloaltonetworks.com</td>
<td>2019-09-10T08:38:55.165853Z</td>
<td>2019-09-10T08:38:55.165874Z</td>
</tr>
<tr>
<td>58440d47-d7b5-4f57-913f-3e13903fa2fc</td>
<td>Arseny's ransomware project</td>
<td>Test of common ransomware variants</td>
<td>akrupnik@paloaltonetworks.com</td>
<td>2019-09-02T11:52:13.933084Z</td>
<td>2019-09-02T11:52:16.100942Z</td>
</tr>
</tbody>
</table>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="h_ac367a07-13b6-4f27-8375-f4c9029ac09a">3. Activates an assessment&nbsp;</h3>
<hr />
<p>Activates the assessment by ID, which is required for execution.</p>
<h5>Base Command</h5>
<p><code>attackiq-activate-assessment</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 185px;"><strong>Argument Name</strong></th>
<th style="width: 402px;"><strong>Description</strong></th>
<th style="width: 121px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 185px;">assessment_id</td>
<td style="width: 402px;">ID of the assessment to activate.</td>
<td style="width: 121px;">Required</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!attackiq-activate-assessment assessment_id=c4e352ae-1506-4c74-bd90-853f02dd765a</pre>
<h5>Human Readable Output</h5>
<p>Successfully activated project c4e352ae-1506-4c74-bd90-853f02dd765a</p>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="h_bb20be26-2e6e-4372-93a0-b1ef4726834b">4. Run tests in the assessment</h3>
<hr />
<p>Runs all tests in the assessment.</p>
<h5>Base Command</h5>
<p><code>attackiq-run-all-tests-in-assessment</code></p>
<h5>Input</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 102px;"><strong>Argument Name</strong></th>
<th style="width: 527px;"><strong>Description</strong></th>
<th style="width: 79px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 102px;">assessment_id</td>
<td style="width: 527px;">The ID of the assessment.</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 102px;">on_demand_only</td>
<td style="width: 527px;">Runs only on-demand tests in the assessment. True executes tests in the assessment that are not scheduled to run. False executes all tests in the assessment including scheduled tests. Default is false.</td>
<td style="width: 79px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!attackiq-run-all-tests-in-assessment assessment_id=8978fe24-607a-4815-a36a-89fb6191b318</pre>
<h5>Human Readable Output</h5>
<p>Successfully started running all tests in project: ATT&amp;CK by the Numbers @ NOVA BSides 2019</p>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="h_d02f6624-77da-4645-a39b-0457e24acb34">5. Get an assessment execution status</h3>
<hr />
<p>Returns an assessment execution status when running an on-demand execution only.</p>
<h5>Base Command</h5>
<p><code>attackiq-get-assessment-execution-status</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 179px;"><strong>Argument Name</strong></th>
<th style="width: 407px;"><strong>Description</strong></th>
<th style="width: 122px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 179px;">assessment_id</td>
<td style="width: 407px;">The assessment to check status.</td>
<td style="width: 122px;">Required</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 244px;"><strong>Path</strong></th>
<th style="width: 121px;"><strong>Type</strong></th>
<th style="width: 343px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 244px;">AttackIQ.Assessment.Running</td>
<td style="width: 121px;">Boolean</td>
<td style="width: 343px;">Whether the assessment is running.</td>
</tr>
<tr>
<td style="width: 244px;">AttackIQ.Assessment.Id</td>
<td style="width: 121px;">String</td>
<td style="width: 343px;">The ID of the assessment.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!attackiq-get-assessment-execution-status assessment_id=c4e352ae-1506-4c74-bd90-853f02dd765a</pre>
<h5>Context Example</h5>
<pre>{
    "AttackIQ.Assessment": {
        "Id": "c4e352ae-1506-4c74-bd90-853f02dd765a",
        "Running": false
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>Assessment c4e352ae-1506-4c74-bd90-853f02dd765a execution is not running.</p>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="h_49db999d-f35d-4a01-a400-67523ce51679">6. Get a test execution status</h3>
<hr />
<p>Returns the status of the test.</p>
<h5>Base Command</h5>
<p><code>attackiq-get-test-execution-status</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 237px;"><strong>Argument Name</strong></th>
<th style="width: 313px;"><strong>Description</strong></th>
<th style="width: 158px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 237px;">test_id</td>
<td style="width: 313px;">The ID of the Test.</td>
<td style="width: 158px;">Required</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 188px;"><strong>Path</strong></th>
<th style="width: 113px;"><strong>Type</strong></th>
<th style="width: 407px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 188px;">AttackIQTest.Detected</td>
<td style="width: 113px;">Number</td>
<td style="width: 407px;">The number of detections in the test.</td>
</tr>
<tr>
<td style="width: 188px;">AttackIQTest.Failed</td>
<td style="width: 113px;">Number</td>
<td style="width: 407px;">The number of failures in the test.</td>
</tr>
<tr>
<td style="width: 188px;">AttackIQTest.Finished</td>
<td style="width: 113px;">Boolean</td>
<td style="width: 407px;">Whether the test is finished.</td>
</tr>
<tr>
<td style="width: 188px;">AttackIQTest.Passed</td>
<td style="width: 113px;">Number</td>
<td style="width: 407px;">The number of passed tests.</td>
</tr>
<tr>
<td style="width: 188px;">AttackIQTest.Errored</td>
<td style="width: 113px;">Number</td>
<td style="width: 407px;">The number of tests that returned errors.</td>
</tr>
<tr>
<td style="width: 188px;">AttackIQTest.Total</td>
<td style="width: 113px;">Number</td>
<td style="width: 407px;">The total number of tests that ran.</td>
</tr>
<tr>
<td style="width: 188px;">AttackIQTest.Id</td>
<td style="width: 113px;">String</td>
<td style="width: 407px;">The ID of the assessment test.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !attackiq-get-test-execution-status test_id=9aed2cef-8c64-4e29-83b4-709de5963b66</pre>
<h5>Context Example</h5>
<pre>{
    "AttackIQTest": {
        "Detected": 0,
        "Errored": 0,
        "Failed": 9,
        "Finished": true,
        "Id": "9aed2cef-8c64-4e29-83b4-709de5963b66",
        "Passed": 1,
        "Total": 10
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Test 9aed2cef-8c64-4e29-83b4-709de5963b66 status</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Detected</strong></th>
<th><strong>Errored</strong></th>
<th><strong>Failed</strong></th>
<th><strong>Finished</strong></th>
<th><strong>Id</strong></th>
<th><strong>Passed</strong></th>
<th><strong>Total</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>0</td>
<td>0</td>
<td>9</td>
<td>true</td>
<td>9aed2cef-8c64-4e29-83b4-709de5963b66</td>
<td>1</td>
<td>10</td>
</tr>
</tbody>
</table>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="h_aaaee141-3cb4-43de-a2de-e0fcffba5669">7. Get a list of tests by assessment</h3>
<hr />
<p>Returns a list of tests by an assessment.</p>
<h5>Base Command</h5>
<p><code>attackiq-list-tests-by-assessment</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 469px;"><strong>Description</strong></th>
<th style="width: 95px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">assessment_id</td>
<td style="width: 469px;">The ID of the assessment that contains the tests.</td>
<td style="width: 95px;">Required</td>
</tr>
<tr>
<td style="width: 144px;">page_size</td>
<td style="width: 469px;">The Maximum page size for the results.</td>
<td style="width: 95px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">page_number</td>
<td style="width: 469px;">The page number to return.</td>
<td style="width: 95px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 219px;"><strong>Path</strong></th>
<th style="width: 87px;"><strong>Type</strong></th>
<th style="width: 402px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 219px;">AttackIQTest.Id</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">ID of the test.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Name</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The name of the test.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Description</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The description of the test.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Scenarios.Id</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The ID of the test scenario.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Scenarios.Name</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The name of the test scenario.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Assets.Id</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The ID of the test asset.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Assets.Ipv4Address</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The IP version 4 address of the test asset.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Assets.Hostname</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The host name of the test asset.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Assets.ProductName</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The product name of the test asset.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Assets.Modified</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The last modified date of the test asset.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Assets.Status</td>
<td style="width: 87px;">Date</td>
<td style="width: 402px;">The status of the test asset. Can be Active or Inactive.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.TotalAssetCount</td>
<td style="width: 87px;">Number</td>
<td style="width: 402px;">The number of assets in which the test ran.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.CronExpression</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The Cron expression of the test.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Runnable</td>
<td style="width: 87px;">Boolean</td>
<td style="width: 402px;">Whether the test can run.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.LastResult</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The last result of the test.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.User</td>
<td style="width: 87px;">String</td>
<td style="width: 402px;">The name of the user that ran the test in the assessment.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Created</td>
<td style="width: 87px;">Date</td>
<td style="width: 402px;">The date that the test was created.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Modified</td>
<td style="width: 87px;">Date</td>
<td style="width: 402px;">The date that the test was last modified.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.LatestInstanceId</td>
<td style="width: 87px;">Number</td>
<td style="width: 402px;">The ID of the most recent run of the test.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.UsingDefaultAssets</td>
<td style="width: 87px;">Boolean</td>
<td style="width: 402px;">Whether the test uses default assets.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.UsingDefaultSchedule</td>
<td style="width: 87px;">Boolean</td>
<td style="width: 402px;">Whether the test uses the default schedule.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.RemainingPages</td>
<td style="width: 87px;">Number</td>
<td style="width: 402px;">The number of remaining pages to return. For example, if the total number of pages is 6, and the last fetch was page 5, the value is 1.</td>
</tr>
<tr>
<td style="width: 219px;">AttackIQTest.Count</td>
<td style="width: 87px;">Number</td>
<td style="width: 402px;">The total number of tests.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !attackiq-list-tests-by-assessment assessment_id=c4e352ae-1506-4c74-bd90-853f02dd765a page_size=3 page_number=1</pre>
<h5>Context Example</h5>
<pre>{
    "AttackIQTest": 0
}
</pre>
<h5>Human Readable Output</h5>
<h1>Assessment c4e352ae-1506-4c74-bd90-853f02dd765a tests</h1>
<h2>Page 1 / 1</h2>
<h3>Test - Ransomware Download</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Id</strong></th>
<th><strong>Name</strong></th>
<th><strong>Created</strong></th>
<th><strong>Modified</strong></th>
<th><strong>Runnable</strong></th>
<th><strong>Last Result</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>1c350a5a-84f2-4938-93d8-cc31f0a99482</td>
<td>Ransomware Download</td>
<td>2019-08-27T10:17:10.132074Z</td>
<td>2019-09-02T07:08:25.237823Z</td>
<td>true</td>
<td>Failed</td>
</tr>
</tbody>
</table>
<h3>Assets (Ransomware Download)</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Hostname</strong></th>
<th><strong>Id</strong></th>
<th><strong>Ipv4Address</strong></th>
<th><strong>Modified</strong></th>
<th><strong>ProductName</strong></th>
<th><strong>Status</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>ec2amaz-g4iu5no</td>
<td>03e17460-849e-4b86-b6c6-ef0db72823ff</td>
<td>172.31.39.254</td>
<td>2019-09-18T08:12:16.957300Z</td>
<td>Windows Server 2016 Datacenter</td>
<td>Active</td>
</tr>
</tbody>
</table>
<h3>Scenarios (Ransomware Download)</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Id</strong></th>
<th><strong>Name</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>7f188dbb-4d75-4c75-97bc-ff2d03fc0a1f</td>
<td>Download WannaCry Ransomware Sample</td>
</tr>
<tr>
<td>35097add-888e-4916-ad25-38afef5d3b73</td>
<td>Download 7ev3n Ransomware</td>
</tr>
<tr>
<td>c12c0cea-96e8-40b2-80af-fb897cffbe6a</td>
<td>Download Alpha Ransomware</td>
</tr>
<tr>
<td>8b4eac5c-0475-475a-8521-dc30670d4212</td>
<td>Download BlackShades Crypter Ransomware</td>
</tr>
<tr>
<td>25b85e85-5255-49d3-8805-8ded910f1a63</td>
<td>Download AutoLocky Ransomware</td>
</tr>
<tr>
<td>ce58ac59-f08a-4b72-918c-25fdfd0f7e4b</td>
<td>Download Bandarchor Ransomware</td>
</tr>
<tr>
<td>66b167f6-acf7-491a-bfd6-ddd513d7290d</td>
<td>Download Bucbi Ransomware</td>
</tr>
<tr>
<td>b2eb8dec-1db0-46fe-b7af-bf87285d0d30</td>
<td>Download BadBlock Ransomeware</td>
</tr>
<tr>
<td>fd81172c-f7f3-4811-a4e8-ebdf10044c85</td>
<td>Download Chimera Ransomware</td>
</tr>
<tr>
<td>193f6df4-aff7-44cd-8553-ed32dab8aac2</td>
<td>Download CoinVault Ransomware</td>
</tr>
<tr>
<td>c75275eb-cf51-47d1-a031-c48e0ce8a3a1</td>
<td>Download Cerber Ransomware</td>
</tr>
<tr>
<td>595e522e-3ef2-4d6c-bfb0-f1e4841455aa</td>
<td>Download Crypren Ransomware</td>
</tr>
<tr>
<td>8c89ab68-12d2-4cd8-8469-97d1a5586400</td>
<td>Download Cryptolocker Ransomware</td>
</tr>
<tr>
<td>0d78245f-fb7e-4a1b-a4ee-c3f06d62ec2c</td>
<td>Download CryptoDefense Ransomware</td>
</tr>
<tr>
<td>59e127c1-4d33-4564-8df1-a4acd4c6d564</td>
<td>Download CryptoWall Ransomware</td>
</tr>
<tr>
<td>ec3d4c58-937d-43be-9283-41ba43380f98</td>
<td>Download Cryptear Ransomware</td>
</tr>
<tr>
<td>3f22d898-2fa2-4824-992a-207f71fe61ce</td>
<td>Download CTBLocker Ransomware</td>
</tr>
<tr>
<td>b1c12d92-7754-45b1-bc85-e52960ba3a6c</td>
<td>Download CryptXXX Ransomware</td>
</tr>
<tr>
<td>d70c6af1-aef4-4748-8bb6-3c1414d4488c</td>
<td>Download DMALocker Ransomware</td>
</tr>
<tr>
<td>fd202846-f523-41d8-9e56-d388e50e1bcb</td>
<td>Download Fakben Ransomware</td>
</tr>
<tr>
<td>e2e94c6a-8749-4630-b2a5-a068a1cdf432</td>
<td>Download GhostCrypt Ransomware</td>
</tr>
<tr>
<td>3aa03297-3732-432d-b79b-7180275712d3</td>
<td>Download Jigsaw Ransomware</td>
</tr>
<tr>
<td>65ef68fa-d62e-4dd1-8892-1b56beb6bd1e</td>
<td>Download HydraCrypt Ransomware</td>
</tr>
<tr>
<td>00c3d6eb-d9c3-4109-b373-8f934a84162d</td>
<td>Download Harasom Ransomware</td>
</tr>
<tr>
<td>c17581f3-6a85-4a98-8803-2a6479117769</td>
<td>Download Zcrypt Ransomware</td>
</tr>
<tr>
<td>264bc140-52db-4f20-a0a2-e50cd37f459a</td>
<td>Download Zyklon Ransomware</td>
</tr>
<tr>
<td>1febae73-86d0-4e2d-9494-051f6629ed7e</td>
<td>Download VaultCrypt Ransomware</td>
</tr>
<tr>
<td>ce98ba43-4293-401e-a203-c4d04e31dacb</td>
<td>Download Xorist Ransomware</td>
</tr>
<tr>
<td>0805f45c-ecb6-4cc2-a531-7a61e5452b2c</td>
<td>Download TeslaCrypt Ransomware</td>
</tr>
<tr>
<td>a25e0c4e-a117-48f5-b05e-39a38144c372</td>
<td>Download TrueCrypt Ransomware</td>
</tr>
<tr>
<td>f116c1fb-9373-4b54-9c7d-3a7e50edbf70</td>
<td>Download SynoLocker Ransomware</td>
</tr>
<tr>
<td>f1590467-b28f-4b9a-84ee-676bfbee2add</td>
<td>Download Sanction Ransomware</td>
</tr>
<tr>
<td>fc057ae4-c56d-4e9a-8c0f-9f22ec1e5576</td>
<td>Download SNSLock Ransomware</td>
</tr>
<tr>
<td>b7425756-ab9a-4c7e-8fda-d1080c170910</td>
<td>Download Rector Ransomware</td>
</tr>
<tr>
<td>00a2bbf3-7faa-4a44-b125-580ebe007931</td>
<td>Download Rokku Ransomware</td>
</tr>
<tr>
<td>0f8097da-345d-4516-9730-8efa68b427e2</td>
<td>Download Rakhni Ransomware</td>
</tr>
<tr>
<td>11270129-4b0a-47f7-a019-45b45568befe</td>
<td>Download Powerware Ransomware</td>
</tr>
<tr>
<td>43dc33fe-f7c2-4741-845c-6ce3f6d703a8</td>
<td>Download Radamant Ransomware</td>
</tr>
<tr>
<td>98cc1e97-9240-4bd5-8448-7d9e71b27249</td>
<td>Download Petya Ransomware</td>
</tr>
<tr>
<td>dc07c76e-b891-43d3-9244-6992524a57f9</td>
<td>Download Nemucod Ransomware</td>
</tr>
<tr>
<td>366a6950-0a08-4295-a7ca-890e47f2cc9b</td>
<td>Download Mobef Ransomware</td>
</tr>
<tr>
<td>16f39816-d245-46fd-ab5d-bd9b18c1d47d</td>
<td>Download Maktub Ransomware</td>
</tr>
<tr>
<td>207144d0-aa40-48c4-99e6-5b246840e7e7</td>
<td>Download Linux Encoder Ransomware</td>
</tr>
<tr>
<td>68d41700-100e-4145-9e34-d38cfa4d75c5</td>
<td>Download KeRanger Ransomware</td>
</tr>
<tr>
<td>8daab70f-0b85-4f24-87a2-40d88effad87</td>
<td>Download Locky Ransomware</td>
</tr>
<tr>
<td>0d5e4988-cffc-4c83-b3e5-3775d0735e3d</td>
<td>Download Kimcilware Ransomware</td>
</tr>
<tr>
<td>b434bb61-67d7-4556-8ff9-99a88b52b566</td>
<td>Download Lechiffre Ransomware</td>
</tr>
<tr>
<td>afb2d3db-7107-40d0-bf28-067c84e144e6</td>
<td>Download Mischa Ransomware</td>
</tr>
<tr>
<td>c567a416-f320-4b9a-8268-50ad6aa0818d</td>
<td>Download ODCODC Ransomware</td>
</tr>
<tr>
<td>5b075299-0368-48f9-a380-b46974b574ca</td>
<td>Download Ransom32 Ransomware</td>
</tr>
<tr>
<td>ef72cfc8-796c-4a35-abea-547f0d898713</td>
<td>Download Coverton Ransomware</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h3>Test - Locky</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Id</strong></th>
<th><strong>Name</strong></th>
<th><strong>Created</strong></th>
<th><strong>Modified</strong></th>
<th><strong>Runnable</strong></th>
<th><strong>Last Result</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>529eebb2-a53c-4f82-9a0e-fc59763cb542</td>
<td>Locky</td>
<td>2019-08-27T10:17:09.968467Z</td>
<td>2019-09-02T07:08:20.393468Z</td>
<td>true</td>
<td>Failed</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h3>Assets (Locky)</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Hostname</strong></th>
<th><strong>Id</strong></th>
<th><strong>Ipv4Address</strong></th>
<th><strong>Modified</strong></th>
<th><strong>ProductName</strong></th>
<th><strong>Status</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>ec2amaz-g4iu5no</td>
<td>03e17460-849e-4b86-b6c6-ef0db72823ff</td>
<td>172.31.39.254</td>
<td>2019-09-18T08:12:16.957300Z</td>
<td>Windows Server 2016 Datacenter</td>
<td>Active</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h3>Scenarios (Locky)</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Id</strong></th>
<th><strong>Name</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>7701f8fb-a725-4a6d-b48d-1881868e24ea</td>
<td>Locky File Encryption</td>
</tr>
<tr>
<td>874d2a63-0cc2-4700-b8b5-6fd31d151c7b</td>
<td>Locky Ransomware Persistence</td>
</tr>
<tr>
<td>150473e3-995b-4c10-81e8-29037f877bf1</td>
<td>Locky Ransomware DGA</td>
</tr>
</tbody>
</table>
<h3>Test - Cryptolocker</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Id</strong></th>
<th><strong>Name</strong></th>
<th><strong>Created</strong></th>
<th><strong>Modified</strong></th>
<th><strong>Runnable</strong></th>
<th><strong>Last Result</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>10413458-7bae-4d47-94e9-06197c60d156</td>
<td>Cryptolocker</td>
<td>2019-08-27T10:17:09.842767Z</td>
<td>2019-09-02T07:08:17.069927Z</td>
<td>true</td>
<td>Failed</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h3>Assets (Cryptolocker)</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Hostname</strong></th>
<th><strong>Id</strong></th>
<th><strong>Ipv4Address</strong></th>
<th><strong>Modified</strong></th>
<th><strong>ProductName</strong></th>
<th><strong>Status</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>ec2amaz-g4iu5no</td>
<td>03e17460-849e-4b86-b6c6-ef0db72823ff</td>
<td>172.31.39.254</td>
<td>2019-09-18T08:12:16.957300Z</td>
<td>Windows Server 2016 Datacenter</td>
<td>Active</td>
</tr>
</tbody>
</table>
<h3>Scenarios (Cryptolocker)</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Id</strong></th>
<th><strong>Name</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>0f45019b-817e-43f2-82c6-accb28c22b7b</td>
<td>Cryptolocker DGA</td>
</tr>
<tr>
<td>411eb1a9-8e00-4d77-b8a1-8f204987a2d2</td>
<td>CryptoLocker Persistence</td>
</tr>
</tbody>
</table>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="h_044bc4ea-ed11-4cc0-84f1-2e0b32751f26">8. Get the test results of an assessment</h3>
<hr />
<p>Returns the test results of an assessment.</p>
<h5>Base Command</h5>
<p><code>attackiq-get-test-results</code></p>
<h5>Input</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 85px;"><strong>Argument Name</strong></th>
<th style="width: 568px;"><strong>Description</strong></th>
<th style="width: 55px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 85px;">test_id</td>
<td style="width: 568px;">ID of the test in which to show results.</td>
<td style="width: 55px;">Required</td>
</tr>
<tr>
<td style="width: 85px;">show_last_result</td>
<td style="width: 568px;">Shows the last result. True shows the last result.</td>
<td style="width: 55px;">Optional</td>
</tr>
<tr>
<td style="width: 85px;">page_number</td>
<td style="width: 568px;">The page number of the test results.</td>
<td style="width: 55px;">Optional</td>
</tr>
<tr>
<td style="width: 85px;">page_size</td>
<td style="width: 568px;">The maximum page size of the results.</td>
<td style="width: 55px;">Optional</td>
</tr>
<tr>
<td style="width: 85px;">outcome_filter</td>
<td style="width: 568px;">Filters results according to user choice. If set to Passed will return only Passed tests and vice versa.</td>
<td style="width: 55px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 267px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 369px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 267px;">AttackIQTestResult.Id</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">ID of the test result.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Modified</td>
<td style="width: 72px;">Date</td>
<td style="width: 369px;">The date the test result was last modified.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Assessment.Id</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The ID of the test assessment.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Assessment.Name</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The name of the test assessment.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.LastResult</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The result of the test's last run.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Scenario.Id</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The scenario ID of the test results.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Scenario.Name</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The scenario name of the test results.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Scenario.Description</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The scenario description of the test results.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Asset.Id</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The ID of the test results asset.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Asset.Ipv4Address</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The IP address of the test results scenario asset.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Asset.Hostname</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The host name of the test results asset.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Asset.ProductName</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The product name of the test results asset.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Asset.Modified</td>
<td style="width: 72px;">Date</td>
<td style="width: 369px;">The date that the asset was last modified.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.AssetGroup</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The asset group of the test.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.JobState</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The state of the job.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Outcome</td>
<td style="width: 72px;">String</td>
<td style="width: 369px;">The result outcome of the test.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.RemainingPages</td>
<td style="width: 72px;">Number</td>
<td style="width: 369px;">The number of remaining pages to return. For example, if the total number pages is 6, and the last fetch was page 5, the value is 1.</td>
</tr>
<tr>
<td style="width: 267px;">AttackIQTestResult.Count</td>
<td style="width: 72px;">Number</td>
<td style="width: 369px;">The total number of tests.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !attackiq-get-test-results test_id=1c350a5a-84f2-4938-93d8-cc31f0a99482 page_number=10 page_size=5 outcome_filter=Passed</pre>
<h5>Context Example</h5>
<pre>{
    "AttackIQTestResult": 62
}
</pre>
<h5>Human Readable Output</h5>
<h3>Test Results for 1c350a5a-84f2-4938-93d8-cc31f0a99482</h3>
<p>### Page 10/72</p>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Assessment Name</strong></th>
<th><strong>Scenario Name</strong></th>
<th><strong>Hostname</strong></th>
<th><strong>Asset IP</strong></th>
<th><strong>Job State</strong></th>
<th><strong>Modified</strong></th>
<th><strong>Outcome</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Arseny's ransomware project</td>
<td>Download Mischa Ransomware</td>
<td>ec2amaz-g4iu5no</td>
<td>172.31.39.254</td>
<td>&nbsp;</td>
<td>2019-09-16T08:41:37.542585Z</td>
<td>&nbsp;</td>
</tr>
<tr>
<td>Arseny's ransomware project</td>
<td>Download AutoLocky Ransomware</td>
<td>ec2amaz-g4iu5no</td>
<td>172.31.39.254</td>
<td>&nbsp;</td>
<td>2019-09-16T08:41:32.646222Z</td>
<td>&nbsp;</td>
</tr>
<tr>
<td>Arseny's ransomware project</td>
<td>Download Mobef Ransomware</td>
<td>ec2amaz-g4iu5no</td>
<td>172.31.39.254</td>
<td>&nbsp;</td>
<td>2019-09-16T08:41:23.089756Z</td>
<td>&nbsp;</td>
</tr>
<tr>
<td>Arseny's ransomware project</td>
<td>Download BadBlock Ransomeware</td>
<td>ec2amaz-g4iu5no</td>
<td>172.31.39.254</td>
<td>&nbsp;</td>
<td>2019-09-16T08:41:18.225112Z</td>
<td>&nbsp;</td>
</tr>
</tbody>
</table>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p></div>

<h3 id="attackiq-list-assessment-templates">9. attackiq-list-assessment-templates</h3>
<hr>
<p>List all available assessment templates.</p>
<h5>Base Command</h5>
<p>
  <code>attackiq-list-assessment-templates</code>
</p>

<h5>Required Permissions</h5>
<h5>Input</h5>
There are no input arguments for this command.
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
      <td>AttackIQ.Template.ID</td>
      <td>String</td>
      <td>The template ID. </td>
    </tr>
    <tr>
      <td>AttackIQ.Template.Name</td>
      <td>String</td>
      <td>The template name.</td>
    </tr>
    <tr>
      <td>AttackIQ.Template.ProjectName</td>
      <td>String</td>
      <td>The name of the project the templete is in.</td>
    </tr>
    <tr>
      <td>AttackIQ.Template.Description</td>
      <td>String</td>
      <td>The description of the template.</td>
    </tr>
    <tr>
      <td>AttackIQ.Template.ProjectDescription</td>
      <td>String</td>
      <td>The description of the project the template is in.</td>
    </tr>
    <tr>
      <td>AttackIQ.Template.Hidden</td>
      <td>Boolean</td>
      <td>Whether the template is hidden.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!attackiq-list-assessment-templates</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AttackIQ.Template": [
        {
            "Description": "Custom project template",
            "Hidden": false,
            "ID": "d09d29ba-eed8-4212-bff2-4d1ee11ed80c",
            "Name": "Custom",
            "ProjectDescription": "Custom project",
            "ProjectName": "Custom"
        },
        {
            "Description": "AttackIQ\u2019s analysis and mapping of the \u201c2019 Crowdstrike Global Threat Report\u201d",
            "Hidden": false,
            "ID": "b30063b9-8f98-4f95-8f32-3a489f239dc8",
            "Name": "Crowdstrike Global Threat Report 2019",
            "ProjectDescription": "AttackIQ\u2019s analysis and mapping of the \u201c2019 Crowdstrike Global Threat Report\u201d",
            "ProjectName": "2019 Crowdstrike Global Threat Report \u2013 Top ATT&CK Techniques"
        },
        {
            "Description": "AttackIQ\u2019s analysis and mapping of the \u201cATT&CK by the Numbers\u201d @ NOVA BSides 2019",
            "Hidden": false,
            "ID": "2b118268-3fbd-42d0-9839-730c3bfa242b",
            "Name": "ATT&CK by the Numbers",
            "ProjectDescription": "AttackIQ\u2019s analysis and mapping of the \u201cATT&CK by the Numbers\u201d @ NOVA BSides 2019",
            "ProjectName": "ATT&CK by the Numbers @ NOVA BSides 2019"
        },
        {
            "Description": "AttackIQ\u2019s analysis and mapping of the \u201c2019 Red Canary Threat Detection Report \u2013 Top ATT&CK Techniques\u201d",
            "Hidden": false,
            "ID": "28933bd5-9323-4a01-8d02-3da3eb0c5d9e",
            "Name": "Red Canary Threat Detection Report 2019",
            "ProjectDescription": "AttackIQ\u2019s analysis and mapping of the \u201c2019 Red Canary Threat Detection Report \u2013 Top ATT&CK Techniques\u201d",
            "ProjectName": "2019 Red Canary Threat Detection Report \u2013 Top ATT&CK Techniques"
        },
        {
            "Description": "Test the Ransomware kill-chain for different samples: Download sample, Save it to disk and Encrypt user's files",
            "Hidden": true,
            "ID": "59d35f4a-2da0-4c4a-a08a-c30cb41dae6b",
            "Name": "Ransomware",
            "ProjectDescription": "Test the Ransomware kill-chain for different samples: Download sample, Save it to disk and Encrypt user's files",
            "ProjectName": "Ransomware"
        },
        {
            "Description": "Test your security controls by running scenarios with different user privileges (Windows only)",
            "Hidden": false,
            "ID": "f876dcbd-77bb-4321-b2a8-c279151b9490",
            "Name": "Managed Privileges",
            "ProjectDescription": "Test your security controls by running scenarios with different user privileges (Windows only)",
            "ProjectName": "Managed Privileges"
        },
        {
            "Description": "Are you a CISO joining a new company? This will help you assess the baseline of the security controls inside your network.",
            "Hidden": true,
            "ID": "6108a03e-16be-47d0-b455-7955c74a43f5",
            "Name": "Security Control Coverage",
            "ProjectDescription": "Test your security controls",
            "ProjectName": "Security Control Coverage"
        },
        {
            "Description": "Test common threats focused on cryptocurrency",
            "Hidden": true,
            "ID": "c11d1a86-df25-452d-8054-7e7cae7d4167",
            "Name": "Cryptocurrency Threats",
            "ProjectDescription": "Test common threats focused on cryptocurrency",
            "ProjectName": "Cryptocurrency Threats"
        },
        {
            "Description": "How would your security controls, processes and people respond against common attack techniques used by known threat actors?",
            "Hidden": false,
            "ID": "14908dc4-0c6f-4445-9af7-cb5438de950b",
            "Name": "MITRE Threat Assessment",
            "ProjectDescription": "Test several adversarial techniques based on MITRE ATT&CK",
            "ProjectName": "MITRE Threat Assessment"
        },
        {
            "Description": "Common techniques to obtain passwords from Windows and browsers",
            "Hidden": false,
            "ID": "c297b3fa-1c56-4e57-88bd-08ec19ec09bd",
            "Name": "Windows Credential Theft",
            "ProjectDescription": "Common techniques to obtain passwords from Windows and browsers",
            "ProjectName": "Windows Credential Theft"
        },
        {
            "Description": "Use the MITRE ATT&CK Matrix to assess your security controls.",
            "Hidden": false,
            "ID": "73599a2c-ee91-44a8-b017-febccd64b364",
            "Name": "MITRE ATT&CK",
            "ProjectDescription": "Select and test various adversarial techniques based on MITRE ATT&CK",
            "ProjectName": "MITRE ATT&CK"
        },
        {
            "Description": "Test adversarial techniques focused on command and control",
            "Hidden": true,
            "ID": "438bbcb8-c573-49b0-8ed8-31f6e7d4257e",
            "Name": "C&C",
            "ProjectDescription": "Test adversarial techniques focused on command and control",
            "ProjectName": "C&C"
        },
        {
            "Description": "Test adversarial techniques focused on discovery",
            "Hidden": false,
            "ID": "f75f1e9e-d01a-4ee2-aba3-883aaee498fe",
            "Name": "Discovery",
            "ProjectDescription": "Test adversarial techniques focused on discovery",
            "ProjectName": "Discovery"
        },
        {
            "Description": "Test adversarial techniques focused on credential access",
            "Hidden": false,
            "ID": "6386735a-9d6d-40a5-826c-635298b02acc",
            "Name": "Credential Access",
            "ProjectDescription": "Test adversarial techniques focused on credential access",
            "ProjectName": "Credential Access"
        },
        {
            "Description": "Test adversarial techniques focused on persistence",
            "Hidden": false,
            "ID": "db958dfd-2da1-440e-9c93-0dc7fd64dfbf",
            "Name": "Persistence",
            "ProjectDescription": "Test adversarial techniques focused on persistence",
            "ProjectName": "Persistence"
        },
        {
            "Description": "Test adversarial techniques focused on defense evasion",
            "Hidden": false,
            "ID": "b5e8a1a5-78fa-4003-a4c2-8b3142e42388",
            "Name": "Defense Evasion",
            "ProjectDescription": "Test adversarial techniques focused on defense evasion",
            "ProjectName": "Defense Evasion"
        },
        {
            "Description": "Test adversarial techniques focused on exfiltration",
            "Hidden": false,
            "ID": "15984ed5-b93e-4ef2-9550-8d36fd49cc58",
            "Name": "Exfiltration",
            "ProjectDescription": "Test adversarial techniques focused on exfiltration",
            "ProjectName": "Exfiltration"
        },
        {
            "Description": "Test adversarial techniques focused on execution",
            "Hidden": false,
            "ID": "6bee8a19-d997-419a-b799-64a67a71644a",
            "Name": "Execution",
            "ProjectDescription": "Test adversarial techniques focused on execution",
            "ProjectName": "Execution"
        },
        {
            "Description": "Test of data loss prevention capabilities by trying to exfiltrate credit card numbers and password patterns over HTTP, ICMP, and DNS",
            "Hidden": false,
            "ID": "517bab19-d382-4835-99f4-74dcbe428f81",
            "Name": "DLP Data Exfiltration",
            "ProjectDescription": "Test of data loss prevention capabilities by trying to exfiltrate credit card numbers and password patterns over HTTP, ICMP, and DNS",
            "ProjectName": "DLP Data Exfiltration"
        },
        {
            "Description": "Basic test of antivirus capabilities",
            "Hidden": true,
            "ID": "219a9735-2923-49c6-bde6-775db3a12655",
            "Name": "Antivirus",
            "ProjectDescription": "Basic test of antivirus capabilities",
            "ProjectName": "Antivirus"
        },
        {
            "Description": "Basic test of common ingress/egress ports",
            "Hidden": true,
            "ID": "efff3e44-eea4-4eaa-80e7-d2c5aec44e76",
            "Name": "Firewall",
            "ProjectDescription": "Basic test of common ingress/egress ports",
            "ProjectName": "Firewall"
        },
        {
            "Description": "C&C communication, circumvention by proxy services or tor, and general content filtering configuration tests",
            "Hidden": true,
            "ID": "4b7bfd88-ff3e-4949-b0b7-3268f5967084",
            "Name": "Content Filtering",
            "ProjectDescription": "C&C communication, circumvention by proxy services or tor, and general content filtering configuration tests",
            "ProjectName": "Content Filtering"
        },
        {
            "Description": "Malicious network traffic and network attacks",
            "Hidden": true,
            "ID": "5a8909d7-2e50-4a81-bab9-884005e3e824",
            "Name": "IDS/IPS",
            "ProjectDescription": "Malicious network traffic and network attacks",
            "ProjectName": "IDS/IPS"
        },
        {
            "Description": "Basic tests of advanced endpoint solutions on selected machines",
            "Hidden": false,
            "ID": "7dd68971-0448-4784-884b-3d143b3c80df",
            "Name": "Advanced Endpoint (Windows)",
            "ProjectDescription": "Basic tests of advanced endpoint solutions on selected machines",
            "ProjectName": "Advanced Endpoint (Windows)"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
</p>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>ProjectName</strong></th>
      <th><strong>ProjectDescription</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> d09d29ba-eed8-4212-bff2-4d1ee11ed80c </td>
      <td> Custom </td>
      <td> Custom project template </td>
      <td> Custom </td>
      <td> Custom project </td>
    </tr>
    <tr>
      <td> b30063b9-8f98-4f95-8f32-3a489f239dc8 </td>
      <td> Crowdstrike Global Threat Report 2019 </td>
      <td> AttackIQ’s analysis and mapping of the “2019 Crowdstrike Global Threat Report” </td>
      <td> 2019 Crowdstrike Global Threat Report – Top ATT&CK Techniques </td>
      <td> AttackIQ’s analysis and mapping of the “2019 Crowdstrike Global Threat Report” </td>
    </tr>
    <tr>
      <td> 2b118268-3fbd-42d0-9839-730c3bfa242b </td>
      <td> ATT&CK by the Numbers </td>
      <td> AttackIQ’s analysis and mapping of the “ATT&CK by the Numbers” @ NOVA BSides 2019 </td>
      <td> ATT&CK by the Numbers @ NOVA BSides 2019 </td>
      <td> AttackIQ’s analysis and mapping of the “ATT&CK by the Numbers” @ NOVA BSides 2019 </td>
    </tr>
    <tr>
      <td> 28933bd5-9323-4a01-8d02-3da3eb0c5d9e </td>
      <td> Red Canary Threat Detection Report 2019 </td>
      <td> AttackIQ’s analysis and mapping of the “2019 Red Canary Threat Detection Report – Top ATT&CK Techniques” </td>
      <td> 2019 Red Canary Threat Detection Report – Top ATT&CK Techniques </td>
      <td> AttackIQ’s analysis and mapping of the “2019 Red Canary Threat Detection Report – Top ATT&CK Techniques” </td>
    </tr>
    <tr>
      <td> 59d35f4a-2da0-4c4a-a08a-c30cb41dae6b </td>
      <td> Ransomware </td>
      <td> Test the Ransomware kill-chain for different samples: Download sample, Save it to disk and Encrypt user's files </td>
      <td> Ransomware </td>
      <td> Test the Ransomware kill-chain for different samples: Download sample, Save it to disk and Encrypt user's files </td>
    </tr>
    <tr>
      <td> f876dcbd-77bb-4321-b2a8-c279151b9490 </td>
      <td> Managed Privileges </td>
      <td> Test your security controls by running scenarios with different user privileges (Windows only) </td>
      <td> Managed Privileges </td>
      <td> Test your security controls by running scenarios with different user privileges (Windows only) </td>
    </tr>
    <tr>
      <td> 6108a03e-16be-47d0-b455-7955c74a43f5 </td>
      <td> Security Control Coverage </td>
      <td> Are you a CISO joining a new company? This will help you assess the baseline of the security controls inside your network. </td>
      <td> Security Control Coverage </td>
      <td> Test your security controls </td>
    </tr>
    <tr>
      <td> c11d1a86-df25-452d-8054-7e7cae7d4167 </td>
      <td> Cryptocurrency Threats </td>
      <td> Test common threats focused on cryptocurrency </td>
      <td> Cryptocurrency Threats </td>
      <td> Test common threats focused on cryptocurrency </td>
    </tr>
    <tr>
      <td> 14908dc4-0c6f-4445-9af7-cb5438de950b </td>
      <td> MITRE Threat Assessment </td>
      <td> How would your security controls, processes and people respond against common attack techniques used by known threat actors? </td>
      <td> MITRE Threat Assessment </td>
      <td> Test several adversarial techniques based on MITRE ATT&CK </td>
    </tr>
    <tr>
      <td> c297b3fa-1c56-4e57-88bd-08ec19ec09bd </td>
      <td> Windows Credential Theft </td>
      <td> Common techniques to obtain passwords from Windows and browsers </td>
      <td> Windows Credential Theft </td>
      <td> Common techniques to obtain passwords from Windows and browsers </td>
    </tr>
    <tr>
      <td> 73599a2c-ee91-44a8-b017-febccd64b364 </td>
      <td> MITRE ATT&CK </td>
      <td> Use the MITRE ATT&CK Matrix to assess your security controls. </td>
      <td> MITRE ATT&CK </td>
      <td> Select and test various adversarial techniques based on MITRE ATT&CK </td>
    </tr>
    <tr>
      <td> 438bbcb8-c573-49b0-8ed8-31f6e7d4257e </td>
      <td> C&C </td>
      <td> Test adversarial techniques focused on command and control </td>
      <td> C&C </td>
      <td> Test adversarial techniques focused on command and control </td>
    </tr>
    <tr>
      <td> f75f1e9e-d01a-4ee2-aba3-883aaee498fe </td>
      <td> Discovery </td>
      <td> Test adversarial techniques focused on discovery </td>
      <td> Discovery </td>
      <td> Test adversarial techniques focused on discovery </td>
    </tr>
    <tr>
      <td> 6386735a-9d6d-40a5-826c-635298b02acc </td>
      <td> Credential Access </td>
      <td> Test adversarial techniques focused on credential access </td>
      <td> Credential Access </td>
      <td> Test adversarial techniques focused on credential access </td>
    </tr>
    <tr>
      <td> db958dfd-2da1-440e-9c93-0dc7fd64dfbf </td>
      <td> Persistence </td>
      <td> Test adversarial techniques focused on persistence </td>
      <td> Persistence </td>
      <td> Test adversarial techniques focused on persistence </td>
    </tr>
    <tr>
      <td> b5e8a1a5-78fa-4003-a4c2-8b3142e42388 </td>
      <td> Defense Evasion </td>
      <td> Test adversarial techniques focused on defense evasion </td>
      <td> Defense Evasion </td>
      <td> Test adversarial techniques focused on defense evasion </td>
    </tr>
    <tr>
      <td> 15984ed5-b93e-4ef2-9550-8d36fd49cc58 </td>
      <td> Exfiltration </td>
      <td> Test adversarial techniques focused on exfiltration </td>
      <td> Exfiltration </td>
      <td> Test adversarial techniques focused on exfiltration </td>
    </tr>
    <tr>
      <td> 6bee8a19-d997-419a-b799-64a67a71644a </td>
      <td> Execution </td>
      <td> Test adversarial techniques focused on execution </td>
      <td> Execution </td>
      <td> Test adversarial techniques focused on execution </td>
    </tr>
    <tr>
      <td> 517bab19-d382-4835-99f4-74dcbe428f81 </td>
      <td> DLP Data Exfiltration </td>
      <td> Test of data loss prevention capabilities by trying to exfiltrate credit card numbers and password patterns over HTTP, ICMP, and DNS </td>
      <td> DLP Data Exfiltration </td>
      <td> Test of data loss prevention capabilities by trying to exfiltrate credit card numbers and password patterns over HTTP, ICMP, and DNS </td>
    </tr>
    <tr>
      <td> 219a9735-2923-49c6-bde6-775db3a12655 </td>
      <td> Antivirus </td>
      <td> Basic test of antivirus capabilities </td>
      <td> Antivirus </td>
      <td> Basic test of antivirus capabilities </td>
    </tr>
    <tr>
      <td> efff3e44-eea4-4eaa-80e7-d2c5aec44e76 </td>
      <td> Firewall </td>
      <td> Basic test of common ingress/egress ports </td>
      <td> Firewall </td>
      <td> Basic test of common ingress/egress ports </td>
    </tr>
    <tr>
      <td> 4b7bfd88-ff3e-4949-b0b7-3268f5967084 </td>
      <td> Content Filtering </td>
      <td> C&C communication, circumvention by proxy services or tor, and general content filtering configuration tests </td>
      <td> Content Filtering </td>
      <td> C&C communication, circumvention by proxy services or tor, and general content filtering configuration tests </td>
    </tr>
    <tr>
      <td> 5a8909d7-2e50-4a81-bab9-884005e3e824 </td>
      <td> IDS/IPS </td>
      <td> Malicious network traffic and network attacks </td>
      <td> IDS/IPS </td>
      <td> Malicious network traffic and network attacks </td>
    </tr>
    <tr>
      <td> 7dd68971-0448-4784-884b-3d143b3c80df </td>
      <td> Advanced Endpoint (Windows) </td>
      <td> Basic tests of advanced endpoint solutions on selected machines </td>
      <td> Advanced Endpoint (Windows) </td>
      <td> Basic tests of advanced endpoint solutions on selected machines </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="attackiq-list-assets">10. attackiq-list-assets</h3>
<hr>
<p>List all assets.</p>
<h5>Base Command</h5>
<p>
  <code>attackiq-list-assets</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>

<h5>Input</h5>
There are no input arguments for this command.
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
      <td>AttackIQ.Asset.ID</td>
      <td>String</td>
      <td>The asset ID.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.Description</td>
      <td>String</td>
      <td>The description of the asset.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.IPv4</td>
      <td>String</td>
      <td>The IPv4 address of the asset.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.IPv6</td>
      <td>String</td>
      <td>The IPv6 address of the asset.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.MacAddress</td>
      <td>String</td>
      <td>The MAC address of the asset.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.ProcessorArch</td>
      <td>String</td>
      <td>The processor arch of the asset.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.ProductName</td>
      <td>String</td>
      <td>The name of the asset.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.Hostname</td>
      <td>String</td>
      <td>The hostname of the asset.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.Domain</td>
      <td>String</td>
      <td>The domain of the asset.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.User</td>
      <td>String</td>
      <td>The user of the asset.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.Status</td>
      <td>String</td>
      <td>Status of the asset.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.Groups.ID</td>
      <td>String</td>
      <td>The ID of the asset's group.</td>
    </tr>
    <tr>
      <td>AttackIQ.Asset.Groups.Name</td>
      <td>String</td>
      <td>The name of the asset's group.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!attackiq-list-assets</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AttackIQ.Asset": [
        {
            "Description": null,
            "Domain": "workgroup",
            "Groups": [
                {
                    "ID": "4fe9c3b1-2a26-487a-97bd-a098e55ea3d2",
                    "Name": "Demisto asset group"
                }
            ],
            "Hostname": "ec2amaz-g4iu5no",
            "ID": "03e17460-849e-4b86-b6c6-ef0db72823ff",
            "IPv4": "172.31.39.254",
            "IPv6": null,
            "MacAddress": "06-FB-B8-38-E2-2A",
            "ProcessorArch": "amd64",
            "ProductName": "Windows Server 2016 Datacenter",
            "Status": "Active",
            "User": "agent_7377e1fa-d49d-44bf-84ef-4e1dfb8e4748@demisto.com"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
### Assets:
</p>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Hostname</strong></th>
      <th><strong>IPv4</strong></th>
      <th><strong>MacAddress</strong></th>
      <th><strong>Domain</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>User</strong></th>
      <th><strong>Status</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 03e17460-849e-4b86-b6c6-ef0db72823ff </td>
      <td> ec2amaz-g4iu5no </td>
      <td> 172.31.39.254 </td>
      <td> 06-FB-B8-38-E2-2A </td>
      <td> workgroup </td>
      <td>  </td>
      <td> agent_7377e1fa-d49d-44bf-84ef-4e1dfb8e4748@demisto.com </td>
      <td> Active </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="attackiq-create-assessment">11. attackiq-create-assessment</h3>
<hr>
<p>Creates a new assesment.</p>
<h5>Base Command</h5>
<p>
  <code>attackiq-create-assessment</code>
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
      <td>name</td>
      <td>The name of the new assesment</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>template_id</td>
      <td>The ID of the template from which to create the assesment.</td>
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
      <td>AttackIQ.Assessment.Id</td>
      <td>String</td>
      <td>The ID of the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.Name</td>
      <td>String</td>
      <td>The name of the assessment name.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.Description</td>
      <td>String</td>
      <td>The description of the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.StartDate</td>
      <td>Date</td>
      <td>The start date of the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.EndDate</td>
      <td>Date</td>
      <td>The end date of the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.AssessmentState</td>
      <td>String</td>
      <td>The state of the assessment. Can be Active or Inactive.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.DefaultSchedule</td>
      <td>String</td>
      <td>The default schedule timing (cron) of the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.AssessmentTemplateId</td>
      <td>String</td>
      <td>The template ID of the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.AssessmentTemplateName</td>
      <td>String</td>
      <td>The template name of the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.AssessmentTemplateDescription</td>
      <td>String</td>
      <td>The template description of the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.AssessmentTemplateDefaultSchedule</td>
      <td>Unknown</td>
      <td>The assessment's template default schedule timing (cron).</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.AssessmentTemplateCompany</td>
      <td>String</td>
      <td>The owner of the template.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.AssessmentTemplateCreated</td>
      <td>Date</td>
      <td>The date that the template was created.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.AssessmentTemplateModified</td>
      <td>Date</td>
      <td>The date that the template was last modified.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.Creator</td>
      <td>String</td>
      <td>The user who created the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.Owner</td>
      <td>String</td>
      <td>The user who owns the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.User</td>
      <td>String</td>
      <td>The user who ran the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.Created</td>
      <td>String</td>
      <td>The date that the assessment was created.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.Modified</td>
      <td>String</td>
      <td>The date that the assessment was last modified.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.Users</td>
      <td>String</td>
      <td>The user IDs that can access the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.Groups</td>
      <td>String</td>
      <td>The user groups that can access the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.DefaultAssetCount</td>
      <td>Number</td>
      <td>The number of machines (assets) that are connected to the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.DefaultAssetGroupCount</td>
      <td>Number</td>
      <td>The number of asset groups that are connected to the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.MasterJobCount</td>
      <td>Number</td>
      <td>The number of tests that ran in the assessment.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.Count</td>
      <td>Number</td>
      <td>The total number of assessments.</td>
    </tr>
    <tr>
      <td>AttackIQ.Assessment.RemainingPages</td>
      <td>Number</td>
      <td>The number of remaining pages to return. For example, if the total number of pages is 6, and the last fetch was page 5, the value is 1.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!attackiq-create-assessment name="Assessment from test playbook" template_id="d09d29ba-eed8-4212-bff2-4d1ee11ed80c"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AttackIQ.Assessment": {
        "AssessmentState": "Inactive",
        "AssessmentTemplateCompany": "906d5ec6-101c-4ae6-8906-b93ce0529060",
        "AssessmentTemplateCreated": "2017-01-18T00:05:10.032807Z",
        "AssessmentTemplateDefaultSchedule": null,
        "AssessmentTemplateDescription": "Custom project template",
        "AssessmentTemplateId": "d09d29ba-eed8-4212-bff2-4d1ee11ed80c",
        "AssessmentTemplateModified": "2018-07-10T21:38:32.040806Z",
        "AssessmentTemplateName": "Custom",
        "Created": "2019-10-29T08:37:22.187577Z",
        "Creator": "olichter@paloaltonetworks.com",
        "DefaultAssetCount": 0,
        "DefaultAssetGroupCount": 0,
        "DefaultSchedule": null,
        "Description": "Custom project",
        "EndDate": null,
        "Groups": [],
        "Id": "08023e86-3b8c-4f98-ab46-7c931d759157",
        "MasterJobCount": 0,
        "Modified": "2019-10-29T08:37:22.187603Z",
        "Name": "Assessment from test playbook",
        "Owner": "olichter@paloaltonetworks.com",
        "StartDate": null,
        "User": "olichter@paloaltonetworks.com",
        "Users": [
            "e9f58a46-31bc-4099-9bb1-624bb20a7340"
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
### Created Assessment: 08023e86-3b8c-4f98-ab46-7c931d759157 successfully.
</p>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Id</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>User</strong></th>
      <th><strong>Created</strong></th>
      <th><strong>Modified</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 08023e86-3b8c-4f98-ab46-7c931d759157 </td>
      <td> Assessment from test playbook </td>
      <td> Custom project </td>
      <td> olichter@paloaltonetworks.com </td>
      <td> 2019-10-29T08:37:22.187577Z </td>
      <td> 2019-10-29T08:37:22.187603Z </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="attackiq-add-assets-to-assessment">12. attackiq-add-assets-to-assessment</h3>
<hr>
<p>Adds assets or asset groups to an assesment.</p>
<h5>Base Command</h5>
<p>
  <code>attackiq-add-assets-to-assessment</code>
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
      <td>assets</td>
      <td>A comma-seperated list of asset IDs.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>asset_groups</td>
      <td>A comma-seperated list of asset group IDs.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>assessment_id</td>
      <td>The ID of the assessment to which the assets will be added.</td>
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
  <code>!attackiq-add-assets-to-assessment assets="03e17460-849e-4b86-b6c6-ef0db72823ff" assessment_id="b2fc06d4-5d0a-4924-a126-66320887dce0"</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Successfully updated default assets/asset groups for project b2fc06d4-5d0a-4924-a126-66320887dce0
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="attackiq-delete-assessment">13. attackiq-delete-assessment</h3>
<hr>
<p>Deletes an assessment.</p>
<h5>Base Command</h5>
<p>
  <code>attackiq-delete-assessment</code>
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
      <td>assessment_id</td>
      <td>The ID of the assessment to delete.</td>
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
  <code>!attackiq-delete-assessment assessment_id="b2fc06d4-5d0a-4924-a126-66320887dce0"</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Deleted assessment b2fc06d4-5d0a-4924-a126-66320887dce0 successfully.
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
