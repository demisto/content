<!-- HTML_DOC -->
<p>Use the Atlassian Confluence Server API integration to manage your Confluence spaces and content.</p>
<p>This integration was integrated and tested with version 6.1 of Atlassian Confluence Server.</p>
<h2>
<a id="Configure_Atlassian_Confluence_Server_on_Demisto_4"></a>Configure Atlassian Confluence Server on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Atlassian Confluence Server.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g.<span> </span>http://1.2.3.4:8090)</strong></li>
<li><strong>Username</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>
<a id="Commands_16"></a>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_c66282e6-68d7-4de1-99c0-353759967c61" target="_self">Create a space: confluence-create-space</a></li>
<li><a href="#h_41991150-fafe-4e28-a884-5db88ef3d457" target="_self">Create content for a space: confluence-create-content</a></li>
<li><a href="#h_d0032205-b3b2-44a6-b00e-eebd5a6c81f0" target="_self">Get a list of all spaces: confluence-list-spaces</a></li>
<li><a href="#h_8eb3996f-7730-4a27-a962-6320cf366bd8" target="_self">Get content for a space: confluence-get-content</a></li>
<li><a href="#h_e517036b-4104-4ed3-9bdd-53fb0876aa10" target="_self">Delete content: confluence-delete-content</a></li>
<li><a href="#h_8037dac0-f498-40e0-9b2b-25b7664d0692" target="_self">Update (overwrite) existing content: confluence-update-content</a></li>
<li><a href="#h_7cf7ae25-f72d-449b-b478-439e6323b9c8" target="_self">Run a CQL query: confluence-search-content</a></li>
</ol>
<h3 id="h_c66282e6-68d7-4de1-99c0-353759967c61">
<a id="1_Create_a_space_25"></a>1. Create a space</h3>
<hr>
<p>Creates a new Confluence space.</p>
<h5>
<a id="Base_Command_28"></a>Base Command</h5>
<p><code>confluence-create-space</code></p>
<h5>
<a id="Input_31"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 522px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">name</td>
<td style="width: 522px;">Space name, for example: “Test Space”.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">description</td>
<td style="width: 522px;">A description for the space.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">key</td>
<td style="width: 522px;">Space key, which will be used as input when creating or updating child components from a space.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_40"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 420px;"><strong>Path</strong></th>
<th style="width: 95px;"><strong>Type</strong></th>
<th style="width: 225px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 420px;">Confluence.Space.ID</td>
<td style="width: 95px;">string</td>
<td style="width: 225px;">Space ID.</td>
</tr>
<tr>
<td style="width: 420px;">Confluence.Space.Key</td>
<td style="width: 95px;">string</td>
<td style="width: 225px;">Space key.</td>
</tr>
<tr>
<td style="width: 420px;">Confluence.Space.Name</td>
<td style="width: 95px;">string</td>
<td style="width: 225px;">Space name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_49"></a>Command Example</h5>
<pre>!confluence-create-space name=test description="testing space" key=TEST</pre>
<h5>
<a id="Human_Readable_Output_54"></a>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/61211686-eda37400-a708-11e9-89df-74f46428a2df.png" alt="image"></p>
<h3 id="h_41991150-fafe-4e28-a884-5db88ef3d457">
<a id="2_Create_content_for_a_space_58"></a>2. Create content for a space</h3>
<hr>
<p>Creates Confluence content for a given space.</p>
<h5>
<a id="Base_Command_61"></a>Base Command</h5>
<p><code>confluence-create-content</code></p>
<h5>
<a id="Input_64"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 170px;"><strong>Argument Name</strong></th>
<th style="width: 479px;"><strong>Description</strong></th>
<th style="width: 91px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170px;">title</td>
<td style="width: 479px;">Confluence page title.</td>
<td style="width: 91px;">Required</td>
</tr>
<tr>
<td style="width: 170px;">type</td>
<td style="width: 479px;">Confluence content type. Can be “page” or “blogpost”.</td>
<td style="width: 91px;">Required</td>
</tr>
<tr>
<td style="width: 170px;">space</td>
<td style="width: 479px;">Space key to add content to a specific space.</td>
<td style="width: 91px;">Required</td>
</tr>
<tr>
<td style="width: 170px;">body</td>
<td style="width: 479px;">Confluence page body to add.</td>
<td style="width: 91px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_74"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 392px;"><strong>Path</strong></th>
<th style="width: 89px;"><strong>Type</strong></th>
<th style="width: 259px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 392px;">Confluence.Content.ID</td>
<td style="width: 89px;">string</td>
<td style="width: 259px;">Page content ID.</td>
</tr>
<tr>
<td style="width: 392px;">Confluence.Content.Title</td>
<td style="width: 89px;">string</td>
<td style="width: 259px;">Content title.</td>
</tr>
<tr>
<td style="width: 392px;">Confluence.Content.Type</td>
<td style="width: 89px;">string</td>
<td style="width: 259px;">Content type.</td>
</tr>
<tr>
<td style="width: 392px;">Confluence.Content.Body</td>
<td style="width: 89px;">string</td>
<td style="width: 259px;">Content body.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_84"></a>Command Example</h5>
<pre>!confluence-create-content space=DemistoContent title="test confluence integration" type=page body=testing</pre>
<h5>
<a id="Human_Readable_Output_89"></a>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/61211959-8cc86b80-a709-11e9-9b02-38223f462487.png" alt="image"></p>
<h3 id="h_d0032205-b3b2-44a6-b00e-eebd5a6c81f0">
<a id="3_Get_a_list_of_all_spaces_93"></a>3. Get a list of all spaces</h3>
<hr>
<p>Returns a list of all Confluence spaces.</p>
<h5>
<a id="Base_Command_96"></a>Base Command</h5>
<p><code>confluence-list-spaces</code></p>
<h5>
<a id="Input_99"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 530px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">limit</td>
<td style="width: 530px;">Maximum number of spaces to return.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">type</td>
<td style="width: 530px;">Filter the returned list of spaces by type. Can be “global” or “personal”.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">status</td>
<td style="width: 530px;">Filter the returned list of spaces by status. Can be “current” or “archived”.</td>
<td style="width: 73px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_108"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 419px;"><strong>Path</strong></th>
<th style="width: 96px;"><strong>Type</strong></th>
<th style="width: 225px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 419px;">Confluence.Space.ID</td>
<td style="width: 96px;">string</td>
<td style="width: 225px;">Space ID.</td>
</tr>
<tr>
<td style="width: 419px;">Confluence.Space.Key</td>
<td style="width: 96px;">string</td>
<td style="width: 225px;">Space key.</td>
</tr>
<tr>
<td style="width: 419px;">Confluence.Space.Name</td>
<td style="width: 96px;">string</td>
<td style="width: 225px;">Space name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_117"></a>Command Example</h5>
<pre>!confluence-list-spaces</pre>
<h5>
<a id="Human_Readable_Output_122"></a>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/61212165-1a0bc000-a70a-11e9-8f93-15073bb4850f.png" alt="image"></p>
<h3 id="h_8eb3996f-7730-4a27-a962-6320cf366bd8">
<a id="4_Get_content_for_a_space_126"></a>4. Get content for a space</h3>
<hr>
<p>Returns Confluence content by space key and title.</p>
<h5>
<a id="Base_Command_129"></a>Base Command</h5>
<p><code>confluence-get-content</code></p>
<h5>
<a id="Input_132"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 330px;"><strong>Argument Name</strong></th>
<th style="width: 229px;"><strong>Description</strong></th>
<th style="width: 181px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 330px;">key</td>
<td style="width: 229px;">Space key.</td>
<td style="width: 181px;">Required</td>
</tr>
<tr>
<td style="width: 330px;">title</td>
<td style="width: 229px;">Content title.</td>
<td style="width: 181px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_140"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 399px;"><strong>Path</strong></th>
<th style="width: 95px;"><strong>Type</strong></th>
<th style="width: 246px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 399px;">Confluence.Content.ID</td>
<td style="width: 95px;">string</td>
<td style="width: 246px;">Content ID.</td>
</tr>
<tr>
<td style="width: 399px;">Confluence.Content.Title</td>
<td style="width: 95px;">string</td>
<td style="width: 246px;">Content title.</td>
</tr>
<tr>
<td style="width: 399px;">Confluence.Content.Type</td>
<td style="width: 95px;">string</td>
<td style="width: 246px;">Content type.</td>
</tr>
<tr>
<td style="width: 399px;">Confluence.Content.Version</td>
<td style="width: 95px;">string</td>
<td style="width: 246px;">Content version.</td>
</tr>
<tr>
<td style="width: 399px;">Confluence.Content.Body</td>
<td style="width: 95px;">string</td>
<td style="width: 246px;">Content body.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_151"></a>Command Example</h5>
<pre>!confluence-get-content key=DemistoContent title=“test confluence integration”</pre>
<h5>
<a id="Human_Readable_Output_154"></a>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/61212224-46bfd780-a70a-11e9-87da-e50a5179e2fe.png" alt="image"></p>
<h3 id="h_e517036b-4104-4ed3-9bdd-53fb0876aa10">
<a id="5_Delete_content_157"></a>5. Delete content</h3>
<hr>
<p>Deletes Confluence content.</p>
<h5>
<a id="Base_Command_160"></a>Base Command</h5>
<p><code>confluence-delete-content</code></p>
<h5>
<a id="Input_163"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 332px;"><strong>Argument Name</strong></th>
<th style="width: 225px;"><strong>Description</strong></th>
<th style="width: 183px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 332px;">id</td>
<td style="width: 225px;">Content ID</td>
<td style="width: 183px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_170"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 361px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 299px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 361px;">Confluence.Content.Result</td>
<td style="width: 80px;">string</td>
<td style="width: 299px;">Content delete result.</td>
</tr>
<tr>
<td style="width: 361px;">Confluence.Content.ID</td>
<td style="width: 80px;">string</td>
<td style="width: 299px;">Content ID deleted.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_178"></a>Command Example</h5>
<pre>!confluence-delete-content id=172723162</pre>
<h5>
<a id="Human_Readable_Output_181"></a>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/61212428-ed0bdd00-a70a-11e9-9447-b4e11dd66260.png" alt="image"></p>
<h3 id="h_8037dac0-f498-40e0-9b2b-25b7664d0692">
<a id="6_Update_overwrite_existing_content_185"></a>6. Update (overwrite) existing content</h3>
<hr>
<p>Update (overwrite) the existing content of a Confluence page with new content.</p>
<h5>
<a id="Base_Command_188"></a>Base Command</h5>
<p><code>confluence-update-content</code></p>
<h5>
<a id="Input_191"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 518px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">pageid</td>
<td style="width: 518px;">Page ID used to find and update the page.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">currentversion</td>
<td style="width: 518px;">The version number, extracted from a content search. The integration will increment by 1.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">title</td>
<td style="width: 518px;">Title of the page to update.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">type</td>
<td style="width: 518px;">Content type. Can be “page” or “blogpost”.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">space</td>
<td style="width: 518px;">Space key to update.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">body</td>
<td style="width: 518px;">Content body to replace (overwrite) existing content of a Confluence page.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_203"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 419px;"><strong>Path</strong></th>
<th style="width: 90px;"><strong>Type</strong></th>
<th style="width: 231px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 419px;">Confluence.Content.ID</td>
<td style="width: 90px;">string</td>
<td style="width: 231px;">Content ID.</td>
</tr>
<tr>
<td style="width: 419px;">Confluence.Content.Title</td>
<td style="width: 90px;">string</td>
<td style="width: 231px;">Content title.</td>
</tr>
<tr>
<td style="width: 419px;">Confluence.Content.Type</td>
<td style="width: 90px;">string</td>
<td style="width: 231px;">Content type.</td>
</tr>
<tr>
<td style="width: 419px;">Confluence.Content.Body</td>
<td style="width: 90px;">string</td>
<td style="width: 231px;">Content body.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_213"></a>Command Example</h5>
<pre>!confluence-update-content type=page pageid=172723162 currentversion=2 space=DemistoContent title="test confluence integration" body="new body"</pre>
<h5>
<a id="Human_Readable_Output_216"></a>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/61212301-8686bf00-a70a-11e9-9aac-7c2d4698c3bb.png" alt="image"></p>
<h3 id="h_7cf7ae25-f72d-449b-b478-439e6323b9c8">
<a id="7_Run_a_CQL_query_220"></a>7. Run a CQL query</h3>
<hr>
<p>Fetches a list of content using the Confluence Query Language (CQL). For more information about CQL syntax, see the<span> </span><a href="https://developer.atlassian.com/server/confluence/advanced-searching-using-cql/" target="_blank" rel="noopener">Atlassian Confluence documentation</a>.</p>
<h5>
<a id="Base_Command_223"></a>Base Command</h5>
<p><code>confluence-search-content</code></p>
<h5>
<a id="Input_226"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 139px;"><strong>Argument Name</strong></th>
<th style="width: 530px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">cql</td>
<td style="width: 530px;">A CQL query string to use to locate content, for example: “space = DEV order by created”.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 139px;">cqlcontext</td>
<td style="width: 530px;">The context in which to execute a CQL search. The context is the JSON serialized form of SearchContext.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">expand</td>
<td style="width: 530px;">A CSV list of properties to expand on the content.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">start</td>
<td style="width: 530px;">The start point of the collection to return.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">limit</td>
<td style="width: 530px;">Maximum number of items to return. This can be restricted by fixed system limits. Default is 25.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_237"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 407px;"><strong>Path</strong></th>
<th style="width: 87px;"><strong>Type</strong></th>
<th style="width: 246px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 407px;">Confluence.Content.ID</td>
<td style="width: 87px;">string</td>
<td style="width: 246px;">Content ID.</td>
</tr>
<tr>
<td style="width: 407px;">Confluence.Content.Title</td>
<td style="width: 87px;">string</td>
<td style="width: 246px;">Content title.</td>
</tr>
<tr>
<td style="width: 407px;">Confluence.Content.Type</td>
<td style="width: 87px;">string</td>
<td style="width: 246px;">Content type.</td>
</tr>
<tr>
<td style="width: 407px;">Confluence.Content.Version</td>
<td style="width: 87px;">string</td>
<td style="width: 246px;">Content version.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_247"></a>Command Example</h5>
<pre>!confluence-search-content cql="title=\"test confluence integration\""</pre>
<h5>
<a id="Human_Readable_Output_250"></a>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/61212390-cf3e7800-a70a-11e9-90db-3f1a72c77d06.png" alt="image"></p>