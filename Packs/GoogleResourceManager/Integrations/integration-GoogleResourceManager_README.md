<!-- HTML_DOC -->
<p>This integration was integrated and tested with version xx of Google Resource Manager</p>
<h2>Configure Google Resource Manager on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Google Resource Manager.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Project ID</strong></li>
<li><strong>Private Key ID</strong></li>
<li><strong>Private Key</strong></li>
<li><strong>Client Email</strong></li>
<li><strong>Client ID</strong></li>
<li><strong>Client X509 Cert URL</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.<br>After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_41199988831548576986335">Create a new project: grm-create-project</a></li>
<li><a href="#h_142730261761548576992423">Get information for a project: grm-get-project</a></li>
<li><a href="#h_7622305761481548576997112">Get a list of all projects: grm-list-projects</a></li>
<li><a href="#h_3587048592191548577003536">Update a project: grm-update-project</a></li>
<li><a href="#h_8592298922891548577010544">Search organization resources: grm-search-organizations</a></li>
<li><a href="#h_6871832833581548577016880">Get information for an organization: grm-get-organization</a></li>
<li><a href="#h_2968228454261548577021815">Delete a project: grm-delete-project</a></li>
<li><a href="#h_8986470554931548577028217">Restore a project: grm-undelete-project</a></li>
</ol>
<h3 id="h_41199988831548576986335">1. Create a new project</h3>
<hr>
<p>Creates a new Project resource with the user-specified values passed as command arguments.</p>
<h5>Base Command</h5>
<p><code>grm-create-project</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 178px;"><strong>Argument Name</strong></th>
<th style="width: 491px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 178px;">project_id</td>
<td style="width: 491px;">The unique, user-assigned ID of the Project. It must be 6 to 30 lowercase letters, digits, or hyphens. It must start with a letter. Trailing hyphens are prohibited. Example: tokyo-rain-123</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 178px;">parent_id</td>
<td style="width: 491px;">The ID of the parent resource. Organizations' Name output is in the format "organizations/12345" where the numbers after the forward slash are the ID of the organization. To find Organization IDs available to assign as a parent resource try running the grm-search-organization command.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 178px;">label_keys</td>
<td style="width: 491px;">The label keys associated with this Project. Label keys must be between 1 and 63 characters long and conform to the following regular expression: <code>[a-z]([-a-z0-9]*[a-z0-9])?</code>. You can associate a maximum of 256 labels with a given resource.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 178px;">name</td>
<td style="width: 491px;">The user-assigned display name of the Project. It must be 4 to 30 characters. Supported characters: lowercase and uppercase letters, numbers, hyphens, single-quotes, double-quotes, spaces, and exclamation points. Example: My Project</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 178px;">parent_type</td>
<td style="width: 491px;">Represents the resource type the parent_id is for. Valid resource types: "organization" and "folder".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 178px;">label_values</td>
<td style="width: 491px;">The label values associated with this Project. Label values must be between 0 and 63 characters long and conform to the following regular expression <code>[a-z]([-a-z0-9]*[a-z0-9])?</code>. A label value can be empty. You can associate a maximum of 256 labels with a given resource.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 232px;"><strong>Path</strong></th>
<th style="width: 76px;"><strong>Type</strong></th>
<th style="width: 432px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 232px;">GRM.Project.Name</td>
<td style="width: 76px;">String</td>
<td style="width: 432px;">The user-assigned display name of the Project</td>
</tr>
<tr>
<td style="width: 232px;">GRM.Project.ID</td>
<td style="width: 76px;">String</td>
<td style="width: 432px;">The unique, user-assigned ID of the Project</td>
</tr>
<tr>
<td style="width: 232px;">GRM.Project.Number</td>
<td style="width: 76px;">String</td>
<td style="width: 432px;">The number uniquely identifying the Project</td>
</tr>
<tr>
<td style="width: 232px;">GRM.Project.State</td>
<td style="width: 76px;">String</td>
<td style="width: 432px;">The Project lifecycle state</td>
</tr>
<tr>
<td style="width: 232px;">GRM.Project.CreateTime</td>
<td style="width: 76px;">Date</td>
<td style="width: 432px;">createTime - The time the resource was created</td>
</tr>
<tr>
<td style="width: 232px;">GRM.Project.Label</td>
<td style="width: 76px;">Unknown</td>
<td style="width: 432px;">The labels associated with this Project</td>
</tr>
<tr>
<td style="width: 232px;">GRM.Project.Parent.ID</td>
<td style="width: 76px;">String</td>
<td style="width: 432px;">ID of the parent resource</td>
</tr>
<tr>
<td style="width: 232px;">GRM.Project.Parent.Type</td>
<td style="width: 76px;">String</td>
<td style="width: 432px;">Type of the parent resource</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>grm-create-project project_id=faramir-111 parent_id=690006273490 parent_type=organization name="Faramir"</code></p>
<h5>Context Example</h5>
<pre>{
    "GRM.Project": {
        "Name": "Faramir",
        "Parent": {
            "Type": "organization",
            "ID": "690006273490"
        },
        "Number": "110336878499",
        "Label": null,
        "State": "ACTIVE",
        "ID": "faramir-111",
        "CreateTime": "2019-01-15T12:30:21.267Z"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Google Cloud Project Successfully Created</h3>
<table>
<thead>
<tr>
<th>Name</th>
<th>Parent</th>
<th>Number</th>
<th>ID</th>
<th>State</th>
<th>Label</th>
<th>CreateTime</th>
</tr>
</thead>
<tbody>
<tr>
<td>Faramir</td>
<td>Type: organization<br>ID: 690006273490</td>
<td>110336878499</td>
<td>faramir-111</td>
<td>ACTIVE</td>
<td> </td>
<td>2019-01-15T12:30:21.267Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_142730261761548576992423">2. Getting information for a project</h3>
<hr>
<p>Retrieves the Project by the specified project_id, e.g., my-project-123.</p>
<h5>Base Command</h5>
<p><code>grm-get-project</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 162px;"><strong>Argument Name</strong></th>
<th style="width: 492px;"><strong>Description</strong></th>
<th style="width: 86px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162px;">project_id</td>
<td style="width: 492px;">The unique ID of the Project to fetch, e.g., tokyo-rain-123.</td>
<td style="width: 86px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 218px;"><strong>Path</strong></th>
<th style="width: 90px;"><strong>Type</strong></th>
<th style="width: 432px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 218px;">GRM.Project.Number</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">The number uniquely identifying the Project</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.ID</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">The unique, user-assigned ID of the Project</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.State</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">The Project lifecycle state</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.Name</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">The user-assigned display name of the Project</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.CreateTime</td>
<td style="width: 90px;">Date</td>
<td style="width: 432px;">createTime - The time the resource was created</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.Label</td>
<td style="width: 90px;">Unknown</td>
<td style="width: 432px;">The labels associated with this Project</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.Parent.ID</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">ID of the parent resource</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.Parent.Type</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">Type of the parent resource</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>grm-get-project project_id=faramir-111</code></p>
<h5>Context Example</h5>
<pre>{
    "GRM.Project": {
        "Name": "Faramir",
        "Parent": {
            "Type": "organization",
            "ID": "690006273490"
        },
        "Number": "110336878499",
        "Label": null,
        "State": "ACTIVE",
        "ID": "faramir-111",
        "CreateTime": "2019-01-15T12:30:21.267Z"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Details of Fetched Google Cloud Project</h3>
<table>
<thead>
<tr>
<th>Name</th>
<th>Parent</th>
<th>Number</th>
<th>ID</th>
<th>State</th>
<th>Label</th>
<th>CreateTime</th>
</tr>
</thead>
<tbody>
<tr>
<td>Faramir</td>
<td>Type: organization<br>ID: 690006273490</td>
<td>110336878499</td>
<td>faramir-111</td>
<td>ACTIVE</td>
<td> </td>
<td>2019-01-15T12:30:21.267Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_7622305761481548576997112">3. Get a list of all projects</h3>
<hr>
<p>Lists projects that are visible to the user and satisfies the specified filter. Projects are returned in an unspecified order.</p>
<h5>Base Command</h5>
<p><code>grm-list-projects</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 269px;"><strong>Argument Name</strong></th>
<th style="width: 400px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 269px;">filter</td>
<td style="width: 400px;">An expression for filtering the results of the request. Filter rules are case insensitive. The fields eligible for filtering are: <br>
<ul>
<li>name</li>
<li>id</li>
<li>labels.key (where key is the name of a label)</li>
</ul>
<p>Examples:</p>
<ul>
<li>
<code>name:how*</code>: The project's name starts with "how".</li>
<li>
<code>name:Howl</code>: The project's name is Howl or howl.</li>
<li>
<code>name:HOWL</code>: Equivalent to above.</li>
<li>
<code>NAME:howl</code>: Equivalent to above.</li>
<li>
<code>labels.color:*</code>: The project has the label color.</li>
<li>
<code>labels.color:red</code>: The project's label color has the value red.</li>
</ul>
</td>
<td style="width: 71px;">Optional </td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 226px;"><strong>Path</strong></th>
<th style="width: 89px;"><strong>Type</strong></th>
<th style="width: 425px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 226px;">GRM.Project.Name</td>
<td style="width: 89px;">String</td>
<td style="width: 425px;">The user-assigned display name of the Project</td>
</tr>
<tr>
<td style="width: 226px;">GRM.Project.ID</td>
<td style="width: 89px;">String</td>
<td style="width: 425px;">The unique, user-assigned ID of the Project</td>
</tr>
<tr>
<td style="width: 226px;">GRM.Project.Number</td>
<td style="width: 89px;">String</td>
<td style="width: 425px;">The number uniquely identifying the Project</td>
</tr>
<tr>
<td style="width: 226px;">GRM.Project.State</td>
<td style="width: 89px;">String</td>
<td style="width: 425px;">The Project lifecycle state.</td>
</tr>
<tr>
<td style="width: 226px;">GRM.Project.CreateTime</td>
<td style="width: 89px;">Date</td>
<td style="width: 425px;">The time the resource was created</td>
</tr>
<tr>
<td style="width: 226px;">GRM.Project.Label</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 425px;">The labels associated with this Project</td>
</tr>
<tr>
<td style="width: 226px;">GRM.Project.Parent.ID</td>
<td style="width: 89px;">String</td>
<td style="width: 425px;">ID of the parent resource</td>
</tr>
<tr>
<td style="width: 226px;">GRM.Project.Parent.Type</td>
<td style="width: 89px;">String</td>
<td style="width: 425px;">Type of the parent resource</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>grm-list-projects filter="id:faramir*"</code></p>
<h5>Context Example</h5>
<pre>{
    "GRM.Project": [
        {
            "Name": "Faramir 2",
            "Parent": {
                "Type": "organization",
                "ID": "690006273490"
            },
            "Number": "877118493152",
            "Label": null,
            "State": "ACTIVE",
            "ID": "faramir-222",
            "CreateTime": "2019-01-20T07:42:58.155Z"
        },
        {
            "Name": "Faramir",
            "Parent": {
                "Type": "organization",
                "ID": "690006273490"
            },
            "Number": "110336878499",
            "Label": null,
            "State": "ACTIVE",
            "ID": "faramir-111",
            "CreateTime": "2019-01-15T12:30:21.267Z"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Projects Filtered by 'id:faramir*'</h3>
<table>
<thead>
<tr>
<th>Name</th>
<th>Parent</th>
<th>Number</th>
<th>ID</th>
<th>State</th>
<th>Label</th>
<th>CreateTime</th>
</tr>
</thead>
<tbody>
<tr>
<td>Faramir 2</td>
<td>Type: organization<br>ID: 690006273490</td>
<td>877118493152</td>
<td>faramir-222</td>
<td>ACTIVE</td>
<td> </td>
<td>2019-01-20T07:42:58.155Z</td>
</tr>
<tr>
<td>Faramir</td>
<td>Type: organization<br>ID: 690006273490</td>
<td>110336878499</td>
<td>faramir-111</td>
<td>ACTIVE</td>
<td> </td>
<td>2019-01-15T12:30:21.267Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3587048592191548577003536">4. Update a project</h3>
<hr>
<p>Updates the attributes of the Project identified by the specified project_id. Currently the only fields that can be updated are the project name and labels.</p>
<h5>Base Command</h5>
<p><code>grm-update-project</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 145px;"><strong>Argument Name</strong></th>
<th style="width: 524px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145px;">project_id</td>
<td style="width: 524px;">The unique ID of the Project to update.<br>Example: tokyo-rain-123</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">name</td>
<td style="width: 524px;">The string to update the Project name with. It must be 4 to 30 characters. Supported characters are: lowercase and uppercase letters, numbers, hyphens, single-quotes, double-quotes, spaces, and exclamation points.<br>Example: My Project</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">parent_id</td>
<td style="width: 524px;">The ID of the parent resource. Organizations' Name output is in the format <code>organizations/12345</code> where the numbers after the forward slash are the ID of the organization. To find Organization IDs available to assign as a parent resource try running the grm-search-organization command.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">parent_type</td>
<td style="width: 524px;">The resource type the parent_id is for. Valid resource types: "organization" and "folder".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">label_keys</td>
<td style="width: 524px;">The label keys to associate with this Project. Label keys must be between 1 and 63 characters long and conform to the following regular expression: <code>[a-z]([-a-z0-9]*[a-z0-9])?</code> You can associate a maximum of 256 labels with a given resource.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">label_values</td>
<td style="width: 524px;">The label values to associate with this Project. Label values must be between 0 and 63 characters long and conform to the following regular expression <code>[a-z]([-a-z0-9]*[a-z0-9])?</code>. A label value can be empty. You can associate a maximum of 256 labels with a given resource.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 233px;"><strong>Path</strong></th>
<th style="width: 82px;"><strong>Type</strong></th>
<th style="width: 425px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 233px;">GRM.Project.Name</td>
<td style="width: 82px;">String</td>
<td style="width: 425px;">The user-assigned display name of the Project</td>
</tr>
<tr>
<td style="width: 233px;">GRM.Project.ID</td>
<td style="width: 82px;">String</td>
<td style="width: 425px;">The unique, user-assigned ID of the Project</td>
</tr>
<tr>
<td style="width: 233px;">GRM.Project.Number</td>
<td style="width: 82px;">String</td>
<td style="width: 425px;">The number uniquely identifying the Project</td>
</tr>
<tr>
<td style="width: 233px;">GRM.Project.State</td>
<td style="width: 82px;">String</td>
<td style="width: 425px;">The Project lifecycle state.</td>
</tr>
<tr>
<td style="width: 233px;">GRM.Project.CreateTime</td>
<td style="width: 82px;">Date</td>
<td style="width: 425px;">The time the resource was created</td>
</tr>
<tr>
<td style="width: 233px;">GRM.Project.Label</td>
<td style="width: 82px;">Unknown</td>
<td style="width: 425px;">The labels associated with this Project</td>
</tr>
<tr>
<td style="width: 233px;">GRM.Project.Parent.ID</td>
<td style="width: 82px;">String</td>
<td style="width: 425px;">ID of the parent resource</td>
</tr>
<tr>
<td style="width: 233px;">GRM.Project.Parent.Type</td>
<td style="width: 82px;">String</td>
<td style="width: 425px;">Type of the parent resource</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>grm-update-project project_id=faramir-111 parent_id=690006273490 parent_type=organization name="Faramir-Updated"</code></p>
<h5>Context Example</h5>
<pre>{
    "GRM.Project": {
        "Name": "Faramir-Updated",
        "Parent": {
            "Type": "organization",
            "ID": "690006273490"
        },
        "Number": "110336878499",
        "Label": null,
        "State": "ACTIVE",
        "ID": "faramir-111",
        "CreateTime": "2019-01-15T12:30:21.267Z"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Details of Updated Google Cloud Project</h3>
<table>
<thead>
<tr>
<th>Name</th>
<th>Parent</th>
<th>Number</th>
<th>ID</th>
<th>State</th>
<th>Label</th>
<th>CreateTime</th>
</tr>
</thead>
<tbody>
<tr>
<td>Faramir-Updated</td>
<td>Type: organization<br>ID: 690006273490</td>
<td>110336878499</td>
<td>faramir-111</td>
<td>ACTIVE</td>
<td> </td>
<td>2019-01-15T12:30:21.267Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_8592298922891548577010544">5. Search organization resources</h3>
<hr>
<p>Searches Organization resources that are visible to the user and satisfies the specified filter. Organizations are returned in an unspecified order. New Organizations do not necessarily appear at the end of the results.</p>
<h5>Base Command</h5>
<p><code>grm-search-organizations</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 532px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">page_size</td>
<td style="width: 532px;">The maximum number of Organizations to return in the response.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">page_token</td>
<td style="width: 532px;">A pagination token returned from a previous call to "organizations.search" that indicates from where the listing should continue</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">filter</td>
<td style="width: 532px;">An expression for filtering the Organizations returned in the results. Filter rules are case-insensitive. Organizations can be filtered by 'owner.directoryCustomerId' or by 'domain', where the domain is a G Suite domain, e.g., owner.directorycustomerid:123456789 Organizations with owner.directory_customer_id equal to 123456789. domain:google.com Organizations corresponding to the domain google.com.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 279px;"><strong>Path</strong></th>
<th style="width: 32px;"><strong>Type</strong></th>
<th style="width: 429px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 279px;">GRM.Organization.Name</td>
<td style="width: 32px;">String</td>
<td style="width: 429px;">The resource name of the organization. This is the organization's relative path in the API. Its format is "organizations/[organization_id]" e.g. "organizations/1234".</td>
</tr>
<tr>
<td style="width: 279px;">GRM.Organization.State</td>
<td style="width: 32px;">String</td>
<td style="width: 429px;">The organization's current lifecycle state</td>
</tr>
<tr>
<td style="width: 279px;">GRM.Organization.CreateTime</td>
<td style="width: 32px;">Date</td>
<td style="width: 429px;">The time the organization resource was created</td>
</tr>
<tr>
<td style="width: 279px;">GRM.Organization.Owner.CustomerID</td>
<td style="width: 32px;">String</td>
<td style="width: 429px;">The G Suite customer ID used in the Directory API</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>grm-search-organizations</code></p>
<h5>Context Example</h5>
<pre>{
    "GRM.Organization": [
        {
            "Owner": {
                "CustomerID": "C02f0zfqw"
            },
            "State": "ACTIVE",
            "CreateTime": "2017-04-25T13:41:05.196Z",
            "Name": "organizations/690006273490"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Organizations</h3>
<table>
<thead>
<tr>
<th>Owner</th>
<th>State</th>
<th>Name</th>
<th>CreateTime</th>
</tr>
</thead>
<tbody>
<tr>
<td>CustomerID: C02f0zfqw</td>
<td>ACTIVE</td>
<td>organizations/690006273490</td>
<td>2017-04-25T13:41:05.196Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_6871832833581548577016880">6. Get information for an organization</h3>
<hr>
<p>Returns an Organization resource identified by the specified resource name.</p>
<h5>Base Command</h5>
<p><code>grm-get-organization</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 534px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">name</td>
<td style="width: 534px;">The resource name of the Organization to fetch, e.g., "organizations/1234".</td>
<td style="width: 72px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 278px;"><strong>Path</strong></th>
<th style="width: 33px;"><strong>Type</strong></th>
<th style="width: 429px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 278px;">GRM.Organization.Name</td>
<td style="width: 33px;">String</td>
<td style="width: 429px;">The resource name of the organization. This is the organization's relative path in the API. Its format is "organizations/[organization_id]" e.g., "organizations/1234"</td>
</tr>
<tr>
<td style="width: 278px;">GRM.Organization.State</td>
<td style="width: 33px;">String</td>
<td style="width: 429px;">The organization's current lifecycle state</td>
</tr>
<tr>
<td style="width: 278px;">GRM.Organization.CreateTime</td>
<td style="width: 33px;">Date</td>
<td style="width: 429px;">The time the organization resource was created</td>
</tr>
<tr>
<td style="width: 278px;">GRM.Organization.Owner.CustomerID</td>
<td style="width: 33px;">String</td>
<td style="width: 429px;">The G Suite customer ID used in the Directory API</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>grm-get-organization name=organizations/690006273490</code></p>
<h5>Context Example</h5>
<pre>{
    "GRM.Organization": {
        "Owner": {
            "CustomerID": "C02f0zfqw"
        },
        "State": "ACTIVE",
        "CreateTime": "2017-04-25T13:41:05.196Z",
        "Name": "organizations/690006273490"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Details of Fetched Organization</h3>
<table>
<thead>
<tr>
<th>Owner</th>
<th>State</th>
<th>Name</th>
<th>CreateTime</th>
</tr>
</thead>
<tbody>
<tr>
<td>CustomerID: C02f0zfqw</td>
<td>ACTIVE</td>
<td>organizations/690006273490</td>
<td>2017-04-25T13:41:05.196Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_2968228454261548577021815">7. Delete an organization</h3>
<hr>
<p>Marks the Project identified by the specified project_id to be deleted, e.g., my-project-123.</p>
<h5>Base Command</h5>
<p><code>grm-delete-project</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 153px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 81px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153px;">project_id</td>
<td style="width: 506px;">The unique ID of the Project to delete. Example: tokyo-rain-123</td>
<td style="width: 81px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 218px;"><strong>Path</strong></th>
<th style="width: 90px;"><strong>Type</strong></th>
<th style="width: 432px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 218px;">GRM.Project.State</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">The Project lifecycle state</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.Number</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">The number uniquely identifying the Project</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.ID</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">The unique, user-assigned ID of the Project</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.Name</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">The user-assigned display name of the Project</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.CreateTime</td>
<td style="width: 90px;">Date</td>
<td style="width: 432px;">createTime - The time the resource was created</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.Label</td>
<td style="width: 90px;">Unknown</td>
<td style="width: 432px;">The labels associated with this Project</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.Parent.ID</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">ID of the parent resource</td>
</tr>
<tr>
<td style="width: 218px;">GRM.Project.Parent.Type</td>
<td style="width: 90px;">String</td>
<td style="width: 432px;">Type of the parent resource</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>grm-delete-project project_id=faramir-111</code></p>
<h5>Context Example</h5>
<pre>{
    "GRM.Project": {
        "Name": "Faramir-Updated",
        "Parent": {
            "Type": "organization",
            "ID": "690006273490"
        },
        "Number": "110336878499",
        "Label": null,
        "State": "DELETE_REQUESTED",
        "ID": "faramir-111",
        "CreateTime": "2019-01-15T12:30:21.267Z"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Project State Successfully Set To DELETE_REQUESTED</h3>
<table>
<thead>
<tr>
<th>Name</th>
<th>Parent</th>
<th>Number</th>
<th>ID</th>
<th>State</th>
<th>Label</th>
<th>CreateTime</th>
</tr>
</thead>
<tbody>
<tr>
<td>Faramir-Updated</td>
<td>Type: organization<br>ID: 690006273490</td>
<td>110336878499</td>
<td>faramir-111</td>
<td>DELETE_REQUESTED</td>
<td> </td>
<td>2019-01-15T12:30:21.267Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_8986470554931548577028217">8. Restore a project</h3>
<hr>
<p>Restores the Project identified by the specified project_id, e.g., my-project-123.</p>
<h5>Base Command</h5>
<p><code>grm-undelete-project</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 150px;"><strong>Argument Name</strong></th>
<th style="width: 510px;"><strong>Description</strong></th>
<th style="width: 80px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 150px;">project_id</td>
<td style="width: 510px;">The unique ID of the Project to restore. Example: tokyo-rain-123</td>
<td style="width: 80px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 224px;"><strong>Path</strong></th>
<th style="width: 91px;"><strong>Type</strong></th>
<th style="width: 425px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 224px;">GRM.Project.State</td>
<td style="width: 91px;">String</td>
<td style="width: 425px;">The Project lifecycle state</td>
</tr>
<tr>
<td style="width: 224px;">GRM.Project.Number</td>
<td style="width: 91px;">String</td>
<td style="width: 425px;">The number uniquely identifying the Project</td>
</tr>
<tr>
<td style="width: 224px;">GRM.Project.ID</td>
<td style="width: 91px;">String</td>
<td style="width: 425px;">The unique, user-assigned ID of the Project</td>
</tr>
<tr>
<td style="width: 224px;">GRM.Project.Name</td>
<td style="width: 91px;">String</td>
<td style="width: 425px;">The user-assigned display name of the Project</td>
</tr>
<tr>
<td style="width: 224px;">GRM.Project.CreateTime</td>
<td style="width: 91px;">Date</td>
<td style="width: 425px;">The time the resource was created</td>
</tr>
<tr>
<td style="width: 224px;">GRM.Project.Label</td>
<td style="width: 91px;">Unknown</td>
<td style="width: 425px;">The labels associated with this Project</td>
</tr>
<tr>
<td style="width: 224px;">GRM.Project.Parent.ID</td>
<td style="width: 91px;">String</td>
<td style="width: 425px;">ID of the parent resource</td>
</tr>
<tr>
<td style="width: 224px;">GRM.Project.Parent.Type</td>
<td style="width: 91px;">String</td>
<td style="width: 425px;">Type of the parent resource</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>grm-undelete-project project_id=faramir-111</code></p>
<h5>Context Example</h5>
<pre>{
    "GRM.Project": {
        "Name": "Faramir-Updated",
        "Parent": {
            "Type": "organization",
            "ID": "690006273490"
        },
        "Number": "110336878499",
        "Label": null,
        "State": "ACTIVE",
        "ID": "faramir-111",
        "CreateTime": "2019-01-15T12:30:21.267Z"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Project State Successfully Set To ACTIVE</h3>
<table>
<thead>
<tr>
<th>Name</th>
<th>Parent</th>
<th>Number</th>
<th>ID</th>
<th>State</th>
<th>Label</th>
<th>CreateTime</th>
</tr>
</thead>
<tbody>
<tr>
<td>Faramir-Updated</td>
<td>Type: organization<br>ID: 690006273490</td>
<td>110336878499</td>
<td>faramir-111</td>
<td>ACTIVE</td>
<td> </td>
<td>2019-01-15T12:30:21.267Z</td>
</tr>
</tbody>
</table>