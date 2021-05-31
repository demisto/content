<!-- HTML_DOC -->
<p>Use the GitHub integration to manage GitHub issues directly from Demisto.</p>
<h2>Configure GitHub on Demisto</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for GitHub.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Fetch incidents</strong></li>
<li><strong>API Token</strong></li>
<li><strong>Credentials (for GitHub bots)</strong></li>
<li><strong>Username of the repository owner, for example: github.com/repos/{<em>owner</em>}/{repo}/issues</strong></li>
<li><strong>The name of the requested repository.</strong></li>
<li><strong>First fetch timestamp, in days.</strong></li>
<li><strong>Use system proxy settings.</strong></li>
<li><strong>Trust any certificate (not secure).</strong></li>
<li><strong>Incident type</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
*Use API token to authenticate as a user and credentials to authenticate as a bot.
<h2>Authenticating</h2>
The integration provides 2 methods of authentication: API token and private key. The API token method is used
to authenticate as a GitHub user, and take actions on behalf of a certain GitHub user. On the other hand, the second 
method uses private key to generate a JWT token to create the API token. This method is required when authenticating as
a bot, a.k.a. GitHub apps.

<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_b3e20a76-c892-4f29-b887-0dbd313f0948" target="_self">Create an issue: GitHub-create-issue</a></li>
<li><a href="#h_3dae91c2-1d82-4b6b-95ef-f7fbdf4813fd" target="_self">Close an issue: GitHub-close-issue</a></li>
<li><a href="#h_3d48d1bf-c274-405c-ad1d-e3f9c1440a3d" target="_self">Update an issue: GitHub-update-issue</a></li>
<li><a href="#h_71872e56-33da-4385-9d5f-89cfecaee19e" target="_self">List all issues: GitHub-list-all-issues</a></li>
<li><a href="#h_ea932aae-5ed3-4b5c-a972-be5526e4bddd" target="_self">Search issues: GitHub-search-issues</a></li>
<li><a href="#h_5dfb412d-e0e1-4344-8216-8fc769620534" target="_self">Get the download count for releases: GitHub-get-download-count</a></li>
<li><a href="#h_a7fb6b16-7d09-419c-b043-65fc543efcc9" target="_self">Get inactive pull requests: GitHub-get-stale-prs</a></li>
<li><a href="#h_072342db-a9b6-4412-a82c-c4d623c89831" target="_self">Get a branch: GitHub-get-branch </a></li>
<li><a href="#h_a892d1ce-98d4-496c-b774-c294100ff6c5" target="_self">Create a new branch: GitHub-create-branch </a></li>
<li><a href="#h_67b96cf1-2679-41ba-8a62-ce5d5bdd1715" target="_self">Get details of a team membership: GitHub-get-team-membership</a></li>
<li><a href="#h_28d8b2e8-c6bd-4121-9bce-9dd4cff83688" target="_self">Request a review for a pull request: GitHub-request-review</a></li>
<li><a href="#h_9b201d60-49f3-49de-84d7-9b429c37fa69" target="_self">Create a comment: GitHub-create-comment</a></li>
<li><a href="#h_2d39779c-c70f-42bc-96ef-60a4643960dc" target="_self">List comments in an issue: GitHub-list-issue-comments </a></li>
<li><a href="#h_ebfd8f85-0967-4272-be2b-15a29e421ab8" target="_self">List pull request files: GitHub-list-pr-files</a></li>
<li><a href="#h_a1e18596-23a3-414a-8326-5cef5b6986c1" target="_self">List reviews on a pull request: GitHub-list-pr-reviews</a></li>
<li><a href="#h_299bf662-bcc0-4738-960e-a5208c0958bb" target="_self">Get the contents of a commit: GitHub-get-commit</a></li>
<li><a href="#h_20064505-4e55-4478-9e30-8a482fa3b26c" target="_self">Add a label to an issue: GitHub-add-label</a></li>
<li><a href="#h_2dff022b-e0a0-4142-8356-22e7c0edf943" target="_self">Get a pull request: GitHub-get-pull-request</a></li>
<li><a href="#h_55d1fc5c-e1c9-4293-9db2-3e6d1da440a0" target="_self">GitHub-list-teams: GitHub-list-teams</a></li>
<li><a href="#h_74b1f29f-07f7-4765-ab39-8222cc3413cb" target="_self">GitHub-delete-branch: GitHub-delete-branch</a></li>
</ol>
<h3 id="h_b3e20a76-c892-4f29-b887-0dbd313f0948">1. Create an issue</h3>
<hr>
<p>Creates an issue in GitHub.</p>
<h5>Base Command</h5>
<p><code>GitHub-create-issue</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 195px;"><strong>Argument Name</strong></th>
<th style="width: 433px;"><strong>Description</strong></th>
<th style="width: 112px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 195px;">title</td>
<td style="width: 433px;">The title of the issue.</td>
<td style="width: 112px;">Required</td>
</tr>
<tr>
<td style="width: 195px;">body</td>
<td style="width: 433px;">The contents of the issue.</td>
<td style="width: 112px;">Optional</td>
</tr>
<tr>
<td style="width: 195px;">labels</td>
<td style="width: 433px;">Labels to associate with this issue.</td>
<td style="width: 112px;">Optional</td>
</tr>
<tr>
<td style="width: 195px;">assignees</td>
<td style="width: 433px;">Logins for users to assign to this issue.</td>
<td style="width: 112px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 249px;"><strong>Path</strong></th>
<th style="width: 100px;"><strong>Type</strong></th>
<th style="width: 391px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 249px;">GitHub.Issue.ID</td>
<td style="width: 100px;">Number</td>
<td style="width: 391px;">The ID of the created issue.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Issue.Repository</td>
<td style="width: 100px;">String</td>
<td style="width: 391px;">The repository of the created issue.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Issue.Title</td>
<td style="width: 100px;">String</td>
<td style="width: 391px;">The title of the created issue.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Issue.Body</td>
<td style="width: 100px;">Unknown</td>
<td style="width: 391px;">The body of the created issue.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Issue.State</td>
<td style="width: 100px;">String</td>
<td style="width: 391px;">The state of the created issue.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Issue.Labels</td>
<td style="width: 100px;">String</td>
<td style="width: 391px;">Labels applied to the issue.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Issue.Assignees</td>
<td style="width: 100px;">String</td>
<td style="width: 391px;">Users assigned to this issue.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Issue.Created_at</td>
<td style="width: 100px;">Date</td>
<td style="width: 391px;">Date when the issue was created.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Issue.Updated_at</td>
<td style="width: 100px;">Date</td>
<td style="width: 391px;">Date when the issue was last updated.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Issue.Closed_at</td>
<td style="width: 100px;">Date</td>
<td style="width: 391px;">Date when the issue was closed.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Issue.Closed_by</td>
<td style="width: 100px;">String</td>
<td style="width: 391px;">User who closed the issue.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>GitHub-create-issue title=“newbug” body=“found a new bug” lable=bug,new</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.Issue": {
        "Body": "\u201cfound", 
        "Repository": "Git-Integration", 
        "Title": "\u201cnewbug\u201d", 
        "Created_at": "2019-06-17T15:14:10Z", 
        "Labels": [], 
        "Updated_at": "2019-06-17T15:14:10Z", 
        "ID": 138, 
        "Assignees": [], 
        "State": "open", 
        "Closed_at": null, 
        "Closed_by": null
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Issues:</h3>
<table style="width: 653px;" border="2">
<thead>
<tr>
<th style="width: 27px;">ID</th>
<th style="width: 105px;">Repository</th>
<th style="width: 68px;">Title</th>
<th style="width: 42px;">State</th>
<th style="width: 47px;">Body</th>
<th style="width: 169px;">Created_at</th>
<th style="width: 173px;">Updated_at</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 27px;">138</td>
<td style="width: 105px;">Git-Integration</td>
<td style="width: 68px;">“newbug”</td>
<td style="width: 42px;">open</td>
<td style="width: 47px;">“found</td>
<td style="width: 169px;">2019-06-17T15:14:10Z</td>
<td style="width: 173px;">2019-06-17T15:14:10Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3dae91c2-1d82-4b6b-95ef-f7fbdf4813fd">2. Close an issue</h3>
<hr>
<p>Closes an existing issue.</p>
<h5>Base Command</h5>
<p><code>GitHub-close-issue</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 224px;"><strong>Argument Name</strong></th>
<th style="width: 394px;"><strong>Description</strong></th>
<th style="width: 122px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 224px;">ID</td>
<td style="width: 394px;">The number of the issue to close.</td>
<td style="width: 122px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 265px;"><strong>Path</strong></th>
<th style="width: 88px;"><strong>Type</strong></th>
<th style="width: 387px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 265px;">GitHub.Issue.ID</td>
<td style="width: 88px;">Number</td>
<td style="width: 387px;">The ID of the closed issue.</td>
</tr>
<tr>
<td style="width: 265px;">GitHub.Issue.Repository</td>
<td style="width: 88px;">String</td>
<td style="width: 387px;">The repository of the closed issue.</td>
</tr>
<tr>
<td style="width: 265px;">GitHub.Issue.Title</td>
<td style="width: 88px;">String</td>
<td style="width: 387px;">The title of the closed issue</td>
</tr>
<tr>
<td style="width: 265px;">GitHub.Issue.Body</td>
<td style="width: 88px;">Unknown</td>
<td style="width: 387px;">The body of the closed issue.</td>
</tr>
<tr>
<td style="width: 265px;">GitHub.Issue.State</td>
<td style="width: 88px;">String</td>
<td style="width: 387px;">The state of the closed issue.</td>
</tr>
<tr>
<td style="width: 265px;">GitHub.Issue.Labels</td>
<td style="width: 88px;">String</td>
<td style="width: 387px;">Labels spplied to the issue.</td>
</tr>
<tr>
<td style="width: 265px;">GitHub.Issue.Assignees</td>
<td style="width: 88px;">String</td>
<td style="width: 387px;">Users assigned to the issue.</td>
</tr>
<tr>
<td style="width: 265px;">GitHub.Issue.Created_at</td>
<td style="width: 88px;">Date</td>
<td style="width: 387px;">Date when the issue was created.</td>
</tr>
<tr>
<td style="width: 265px;">GitHub.Issue.Updated_at</td>
<td style="width: 88px;">Date</td>
<td style="width: 387px;">Date when the issue was last updated</td>
</tr>
<tr>
<td style="width: 265px;">GitHub.Issue.Closed_at</td>
<td style="width: 88px;">Date</td>
<td style="width: 387px;">Date when the issue was closed.</td>
</tr>
<tr>
<td style="width: 265px;">GitHub.Issue.Closed_by</td>
<td style="width: 88px;">String</td>
<td style="width: 387px;">User who closed the issue.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>GitHub-close-issue ID=136</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.Issue": {
        "Body": null, 
        "Repository": "Git-Integration", 
        "Title": "new", 
        "Created_at": "2019-06-17T14:48:15Z", 
        "Labels": [
            "bug", 
            "else", 
            "new"
        ], 
        "Updated_at": "2019-06-17T15:14:12Z", 
        "ID": 136, 
        "Assignees": [], 
        "State": "closed", 
        "Closed_at": "2019-06-17T15:14:12Z", 
        "Closed_by": "roysagi"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Issues:</h3>
<table style="width: 708px;" border="2">
<thead>
<tr>
<th style="width: 27px;">ID</th>
<th style="width: 85px;">Repository</th>
<th style="width: 35px;">Title</th>
<th style="width: 44px;">State</th>
<th style="width: 115px;">Created_at</th>
<th style="width: 116px;">Updated_at</th>
<th style="width: 116px;">Closed_at</th>
<th style="width: 81px;">Closed_by</th>
<th style="width: 61px;">Labels</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 27px;">136</td>
<td style="width: 85px;">Git-Integration</td>
<td style="width: 35px;">new</td>
<td style="width: 44px;">closed</td>
<td style="width: 115px;">2019-06-17T14:48:15Z</td>
<td style="width: 116px;">2019-06-17T15:14:12Z</td>
<td style="width: 116px;">2019-06-17T15:14:12Z</td>
<td style="width: 81px;">roysagi</td>
<td style="width: 61px;">bug,<br> else,<br> new</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3d48d1bf-c274-405c-ad1d-e3f9c1440a3d">3. Update an issue</h3>
<hr>
<p>Updates the parameters of a specified issue.</p>
<h5>Base Command</h5>
<p><code>GitHub-update-issue</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 520px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">ID</td>
<td style="width: 520px;">The number of the issue to update.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 149px;">title</td>
<td style="width: 520px;">The title of the issue.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">body</td>
<td style="width: 520px;">The contents of the issue.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">state</td>
<td style="width: 520px;">State of the issue. Either open or closed.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">labels</td>
<td style="width: 520px;">Labels to apply to this issue. Pass one or more Labels to replace the set of Labels on this Issue. Send an empty array ([]) to clear all Labels from the Issue.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">assignees</td>
<td style="width: 520px;">Logins for Users to assign to this issue. Pass one or more user logins to replace the set of assignees on this Issue. Send an empty array ([]) to clear all assignees from the Issue.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 262px;"><strong>Path</strong></th>
<th style="width: 87px;"><strong>Type</strong></th>
<th style="width: 391px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 262px;">GitHub.Issue.ID</td>
<td style="width: 87px;">Number</td>
<td style="width: 391px;">The ID of the updated issue.</td>
</tr>
<tr>
<td style="width: 262px;">GitHub.Issue.Repository</td>
<td style="width: 87px;">String</td>
<td style="width: 391px;">The repository of the updated issue.</td>
</tr>
<tr>
<td style="width: 262px;">GitHub.Issue.Title</td>
<td style="width: 87px;">String</td>
<td style="width: 391px;">The title of the updated issue.</td>
</tr>
<tr>
<td style="width: 262px;">GitHub.Issue.Body</td>
<td style="width: 87px;">Unknown</td>
<td style="width: 391px;">The body of the updated issue.</td>
</tr>
<tr>
<td style="width: 262px;">GitHub.Issue.State</td>
<td style="width: 87px;">String</td>
<td style="width: 391px;">The state of the updated issue.</td>
</tr>
<tr>
<td style="width: 262px;">GitHub.Issue.Labels</td>
<td style="width: 87px;">String</td>
<td style="width: 391px;">Labels applied to the issue.</td>
</tr>
<tr>
<td style="width: 262px;">GitHub.Issue.Assignees</td>
<td style="width: 87px;">String</td>
<td style="width: 391px;">Users assigned to the issue.</td>
</tr>
<tr>
<td style="width: 262px;">GitHub.Issue.Created_at</td>
<td style="width: 87px;">Date</td>
<td style="width: 391px;">Date when the issue was created.</td>
</tr>
<tr>
<td style="width: 262px;">GitHub.Issue.Updated_at</td>
<td style="width: 87px;">Date</td>
<td style="width: 391px;">Date when the issue was last updated.</td>
</tr>
<tr>
<td style="width: 262px;">GitHub.Issue.Closed_at</td>
<td style="width: 87px;">Date</td>
<td style="width: 391px;">Date when the issue was closed.</td>
</tr>
<tr>
<td style="width: 262px;">GitHub.Issue.Closed_by</td>
<td style="width: 87px;">String</td>
<td style="width: 391px;">User who closed the issue.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>GitHub-update-issue ID=137 title=“new_title” body=“new info” state=open</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.Issue": {
        "Body": "\u201cnew", 
        "Repository": "Git-Integration", 
        "Title": "\u201cnew_title\u201d", 
        "Created_at": "2019-06-17T15:09:50Z", 
        "Labels": [], 
        "Updated_at": "2019-06-17T15:14:13Z", 
        "ID": 137, 
        "Assignees": [], 
        "State": "open", 
        "Closed_at": null, 
        "Closed_by": null
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Issues:</h3>
<table style="width: 652px;" border="2">
<thead>
<tr>
<th style="width: 27px;">ID</th>
<th style="width: 105px;">Repository</th>
<th style="width: 78px;">Title</th>
<th style="width: 42px;">State</th>
<th style="width: 40px;">Body</th>
<th style="width: 173px;">Created_at</th>
<th style="width: 165px;">Updated_at</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 27px;">137</td>
<td style="width: 105px;">Git-Integration</td>
<td style="width: 78px;">“new_title”</td>
<td style="width: 42px;">open</td>
<td style="width: 40px;">“new</td>
<td style="width: 173px;">2019-06-17T15:09:50Z</td>
<td style="width: 165px;">2019-06-17T15:14:13Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_71872e56-33da-4385-9d5f-89cfecaee19e">4. List all issues</h3>
<hr>
<p>Lists all issues that the user has access to view.</p>
<h5>Base Command</h5>
<p><code>GitHub-list-all-issues</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 158px;"><strong>Argument Name</strong></th>
<th style="width: 511px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 158px;">state</td>
<td style="width: 511px;">The state of the issues to return. Can be 'open', 'closed' or 'all'. Default is 'open'.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 158px;">limit</td>
<td style="width: 511px;">The number of issues to return. Default is 50. Maximum is 200.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 260px;"><strong>Path</strong></th>
<th style="width: 89px;"><strong>Type</strong></th>
<th style="width: 391px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 260px;">GitHub.Issue.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 391px;">The ID of the issue.</td>
</tr>
<tr>
<td style="width: 260px;">GitHub.Issue.Repository</td>
<td style="width: 89px;">String</td>
<td style="width: 391px;">The repository of the issue.</td>
</tr>
<tr>
<td style="width: 260px;">GitHub.Issue.Title</td>
<td style="width: 89px;">String</td>
<td style="width: 391px;">The title of the issue.</td>
</tr>
<tr>
<td style="width: 260px;">GitHub.Issue.Body</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 391px;">The body of the issue.</td>
</tr>
<tr>
<td style="width: 260px;">GitHub.Issue.State</td>
<td style="width: 89px;">String</td>
<td style="width: 391px;">The state of the issue.</td>
</tr>
<tr>
<td style="width: 260px;">GitHub.Issue.Labels</td>
<td style="width: 89px;">String</td>
<td style="width: 391px;">Labels applied to the issue.</td>
</tr>
<tr>
<td style="width: 260px;">GitHub.Issue.Assignees</td>
<td style="width: 89px;">String</td>
<td style="width: 391px;">Users assigned to the issue.</td>
</tr>
<tr>
<td style="width: 260px;">GitHub.Issue.Created_at</td>
<td style="width: 89px;">Date</td>
<td style="width: 391px;">Date when the issue was created.</td>
</tr>
<tr>
<td style="width: 260px;">GitHub.Issue.Updated_at</td>
<td style="width: 89px;">Date</td>
<td style="width: 391px;">Date when the issue was last updated.</td>
</tr>
<tr>
<td style="width: 260px;">GitHub.Issue.Closed_at</td>
<td style="width: 89px;">Date</td>
<td style="width: 391px;">Date when the issue was closed.</td>
</tr>
<tr>
<td style="width: 260px;">GitHub.Issue.Closed_by</td>
<td style="width: 89px;">String</td>
<td style="width: 391px;">User who closed the issue.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>GitHub-list-all-issues state=all limit=2</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.Issue": [
        {
            "Body": "\"new information\"", 
            "Repository": "Git-Integration", 
            "Title": "\"new issue\"", 
            "Created_at": "2019-06-04T11:52:11Z", 
            "Labels": [
                "newbug"
            ], 
            "Updated_at": "2019-06-04T11:52:13Z", 
            "ID": 109, 
            "Assignees": [], 
            "State": "closed", 
            "Closed_at": "2019-06-04T11:52:13Z", 
            "Closed_by": null
        }, 
        {
            "Body": "\"new information\"", 
            "Repository": "Git-Integration", 
            "Title": "\"new issue\"", 
            "Created_at": "2019-06-04T11:53:19Z", 
            "Labels": [
                "newbug"
            ], 
            "Updated_at": "2019-06-04T11:53:22Z", 
            "ID": 110, 
            "Assignees": [], 
            "State": "closed", 
            "Closed_at": "2019-06-04T11:53:22Z", 
            "Closed_by": null
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Issues:</h3>
<table style="width: 705px;" border="2">
<thead>
<tr>
<th style="width: 27px;">ID</th>
<th style="width: 85px;">Repository</th>
<th style="width: 49px;">Title</th>
<th style="width: 44px;">State</th>
<th style="width: 88px;">Body</th>
<th style="width: 107px;">Created_at</th>
<th style="width: 107px;">Updated_at</th>
<th style="width: 108px;">Closed_at</th>
<th style="width: 62px;">Labels</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 27px;">109</td>
<td style="width: 85px;">Git-Integration</td>
<td style="width: 49px;">"new issue"</td>
<td style="width: 44px;">closed</td>
<td style="width: 88px;">"new information"</td>
<td style="width: 107px;">2019-06-04T11:52:11Z</td>
<td style="width: 107px;">2019-06-04T11:52:13Z</td>
<td style="width: 108px;">2019-06-04T11:52:13Z</td>
<td style="width: 62px;">newbug</td>
</tr>
<tr>
<td style="width: 27px;">110</td>
<td style="width: 85px;">Git-Integration</td>
<td style="width: 49px;">"new issue"</td>
<td style="width: 44px;">closed</td>
<td style="width: 88px;">"new information"</td>
<td style="width: 107px;">2019-06-04T11:53:19Z</td>
<td style="width: 107px;">2019-06-04T11:53:22Z</td>
<td style="width: 108px;">2019-06-04T11:53:22Z</td>
<td style="width: 62px;">newbug</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_ea932aae-5ed3-4b5c-a972-be5526e4bddd">5. Search issues</h3>
<hr>
<p>Searches for and returns issues that match a given query.</p>
<h5>Base Command</h5>
<p><code>GitHub-search-issues</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 152px;"><strong>Argument Name</strong></th>
<th style="width: 517px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 152px;">query</td>
<td style="width: 517px;">The query line for the search. See the<span> </span><a href="https://help.github.com/en/articles/searching-issues-and-pull-requests">GitHub documentation</a><span> </span>for more information.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 152px;">limit</td>
<td style="width: 517px;">The number of issues to return. Default is 50. Maximum is 200.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 261px;"><strong>Path</strong></th>
<th style="width: 88px;"><strong>Type</strong></th>
<th style="width: 391px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 261px;">GitHub.Issue.ID</td>
<td style="width: 88px;">Number</td>
<td style="width: 391px;">The ID of the issue.</td>
</tr>
<tr>
<td style="width: 261px;">GitHub.Issue.Repository</td>
<td style="width: 88px;">String</td>
<td style="width: 391px;">The repository of the issue.</td>
</tr>
<tr>
<td style="width: 261px;">GitHub.Issue.Title</td>
<td style="width: 88px;">String</td>
<td style="width: 391px;">The title of the issue.</td>
</tr>
<tr>
<td style="width: 261px;">GitHub.Issue.Body</td>
<td style="width: 88px;">Unknown</td>
<td style="width: 391px;">The body of the issue.</td>
</tr>
<tr>
<td style="width: 261px;">GitHub.Issue.State</td>
<td style="width: 88px;">String</td>
<td style="width: 391px;">The state of the issue.</td>
</tr>
<tr>
<td style="width: 261px;">GitHub.Issue.Labels</td>
<td style="width: 88px;">String</td>
<td style="width: 391px;">Labels applied to the issue.</td>
</tr>
<tr>
<td style="width: 261px;">GitHub.Issue.Assignees</td>
<td style="width: 88px;">String</td>
<td style="width: 391px;">Users assigned to the issue.</td>
</tr>
<tr>
<td style="width: 261px;">GitHub.Issue.Created_at</td>
<td style="width: 88px;">Date</td>
<td style="width: 391px;">Date when the issue was created.</td>
</tr>
<tr>
<td style="width: 261px;">GitHub.Issue.Updated_at</td>
<td style="width: 88px;">Date</td>
<td style="width: 391px;">Date when the issue was last updated.</td>
</tr>
<tr>
<td style="width: 261px;">GitHub.Issue.Closed_at</td>
<td style="width: 88px;">Date</td>
<td style="width: 391px;">Date when the issue was closed.</td>
</tr>
<tr>
<td style="width: 261px;">GitHub.Issue.Closed_by</td>
<td style="width: 88px;">String</td>
<td style="width: 391px;">User who closed the issue.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>GitHub-search-issues query=“label:bug state:open” limit=2</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.Issue": []
}
</pre>
<h5>Human Readable Output</h5>
<h3>Issues:</h3>
<p><strong>No entries.</strong></p>
<h3 id="h_5dfb412d-e0e1-4344-8216-8fc769620534">6. Get the download count for releases</h3>
<hr>
<p>Returns the total number of downloads for all releases for the specified repository.</p>
<h5>Base Command</h5>
<p><code>GitHub-get-download-count</code></p>
<h5>Input</h5>
<p>There are no input arguments for this command.</p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 319px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 359px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 319px;">GitHub.Release.ID</td>
<td style="width: 62px;">Number</td>
<td style="width: 359px;">ID of the release.</td>
</tr>
<tr>
<td style="width: 319px;">GitHub.Release.Download_count</td>
<td style="width: 62px;">Number</td>
<td style="width: 359px;">Download count for the release.</td>
</tr>
<tr>
<td style="width: 319px;">GitHub.Release.Name</td>
<td style="width: 62px;">String</td>
<td style="width: 359px;">Name of the release.</td>
</tr>
<tr>
<td style="width: 319px;">GitHub.Release.Body</td>
<td style="width: 62px;">String</td>
<td style="width: 359px;">Body of the release.</td>
</tr>
<tr>
<td style="width: 319px;">GitHub.Release.Created_at</td>
<td style="width: 62px;">Date</td>
<td style="width: 359px;">Date when the release was created.</td>
</tr>
<tr>
<td style="width: 319px;">GitHub.Release.Published_at</td>
<td style="width: 62px;">Date</td>
<td style="width: 359px;">Date when the release was published.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>GitHub-get-download-count</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.Release": [
        {
            "Body": "this is another release", 
            "Name": "anotherone", 
            "Created_at": "2019-05-22T15:00:51Z", 
            "Published_at": "2019-05-22T15:06:48Z", 
            "Download_count": 5, 
            "ID": 17519182
        }, 
        {
            "Body": "this is a test", 
            "Name": "test", 
            "Created_at": "2019-05-22T15:00:51Z", 
            "Published_at": "2019-05-22T15:02:16Z", 
            "Download_count": 1, 
            "ID": 17519007
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Releases:</h3>
<table style="width: 709px;" border="2">
<thead>
<tr>
<th style="width: 72px;">ID</th>
<th style="width: 81px;">Name</th>
<th style="width: 133px;">Download_count</th>
<th style="width: 124px;">Body</th>
<th style="width: 134px;">Created_at</th>
<th style="width: 146px;">Published_at</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 72px;">17519182</td>
<td style="width: 81px;">anotherone</td>
<td style="width: 133px;">5</td>
<td style="width: 124px;">this is another release</td>
<td style="width: 134px;">2019-05-22T15:00:51Z</td>
<td style="width: 146px;">2019-05-22T15:06:48Z</td>
</tr>
<tr>
<td style="width: 72px;">17519007</td>
<td style="width: 81px;">test</td>
<td style="width: 133px;">1</td>
<td style="width: 124px;">this is a test</td>
<td style="width: 134px;">2019-05-22T15:00:51Z</td>
<td style="width: 146px;">2019-05-22T15:02:16Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_a7fb6b16-7d09-419c-b043-65fc543efcc9">7. Get inactive pull requests</h3>
<hr>
<p>Returns inactive pull requests from GitHub.</p>
<h5>Base Command</h5>
<p><code>GitHub-get-stale-prs</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 133px;"><strong>Argument Name</strong></th>
<th style="width: 496px;"><strong>Description</strong></th>
<th style="width: 79px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133px;">stale_time</td>
<td style="width: 496px;">The time of inactivity after which a pull request becomes stale.</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 133px;">label</td>
<td style="width: 496px;">The label used to identify relevant pull requests.</td>
<td style="width: 79px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 241px;"><strong>Path</strong></th>
<th style="width: 89px;"><strong>Type</strong></th>
<th style="width: 378px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 241px;">GitHub.PR.URL</td>
<td style="width: 89px;">String</td>
<td style="width: 378px;">The URL of the pull request.</td>
</tr>
<tr>
<td style="width: 241px;">GitHub.PR.Number</td>
<td style="width: 89px;">Number</td>
<td style="width: 378px;">The number of the pull request.</td>
</tr>
<tr>
<td style="width: 241px;">GitHub.PR.RequestedReviewer</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 378px;">The requested reviewer's list of pull requests.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !GitHub-get-stale-prs stale_time="2 days"</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.PR": [
        {
            "Number": 18,
            "RequestedReviewer": [],
            "URL": "https://github.com/example-user1/content/pull/18"
        },
        {
            "Number": 16,
            "RequestedReviewer": [],
            "URL": "https://github.com/example-user1/content/pull/16"
        },
        {
            "Number": 15,
            "RequestedReviewer": [],
            "URL": "https://github.com/example-user1/content/pull/15"
        },
        {
            "Number": 14,
            "RequestedReviewer": [],
            "URL": "https://github.com/example-user1/content/pull/14"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Stale PRs</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Number</strong></th>
<th><strong>URL</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>18</td>
<td>https://github.com/example-user1/content/pull/18</td>
</tr>
<tr>
<td>16</td>
<td>https://github.com/example-user1/content/pull/16</td>
</tr>
<tr>
<td>15</td>
<td>https://github.com/example-user1/content/pull/15</td>
</tr>
<tr>
<td>14</td>
<td>https://github.com/example-user1/content/pull/14</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_072342db-a9b6-4412-a82c-c4d623c89831">8.  Get a branch</h3>
<hr>
<p>Retrieves a branch from the repository.</p>
<h5>Base Command</h5>
<p><code>GitHub-get-branch</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 196px;"><strong>Argument Name</strong></th>
<th style="width: 396px;"><strong>Description</strong></th>
<th style="width: 116px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 196px;">branch_name</td>
<td style="width: 396px;">The name of the branch to retrieve.</td>
<td style="width: 116px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 237px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 404px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 237px;">GitHub.Branch.Name</td>
<td style="width: 67px;">String</td>
<td style="width: 404px;">The name of the branch.</td>
</tr>
<tr>
<td style="width: 237px;">GitHub.Branch.CommitSHA</td>
<td style="width: 67px;">String</td>
<td style="width: 404px;">The SHA of the commit for which the branch references.</td>
</tr>
<tr>
<td style="width: 237px;">GitHub.Branch.CommitNodeID</td>
<td style="width: 67px;">String</td>
<td style="width: 404px;">The Node ID of the commit for which the branch references.</td>
</tr>
<tr>
<td style="width: 237px;">GitHub.Branch.CommitAuthorID</td>
<td style="width: 67px;">Number</td>
<td style="width: 404px;">The GitHub Commit Author ID for which the branch references.</td>
</tr>
<tr>
<td style="width: 237px;">GitHub.Branch.CommitAuthorLogin</td>
<td style="width: 67px;">String</td>
<td style="width: 404px;">The GitHub Commit Author login for which the branch references.</td>
</tr>
<tr>
<td style="width: 237px;">GitHub.Branch.CommitParentSHA</td>
<td style="width: 67px;">String</td>
<td style="width: 404px;">The SHAs of the commit parent.</td>
</tr>
<tr>
<td style="width: 237px;">GitHub.Branch.Protected</td>
<td style="width: 67px;">Boolean</td>
<td style="width: 404px;">Whether the branch is protected.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !GitHub-get-pull-request pull_number=1
</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.PR": {
        "ActiveLockReason": null,
        "Additions": 4,
        "AuthorAssociation": "FIRST_TIME_CONTRIBUTOR",
        "Base": {
            "Label": "example-user1:master",
            "Ref": "master",
            "Repo": {
                "AllowMergeCommit": null,
                "AllowRebaseMerge": null,
                "AllowSquashMerge": null,
                "Archived": false,
                "CreatedAt": "2019-09-11T06:59:20Z",
                "DefaultBranch": "master",
                "Description": "This repository contains all Demisto content and from here we share content updates",
                "Disabled": false,
                "Fork": true,
                "ForksCount": 0,
                "FullName": "example-user1/content",
                "HasDownloads": true,
                "HasIssues": false,
                "HasPages": false,
                "HasProjects": true,
                "HasWiki": false,
                "ID": 207744685,
                "Language": "Python",
                "Name": "content",
                "NodeID": "MDEwOlJlcG9zaXRvcnkyMDc3NDQ2ODU=",
                "OpenIssuesCount": 10,
                "Owner": {
                    "ID": 55035720,
                    "Login": "example-user1",
                    "NodeID": "MDQ6VXNlcjU1MDM1NzIw",
                    "SiteAdmin": false,
                    "Type": "User"
                },
                "Private": false,
                "PushedAt": "2019-09-18T14:05:43Z",
                "Size": 96530,
                "StargazersCount": 0,
                "SucscribersCount": null,
                "Topics": null,
                "UpdatedAt": "2019-09-16T15:42:46Z",
                "WatchersCount": 0
            },
            "SHA": "b27ea6ac9836d2e756b44eb1d66f02d3d4299362",
            "User": {
                "ID": 55035720,
                "Login": "example-user1",
                "NodeID": "MDQ6VXNlcjU1MDM1NzIw",
                "SiteAdmin": false,
                "Type": "User"
            }
        },
        "Body": "<!-- REMINDER: THIS IS A PUBLIC REPO DO NOT POST HERE SECRETS/SENSITIVE DATA -->\r\n\r\n## Status\r\nReady/In Progress/In Hold(Reason for hold)\r\n\r\n## Related Issues\r\nfixes: link to the issue\r\n\r\n## Description\r\nA few sentences describing the overall goals of the pull request's commits.\r\n\r\n## Screenshots\r\nPaste here any images that will help the reviewer\r\n\r\n## Related PRs\r\nList related PRs against other branches:\r\n\r\nbranch | PR\r\n------ | ------\r\n\r\n\r\n## Required version of Demisto\r\nx.x.x\r\n\r\n## Does it break backward compatibility?\r\n   - Yes\r\n       - Further details:\r\n   - No\r\n\r\n## Must have\r\n- [ ] Tests\r\n- [ ] Documentation (with link to it)\r\n- [ ] Code Review\r\n\r\n## Dependencies\r\nMention the dependencies of the entity you changed as given from the precommit hooks in checkboxes, and tick after tested them.\r\n- [ ] Dependency 1\r\n- [ ] Dependency 2\r\n- [ ] Dependency 3\r\n\r\n## Additional changes\r\nDescribe additional changes done, for example adding a function to common server.\r\n",
        "ChangedFiles": 1,
        "ClosedAt": null,
        "Comments": 5,
        "Commits": 4,
        "CreatedAt": "2019-09-11T07:06:26Z",
        "Deletions": 0,
        "Draft": null,
        "Head": {
            "Label": "example-user4:patch-1",
            "Ref": "patch-1",
            "Repo": {
                "AllowMergeCommit": null,
                "AllowRebaseMerge": null,
                "AllowSquashMerge": null,
                "Archived": false,
                "CreatedAt": "2019-08-29T10:18:15Z",
                "DefaultBranch": "master",
                "Description": "This repository contains all Demisto content and from here we share content updates",
                "Disabled": false,
                "Fork": true,
                "ForksCount": 2,
                "FullName": "example-user4/content",
                "HasDownloads": true,
                "HasIssues": false,
                "HasPages": false,
                "HasProjects": true,
                "HasWiki": false,
                "ID": 205137013,
                "Language": "Python",
                "Name": "content",
                "NodeID": "MDEwOlJlcG9zaXRvcnkyMDUxMzcwMTM=",
                "OpenIssuesCount": 2,
                "Owner": {
                    "ID": 46294017,
                    "Login": "example-user4",
                    "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3",
                    "SiteAdmin": false,
                    "Type": "User"
                },
                "Private": false,
                "PushedAt": "2019-09-16T15:43:54Z",
                "Size": 95883,
                "StargazersCount": 0,
                "SucscribersCount": null,
                "Topics": null,
                "UpdatedAt": "2019-08-29T10:18:18Z",
                "WatchersCount": 0
            },
            "SHA": "c01238eea80e35bb76a5c51ac0c95eba4010d8e5",
            "User": {
                "ID": 46294017,
                "Login": "example-user4",
                "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3",
                "SiteAdmin": false,
                "Type": "User"
            }
        },
        "ID": 316303415,
        "Label": [
            {
                "Color": null,
                "Default": false,
                "Description": null,
                "ID": 1563600288,
                "Name": "Content",
                "NodeID": "MDU6TGFiZWwxNTYzNjAwMjg4"
            },
            {
                "Color": null,
                "Default": false,
                "Description": null,
                "ID": 1549466359,
                "Name": "Contribution",
                "NodeID": "MDU6TGFiZWwxNTQ5NDY2MzU5"
            },
            {
                "Color": null,
                "Default": true,
                "Description": null,
                "ID": 1549411616,
                "Name": "bug",
                "NodeID": "MDU6TGFiZWwxNTQ5NDExNjE2"
            }
        ],
        "Locked": false,
        "MaintainerCanModify": true,
        "MergeCommitSHA": "5714b1359b9d7549c89c35fe9fdc266a3db3b766",
        "Mergeable": true,
        "MergeableState": "unstable",
        "Merged": false,
        "MergedAt": null,
        "NodeID": "MDExOlB1bGxSZXF1ZXN0MzE2MzAzNDE1",
        "Number": 1,
        "Rebaseable": true,
        "RequestedReviewer": [
            {
                "ID": 30797606,
                "Login": "example-user3",
                "NodeID": "MDQ6VXNlcjMwNzk3NjA2",
                "SiteAdmin": false,
                "Type": "User"
            },
            {
                "ID": 55035720,
                "Login": "example-user1",
                "NodeID": "MDQ6VXNlcjU1MDM1NzIw",
                "SiteAdmin": false,
                "Type": "User"
            }
        ],
        "ReviewComments": 0,
        "State": "open",
        "UpdatedAt": "2019-09-18T14:05:51Z",
        "User": {
            "ID": 46294017,
            "Login": "example-user4",
            "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3",
            "SiteAdmin": false,
            "Type": "User"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Branch "master"</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>CommitAuthorID</strong></th>
<th><strong>CommitAuthorLogin</strong></th>
<th><strong>CommitNodeID</strong></th>
<th><strong>CommitParentSHA</strong></th>
<th><strong>CommitSHA</strong></th>
<th><strong>Name</strong></th>
<th><strong>Protected</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>55035720</td>
<td>example-user1</td>
<td>MDY6Q29tbWl0MjA3NzQ0Njg1OjhhNjdhMDc4MTM5NDk4ZjNlOGUxYmQyZTI2ZmZjNWEyZmVhMWI5MTg=</td>
<td>d6bafef5a0021a6d9ab0a22e11bd0afd5801d936</td>
<td>8a67a078139498f3e8e1bd2e26ffc5a2fea1b918</td>
<td>master</td>
<td>false</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_a892d1ce-98d4-496c-b774-c294100ff6c5">9. Create a new branch</h3>
<hr>
<p>Creates a new branch of the repository.</p>
<h5>Base Command</h5>
<p><code>GitHub-create-branch</code></p>
<h5>Input</h5>
<table style="width: 738px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 502px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">branch_name</td>
<td style="width: 502px;">The name for the new branch.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 135px;">commit_sha</td>
<td style="width: 502px;">The SHA hash of the commit to reference. Execute the <strong>GitHub-get-branch</strong> command to find a commit SHA hash to reference.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  GitHub-create-branch branch_name=new-branch-example commit_sha=8a67a078139498f3e8e1bd2e26ffc5a2fea1b918</pre>
<h5>Human Readable Output</h5>
<p>Branch "new-branch-example" Created Successfully</p>
<h3 id="h_67b96cf1-2679-41ba-8a62-ce5d5bdd1715">10. Get details of a team membership</h3>
<hr>
<p>Retrieves details of a user's team membership.</p>
<h5>Base Command</h5>
<p><code>GitHub-get-team-membership</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 78px;"><strong>Argument Name</strong></th>
<th style="width: 559px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 78px;">team-id</td>
<td style="width: 559px;"><span>The ID number by which the team is identified. Execute the GitHub-list-teams command to find team IDs to reference.</span></td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 78px;">user_name</td>
<td style="width: 559px;">The name of the user whose membership you want to check.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 283px;"><strong>Path</strong></th>
<th style="width: 96px;"><strong>Type</strong></th>
<th style="width: 329px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 283px;">GitHub.Team.Member.Role</td>
<td style="width: 96px;">String</td>
<td style="width: 329px;">The user's role in the team.</td>
</tr>
<tr>
<td style="width: 283px;">GitHub.Team.Member.State</td>
<td style="width: 96px;">String</td>
<td style="width: 329px;">The user's state in the team.</td>
</tr>
<tr>
<td style="width: 283px;">GitHub.Team.ID</td>
<td style="width: 96px;">Number</td>
<td style="width: 329px;">The ID number of the team.</td>
</tr>
<tr>
<td style="width: 283px;">GitHub.Team.Member.Login</td>
<td style="width: 96px;">String</td>
<td style="width: 329px;">The login of the team member.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!GitHub-get-team-membership team_id=3043448 user_name=example-user2
</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.Team": {
        "ID": 3043448,
        "Role": "member",
        "State": "active",
        "Login": "example-user2"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Team Membership of example-user2</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>ID</strong></th>
<th><strong>Role</strong></th>
<th><strong>State</strong></th>
<th><strong>Login</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>3043448</td>
<td>member</td>
<td>active</td>
<td>example-user2</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_28d8b2e8-c6bd-4121-9bce-9dd4cff83688">11. Request a review for a pull request</h3>
<hr>
<p>Requests reviews from GitHub users for a pull request.</p>
<h5>Base Command</h5>
<p><code>GitHub-request-review</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 129px;"><strong>Argument Name</strong></th>
<th style="width: 502px;"><strong>Description</strong></th>
<th style="width: 77px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 129px;">pull_number</td>
<td style="width: 502px;">The number of the pull request that you wish to request a review.</td>
<td style="width: 77px;">Required</td>
</tr>
<tr>
<td style="width: 129px;">reviewers</td>
<td style="width: 502px;">A CSV list of GitHub users to request a review for a pull request.</td>
<td style="width: 77px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 276px;"><strong>Path</strong></th>
<th style="width: 71px;"><strong>Type</strong></th>
<th style="width: 361px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 276px;">GitHub.PR.Number</td>
<td style="width: 71px;">Number</td>
<td style="width: 361px;">The number of the Pull Request.</td>
</tr>
<tr>
<td style="width: 276px;">GitHub.PR.RequestedReviewer.Login</td>
<td style="width: 71px;">String</td>
<td style="width: 361px;">The login of the user requested for a review.</td>
</tr>
<tr>
<td style="width: 276px;">GitHub.PR.RequestedReviewer.ID</td>
<td style="width: 71px;">Number</td>
<td style="width: 361px;">The ID of the user requested for a review.</td>
</tr>
<tr>
<td style="width: 276px;">GitHub.PR.RequestedReviewer.NodeID</td>
<td style="width: 71px;">String</td>
<td style="width: 361px;">The node ID of the user requested for a review.</td>
</tr>
<tr>
<td style="width: 276px;">GitHub.PR.RequestedReviewer.Type</td>
<td style="width: 71px;">String</td>
<td style="width: 361px;">The type of the user requested for a review.</td>
</tr>
<tr>
<td style="width: 276px;">GitHub.PR.RequestedReviewer.SiteAdmin</td>
<td style="width: 71px;">Boolean</td>
<td style="width: 361px;">Whether the user who is requested for review is a site administrator.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !GitHub-request-review pull_number=1 reviewers=example-user1
</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.PR": {
        "Number": 1,
        "RequestedReviewer": [
            {
                "ID": 30797606,
                "Login": "example-user3",
                "NodeID": "MDQ6VXNlcjMwNzk3NjA2",
                "SiteAdmin": false,
                "Type": "User"
            },
            {
                "ID": 55035720,
                "Login": "example-user1",
                "NodeID": "MDQ6VXNlcjU1MDM1NzIw",
                "SiteAdmin": false,
                "Type": "User"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Requested Reviewers for #1</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>ID</strong></th>
<th><strong>Login</strong></th>
<th><strong>NodeID</strong></th>
<th><strong>SiteAdmin</strong></th>
<th><strong>Type</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>30797606</td>
<td>example-user3</td>
<td>MDQ6VXNlcjMwNzk3NjA2</td>
<td>false</td>
<td>User</td>
</tr>
<tr>
<td>55035720</td>
<td>example-user1</td>
<td>MDQ6VXNlcjU1MDM1NzIw</td>
<td>false</td>
<td>User</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_9b201d60-49f3-49de-84d7-9b429c37fa69">12. Create a comment</h3>
<p>Creates a comment in the Github issue.</p>
<h5>Base Command</h5>
<p><code>GitHub-create-comment</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 80px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">issue_number</td>
<td style="width: 497px;">The number of the Pull Request for which to request a review.</td>
<td style="width: 80px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">body</td>
<td style="width: 497px;">The contents of the message.</td>
<td style="width: 80px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 222px;"><strong>Path</strong></th>
<th style="width: 73px;"><strong>Type</strong></th>
<th style="width: 413px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 222px;">GitHub.Comment.IssueNumber</td>
<td style="width: 73px;">Number</td>
<td style="width: 413px;">The number of the issue in which the comment belongs.</td>
</tr>
<tr>
<td style="width: 222px;">GitHub.Comment.ID</td>
<td style="width: 73px;">Number</td>
<td style="width: 413px;">The ID of the comment.</td>
</tr>
<tr>
<td style="width: 222px;">GitHub.Comment.NodeID</td>
<td style="width: 73px;">String</td>
<td style="width: 413px;">The Node ID of the comment.</td>
</tr>
<tr>
<td style="width: 222px;">GitHub.Comment.Body</td>
<td style="width: 73px;">String</td>
<td style="width: 413px;">The body content of the comment.</td>
</tr>
<tr>
<td style="width: 222px;">GitHub.Comment.User.Login</td>
<td style="width: 73px;">String</td>
<td style="width: 413px;">The login of the user who commented.</td>
</tr>
<tr>
<td style="width: 222px;">GitHub.Comment.User.ID</td>
<td style="width: 73px;">Number</td>
<td style="width: 413px;">The ID of the user who commented.</td>
</tr>
<tr>
<td style="width: 222px;">GitHub.Comment.User.NodeID</td>
<td style="width: 73px;">String</td>
<td style="width: 413px;">The Node ID of the user who commented.</td>
</tr>
<tr>
<td style="width: 222px;">GitHub.Comment.User.Type</td>
<td style="width: 73px;">String</td>
<td style="width: 413px;">The type of the user who commented.</td>
</tr>
<tr>
<td style="width: 222px;">GitHub.Comment.User.SiteAdmin</td>
<td style="width: 73px;">Boolean</td>
<td style="width: 413px;">Whether the user who commented is a site administrator.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !GitHub-create-comment issue_number=1 body="Look this comment was made using the GitHub integration"
</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.Comment": {
        "Body": "Look this comment was made using the GitHub integration",
        "ID": 532700206,
        "IssueNumber": 1,
        "NodeID": "MDEyOklzc3VlQ29tbWVudDUzMjcwMDIwNg==",
        "User": {
            "ID": 55035720,
            "Login": "example-user1",
            "NodeID": "MDQ6VXNlcjU1MDM1NzIw",
            "SiteAdmin": false,
            "Type": "User"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Created Comment</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Body</strong></th>
<th><strong>ID</strong></th>
<th><strong>IssueNumber</strong></th>
<th><strong>NodeID</strong></th>
<th><strong>User</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Look this comment was made using the GitHub integration</td>
<td>532700206</td>
<td>1</td>
<td>MDEyOklzc3VlQ29tbWVudDUzMjcwMDIwNg==</td>
<td>Login: example-user1<br> ID: 55035720<br> NodeID: MDQ6VXNlcjU1MDM1NzIw<br> Type: User<br> SiteAdmin: false</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_2d39779c-c70f-42bc-96ef-60a4643960dc">13. List comments in an issue</h3>
<hr>
<p>Lists all comments in a Github Issue.</p>
<h5>Base Command</h5>
<p><code>GitHub-list-issue-comments</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 158px;"><strong>Argument Name</strong></th>
<th style="width: 458px;"><strong>Description</strong></th>
<th style="width: 92px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 158px;">issue_number</td>
<td style="width: 458px;">The number of the issue in which to list comments.</td>
<td style="width: 92px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 229px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 413px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 229px;">GitHub.Comment.IssueNumber</td>
<td style="width: 66px;">Number</td>
<td style="width: 413px;">The number of the issue in which the comment belongs.</td>
</tr>
<tr>
<td style="width: 229px;">GitHub.Comment.ID</td>
<td style="width: 66px;">Number</td>
<td style="width: 413px;">The ID of the comment.</td>
</tr>
<tr>
<td style="width: 229px;">GitHub.Comment.NodeID</td>
<td style="width: 66px;">String</td>
<td style="width: 413px;">The Node ID of the comment.</td>
</tr>
<tr>
<td style="width: 229px;">GitHub.Comment.Body</td>
<td style="width: 66px;">String</td>
<td style="width: 413px;">The body content of the comment.</td>
</tr>
<tr>
<td style="width: 229px;">GitHub.Comment.User.Login</td>
<td style="width: 66px;">String</td>
<td style="width: 413px;">The login of the user who commented.</td>
</tr>
<tr>
<td style="width: 229px;">GitHub.Comment.User.ID</td>
<td style="width: 66px;">Number</td>
<td style="width: 413px;">The ID of the user who commented.</td>
</tr>
<tr>
<td style="width: 229px;">GitHub.Comment.User.NodeID</td>
<td style="width: 66px;">String</td>
<td style="width: 413px;">The Node ID of the user who commented.</td>
</tr>
<tr>
<td style="width: 229px;">GitHub.Comment.User.Type</td>
<td style="width: 66px;">String</td>
<td style="width: 413px;">The type of the user who commented.</td>
</tr>
<tr>
<td style="width: 229px;">GitHub.Comment.User.SiteAdmin</td>
<td style="width: 66px;">Boolean</td>
<td style="width: 413px;">Whether the user who commented is a site administrator.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!GitHub-list-issue-comments issue_number=1</code></p>
<h5>Context Example</h5>
<pre>{
    "GitHub.Comment": [
        {
            "Body": "Thank you for your contribution. Your generosity and caring are unrivaled! Rest assured - our content wizard @example-user3 will very shortly look over your proposed changes. ",
            "ID": 530276333,
            "IssueNumber": 1,
            "NodeID": "MDEyOklzc3VlQ29tbWVudDUzMDI3NjMzMw==",
            "User": {
                "ID": 55035720,
                "Login": "example-user1",
                "NodeID": "MDQ6VXNlcjU1MDM1NzIw",
                "SiteAdmin": false,
                "Type": "User"
            }
        },
        {
            "Body": "what about my pr eh",
            "ID": 530313678,
            "IssueNumber": 1,
            "NodeID": "MDEyOklzc3VlQ29tbWVudDUzMDMxMzY3OA==",
            "User": {
                "ID": 46294017,
                "Login": "example-user4",
                "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3",
                "SiteAdmin": false,
                "Type": "User"
            }
        },
        {
            "Body": "@example-user4 can we close?",
            "ID": 530774162,
            "IssueNumber": 1,
            "NodeID": "MDEyOklzc3VlQ29tbWVudDUzMDc3NDE2Mg==",
            "User": {
                "ID": 30797606,
                "Login": "example-user3",
                "NodeID": "MDQ6VXNlcjMwNzk3NjA2",
                "SiteAdmin": false,
                "Type": "User"
            }
        },
        {
            "Body": "Look this comment was made using the GitHub integration",
            "ID": 532700206,
            "IssueNumber": 1,
            "NodeID": "MDEyOklzc3VlQ29tbWVudDUzMjcwMDIwNg==",
            "User": {
                "ID": 55035720,
                "Login": "example-user1",
                "NodeID": "MDQ6VXNlcjU1MDM1NzIw",
                "SiteAdmin": false,
                "Type": "User"
            }
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Comments for Issue #1</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Body</strong></th>
<th><strong>ID</strong></th>
<th><strong>IssueNumber</strong></th>
<th><strong>NodeID</strong></th>
<th><strong>User</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Thank you for your contribution. Your generosity and caring are unrivaled! Rest assured - our content wizard @example-user3 will very shortly look over your proposed changes.</td>
<td>530276333</td>
<td>1</td>
<td>MDEyOklzc3VlQ29tbWVudDUzMDI3NjMzMw==</td>
<td>Login: example-user1<br> ID: 55035720<br> NodeID: MDQ6VXNlcjU1MDM1NzIw<br> Type: User<br> SiteAdmin: false</td>
</tr>
<tr>
<td>what about my pr eh</td>
<td>530313678</td>
<td>1</td>
<td>MDEyOklzc3VlQ29tbWVudDUzMDMxMzY3OA==</td>
<td>Login: example-user4<br> ID: 46294017<br> NodeID: MDQ6VXNlcjQ2Mjk0MDE3<br> Type: User<br> SiteAdmin: false</td>
</tr>
<tr>
<td>@example-user4 can we close?</td>
<td>530774162</td>
<td>1</td>
<td>MDEyOklzc3VlQ29tbWVudDUzMDc3NDE2Mg==</td>
<td>Login: example-user3<br> ID: 30797606<br> NodeID: MDQ6VXNlcjMwNzk3NjA2<br> Type: User<br> SiteAdmin: false</td>
</tr>
<tr>
<td>Look this comment was made using the GitHub integration</td>
<td>532700206</td>
<td>1</td>
<td>MDEyOklzc3VlQ29tbWVudDUzMjcwMDIwNg==</td>
<td>Login: example-user1<br> ID: 55035720<br> NodeID: MDQ6VXNlcjU1MDM1NzIw<br> Type: User<br> SiteAdmin: false</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_ebfd8f85-0967-4272-be2b-15a29e421ab8">14. List pull request files</h3>
<hr>
<p>List all pull request files in Github.</p>
<h5>Base Command</h5>
<p><code>GitHub-list-pr-files</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 207px;"><strong>Argument Name</strong></th>
<th style="width: 378px;"><strong>Description</strong></th>
<th style="width: 123px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 207px;">pull_number</td>
<td style="width: 378px;">The number of the pull request.</td>
<td style="width: 123px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 164px;"><strong>Path</strong></th>
<th style="width: 71px;"><strong>Type</strong></th>
<th style="width: 473px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 164px;">GitHub.PR.Number</td>
<td style="width: 71px;">Number</td>
<td style="width: 473px;">The number of the pull request.</td>
</tr>
<tr>
<td style="width: 164px;">GitHub.PR.File.SHA</td>
<td style="width: 71px;">String</td>
<td style="width: 473px;">The SHA hash for the last commit included in the associated file.</td>
</tr>
<tr>
<td style="width: 164px;">GitHub.PR.File.Name</td>
<td style="width: 71px;">String</td>
<td style="width: 473px;">The name of the file.</td>
</tr>
<tr>
<td style="width: 164px;">GitHub.PR.File.Status</td>
<td style="width: 71px;">String</td>
<td style="width: 473px;">The status of the file.</td>
</tr>
<tr>
<td style="width: 164px;">GitHub.PR.File.Additions</td>
<td style="width: 71px;">Number</td>
<td style="width: 473px;">The number of additions to the file.</td>
</tr>
<tr>
<td style="width: 164px;">GitHub.PR.File.Deletions</td>
<td style="width: 71px;">Number</td>
<td style="width: 473px;">The number of deletions in the file.</td>
</tr>
<tr>
<td style="width: 164px;">GitHub.PR.File.Changes</td>
<td style="width: 71px;">Number</td>
<td style="width: 473px;">The number of changes in the file.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5> </h5>
<h5>Command Example</h5>
<pre>  !GitHub-list-pr-files pull_number=1
</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.PR": {
        "File": [
            {
                "Additions": 4,
                "Changes": 4,
                "Deletions": 0,
                "Name": "TEST.md",
                "SHA": "4e7fd23b44ef46ebd04a9812dda55cecb487fcbe",
                "Status": "added"
            }
        ],
        "Number": "1"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Pull Request Files for #1</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Additions</strong></th>
<th><strong>Changes</strong></th>
<th><strong>Deletions</strong></th>
<th><strong>Name</strong></th>
<th><strong>SHA</strong></th>
<th><strong>Status</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>4</td>
<td>4</td>
<td>0</td>
<td>TEST.md</td>
<td>4e7fd23b44ef46ebd04a9812dda55cecb487fcbe</td>
<td>added</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_a1e18596-23a3-414a-8326-5cef5b6986c1">15. List reviews on a pull request</h3>
<hr>
<p>List review comments on a pull request.</p>
<h5>Base Command</h5>
<p><code>GitHub-list-pr-reviews</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 207px;"><strong>Argument Name</strong></th>
<th style="width: 378px;"><strong>Description</strong></th>
<th style="width: 123px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 207px;">pull_number</td>
<td style="width: 378px;">The number of the pull request.</td>
<td style="width: 123px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 255px;"><strong>Path</strong></th>
<th style="width: 87px;"><strong>Type</strong></th>
<th style="width: 366px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 255px;">GitHub.PR.Number</td>
<td style="width: 87px;">Number</td>
<td style="width: 366px;">The number of the pull request.</td>
</tr>
<tr>
<td style="width: 255px;">GitHub.PR.Review.ID</td>
<td style="width: 87px;">Number</td>
<td style="width: 366px;">The ID of the review.</td>
</tr>
<tr>
<td style="width: 255px;">GitHub.PR.Review.NodeID</td>
<td style="width: 87px;">String</td>
<td style="width: 366px;">The Node ID of the review.</td>
</tr>
<tr>
<td style="width: 255px;">GitHub.PR.Review.Body</td>
<td style="width: 87px;">String</td>
<td style="width: 366px;">The content of the review.</td>
</tr>
<tr>
<td style="width: 255px;">GitHub.PR.Review.CommitID</td>
<td style="width: 87px;">String</td>
<td style="width: 366px;">The ID of the commit review.</td>
</tr>
<tr>
<td style="width: 255px;">GitHub.PR.Review.State</td>
<td style="width: 87px;">String</td>
<td style="width: 366px;">The state of the review.</td>
</tr>
<tr>
<td style="width: 255px;">GitHub.PR.Review.User.Login</td>
<td style="width: 87px;">String</td>
<td style="width: 366px;">The user login of the reviewer.</td>
</tr>
<tr>
<td style="width: 255px;">GitHub.PR.Review.User.ID</td>
<td style="width: 87px;">Number</td>
<td style="width: 366px;">The user ID of the reviewer.</td>
</tr>
<tr>
<td style="width: 255px;">GitHub.PR.Review.User.NodeID</td>
<td style="width: 87px;">String</td>
<td style="width: 366px;">The Node ID of the reviewer.</td>
</tr>
<tr>
<td style="width: 255px;">GitHub.PR.Review.User.Type</td>
<td style="width: 87px;">String</td>
<td style="width: 366px;">The user type of the reviewer.</td>
</tr>
<tr>
<td style="width: 255px;">GitHub.PR.Review.User.SiteAdmin</td>
<td style="width: 87px;">Boolean</td>
<td style="width: 366px;">Whether the reviewer is a site administrator.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !GitHub-list-pr-reviews pull_number=1
</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.PR": {
        "Number": "1",
        "Review": [
            {
                "Body": "review comment",
                "CommitID": "b6cf0431e2aea2b345ea1d66d18aa72be63936a9",
                "ID": 287327154,
                "NodeID": "MDE3OlB1bGxSZXF1ZXN0UmV2aWV3Mjg3MzI3MTU0",
                "State": "COMMENTED",
                "User": {
                    "ID": 31018228,
                    "Login": "example-user2",
                    "NodeID": "MDQ6VXNlcjMxMDE4MjI4",
                    "SiteAdmin": false,
                    "Type": "User"
                }
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Pull Request Reviews for #1</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Body</strong></th>
<th><strong>CommitID</strong></th>
<th><strong>ID</strong></th>
<th><strong>NodeID</strong></th>
<th><strong>State</strong></th>
<th><strong>User</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>review comment</td>
<td>b6cf0431e2aea2b345ea1d66d18aa72be63936a9</td>
<td>287327154</td>
<td>MDE3OlB1bGxSZXF1ZXN0UmV2aWV3Mjg3MzI3MTU0</td>
<td>COMMENTED</td>
<td>Login: example-user2<br> ID: 31018228<br> NodeID: MDQ6VXNlcjMxMDE4MjI4<br> Type: User<br> SiteAdmin: false</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_299bf662-bcc0-4738-960e-a5208c0958bb">16. Get the contents of a commit</h3>
<hr>
<p>Retrieves the contents of a commit reference.</p>
<h5>Base Command</h5>
<p><code>GitHub-get-commit</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 132px;"><strong>Argument Name</strong></th>
<th style="width: 496px;"><strong>Description</strong></th>
<th style="width: 80px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 132px;">commit_sha</td>
<td style="width: 496px;">The SHA hash of the commit. Execute the 'GitHub-get-branch'<br> command to find a commit SHA hash to reference.</td>
<td style="width: 80px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 269px;"><strong>Path</strong></th>
<th style="width: 81px;"><strong>Type</strong></th>
<th style="width: 358px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 269px;">GitHub.Commit.SHA</td>
<td style="width: 81px;">String</td>
<td style="width: 358px;">The SHA hash of the commit.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Author.Date</td>
<td style="width: 81px;">String</td>
<td style="width: 358px;">The date of the commit author.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Author.Name</td>
<td style="width: 81px;">String</td>
<td style="width: 358px;">The name of the author.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Author.Email</td>
<td style="width: 81px;">String</td>
<td style="width: 358px;">The email of the author.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Committer.Date</td>
<td style="width: 81px;">String</td>
<td style="width: 358px;">The date the commiter committed.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Committer.Name</td>
<td style="width: 81px;">String</td>
<td style="width: 358px;">The name of the committer.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Committer.Email</td>
<td style="width: 81px;">String</td>
<td style="width: 358px;">The email of the committer.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Message</td>
<td style="width: 81px;">String</td>
<td style="width: 358px;">The message associated with the commit.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Parent</td>
<td style="width: 81px;">Unknown</td>
<td style="width: 358px;">List of the parent SHA hashes.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.TreeSHA</td>
<td style="width: 81px;">String</td>
<td style="width: 358px;">The SHA hash of the commit's tree.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Verification.Verified</td>
<td style="width: 81px;">Boolean</td>
<td style="width: 358px;">Whether the commit was verified.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Verification.Reason</td>
<td style="width: 81px;">String</td>
<td style="width: 358px;">The reason the commit was or was not verified.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Verification.Signature</td>
<td style="width: 81px;">Unknown</td>
<td style="width: 358px;">The verification signature of the commit.</td>
</tr>
<tr>
<td style="width: 269px;">GitHub.Commit.Verification.Payload</td>
<td style="width: 81px;">Unknown</td>
<td style="width: 358px;">The verification payload of the commit.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !GitHub-get-commit commit_sha=8a67a078139498f3e8e1bd2e26ffc5a2fea1b918
</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.Commit": {
        "Author": {
            "Date": "2019-09-16T15:42:43Z",
            "Email": "55035720example.user1@users.noreply.github.com",
            "Name": "example-user1"
        },
        "Committer": {
            "Date": "2019-09-16T15:42:43Z",
            "Email": "noreply@github.com",
            "Name": "GitHub"
        },
        "Message": "Update config.yml",
        "Parent": [
            {
                "SHA": "d6bafef5a0021a6d9ab0a22e11bd0afd5801d936"
            }
        ],
        "SHA": "8a67a078139498f3e8e1bd2e26ffc5a2fea1b918",
        "TreeSHA": "42fdb6c89538099a141e94fabe4bbc58098f4d90",
        "Verification": {
            "Payload": "tree 42fdb6c89538099a141e94fabe4bbc58098f4d90\nparent d6bafef5a0021a6d9ab0a22e11bd0afd5801d936\nauthor example-user1 &lt;55035720example.user1@users.noreply.github.com&gt; 1568648563 +0300\ncommitter GitHub &lt;noreply@github.com&gt; 1568648563 +0300\n\nUpdate config.yml",
            "Reason": "valid",
            "Signature": "-----BEGIN PGP SIGNATURE-----\n\nwsBcBAABCAAQBQJ****************************sIKrPT2jUSWyzfu5wnu\noWz7+2KMdaglV****************************M08HXTm\na9eO/ahlodARkgH/bWjulomeO+jDEgbZenlPUrBnX136QzPPqgl4uvxfquAOj1/a\na89YtPAFh2X1+1q7pl5dVtZfYpo6mYJoY9dwVpDRbLoVHJRa1wnqEv4kxRHrrRL9\nmGWSMHqK8I6j9zXi4niod8pQpl0k4O/2SlNh81RyeILEYb587Zs1XGuIYQEDrcAf\nu+FURxEHSuT4yaZ+oBwhhcIsmsWQMGkfABbwo1Fi2BMtEgZpzd/TScNg1KeSrVI=\n=dWrz\n-----END PGP SIGNATURE-----\n",
            "Verified": true
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Commit *8a67a07813*</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Author</strong></th>
<th><strong>Committer</strong></th>
<th><strong>Message</strong></th>
<th><strong>Parent</strong></th>
<th><strong>SHA</strong></th>
<th><strong>TreeSHA</strong></th>
<th><strong>Verification</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Date: 2019-09-16T15:42:43Z<br> Name: example-user1<br> Email: 55035720example.user1@users.noreply.github.com</td>
<td>Date: 2019-09-16T15:42:43Z<br> Name: GitHub<br> Email: noreply@github.com</td>
<td>Update config.yml</td>
<td>{'SHA': 'd6bafef5a0021a6d9ab0a22e11bd0afd5801d936'}</td>
<td>8a67a078139498f3e8e1bd2e26ffc5a2fea1b918</td>
<td>42fdb6c89538099a141e94fabe4bbc58098f4d90</td>
<td>Verified: true<br> Reason: valid<br> Signature: -----BEGIN PGP SIGNATURE-----<br> <br> wsBcBAABCAAQBQJ****************************sIKrPT2jUSWyzfu5wnu<br> oWz7+2KMdaglV****************************M08HXTm<br> a9eO/ahlodARkgH/bWjulomeO+jDEgbZenlPUrBnX136QzPPqgl4uvxfquAOj1/a<br> a89YtPAFh2X1+1q7pl5dVtZfYpo6mYJoY9dwVpDRbLoVHJRa1wnqEv4kxRHrrRL9<br> mGWSMHqK8I6j9zXi4niod8pQpl0k4O/2SlNh81RyeILEYb587Zs1XGuIYQEDrcAf<br> u+FURxEHSuT4yaZ+oBwhhcIsmsWQMGkfABbwo1Fi2BMtEgZpzd/TScNg1KeSrVI=<br> =dWrz<br> -----END PGP SIGNATURE-----<br> <br> Payload: tree 42fdb6c89538099a141e94fabe4bbc58098f4d90<br> parent d6bafef5a0021a6d9ab0a22e11bd0afd5801d936<br> author example-user1 &lt;55035720example.user1@users.noreply.github.com&gt; 1568648563 +0300<br> committer GitHub &lt;noreply@github.com&gt; 1568648563 +0300<br> <br> Update config.yml</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_20064505-4e55-4478-9e30-8a482fa3b26c">17. Add a label to an issue</h3>
<hr>
<p>Add labels to a Github Issue.</p>
<h5>Base Command</h5>
<p><code>GitHub-add-label</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 158px;"><strong>Argument Name</strong></th>
<th style="width: 453px;"><strong>Description</strong></th>
<th style="width: 97px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 158px;">issue_number</td>
<td style="width: 453px;">The number of the issue in which to add labels.</td>
<td style="width: 97px;">Required</td>
</tr>
<tr>
<td style="width: 158px;">labels</td>
<td style="width: 453px;">A CSV list of labels to add to an issue.</td>
<td style="width: 97px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !GitHub-add-label issue_number=1 labels=Content
</pre>
<h5>Human Readable Output</h5>
<p>Label "Content" Successfully Added to Issue #1</p>
<h3 id="h_2dff022b-e0a0-4142-8356-22e7c0edf943">18. Get a pull request</h3>
<hr>
<p>Retrieves a pull request from the Github repository.</p>
<h5>Base Command</h5>
<p><code>GitHub-get-pull-request</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 171px;"><strong>Argument Name</strong></th>
<th style="width: 433px;"><strong>Description</strong></th>
<th style="width: 104px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 171px;">pull_number</td>
<td style="width: 433px;">The number of the pull request to retrieve.</td>
<td style="width: 104px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 270px;"><strong>Path</strong></th>
<th style="width: 89px;"><strong>Type</strong></th>
<th style="width: 349px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 270px;">GitHub.PR.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The ID number of the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The Node ID of the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Number</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The issue number of the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.State</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The state of the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Locked</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the pull request is locked.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Title</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The title of the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.User.Login</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The login of the user who opened the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.User.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The ID of the user who opened the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.User.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The Node ID of the user who opened the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.User.Type</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The type of the user who opened the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.User.SiteAdmin</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the user who opened the pull request is a site administrator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Body</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The body content of the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Label.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The ID of the label.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Label.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The Node ID of the label.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Label.Name</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The name of the label.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Label.Description</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The description of the label.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Label.Color</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The hex color value of the label.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Label.Default</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the label is a default.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The ID of the milestone.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The Node ID of the milestone.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.Number</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of the milestone.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.State</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The state of the milestone.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.Title</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The title of the milestone.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.Description</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The description of the milestone.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.Creator.Login</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The login of the milestone creator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.Creator.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The ID the milestone creator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.Creator.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The Node ID of the milestone creator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.Creator.Type</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The type of the milestone creator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.Creator.SiteAdmin</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the milestone creator is a site administrator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.OpenIssues</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of open issues with this milestone.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.ClosedIssues</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of closed issues with this milestone.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.CreatedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date the milestone was created.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.UpdatedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date the milestone was updated.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.ClosedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date the milestone was closed.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Milestone.DueOn</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The due date for the milestone.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.ActiveLockReason</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The reason the pull request is locked.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.CreatedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date the pull request was created.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.UpdatedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date the pull request was updated.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.ClosedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date the pull request was closed.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.MergedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date the pull request was merged.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.MergeCommitSHA</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The SHA hash of the pull request's merge commit.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Assignee.Login</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The login of the user assigned to the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Assignee.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The ID of the user assigned to the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Assignee.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The Node ID of the user assigned to the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Assignee.Type</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The type of the user assigned to the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Assignee.SiteAdmin</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the user assigned to the pull request is a site administrator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedReviewer.Login</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The login of the user requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedReviewer.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The ID of the user requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedReviewer.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The node ID of the user requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedReviewer.Type</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The type of the user requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedReviewer.SiteAdmin</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the user requested for review is a site administrator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedTeam.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The ID of the team requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedTeam.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The node ID of the team requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedTeam.Name</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The name of the team requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedTeam.Slug</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The slug of the team requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedTeam.Description</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The description of the team requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedTeam.Privacy</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The privacy setting of the team requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedTeam.Permission</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The permissions of the team requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.RequestedTeam.Parent</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 349px;">The parent of the team requested for a review.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Label</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The label of the branch for which the HEAD points.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Ref</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The reference of the branch for which the  HEAD points.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.SHA</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The SHA hash of the commit for which the  HEAD points.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.User.Login</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The committer login of the HEAD commit of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.User.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The committer ID of the HEAD commit of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.User.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The committer Node ID of the HEAD commit of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.User.Type</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The type of the committer of the HEAD commit of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.User.SiteAdmin</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the committer of the HEAD commit of the checked out branch is a site administrator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The ID of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The Node ID of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Name</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The name of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.FullName</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The full name of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Owner.Login</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The user login of the owner of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Owner.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The user ID of the owner of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Owner.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The user Node ID of the owner of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Owner.Type</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The user type of the owner of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Owner.SiteAdmin</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the owner of the repository of the checked out branch is a site administrator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Private</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch is private.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Description</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The description of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Fork</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch is a fork.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Language</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 349px;">The language of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.ForksCount</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of forks of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.StargazersCount</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of stars of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.WatchersCount</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of entities watching the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Size</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The size of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.DefaultBranch</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The default branch of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.OpenIssuesCount</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The open issues of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Topics</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 349px;">Topics listed for the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.HasIssues</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch has issues.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.HasProjects</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch has projects.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.HasWiki</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch has a wiki.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.HasPages</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch has pages.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.HasDownloads</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch has downloads.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Archived</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch has been archived.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.Disabled</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch has been disabled.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.PushedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date of the latest push to the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.CreatedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date of creation of the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.UpdatedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date the repository of the checked out branch was last updated.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.AllowRebaseMerge</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch permits rebase-style merges.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.AllowSquashMerge</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch permits squash merges.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.AllowMergeCommit</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository of the checked out branch permits merge commits.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Head.Repo.SubscribersCount</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of entities subscribing to the repository of the checked out branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Label</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The label of the base branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Ref</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The reference of the base branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.SHA</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The SHA hash of the base branch.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.User.Login</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The login of the committer of the commit for which the base branch points.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.User.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The committer ID of the commit for which the base branch points.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.User.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The committer Node ID of the commit that the base branch points.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.User.Type</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The committer user type of the commit that the base branch points.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.User.SiteAdmin</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the committer of the commit that the base branch points to is a site administrator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The ID of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The Node ID of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Name</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The name of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.FullName</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The full name of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Owner.Login</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The user login of the owner of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Owner.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The user ID of the owner of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Owner.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The user node ID of the owner of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Owner.Type</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The user type of the owner of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Owner.SiteAdmin</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the owner of the repository that the base branch belongs to is a site administrator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Private</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository for which the base branch belongs to is private.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Description</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The description of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Fork</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository that the base branch belongs to is a fork.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Language</td>
<td style="width: 89px;">Unknown</td>
<td style="width: 349px;">The language of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.ForksCount</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of times that the repository for which the base branch belongs to has been forked.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.StargazersCount</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of times that the repository for which the base branch belongs has been starred.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.WatchersCount</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of entities watching the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Size</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The size of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.DefaultBranch</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The default branch of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.OpenIssuesCount</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of open issues in the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Topics</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">Topics listed for the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.HasIssues</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository for which the base branch belongs has issues.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.HasProjects</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository for which the base branch belongs to has projects.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.HasWiki</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository for which the base branch belongs has a wiki.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.HasPages</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository for which the base branch belongs to has pages.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.HasDownloads</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository for which the base branch belongs has downloads.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Archived</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository for which the base branch belongs to is archived.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.Disabled</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository for which the base branch belongs to is disabled.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.PushedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date that the repository for which the base branch belongs to was last pushed.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.CreatedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date of creation of the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.UpdatedAt</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The date that the repository for which the base branch belongs to was last updated.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.AllowRebaseMerge</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository that the base branch belongs to allows rebase-style merges.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.AllowSquashMerge</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository that the base branch belongs to allows squash merges.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.AllowMergeCommit</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the repository for which the base branch belongs to allows merge commits.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Base.Repo.SubscribersCount</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of entities that subscribe to the repository for which the base branch belongs.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.AuthorAssociation</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The pull request author association.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Draft</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the pull request is a draft.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Merged</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the pull request is merged.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Mergeable</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the pull request is mergeable.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Rebaseable</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the pull request is rebaseable.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.MergeableState</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The mergeable state of the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.MergedBy.Login</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The login of the user who merged the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.MergedBy.ID</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The ID of the user who merged the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.MergedBy.NodeID</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The Node ID of the user who merged the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.MergedBy.Type</td>
<td style="width: 89px;">String</td>
<td style="width: 349px;">The type of the user who merged the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.MergedBy.SiteAdmin</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the user who merged the pull request is a site administrator.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Comments</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of comments on the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.ReviewComments</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of review comments on the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.MaintainerCanModify</td>
<td style="width: 89px;">Boolean</td>
<td style="width: 349px;">Whether the maintainer can modify the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Commits</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of commits in the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Additions</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of additions in the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.Deletions</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of deletions in the pull request.</td>
</tr>
<tr>
<td style="width: 270px;">GitHub.PR.ChangedFiles</td>
<td style="width: 89px;">Number</td>
<td style="width: 349px;">The number of changed files in the pull request.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !GitHub-get-pull-request pull_number=1
</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.PR": {
        "ActiveLockReason": null,
        "Additions": 4,
        "AuthorAssociation": "FIRST_TIME_CONTRIBUTOR",
        "Base": {
            "Label": "example-user1:master",
            "Ref": "master",
            "Repo": {
                "AllowMergeCommit": null,
                "AllowRebaseMerge": null,
                "AllowSquashMerge": null,
                "Archived": false,
                "CreatedAt": "2019-09-11T06:59:20Z",
                "DefaultBranch": "master",
                "Description": "This repository contains all Demisto content and from here we share content updates",
                "Disabled": false,
                "Fork": true,
                "ForksCount": 0,
                "FullName": "example-user1/content",
                "HasDownloads": true,
                "HasIssues": false,
                "HasPages": false,
                "HasProjects": true,
                "HasWiki": false,
                "ID": 207744685,
                "Language": "Python",
                "Name": "content",
                "NodeID": "MDEwOlJlcG9zaXRvcnkyMDc3NDQ2ODU=",
                "OpenIssuesCount": 10,
                "Owner": {
                    "ID": 55035720,
                    "Login": "example-user1",
                    "NodeID": "MDQ6VXNlcjU1MDM1NzIw",
                    "SiteAdmin": false,
                    "Type": "User"
                },
                "Private": false,
                "PushedAt": "2019-09-18T14:05:43Z",
                "Size": 96530,
                "StargazersCount": 0,
                "SucscribersCount": null,
                "Topics": null,
                "UpdatedAt": "2019-09-16T15:42:46Z",
                "WatchersCount": 0
            },
            "SHA": "b27ea6ac9836d2e756b44eb1d66f02d3d4299362",
            "User": {
                "ID": 55035720,
                "Login": "example-user1",
                "NodeID": "MDQ6VXNlcjU1MDM1NzIw",
                "SiteAdmin": false,
                "Type": "User"
            }
        },
        "Body": "<!-- REMINDER: THIS IS A PUBLIC REPO DO NOT POST HERE SECRETS/SENSITIVE DATA -->\r\n\r\n## Status\r\nReady/In Progress/In Hold(Reason for hold)\r\n\r\n## Related Issues\r\nfixes: link to the issue\r\n\r\n## Description\r\nA few sentences describing the overall goals of the pull request's commits.\r\n\r\n## Screenshots\r\nPaste here any images that will help the reviewer\r\n\r\n## Related PRs\r\nList related PRs against other branches:\r\n\r\nbranch | PR\r\n------ | ------\r\n\r\n\r\n## Required version of Demisto\r\nx.x.x\r\n\r\n## Does it break backward compatibility?\r\n   - Yes\r\n       - Further details:\r\n   - No\r\n\r\n## Must have\r\n- [ ] Tests\r\n- [ ] Documentation (with link to it)\r\n- [ ] Code Review\r\n\r\n## Dependencies\r\nMention the dependencies of the entity you changed as given from the precommit hooks in checkboxes, and tick after tested them.\r\n- [ ] Dependency 1\r\n- [ ] Dependency 2\r\n- [ ] Dependency 3\r\n\r\n## Additional changes\r\nDescribe additional changes done, for example adding a function to common server.\r\n",
        "ChangedFiles": 1,
        "ClosedAt": null,
        "Comments": 5,
        "Commits": 4,
        "CreatedAt": "2019-09-11T07:06:26Z",
        "Deletions": 0,
        "Draft": null,
        "Head": {
            "Label": "example-user4:patch-1",
            "Ref": "patch-1",
            "Repo": {
                "AllowMergeCommit": null,
                "AllowRebaseMerge": null,
                "AllowSquashMerge": null,
                "Archived": false,
                "CreatedAt": "2019-08-29T10:18:15Z",
                "DefaultBranch": "master",
                "Description": "This repository contains all Demisto content and from here we share content updates",
                "Disabled": false,
                "Fork": true,
                "ForksCount": 2,
                "FullName": "example-user4/content",
                "HasDownloads": true,
                "HasIssues": false,
                "HasPages": false,
                "HasProjects": true,
                "HasWiki": false,
                "ID": 205137013,
                "Language": "Python",
                "Name": "content",
                "NodeID": "MDEwOlJlcG9zaXRvcnkyMDUxMzcwMTM=",
                "OpenIssuesCount": 2,
                "Owner": {
                    "ID": 46294017,
                    "Login": "example-user4",
                    "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3",
                    "SiteAdmin": false,
                    "Type": "User"
                },
                "Private": false,
                "PushedAt": "2019-09-16T15:43:54Z",
                "Size": 95883,
                "StargazersCount": 0,
                "SucscribersCount": null,
                "Topics": null,
                "UpdatedAt": "2019-08-29T10:18:18Z",
                "WatchersCount": 0
            },
            "SHA": "c01238eea80e35bb76a5c51ac0c95eba4010d8e5",
            "User": {
                "ID": 46294017,
                "Login": "example-user4",
                "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3",
                "SiteAdmin": false,
                "Type": "User"
            }
        },
        "ID": 316303415,
        "Label": [
            {
                "Color": null,
                "Default": false,
                "Description": null,
                "ID": 1563600288,
                "Name": "Content",
                "NodeID": "MDU6TGFiZWwxNTYzNjAwMjg4"
            },
            {
                "Color": null,
                "Default": false,
                "Description": null,
                "ID": 1549466359,
                "Name": "Contribution",
                "NodeID": "MDU6TGFiZWwxNTQ5NDY2MzU5"
            },
            {
                "Color": null,
                "Default": true,
                "Description": null,
                "ID": 1549411616,
                "Name": "bug",
                "NodeID": "MDU6TGFiZWwxNTQ5NDExNjE2"
            }
        ],
        "Locked": false,
        "MaintainerCanModify": true,
        "MergeCommitSHA": "5714b1359b9d7549c89c35fe9fdc266a3db3b766",
        "Mergeable": true,
        "MergeableState": "unstable",
        "Merged": false,
        "MergedAt": null,
        "NodeID": "MDExOlB1bGxSZXF1ZXN0MzE2MzAzNDE1",
        "Number": 1,
        "Rebaseable": true,
        "RequestedReviewer": [
            {
                "ID": 30797606,
                "Login": "example-user3",
                "NodeID": "MDQ6VXNlcjMwNzk3NjA2",
                "SiteAdmin": false,
                "Type": "User"
            },
            {
                "ID": 55035720,
                "Login": "example-user1",
                "NodeID": "MDQ6VXNlcjU1MDM1NzIw",
                "SiteAdmin": false,
                "Type": "User"
            }
        ],
        "ReviewComments": 0,
        "State": "open",
        "UpdatedAt": "2019-09-18T14:05:51Z",
        "User": {
            "ID": 46294017,
            "Login": "example-user4",
            "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3",
            "SiteAdmin": false,
            "Type": "User"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Pull Request #1</h3>
<table style="width: 4291px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 75px;"><strong>Additions</strong></th>
<th style="width: 200px;"><strong>AuthorAssociation</strong></th>
<th style="width: 347px;"><strong>Base</strong></th>
<th style="width: 107px;"><strong>Body</strong></th>
<th style="width: 105px;"><strong>ChangedFiles</strong></th>
<th style="width: 84px;"><strong>Comments</strong></th>
<th style="width: 69px;"><strong>Commits</strong></th>
<th style="width: 103px;"><strong>CreatedAt</strong></th>
<th style="width: 75px;"><strong>Deletions</strong></th>
<th style="width: 345px;"><strong>Head</strong></th>
<th style="width: 81px;"><strong>ID</strong></th>
<th style="width: 245px;"><strong>Label</strong></th>
<th style="width: 56px;"><strong>Locked</strong></th>
<th style="width: 167px;"><strong>MaintainerCanModify</strong></th>
<th style="width: 341px;"><strong>MergeCommitSHA</strong></th>
<th style="width: 82px;"><strong>Mergeable</strong></th>
<th style="width: 124px;"><strong>MergeableState</strong></th>
<th style="width: 59px;"><strong>Merged</strong></th>
<th style="width: 298px;"><strong>NodeID</strong></th>
<th style="width: 63px;"><strong>Number</strong></th>
<th style="width: 91px;"><strong>Rebaseable</strong></th>
<th style="width: 199px;"><strong>RequestedReviewer</strong></th>
<th style="width: 95px;"><strong>ReviewComments</strong></th>
<th style="width: 88px;"><strong>State</strong></th>
<th style="width: 103px;"><strong>UpdatedAt</strong></th>
<th style="width: 183px;"><strong>User</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 75px;">4</td>
<td style="width: 200px;">FIRST_TIME_CONTRIBUTOR</td>
<td style="width: 347px;">Label: example-user1:master<br> Ref: master<br> SHA: b27ea6ac9836d2e756b44eb1d66f02d3d4299362<br> User: {"Login": "example-user1", "ID": 55035720, "NodeID": "MDQ6VXNlcjU1MDM1NzIw", "Type": "User", "SiteAdmin": false}<br> Repo: {"ID": 207744685, "NodeID": "MDEwOlJlcG9zaXRvcnkyMDc3NDQ2ODU=", "Name": "content", "FullName": "example-user1/content", "Owner": {"Login": "example-user1", "ID": 55035720, "NodeID": "MDQ6VXNlcjU1MDM1NzIw", "Type": "User", "SiteAdmin": false}, "Private": false, "Description": "This repository contains all Demisto content and from here we share content updates", "Fork": true, "Language": "Python", "ForksCount": 0, "StargazersCount": 0, "WatchersCount": 0, "Size": 96530, "DefaultBranch": "master", "OpenIssuesCount": 10, "Topics": null, "HasIssues": false, "HasProjects": true, "HasWiki": false, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2019-09-18T14:05:43Z", "CreatedAt": "2019-09-11T06:59:20Z", "UpdatedAt": "2019-09-16T15:42:46Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null}</td>
<td style="width: 107px;">
<p><!-- REMINDER: THIS IS A PUBLIC REPO DO NOT POST HERE SECRETS/SENSITIVE DATA --> <br> <br> ## Status<br> Ready/In Progress/In Hold(Reason for hold)<br> <br> ## Related Issues<br> fixes: link to the issue<br> <br> ## Description<br> A few sentences describing the overall goals of the pull request's commits.<br> <br> ## Screenshots<br> Paste here any images that will help the reviewer<br> <br> ## Related PRs<br> List related PRs against other branches:<br> <br> branch \</p>
<p>PR<br> ------ \</p>
<p>## Required version of Demisto<br>x.x.x</p>
<p>## Does it break backward compatibility?<br>- Yes<br>- Further details:<br>- No</p>
<p>## Must have<br>- [ ] Tests<br>- [ ] Documentation (with link to it)<br>- [ ] Code Review</p>
<p>## Dependencies<br>Mention the dependencies of the entity you changed as given from the precommit hooks in checkboxes, and tick after tested them.<br>- [ ] Dependency 1<br>- [ ] Dependency 2<br>- [ ] Dependency 3</p>
<p>## Additional changes<br>Describe additional changes done, for example adding a function to common server. </p>
</td>
<td style="width: 105px;">1</td>
<td style="width: 84px;">5</td>
<td style="width: 69px;"> 4</td>
<td style="width: 103px;"> 2019-09-11T07:06:26Z</td>
<td style="width: 75px;">0</td>
<td style="width: 345px;">Label: example-user4:patch-1<br> Ref: patch-1<br> SHA: c01238eea80e35bb76a5c51ac0c95eba4010d8e5<br> User: {"Login": "example-user4", "ID": 46294017, "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3", "Type": "User", "SiteAdmin": false}<br> Repo: {"ID": 205137013, "NodeID": "MDEwOlJlcG9zaXRvcnkyMDUxMzcwMTM=", "Name": "content", "FullName": "example-user4/content", "Owner": {"Login": "example-user4", "ID": 46294017, "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3", "Type": "User", "SiteAdmin": false}, "Private": false, "Description": "This repository contains all Demisto content and from here we share content updates", "Fork": true, "Language": "Python", "ForksCount": 2, "StargazersCount": 0, "WatchersCount": 0, "Size": 95883, "DefaultBranch": "master", "OpenIssuesCount": 2, "Topics": null, "HasIssues": false, "HasProjects": true, "HasWiki": false, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2019-09-16T15:43:54Z", "CreatedAt": "2019-08-29T10:18:15Z", "UpdatedAt": "2019-08-29T10:18:18Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null}</td>
<td style="width: 81px;">316303415</td>
<td style="width: 245px;">'ID': 1563600288, 'NodeID': 'MDU6TGFiZWwxNTYzNjAwMjg4', 'Name': 'Content', 'Description': None, 'Color': None, 'Default': False},<br>{'ID': 1549466359, 'NodeID': 'MDU6TGFiZWwxNTQ5NDY2MzU5', 'Name': 'Contribution', 'Description': None, 'Color': None, 'Default': False},<br>{'ID': 1549411616, 'NodeID': 'MDU6TGFiZWwxNTQ5NDExNjE2', 'Name': 'bug', 'Description': None, 'Color': None, 'Default': True}</td>
<td style="width: 56px;">false</td>
<td style="width: 167px;">true</td>
<td style="width: 341px;">5714b1359b9d7549c89c35fe9fdc266a3db3b766</td>
<td style="width: 82px;">true</td>
<td style="width: 124px;">unstable</td>
<td style="width: 59px;">false</td>
<td style="width: 298px;">MDExOlB1bGxSZXF1ZXN0MzE2MzAzNDE1</td>
<td style="width: 63px;">1</td>
<td style="width: 91px;">true</td>
<td style="width: 199px;">{'Login': 'example-user3', 'ID': 30797606, 'NodeID': 'MDQ6VXNlcjMwNzk3NjA2', 'Type': 'User', 'SiteAdmin': False},<br> {'Login': 'example-user1', 'ID': 55035720, 'NodeID': 'MDQ6VXNlcjU1MDM1NzIw', 'Type': 'User', 'SiteAdmin': False}</td>
<td style="width: 95px;">0</td>
<td style="width: 88px;">open</td>
<td style="width: 103px;">2019-09-18T14:05:51Z</td>
<td style="width: 183px;">Login: example-user4<br> ID: 46294017<br> NodeID: MDQ6VXNlcjQ2Mjk0MDE3<br> Type: User<br> SiteAdmin: false</td>
<td style="width: 88px;"> </td>
<td style="width: 53px;"> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_55d1fc5c-e1c9-4293-9db2-3e6d1da440a0">19. GitHub-list-teams</h3>
<hr>
<p>List the teams for an organization. Note that this API call is only available to authenticated members of the organization.</p>
<h5>Base Command</h5>
<p><code>GitHub-list-teams</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 212px;"><strong>Argument Name</strong></th>
<th style="width: 368px;"><strong>Description</strong></th>
<th style="width: 128px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 212px;">organization</td>
<td style="width: 368px;">The name of the organization</td>
<td style="width: 128px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 249px;"><strong>Path</strong></th>
<th style="width: 117px;"><strong>Type</strong></th>
<th style="width: 342px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 249px;">GitHub.Team.ID</td>
<td style="width: 117px;">Number</td>
<td style="width: 342px;">The ID of the team.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Team.NodeID</td>
<td style="width: 117px;">String</td>
<td style="width: 342px;">The Node ID of the team.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Team.Name</td>
<td style="width: 117px;">String</td>
<td style="width: 342px;">The name of the team.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Team.Slug</td>
<td style="width: 117px;">String</td>
<td style="width: 342px;">The slug of the team.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Team.Description</td>
<td style="width: 117px;">String</td>
<td style="width: 342px;">The description of the team.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Team.Privacy</td>
<td style="width: 117px;">String</td>
<td style="width: 342px;">The privacy setting of the team.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Team.Permission</td>
<td style="width: 117px;">String</td>
<td style="width: 342px;">The permissions of the team.</td>
</tr>
<tr>
<td style="width: 249px;">GitHub.Team.Parent</td>
<td style="width: 117px;">Unknown</td>
<td style="width: 342px;">The parent of the team.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !GitHub-list-teams organization=demisto
</pre>
<h5>Context Example</h5>
<pre>{
    "GitHub.Team": [
        {
            "Description": "Review our magnificent SDK",
            "ID": 2084761,
            "Name": "SDK",
            "NodeID": "MDQ6VGVhbTIwODQ3NjE=",
            "Parent": null,
            "Permission": "pull",
            "Privacy": "closed",
            "Slug": "sdk"
        },
        {
            "Description": "Sales engineering",
            "ID": 2086953,
            "Name": "SEs &amp; SAs",
            "NodeID": "MDQ6VGVhbTIwODY5NTM=",
            "Parent": null,
            "Permission": "pull",
            "Privacy": "closed",
            "Slug": "ses-sas"
        },
        {
            "Description": "Our customer success great again team",
            "ID": 2276670,
            "Name": "customer-success",
            "NodeID": "MDQ6VGVhbTIyNzY2NzA=",
            "Parent": null,
            "Permission": "pull",
            "Privacy": "closed",
            "Slug": "customer-success"
        },
        {
            "Description": "",
            "ID": 2615431,
            "Name": "content-admin",
            "NodeID": "MDQ6VGVhbTI2MTU0MzE=",
            "Parent": null,
            "Permission": "pull",
            "Privacy": "closed",
            "Slug": "content-admin"
        },
        {
            "Description": "Our fantastic tech writers",
            "ID": 2944746,
            "Name": "tech writers",
            "NodeID": "MDQ6VGVhbTI5NDQ3NDY=",
            "Parent": null,
            "Permission": "pull",
            "Privacy": "closed",
            "Slug": "tech-writers"
        },
        {
            "Description": "Contractors for customer success team",
            "ID": 2973057,
            "Name": "cs-contractors",
            "NodeID": "MDQ6VGVhbTI5NzMwNTc=",
            "Parent": null,
            "Permission": "pull",
            "Privacy": "closed",
            "Slug": "cs-contractors"
        },
        {
            "Description": "Our beloved content team ",
            "ID": 3043448,
            "Name": "Content",
            "NodeID": "MDQ6VGVhbTMwNDM0NDg=",
            "Parent": null,
            "Permission": "pull",
            "Privacy": "closed",
            "Slug": "content"
        },
        {
            "Description": "Our lovely dev-ops team",
            "ID": 3054683,
            "Name": "dev-ops",
            "NodeID": "MDQ6VGVhbTMwNTQ2ODM=",
            "Parent": null,
            "Permission": "pull",
            "Privacy": "closed",
            "Slug": "dev-ops"
        },
        {
            "Description": "Our sales team",
            "ID": 3086506,
            "Name": "Sales",
            "NodeID": "MDQ6VGVhbTMwODY1MDY=",
            "Parent": null,
            "Permission": "pull",
            "Privacy": "closed",
            "Slug": "sales"
        },
        {
            "Description": "SOC 2 team",
            "ID": 3199605,
            "Name": "soc2",
            "NodeID": "MDQ6VGVhbTMxOTk2MDU=",
            "Parent": null,
            "Permission": "pull",
            "Privacy": "closed",
            "Slug": "soc2"
        },
        {
            "Description": "",
            "ID": 3235143,
            "Name": "mobile",
            "NodeID": "MDQ6VGVhbTMyMzUxNDM=",
            "Parent": null,
            "Permission": "pull",
            "Privacy": "closed",
            "Slug": "mobile"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Teams for Organization "demisto"</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Description</strong></th>
<th><strong>ID</strong></th>
<th><strong>Name</strong></th>
<th><strong>NodeID</strong></th>
<th><strong>Permission</strong></th>
<th><strong>Privacy</strong></th>
<th><strong>Slug</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Our customer success team</td>
<td>2276690</td>
<td>customer-success</td>
<td>MDQ6VGVhbTIyNzY2NzA=</td>
<td>pull</td>
<td>closed</td>
<td>customer-success</td>
</tr>
<tr>
<td>Our beloved content team</td>
<td>3043998</td>
<td>Content</td>
<td>MDQ6VGVhbTMwNDM0NDg=</td>
<td>pull</td>
<td>closed</td>
<td>content</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_74b1f29f-07f7-4765-ab39-8222cc3413cb">20. Delete a branch</h3>
<hr>
<p>Deletes a branch of the repository.</p>
<h5>Base Command</h5>
<p><code>GitHub-delete-branch</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 198px;"><strong>Argument Name</strong></th>
<th style="width: 390px;"><strong>Description</strong></th>
<th style="width: 120px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198px;">branch_name</td>
<td style="width: 390px;">The name of the branch to delete.</td>
<td style="width: 120px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !GitHub-delete-branch branch_name=new-branch-example
</pre>
<h5>Human Readable Output</h5>
<p>Branch "new-branch-example" Deleted Successfully</p>
