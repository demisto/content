<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Deprecated. Vendor has declared end of life for this integration. No available replacement.</p>
<h5>Limitations</h5>
<ul>
<li>Not all actions are supported, only the commands listed in the <a href="#h_30483980971528705313167">Use Cases</a>.</li>
<li>SkyFormation 2.2.10 works with the following cloud applications:
<ul>
<li>Egnyte</li>
<li>DropBox</li>
<li>Azure</li>
<li>Office 365</li>
<li>Salesforce</li>
<li>ServiceNow</li>
</ul>
</li>
</ul>
<hr>
<h2 id="h_30483980971528705313167">Use Cases</h2>
<ul>
<li>Get configured accounts</li>
<li>Suspend a user</li>
<li>Reactivate a user</li>
</ul>
<hr>
<h2>Field Examples</h2>
<p>A SIEM detects a potential "account compromised" in a cloud app (example: Office 365). The alert triggered is fetched by Cortex XSOAR which identifies the alert name and executes the playbook<br> to suspend the Office 365 user until an incident check is performed.</p>
<p>A SIEM detects that a user who has left the company is still using a cloud app (example: Salesforce). The alert triggered is fetched by Cortex XSOAR which identifies the alert name and executes the playbook to suspend the Salesforce user until an incident check is performed.</p>
<hr>
<h2 id="h_16612523431528700689806">Prerequisites</h2>
<p>Verify the following:</p>
<ol>
<li>Make sure that your SkyFormation application is running and events are sent to your selected SIEM.</li>
<li>Obtain a Skyformation API Key. By default, API is disabled.
<ul>
<li>Contact the SkyFormation adminstrator for user-password-credentials, specifically for a user with API access.</li>
<li>Follow the instructions for <a href="https://skyformation.zendesk.com/hc/en-us/articles/115002333394" target="_blank" rel="noopener">SkyFormation API Authentication</a>.</li>
</ul>
</li>
<li>Query/users that should be configured (+ required permissions for that user): As explained above</li>
</ol>
<hr>
<h2>Configure SkyFormation on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for SkyFormation.</li>
<li>Click <strong>Add instance</strong><span class="wysiwyg-color-black"> to create and configure a new integration instance.</span>
<ul>
<li>
<strong>Name:</strong> a textual name for the integration instance</li>
<li>
<strong>Server URL</strong> (example: https://35.158.26.15:8443)</li>
<li>
<strong>C</strong><strong>redentials and Password</strong>: Username and password must be of Skyformation user with API access. See <a href="#h_16612523431528700689806">Prerequisites.</a>
</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>
</ol>
<hr>
<h2>Commands</h2>
<ul>
<li><a href="#h_55806289261528709352127">Get configured accounts: skyformation-get-accounts</a></li>
<li><a href="#h_120685875161528709361236">Suspend a user: skyformation-suspend-user</a></li>
<li><a href="#h_645694409261528709372170">Reactivate a user: skyformation-unsuspend-user</a></li>
</ul>
<hr>
<h3 id="h_55806289261528709352127">Get configured accounts</h3>
<p>Returns all the configured accounts in SkyFormation.</p>
<h5>Basic Command</h5>
<p><code>skyformation-get-accounts</code></p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="height: 113px; width: 717px;" border="6" cellpadding="2">
<tbody>
<tr>
<td style="width: 307px;"><strong>Path</strong></td>
<td style="width: 421px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 307px;">Skyformation.Account</td>
<td style="width: 421px;">
<p>Account object</p>
</td>
</tr>
<tr>
<td style="width: 307px;">Skyformation.Account.Name</td>
<td style="width: 421px;">Account name</td>
</tr>
<tr>
<td style="width: 307px;">Skyformation.Account.Application</td>
<td style="width: 421px;">Application name (example: Office 365, Sales Cloud)</td>
</tr>
<tr>
<td style="width: 307px;">Skyformation.Account.Id</td>
<td style="width: 421px;">Account ID</td>
</tr>
<tr>
<td style="width: 307px;">Skyformation.Account.TenantName</td>
<td style="width: 421px;">Tenant name</td>
</tr>
<tr>
<td style="width: 307px;">Skyformation.Account.TenantId</td>
<td style="width: 421px;">Tenant ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!skyformation-get-accounts</code></p>
<h5>Sample Execution</h5>
<pre>"Skyformation":{  
   "Account":[  
      {  
         "Application":"Office 365",
         "Id":"62ffd05b-2b45-47a9-955a-80030ef08382",
         "Name":"demisto",
         "TenantId":"default-tenant-id",
         "TenantName":"default-tenant"
      },
      {  
         "Application":"Sales Cloud",
         "Id":"e217f098-6fb3-4da1-a399-76210b27513c",
         "Name":"SK4-Salesforce",
         "TenantId":"default-tenant-id",
         "TenantName":"default-tenant"
      }
   ]
}</pre>
<h5>Raw Output</h5>
<pre>[  
   {  
      "application":"Office 365",
      "authn-data":{  
         "fields":[  
            {  
               "name":"client-id",
               "value":"5bd90c0a-a75e-483d-a573-d685f50f4716"
            },
            {  
               "name":"tenant-id",
               "value":"ebac1a16-81bf-449b-8d43-5732c3c1d999"
            },
            {  
               "name":"client-secret",
               "value":"minified-authn-value"
            }
         ],
         "type":"OAUTH2"
      },
      "description":"demisto",
      "id":"62ffd05b-2b45-47a9-955a-80030ef08382",
      "name":"demisto",
      "tenant":{  
         "id":"default-tenant-id",
         "name":"default-tenant"
      }
   },
   {  
      "application":"Sales Cloud",
      "authn-data":{  
         "fields":[  
            {  
               "name":"security-token",
               "value":"some-token"
            },
            {  
               "name":"username",
               "value":"testuser@demisto.com"
            },
            {  
               "name":"password",
               "value":"some-password"
            },
            {  
               "name":"authentication-endpoint",
               "value":"https://login.salesforce.com/services/Soap/u/38.0"
            }
         ],
         "type":"BASIC"
      },
      "description":null,
      "id":"e217f098-6fb3-4da1-a399-76210b27513c",
      "name":"SK4-Salesforce",
      "tenant":{  
         "id":"default-tenant-id",
         "name":"default-tenant"
      }
   }
]
</pre>
<hr>
<h3 id="h_120685875161528709361236">Suspend a user</h3>
<p>The command will suspend the user in the configured application.</p>
<h5>Basic Command</h5>
<p><code>skyformation-suspend-user</code></p>
<h5>Input</h5>
<table style="height: 113px; width: 717px;" border="6" cellpadding="2">
<tbody>
<tr>
<td style="width: 128px;"><strong>Parameter</strong></td>
<td style="width: 600px;"><strong>Description/Notes</strong></td>
</tr>
<tr>
<td style="width: 128px;">accountId</td>
<td style="width: 600px;">
<p>Account ID. You can get the account ID by executing skyformation-get-accounts.</p>
</td>
</tr>
<tr>
<td style="width: 128px;">userEmail</td>
<td style="width: 600px;">
<p>Email address of the user you want to suspend</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command example</h5>
<p><code>!skyformation-suspend-user accountId=62ffd05b-2b45-47a9-955a-80030ef08382 userEmail=testuser@demisto.com</code> </p>
<hr>
<h3 id="h_645694409261528709372170">Reactivate a user</h3>
<p>The command will reactivate the user in the configured application.</p>
<h5>Basic Command</h5>
<p><code>skyformation-unsuspend-user</code></p>
<h5>Input</h5>
<table style="height: 113px; width: 716px;" border="6" cellpadding="2">
<tbody>
<tr>
<td style="width: 128px;"><strong>Parameter</strong></td>
<td style="width: 605px;"><strong>Description/Notes</strong></td>
</tr>
<tr>
<td style="width: 128px;">accountId</td>
<td style="width: 605px;">
<p>Account ID, available by executing "skyformation-get-accounts." command</p>
</td>
</tr>
<tr>
<td style="width: 128px;">userEmail</td>
<td style="width: 605px;">
<p>Email of the user you want to reactivate</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5> Command Example</h5>
<p><code>!skyformation-unsuspend-user accountId=62ffd05b-2b45-47a9-955a-80030ef08382 userEmail=testuser@demisto.com</code></p>
<hr>
<h2>Troubleshooting</h2>
<p> You might receive this error message if you try to suspend or reactivate a user who does not exist in the account.</p>
<p><img src="https://user-images.githubusercontent.com/7270217/38675723-f709f718-3e58-11e8-9a01-3b186fddd772.png" width="821" height="128"></p>