<p>
  Use the Gmail integration to search and process emails in the organizational
  Gmail mailboxes.
</p>
<p>
  This integration replaces the Gmail functionality in the GoogleApps API and G
  Suite integration.&nbsp;
</p>
<h2>Prerequisites</h2>
<p>
  There are several procedures you have to perform in Google before configuring
  the integration on Demisto.
</p>
<ul>
  <li>
    <a href="#h_83620016031534851645646">Get a New Private Key</a>
  </li>
  <li>
    <a href="#h_55847897541534851652027">Delegate Domain-wide Authority to Your Service Account</a>
  </li>
  <li>
    <a href="#h_1988526951041534851657765">Get an Immutable Google Apps ID</a>
  </li>
</ul>
<p>&nbsp;</p>
<h3 id="h_83620016031534851645646">Get a New Private Key</h3>
<ol>
  <ol>
    <ol>
      <ol>
        <ol>
          <li>
            Access your
            <a href="https://console.developers.google.com/projectselector/iam-admin/serviceaccounts%C2%A0" target="_blank" rel="noopener">Google Service Account</a>.
          </li>
          <li>
            In the IAM &amp; admin section select
            <strong>Service accounts</strong>.
          </li>
          <li>
            If you need to create a new project, click <strong>CREATE</strong>&nbsp;do
            the following:
            <ol>
              <li>
                In the&nbsp;<strong>New Project </strong>window,
                type&nbsp;a project name, select an organization
                from the drop-down list&nbsp; and then select a location.&nbsp;
              </li>
              <li>
                Click <strong>CREATE</strong>.
              </li>
            </ol>
          </li>
          <li>
            In the Service accounts section, click
            <strong>Create Service Account</strong>.
          </li>
          <li>
            <span>In the&nbsp;</span><strong>Create service account</strong><span>&nbsp;window, type a name for the service account, add a description and then click <strong>CREATE</strong>.</span>
          </li>
          <li>
            Click <strong>Continue.</strong>
          </li>
          <li>
            In the <strong>Create key</strong> section, click
            <strong>CREATE KEY</strong>.
          </li>
          <li>
            Select Key type <strong>JSON</strong>&nbsp;and click
            <strong>CREATE</strong>.
          </li>
          <li>
            Click <strong>DONE</strong>.
            <p>A key pair is generated and automatically downloads.</p>
          </li>
          <li>
            In the <strong>Actions</strong> column, select the service
            and then click <strong>edit</strong>.
            <p>
              <img src="/hc/article_attachments/360047607593/mceclip1.png" alt="mceclip1.png">
            </p>
          </li>
          <li>
            Under the show domain wide delegation, select
            <strong>Enable G Suite Domain-wide Delegation</strong>.
            <p class="wysiwyg-text-align-left">
              <img src="/hc/article_attachments/360047608933/gmail-_enable.png" alt="gmail-_enable.png">
            </p>
            <p>
              &nbsp;NOTE: Copy the value of the Unique ID for the client
              name in step 2 in&nbsp;<a href="#h_55847897541534851652027" target="_self">Delegate Domain-wide Authority to Your Service Account</a>.
              &nbsp;
            </p>
          </li>
          <li>Click Save.</li>
          <li>
            In the top search bar, search for&nbsp;<em>admin sdk</em>.
          </li>
          <li>
            Click&nbsp;<strong>Enable</strong>.
          </li>
        </ol>
      </ol>
    </ol>
  </ol>
</ol>
<p>&nbsp;</p>
<h3 id="h_55847897541534851652027">Delegate Domain-wide Authority to Your Service Account</h3>
<hr>
<ol>
  <ol>
    <ol>
      <ol>
        <ol>
          <li>
            Access the
            <a href="http://admin.google.com/%C2%A0" target="_blank" rel="noopener">Google Administrator Console</a>.
          </li>
          <li>
            Enter a client name (the Unique ID) and paste the following
            into the One or More API Scopes textbox.&nbsp;<br>
            <p>
              https://www.googleapis.com/auth/gmail.settings.basic,https://www.googleapis.com/auth/admin.directory.user,https://www.googleapis.com/auth/admin.directory.device.mobile.action,https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,https://www.googleapis.com/auth/gmail.modify,https://www.googleapis.com/auth/gmail.settings.sharing,https://www.googleapis.com/auth/gmail.send,https://www.googleapis.com/auth/gmail.modify,https://www.googleapis.com/auth/admin.directory.device.chromeos,https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.directory.rolemanagement,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/gmail.readonly,https://mail.google.com
            </p>
            <p class="wysiwyg-text-align-left">
              <img src="/hc/article_attachments/115005717893/mceclip1.png" width="734" height="191">
            </p>
          </li>
        </ol>
      </ol>
    </ol>
  </ol>
</ol>
<p>&nbsp;</p>
<h3 id="h_1988526951041534851657765">Get an Immutable Google Apps ID Parameters</h3>
<hr>
<div>
  In order to revoke/fetch a user role, you need an Immutable Google Apps ID param.
</div>
<ol>
  <ol>
    <ol>
      <ol>
        <ol>
          <li>
            Open&nbsp;<a href="https://admin.google.com/" target="_blank" rel="noopener noreferrer">https://admin.google.com</a>&nbsp;(as
            in step 2).
          </li>
          <li>
            Navigate to <strong>Security</strong>&nbsp;&gt;
            <strong>Set up single sign-on (SSO)</strong>.&nbsp;<br>
            The SSO URL is the Immutable Google Apps ID.
          </li>
          <li>
            Record the SSO URL, which is the Immutable Google Apps ID,
            and copy it for later use.<br>
            <p>
              <img src="/hc/article_attachments/115005720253/mceclip2.png" width="492" height="158">
            </p>
          </li>
        </ol>
      </ol>
    </ol>
  </ol>
</ol>
<p>&nbsp;</p>
<h2>Configure the Gmail Integration on Demisto</h2>
<ol>
  <ol>
    <ol>
      <ol>
        <ol>
          <li>
            Navigate to <strong>Settings</strong> &gt;
            <strong>Integrations</strong> &gt;
            <strong>Servers &amp; Services</strong>.
          </li>
          <li>Search for Gmail.</li>
          <li>
            Click <strong>Add instance</strong>&nbsp;to create and configure
            a new integration instance.<br>
            <ul>
              <li>
                <strong>Name</strong>: a textual name for the integration
                instance.
              </li>
              <li>
                <strong>Email of user with admin capabilities</strong>
                - Enter the email address of the user that you set&nbsp;admin
                capabilities for.
              </li>
              <li>
                <strong>Password (JSON):</strong>&nbsp; Paste the&nbsp;Service
                account JSON you generated in the Google console,
                which includes the JSON key. The&nbsp;JSON might
                be long, so you can expand the text box.
              </li>
              <li>
                <strong>Immutable Google Apps ID:</strong> Only the&nbsp;Cxxxxxxxx,
                section is needed.
              </li>
              <li>
                <label class="checkbox-label" title="Import events as incidents"><strong>Events query</strong> - Use this to filter out the fetched messages. <br>The query language follows the Gmail query specification example: "from:someuser@example.com rfc822msgid:&lt;somemsgid@example.com&gt; is:unread". For more information, read the <a href="https://support.google.com/mail/answer/7190?hl=en" target="_blank" rel="noopener">Gmail Query Language documentation</a>.</label>
              </li>
              <li>
                <div class="demisto-checkbox ui checkbox ">
                  <label class="checkbox-label" title="Import events as incidents"><strong>Events user key</strong>- Use this&nbsp;<label class="checkbox-label" title="Import events as incidents">to specify the email account to search for messages. By default, the integration uses the email address specified in the admin instance</label>.&nbsp;&nbsp;</label>
                </div>
                <div class="demisto-checkbox ui checkbox ">
                  <label class="checkbox-label" title="Import events as incidents"><label class="checkbox-label" title="Import events as incidents"><img src="/hc/article_attachments/360003150494/mceclip0.png" width="263" height="113"></label></label>
                </div>
              </li>
              <li>
                <strong>Incident type</strong>
              </li>
              <li>
                <strong>Demisto engine</strong>
              </li>
            </ul>
          </li>
          <li>
            Click&nbsp;<strong>Test</strong> to validate the URLs and
            connection.
          </li>
        </ol>
      </ol>
    </ol>
  </ol>
</ol>
<p>&nbsp;</p>
<h2>Use Cases</h2>
<ol>
  <ol>
    <ol>
      <ol>
        <ul>
          <li>
            Monitors a mailbox by using&nbsp;the integration fetch incident
            capability to monitor a mailbox and create incidents for
            new filtered emails.
          </li>
          <li>
            Searches a mailbox for emails with PDF attachments by using
            the following command.<br>
            <code>
    gmail-search user-id=admin@demisto.com filename=”pdf” after=”2018/05/10”.</code>
          </li>
          <li>
            Deletes emails by using the following command.<br>
            <code>!gmail-delete-mail user-id=admin@demisto.com
      message-id=164d2110e0152660</code>
          </li>
        </ul>
      </ol>
    </ol>
  </ol>
</ol>
<p>&nbsp;</p>
<h2>Fetched Incidents Data</h2>
<ol>
  <ol>
    <ol>
      <ol>
        <ul>
          <li>Incident Name</li>
          <li>Occurred</li>
          <li>Owner</li>
          <li>Type</li>
          <li>Severity</li>
          <li>Email From</li>
          <li>Email Message ID</li>
          <li>Email Subject</li>
          <li>Email To</li>
          <li>Attachment Extension</li>
          <li>Attachment Name</li>
          <li>Email Body</li>
          <li>Email Body Format</li>
        </ul>
      </ol>
    </ol>
  </ol>
</ol>
<p>&nbsp;</p>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation,
  or in a playbook. After you successfully execute a command, a DBot message appears
  in the War Room with the command details.
</p>
<ol>
  <ol>
    <ol>
      <ol>
        <ol>
          <li>
            <a href="#h_b0254633-137e-4270-a589-a3b35fdd5bdb" target="_self">Delete a user: gmail-delete-user</a>
          </li>
          <li>
            <a href="#h_8df8a7e8-5f66-4b57-9c33-39422ef2a3fe" target="_self">Get tokens for a user: gmail-get-tokens-for-user</a>
          </li>
          <li>
            <a href="#h_c0c48b18-b019-47bf-95be-4e4fbd61c9b7" target="_self">Get information for a Google user: gmail-get-user</a>
          </li>
          <li>
            <a href="#h_43d07e97-b5a9-45cd-b943-4a612dccee19" target="_self">Get all available Google roles: gmail-get-user-roles</a>
          </li>
          <li>
            <a href="#h_f2e66979-5328-481d-bd01-8272a6f67722" target="_self">Get Gmail message attachments: gmail-get-attachments</a>
          </li>
          <li>
            <a href="#h_64d76dfa-7288-43c3-bf6e-4f5e62735f68" target="_self">Get a Gmail message: gmail-get-mail</a>
          </li>
          <li>
            <a href="#h_fc21f5cb-ab2b-4758-96c6-7ff19a550504" target="_self">Search a user's Gmail records: gmail-search</a>
          </li>
          <li>
            <a href="#h_aef2387b-01c9-4638-bdfb-d66d8b0bd3f2" target="_self">Search in all Gmail mailboxes: gmail-search-all-mailboxes</a>
          </li>
          <li>
            <a href="#h_e8581779-4a1b-45ec-8cf3-3016fe0f2bca" target="_self">List all Google users: gmail-list-users</a>
          </li>
          <li>
            <a href="#h_b3b4908f-7e88-4397-b4e7-b83c9d6f2e7d" target="_self">Revoke a Google user's role: gmail-revoke-user-role</a>
          </li>
          <li>
            <a href="#h_84ffd332-3475-4e33-900e-9e9bc2dbb352" target="_self">Create a new user: gmail-create-user</a>
          </li>
          <li>
            <a href="#h_01733786-6f8e-42ed-a8e1-a10b52f324b4" target="_self">Delete mail from a mailbox: gmail-delete-mail</a>
          </li>
          <li>
            <a href="#h_7c28d177-2aa4-4803-be8e-6d38f1abe8f7" target="_self">Get message in an email thread: gmail-get-thread</a>
          </li>
          <li>
            <a href="#h_ab82adf8-181e-4dfc-91ab-7386f0cadbc2" target="_self">Move mail to a different folder: gmail-move-mail</a>
          </li>
          <li>
            <a href="#h_5bbef95c-6bf1-44ea-9b10-31826260c64d" target="_self">Move a mail to a different mailbox: gmail-move-mail-to-mailbox</a>
          </li>
          <li>
            <a href="#h_21d165fc-a05a-4d3a-9f1a-f1b1d28ae064" target="_self">Add a rule to delete an email: gmail-add-delete-filter</a>
          </li>
          <li>
            <a href="#h_acd7c5ed-5c46-4cb3-ac99-99ec391b18ce" target="_self">Add a new filter: gmail-add-filter</a>
          </li>
          <li>
            <a href="#h_a5e4ed4e-29ec-4c67-929e-3941efae29e7" target="_self">Get a list of filters in a mailbox: gmail-list-fillter</a>
          </li>
          <li>
            <a href="#h_32f83831-3fea-4b22-a6a8-28a7e75bc38c" target="_self">Remove a filter from a mail: gmail-remove-filter</a>
          </li>
          <li>
            <a href="#h_7d54beb9-bff7-4e22-9ebf-56a921aeb368" target="_self">Move a mail to a different mailbox: gmail-move-mail-to-mailbox</a>
          </li>
          <li>
            <a href="#h_ac2b8475-5561-47e5-8b35-f19e9003aed2" target="_self">Hide a user's information: gmail-hide-user-in-directory</a>
          </li>
          <li>
            <a href="#h_03d832cf-9cea-4726-b6df-9c1ee9ae86fa" target="_self">Set a password: gmail-set-password</a>
          </li>
          <li>
            <a href="#h_7e249b6b-675e-4a16-ae4b-1c96df0cae90" target="_self">Get an auto reply message for the user: gmail-get-autoreply</a>
          </li>
          <li>
            <a href="#h_e8138221-0d22-4c0f-b7b1-595503a6ce5c" target="_self">Set an auto-reply for the user: gmail-set-autoreply</a>
          </li>
          <li>
            <a href="#h_9032f028-a988-4416-b97a-9888cbdab04b" target="_self">Add a delete user to a mailbox: gmail-delegate-user-mailbox</a>
          </li>
          <li>
            <a href="#h_6b56a925-b478-49a7-a57c-28e81258f007" target="_self">Send an email using Gmail: send-mail</a>
          </li>
          <li>
            <a href="#h_426da8de-404c-432d-9080-b476cf896f5a" target="_self">Removers a delegate from a mailbox: gmail-remove-delegated-mailbox</a>
          </li>
        </ol>
      </ol>
    </ol>
  </ol>
</ol>
<h3 id="h_b0254633-137e-4270-a589-a3b35fdd5bdb">1. Delete a user</h3>
<hr>
<p>Deletes a Gmail user.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-delete-user</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:98px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:539px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:98px">user-id</td>
      <td style="width:539px">
        The user's email address. The "me" special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-delete-user user-id=user@demistodev.com</pre>
<h5>Human Readable Output</h5>
<p>User user@demistodev.com have been deleted.</p>
<h3 id="h_8df8a7e8-5f66-4b57-9c33-39422ef2a3fe">2. Get tokens for a Google user</h3>
<hr>
<p>
  Lists all tokens associated with a specified user applications.
</p>
<h5>Base Command</h5>
<p>
  <code>gmail-get-tokens-for-user</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:98px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:539px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:98px">user-id</td>
      <td style="width:539px">
        The user's email address. The "me" special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!gmail-get-tokens-for-user user-id=admin@demistodev.com</pre>
<h5>Context Example</h5>
<pre>{
    "Tokens": [
        {
            "ClientId": "292824132082.apps.googleusercontent.com",
            "DisplayText": "Google APIs Explorer",
            "Kind": "admin#directory#token",
            "Scopes": [
                "https://www.googleapis.com/auth/ediscovery.readonly",
                "openid",
                "https://www.googleapis.com/auth/ediscovery",
                "https://www.googleapis.com/auth/cloudkms",
                "https://www.googleapis.com/auth/admin.directory.user.security",
                "https://www.googleapis.com/auth/admin.directory.user",
                "https://www.googleapis.com/auth/admin.directory.user.readonly",
                "https://www.googleapis.com/auth/admin.directory.rolemanagement",
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly"
            ],
            "UserKey": "103020731686044834269"
        },
        {
            "ClientId": "422358954086-4fvv287aojmge1qaqe9m5mmgmbuhg1hj.apps.googleusercontent.com",
            "DisplayText": "Go Phish!",
            "Kind": "admin#directory#token",
            "Scopes": [
                "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
                "https://www.googleapis.com/auth/script.send_mail",
                "https://www.googleapis.com/auth/userinfo.email",
                "openid",
                "https://www.googleapis.com/auth/script.storage",
                "https://www.googleapis.com/auth/gmail.addons.execute",
                "https://www.googleapis.com/auth/admin.directory.user.readonly"
            ],
            "UserKey": "103020731686044834269"
        },
        {
            "ClientId": "950822307886-oiv25bpm32dtp21eabn2k5lf1ba7koum.apps.googleusercontent.com",
            "DisplayText": "Demisto KMS DEV",
            "Kind": "admin#directory#token",
            "Scopes": [
                "https://www.googleapis.com/auth/cloud-platform"
            ],
            "UserKey": "103020731686044834269"
        },
        {
            "ClientId": "371237729773-oj8m98u7esgqep8snt9aold136opo3fi.apps.googleusercontent.com",
            "DisplayText": "Google Data Studio",
            "Kind": "admin#directory#token",
            "Scopes": [
                "https://www.googleapis.com/auth/bigquery.readonly"
            ],
            "UserKey": "103020731686044834269"
        },
        {
            "ClientId": "805864674475-3abs2rivkn7kreou30b8ru8esnti4oih.apps.googleusercontent.com",
            "DisplayText": "Postman",
            "Kind": "admin#directory#token",
            "Scopes": [
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/userinfo.email"
            ],
            "UserKey": "103020731686044834269"
        },
        {
            "ClientId": "77185425430.apps.googleusercontent.com",
            "DisplayText": "Google Chrome",
            "Kind": "admin#directory#token",
            "Scopes": [
                "https://www.google.com/accounts/OAuthLogin"
            ],
            "UserKey": "103020731686044834269"
        },
        {
            "ClientId": "1041831412594-vrl2ne8nr3rnireuc39qk4i7aqgu0n39.apps.googleusercontent.com",
            "DisplayText": "demisto",
            "Kind": "admin#directory#token",
            "Scopes": [
                "https://www.googleapis.com/auth/admin.directory.group.readonly",
                "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
                "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                "https://www.googleapis.com/auth/drive.readonly",
                "https://www.googleapis.com/auth/calendar.readonly",
                "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
                "https://www.googleapis.com/auth/admin.directory.user.readonly",
                "https://www.googleapis.com/auth/admin.reports.usage.readonly",
                "https://www.googleapis.com/auth/tasks"
            ],
            "UserKey": "103020731686044834269"
        },
        {
            "ClientId": "800521135851-nh4gf3m9kbpu83h2sl8sm8a21e7g7ldi.apps.googleusercontent.com",
            "DisplayText": "BetterCloud",
            "Kind": "admin#directory#token",
            "Scopes": [
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/userinfo.email",
                "openid",
                "https://www.googleapis.com/auth/admin.directory.user.readonly"
            ],
            "UserKey": "103020731686044834269"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>
  <strong>Tokens</strong>:
</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>DisplayText</strong>
      </th>
      <th>
        <strong>ClientId</strong>
      </th>
      <th>
        <strong>Kind</strong>
      </th>
      <th>
        <strong>Scopes</strong>
      </th>
      <th>
        <strong>UserKey</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Google APIs Explorer</td>
      <td>292824132082.apps.googleusercontent.com</td>
      <td>admin#directory#token</td>
      <td>
        https://www.googleapis.com/auth/ediscovery.readonly,<br>
        openid,<br>
        https://www.googleapis.com/auth/ediscovery,<br>
        https://www.googleapis.com/auth/cloudkms,<br>
        https://www.googleapis.com/auth/admin.directory.user.security,<br>
        https://www.googleapis.com/auth/admin.directory.user,<br>
        https://www.googleapis.com/auth/admin.directory.user.readonly,<br>
        https://www.googleapis.com/auth/admin.directory.rolemanagement,<br>
        https://www.googleapis.com/auth/cloud-platform,<br>
        https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly
      </td>
      <td>103020731686044834269</td>
    </tr>
    <tr>
      <td>Go Phish!</td>
      <td>
        422358954086-4fvv287aojmge1qaqe9m5mmgmbuhg1hj.apps.googleusercontent.com
      </td>
      <td>admin#directory#token</td>
      <td>
        https://www.googleapis.com/auth/gmail.addons.current.message.readonly,<br>
        https://www.googleapis.com/auth/script.send_mail,<br>
        https://www.googleapis.com/auth/userinfo.email,<br>
        openid,<br>
        https://www.googleapis.com/auth/script.storage,<br>
        https://www.googleapis.com/auth/gmail.addons.execute,<br>
        https://www.googleapis.com/auth/admin.directory.user.readonly
      </td>
      <td>103020731686044834269</td>
    </tr>
    <tr>
      <td>Demisto KMS DEV</td>
      <td>
        950822307886-oiv25bpm32dtp21eabn2k5lf1ba7koum.apps.googleusercontent.com
      </td>
      <td>admin#directory#token</td>
      <td>https://www.googleapis.com/auth/cloud-platform</td>
      <td>103020731686044834269</td>
    </tr>
    <tr>
      <td>Google Data Studio</td>
      <td>
        371237729773-oj8m98u7esgqep8snt9aold136opo3fi.apps.googleusercontent.com
      </td>
      <td>admin#directory#token</td>
      <td>https://www.googleapis.com/auth/bigquery.readonly</td>
      <td>103020731686044834269</td>
    </tr>
    <tr>
      <td>Postman</td>
      <td>
        805864674475-3abs2rivkn7kreou30b8ru8esnti4oih.apps.googleusercontent.com
      </td>
      <td>admin#directory#token</td>
      <td>
        https://www.googleapis.com/auth/userinfo.profile,<br>
        https://www.googleapis.com/auth/userinfo.email
      </td>
      <td>103020731686044834269</td>
    </tr>
    <tr>
      <td>Google Chrome</td>
      <td>77185425430.apps.googleusercontent.com</td>
      <td>admin#directory#token</td>
      <td>https://www.google.com/accounts/OAuthLogin</td>
      <td>103020731686044834269</td>
    </tr>
    <tr>
      <td>demisto</td>
      <td>
        1041831412594-vrl2ne8nr3rnireuc39qk4i7aqgu0n39.apps.googleusercontent.com
      </td>
      <td>admin#directory#token</td>
      <td>
        https://www.googleapis.com/auth/admin.directory.group.readonly,<br>
        https://www.googleapis.com/auth/admin.directory.orgunit.readonly,<br>
        https://www.googleapis.com/auth/admin.reports.audit.readonly,<br>
        https://www.googleapis.com/auth/drive.readonly,<br>
        https://www.googleapis.com/auth/calendar.readonly,<br>
        https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,<br>
        https://www.googleapis.com/auth/admin.directory.user.readonly,<br>
        https://www.googleapis.com/auth/admin.reports.usage.readonly,<br>
        https://www.googleapis.com/auth/tasks
      </td>
      <td>103020731686044834269</td>
    </tr>
    <tr>
      <td>BetterCloud</td>
      <td>
        800521135851-nh4gf3m9kbpu83h2sl8sm8a21e7g7ldi.apps.googleusercontent.com
      </td>
      <td>admin#directory#token</td>
      <td>
        https://www.googleapis.com/auth/userinfo.profile,<br>
        https://www.googleapis.com/auth/userinfo.email,<br>
        openid,<br>
        https://www.googleapis.com/auth/admin.directory.user.readonly
      </td>
      <td>103020731686044834269</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_c0c48b18-b019-47bf-95be-4e4fbd61c9b7">3. Get information for a Google user</h3>
<hr>
<p>Retrieves information for a specified Google user.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-get-user</code>
</p>
<h5>Input</h5>
<table style="width:746px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:69px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:568px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:69px">user-id</td>
      <td style="width:568px">
        The user's email address. The "me" special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:69px">projection</td>
      <td style="width:568px">
        The subset of fields to fetch for the user. Can be: "basic": Do not
        include any custom fields for the user (default), "custom": Includes
        custom fields from schema requested in custom-field-mask, "full":
        Includes all fields associated with the user.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:69px">view-type-public-domain</td>
      <td style="width:568px">
        Whether to fetch the administrator or public view of the user. Can
        be admin_view (default), which includes both administrator and domain-public
        fields; or "domain_public", which includes user fields that are publicly
        visible to other users in the domain.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:69px">custom-field-mask</td>
      <td style="width:568px">
        A comma separated list of schema names. All fields from these schemas
        are fetched. This should only be set when projection=custom.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:166px">
        <strong>Path</strong>
      </th>
      <th style="width:56px">
        <strong>Type</strong>
      </th>
      <th style="width:486px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:166px">Account.Type</td>
      <td style="width:56px">String</td>
      <td style="width:486px">
        The account type. For example, "AD", "LocalOS", "Google", "AppleID",
        and so on.
      </td>
    </tr>
    <tr>
      <td style="width:166px">Account.ID</td>
      <td style="width:56px">String</td>
      <td style="width:486px">
        The unique ID for the account (integration specific). For AD accounts
        this is the Distinguished Name (DN).
      </td>
    </tr>
    <tr>
      <td style="width:166px">Account.DisplayName</td>
      <td style="width:56px">string</td>
      <td style="width:486px">The display name.</td>
    </tr>
    <tr>
      <td style="width:166px">Account.Gmail.Address</td>
      <td style="width:56px">string</td>
      <td style="width:486px">Email assigned with the current account.</td>
    </tr>
    <tr>
      <td style="width:166px">Account.Email.Address</td>
      <td style="width:56px">String</td>
      <td style="width:486px">The email address of the account.</td>
    </tr>
    <tr>
      <td style="width:166px">Account.Groups</td>
      <td style="width:56px">String</td>
      <td style="width:486px">
        Groups to which the account belongs (integration specific). For example,
        for AD, these are the groups in which the account is a member.
      </td>
    </tr>
    <tr>
      <td style="width:166px">Account.Domain</td>
      <td style="width:56px">String</td>
      <td style="width:486px">The domain of the account.</td>
    </tr>
    <tr>
      <td style="width:166px">Account.Username</td>
      <td style="width:56px">String</td>
      <td style="width:486px">The account username in the relevant system.</td>
    </tr>
    <tr>
      <td style="width:166px">Account.OrganizationUnit</td>
      <td style="width:56px">String</td>
      <td style="width:486px">The Organization Unit (OU) of the account.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-get-user user-id=user@demistodev.com</pre>
<h5>Context Example</h5>
<pre>{
    "Account": [
        {
            "CustomerId": "C02f0zfqw",
            "DisplayName": "John Snow",
            "Domain": "demistodev.com",
            "Email": {
                "Address": "user@demistodev.com"
            },
            "Gmail": {
                "Address": "user@demistodev.com"
            },
            "Group": "admin#directory#user",
            "Groups": "admin#directory#user",
            "ID": "117047108909890245378",
            "Type": "Google",
            "UserName": "John",
            "Username": "John",
            "VisibleInDirectory": true
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>User user@demistodev.com:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>Username</strong>
      </th>
      <th>
        <strong>DisplayName</strong>
      </th>
      <th>
        <strong>Groups</strong>
      </th>
      <th>
        <strong>CustomerId</strong>
      </th>
      <th>
        <strong>Domain</strong>
      </th>
      <th>
        <strong>Email</strong>
      </th>
      <th>
        <strong>VisibleInDirectory</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Google</td>
      <td>117047108909890245378</td>
      <td>John</td>
      <td>John Snow</td>
      <td>admin#directory#user</td>
      <td>C02f0zfqw</td>
      <td>demistodev.com</td>
      <td>Address: user@demistodev.com</td>
      <td>true</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_43d07e97-b5a9-45cd-b943-4a612dccee19">4. Get all available Google roles</h3>
<hr>
<p>
  Lists all available Google roles for a specified Google user.
</p>
<h5>Base Command</h5>
<p>
  <code>gmail-get-user-roles</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:96px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:541px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:96px">user-id</td>
      <td style="width:541px">
        The user's email address. The "me" special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:295px">
        <strong>Path</strong>
      </th>
      <th style="width:59px">
        <strong>Type</strong>
      </th>
      <th style="width:354px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:295px">GoogleApps.Role.RoleAssignmentId</td>
      <td style="width:59px">string</td>
      <td style="width:354px">The unique ID of the role assignment.</td>
    </tr>
    <tr>
      <td style="width:295px">GoogleApps.Role.ScopeType</td>
      <td style="width:59px">string</td>
      <td style="width:354px">The scope type of the role.</td>
    </tr>
    <tr>
      <td style="width:295px">GoogleApps.Role.Kind</td>
      <td style="width:59px">string</td>
      <td style="width:354px">The kind of the Role.</td>
    </tr>
    <tr>
      <td style="width:295px">GoogleApps.Role.OrgUnitId</td>
      <td style="width:59px">string</td>
      <td style="width:354px">Organization in which user was assigned.</td>
    </tr>
    <tr>
      <td style="width:295px">GoogleApps.Role.ID</td>
      <td style="width:59px">string</td>
      <td style="width:354px">The inner role ID.</td>
    </tr>
    <tr>
      <td style="width:295px">GoogleApps.Role.AssignedTo</td>
      <td style="width:59px">string</td>
      <td style="width:354px">User ID who was assigned to the role.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-get-user-roles user-id=admin@demistodev.com
</pre>
<h5>Context Example</h5>
<pre>{
    "Gmail.Role": [
        {
            "AssignedTo": "103020731686044834269",
            "ID": "10740456929361921",
            "Kind": "admin#directory#roleAssignment",
            "OrgUnitId": "",
            "RoleAssignmentId": "10740456929361921",
            "ScopeType": "CUSTOMER"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>User Roles of admin@demistodev.com:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>AssignedTo</strong>
      </th>
      <th>
        <strong>RoleAssignmentId</strong>
      </th>
      <th>
        <strong>ScopeType</strong>
      </th>
      <th>
        <strong>Kind</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>10740456929361921</td>
      <td>103020731686044834269</td>
      <td>10740456929361921</td>
      <td>CUSTOMER</td>
      <td>admin#directory#roleAssignment</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_f2e66979-5328-481d-bd01-8272a6f67722">5. Get Gmail message attachments</h3>
<hr>
<p>
  Retrieves Gmail attachments sent to a specified Google user.
</p>
<h5>Base Command</h5>
<p>
  <code>gmail-get-attachments</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:96px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:541px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:96px">message-id</td>
      <td style="width:541px">The ID of the message to retrieve.</td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:96px">user-id</td>
      <td style="width:541px">
        The user's email address. The "me" special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-get-attachments message-id=16d4316a25a332e4 user-id=admin@demistodev.com
</pre>
<p>&nbsp;</p>
<h3 id="h_64d76dfa-7288-43c3-bf6e-4f5e62735f68">6. Get a Gmail message</h3>
<hr>
<p>Retrieves a Gmail message sent to a specified Google user.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-get-mail</code>
</p>
<h5>Required Permissions</h5>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:75px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:562px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:75px">user-id</td>
      <td style="width:562px">
        The user's email address. The special value me can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:75px">message-id</td>
      <td style="width:562px">The ID of the message to retrieve.</td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:75px">format</td>
      <td style="width:562px">
        The format in which to return the message. Can be: "full": Returns
        the full email message data with body content parsed in the payload
        field; the raw field is not used. (default) / "metadata": Returns
        only the email message ID, labels, and email headers / "minimal":
        Returns only the email message ID and labels; does not return the
        email headers, body, or payload / "raw": Returns the full email message
        data with body content in the raw field as a base64url encoded string;
        the payload field is not used.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:188px">
        <strong>Path</strong>
      </th>
      <th style="width:70px">
        <strong>Type</strong>
      </th>
      <th style="width:450px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:188px">Gmail.ID</td>
      <td style="width:70px">String</td>
      <td style="width:450px">Inner ID of the Gmail message.</td>
    </tr>
    <tr>
      <td style="width:188px">Gmail.ThreadId</td>
      <td style="width:70px">string</td>
      <td style="width:450px">The thread ID.</td>
    </tr>
    <tr>
      <td style="width:188px">Gmail.Format</td>
      <td style="width:70px">string</td>
      <td style="width:450px">MIME type of email.</td>
    </tr>
    <tr>
      <td style="width:188px">Gmail.Labels</td>
      <td style="width:70px">string</td>
      <td style="width:450px">Labels of the specific email.</td>
    </tr>
    <tr>
      <td style="width:188px">Gmail.To</td>
      <td style="width:70px">String</td>
      <td style="width:450px">Email Address of the receiver.</td>
    </tr>
    <tr>
      <td style="width:188px">Gmail.From</td>
      <td style="width:70px">String</td>
      <td style="width:450px">Email Address of the sender.</td>
    </tr>
    <tr>
      <td style="width:188px">Gmail.Cc</td>
      <td style="width:70px">string</td>
      <td style="width:450px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:188px">Email.Bcc</td>
      <td style="width:70px">string</td>
      <td style="width:450px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:188px">Gmail.Subject</td>
      <td style="width:70px">string</td>
      <td style="width:450px">Subject of the email.</td>
    </tr>
    <tr>
      <td style="width:188px">Gmail.Body</td>
      <td style="width:70px">string</td>
      <td style="width:450px">The content of the email.</td>
    </tr>
    <tr>
      <td style="width:188px">Gmail.Attachments</td>
      <td style="width:70px">unknown</td>
      <td style="width:450px">
        The attachments of the email. Attachments ID's are separated by ','.
      </td>
    </tr>
    <tr>
      <td style="width:188px">Gmail.Headers</td>
      <td style="width:70px">unknown</td>
      <td style="width:450px">All headers of the specific email (list).</td>
    </tr>
    <tr>
      <td style="width:188px">Email.Mailbox</td>
      <td style="width:70px">string</td>
      <td style="width:450px">The email mailbox.</td>
    </tr>
    <tr>
      <td style="width:188px">Email.To</td>
      <td style="width:70px">String</td>
      <td style="width:450px">The recipient of the email.</td>
    </tr>
    <tr>
      <td style="width:188px">Email.From</td>
      <td style="width:70px">String</td>
      <td style="width:450px">The sender of the email.</td>
    </tr>
    <tr>
      <td style="width:188px">Email.CC</td>
      <td style="width:70px">String</td>
      <td style="width:450px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:188px">Email.BCC</td>
      <td style="width:70px">String</td>
      <td style="width:450px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:188px">Email.Format</td>
      <td style="width:70px">String</td>
      <td style="width:450px">The format of the email.</td>
    </tr>
    <tr>
      <td style="width:188px">Email.Body/HTML</td>
      <td style="width:70px">String</td>
      <td style="width:450px">The HTML version of the email.</td>
    </tr>
    <tr>
      <td style="width:188px">Email.Body/Text</td>
      <td style="width:70px">String</td>
      <td style="width:450px">The plain-text version of the email.</td>
    </tr>
    <tr>
      <td style="width:188px">Email.Subject</td>
      <td style="width:70px">String</td>
      <td style="width:450px">The subject of the email.</td>
    </tr>
    <tr>
      <td style="width:188px">Email.Headers</td>
      <td style="width:70px">String</td>
      <td style="width:450px">The headers of the email.</td>
    </tr>
    <tr>
      <td style="width:188px">Email.Attachments.entryID</td>
      <td style="width:70px">Unknown</td>
      <td style="width:450px">Attachments ids separated by ','.</td>
    </tr>
    <tr>
      <td style="width:188px">Email.Date</td>
      <td style="width:70px">String</td>
      <td style="width:450px">The date the email was received.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-get-mail user-id=admin@demistodev.com message-id=16d4316a25a332e4
</pre>
<h5>Context Example</h5>
<pre>{
    "Email": [
        {
            "Attachment Names": "puppy.png",
            "Attachments": [
                {
                    "ID": "<id>",
                    "Name": "puppy.png"
                }
            ],
            "BCC": "",
            "Body/HTML": "",
            "Body/Text": "",
            "CC": "",
            "Date": "Tue, 17 Sep 2019 23:36:59 -0700",
            "Format": "multipart/mixed",
            "From": "admin@demistodev.com",
            "Headers": [
                {
                    "Name": "Received",
                    "Value": "from 1041831412594 named unknown by gmailapi.google.com with HTTPREST; Tue, 17 Sep 2019 23:36:59 -0700"
                },
                {
                    "Name": "Content-Type",
                    "Value": "multipart/mixed; boundary=\"===============3751607758919896682==\""
                },
                {
                    "Name": "MIME-Version",
                    "Value": "1.0"
                },
                {
                    "Name": "to",
                    "Value": "admin@demistodev.com"
                },
                {
                    "Name": "cc",
                    "Value": ""
                },
                {
                    "Name": "bcc",
                    "Value": ""
                },
                {
                    "Name": "from",
                    "Value": "admin@demistodev.com"
                },
                {
                    "Name": "subject",
                    "Value": "attachment"
                },
                {
                    "Name": "reply-to",
                    "Value": ""
                },
                {
                    "Name": "Date",
                    "Value": "Tue, 17 Sep 2019 23:36:59 -0700"
                },
                {
                    "Name": "Message-Id",
                    "Value": "&lt;<value>&gt;"
                }
            ],
            "ID": "16d4316a25a332e4",
            "RawData": null,
            "Subject": "attachment",
            "To": "admin@demistodev.com"
        }
    ],
    "Gmail": [
        {
            "Attachment Names": "puppy.png",
            "Attachments": [
                {
                    "ID": "<id>",
                    "Name": "puppy.png"
                }
            ],
            "Bcc": "",
            "Body": "",
            "Cc": "",
            "Date": "Tue, 17 Sep 2019 23:36:59 -0700",
            "Format": "multipart/mixed",
            "From": "admin@demistodev.com",
            "Headers": [
                {
                    "Name": "Received",
                    "Value": "from 1041831412594 named unknown by gmailapi.google.com with HTTPREST; Tue, 17 Sep 2019 23:36:59 -0700"
                },
                {
                    "Name": "Content-Type",
                    "Value": "multipart/mixed; boundary=\"===============3751607758919896682==\""
                },
                {
                    "Name": "MIME-Version",
                    "Value": "1.0"
                },
                {
                    "Name": "to",
                    "Value": "admin@demistodev.com"
                },
                {
                    "Name": "cc",
                    "Value": ""
                },
                {
                    "Name": "bcc",
                    "Value": ""
                },
                {
                    "Name": "from",
                    "Value": "admin@demistodev.com"
                },
                {
                    "Name": "subject",
                    "Value": "attachment"
                },
                {
                    "Name": "reply-to",
                    "Value": ""
                },
                {
                    "Name": "Date",
                    "Value": "Tue, 17 Sep 2019 23:36:59 -0700"
                },
                {
                    "Name": "Message-Id",
                    "Value": "&lt;<value>&gt;"
                }
            ],
            "Html": "",
            "ID": "16d4316a25a332e4",
            "Labels": "UNREAD, SENT, INBOX",
            "Mailbox": "admin@demistodev.com",
            "RawData": null,
            "Subject": "attachment",
            "ThreadId": "16d4316a25a332e4",
            "To": "admin@demistodev.com",
            "Type": "Gmail"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Email:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Mailbox</strong>
      </th>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>Subject</strong>
      </th>
      <th>
        <strong>From</strong>
      </th>
      <th>
        <strong>To</strong>
      </th>
      <th>
        <strong>Labels</strong>
      </th>
      <th>
        <strong>Attachment Names</strong>
      </th>
      <th>
        <strong>Format</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>admin@demistodev.com</td>
      <td>16d4316a25a332e4</td>
      <td>attachment</td>
      <td>admin@demistodev.com</td>
      <td>admin@demistodev.com</td>
      <td>UNREAD, SENT, INBOX</td>
      <td>puppy.png</td>
      <td>multipart/mixed</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_fc21f5cb-ab2b-4758-96c6-7ff19a550504">7. Search a user's Gmail records</h3>
<hr>
<p>Searches for Gmail records of a specified Google user.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-search</code>
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
      <td>user-id</td>
      <td>
        The user's email address. The "me" special value can be used to indicate
        the authenticated user.
      </td>
      <td>Required</td>
    </tr>
    <tr>
      <td>query</td>
      <td>
        Returns messages matching the specified query. Supports the same
        query format as the Gmail search box. For example, "from:someuser@example.com
        rfc822msgid: is:unread". For more syntax information see "https://support.google.com/mail/answer/7190?hl=en"
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>max-results</td>
      <td>
        Maximum number of results to return. Default is 100. Maximum is 500.
        Can be 1 to 500, inclusive.
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fields</td>
      <td>
        Enables partial responses to be retrieved, separated by commas. For
        more information, see https://developers.google.com/gdata/docs/2.0/basics#PartialResponse.
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>labels-ids</td>
      <td>
        Only returns messages with labels that match all of the specified
        label IDs in a comma separated list.
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>page-token</td>
      <td>
        Page token to retrieve a specific page of results in the list.
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>include-spam-trash</td>
      <td>
        Include messages from SPAM and TRASH in the results. (Default: false)
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>from</td>
      <td>Specify the sender. For example, "john"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>to</td>
      <td>Specify the receiver. For example, "john"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>subject</td>
      <td>Words in the subject line. For example, "alert"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>filename</td>
      <td>
        Attachments with a certain name or file type. For example, "pdf"
        or "report.pdf"
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>in</td>
      <td>
        Messages in any folder, including Spam and Trash. For example: shopping
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>after</td>
      <td>
        Search for messages sent after a certain time period. For example:
        2018/05/06
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>before</td>
      <td>
        Search for messages sent before a certain time period. for example:
        2018/05/09
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>has-attachments</td>
      <td>
        Whether to search for messages sent with attachments (boolean value).
      </td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:200px">
        <strong>Path</strong>
      </th>
      <th style="width:74px">
        <strong>Type</strong>
      </th>
      <th style="width:434px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:200px">Gmail.ID</td>
      <td style="width:74px">string</td>
      <td style="width:434px">Inner ID of the Gmail message.</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.ThreadId</td>
      <td style="width:74px">string</td>
      <td style="width:434px">The thread ID.</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.Format</td>
      <td style="width:74px">string</td>
      <td style="width:434px">MIME type of email.</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.Labels</td>
      <td style="width:74px">string</td>
      <td style="width:434px">Labels of the specific email.</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.To</td>
      <td style="width:74px">string</td>
      <td style="width:434px">Email Address of the receiver.</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.From</td>
      <td style="width:74px">string</td>
      <td style="width:434px">Email Address of the sender.</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.Cc</td>
      <td style="width:74px">string</td>
      <td style="width:434px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.Bcc</td>
      <td style="width:74px">string</td>
      <td style="width:434px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.Subject</td>
      <td style="width:74px">string</td>
      <td style="width:434px">Subject of the specific email.</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.Body</td>
      <td style="width:74px">string</td>
      <td style="width:434px">The content of the email.</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.Attachments</td>
      <td style="width:74px">unknown</td>
      <td style="width:434px">Attachment details. Attachments IDs are separated by ','.</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.Headers</td>
      <td style="width:74px">unknown</td>
      <td style="width:434px">All headers of a specific email (list).</td>
    </tr>
    <tr>
      <td style="width:200px">Gmail.Mailbox</td>
      <td style="width:74px">string</td>
      <td style="width:434px">The email mailbox.</td>
    </tr>
    <tr>
      <td style="width:200px">Email.To</td>
      <td style="width:74px">String</td>
      <td style="width:434px">The recipient of the email.</td>
    </tr>
    <tr>
      <td style="width:200px">Email.From</td>
      <td style="width:74px">String</td>
      <td style="width:434px">The sender of the email.</td>
    </tr>
    <tr>
      <td style="width:200px">Email.CC</td>
      <td style="width:74px">String</td>
      <td style="width:434px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:200px">Email.BCC</td>
      <td style="width:74px">String</td>
      <td style="width:434px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:200px">Email.Format</td>
      <td style="width:74px">String</td>
      <td style="width:434px">The format of the email.</td>
    </tr>
    <tr>
      <td style="width:200px">Email.Body/HTML</td>
      <td style="width:74px">String</td>
      <td style="width:434px">The HTML version of the email.</td>
    </tr>
    <tr>
      <td style="width:200px">Email.Body/Text</td>
      <td style="width:74px">String</td>
      <td style="width:434px">The plain-text version of the email.</td>
    </tr>
    <tr>
      <td style="width:200px">Email.Subject</td>
      <td style="width:74px">String</td>
      <td style="width:434px">The subject of the email.</td>
    </tr>
    <tr>
      <td style="width:200px">Email.Headers</td>
      <td style="width:74px">String</td>
      <td style="width:434px">The headers of the email.</td>
    </tr>
    <tr>
      <td style="width:200px">Email.Attachments.entryID</td>
      <td style="width:74px">Unknown</td>
      <td style="width:434px">Email Attachment IDs. Separated by ','.</td>
    </tr>
    <tr>
      <td style="width:200px">Email.Date</td>
      <td style="width:74px">String</td>
      <td style="width:434px">The date the email was received.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-search user-id=yarden@demistodev.com after=2019/03/20 before=2019/04/01 query=playbook max-results=2
</pre>
<h5>Context Example</h5>
<pre>{
    “Gmail”: {
	"Email": [
        {
            "ID": ,
            "ThreadId": ,
            "Format": "multipart/mixed",
            "Labels": "UNREAD, CATEGORY_PERSONAL, INBOX",
            "To": "example@demisto.com",
            "From": "example@demisto.com",
            "Cc": ,
            "Bcc": ,
            "Subject": “email subject”,
            "Body": "email body",
            "Headers" : [
		{
                   "Name": ,
                   "Value": ,
               },
               {
                   "Name": ,
                   "Value": ,
               }
            ],
            "Attachments": [
                {
                    "Name": ,
                    "ID": ,
                }
            ],
            "Type": "Gmail",
        }
      ]
    }
}
 
</pre>
<h5>Human Readable Output</h5>
<h3>Search in yarden@demistodev.com:</h3>
<p>query: "after:2019/03/20 before:2019/04/01 playbook"</p>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Mailbox</strong>
      </th>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>Subject</strong>
      </th>
      <th>
        <strong>From</strong>
      </th>
      <th>
        <strong>To</strong>
      </th>
      <th>
        <strong>Labels</strong>
      </th>
      <th>
        <strong>Attachment Names</strong>
      </th>
      <th>
        <strong>Format</strong>
      </th>
      <th>
        <strong>Body</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>yarden@demistodev.com</td>
      <td>169d1994d578242b</td>
      <td>special test via playbook (2)</td>
      <td>Avishai Brandeis &lt;avishai@demistodev.onmicrosoft.com&gt;</td>
      <td>"yarden@demistodev.com" &lt;yarden@demistodev.com&gt;</td>
      <td>UNREAD, IMPORTANT, CATEGORY_PERSONAL, INBOX</td>
      <td>attach.txt, test.txt, test2.txt</td>
      <td>multipart/mixed</td>
      <td>this is a test by playbook</td>
    </tr>
    <tr>
      <td>yarden@demistodev.com</td>
      <td>169d199021c5df09</td>
      <td>special test via playbook (1)</td>
      <td>Avishai Brandeis &lt;avishai@demistodev.onmicrosoft.com&gt;</td>
      <td>"yarden@demistodev.com" &lt;yarden@demistodev.com&gt;</td>
      <td>UNREAD, IMPORTANT, CATEGORY_PERSONAL, INBOX</td>
      <td>test.txt</td>
      <td>multipart/mixed</td>
      <td>this is a test by playbook</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_aef2387b-01c9-4638-bdfb-d66d8b0bd3f2">8. Search in all Gmail mailboxes</h3>
<hr>
<p>Searches the Gmail records for all Google users.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-search-all-mailboxes</code>
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
      <td>query</td>
      <td>
        Returns messages matching the specified query. Supports the same
        query format as the Gmail search box. For example, "from:someuser@example.com
        rfc822msgid: is:unread". For more syntax information,see "https://support.google.com/mail/answer/7190?hl=en"
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>max-results</td>
      <td>
        Maximum number of results to return. Default is 100. Maximum is 500.
        Acceptable values are 1 to 500, inclusive.
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fields</td>
      <td>
        Enables partial responses to be retrieved in a comma separated list.
        For more information, see https://developers.google.com/gdata/docs/2.0/basics#PartialResponse.
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>labels-ids</td>
      <td>
        Only returns messages with labels that match all of the specified
        label IDs in a comma separated list.
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>page-token</td>
      <td>
        Page token to retrieve a specific page of results in the list.
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>include-spam-trash</td>
      <td>
        Includes messages from SPAM and TRASH in the results. (Default: false)
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>from</td>
      <td>Specifies the sender. For example, "john"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>to</td>
      <td>Specifies the receiver. For example, "john"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>subject</td>
      <td>Words in the subject line. For example, "alert"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>filename</td>
      <td>
        Attachments with a certain name or file type. For example, "pdf"
        or "report.pdf"
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>in</td>
      <td>
        Messages in any folder, including Spam and Trash. For example, shopping
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>after</td>
      <td>
        Search for messages sent after a certain time period. For example,
        2018/05/06
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>before</td>
      <td>
        Search for messages sent before a certain time period. For example,
        2018/05/09
      </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>has-attachments</td>
      <td>Whether to search for messages sent with attachments.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:203px">
        <strong>Path</strong>
      </th>
      <th style="width:80px">
        <strong>Type</strong>
      </th>
      <th style="width:425px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:203px">Gmail.ID</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Inner ID of the Gmail message.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.ThreadId</td>
      <td style="width:80px">string</td>
      <td style="width:425px">The thread ID.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Format</td>
      <td style="width:80px">string</td>
      <td style="width:425px">MIME type of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Labels</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Labels of a specific email.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.To</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Email Address of the receiver.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.From</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Email Address of the sender.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Cc</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Bcc</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Subject</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Subject of the specific email.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Body</td>
      <td style="width:80px">string</td>
      <td style="width:425px">The content of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Attachments</td>
      <td style="width:80px">unknown</td>
      <td style="width:425px">The attachments of the email. IDs are separated by ','.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Headers</td>
      <td style="width:80px">unknown</td>
      <td style="width:425px">All headers of specific mail (list).</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Mailbox</td>
      <td style="width:80px">string</td>
      <td style="width:425px">The Gmail Mailbox.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.To</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The recipient of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.From</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The sender of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.CC</td>
      <td style="width:80px">String</td>
      <td style="width:425px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:203px">Email.BCC</td>
      <td style="width:80px">String</td>
      <td style="width:425px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Format</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The format of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Body/HTML</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The HTML version of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Body/Text</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The plain-text version of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Subject</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The subject of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Headers</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The headers of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Attachments.entryID</td>
      <td style="width:80px">Unknown</td>
      <td style="width:425px">Email Attachments. IDs are separated by ','.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Date</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The date the email was received.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!gmail-search-all-mailboxes after=2019/04/10 max-results=3 before=2019/04/15 query=test</pre>
<h5>Context Example</h5>
<pre>    “Gmail”: {
	"Email": [
        {
            "ID": ,
            "ThreadId": ,
            "Format": "multipart/mixed",
            "Labels": "UNREAD, CATEGORY_PERSONAL, INBOX",
            "To": "example@demisto.com",
            "From": "example@demisto.com",
            "Cc": ,
            "Bcc": ,
            "Subject": “email subject”,
            "Body": "email body",
            "Headers" : [
		{
                   "Name": ,
                   "Value": ,
               },
               {
                   "Name": ,
                   "Value": ,
               }
            ],
            "Attachments": [
                {
                    "Name": ,
                    "ID": ,
                }
            ],
            "Type": "Gmail",
        }
      ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Search in admin@demistodev.com:</h3>
<p>
  query: "after:2019/04/10 before:2019/04/15 test" **No entries.**
</p>
<h3>Search in art@demistodev.com:</h3>
<p>
  query: "after:2019/04/10 before:2019/04/15 test" **No entries.**
</p>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Mailbox</strong>
      </th>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>Subject</strong>
      </th>
      <th>
        <strong>From</strong>
      </th>
      <th>
        <strong>To</strong>
      </th>
      <th>
        <strong>Labels</strong>
      </th>
      <th>
        <strong>Attachment Names</strong>
      </th>
      <th>
        <strong>Format</strong>
      </th>
      <th>
        <strong>Body</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>yarden@demistodev.com</td>
      <td>16a1d1886b5abaeb</td>
      <td>special test via playbook (2)</td>
      <td>Avishai Brandeis &lt;avishai@demistodev.onmicrosoft.com&gt;</td>
      <td>"yarden@demistodev.com" &lt;yarden@demistodev.com&gt;</td>
      <td>UNREAD, CATEGORY_PERSONAL, INBOX</td>
      <td>attach.txt, test.txt, test2.txt</td>
      <td>multipart/mixed</td>
      <td>this is a test by playbook</td>
    </tr>
    <tr>
      <td>yarden@demistodev.com</td>
      <td>16a1d182a271708c</td>
      <td>special test via playbook (1)</td>
      <td>Avishai Brandeis &lt;avishai@demistodev.onmicrosoft.com&gt;</td>
      <td>"yarden@demistodev.com" &lt;yarden@demistodev.com&gt;</td>
      <td>UNREAD, IMPORTANT, CATEGORY_PERSONAL, INBOX</td>
      <td>test.txt</td>
      <td>multipart/mixed</td>
      <td>this is a test by playbook</td>
    </tr>
    <tr>
      <td>yarden@demistodev.com</td>
      <td>16a1d0bd1701cd1a</td>
      <td>special test via playbook (2)</td>
      <td>Avishai Brandeis &lt;avishai@demistodev.onmicrosoft.com&gt;</td>
      <td>"yarden@demistodev.com" &lt;yarden@demistodev.com&gt;</td>
      <td>UNREAD, CATEGORY_PERSONAL, INBOX</td>
      <td>attach.txt, test.txt, test2.txt</td>
      <td>multipart/mixed</td>
      <td>this is a test by playbook</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3>
  <span style="font-size:15px">9. List all Google users</span>
</h3>
<hr>
<p>Lists all Google users in a domain.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-list-users</code>
</p>
<h5>
  <span style="font-size:15px">Input</span>
</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:74px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:563px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:74px">projection</td>
      <td style="width:563px">
        The subset of fields to fetch for the user. Can be "basic": Do not
        include any custom fields for the user. (default), "custom": Include
        custom fields from schemas requested in customFieldMask, "full":
        Include all fields associated with this user.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:74px">domain</td>
      <td style="width:563px">
        The domain name. Use this field to get fields from only one domain.
        To return all domains for a customer account, use the customer query
        parameter.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:74px">customer</td>
      <td style="width:563px">
        The unique ID for the customers Google account. Default is the value
        specified in the integration configuration. For a multi-domain account,
        to fetch all groups for a customer, use this field instead of domain.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:74px">event</td>
      <td style="width:563px">
        The event on which subscription intended (if subscribing). Can be
        "add", "delete", "makeAdmin", "undelete", or "update".
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:74px">max-results</td>
      <td style="width:563px">
        Maximum number of results to return. Default is 100. Maximum is 500.
        Can be 1 to 500, inclusive.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:74px">custom-field-mask</td>
      <td style="width:563px">
        A comma-separated list of schema names. All fields from these schemas
        are fetched. Must be set when projection=custom.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:74px">query</td>
      <td style="width:563px">
        Query string search. Should be of the form "". Complete documentation
        is at https://developers.google.com/admin-sdk/directory/v1/guides/search-users
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:74px">show-deleted</td>
      <td style="width:563px">
        If true, retrieves the list of deleted users. Default is false.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:74px">sort-order</td>
      <td style="width:563px">How to sort out results. Can be ASCENDING/DESCENDING</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:74px">token</td>
      <td style="width:563px">Token to authorize and authenticate the action.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:74px">view-type-public-domain</td>
      <td style="width:563px">
        Whether to fetch either the administrator or public view of the user.
        Can be admin_view (default), which includes both administrator and
        domain-public fields or "domain_public"(includes fields for the user
        that are publicly visible to other users in the domain).
      </td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:174px">
        <strong>Path</strong>
      </th>
      <th style="width:48px">
        <strong>Type</strong>
      </th>
      <th style="width:486px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:174px">Account.Type</td>
      <td style="width:48px">String</td>
      <td style="width:486px">
        The account type. For example, "AD", "LocalOS", "Google", "AppleID",
        and so on.
      </td>
    </tr>
    <tr>
      <td style="width:174px">Account.ID</td>
      <td style="width:48px">String</td>
      <td style="width:486px">
        The unique ID for the account (integration specific). For AD accounts
        this is the Distinguished Name (DN).
      </td>
    </tr>
    <tr>
      <td style="width:174px">Account.DisplayName</td>
      <td style="width:48px">String</td>
      <td style="width:486px">The display name.</td>
    </tr>
    <tr>
      <td style="width:174px">Account.Gmail.Address</td>
      <td style="width:48px">string</td>
      <td style="width:486px">Email assigned with the current account.</td>
    </tr>
    <tr>
      <td style="width:174px">Account.Email.Adderss</td>
      <td style="width:48px">String</td>
      <td style="width:486px">The email address of the account.</td>
    </tr>
    <tr>
      <td style="width:174px">Account.Groups</td>
      <td style="width:48px">String</td>
      <td style="width:486px">
        Groups to which the account belongs (integration specific). For example,
        for AD these are the groups in which the account is member.
      </td>
    </tr>
    <tr>
      <td style="width:174px">Account.Domain</td>
      <td style="width:48px">String</td>
      <td style="width:486px">The domain of the account.</td>
    </tr>
    <tr>
      <td style="width:174px">Account.Username</td>
      <td style="width:48px">String</td>
      <td style="width:486px">The username of the account.</td>
    </tr>
    <tr>
      <td style="width:174px">Account.OrganizationUnit</td>
      <td style="width:48px">String</td>
      <td style="width:486px">The Organization Unit (OU) of the account.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-list-users query=John show-deleted=False</pre>
<h5>Context Example</h5>
<pre>{
    "Account": [
        {
            "CustomerId": "C02f0zfqw",
            "DisplayName": "John Smith",
            "Domain": "demistodev.com",
            "Email": {
                "Address": "johns@demistodev.com"
            },
            "Gmail": {
                "Address": "johns@demistodev.com"
            },
            "Group": "admin#directory#user",
            "Groups": "admin#directory#user",
            "ID": "105877121188199653770",
            "Type": "Google",
            "UserName": "John",
            "Username": "John",
            "VisibleInDirectory": true
        },
        {
            "CustomerId": "C02f0zfqw",
            "DisplayName": "John Snow",
            "Domain": "demistodev.com",
            "Email": {
                "Address": "user@demistodev.com"
            },
            "Gmail": {
                "Address": "user@demistodev.com"
            },
            "Group": "admin#directory#user",
            "Groups": "admin#directory#user",
            "ID": "117047108909890245378",
            "Type": "Google",
            "UserName": "John",
            "Username": "John",
            "VisibleInDirectory": true
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Users:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>Username</strong>
      </th>
      <th>
        <strong>DisplayName</strong>
      </th>
      <th>
        <strong>Groups</strong>
      </th>
      <th>
        <strong>CustomerId</strong>
      </th>
      <th>
        <strong>Domain</strong>
      </th>
      <th>
        <strong>Email</strong>
      </th>
      <th>
        <strong>VisibleInDirectory</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Google</td>
      <td>105877121188199653770</td>
      <td>John</td>
      <td>John Smith</td>
      <td>admin#directory#user</td>
      <td>C02f0zfqw</td>
      <td>demistodev.com</td>
      <td>Address: johns@demistodev.com</td>
      <td>true</td>
    </tr>
    <tr>
      <td>Google</td>
      <td>117047108909890245378</td>
      <td>John</td>
      <td>John Snow</td>
      <td>admin#directory#user</td>
      <td>C02f0zfqw</td>
      <td>demistodev.com</td>
      <td>Address: user@demistodev.com</td>
      <td>true</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_b3b4908f-7e88-4397-b4e7-b83c9d6f2e7d">10. Revoke a Google user's role</h3>
<hr>
<p>Revokes a role for a specified Google user.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-revoke-user-role</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:100px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:537px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:100px">user-id</td>
      <td style="width:537px">
        The user's email address. The special value me can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:100px">role-assignment-id</td>
      <td style="width:537px">The immutable ID of the role assignment.</td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_84ffd332-3475-4e33-900e-9e9bc2dbb352">11. Create a new user</h3>
<hr>
<p>Creates a new Gmail user.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-create-user</code>
</p>
<h5>Input</h5>
<table style="width:744px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:60px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:577px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:60px">email</td>
      <td style="width:577px">
        The user's primary email address. The primary email address must
        be unique and cannot be an alias of another user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:60px">first-name</td>
      <td style="width:577px">The user's first name.</td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:60px">family-name</td>
      <td style="width:577px">The user's last name.</td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:60px">password</td>
      <td style="width:577px">
        Stores the password for the user account. A password can contain
        any combination of ASCII characters. A minimum of 8 characters is
        required. The maximum length is 100 characters.
      </td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:173px">
        <strong>Path</strong>
      </th>
      <th style="width:49px">
        <strong>Type</strong>
      </th>
      <th style="width:486px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:173px">Account.Type</td>
      <td style="width:49px">String</td>
      <td style="width:486px">
        The account type. For example, "AD", "LocalOS", "Google", "AppleID",
        and so on.
      </td>
    </tr>
    <tr>
      <td style="width:173px">Account.ID</td>
      <td style="width:49px">String</td>
      <td style="width:486px">
        The unique ID for the account (integration specific). For AD accounts
        this is the Distinguished Name (DN).
      </td>
    </tr>
    <tr>
      <td style="width:173px">Account.DisplayName</td>
      <td style="width:49px">string</td>
      <td style="width:486px">The display name.</td>
    </tr>
    <tr>
      <td style="width:173px">Account.Gmail.Address</td>
      <td style="width:49px">string</td>
      <td style="width:486px">Email assigned with the current account.</td>
    </tr>
    <tr>
      <td style="width:173px">Account.Email.Address</td>
      <td style="width:49px">String</td>
      <td style="width:486px">The email address of the account.</td>
    </tr>
    <tr>
      <td style="width:173px">Account.Username</td>
      <td style="width:49px">String</td>
      <td style="width:486px">The username of the account.</td>
    </tr>
    <tr>
      <td style="width:173px">Account.Groups</td>
      <td style="width:49px">String</td>
      <td style="width:486px">
        Groups to which the account belongs (integration specific). For example,
        for AD these are groups in which the account is a member.
      </td>
    </tr>
    <tr>
      <td style="width:173px">Account.Domain</td>
      <td style="width:49px">String</td>
      <td style="width:486px">The domain of the account.</td>
    </tr>
    <tr>
      <td style="width:173px">Account.OrganizationUnit</td>
      <td style="width:49px">String</td>
      <td style="width:486px">The Organization Unit (OU) of the account.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!gmail-create-user email=user@demistodev.com first-name=John family-name=Snow password=WinterIsComing</pre>
<h5>Context Example</h5>
<pre>{
    "Account": [
        {
            "CustomerId": "C02f0zfqw",
            "DisplayName": "John Snow",
            "Domain": "demistodev.com",
            "Email": {
                "Address": "user@demistodev.com"
            },
            "Gmail": {
                "Address": "user@demistodev.com"
            },
            "Group": "admin#directory#user",
            "Groups": "admin#directory#user",
            "ID": "117047108909890245378",
            "Type": "Google",
            "UserName": "John",
            "Username": "John",
            "VisibleInDirectory": null
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>New User:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>Username</strong>
      </th>
      <th>
        <strong>DisplayName</strong>
      </th>
      <th>
        <strong>Groups</strong>
      </th>
      <th>
        <strong>CustomerId</strong>
      </th>
      <th>
        <strong>Domain</strong>
      </th>
      <th>
        <strong>Email</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Google</td>
      <td>117047108909890245378</td>
      <td>John</td>
      <td>John Snow</td>
      <td>admin#directory#user</td>
      <td>C02f0zfqw</td>
      <td>demistodev.com</td>
      <td>Address: user@demistodev.com</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_01733786-6f8e-42ed-a8e1-a10b52f324b4">12. Delete mail from a mailbox</h3>
<hr>
<p>Deletes an email in the user's mailbox.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-delete-mail</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:97px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:540px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:97px">user-id</td>
      <td style="width:540px">
        The user's email address. The special value me can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:97px">message-id</td>
      <td style="width:540px">The ID of the message to delete.</td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:97px">permanent</td>
      <td style="width:540px">
        Whether to delete the email permanently or move it to trash (default).
      </td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-delete-mail user-id=admin@demistodev.com message-id=16d4316a25a332e4
</pre>
<h5>Human Readable Output</h5>
<p>Email has been successfully moved to trash.</p>
<h3 id="h_7c28d177-2aa4-4803-be8e-6d38f1abe8f7">13. Get message in an email thread</h3>
<hr>
<p>Returns all messages in a email thread.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-get-thread</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:75px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:562px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:75px">user-id</td>
      <td style="width:562px">
        The user's email address. The special value me can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:75px">thread-id</td>
      <td style="width:562px">The ID of the thread to retrieve.</td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:75px">format</td>
      <td style="width:562px">
        The format in which to return the message. Can be: "full": Returns
        the full email message data with body content parsed in the payload
        field; the raw field is not used. (default) / "metadata": Returns
        only email message ID, labels, and email headers / "minimal": Returns
        only email message ID and labels; does not return the email headers,
        body, or payload / "raw": Returns the full email message data with
        body content in the raw field as a base64url encoded string; the
        payload field is not used
      </td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:203px">
        <strong>Path</strong>
      </th>
      <th style="width:80px">
        <strong>Type</strong>
      </th>
      <th style="width:425px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:203px">Gmail.ID</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Inner ID of the Gmail message.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.ThreadId</td>
      <td style="width:80px">string</td>
      <td style="width:425px">The thread ID.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Format</td>
      <td style="width:80px">string</td>
      <td style="width:425px">MIME type of email.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Labels</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Labels of the specific email.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.To</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Email Address of the receiver.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.From</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Email Address of the sender.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Cc</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Bcc</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Subject</td>
      <td style="width:80px">string</td>
      <td style="width:425px">Subject of a specific email.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Body</td>
      <td style="width:80px">string</td>
      <td style="width:425px">The content of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Attachments</td>
      <td style="width:80px">unknown</td>
      <td style="width:425px">The attachments of the email. IDs are separated by ','.</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Headers</td>
      <td style="width:80px">unknown</td>
      <td style="width:425px">All headers of the specific email (list).</td>
    </tr>
    <tr>
      <td style="width:203px">Gmail.Mailbox</td>
      <td style="width:80px">string</td>
      <td style="width:425px">The Gmail Mailbox.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.To</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The recipient of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.From</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The sender of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.CC</td>
      <td style="width:80px">String</td>
      <td style="width:425px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:203px">Email.BCC</td>
      <td style="width:80px">String</td>
      <td style="width:425px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Format</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The format of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Body/HTML</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The HTML version of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Body/Text</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The plain-text version of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Subject</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The subject of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Headers</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The headers of the email.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Attachments.entryID</td>
      <td style="width:80px">Unknown</td>
      <td style="width:425px">Email Attachments. IDs are separated by ','.</td>
    </tr>
    <tr>
      <td style="width:203px">Email.Date</td>
      <td style="width:80px">String</td>
      <td style="width:425px">The date the email was received.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-get-thread user-id=admin@demistodev.com thread-id=16d4316a25a332e4</pre>
<h5>Context Example</h5>
<pre>{
    "Email": [
        {
            "Attachment Names": "puppy.png",
            "Attachments": [
                {
                    "ID": "<id>",
                    "Name": "puppy.png"
                }
            ],
            "BCC": "",
            "Body/HTML": "",
            "Body/Text": "",
            "CC": "",
            "Date": "Tue, 17 Sep 2019 23:36:59 -0700",
            "Format": "multipart/mixed",
            "From": "admin@demistodev.com",
            "Headers": [
                {
                    "Name": "Received",
                    "Value": "from 1041831412594 named unknown by gmailapi.google.com with HTTPREST; Tue, 17 Sep 2019 23:36:59 -0700"
                },
                {
                    "Name": "Content-Type",
                    "Value": "multipart/mixed; boundary=\"===============3751607758919896682==\""
                },
                {
                    "Name": "MIME-Version",
                    "Value": "1.0"
                },
                {
                    "Name": "to",
                    "Value": "admin@demistodev.com"
                },
                {
                    "Name": "cc",
                    "Value": ""
                },
                {
                    "Name": "bcc",
                    "Value": ""
                },
                {
                    "Name": "from",
                    "Value": "admin@demistodev.com"
                },
                {
                    "Name": "subject",
                    "Value": "attachment"
                },
                {
                    "Name": "reply-to",
                    "Value": ""
                },
                {
                    "Name": "Date",
                    "Value": "Tue, 17 Sep 2019 23:36:59 -0700"
                },
                {
                    "Name": "Message-Id",
                    "Value": "&lt;<value>&gt;"
                }
            ],
            "ID": "16d4316a25a332e4",
            "RawData": null,
            "Subject": "attachment",
            "To": "admin@demistodev.com"
        }
    ],
    "Gmail": [
        {
            "Attachment Names": "puppy.png",
            "Attachments": [
                {
                    "ID": "<id>",
                    "Name": "puppy.png"
                }
            ],
            "Bcc": "",
            "Body": "",
            "Cc": "",
            "Date": "Tue, 17 Sep 2019 23:36:59 -0700",
            "Format": "multipart/mixed",
            "From": "admin@demistodev.com",
            "Headers": [
                {
                    "Name": "Received",
                    "Value": "from 1041831412594 named unknown by gmailapi.google.com with HTTPREST; Tue, 17 Sep 2019 23:36:59 -0700"
                },
                {
                    "Name": "Content-Type",
                    "Value": "multipart/mixed; boundary=\"===============3751607758919896682==\""
                },
                {
                    "Name": "MIME-Version",
                    "Value": "1.0"
                },
                {
                    "Name": "to",
                    "Value": "admin@demistodev.com"
                },
                {
                    "Name": "cc",
                    "Value": ""
                },
                {
                    "Name": "bcc",
                    "Value": ""
                },
                {
                    "Name": "from",
                    "Value": "admin@demistodev.com"
                },
                {
                    "Name": "subject",
                    "Value": "attachment"
                },
                {
                    "Name": "reply-to",
                    "Value": ""
                },
                {
                    "Name": "Date",
                    "Value": "Tue, 17 Sep 2019 23:36:59 -0700"
                },
                {
                    "Name": "Message-Id",
                    "Value": "&lt;<value>&gt;"
                }
            ],
            "Html": "",
            "ID": "16d4316a25a332e4",
            "Labels": "UNREAD, SENT, INBOX",
            "Mailbox": "admin@demistodev.com",
            "RawData": null,
            "Subject": "attachment",
            "ThreadId": "16d4316a25a332e4",
            "To": "admin@demistodev.com",
            "Type": "Gmail"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Emails of Thread:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Mailbox</strong>
      </th>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>Subject</strong>
      </th>
      <th>
        <strong>From</strong>
      </th>
      <th>
        <strong>To</strong>
      </th>
      <th>
        <strong>Labels</strong>
      </th>
      <th>
        <strong>Attachment Names</strong>
      </th>
      <th>
        <strong>Format</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>admin@demistodev.com</td>
      <td>16d4316a25a332e4</td>
      <td>attachment</td>
      <td>admin@demistodev.com</td>
      <td>admin@demistodev.com</td>
      <td>UNREAD, SENT, INBOX</td>
      <td>puppy.png</td>
      <td>multipart/mixed</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_ab82adf8-181e-4dfc-91ab-7386f0cadbc2">14. Moves mail to a different folder</h3>
<hr>
<p>Moves an email to a different folder.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-move-mail</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:95px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:542px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:95px">user-id</td>
      <td style="width:542px">
        The user's email address. The special value me can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:95px">message-id</td>
      <td style="width:542px">The ID of the message to retrieve.</td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:95px">add-labels</td>
      <td style="width:542px">Comma-separated list of labels to add to the email.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:95px">remove-labels</td>
      <td style="width:542px">Comma separated list of labels to remove from the email.</td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:201px">
        <strong>Path</strong>
      </th>
      <th style="width:82px">
        <strong>Type</strong>
      </th>
      <th style="width:425px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:201px">Gmail.ID</td>
      <td style="width:82px">string</td>
      <td style="width:425px">Inner ID of the Gmail message.</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.ThreadId</td>
      <td style="width:82px">string</td>
      <td style="width:425px">The thread ID.</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.Format</td>
      <td style="width:82px">string</td>
      <td style="width:425px">MIME type of email.</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.Labels</td>
      <td style="width:82px">string</td>
      <td style="width:425px">Labels of the specific email.</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.To</td>
      <td style="width:82px">string</td>
      <td style="width:425px">Gmail address of the receiver.</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.From</td>
      <td style="width:82px">string</td>
      <td style="width:425px">Gmail address of the sender.</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.Cc</td>
      <td style="width:82px">string</td>
      <td style="width:425px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.Bcc</td>
      <td style="width:82px">string</td>
      <td style="width:425px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.Subject</td>
      <td style="width:82px">string</td>
      <td style="width:425px">Subject of the specific email.</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.Body</td>
      <td style="width:82px">string</td>
      <td style="width:425px">The content of the email.</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.Attachments</td>
      <td style="width:82px">unknown</td>
      <td style="width:425px">The attachments of the email. IDs are separated by ','.</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.Headers</td>
      <td style="width:82px">unknown</td>
      <td style="width:425px">All headers of the specific email (list).</td>
    </tr>
    <tr>
      <td style="width:201px">Gmail.Mailbox</td>
      <td style="width:82px">string</td>
      <td style="width:425px">The Gmail mailbox.</td>
    </tr>
    <tr>
      <td style="width:201px">Email.To</td>
      <td style="width:82px">String</td>
      <td style="width:425px">The recipient of the email.</td>
    </tr>
    <tr>
      <td style="width:201px">Email.From</td>
      <td style="width:82px">String</td>
      <td style="width:425px">The sender of the email.</td>
    </tr>
    <tr>
      <td style="width:201px">Email.CC</td>
      <td style="width:82px">Unknown</td>
      <td style="width:425px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:201px">Email.BCC</td>
      <td style="width:82px">Unknown</td>
      <td style="width:425px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:201px">Email.Format</td>
      <td style="width:82px">String</td>
      <td style="width:425px">The format of the email.</td>
    </tr>
    <tr>
      <td style="width:201px">Email.Body/HTML</td>
      <td style="width:82px">String</td>
      <td style="width:425px">The HTML version of the email.</td>
    </tr>
    <tr>
      <td style="width:201px">Email.Body/Text</td>
      <td style="width:82px">String</td>
      <td style="width:425px">The plain-text version of the email.</td>
    </tr>
    <tr>
      <td style="width:201px">Email.Subject</td>
      <td style="width:82px">String</td>
      <td style="width:425px">The subject of the email.</td>
    </tr>
    <tr>
      <td style="width:201px">Email.Headers</td>
      <td style="width:82px">String</td>
      <td style="width:425px">The headers of the email.</td>
    </tr>
    <tr>
      <td style="width:201px">Email.Attachments.entryID</td>
      <td style="width:82px">Unknown</td>
      <td style="width:425px">Email attachments. IDs are separated by ','.</td>
    </tr>
    <tr>
      <td style="width:201px">Email.Date</td>
      <td style="width:82px">String</td>
      <td style="width:425px">The date the email was received.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-move-mail user-id=admin@demistodev.com message-id=16d43097d9664008 add-labels=INBOX remove-labels=TRASH
</pre>
<h5>Context Example</h5>
<pre>{
    "Email": [
        {
            "Attachments": {
                "entryID": ""
            },
            "BCC": [],
            "Body/HTML": null,
            "Body/Text": "",
            "CC": [],
            "Date": "",
            "Format": "",
            "From": null,
            "Headers": [],
            "ID": "16d43097d9664008",
            "RawData": null,
            "Subject": null,
            "To": null
        }
    ],
    "Gmail": [
        {
            "Attachments": "",
            "Bcc": [],
            "Body": "",
            "Cc": [],
            "Date": "",
            "Format": "",
            "From": null,
            "Headers": [],
            "Html": null,
            "ID": "16d43097d9664008",
            "Labels": "UNREAD, SENT, INBOX",
            "Mailbox": "admin@demistodev.com",
            "RawData": null,
            "Subject": null,
            "ThreadId": "16d43097d9664008",
            "To": null,
            "Type": "Gmail"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Email:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Mailbox</strong>
      </th>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>Labels</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>admin@demistodev.com</td>
      <td>16d43097d9664008</td>
      <td>UNREAD, SENT, INBOX</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_5bbef95c-6bf1-44ea-9b10-31826260c64d">15. Move a mail to a different mailbox</h3>
<hr>
<p>Moves an email to a different mailbox.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-move-mail-to-mailbox</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:87px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:550px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:87px">src-user-id</td>
      <td style="width:550px">
        The source user's email address. The special value me can be used
        to indicate the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:87px">message-id</td>
      <td style="width:550px">The ID of the message to retrieve.</td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:87px">dst-user-id</td>
      <td style="width:550px">
        The destination user's email address. The me special value can be
        used to indicate the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:204px">
        <strong>Path</strong>
      </th>
      <th style="width:79px">
        <strong>Type</strong>
      </th>
      <th style="width:425px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:204px">Gmail.ID</td>
      <td style="width:79px">string</td>
      <td style="width:425px">Inner ID of the Gmail message.</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.ThreadId</td>
      <td style="width:79px">string</td>
      <td style="width:425px">The thread ID.</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.Format</td>
      <td style="width:79px">string</td>
      <td style="width:425px">MIME type of email.</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.Labels</td>
      <td style="width:79px">string</td>
      <td style="width:425px">Labels of the specific email.</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.To</td>
      <td style="width:79px">string</td>
      <td style="width:425px">Gmail address of the receiver.</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.From</td>
      <td style="width:79px">string</td>
      <td style="width:425px">Gmail address of the sender.</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.Cc</td>
      <td style="width:79px">string</td>
      <td style="width:425px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.Bcc</td>
      <td style="width:79px">string</td>
      <td style="width:425px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.Subject</td>
      <td style="width:79px">string</td>
      <td style="width:425px">Subject of the specific email.</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.Body</td>
      <td style="width:79px">string</td>
      <td style="width:425px">The content of the email.</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.Attachments</td>
      <td style="width:79px">unknown</td>
      <td style="width:425px">The attachments of the email. IDs are separated by ','.</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.Headers</td>
      <td style="width:79px">unknown</td>
      <td style="width:425px">All headers of specific the email (list).</td>
    </tr>
    <tr>
      <td style="width:204px">Gmail.Mailbox</td>
      <td style="width:79px">string</td>
      <td style="width:425px">The Gmail mailbox.</td>
    </tr>
    <tr>
      <td style="width:204px">Email.To</td>
      <td style="width:79px">String</td>
      <td style="width:425px">The recipient of the email.</td>
    </tr>
    <tr>
      <td style="width:204px">Email.From</td>
      <td style="width:79px">String</td>
      <td style="width:425px">The sender of the email.</td>
    </tr>
    <tr>
      <td style="width:204px">Email.CC</td>
      <td style="width:79px">String</td>
      <td style="width:425px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:204px">Email.BCC</td>
      <td style="width:79px">String</td>
      <td style="width:425px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:204px">Email.Format</td>
      <td style="width:79px">String</td>
      <td style="width:425px">The format of the email.</td>
    </tr>
    <tr>
      <td style="width:204px">Email.Body/HTML</td>
      <td style="width:79px">String</td>
      <td style="width:425px">The HTML version of the email.</td>
    </tr>
    <tr>
      <td style="width:204px">Email.Body/Text</td>
      <td style="width:79px">String</td>
      <td style="width:425px">The plain-text version of the email.</td>
    </tr>
    <tr>
      <td style="width:204px">Email.Subject</td>
      <td style="width:79px">String</td>
      <td style="width:425px">The subject of the email.</td>
    </tr>
    <tr>
      <td style="width:204px">Email.Headers</td>
      <td style="width:79px">String</td>
      <td style="width:425px">The headers of the email.</td>
    </tr>
    <tr>
      <td style="width:204px">Email.Attachments.entryID</td>
      <td style="width:79px">Unknown</td>
      <td style="width:425px">Emails attachments. IDs are separated by ','.</td>
    </tr>
    <tr>
      <td style="width:204px">Email.Date</td>
      <td style="width:79px">String</td>
      <td style="width:425px">The date the email was received.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-move-mail-to-mailbox src-user-id=admin@demistodev.com message-id=16d4316a25a332e4 dst-user-id=test@demistodev.com</pre>
<p>&nbsp;</p>
<h3 id="h_21d165fc-a05a-4d3a-9f1a-f1b1d28ae064">16. Add a rule to delete an email</h3>
<hr>
<p>Adds a rule for email deletion by address.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-add-delete-filter</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:97px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:540px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:97px">user-id</td>
      <td style="width:540px">
        The user's email address. The me special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:97px">email-address</td>
      <td style="width:540px">Email address in which to block messages.</td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-add-delete-filter user-id=admin@demistodev.com email-address=test@demistodev.com
</pre>
<h3 id="h_acd7c5ed-5c46-4cb3-ac99-99ec391b18ce">17. Add a new filter</h3>
<hr>
<p>Adds a new filter to the email.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-add-filter</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:82px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:555px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:82px">user-id</td>
      <td style="width:555px">
        The user's email address. The me special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:82px">from</td>
      <td style="width:555px">The sender's display name or email address.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:82px">to</td>
      <td style="width:555px">
        The recipient's display name or email address. Includes recipients
        in the "to", "cc", and "bcc" header fields. You can use the local
        part of the email address. For example, "example" and "example@"
        both match "example@gmail.com". This field is case-insensitive.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:82px">subject</td>
      <td style="width:555px">The email subject.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:82px">query</td>
      <td style="width:555px">
        Returns messages matching the specified query. Supports the same
        query format as the Gmail search box. For example, "from:someuser@example.com
        is:unread".
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:82px">has-attachments</td>
      <td style="width:555px">Whether the message has any attachments.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:82px">size</td>
      <td style="width:555px">
        The size of the entire RFC822 message in bytes, including all headers
        and attachments.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:82px">add-labels</td>
      <td style="width:555px">Comma-separated list of labels to add to the message.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:82px">remove-labels</td>
      <td style="width:555px">Comma-separated list of labels to remove from the message.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:82px">forward</td>
      <td style="width:555px">
        Email address that the message is to be forwarded. The email needs
        to be configured as a forwarding address, see https://support.google.com/mail/answer/10957?hl=en#null.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:82px">size-comparison</td>
      <td style="width:555px">The message size in bytes compared to the size field.</td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:231px">
        <strong>Path</strong>
      </th>
      <th style="width:127px">
        <strong>Type</strong>
      </th>
      <th style="width:350px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:231px">GmailFilter.ID</td>
      <td style="width:127px">string</td>
      <td style="width:350px">Filter ID.</td>
    </tr>
    <tr>
      <td style="width:231px">GmailFilter.Mailbox</td>
      <td style="width:127px">string</td>
      <td style="width:350px">Mailbox containing the filter.</td>
    </tr>
    <tr>
      <td style="width:231px">GmailFilter.Criteria</td>
      <td style="width:127px">Unknown</td>
      <td style="width:350px">Filter Criteria.</td>
    </tr>
    <tr>
      <td style="width:231px">GmailFilter.Action</td>
      <td style="width:127px">Unknown</td>
      <td style="width:350px">Filter Action.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-add-filter user-id=admin@demistodev.com has-attachments=true forward=test@demistodev.com subject=phishing</pre>
<h3 id="h_a5e4ed4e-29ec-4c67-929e-3941efae29e7">18. Get a list of filters in a mailbox</h3>
<hr>
<p>List all filters in a user's mailbox.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-list-filters</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:101px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:536px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:101px">user-id</td>
      <td style="width:536px">
        User's email address. The "me" special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:101px">limit</td>
      <td style="width:536px">Limit of the results list. Default is 100.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:101px">address</td>
      <td style="width:536px">List filters associated with the email address.</td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:231px">
        <strong>Path</strong>
      </th>
      <th style="width:127px">
        <strong>Type</strong>
      </th>
      <th style="width:350px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:231px">GmailFilter.ID</td>
      <td style="width:127px">string</td>
      <td style="width:350px">Filter ID.</td>
    </tr>
    <tr>
      <td style="width:231px">GmailFilter.Mailbox</td>
      <td style="width:127px">string</td>
      <td style="width:350px">Mailbox containing the filter.</td>
    </tr>
    <tr>
      <td style="width:231px">GmailFilter.Criteria</td>
      <td style="width:127px">Unknown</td>
      <td style="width:350px">Filter Criteria.</td>
    </tr>
    <tr>
      <td style="width:231px">GmailFilter.Action</td>
      <td style="width:127px">Unknown</td>
      <td style="width:350px">Filter Action.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-list-filters user-id=me</pre>
<h5>Context Example</h5>
<pre>{
    "GmailFilter": [
        {
            "Action": {
                "addLabelIds": [
                    "TRASH"
                ]
            },
            "Criteria": {
                "from": "<mail>"
            },
            "ID": "<id>,
            "Mailbox": "admin@demistodev.com"
        },
        {
            "Action": {
                "addLabelIds": [
                    "TRASH"
                ]
            },
            "Criteria": {
                "from": "test@demistodev.com"
            },
            "ID": "<id>",
            "Mailbox": "admin@demistodev.com"
        },
        {
            "Action": {
                "forward": "test@demistodev.com"
            },
            "Criteria": {
                "hasAttachment": true,
                "subject": "phishing"
            },
            "ID": "<id>,
            "Mailbox": "admin@demistodev.com"
        },
        {
            "Action": {
                "addLabelIds": [
                    "TRASH"
                ]
            },
            "Criteria": {
                "from": "JohnS1555841687807@demistodev.com"
            },
            "ID": "<id>,
            "Mailbox": "admin@demistodev.com"
        },
        {
            "Action": {
                "addLabelIds": [
                    "CATEGORY_SOCIAL"
                ]
            },
            "Criteria": {
                "from": "<mail>"
            },
            "ID": "<id>",
            "Mailbox": "admin@demistodev.com"
        },
        {
            "Action": {
                "addLabelIds": [
                    "TRASH"
                ]
            },
            "Criteria": {
                "from": "<mail>"
            },
            "ID": "<id>,
            "Mailbox": "admin@demistodev.com"
        },
        {
            "Action": {
                "removeLabelIds": [
                    "INBOX"
                ]
            },
            "Criteria": {
                "to": "<mail>"
            },
            "ID": "<id>",
            "Mailbox": "admin@demistodev.com"
        },
        {
            "Action": {
                "addLabelIds": [
                    "TRASH"
                ]
            },
            "Criteria": {
                "from": "<mail>"
            },
            "ID": "<id>,
            "Mailbox": "admin@demistodev.com"
        },
        {
            "Action": {
                "addLabelIds": [
                    "TRASH"
                ]
            },
            "Criteria": {
                "from": "JohnS1555840057376@demistodev.com"
            },
            "ID": "<id>",
            "Mailbox": "admin@demistodev.com"
        },
        {
            "Action": {
                "addLabelIds": [
                    "TRASH"
                ]
            },
            "Criteria": {
                "from": "JohnS1555841545018@demistodev.com"
            },
            "ID": "<id>",
            "Mailbox": "admin@demistodev.com"
        },
        {
            "Action": {
                "addLabelIds": [
                    "TRASH"
                ]
            },
            "Criteria": {
                "from": "JohnS1555840196890@demistodev.com"
            },
            "ID": "<id>,
            "Mailbox": "admin@demistodev.com"
        },
        {
            "Action": {
                "addLabelIds": [
                    "TRASH"
                ]
            },
            "Criteria": {
                "from": "JohnS1555841616384@demistodev.com"
            },
            "ID": "<id>",
            "Mailbox": "admin@demistodev.com"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Filters:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>Criteria</strong>
      </th>
      <th>
        <strong>Action</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><id></td>
      <td>from: <mail></td>
      <td>addLabelIds: TRASH</td>
    </tr>
    <tr>
      <td><id></td>
      <td>from: test@demistodev.com</td>
      <td>addLabelIds: TRASH</td>
    </tr>
    <tr>
      <td><id></td>
      <td>
        hasAttachment: true<br>
        subject: phishing
      </td>
      <td>forward: test@demistodev.com</td>
    </tr>
    <tr>
      <td><id></td>
      <td>from: JohnS1555841687807@demistodev.com</td>
      <td>addLabelIds: TRASH</td>
    </tr>
    <tr>
      <td><id></td>
      <td>from: <mail></td>
      <td>addLabelIds: CATEGORY_SOCIAL</td>
    </tr>
    <tr>
      <td><id></td>
      <td>from: <mail></td>
      <td>addLabelIds: TRASH</td>
    </tr>
    <tr>
      <td><id></td>
      <td>to: <mail></td>
      <td>removeLabelIds: INBOX</td>
    </tr>
    <tr>
      <td><id></td>
      <td>from: <mail></td>
      <td>addLabelIds: TRASH</td>
    </tr>
    <tr>
      <td><id></td>
      <td>from: JohnS1555840057376@demistodev.com</td>
      <td>addLabelIds: TRASH</td>
    </tr>
    <tr>
      <td><id></td>
      <td>from: JohnS1555841545018@demistodev.com</td>
      <td>addLabelIds: TRASH</td>
    </tr>
    <tr>
      <td><id></td>
      <td>from: JohnS1555840196890@demistodev.com</td>
      <td>addLabelIds: TRASH</td>
    </tr>
    <tr>
      <td><id></td>
      <td>from: JohnS1555841616384@demistodev.com</td>
      <td>addLabelIds: TRASH</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_32f83831-3fea-4b22-a6a8-28a7e75bc38c">19. Remove a filter from a mailbox.</h3>
<hr>
<p>Removes a Filter from a user's mailbox.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-remove-filter</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:100px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:537px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:100px">user-id</td>
      <td style="width:537px">
        User's email address. The "me" special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:100px">filter_ids</td>
      <td style="width:537px">
        Comma separated list of filter IDs (can be retrieve using `gmail-list-filters`
        command)
      </td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-remove-filter user-id=admin@demistodev.com filter_ids=<id>
</pre>
<h5>Human Readable Output</h5>
<h3 id="h_7d54beb9-bff7-4e22-9ebf-56a921aeb368">20. Move a mail to a different mailbox</h3>
<hr>
<p>Moves a mail to a different mailbox.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-move-mail-to-mailbox</code>
</p>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <td style="width:199px">
        <strong>Argument</strong>
      </td>
      <td style="width:522px">
        <p>
          <strong>Description</strong>
        </p>
      </td>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:199px">
        <p>src-user-id</p>
      </td>
      <td style="width:522px">
        <p>
          The source user's email address. The special value
          <em><strong>me&nbsp;</strong></em>can be used to indicate the
          authenticated user.
        </p>
      </td>
    </tr>
    <tr>
      <td style="width:199px">
        <p>message-id</p>
      </td>
      <td style="width:522px">
        <p>The ID of the message to move.</p>
      </td>
    </tr>
    <tr>
      <td style="width:199px">
        <p>dst-user-id</p>
      </td>
      <td style="width:522px">
        <p>
          The destination user's email address. The special value
          <em><strong>me</strong></em> can be used to indicate the authenticated
          user.
        </p>
      </td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context example</h5>
<pre>{
    “Gmail”: {
	"Email": [
        {
            "ID": ,
            "ThreadId": ,
            "Format": "multipart/mixed",
            "Labels": "UNREAD, CATEGORY_PERSONAL, INBOX",
            "To": "example@demisto.com",
            "From": "example@demisto.com",
            "Cc": ,
            "Bcc": ,
            "Subject": “email subject”,
            "Body": "email body",
            "Headers" : [
		{
                   "Name": ,
                   "Value": ,
               },
               {
                   "Name": ,
                   "Value": ,
               }
            ],
            "Attachments": [
                {
                    "Name": ,
                    "ID": ,
                }
            ],
            "Type": "Gmail",
        }
      ]
    }
}
</pre>
<h3 id="h_ac2b8475-5561-47e5-8b35-f19e9003aed2">21. Hide a user's information&nbsp;</h3>
<hr>
<p>
  Hide a user's contact information, such as email addresses, profile information,
  etc, in the Global Directory.
</p>
<h5>Base Command</h5>
<p>
  <code>gmail-hide-user-in-directory</code>
</p>
<h5>Input</h5>
<table style="width:746px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:61px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:576px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:61px">user-id</td>
      <td style="width:576px">
        The user's email address. The "me" special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:61px">visible-globally</td>
      <td style="width:576px">
        Whether to hide the user's visibility in the Global Directory. Can
        be False to hide the user, True to show the user in the directory
        (default).
      </td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:175px">
        <strong>Path</strong>
      </th>
      <th style="width:77px">
        <strong>Type</strong>
      </th>
      <th style="width:456px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:175px">Account.Type</td>
      <td style="width:77px">String</td>
      <td style="width:456px">
        The account type. For example, "AD", "LocalOS", "Google", "AppleID",
        and so on.
      </td>
    </tr>
    <tr>
      <td style="width:175px">Account.ID</td>
      <td style="width:77px">String</td>
      <td style="width:456px">
        The unique ID for the account (integration specific). For AD accounts
        this is the Distinguished Name (DN).
      </td>
    </tr>
    <tr>
      <td style="width:175px">Account.DisplayName</td>
      <td style="width:77px">String</td>
      <td style="width:456px">The display name.</td>
    </tr>
    <tr>
      <td style="width:175px">Account.Email.Address</td>
      <td style="width:77px">String</td>
      <td style="width:456px">The email address of the account.</td>
    </tr>
    <tr>
      <td style="width:175px">Account.Gmail.Address</td>
      <td style="width:77px">Unknown</td>
      <td style="width:456px">Email assigned with current account.</td>
    </tr>
    <tr>
      <td style="width:175px">Account.Domain</td>
      <td style="width:77px">String</td>
      <td style="width:456px">The domain of the account.</td>
    </tr>
    <tr>
      <td style="width:175px">Account.Username</td>
      <td style="width:77px">String</td>
      <td style="width:456px">The username of the account.</td>
    </tr>
    <tr>
      <td style="width:175px">Account.OrganizationUnit</td>
      <td style="width:77px">String</td>
      <td style="width:456px">The Organization Unit (OU) of the account.</td>
    </tr>
    <tr>
      <td style="width:175px">Account.VisibleInDirectory</td>
      <td style="width:77px">Boolean</td>
      <td style="width:456px">Whether the account is visible in the Global Directory.</td>
    </tr>
    <tr>
      <td style="width:175px">Account.Groups</td>
      <td style="width:77px">String</td>
      <td style="width:456px">
        Groups in which the account belongs (integration specific). For example,
        for AD these are groups of which the account is member.
      </td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-hide-user-in-directory user-id=user@demistodev.com visible-globally=false
</pre>
<h5>Context Example</h5>
<pre>{
    "Account": [
        {
            "CustomerId": "C02f0zfqw",
            "DisplayName": "John Snow",
            "Domain": "demistodev.com",
            "Email": {
                "Address": "user@demistodev.com"
            },
            "Gmail": {
                "Address": "user@demistodev.com"
            },
            "Group": "admin#directory#user",
            "Groups": "admin#directory#user",
            "ID": "117047108909890245378",
            "Type": "Google",
            "UserName": "John",
            "Username": "John",
            "VisibleInDirectory": false
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>User user@demistodev.com:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>Username</strong>
      </th>
      <th>
        <strong>DisplayName</strong>
      </th>
      <th>
        <strong>Groups</strong>
      </th>
      <th>
        <strong>CustomerId</strong>
      </th>
      <th>
        <strong>Domain</strong>
      </th>
      <th>
        <strong>Email</strong>
      </th>
      <th>
        <strong>VisibleInDirectory</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Google</td>
      <td>117047108909890245378</td>
      <td>John</td>
      <td>John Snow</td>
      <td>admin#directory#user</td>
      <td>C02f0zfqw</td>
      <td>demistodev.com</td>
      <td>Address: user@demistodev.com</td>
      <td>false</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_03d832cf-9cea-4726-b6df-9c1ee9ae86fa">22. Set a password</h3>
<hr>
<p>Sets the password for the user.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-set-password</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:95px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:542px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:95px">user-id</td>
      <td style="width:542px">
        The user's email address. The special value me can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:95px">password</td>
      <td style="width:542px">
        String formatted password for the user. Depends on the Password Policy
        of the Organization
      </td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-set-password user-id=user@demistodev.com password=new_password1!</pre>
<h5>Human Readable Output</h5>
<p>User user@demistodev.com password has been set.</p>
<h3 id="h_7e249b6b-675e-4a16-ae4b-1c96df0cae90">23. Get an auto reply message for the user</h3>
<hr>
<p>Returns the auto-reply message for the user's account.</p>
<h5>Base Command</h5>
<p>
  <code>gmail-get-autoreply</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:96px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:541px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:96px">user-id</td>
      <td style="width:541px">
        The user's email address. The special value me can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:295px">
        <strong>Path</strong>
      </th>
      <th style="width:67px">
        <strong>Type</strong>
      </th>
      <th style="width:346px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:295px">Account.Gmail.AutoReply.EnableAutoReply</td>
      <td style="width:67px">Boolean</td>
      <td style="width:346px">
        Flag that controls whether Gmail automatically replies to messages.
      </td>
    </tr>
    <tr>
      <td style="width:295px">Account.Gmail.AutoReply.ResponseBody</td>
      <td style="width:67px">String</td>
      <td style="width:346px">Response body in plain text format.</td>
    </tr>
    <tr>
      <td style="width:295px">Account.Gmail.AutoReply.ResponseSubject</td>
      <td style="width:67px">String</td>
      <td style="width:346px">
        Optional text to add to the subject line in vacation responses. To
        enable auto-replies, the response subject or the response body must
        not be empty.
      </td>
    </tr>
    <tr>
      <td style="width:295px">Account.Gmail.AutoReply.RestrictToContact</td>
      <td style="width:67px">String</td>
      <td style="width:346px">
        Flag that determines whether responses are sent to recipients who
        are not in the user's list of contacts.
      </td>
    </tr>
    <tr>
      <td style="width:295px">Account.Gmail.AutoReply.RestrcitToDomain</td>
      <td style="width:67px">String</td>
      <td style="width:346px">
        Flag that determines whether responses are sent to recipients who
        are outside of the user's domain. This feature is only available
        for G Suite users.
      </td>
    </tr>
    <tr>
      <td style="width:295px">Account.Gmail.Address</td>
      <td style="width:67px">String</td>
      <td style="width:346px">Email assigned with the current account.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!gmail-get-autoreply user-id=admin@demistodev.com</pre>
<h5>Context Example</h5>
<pre>{
    "Account.Gmail": {
        "Address": "admin@demistodev.com",
        "AutoReply": [
            {
                "EnableAutoReply": false,
                "ResponseBody": "body_test",
                "ResponseSubject": "subject_test",
                "RestrictToContact": false,
                "RestrictToDomain": false
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>User admin@demistodev.com:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>EnableAutoReply</strong>
      </th>
      <th>
        <strong>ResponseBody</strong>
      </th>
      <th>
        <strong>ResponseSubject</strong>
      </th>
      <th>
        <strong>RestrictToContact</strong>
      </th>
      <th>
        <strong>RestrictToDomain</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>false</td>
      <td>body_test</td>
      <td>subject_test</td>
      <td>false</td>
      <td>false</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_e8138221-0d22-4c0f-b7b1-595503a6ce5c">24. Set an auto-reply for the user</h3>
<hr>
<p>Sets the auto-reply for the user's account.&nbsp;</p>
<h5>Base Command</h5>
<p>
  <code>gmail-set-autoreply</code>
</p>
<h5>
  <span style="font-size:15px">Input</span>
</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:72px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:565px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:72px">user-id</td>
      <td style="width:565px">
        The user's email address. The "me" special value me can be used to
        indicate the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:72px">enable-autoReply</td>
      <td style="width:565px">
        Whether Gmail automatically replies to messages. Boolean. Set to
        true to automatically reply (default).
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:72px">response-subject</td>
      <td style="width:565px">
        Optional text to add to the subject line in vacation responses. To
        enable auto-replies, either the response subject or the response
        body must not be empty.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:72px">response-body</td>
      <td style="width:565px">Response body in plain text format.</td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:295px">
        <strong>Path</strong>
      </th>
      <th style="width:67px">
        <strong>Type</strong>
      </th>
      <th style="width:346px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:295px">Account.Gmail.AutoReply.EnableAutoReply</td>
      <td style="width:67px">Boolean</td>
      <td style="width:346px">
        Flag that controls whether Gmail automatically replies to messages.
      </td>
    </tr>
    <tr>
      <td style="width:295px">Account.Gmail.AutoReply.ResponseBody</td>
      <td style="width:67px">String</td>
      <td style="width:346px">Response body in plain text format.</td>
    </tr>
    <tr>
      <td style="width:295px">Account.Gmail.AutoReply.ResponseSubject</td>
      <td style="width:67px">String</td>
      <td style="width:346px">
        Optional text to add to the subject line in vacation responses. To
        enable auto-replies, either the response subject or the response
        body must not be empty.
      </td>
    </tr>
    <tr>
      <td style="width:295px">Account.Gmail.AutoReply.RestrictToContact</td>
      <td style="width:67px">String</td>
      <td style="width:346px">
        Determines whether responses are sent to recipients who are not in
        the user's list of contacts.
      </td>
    </tr>
    <tr>
      <td style="width:295px">Account.Gmail.AutoReply.RestrcitToDomain</td>
      <td style="width:67px">String</td>
      <td style="width:346px">
        Determines whether responses are sent to recipients who are outside
        of the user's domain. This feature is only available for G Suite
        users.
      </td>
    </tr>
    <tr>
      <td style="width:295px">Account.Gmail.Address</td>
      <td style="width:67px">String</td>
      <td style="width:346px">Email assigned with the current account.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-set-autoreply user-id=admin@demistodev.com enable-autoReply=false response-body=body_test response-subject=subject_test
</pre>
<h5>Context Example</h5>
<pre>{
    "Account.Gmail": {
        "Address": "admin@demistodev.com",
        "AutoReply": [
            {
                "EnableAutoReply": false,
                "ResponseBody": "body_test",
                "ResponseSubject": "subject_test",
                "RestrictToContact": false,
                "RestrictToDomain": false
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>User admin@demistodev.com:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>EnableAutoReply</strong>
      </th>
      <th>
        <strong>ResponseBody</strong>
      </th>
      <th>
        <strong>ResponseSubject</strong>
      </th>
      <th>
        <strong>RestrictToContact</strong>
      </th>
      <th>
        <strong>RestrictToDomain</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>false</td>
      <td>body_test</td>
      <td>subject_test</td>
      <td>false</td>
      <td>false</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_9032f028-a988-4416-b97a-9888cbdab04b">25. Add a delegate user to a mailbox</h3>
<hr>
<p>
  Adds a delegate user to the mailbox, without sending any verification email.&nbsp;
</p>
<h5>Base Command</h5>
<p>
  <code>gmail-delegate-user-mailbox</code>
</p>
<h5>Input</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:73px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:564px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:73px">user-id</td>
      <td style="width:564px">
        The user's email address. The "me" special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:73px">delegate-email</td>
      <td style="width:564px">
        The email address of the delegate.&nbsp;The delegate user must be
        a member of the same G Suite organization as the delegator user and
        must be added using their primary email address, and not an email
        alias.
      </td>
      <td style="width:71px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-delegate-user-mailbox delegate-email=shai@demistodev.com user-id=admin@demistodev.com</pre>
<h5>Human Readable Output</h5>
<p>Email shai@demistodev.com has been delegated</p>
<h3 id="h_6b56a925-b478-49a7-a57c-28e81258f007">26. Sends an email using Gmail</h3>
<hr>
<p>Sends an email using a Gmail account.</p>
<h5>Base Command</h5>
<p>
  <code>send-mail</code>
</p>
<h5>
  <span style="font-size:15px">Input</span>
</h5>
<table style="width:746px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:125px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:512px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:125px">to</td>
      <td style="width:512px">Email addresses of the receiver.</td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:125px">from</td>
      <td style="width:512px">Email address of the sender.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">body</td>
      <td style="width:512px">The contents (body) of the email to be sent in plain text.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">subject</td>
      <td style="width:512px">Subject for the email to be sent.</td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:125px">attachIDs</td>
      <td style="width:512px">
        A comma-separated list of IDs of War Room entries that contain the
        files that need be attached to the email.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">cc</td>
      <td style="width:512px">Additional recipient email address (CC).</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">bcc</td>
      <td style="width:512px">Additional recipient email address (BCC).</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">htmlBody</td>
      <td style="width:512px">The contents (body) of the email to be sent in HTML format.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">replyTo</td>
      <td style="width:512px">Address that needs to be used to reply to the message.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">attachNames</td>
      <td style="width:512px">
        A comma-separated list of new names to rename attachments corresponding
        to the order that they were attached to the email. Examples - To
        rename first and third file attachNames=new_fileName1,new_fileName3
        To rename second and fifth files attachNames=,new_fileName2,new_fileName5
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">attachCIDs</td>
      <td style="width:512px">
        A comma-separated list of CID images to embed attachments inside
        the email.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">transientFile</td>
      <td style="width:512px">
        Textual name for an attached file. Multiple files are supported as
        a comma-separated list. For example, transientFile="t1.txt,temp.txt,t3.txt"
        transientFileContent="test 2,temporary file content,third file content"
        transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz")
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">transientFileContent</td>
      <td style="width:512px">
        Content for the attached file. Multiple files are supported as a
        comma-separated list. For example, transientFile="t1.txt,temp.txt,t3.txt"
        transientFileContent="test 2,temporary file content,third file content"
        transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz")
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">transientFileCID</td>
      <td style="width:512px">
        CID image for an attached file to include within the email body.
        Multiple files are supported as comma-separated list. (e.g. transientFile="t1.txt,temp.txt,t3.txt"
        transientFileContent="test 2,temporary file content,third file content"
        transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz")
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">additionalHeader</td>
      <td style="width:512px">
        A CSV list of additional headers in the format: headerName=headerValue.
        For example: "headerName1=headerValue1,headerName2=headerValue2".
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:125px">templateParams</td>
      <td style="width:512px">
        Replaces {varname} variables with values from this parameter. Expected
        values are in the form of a JSON document. For example, {"varname"
        :{"value" "some value", "key": "context key"}}. Each var name can
        either be provided with the value or a context key to retrieve the
        value.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:748px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:195px">
        <strong>Path</strong>
      </th>
      <th style="width:87px">
        <strong>Type</strong>
      </th>
      <th style="width:426px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:195px">Gmail.SentMail.ID</td>
      <td style="width:87px">String</td>
      <td style="width:426px">The immutable ID of the message.</td>
    </tr>
    <tr>
      <td style="width:195px">Gmail.SentMail.Labels</td>
      <td style="width:87px">String</td>
      <td style="width:426px">List of IDs of labels applied to this message.</td>
    </tr>
    <tr>
      <td style="width:195px">Gmail.SentMail.ThreadId</td>
      <td style="width:87px">String</td>
      <td style="width:426px">The ID of the thread in which the message belongs.</td>
    </tr>
    <tr>
      <td style="width:195px">Gmail.SentMail.To</td>
      <td style="width:87px">String</td>
      <td style="width:426px">The recipient of the email.</td>
    </tr>
    <tr>
      <td style="width:195px">Gmail.SentMail.From</td>
      <td style="width:87px">Unknown</td>
      <td style="width:426px">The sender of the email.</td>
    </tr>
    <tr>
      <td style="width:195px">Gmail.SentMail.Cc</td>
      <td style="width:87px">String</td>
      <td style="width:426px">Additional recipient email address (CC).</td>
    </tr>
    <tr>
      <td style="width:195px">Gmail.SentMail.Bcc</td>
      <td style="width:87px">String</td>
      <td style="width:426px">Additional recipient email address (BCC).</td>
    </tr>
    <tr>
      <td style="width:195px">Gmail.SentMail.Subject</td>
      <td style="width:87px">String</td>
      <td style="width:426px">The subject of the email.</td>
    </tr>
    <tr>
      <td style="width:195px">Gmail.SentMail.Body</td>
      <td style="width:87px">Unknown</td>
      <td style="width:426px">The plain-text version of the email.</td>
    </tr>
    <tr>
      <td style="width:195px">Gmail.SentMail.MailBox</td>
      <td style="width:87px">String</td>
      <td style="width:426px">The mailbox from which the mail was sent.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !send-mail subject="this is the subject" to=test@demistodev.com body="this is the body"
</pre>
<h5>Context Example</h5>
<pre>{
    "Gmail.SentMail": [
        {
            "Bcc": null,
            "Body": "this is the body",
            "Cc": null,
            "From": "admin@demistodev.com",
            "ID": "16d43287fc29b71a",
            "Labels": [
                "SENT"
            ],
            "Mailbox": "test@demistodev.com",
            "Subject": "this is the subject",
            "ThreadId": "16d43287fc29b71a",
            "To": "test@demistodev.com",
            "Type": "Gmail"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Email sent:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>ID</strong>
      </th>
      <th>
        <strong>To</strong>
      </th>
      <th>
        <strong>From</strong>
      </th>
      <th>
        <strong>Subject</strong>
      </th>
      <th>
        <strong>Body</strong>
      </th>
      <th>
        <strong>Labels</strong>
      </th>
      <th>
        <strong>ThreadId</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Gmail</td>
      <td>16d43287fc29b71a</td>
      <td>test@demistodev.com</td>
      <td>admin@demistodev.com</td>
      <td>this is the subject</td>
      <td>this is the body</td>
      <td>SENT</td>
      <td>16d43287fc29b71a</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_426da8de-404c-432d-9080-b476cf896f5a">27. Removes a delegate from a mailbox</h3>
<hr>
<p>
  Removes a delegate user from the mailbox, without sending any verification email.&nbsp;
</p>
<h5>Base Command</h5>
<p>
  <code>gmail-remove-delegated-mailbox</code>
</p>
<h5>Input</h5>
<table style="width:744px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th style="width:57px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:575px">
        <strong>Description</strong>
      </th>
      <th style="width:76px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:57px">user-id</td>
      <td style="width:575px">
        The user's email address. The "me" special value can be used to indicate
        the authenticated user.
      </td>
      <td style="width:76px">Required</td>
    </tr>
    <tr>
      <td style="width:57px">removed-mail</td>
      <td style="width:575px">
        The email address to remove from delegation.&nbsp;The delegate user
        must be a member of the same G Suite organization as the delegator
        user using their primary email address, and not an email alias.
      </td>
      <td style="width:76px">Required</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>  !gmail-remove-delegated-mailbox removed-mail=shai@demistodev.com user-id=admin@demistodev.com
</pre>
<h5>Human Readable Output</h5>
<p>Email shai@demistodev.com has been removed from delegation</p>